/* ==================================================================== 
 * The Kannel Software License, Version 1.0 
 * 
 * Copyright (c) 2001-2018 Kannel Group  
 * Copyright (c) 1998-2001 WapIT Ltd.   
 * All rights reserved. 
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 * 
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 * 
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in 
 *    the documentation and/or other materials provided with the 
 *    distribution. 
 * 
 * 3. The end-user documentation included with the redistribution, 
 *    if any, must include the following acknowledgment: 
 *       "This product includes software developed by the 
 *        Kannel Group (http://www.kannel.org/)." 
 *    Alternately, this acknowledgment may appear in the software itself, 
 *    if and wherever such third-party acknowledgments normally appear. 
 * 
 * 4. The names "Kannel" and "Kannel Group" must not be used to 
 *    endorse or promote products derived from this software without 
 *    prior written permission. For written permission, please  
 *    contact org@kannel.org. 
 * 
 * 5. Products derived from this software may not be called "Kannel", 
 *    nor may "Kannel" appear in their name, without prior written 
 *    permission of the Kannel Group. 
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED 
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES 
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED.  IN NO EVENT SHALL THE KANNEL GROUP OR ITS CONTRIBUTORS 
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,  
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT  
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR  
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,  
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE  
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,  
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
 * ==================================================================== 
 * 
 * This software consists of voluntary contributions made by many 
 * individuals on behalf of the Kannel Group.  For more information on  
 * the Kannel Group, please see <http://www.kannel.org/>. 
 * 
 * Portions of this software are based upon software originally written at  
 * WapIT Ltd., Helsinki, Finland for the Kannel project.  
 */ 

/*
 * protected.c - thread-safe versions of standard library functions
 *
 * Lars Wirzenius
 */

#include <locale.h>
#include <errno.h>

#include "gwlib.h"


/*
 * Undefine the accident protectors.
 */
#undef localtime
#undef gmtime
#undef rand
#undef mktime
#undef strftime


enum {
    RAND,
    GWTIME,
    NUM_LOCKS
};


static Mutex locks[NUM_LOCKS];


static void lock(int which)
{
    mutex_lock(&locks[which]);
}


static void unlock(int which)
{
    mutex_unlock(&locks[which]);
}


void gwlib_protected_init(void)
{
    int i;

    for (i = 0; i < NUM_LOCKS; ++i)
        mutex_init_static(&locks[i]);
}


void gwlib_protected_shutdown(void)
{
    int i;

    for (i = 0; i < NUM_LOCKS; ++i)
        mutex_destroy(&locks[i]);
}


struct tm gw_localtime(time_t t)
{
    struct tm tm;

#ifndef HAVE_LOCALTIME_R
    lock(GWTIME);
    tm = *localtime(&t);
    unlock(GWTIME);
#else
    localtime_r(&t, &tm);
#endif

    return tm;
}


struct tm gw_gmtime(time_t t)
{
    struct tm tm;

#ifndef HAVE_GMTIME_R
    lock(GWTIME);
    tm = *gmtime(&t);
    unlock(GWTIME);
#else
    gmtime_r(&t, &tm);
#endif

    return tm;
}


time_t gw_mktime(struct tm *tm)
{
    time_t t;
    lock(GWTIME);
    t = mktime(tm);
    unlock(GWTIME);

    return t;
}


size_t gw_strftime(char *s, size_t max, const char *format, const struct tm *tm)
{
    size_t ret;
    lock(GWTIME);
    ret = strftime(s, max, format, tm);
    unlock(GWTIME);
    return ret;
}


int gw_rand(void)
{
    int ret;

    lock(RAND);
    ret = rand();
    unlock(RAND);
    return ret;
}

/*
 * Resolve a hostname to a list of IPv4 addresses using the modern,
 * thread-safe getaddrinfo(3) API. The legacy gethostbyname/gethostbyname_r
 * functions are deprecated on current glibc and may emit warnings (or
 * errors with -Werror) on recent toolchains.
 *
 * To keep the existing call sites unchanged we still hand back a
 * struct hostent populated with IPv4 addresses. A single buffer is
 * allocated in *buff that owns the canonical name string, the
 * h_addr_list pointer array and the in_addr slots it points into;
 * the caller is responsible for gw_free(*buff) when done.
 */
int gw_gethostbyname(struct hostent *ent, const char *name, char **buff)
{
    struct addrinfo hints, *res, *ai;
    int rc, n, i;
    size_t name_len, addrs_off, addrs_size, ptrs_size, total;
    char *bufptr;
    static char *empty_aliases[1] = { NULL };

    *buff = NULL;
    if (ent == NULL || name == NULL) {
        errno = EINVAL;
        return -1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;

    rc = getaddrinfo(name, NULL, &hints, &res);
    if (rc != 0) {
        if (rc != EAI_SYSTEM)
            errno = ENOENT;
        error(0, "getaddrinfo(%s) failed: %s", name, gai_strerror(rc));
        return -1;
    }

    /* Count IPv4 addresses returned. */
    n = 0;
    for (ai = res; ai != NULL; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET && ai->ai_addr != NULL &&
            ai->ai_addrlen >= sizeof(struct sockaddr_in))
            n++;
    }
    if (n == 0) {
        errno = EADDRNOTAVAIL;
        error(0, "getaddrinfo(%s): no IPv4 addresses returned", name);
        freeaddrinfo(res);
        return -1;
    }

    /*
     * Single-buffer layout:
     *   [ canonical name string, NUL-terminated ]
     *   [ padding to pointer alignment ]
     *   [ (n+1) * (char *)        -> h_addr_list ]
     *   [ n * struct in_addr      -> referenced by h_addr_list ]
     */
    {
        const char *canon = (res->ai_canonname != NULL) ? res->ai_canonname : name;
        name_len = strlen(canon) + 1;
        /* Align after name to sizeof(void *). */
        addrs_off = (name_len + sizeof(void *) - 1) & ~(sizeof(void *) - 1);
        ptrs_size = (n + 1) * sizeof(char *);
        addrs_size = n * sizeof(struct in_addr);
        total = addrs_off + ptrs_size + addrs_size;

        bufptr = gw_malloc(total);
        *buff = bufptr;

        memcpy(bufptr, canon, name_len);
        ent->h_name = bufptr;
    }

    ent->h_aliases = empty_aliases;
    ent->h_addrtype = AF_INET;
    ent->h_length = sizeof(struct in_addr);
    ent->h_addr_list = (char **)(bufptr + addrs_off);

    {
        struct in_addr *addrs = (struct in_addr *)((char *)ent->h_addr_list + ptrs_size);
        i = 0;
        for (ai = res; ai != NULL && i < n; ai = ai->ai_next) {
            if (ai->ai_family != AF_INET || ai->ai_addr == NULL ||
                ai->ai_addrlen < sizeof(struct sockaddr_in))
                continue;
            addrs[i] = ((struct sockaddr_in *)ai->ai_addr)->sin_addr;
            ent->h_addr_list[i] = (char *)&addrs[i];
            i++;
        }
        ent->h_addr_list[i] = NULL;
    }

    freeaddrinfo(res);
    return 0;
}
