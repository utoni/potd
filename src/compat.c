/*
 * compat.c
 * potd is licensed under the BSD license:
 *
 * Copyright (c) 2018 Toni Uhlig <matzeton@googlemail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * - The names of its contributors may not be used to endorse or promote
 *   products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <errno.h>

#include "compat.h"


char *
potd_strtok(char *str, const char *delim, char **saveptr)
{
#ifdef HAVE_STRTOK_R
    return strtok_r(str, delim, saveptr);
#else
    (void) saveptr;

    return strtok(str, delim);
#endif
}

struct tm *
potd_localtime(const time_t *timep, struct tm *result)
{
#ifdef HAVE_LOCALTIME_R
    return localtime_r(timep, result);
#else
    (void) result;

    return localtime(timep);
#endif
}

int
potd_getpwnam(const char *name, struct passwd *pwd)
{
    struct passwd *result = NULL;

    errno = 0;
#ifdef HAVE_GETPWNAM_R
    char buf[BUFSIZ];

    return getpwnam_r(name, pwd, buf, sizeof buf, &result) || !result;
#else
    result = getpwnam(name);
    if (result)
        *pwd = *result;

    return result == NULL;
#endif
}

int
potd_getgrnam(const char *name, struct group *grp)
{
    struct group *result = NULL;

    errno = 0;
#ifdef HAVE_GETGRNAM_R
    char buf[BUFSIZ];

    return getgrnam_r(name, grp, buf, sizeof buf, &result) || !result;
#else
    result = getgrnam(name);
    if (result)
        *grp = *result;

    return result == NULL;
#endif
}
