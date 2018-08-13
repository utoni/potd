/*
 * log_syslog.c
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
#else
#define PACKAGE "unknown"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <assert.h>

#include "log_syslog.h"

#define LOG(facility, fmt, arglist) \
    { vsyslog(facility, fmt, arglist); } while(0)
#define LOGEX(facility, src, line, out) \
    { syslog(facility, "%s.%zu: %s", src, line, out); } while(0)
#define LOGEXERR(facility, src, line, out, serrno) \
    { \
        if (serrno) { \
            syslog(facility, "%s.%zu: %s failed: %s", \
                src, line, out, strerror(serrno)); \
        } else { \
            syslog(facility, "%s.%zu: %s failed", \
                src, line, out); \
        } \
    } while(0)


int log_open_syslog(void)
{
    openlog(PACKAGE, 0, LOG_DAEMON);

    return 0;
}

void log_close_syslog(void)
{
    closelog();
}

void log_fmt_syslog(log_priority prio, const char *fmt, ...)
{
    va_list arglist;

    if (prio < log_prio)
        return;
    assert(fmt);
    va_start(arglist, fmt);
    switch (prio) {
        case DEBUG:
            LOG(LOG_DEBUG, fmt, arglist);
            break;
        case NOTICE:
            LOG(LOG_NOTICE, fmt, arglist);
            break;
        case WARNING:
            LOG(LOG_WARNING, fmt, arglist);
            break;
        case ERROR:
            LOG(LOG_ERR, fmt, arglist);
            break;
        case CMD:
            LOG(LOG_INFO, fmt, arglist);
            break;
        case PROTOCOL:
            LOG(LOG_INFO, fmt, arglist);
            break;
    }
    va_end(arglist);
}

void log_fmtex_syslog(log_priority prio, const char *srcfile,
                      size_t line, const char *fmt, ...)
{
    char out[LOGMSG_MAXLEN+1] = {0};
    va_list arglist;

    if (prio < log_prio)
        return;
    assert(fmt);
    va_start(arglist, fmt);
    /* Flawfinder: ignore */
    assert( vsnprintf(&out[0], LOGMSG_MAXLEN, fmt, arglist) >= 0 );
    va_end(arglist);

    switch (prio) {
        case DEBUG:
            LOGEX(LOG_DEBUG, srcfile, line, out);
            break;
        case NOTICE:
            LOGEX(LOG_NOTICE, srcfile, line, out);
            break;
        case WARNING:
            LOGEX(LOG_WARNING, srcfile, line, out);
            break;
        case ERROR:
            LOGEX(LOG_ERR, srcfile, line, out);
            break;
        case CMD:
        case PROTOCOL:
            break;
    }
}

void log_fmtexerr_syslog(log_priority prio, const char *srcfile,
                         size_t line, const char *fmt, ...)
{
    int saved_errno = errno;
    char out[LOGMSG_MAXLEN+1] = {0};
    va_list arglist;

    if (prio < log_prio)
        return;
    assert(fmt);
    va_start(arglist, fmt);
    /* Flawfinder: ignore */
    assert( vsnprintf(&out[0], LOGMSG_MAXLEN, fmt, arglist) >= 0 );
    va_end(arglist);

    switch (prio) {
        case DEBUG:
            LOGEXERR(LOG_DEBUG, srcfile, line, out, saved_errno);
            break;
        case NOTICE:
            LOGEXERR(LOG_NOTICE, srcfile, line, out, saved_errno);
            break;
        case WARNING:
            LOGEXERR(LOG_WARNING, srcfile, line, out, saved_errno);
            break;
        case ERROR:
            LOGEXERR(LOG_WARNING, srcfile, line, out, saved_errno);
            break;
        case CMD:
        case PROTOCOL:
            break;
    }
}
