/*
 * log_colored.c
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
#define GETENV_FUNC getenv
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include "log_colored.h"

#define LOG(time, facl, pid, out) { printf("[%s]" facl "[%5d] %s\n", time, pid, out); } while(0)
#define LOGEX(time, facl, pid, src, line, out) \
    { printf("[%s]" facl "[%5d] %s.%zu: %s\n", time, pid, src, line, out); } while(0)
#define LOGEXERR(time, facl, pid, src, line, out, serrno) \
    { \
        if (serrno) { \
            printf("[%s]" facl "[%5d] %s.%zu: %s failed: %s\n", \
                time, pid, src, line, out, strerror(serrno)); \
        } else { \
            printf("[%s]" facl "[%5d] %s.%zu: %s failed\n", \
                time, pid, src, line, out); \
        } \
    } while(0)


int log_open_colored(void)
{
    if (!GETENV_FUNC("TERM")) {
        fprintf(stderr, "%s\n", "Missing TERM variable in your environment.");
        return 1;
    }
    if (!strstr(GETENV_FUNC("TERM"), "linux")
      && !strstr(GETENV_FUNC("TERM"), "xterm"))
    {
        fprintf(stderr, "%s\n", "Unsupported TERM variable in your environment");
        return 1;
    }
    return 0;
}

void log_close_colored(void)
{
    return;
}

void log_fmt_colored(log_priority prio, const char *fmt, ...)
{
    pid_t my_pid;
    char time[64];
    char out[LOGMSG_MAXLEN+1] = {0};
    va_list arglist;

    if (prio < log_prio)
        return;
    assert(fmt);
    va_start(arglist, fmt);
    assert( vsnprintf(&out[0], LOGMSG_MAXLEN, fmt, arglist) >= 0 );
    va_end(arglist);

    my_pid = getpid();
    curtime_str(time, sizeof time);
    switch (prio) {
        case DEBUG:
            LOG(time, "[DEBUG]  ", my_pid, out);
            break;
        case NOTICE:
            LOG(time, "[" GRN "NOTICE" RESET "] ", my_pid, out);
            break;
        case WARNING:
            LOG(time, "[" YEL "WARNING" RESET "]", my_pid, out);
            break;
        case ERROR:
            LOG(time, "[" RED "ERROR" RESET "]  ", my_pid, out);
            break;
        case CMD:
            LOG(time, "[" BLU "CMD" RESET "]    ", my_pid, out);
            break;
        case PROTOCOL:
            LOG(time, "[" CYA "PROTO" RESET "]  ", my_pid, out);
            break;
    }
}

void log_fmtex_colored(log_priority prio, const char *srcfile,
                       size_t line, const char *fmt, ...)
{
    pid_t my_pid;
    char time[64];
    char out[LOGMSG_MAXLEN+1] = {0};
    va_list arglist;

    if (prio < log_prio)
        return;
    assert(fmt);
    va_start(arglist, fmt);
    assert( vsnprintf(&out[0], LOGMSG_MAXLEN, fmt, arglist) >= 0 );
    va_end(arglist);

    my_pid = getpid();
    curtime_str(time, sizeof time);
    switch (prio) {
        case DEBUG:
            LOGEX(time, "[DEBUG]  ", my_pid, srcfile, line, out);
            break;
        case NOTICE:
            LOGEX(time, "[" GRN "NOTICE" RESET "] ", my_pid, srcfile, line, out);
            break;
        case WARNING:
            LOGEX(time, "[" YEL "WARNING" RESET "]", my_pid, srcfile, line, out);
            break;
        case ERROR:
            LOGEX(time, "[" RED "ERROR" RESET "]  ", my_pid, srcfile, line, out);
            break;
        case CMD:
        case PROTOCOL:
            break;
    }
}

void log_fmtexerr_colored(log_priority prio, const char *srcfile,
                          size_t line, const char *fmt, ...)
{
    pid_t my_pid;
    int saved_errno = errno;
    char time[64];
    char out[LOGMSG_MAXLEN+1] = {0};
    va_list arglist;

    if (prio < log_prio)
        return;
    assert(fmt);
    va_start(arglist, fmt);
    assert( vsnprintf(&out[0], LOGMSG_MAXLEN, fmt, arglist) >= 0 );
    va_end(arglist);

    my_pid = getpid();
    curtime_str(time, sizeof time);
    switch (prio) {
        case DEBUG:
            LOGEXERR(time, "[DEBUG]  ", my_pid, srcfile, line, out, saved_errno);
            break;
        case NOTICE:
            LOGEXERR(time, "[" GRN "NOTICE" RESET "] ", my_pid, srcfile, line, out, saved_errno);
            break;
        case WARNING:
            LOGEXERR(time, "[" YEL "WARNING" RESET "]", my_pid, srcfile, line, out, saved_errno);
            break;
        case ERROR:
            LOGEXERR(time, "[" RED "ERROR" RESET "]  ", my_pid, srcfile, line, out, saved_errno);
            break;
        case CMD:
        case PROTOCOL:
            break;
    }
}
