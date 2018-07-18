/*
 * log_file.c
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <assert.h>

#include "log_file.h"

#define LOG(fp, time, facl, pid, out) \
    { fprintf(fp, "[%s]" facl "[%5d] %s\n", time, pid, out); } while(0)
#define LOGEX(fp, time, facl, pid, src, line, out) \
    { \
        fprintf(fp, "[%s]" facl "[%5d] %s.%zu: %s\n", \
            time, pid, src, line, out); \
    } while(0)
#define LOGEXERR(fp, time, facl, pid, src, line, out, serrno) \
    { \
        if (serrno) { \
            fprintf(fp, "[%s]" facl "[%5d] %s.%zu: %s failed: %s\n", \
                time, pid, src, line, out, strerror(serrno)); \
        } else { \
            fprintf(fp, "[%s]" facl "[%5d] %s.%zu: %s failed\n", \
                time, pid, src, line, out); \
        } \
    } while(0)

char *log_file = NULL;
static FILE *flog = NULL;


int log_open_file(void)
{
    if (!log_file) {
        fprintf(stderr, "%s\n", "The path to the logfile was not set.");
        return 1;
    }

    flog = fopen(log_file, "a+");
    if (!flog) {
        fprintf(stderr, "Could not open '%s' for writing: %s\n",
            log_file, strerror(errno));
        return 1;
    }

    if (setvbuf(flog, NULL, _IOLBF, BUFSIZ)) {
        log_close_file();
        return 1;
    }

    return 0;
}

void log_close_file(void)
{
    fclose(flog);
    flog = NULL;
}

void log_fmt_file(log_priority prio, const char *fmt, ...)
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
            LOG(flog, time, "[DEBUG]  ", my_pid, out);
            break;
        case NOTICE:
            LOG(flog, time, "[NOTICE] ", my_pid, out);
            break;
        case WARNING:
            LOG(flog, time, "[WARNING]", my_pid, out);
            break;
        case ERROR:
            LOG(flog, time, "[ERROR]  ", my_pid, out);
            break;
        case CMD:
            LOG(flog, time, "[CMD]    ", my_pid, out);
            break;
        case PROTOCOL:
            LOG(flog, time, "[PROTO]  ", my_pid, out);
            break;
    }
}

void log_fmtex_file(log_priority prio, const char *srcfile,
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
            LOGEX(flog, time, "[DEBUG]  ", my_pid, srcfile, line, out);
            break;
        case NOTICE:
            LOGEX(flog, time, "[NOTICE] ", my_pid, srcfile, line, out);
            break;
        case WARNING:
            LOGEX(flog, time, "[WARNING]", my_pid, srcfile, line, out);
            break;
        case ERROR:
            LOGEX(flog, time, "[ERROR]  ", my_pid, srcfile, line, out);
            break;
        case CMD:
        case PROTOCOL:
            break;
    }
}

void log_fmtexerr_file(log_priority prio, const char *srcfile,
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
            LOGEXERR(flog, time, "[DEBUG]  ", my_pid, srcfile, line, out,
                saved_errno);
            break;
        case NOTICE:
            LOGEXERR(flog, time, "[NOTICE] ", my_pid, srcfile, line, out,
                saved_errno);
            break;
        case WARNING:
            LOGEXERR(flog, time, "[WARNING]", my_pid, srcfile, line, out,
                saved_errno);
            break;
        case ERROR:
            LOGEXERR(flog, time, "[ERROR]  ", my_pid, srcfile, line, out,
                saved_errno);
            break;
        case CMD:
        case PROTOCOL:
            break;
    }
}
