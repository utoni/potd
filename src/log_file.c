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
            break;
    }
}
