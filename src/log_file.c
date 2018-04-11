#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <assert.h>

#include "log_file.h"

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
    char out[LOGMSG_MAXLEN+1] = {0};
    va_list arglist;

    if (prio < log_prio)
        return;
    assert(fmt);
    va_start(arglist, fmt);
    assert( vsnprintf(&out[0], LOGMSG_MAXLEN, fmt, arglist) >= 0 );
    va_end(arglist);

    my_pid = getpid();
    switch (prio) {
        case DEBUG:
            fprintf(flog, "[DEBUG]  [%d] %s\n", my_pid, out);
            break;
        case NOTICE:
            fprintf(flog, "[NOTICE] [%d] %s\n", my_pid, out);
            break;
        case WARNING:
            fprintf(flog, "[WARNING][%d] %s\n", my_pid, out);
            break;
        case ERROR:
            fprintf(flog, "[ERROR]  [%d] %s\n", my_pid, out);
            break;
        case CMD:
            fprintf(flog, "[CMD]    [%d] %s\n", my_pid, out);
            break;
    }
}

void log_fmtex_file(log_priority prio, const char *srcfile,
                    size_t line, const char *fmt, ...)
{
    pid_t my_pid;
    char out[LOGMSG_MAXLEN+1] = {0};
    va_list arglist;

    if (prio < log_prio)
        return;
    assert(fmt);
    va_start(arglist, fmt);
    assert( vsnprintf(&out[0], LOGMSG_MAXLEN, fmt, arglist) >= 0 );
    va_end(arglist);

    my_pid = getpid();
    switch (prio) {
        case DEBUG:
            fprintf(flog, "[DEBUG]  [%d] %s.%zu: %s\n", my_pid, srcfile,
                line, out);
            break;
        case NOTICE:
            fprintf(flog, "[NOTICE] [%d] %s.%zu: %s\n",
                my_pid, srcfile, line, out);
            break;
        case WARNING:
            fprintf(flog, "[WARNING][%d] %s.%zu: %s\n",
                my_pid, srcfile, line, out);
            break;
        case ERROR:
            fprintf(flog, "[ERROR]  [%d] %s.%zu: %s\n",
                my_pid, srcfile, line, out);
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
    char out[LOGMSG_MAXLEN+1] = {0};
    va_list arglist;

    if (prio < log_prio)
        return;
    assert(fmt);
    va_start(arglist, fmt);
    assert( vsnprintf(&out[0], LOGMSG_MAXLEN, fmt, arglist) >= 0 );
    va_end(arglist);

    my_pid = getpid();
    switch (prio) {
        case DEBUG:
            if (saved_errno)
                fprintf(flog, "[DEBUG]  [%d] %s.%zu: %s failed: %s\n",
                    my_pid, srcfile, line, out,
                    strerror(saved_errno));
            else
                fprintf(flog, "[DEBUG]  [%d] %s.%zu: %s failed\n",
                    my_pid, srcfile, line, out);
            break;
        case NOTICE:
            if (saved_errno)
                fprintf(flog, "[NOTICE] [%d] %s.%zu: %s failed: %s\n",
                    my_pid, srcfile,
                    line, out, strerror(saved_errno));
            else
                fprintf(flog, "[NOTICE] [%d] %s.%zu: %s failed\n",
                    my_pid, srcfile,
                    line, out);
            break;
        case WARNING:
            if (saved_errno)
                fprintf(flog, "[WARNING][%d] %s.%zu: %s failed: %s\n",
                    my_pid, srcfile,
                    line, out, strerror(saved_errno));
            else
                fprintf(flog, "[WARNING][%d] %s.%zu: %s failed\n",
                    my_pid, srcfile,
                    line, out);
            break;
        case ERROR:
            if (saved_errno)
                fprintf(flog, "[ERROR]  [%d] %s.%zu: %s failed: %s\n",
                    my_pid, srcfile,
                    line, out, strerror(saved_errno));
            else
                fprintf(flog, "[ERROR]  [%d] %s.%zu: %s failed\n",
                    my_pid, srcfile,
                    line, out);
            break;
        case CMD:
            break;
    }
}
