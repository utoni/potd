#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include "log_colored.h"


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
            printf("[DEBUG]  [%d] %s\n", my_pid, out);
            break;
        case NOTICE:
            printf("[" GRN "NOTICE" RESET "] [%d] %s\n", my_pid, out);
            break;
        case WARNING:
            printf("[" YEL "WARNING" RESET "][%d] %s\n", my_pid, out);
            break;
        case ERROR:
            printf("[" RED "ERROR" RESET "]  [%d] %s\n", my_pid, out);
            break;
        case CMD:
            printf("[" BLUE "CMD" RESET "]    [%d] %s\n", my_pid, out);
            break;
    }
}

void log_fmtex_colored(log_priority prio, const char *srcfile,
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
            printf("[DEBUG]  [%d] %s.%zu: %s\n", my_pid, srcfile, line, out);
            break;
        case NOTICE:
            printf("[" GRN "NOTICE" RESET "] [%d] %s.%zu: %s\n",
                my_pid, srcfile, line, out);
            break;
        case WARNING:
            printf("[" YEL "WARNING" RESET "][%d] %s.%zu: %s\n",
                my_pid, srcfile, line, out);
            break;
        case ERROR:
            printf("[" RED "ERROR" RESET "]  [%d] %s.%zu: %s\n",
                my_pid, srcfile, line, out);
            break;
        case CMD:
            break;
    }
}

void log_fmtexerr_colored(log_priority prio, const char *srcfile,
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
                printf("[DEBUG]  [%d] %s.%zu: %s failed: %s\n",
                    my_pid, srcfile, line, out,
                    strerror(saved_errno));
            else
                printf("[DEBUG]  [%d] %s.%zu: %s failed\n",
                    my_pid, srcfile, line, out);
            break;
        case NOTICE:
            if (saved_errno)
                printf("[" GRN "NOTICE" RESET "] [%d] %s.%zu: %s failed: %s\n",
                    my_pid, srcfile,
                    line, out, strerror(saved_errno));
            else
                printf("[" GRN "NOTICE" RESET "] [%d] %s.%zu: %s failed\n",
                    my_pid, srcfile,
                    line, out);
            break;
        case WARNING:
            if (saved_errno)
                printf("[" YEL "WARNING" RESET "][%d] %s.%zu: %s failed: %s\n",
                    my_pid, srcfile,
                    line, out, strerror(saved_errno));
            else
                printf("[" YEL "WARNING" RESET "][%d] %s.%zu: %s failed\n",
                    my_pid, srcfile,
                    line, out);
            break;
        case ERROR:
            if (saved_errno)
                printf("[" RED "ERROR" RESET "]  [%d] %s.%zu: %s failed: %s\n",
                    my_pid, srcfile,
                    line, out, strerror(saved_errno));
            else
                printf("[" RED "ERROR" RESET "]  [%d] %s.%zu: %s failed\n",
                    my_pid, srcfile,
                    line, out);
            break;
        case CMD:
            break;
    }
}
