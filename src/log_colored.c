#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>

#include "log_colored.h"


int log_open_colored(void)
{
    if (!getenv("TERM")) {
        fprintf(stderr, "%s\n", "Missing TERM variable in your environment.");
        return 1;
    }
    if (!strstr(getenv("TERM"), "linux")
      && !strstr(getenv("TERM"), "xterm"))
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
    char out[LOGMSG_MAXLEN+1] = {0};
    va_list arglist;

    assert(fmt);
    va_start(arglist, fmt);
    assert( vsnprintf(&out[0], LOGMSG_MAXLEN, fmt, arglist) >= 0 );
    va_end(arglist);

    switch (prio) {
        case DEBUG:
            printf("[DEBUG]   %s\n", out);
            break;
        case NOTICE:
            printf("[" GRN "NOTICE" RESET "]  %s\n", out);
            break;
        case WARNING:
            printf("[" YEL "WARNING" RESET "] %s\n", out);
            break;
        case ERROR:
            printf("[" RED "ERROR" RESET "]   %s\n", out);
            break;
    }
}

void log_fmtex_colored(log_priority prio, const char *srcfile,
                       size_t line, const char *fmt, ...)
{
    char out[LOGMSG_MAXLEN+1] = {0};
    va_list arglist;

    assert(fmt);
    va_start(arglist, fmt);
    assert( vsnprintf(&out[0], LOGMSG_MAXLEN, fmt, arglist) >= 0 );
    va_end(arglist);

    switch (prio) {
        case DEBUG:
            printf("[DEBUG]   %s.%lu: %s\n", srcfile, line, out);
            break;
        case NOTICE:
            printf("[" GRN "NOTICE" RESET "]  %s.%lu: %s\n", srcfile, line, out);
            break;
        case WARNING:
            printf("[" YEL "WARNING" RESET "] %s.%lu: %s\n", srcfile, line, out);
            break;
        case ERROR:
            printf("[" RED "ERROR" RESET "]   %s.%lu: %s\n", srcfile, line, out);
            break;
    }
}
