#include <stdio.h>
#include <time.h>

#include "log.h"

log_priority log_prio = NOTICE;
log_open_cb log_open = NULL;
log_close_cb log_close = NULL;
log_fmt_cb log_fmt = NULL;
log_fmtex_cb log_fmtex = NULL;
log_fmtexerr_cb log_fmtexerr = NULL;


char *
curtime_str(char *buf, size_t siz)
{
    time_t t;
    struct tm *tmp;

    t = time(NULL);
    tmp = localtime(&t);

    if (!strftime(buf, siz, "%d %b %y - %H:%M:%S", tmp))
        snprintf(buf, siz, "%s", "UNKNOWN_TIME");

    return buf;
}
