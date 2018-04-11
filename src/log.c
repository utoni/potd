#include <stdio.h>

#include "log.h"

log_priority log_prio = NOTICE;
log_open_cb log_open = NULL;
log_close_cb log_close = NULL;
log_fmt_cb log_fmt = NULL;
log_fmtex_cb log_fmtex = NULL;
log_fmtexerr_cb log_fmtexerr = NULL;
