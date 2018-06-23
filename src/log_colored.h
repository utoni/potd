#ifndef POTD_LOG_COLORED_H
#define POTD_LOG_COLORED_H 1

#include "log.h"

/* ANSI terminal color codes */
#define RESET "\x1B[0m"
#define GRN   "\x1B[32;1m"
#define YEL   "\x1B[33;1m"
#define RED   "\x1B[31;1;5m"
#define BLU   "\x1B[34;1;1m"
/* LOG_SET_FUNCS comfort */
#define LOG_COLORED_FUNCS log_open_colored, log_close_colored, \
    log_fmt_colored, log_fmtex_colored, log_fmtexerr_colored


int log_open_colored(void);

void log_close_colored(void);

void log_fmt_colored(log_priority prio, const char *fmt, ...);

void log_fmtex_colored(log_priority prio, const char *srcfile,
                       size_t line, const char *fmt, ...);

void log_fmtexerr_colored(log_priority prio, const char *srcfile,
                          size_t line, const char *fmt, ...);

#endif
