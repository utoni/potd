#ifndef POTD_LOG_FILE_H
#define POTD_LOG_FILE_H 1

#include "log.h"

#define LOG_FILE_FUNCS log_open_file, log_close_file, \
    log_fmt_file, log_fmtex_file, log_fmtexerr_file

extern char *log_file;


int log_open_file(void);

void log_close_file(void);

void log_fmt_file(log_priority prio, const char *fmt, ...);

void log_fmtex_file(log_priority prio, const char *srcfile,
                    size_t line, const char *fmt, ...);

void log_fmtexerr_file(log_priority prio, const char *srcfile,
                       size_t line, const char *fmt, ...);

#endif
