#ifndef POTD_LOG_H
#define POTD_LOG_H 1

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define LOGMSG_MAXLEN 255
#define LOG_SET_FUNCS(open_cb, close_cb, fmt_cb, fmtex_cb) \
    { \
        log_open = open_cb; log_close = close_cb; \
        log_fmt = fmt_cb; log_fmtex = fmtex_cb; \
    }
#define LOG_SET_FUNCS_VA(...) LOG_SET_FUNCS(__VA_ARGS__)
#define D(fmt, ...) log_fmt(DEBUG, fmt, __VA_ARGS__)
#define N(fmt, ...) log_fmt(NOTICE, fmt, __VA_ARGS__)
#define W(fmt, ...) log_fmt(WARNING, fmt, __VA_ARGS__)
#define E(fmt, ...) log_fmt(ERROR, fmt, __VA_ARGS__)
#define D2(fmt, ...) log_fmtex(DEBUG, __FILE__, __LINE__, fmt, __VA_ARGS__)
#define N2(fmt, ...) log_fmtex(NOTICE, __FILE__, __LINE__, fmt, __VA_ARGS__)
#define W2(fmt, ...) log_fmtex(WARNING, __FILE__, __LINE__, fmt, __VA_ARGS__)
#define E2(fmt, ...) log_fmtex(ERROR, __FILE__, __LINE__, fmt, __VA_ARGS__)
#define W_STRERR(msg) { if (errno) W2("%s failed: %s", msg, strerror(errno)); }
#define E_STRERR(msg) { if (errno) E2("%s failed: %s", msg, strerror(errno)); }
#define ABORT_ON_FATAL(expr, msg) \
    { errno = 0; if (expr) { E_STRERR(msg); abort(); } }

typedef enum log_priority {
    DEBUG = 0, NOTICE, WARNING, ERROR
} log_priority;

typedef int (*log_open_cb) (void);
typedef void (*log_close_cb) (void);
typedef void (*log_fmt_cb) (log_priority prio, const char *fmt, ...);
typedef void (*log_fmtex_cb) (log_priority prio, const char *srcfile,
                              size_t line, const char *fmt, ...);


extern log_open_cb log_open;
extern log_close_cb log_close;
extern log_fmt_cb log_fmt;
extern log_fmtex_cb log_fmtex;

#endif
