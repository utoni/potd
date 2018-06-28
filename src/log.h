#ifndef POTD_LOG_H
#define POTD_LOG_H 1

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define LOGMSG_MAXLEN BUFSIZ
#define LOG_SET_FUNCS(open_cb, close_cb, fmt_cb, fmtex_cb, fmtexerr_cb) \
    { \
        log_open = open_cb; log_close = close_cb; \
        log_fmt = fmt_cb; log_fmtex = fmtex_cb; \
        log_fmtexerr = fmtexerr_cb; \
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
#define W_STRERR(fmt, ...) log_fmtexerr(WARNING, __FILE__, __LINE__, fmt, \
                                        __VA_ARGS__)
#define E_STRERR(fmt, ...) log_fmtexerr(ERROR, __FILE__, __LINE__, fmt, \
                                        __VA_ARGS__)
#define E_GAIERR(ret, msg) { if (ret) { E2("%s failed: %s", msg, gai_strerror(ret)); } }
#define FATAL(fmt, ...) { E_STRERR(fmt, __VA_ARGS__); abort(); }
#define ABORT_ON_FATAL(expr, msg) \
    { errno = 0; long rv = (long) expr; \
      if (rv) { \
          /* \
          E_STRERR("`%s` returned %ld. %s", \
              #expr, rv, msg); abort(); \
          */ \
          E_STRERR("%s", msg); \
          kill(0, SIGABRT); \
          abort(); \
      } \
    }
#define C(fmt, ...) log_fmt(CMD, fmt, __VA_ARGS__)
#define P(fmt, ...) log_fmt(PROTOCOL, fmt, __VA_ARGS__)

typedef enum log_priority {
    DEBUG = 0, PROTOCOL, NOTICE, WARNING, ERROR, CMD
} log_priority;

typedef int (*log_open_cb) (void);
typedef void (*log_close_cb) (void);

typedef void (*log_fmt_cb) (log_priority prio, const char *fmt, ...)
                            __attribute__ ((format (printf, 2, 3)));

typedef void (*log_fmtex_cb) (log_priority prio, const char *srcfile,
                              size_t line, const char *fmt, ...)
                              __attribute__ ((format (printf, 4, 5)));

typedef void (*log_fmtexerr_cb) (log_priority prio, const char *srcfile,
                                 size_t line, const char *fmt, ...)
                                 __attribute__ ((format (printf, 4, 5)));


extern log_priority log_prio;
extern log_open_cb log_open;
extern log_close_cb log_close;
extern log_fmt_cb log_fmt;
extern log_fmtex_cb log_fmtex;
extern log_fmtexerr_cb log_fmtexerr;

char *
curtime_str(char *buf, size_t siz);

#endif
