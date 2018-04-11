#ifndef POTD_EVENT_H
#define POTD_EVENT_H 1

#include <sys/epoll.h>

#include "socket.h"

#define POTD_MAXFD 32
#define POTD_MAXEVENTS 64

typedef enum forward_state {
    CON_OK, CON_IN_TERMINATED, CON_OUT_TERMINATED,
    CON_IN_ERROR, CON_OUT_ERROR
} forward_state;

typedef struct event_ctx {
    int active;
    int has_error;

    int epoll_fd;
    struct epoll_event events[POTD_MAXEVENTS];
    int current_event;
} event_ctx;

typedef int (*on_event_cb) (event_ctx *ev_ctx, int fd, void *user_data);
typedef int (*on_data_cb) (event_ctx *ev_ctx, int src_fd, int dst_fd,
                           char *buf, size_t siz, void *user_data);


void event_init(event_ctx **ctx);

void event_free(event_ctx **ctx);

int event_setup(event_ctx *ctx);

int event_add_sock(event_ctx *ctx, psocket *sock);

int event_add_fd(event_ctx *ctx, int fd);

int event_loop(event_ctx *ctx, on_event_cb on_event, void *user_data);

forward_state
event_forward_connection(event_ctx *ctx, int dest_fd, on_data_cb on_data,
                         void *user_data);

#endif
