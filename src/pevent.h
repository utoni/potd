/*
 * pevent.h
 * potd is licensed under the BSD license:
 *
 * Copyright (c) 2018 Toni Uhlig <matzeton@googlemail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * - The names of its contributors may not be used to endorse or promote
 *   products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef POTD_EVENT_H
#define POTD_EVENT_H 1

#include <stdio.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <string.h>

#include "socket.h"

#define POTD_MAXFD 32
#define POTD_MAXEVENTS 64
#define POTD_EVENTBUF_REALLOCSIZ 5
#define WRITE_BUF(fd) { fd, {0}, 0, NULL }
#define EMPTY_BUF { -1, {0}, 0, NULL }

typedef enum forward_state {
    CON_OK, CON_IN_TERMINATED, CON_OUT_TERMINATED,
    CON_IN_ERROR, CON_OUT_ERROR
} forward_state;

typedef struct event_buf {
    int fd;

    char buf[BUFSIZ];
    size_t buf_used;

    void *buf_user_data;
} event_buf;

typedef struct event_ctx {
    int active;
    int has_error;

    int epoll_fd;
    struct epoll_event events[POTD_MAXEVENTS];
    int current_event;

    event_buf *buffer_array;
    size_t buffer_size;
    size_t buffer_used;
} event_ctx;

typedef int (*on_event_cb) (event_ctx *ev_ctx, int src_fd,
                            void *user_data);
typedef int (*on_data_cb) (event_ctx *ev_ctx, event_buf *read_buf,
                           event_buf *write_buf, void *user_data);


void event_init(event_ctx **ctx);

void event_free(event_ctx **ctx);

int event_setup(event_ctx *ctx);

int event_validate_ctx(event_ctx *ctx);

int event_add_sock(event_ctx *ctx, psocket *sock, void *buf_user_data);

int event_add_fd(event_ctx *ctx, int fd, void *buf_user_data);

int event_loop(event_ctx *ctx, on_event_cb on_event, void *user_data);

forward_state
event_forward_connection(event_ctx *ctx, int dest_fd, on_data_cb on_data,
                         void *user_data);

int event_buf_fill(event_buf *buf, char *data, size_t size);

ssize_t event_buf_drain(event_buf *write_buf);

static inline size_t event_buf_avail(event_buf *buf)
{
    return sizeof(buf->buf) - buf->buf_used;
}

static inline ssize_t event_buf_read(event_buf *read_buf)
{
    ssize_t siz;

    siz = read(read_buf->fd, read_buf->buf + read_buf->buf_used,
               event_buf_avail(read_buf));
    if (siz > 0)
        read_buf->buf_used += siz;
    return siz;
}

static inline void event_buf_discard(event_buf *input, size_t siz)
{
    if (siz <= input->buf_used) {
        memmove(input->buf + siz, input->buf, input->buf_used - siz);
        input->buf_used -= siz;
    }
}

static inline void event_buf_discardall(event_buf *input)
{
    event_buf_discard(input, input->buf_used);
}

static inline int event_buf_dup(event_buf *input, event_buf *output)
{
    int rc = event_buf_fill(output, input->buf, input->buf_used);
    if (!rc)
        event_buf_discardall(input);
    return rc;
}

#endif
