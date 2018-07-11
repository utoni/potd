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
 * - Neither the name of the Yellow Lemon Software nor the names of its
 *   contributors may be used to endorse or promote products derived from this
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
