/*
 * pevent.c
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/epoll.h>
#include <assert.h>

#include "pevent.h"
#include "log.h"

static int epoll_event_string(uint32_t event, char *buf, size_t siz);


static int epoll_event_string(uint32_t event, char *buf, size_t siz)
{
    if (event & EPOLLERR) {
        snprintf(buf, siz, "%s", "EPOLLERR");
    } else if (event & EPOLLHUP) {
        snprintf(buf, siz, "%s", "EPOLLHUP");
    } else if (event & EPOLLRDHUP) {
        snprintf(buf, siz, "%s", "EPOLLRDHUP");
    } else if (event & EPOLLIN) {
        snprintf(buf, siz, "%s", "EPOLLIN");
    } else return 1;

    return 0;
}

void event_init(event_ctx **ctx)
{
    assert(ctx);
    if (!*ctx)
        *ctx = (event_ctx *) malloc(sizeof(**ctx));
    assert(*ctx);

    memset(*ctx, 0, sizeof(**ctx));
    (*ctx)->epoll_fd = -1;
}

void event_free(event_ctx **ctx)
{
    assert(ctx && *ctx);

    close((*ctx)->epoll_fd);
    free((*ctx));
    *ctx = NULL;
}

int event_setup(event_ctx *ctx)
{
    assert(ctx);

    if (ctx->epoll_fd < 0)
        /* flags == 0 -> obsolete size arg is dropped */
        ctx->epoll_fd = epoll_create1(0);

    return ctx->epoll_fd < 0;
}

int event_add_sock(event_ctx *ctx, psocket *sock)
{
    int s;
    struct epoll_event ev = {0,{0}};

    assert(ctx && sock);

    ev.data.fd = sock->fd;
    ev.events = EPOLLIN /*| EPOLLET*/; /* EPOLLET: broken */
    s = epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, sock->fd, &ev);
    if (s)
        return 1;

    return 0;
}

int event_add_fd(event_ctx *ctx, int fd)
{
    int s;
    struct epoll_event ev = {0,{0}};

    assert(ctx);

    ev.data.fd = fd;
    ev.events = EPOLLIN | EPOLLET;
    s = epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev);
    if (s)
        return 1;

    return 0;
}

int event_loop(event_ctx *ctx, on_event_cb on_event, void *user_data)
{
    int n, i, saved_errno;
    char ev_err[16];
    sigset_t eset;

    assert(ctx && on_event);
    sigemptyset(&eset);
    ctx->active = 1;
    ctx->has_error = 0;

    while (ctx->active && !ctx->has_error) {
        errno = 0;
        n = epoll_pwait(ctx->epoll_fd, ctx->events, POTD_MAXEVENTS, -1, &eset);
        saved_errno = errno;
        if (errno == EINTR)
            continue;
        if (n < 0) {
            ctx->has_error = 1;
            break;
        }

        for (i = 0; i < n; ++i) {
            ctx->current_event = i;

            if ((ctx->events[i].events & EPOLLERR) ||
                (ctx->events[i].events & EPOLLHUP) ||
                (ctx->events[i].events & EPOLLRDHUP) ||
                (!(ctx->events[i].events & EPOLLIN)))
            {
                if (epoll_event_string(ctx->events[i].events, ev_err, sizeof ev_err)) {
                    errno = saved_errno;
                    E_STRERR("Event for descriptor %d",
                        ctx->events[i].data.fd);
                } else {
                    errno = saved_errno;
                    E_STRERR("Event [%s] for descriptor %d",
                        ev_err, ctx->events[i].data.fd);
                }

                ctx->has_error = 1;
            } else {
                if (!on_event(ctx, ctx->events[i].data.fd, user_data) && !ctx->has_error)
                    W2("Event callback failed: [fd: %d , npoll: %d]",
                        ctx->events[i].data.fd, n);
            }

            if (!ctx->active || ctx->has_error)
                break;
        }
    }

    return ctx->has_error != 0;
}

forward_state
event_forward_connection(event_ctx *ctx, int dest_fd, on_data_cb on_data,
                         void *user_data)
{
    int data_avail = 1;
    int has_input;
    int saved_errno;
    forward_state rc = CON_OK;
    ssize_t siz;
    char buf[BUFSIZ];
    struct epoll_event *ev;

    assert(ctx->current_event >= 0 &&
        ctx->current_event < POTD_MAXEVENTS);
    ev = &ctx->events[ctx->current_event];

    while (data_avail) {
        has_input = 0;
        saved_errno = 0;
        siz = -1;

        if (ev->events & EPOLLIN) {
            has_input = 1;
            errno = 0;
            siz = read(ev->data.fd, &buf[0], BUFSIZ);
            saved_errno = errno;
        } else break;
        if (saved_errno == EAGAIN)
            break;

        switch (siz) {
            case -1:
                E_STRERR("Client read from fd %d", ev->data.fd);
                ctx->has_error = 1;
                rc = CON_IN_ERROR;
                break;
            case 0:
                rc = CON_IN_TERMINATED;
                break;
            default:
                D2("Read %zu bytes from fd %d", siz, ev->data.fd);
                break;
        }

        if (rc != CON_OK)
            break;

        if (on_data &&
            on_data(ctx, ev->data.fd, dest_fd, buf, siz, user_data))
        {
            W2("On data callback failed, not forwarding from %d to %d",
                ev->data.fd, dest_fd);
            continue;
        }

        if (has_input) {
            errno = 0;
            siz = write(dest_fd, &buf[0], siz);

            switch (siz) {
                case -1:
                    ctx->has_error = 1;
                    rc = CON_OUT_ERROR;
                    break;
                case 0:
                    rc = CON_OUT_TERMINATED;
                    break;
                default:
                    D2("Written %zu bytes from fd %d to fd %d",
                        siz, ev->data.fd, dest_fd);
                    break;
            }
        }

        if (rc != CON_OK)
            break;
    }

    D2("Connection state: %d", rc);
    if (rc != CON_OK) {
        shutdown(ev->data.fd, SHUT_RDWR);
        shutdown(dest_fd, SHUT_RDWR);
    }
    return rc;
}
