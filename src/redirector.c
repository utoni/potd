/*
 * redirector.c
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
#include <pthread.h>
#include <semaphore.h>
#include <time.h>
#include <sys/mman.h>
#include <assert.h>

#include "redirector.h"
#include "socket.h"
#include "utils.h"
#include "log.h"

#define MAX_SESSIONS 3

typedef struct client_thread {
    pthread_t self;
    psocket client_sock;
    char host_buf[NI_MAXHOST], service_buf[NI_MAXSERV];
    redirector_ctx *rdr_ctx;
    sem_t *sessions_sem;
} client_thread;

typedef struct server_event {
    redirector_ctx **rdr_ctx;
    size_t siz;
    size_t last_accept_count;
    time_t last_accept_stamp;
    sem_t sessions_sem;
} server_event;

typedef struct client_event {
    const psocket *fwd_sock;
    const client_thread *client_args;
} client_event;

static forward_state
fwd_state_string(const forward_state c_state, const client_thread *args,
                 const psocket *fwd);
static int
redirector_mainloop(event_ctx **ev_ctx, redirector_ctx *rdr_ctx[], size_t siz)
    __attribute__((noreturn));
static int redirector_accept_client(event_ctx *ev_ctx, int src_fd,
                                    void *user_data);
static void *
client_mainloop(void *arg);
static int client_io(event_ctx *ev_ctx, int src_fd, void *user_data);

static pthread_attr_t pattr;


int redirector_init_ctx(redirector_ctx **ctx)
{
    forward_ctx *fwd;

    assert(ctx);
    if (!*ctx)
        *ctx = (redirector_ctx *) malloc(sizeof(**ctx));
    assert(*ctx);

    memset(*ctx, 0, sizeof(**ctx));
    fwd = &(*ctx)->fwd_ctx;
    if (fwd_init_ctx(&fwd))
        return 1;

    if (pthread_attr_init(&pattr))
        return 1;
    /* BUG: Do not use pthread_detach in pthread routine! */
    if (pthread_attr_setdetachstate(&pattr, PTHREAD_CREATE_DETACHED))
        return 1;

    return 0;
}

void redirector_free_ctx(redirector_ctx **rdr_ctx)
{
    assert(rdr_ctx && *rdr_ctx);

    socket_close(&(*rdr_ctx)->fwd_ctx.sock);
    socket_close(&(*rdr_ctx)->sock);
    free(*rdr_ctx);
    (*rdr_ctx) = NULL;
}

int redirector_setup(redirector_ctx *ctx,
                 const char *listen_addr, const char *listen_port,
                 const char *host, const char *port)
{
    int s;
    struct addrinfo *srv_addr = NULL;

    assert(ctx);
    assert(listen_port);

    if (!listen_addr)
        listen_addr = "0.0.0.0";
    D2("Try to listen on %s:%s and forward to %s:%s",
       (listen_addr ? listen_addr : "*"), listen_port,
       host, port);
    s = socket_init_in(listen_addr, listen_port, &srv_addr);
    if (s) {
        E_GAIERR(s, "Could not initialise server socket");
        return 1;
    }
    if (socket_bind_in(&ctx->sock, &srv_addr)) {
        E_STRERR("Could not bind server socket to %s:%s",
            listen_addr, listen_port);
        return 1;
    }
    if (socket_listen_in(&ctx->sock)) {
        E_STRERR("Could not listen on server socket on %s:%s",
            listen_addr, listen_port);
        return 1;
    }

    if (fwd_setup_client(&ctx->fwd_ctx, host, port))
        return 1;
    if (fwd_validate_ctx(&ctx->fwd_ctx))
        return 1;

    return 0;
}

int redirector_validate_ctx(const redirector_ctx *ctx)
{
    assert(ctx);
    assert(ctx->sock.fd >= 0 && ctx->sock.addr_len > 0);

    return 0;
}

int redirector_setup_event(redirector_ctx *rdr_ctx[], size_t siz, event_ctx **ev_ctx)
{
    int s;

    assert(rdr_ctx && ev_ctx);
    assert(siz > 0 && siz < POTD_MAXFD);

    event_init(ev_ctx);
    if (event_setup(*ev_ctx))
        return 1;

    for (size_t i = 0; i < siz; ++i) {
        if (event_add_sock(*ev_ctx, &rdr_ctx[i]->sock, NULL)) {
            return 1;
        }

        s = socket_addrtostr_in(&rdr_ctx[i]->sock,
                                rdr_ctx[i]->host_buf, rdr_ctx[i]->service_buf);
        if (s) {
            E_GAIERR(s, "Convert socket address to string");
            return 1;
        }
        N("Redirector service listening on %s:%s",
          rdr_ctx[i]->host_buf, rdr_ctx[i]->service_buf);
    }

    return 0;
}

pid_t redirector_daemonize(event_ctx **ev_ctx, redirector_ctx *rdr_ctx[], size_t siz)
{
    pid_t p;
    int s;
    size_t i;

    assert(rdr_ctx && ev_ctx);
    assert(siz > 0 && siz < POTD_MAXFD); 

    for (i = 0; i < siz; ++i) {
        assert(rdr_ctx[i]);
        s = socket_addrtostr_in(&rdr_ctx[i]->sock,
            rdr_ctx[i]->host_buf,
            rdr_ctx[i]->service_buf);
        if (s) {
            E_GAIERR(s, "Could not initialise server daemon socket");
            return 1;
        }
    }

    p = fork();
    switch (p) {
        case -1:
            W_STRERR("%s", "Server daemonize");
            return -1;
        case 0:
            if (change_default_user_group()) {
                E_STRERR("%s", "Change user/group");
                return -1;
            }
            N("%s", "Server daemon mainloop");
            redirector_mainloop(ev_ctx, rdr_ctx, siz);
    }
    D2("Server daemon pid: %d", p);

    event_free(ev_ctx);
    for (i = 0; i < siz; ++i)
        redirector_free_ctx(&rdr_ctx[i]);

    return p;
}

static forward_state
fwd_state_string(const forward_state c_state, const client_thread *args,
                 const psocket *fwd)
{
    switch (c_state) {
        case CON_OK:
            break;
        case CON_IN_ERROR:
            N("Lost connection to %s:%s: %d",
                args->host_buf, args->service_buf,
                args->client_sock.fd);
            break;
        case CON_IN_TERMINATED:
            N("Connection terminated: %s:%s: %d",
                args->host_buf, args->service_buf,
                args->client_sock.fd);
            break;
        case CON_OUT_ERROR:
            N("Lost forward connection to %s:%s: %d",
                args->rdr_ctx->fwd_ctx.host_buf,
                args->rdr_ctx->fwd_ctx.service_buf,
                fwd->fd);
            break;
        case CON_OUT_TERMINATED:
            N("Forward connection terminated: %s:%s: %d",
                args->rdr_ctx->fwd_ctx.host_buf,
                args->rdr_ctx->fwd_ctx.service_buf,
                fwd->fd);
            break;
    }

    return c_state;
}

static int redirector_mainloop(event_ctx **ev_ctx, redirector_ctx *rdr_ctx[], size_t siz)
{
    int rc;
    server_event *ev_srv;

    set_procname("[potd] redirector");
    assert( set_child_sighandler() == 0 );

    ev_srv = (server_event *) mmap(NULL, sizeof *ev_srv, PROT_READ|PROT_WRITE,
                                   MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    assert( ev_srv );
    memset(ev_srv, 0, sizeof *ev_srv);
    ev_srv->rdr_ctx = rdr_ctx;
    ev_srv->siz = siz;
    ev_srv->last_accept_stamp = time(NULL);
    assert( !sem_init(&ev_srv->sessions_sem, 1, MAX_SESSIONS) );
    rc = event_loop(*ev_ctx, redirector_accept_client, ev_srv);
    event_free(ev_ctx);
    sem_destroy(&ev_srv->sessions_sem);
    munmap(ev_srv, sizeof *ev_srv);

    exit(rc);
}

static int redirector_accept_client(event_ctx *ev_ctx, int src_fd,
                                    void *user_data)
{
    size_t i;
    double d;
    int s;
    time_t t;
    server_event *ev_srv;
    client_thread *args;
    redirector_ctx *rdr_ctx;

    (void) ev_ctx;
    assert(ev_ctx && user_data);
    ev_srv = (server_event *) user_data;

    for (i = 0; i < ev_srv->siz; ++i) {
        rdr_ctx = ev_srv->rdr_ctx[i];
        if (rdr_ctx->sock.fd == src_fd) {
            args = (client_thread *) calloc(1, sizeof(*args));
            assert(args);

            if (socket_accept_in(&rdr_ctx->sock,
                    &args->client_sock))
            {
                E_STRERR("Could not accept client connection on fd %d",
                    rdr_ctx->sock.fd);
                goto error;
            }

            /* DDoS protection */
            ev_srv->last_accept_count++;
            t = time(NULL);
            d = difftime(t, ev_srv->last_accept_stamp);
            if (d == 0.0f)
                d = 1.0f;
            if (d > 5.0f) {
                ev_srv->last_accept_stamp = t;
                ev_srv->last_accept_count = 0;
            }
            if (ev_srv->last_accept_count / (size_t)d > 3) {
                W2("DDoS protection: Got %zu accepts/s",
                    ev_srv->last_accept_count / (size_t)d);
                goto error;
            }

            /* Max session limit */
            if (sem_trywait(&ev_srv->sessions_sem)) {
                W2("Session limit reached: %d", MAX_SESSIONS);
                goto error;
            }

            args->rdr_ctx = rdr_ctx;
            args->sessions_sem = &ev_srv->sessions_sem;
            s = socket_addrtostr_in(&args->client_sock,
                                    args->host_buf, args->service_buf);
            if (s) {
                E_GAIERR(s, "Convert socket address to string");
                goto error_sempost;
            }
            N2("New connection from %s:%s to %s:%s: %d",
                args->host_buf, args->service_buf,
                rdr_ctx->host_buf, rdr_ctx->service_buf,
                args->client_sock.fd);

            if (pthread_create(&args->self, &pattr,
                               client_mainloop, args))
            {
                E_STRERR("Thread creation for %s:%s on fd %d",
                    args->host_buf, args->service_buf,
                    args->client_sock.fd);
                goto error_sempost;
            }

            return 1;
error_sempost:
            sem_post(&ev_srv->sessions_sem);
error:
            socket_close(&args->client_sock);
            free(args);
            return 0;
        }
    }

    return 0;
}

static void *
client_mainloop(void *arg)
{
    client_thread *args;
    client_event ev_cli;
    int s;
    event_ctx *ev_ctx = NULL;
    psocket fwd;

    assert(arg);
    args = (client_thread *) arg;

    event_init(&ev_ctx);
    if (event_setup(ev_ctx)) {
        E_STRERR("Client event context creation for server fd %d",
            args->rdr_ctx->sock.fd);
        goto finish;
    }

    if (fwd_connect_sock(&args->rdr_ctx->fwd_ctx, &fwd)) {
        E_STRERR("Forward connection to %s:%s server fd %d",
            args->rdr_ctx->fwd_ctx.host_buf,
            args->rdr_ctx->fwd_ctx.service_buf,
            args->rdr_ctx->sock.fd);
        goto finish;
    }
    N("Forwarding connection from %s:%s to %s:%s forward fd %d",
        args->host_buf, args->service_buf,
        args->rdr_ctx->fwd_ctx.host_buf,
        args->rdr_ctx->fwd_ctx.service_buf, fwd.fd);

    if (event_add_sock(ev_ctx, &fwd, NULL)) {
        E_STRERR("Forward event context add to %s:%s forward fd %d",
            args->rdr_ctx->fwd_ctx.host_buf,
            args->rdr_ctx->fwd_ctx.service_buf, fwd.fd);
        goto finish;
    }

    /*
     * We got the client socket from our main thread, so fd flags like
     * O_NONBLOCK are not inherited!
     */
    s = socket_nonblock(&args->client_sock);
    if (s) {
        E_STRERR("Socket non blocking mode to %s:%s forward fd %d",
            args->rdr_ctx->fwd_ctx.host_buf,
            args->rdr_ctx->fwd_ctx.service_buf, fwd.fd);
        goto finish;
    }
    if (event_add_sock(ev_ctx, &args->client_sock, NULL)) {
        E_STRERR("Forward event context add to %s:%s forward fd %d",
	        args->rdr_ctx->fwd_ctx.host_buf,
            args->rdr_ctx->fwd_ctx.service_buf, fwd.fd);
        goto finish;
    }

    ev_cli.client_args = args;
    ev_cli.fwd_sock = &fwd;
    if (event_loop(ev_ctx, client_io, &ev_cli) && ev_ctx->has_error)
        E_STRERR("Forward connection data from %s:%s to %s:%s",
            args->host_buf, args->service_buf,
            args->rdr_ctx->fwd_ctx.host_buf,
            args->rdr_ctx->fwd_ctx.service_buf);

finish:
    sem_post(args->sessions_sem);
    event_free(&ev_ctx);
    socket_close(&fwd);
    socket_close(&args->client_sock);
    free(args);
    return NULL;
}

static int
client_io(event_ctx *ev_ctx, int src_fd, void *user_data)
{
    int dest_fd;
    client_event *ev_cli = (client_event *) user_data;
    const psocket *client_sock = &ev_cli->client_args->client_sock;
    forward_state fwd_state;

    if (src_fd == ev_cli->fwd_sock->fd) {
        dest_fd = client_sock->fd;
    } else if (src_fd == client_sock->fd) {
        dest_fd = ev_cli->fwd_sock->fd;
    } else return 0;

    fwd_state = event_forward_connection(ev_ctx, dest_fd, NULL, NULL);

    switch (fwd_state_string(fwd_state, ev_cli->client_args,
                             ev_cli->fwd_sock))
    {
        case CON_IN_TERMINATED:
        case CON_OUT_TERMINATED:
            ev_ctx->active = 0;
        case CON_OK:
            return 1;
        case CON_IN_ERROR:
        case CON_OUT_ERROR:
            ev_ctx->active = 0;
            return 0;
    }

    return 1;
}
