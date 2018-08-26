/*
 * jail.c
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <signal.h>
#include <pty.h>
#include <utmp.h>
#include <limits.h>
#ifdef HAVE_SECUREBITS_AMBIENT
#include <linux/securebits.h>
#endif
#include <sys/signalfd.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <assert.h>

#include "jail.h"
#include "jail_packet.h"
#include "socket.h"
#ifdef HAVE_SECCOMP
#include "pseccomp.h"
#endif
#include "capabilities.h"
#include "filesystem.h"
#include "utils.h"
#include "log.h"
#include "options.h"

typedef struct prisoner_process {
    psocket client_psock;
    char host_buf[NI_MAXHOST], service_buf[NI_MAXSERV];
    char *newroot;
} prisoner_process;

typedef struct server_event {
    const jail_ctx **jail_ctx;
    const size_t siz;
} server_event;

typedef struct client_event {
    jail_con connection;
    char *host_buf;
    char *service_buf;
    int signal_fd;
    char tty_logbuf[BUFSIZ];
    size_t off_logbuf;
    char *tty_logbuf_escaped;
    size_t tty_logbuf_size;
} client_event;

static int jail_mainloop(event_ctx **ev_ctx, const jail_ctx *ctx[], size_t siz)
    __attribute__((noreturn));
static int jail_accept_client(event_ctx *ev_ctx, int src_fd,
                              void *user_data);
static int jail_childfn(prisoner_process *ctx)
    __attribute__((noreturn));
static int jail_socket_tty(prisoner_process *ctx, int tty_fd);


void jail_init_ctx(jail_ctx **ctx, size_t stacksize)
{
    assert(ctx);
    if (stacksize > MAX_STACKSIZE ||
        stacksize < MIN_STACKSIZE)
    {
        stacksize = MAX_STACKSIZE;
    }
    if (!*ctx)
        *ctx = (jail_ctx *) malloc(sizeof(**ctx));
    assert(*ctx);

    memset(*ctx, 0, sizeof(**ctx));
    (*ctx)->stacksize = stacksize;
    (*ctx)->stack_ptr = calloc(1, (*ctx)->stacksize);
    (*ctx)->stack_beg =
        (unsigned char *) (*ctx)->stack_ptr
            + (*ctx)->stacksize;
}

int jail_setup(jail_ctx *ctx,
               const char *listen_addr, const char *listen_port)
{
    assert(ctx);
    assert(listen_addr || listen_port);

    D2("Try to listen on %s:%s",
       (listen_addr ? listen_addr : "*"), listen_port);
    if (fwd_setup_server(&ctx->fwd_ctx, listen_addr, listen_port))
        return 1;
    if (fwd_listen_sock(&ctx->fwd_ctx, NULL))
        return 1;

    return 0;
}

int jail_validate_ctx(const jail_ctx *ctx)
{
    assert(ctx);
    assert(ctx->fwd_ctx.sock.addr_len > 0);
    assert(ctx->stack_ptr);
    assert(ctx->newroot);

    if (access(ctx->newroot, R_OK|X_OK)) {
        E_STRERR("new root directory access to '%s'", ctx->newroot);
        return 1;
    }

    return 0;
}

int jail_setup_event(jail_ctx *ctx[], size_t siz, event_ctx **ev_ctx)
{
    int s;

    assert(ctx);
    assert(siz > 0 && siz < POTD_MAXFD);

    event_init(ev_ctx);
    if (event_setup(*ev_ctx))
        return 1;

    for (size_t i = 0; i < siz; ++i) {
        if (event_add_sock(*ev_ctx, &ctx[i]->fwd_ctx.sock, NULL)) {
            return 1;
        }

        s = socket_addrtostr_in(&ctx[i]->fwd_ctx.sock,
                                ctx[i]->host_buf, ctx[i]->service_buf);
        if (s) {
            E_GAIERR(s, "Convert socket address to string");
            return -2;
        }
        N("Jail service listening on %s:%s",
            ctx[i]->host_buf, ctx[i]->service_buf);
    }

    return 0;
}

pid_t jail_daemonize(event_ctx **ev_ctx, jail_ctx *ctx[], size_t siz)
{
    pid_t p;
	int s;
	size_t i;

    assert(ev_ctx && *ev_ctx && ctx);
    assert(siz > 0 && siz <= POTD_MAXFD);

	for (i = 0; i < siz; ++i) {
        assert(ctx[i]);
        s = socket_addrtostr_in(&ctx[i]->fwd_ctx.sock,
                                ctx[i]->host_buf, ctx[i]->service_buf);
        if (s) {
            E_GAIERR(s, "Could not initialise jail daemon socket");
            return 1;
        }
    }

	p = fork();
	switch (p) {
        case -1:
            E_STRERR("%s", "Jail daemonize");
	        return -1;
        case 0:
            caps_jail_filter();
            jail_mainloop(ev_ctx, (const jail_ctx **) ctx, siz);
    }
    D2("Jail daemon pid: %d", p);

    event_free(ev_ctx);
    for (i = 0; i < siz; ++i)
        socket_close(&ctx[i]->fwd_ctx.sock);

    return p;
}

static int jail_mainloop(event_ctx **ev_ctx, const jail_ctx *ctx[], size_t siz)
{
    int rc;
    server_event ev_jail = { ctx, siz };

    set_procname("[potd] jail");
    assert( set_child_sighandler() == 0 );

    D2("%s", "Setup cgroups");
    if (cgroups_set())
        FATAL("%s", "Setup cgroups");

    rc = event_loop(*ev_ctx, jail_accept_client, &ev_jail);
    event_free(ev_ctx);

    exit(rc);
}

static int jail_accept_client(event_ctx *ev_ctx, int src_fd,
                              void *user_data)
{
    size_t i, rc = 0;
    int s;
    pid_t prisoner_pid;
    server_event *ev_jail;
    static prisoner_process *args;
    const jail_ctx *jail_ctx;

    (void) ev_ctx;
    assert(ev_ctx && user_data);
    ev_jail = (server_event *) user_data;

    for (i = 0; i < ev_jail->siz; ++i) {
        jail_ctx = ev_jail->jail_ctx[i];
        if (jail_ctx->fwd_ctx.sock.fd == src_fd) {
            args = (prisoner_process *) calloc(1, sizeof(*args));
            assert(args);
            args->newroot = jail_ctx->newroot;

            if (socket_accept_in(&jail_ctx->fwd_ctx.sock,
                    &args->client_psock))
            {
                E_STRERR("Could not accept client connection for fd %d",
                    args->client_psock.fd);
                goto error;
            }

            s = socket_addrtostr_in(&args->client_psock,
                                    args->host_buf, args->service_buf);
            if (s) {
                E_GAIERR(s, "Convert socket address to string");
                goto error;
            }
            N2("New connection from %s:%s to %s:%s: %d",
                args->host_buf, args->service_buf,
                jail_ctx->host_buf, jail_ctx->service_buf,
                args->client_psock.fd);

            prisoner_pid = fork();
            switch (prisoner_pid) {
                case -1:
                    W_STRERR("%s", "Jail client fork");
                    goto error;
                case 0:
                    jail_childfn(args);
            }
            N2("Jail prisoner pid %d", prisoner_pid);

            rc = 1;
error:
            socket_close(&args->client_psock);
            free(args);
            args = NULL;
            return rc;
        }
    }

    return rc;
}

static int jail_childfn(prisoner_process *ctx)
{
    char path[PATH_MAX];
    const char *path_dev = "/dev";
    const char *path_devpts = "/dev/pts";
    const char *path_proc = "/proc";
    const char *path_shell = "/bin/sh";
    int i, s, master_fd, slave_fd;
    int unshare_flags = CLONE_NEWUTS|CLONE_NEWPID|CLONE_NEWIPC|
        CLONE_NEWNS/*|CLONE_NEWUSER*/;
#if 0
    unsigned int ug_map[3] = { 0, 10000, 65535 };
#endif
    pid_t self_pid, child_pid;
#ifdef HAVE_SECCOMP
    pseccomp_ctx *psc = NULL;
#endif

    assert(ctx);
    self_pid = getpid();
    set_procname("[potd] jail-client");
    if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0)
        FATAL("%s", "Jail child setting deathsig");
#ifdef HAVE_SECUREBITS_AMBIENT
    if (prctl(PR_SET_SECUREBITS,
              SECBIT_NOROOT | SECBIT_NOROOT_LOCKED |
              SECBIT_NO_CAP_AMBIENT_RAISE | SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED))
        FATAL("%s", "Jail child setting securebits");
#endif
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        FATAL("%s", "Jail child setting no new privs");

    if (!ctx->newroot)
        FATAL("New root set for pid %d", self_pid);

    if (clearenv())
        FATAL("Clearing ENV for pid %d", self_pid);

    D2("Activating cgroups for pid %d", self_pid);
    if (cgroups_activate())
        FATAL("Activating cgroups for pid %d", self_pid);

    D2("Setup network namespace for pid %d", self_pid);
    if (switch_network_namespace("default"))
        if (setup_network_namespace("default"))
            FATAL("Setup network namespace for pid %d", self_pid);

    caps_drop_dac_override(0);

    D2("Unshare prisoner %d", self_pid);
    if (unshare(unshare_flags))
        FATAL("Unshare prisoner %d", self_pid);

    D2("Mounting rootfs to '%s'", ctx->newroot);
    mount_root();

    snprintf(path, sizeof path, "%s%s", ctx->newroot, path_shell);
    D2("Checking Shell '%s'", path);
    if (access(path, R_OK|X_OK))
        FATAL("Access to shell '%s'", path);

    snprintf(path, sizeof path, "%s%s", ctx->newroot, path_dev);
    D2("Mounting devtmpfs to '%s'", path);
    s = mkdir(path, S_IRUSR|S_IWUSR|S_IXUSR|
                    S_IRGRP|S_IXGRP|
                    S_IROTH|S_IXOTH);
    if (s && errno != EEXIST)
        FATAL("Create directory '%s'", path);
    if (!path_is_mountpoint(path) && mount_dev(path))
        FATAL("Mount devtmpfs to '%s'", path);

    snprintf(path, sizeof path, "%s%s", ctx->newroot, path_devpts);
    D2("Mounting devpts to '%s'", path);
    s = mkdir(path, S_IRUSR|S_IWUSR|S_IXUSR|
                    S_IRGRP|S_IXGRP|
                    S_IROTH|S_IXOTH);
    if (s && errno != EEXIST)
        FATAL("Create directory '%s'", path);
    if (!path_is_mountpoint(path) && mount_pts(path))
        FATAL("Mount devpts to '%s'", path);

    snprintf(path, sizeof path, "%s%s", ctx->newroot, path_proc);
    D2("Mounting proc to '%s'", path);
    s = mkdir(path, S_IRUSR|S_IWUSR|S_IXUSR|
                    S_IRGRP|S_IXGRP|
                    S_IROTH|S_IXOTH);
    if (s && errno != EEXIST)
        FATAL("Create directory '%s'", path);

    snprintf(path, sizeof path, "%s%s", ctx->newroot, path_dev);
    D2("Creating device files in '%s'", path);
    if (create_device_files(path))
        FATAL("Device file creation failed for rootfs '%s'", path);

    if (openpty(&master_fd, &slave_fd, NULL, NULL, NULL))
        FATAL("%s", "openpty");

    child_pid = fork();
    switch (child_pid) {
        case -1:
            close(master_fd);
            close(slave_fd);
            FATAL("Forking a new process for the slave tty from "
                "parent pty with pid %d",
                self_pid);
            break;
        case 0:
            fs_proc_sys(ctx->newroot);
            fs_disable_files(ctx->newroot);

            D2("Safe change root to: '%s'", ctx->newroot);
            if (safe_chroot(ctx->newroot))
            FATAL("Safe jail chroot to '%s' failed", ctx->newroot);

            fs_basic_fs();
            socket_set_ifaddr(&ctx->client_psock, "lo", "127.0.0.1", "255.0.0.0");
#if 0
            if (update_setgroups_self(0))
                exit(EXIT_FAILURE);
            if (update_guid_map(getpid(), ug_map, 0))
                exit(EXIT_FAILURE);
            if (update_guid_map(getpid(), ug_map, 1))
                exit(EXIT_FAILURE);
#endif
            close(master_fd);
            if (login_tty(slave_fd))
                exit(EXIT_FAILURE);

            if (close_fds_except(0, 1, 2, -1))
                exit(EXIT_FAILURE);

            if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0)
                exit(EXIT_FAILURE);

#ifdef HAVE_SECCOMP
            pseccomp_set_immutable();
            pseccomp_init(&psc,
                (getopt_used(OPT_SECCOMP_MINIMAL) ? PS_MINIMUM : 0));
            if (pseccomp_jail_rules(psc))
                FATAL("%s", "SECCOMP: adding jail rules");
            pseccomp_free(&psc);
#else
            /* libseccomp is not available, so drop at least all caps */
            W2("%s", "Compiled without libseccomp, dropping ALL capabilities");
            caps_drop_all();
#endif

            if (sethostname("openwrt", SIZEOF("openwrt")))
                exit(EXIT_FAILURE);
            printf("%s",
                "  _______                     ________        __\n"
                " |       |.-----.-----.-----.|  |  |  |.----.|  |_\n"
                " |   -   ||  _  |  -__|     ||  |  |  ||   _||   _|\n"
                " |_______||   __|_____|__|__||________||__|  |____|\n"
                "          |__| W I R E L E S S   F R E E D O M\n"
                " -----------------------------------------------------\n"
                " ATTITUDE ADJUSTMENT\n"
                " -----------------------------------------------------\n"
                "  * 1/4 oz Vodka      Pour all ingredients into mixing\n"
                "  * 1/4 oz Gin        tin with ice, strain into glass.\n"
                "  * 1/4 oz Amaretto\n"
                "  * 1/4 oz Triple sec\n"
                "  * 1/4 oz Peach schnapps\n"
                "  * 1/4 oz Sour mix\n"
                "  * 1 splash Cranberry juice\n"
                " -----------------------------------------------------\n"
            );
            /* Flawfinder: ignore */
            if (execl(path_shell, path_shell, (char *) NULL))
                exit(EXIT_FAILURE);
            break;
        default:
            close(slave_fd);
            if (set_fd_nonblock(master_fd)) {
                E_STRERR("Pty master fd nonblock for prisoner pid %d",
                    child_pid);
                goto finalise;
            }

            N("Socket to tty I/O for prisoner pid %d",
                child_pid);
            if (jail_socket_tty(ctx, master_fd))
                E_STRERR("Socket to tty I/O for prisoner pid %d",
                    child_pid);
            N("Killing prisoner pid %d", child_pid);

            kill(child_pid, SIGTERM);
            i = 10;
            while (i > 0 && waitpid(child_pid, &s, WNOHANG) > 0) {
                if (WIFEXITED(s))
                    break;
                usleep(250000);
                i--;
            }
            kill(child_pid, SIGKILL);
    }

finalise:
    close(master_fd);
    exit(EXIT_FAILURE);
}

static int jail_socket_tty(prisoner_process *ctx, int tty_fd)
{
    static client_event ev_cli = {{-1,-1}, NULL, NULL, -1, {0}, 0, NULL, 0};
    static jail_packet_ctx pkt_ctx =
        {0, 0, 1, EMPTY_JAILCON, EMPTY_BUF, JC_SERVER, JP_NONE, NULL, NULL};
    int s, rc = 1;
    event_ctx *ev_ctx = NULL;
    sigset_t mask;

    assert(ctx);

    event_init(&ev_ctx);
    if (event_setup(ev_ctx)) {
        E_STRERR("Jail event context creation for jail tty fd %d",
            tty_fd);
        goto finish;
    }
    s = socket_nonblock(&ctx->client_psock);
    if (s) {
        E_STRERR("Socket non blocking mode to client %s:%s fd %d",
            ctx->host_buf, ctx->service_buf, ctx->client_psock.fd);
        goto finish;
    }
    if (event_add_sock(ev_ctx, &ctx->client_psock, NULL)) {
        E_STRERR("Jail event context for socket %s:%s",
            ctx->host_buf, ctx->service_buf);
        goto finish;
    }
    if (event_add_fd(ev_ctx, tty_fd, NULL)) {
        E_STRERR("Jail event context for tty fd %d",
            tty_fd);
        goto finish;
    }

    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
        E_STRERR("%s", "SIGTERM block");
        goto finish;
    }
    ev_cli.signal_fd = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);
    if (ev_cli.signal_fd < 0) {
        E_STRERR("%s", "SIGNAL fd");
        goto finish;
    }
    if (event_add_fd(ev_ctx, ev_cli.signal_fd, NULL)) {
        E_STRERR("Jail SIGNAL fd %d", ev_cli.signal_fd);
        goto finish;
    }

    pkt_ctx.connection.client_fd = ev_cli.connection.client_fd = ctx->client_psock.fd;
    pkt_ctx.connection.jail_fd = ev_cli.connection.jail_fd = tty_fd;
    ev_cli.host_buf = &ctx->host_buf[0];
    ev_cli.service_buf = &ctx->service_buf[0];

    if (!jail_server_handshake(ev_ctx, &pkt_ctx) && pkt_ctx.is_valid) {
        N("Using Jail protocol for %s:%s",
            ctx->host_buf, ctx->service_buf);
        rc = jail_server_loop(ev_ctx, &pkt_ctx);
    } else {
        E("Jail protocol handshake failed for %s:%s",
            ctx->host_buf, ctx->service_buf);
    }
finish:
    event_free(&ev_ctx);
    return rc;
}

#if 0
static int
jail_socket_tty_io(event_ctx *ev_ctx, int src_fd, void *user_data)
{
    int dest_fd;
    client_event *ev_cli = (client_event *) user_data;
    forward_state fwd_state;

    (void) ev_ctx;
    (void) src_fd;
    (void) ev_cli;

    if (src_fd == ev_cli->connection.client_fd) {
        dest_fd = ev_cli->connection.jail_fd;
    } else if (src_fd == ev_cli->connection.jail_fd) {
        dest_fd = ev_cli->connection.client_fd;
    } else if (src_fd == ev_cli->signal_fd) {
        ev_ctx->active = 0;
        return 0;
    } else return 0;

    fwd_state = event_forward_connection(ev_ctx, dest_fd, jail_log_input,
                                         user_data);

    switch (fwd_state) {
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

static int jail_log_input(event_ctx *ev_ctx, event_buf *read_buf,
                          event_buf *write_buf, void *user_data)
{
    size_t idx = 0, slen, read_siz = read_buf->buf_used;
    client_event *ev_cli = (client_event *) user_data;

    (void) ev_ctx;

    if (ev_cli->connection.jail_fd == write_buf->fd) {
        while (read_siz > 0) {
            slen = MIN(sizeof(ev_cli->tty_logbuf) - ev_cli->off_logbuf, read_siz);
            if (slen == 0) {
                escape_ascii_string(ev_cli->tty_logbuf, ev_cli->off_logbuf,
                                    &ev_cli->tty_logbuf_escaped, &ev_cli->tty_logbuf_size);
                C("[%s:%s] %s", ev_cli->host_buf, ev_cli->service_buf,
                    ev_cli->tty_logbuf_escaped);
                ev_cli->off_logbuf = 0;
                ev_cli->tty_logbuf[0] = 0;
                continue;
            }
            strncat(ev_cli->tty_logbuf, read_buf->buf + idx, slen);
            read_siz -= slen;
            idx += slen;
            ev_cli->off_logbuf += slen;
        }
        if (read_buf->buf[read_buf->buf_used-1] == '\r' ||
            read_buf->buf[read_buf->buf_used-1] == '\n')
        {
            escape_ascii_string(ev_cli->tty_logbuf, ev_cli->off_logbuf,
                                &ev_cli->tty_logbuf_escaped, &ev_cli->tty_logbuf_size);
            C("[%s:%s] %s", ev_cli->host_buf, ev_cli->service_buf,
                ev_cli->tty_logbuf_escaped);
            ev_cli->off_logbuf = 0;
            ev_cli->tty_logbuf[0] = 0;
        }
    }

    event_buf_dup(read_buf, write_buf);

    return 0;
}
#endif
