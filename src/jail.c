#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <signal.h>
#include <pty.h>
#include <sys/signalfd.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <assert.h>

#include "jail.h"
#include "socket.h"
#include "pseccomp.h"
#include "capabilities.h"
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
    psocket *client_sock;
    char *host_buf;
    char *service_buf;
    int tty_fd;
    int signal_fd;
    char tty_logbuf[BUFSIZ];
    size_t off_logbuf;
    char *tty_logbuf_escaped;
    size_t tty_logbuf_size;
} client_event;

static int jail_mainloop(event_ctx **ev_ctx, const jail_ctx *ctx[], size_t siz)
    __attribute__((noreturn));
static int jail_accept_client(event_ctx *ev_ctx, int fd, void *user_data);
static int jail_childfn(prisoner_process *ctx)
    __attribute__((noreturn));
static int jail_socket_tty(prisoner_process *ctx, int tty_fd);
static int jail_socket_tty_io(event_ctx *ev_ctx, int src_fd, void *user_data);
static int jail_log_input(event_ctx *ev_ctx, int src_fd, int dst_fd,
                          char *buf, size_t siz, void *user_data);


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
        if (event_add_sock(*ev_ctx, &ctx[i]->fwd_ctx.sock)) {
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

static int jail_accept_client(event_ctx *ev_ctx, int fd, void *user_data)
{
    size_t i, rc = 0;
    int s;
    pid_t prisoner_pid;
    server_event *ev_jail = (server_event *) user_data;
    static prisoner_process *args;
    const jail_ctx *jail_ctx;

    (void) ev_ctx;
    assert(ev_jail);

    for (i = 0; i < ev_jail->siz; ++i) {
        jail_ctx = ev_jail->jail_ctx[i];
        if (jail_ctx->fwd_ctx.sock.fd == fd) {
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
    const char *path_dev = "/dev";
    const char *path_devpts = "/dev/pts";
    const char *path_proc = "/proc";
    const char *path_shell = "/bin/sh";
    int i, s, master_fd;
    int unshare_flags = CLONE_NEWUTS|CLONE_NEWPID|CLONE_NEWIPC|
        CLONE_NEWNS/*|CLONE_NEWUSER*/;
    //unsigned int ug_map[3] = { 0, 10000, 65535 };
    pid_t self_pid, child_pid;
    pseccomp_ctx *psc = NULL;

    assert(ctx);
    self_pid = getpid();
    set_procname("[potd] jail-client");
    if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0)
        FATAL("Jail child prctl for pid %d", self_pid);

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
    //caps_drop_all();

    D2("Unshare prisoner %d", self_pid);
    if (unshare(unshare_flags))
        FATAL("Unshare prisoner %d", self_pid);

    D2("Safe change root to: '%s'", ctx->newroot);
    if (safe_chroot(ctx->newroot))
        FATAL("Safe jail chroot to '%s' failed", ctx->newroot);

    D2("Mounting rootfs to '%s'", ctx->newroot);
    mount_root();

    D2("Checking Shell '%s%s'", ctx->newroot, path_shell);
    if (access(path_shell, R_OK|X_OK))
        FATAL("Shell '%s%s' is not accessible", ctx->newroot, path_shell);

    D2("Mounting devtmpfs to '%s%s'", ctx->newroot, path_dev);
    s = mkdir(path_dev, S_IRUSR|S_IWUSR|S_IXUSR|
                        S_IRGRP|S_IXGRP|
                        S_IROTH|S_IXOTH);
    if (s && errno != EEXIST)
        FATAL("Create directory '%s'", path_dev);
    if (!path_is_mountpoint(path_dev) && mount_dev(path_dev))
        FATAL("Mount devtmpfs to '%s%s'", ctx->newroot, path_dev);

    D2("Mounting devpts to '%s%s'", ctx->newroot, path_devpts);
    s = mkdir(path_devpts, S_IRUSR|S_IWUSR|S_IXUSR|
                           S_IRGRP|S_IXGRP|
                           S_IROTH|S_IXOTH);
    if (s && errno != EEXIST)
        FATAL("Create directory '%s'", path_devpts);
    if (!path_is_mountpoint(path_devpts) && mount_pts(path_devpts))
        FATAL("Mount devpts to '%s%s'", ctx->newroot, path_devpts);

    D2("Mounting proc to '%s%s'", ctx->newroot, path_proc);
    s = mkdir(path_proc, S_IRUSR|S_IWUSR|S_IXUSR|
                         S_IRGRP|S_IXGRP|
                         S_IROTH|S_IXOTH);
    if (s && errno != EEXIST)
        FATAL("Create directory '%s'", path_proc);

    D2("Creating device files in '%s%s'", ctx->newroot, path_dev);
    if (create_device_files(path_dev))
        FATAL("Device file creation failed for rootfs '%s%s'",
            ctx->newroot, path_dev);

    D2("Forking a new pty process for "
       "parent %d", self_pid);
    child_pid = forkpty(&master_fd, NULL, NULL, NULL);
    switch (child_pid) {
        case -1:
            FATAL("Forking a new process for the slave tty from "
                "parent pty with pid %d",
                self_pid);
            break;
        case 0:
            if (mount_proc(path_proc))
                exit(EXIT_FAILURE);
            socket_set_ifaddr(&ctx->client_psock, "lo", "127.0.0.1", "255.0.0.0");
/*
            if (update_setgroups_self(0))
                exit(EXIT_FAILURE);
            if (update_guid_map(getpid(), ug_map, 0))
                exit(EXIT_FAILURE);
            if (update_guid_map(getpid(), ug_map, 1))
                exit(EXIT_FAILURE);
*/
            if (close_fds_except(0, 1, 2, -1))
                exit(EXIT_FAILURE);

            if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0)
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

            pseccomp_set_immutable();
            pseccomp_init(&psc,
                (getopt_used(OPT_SECCOMP_MINIMAL) ? PS_MINIMUM : 0));
            if (pseccomp_jail_rules(psc))
                FATAL("%s", "SECCOMP: adding jail rules");
            pseccomp_free(&psc);

            sethostname("openwrt", SIZEOF("openwrt"));
            if (execl(path_shell, path_shell, (char *) NULL))
                exit(EXIT_FAILURE);
            break;
        default:
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
    static client_event ev_cli = {NULL, NULL, NULL, -1, -1, {0}, 0, 0, 0};
    int s, rc = 1;
    event_ctx *ev_ctx = NULL;
    sigset_t mask;

    assert(ctx);
    ev_cli.tty_fd = tty_fd;

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
    if (event_add_sock(ev_ctx, &ctx->client_psock)) {
        E_STRERR("Jail event context for socket %s:%s",
            ctx->host_buf, ctx->service_buf);
        goto finish;
    }
    if (event_add_fd(ev_ctx, tty_fd)) {
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
    if (event_add_fd(ev_ctx, ev_cli.signal_fd)) {
        E_STRERR("Jail SIGNAL fd %d", ev_cli.signal_fd);
        goto finish;
    }

    ev_cli.client_sock = &ctx->client_psock;
    ev_cli.host_buf = &ctx->host_buf[0];
    ev_cli.service_buf = &ctx->service_buf[0];
    rc = event_loop(ev_ctx, jail_socket_tty_io, &ev_cli);
finish:
    close(ev_cli.signal_fd);
    event_free(&ev_ctx);
    return rc;
}

static int
jail_socket_tty_io(event_ctx *ev_ctx, int src_fd, void *user_data)
{
    int dest_fd;
    client_event *ev_cli = (client_event *) user_data;
    forward_state fwd_state;

    (void) ev_ctx;
    (void) src_fd;
    (void) ev_cli;

    if (src_fd == ev_cli->client_sock->fd) {
        dest_fd = ev_cli->tty_fd;
    } else if (src_fd == ev_cli->tty_fd) {
        dest_fd = ev_cli->client_sock->fd;
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

static int jail_log_input(event_ctx *ev_ctx, int src_fd, int dst_fd,
                          char *buf, size_t siz, void *user_data)
{
    size_t idx = 0, slen, ssiz = siz;
    client_event *ev_cli = (client_event *) user_data;

    (void) ev_ctx;
    (void) src_fd;

    if (ev_cli->tty_fd == dst_fd) {
        while (ssiz > 0) {
            slen = MIN(sizeof(ev_cli->tty_logbuf) - ev_cli->off_logbuf, ssiz);
            if (slen == 0) {
                escape_ascii_string(ev_cli->tty_logbuf, ev_cli->off_logbuf,
                                    &ev_cli->tty_logbuf_escaped, &ev_cli->tty_logbuf_size);
                C("[%s:%s] %s", ev_cli->host_buf, ev_cli->service_buf,
                    ev_cli->tty_logbuf_escaped);
                ev_cli->off_logbuf = 0;
                ev_cli->tty_logbuf[0] = 0;
                continue;
            }
            strncat(ev_cli->tty_logbuf, buf+idx, slen);
            ssiz -= slen;
            idx += slen;
            ev_cli->off_logbuf += slen;
        }
        if (buf[siz-1] == '\r' || buf[siz-1] == '\n') {
            escape_ascii_string(ev_cli->tty_logbuf, ev_cli->off_logbuf,
                                &ev_cli->tty_logbuf_escaped, &ev_cli->tty_logbuf_size);
            C("[%s:%s] %s", ev_cli->host_buf, ev_cli->service_buf,
                ev_cli->tty_logbuf_escaped);
            ev_cli->off_logbuf = 0;
            ev_cli->tty_logbuf[0] = 0;
        }
    }

    return 0;
}
