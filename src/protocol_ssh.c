#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <poll.h>
#include <pwd.h>
#include <linux/limits.h>
#include <libssh/callbacks.h>
#include <libssh/server.h>

#include "protocol_ssh.h"
#include "protocol.h"
#ifdef HAVE_SECCOMP
#include "pseccomp.h"
#endif
#include "options.h"
#include "utils.h"
#include "log.h"

#if LIBSSH_VERSION_MAJOR != 0 || LIBSSH_VERSION_MINOR < 7 || \
    LIBSSH_VERSION_MICRO < 3
#pragma message "Unsupported libssh version < 0.7.3"
#endif

static int version_logged = 0;
static const char rsa_key_suf[] = "ssh_host_rsa_key";
static const char dsa_key_suf[] = "ssh_host_dsa_key";
static const char ecdsa_key_suf[] = "ssh_host_ecdsa_key";

typedef struct ssh_data {
    ssh_bind sshbind;
    protocol_ctx *ctx;
} ssh_data;

typedef struct ssh_client {
    ssh_channel chan;
    forward_ctx dst;
} ssh_client;

struct protocol_cbs potd_ssh_callbacks = {
    .on_listen = ssh_on_listen,
    .on_shutdown = ssh_on_shutdown
};

static int set_default_keys(ssh_bind sshbind, int rsa_already_set,
                            int dsa_already_set, int ecdsa_already_set);
static int gen_default_keys(void);
static int gen_export_sshkey(enum ssh_keytypes_e type, int length, const char *path);
static void ssh_log_cb(int priority, const char *function, const char *buffer, void *userdata);
static void ssh_mainloop(ssh_data *arg)
    __attribute__((noreturn));
static int authenticate(ssh_session session);
static int auth_password(const char *user, const char *password);
static int client_mainloop(ssh_client *arg);
static int copy_fd_to_chan(socket_t fd, int revents, void *userdata);
static int copy_chan_to_fd(ssh_session session, ssh_channel channel, void *data,
                           uint32_t len, int is_stderr, void *userdata);
static void chan_close(ssh_session session, ssh_channel channel, void *userdata);

struct ssh_channel_callbacks_struct ssh_channel_cb = {
    .channel_data_function = copy_chan_to_fd,
    .channel_eof_function = chan_close,
    .channel_close_function = chan_close,
    .userdata = NULL
};


int ssh_init_cb(protocol_ctx *ctx)
{
    if (!version_logged) {
        N("libssh version: %s", ssh_version(0));
        if (ssh_version(SSH_VERSION_INT(LIBSSH_VERSION_MAJOR,
                                        LIBSSH_VERSION_MINOR,
                                        LIBSSH_VERSION_MICRO)) == NULL)
        {
            W("This software was compiled/linked for libssh %d.%d.%d,"
              " which you aren't currently using.",
              LIBSSH_VERSION_MAJOR, LIBSSH_VERSION_MINOR, LIBSSH_VERSION_MICRO);
        }
        if (ssh_version(SSH_VERSION_INT(0,7,3)) == NULL)
        {
            W("%s", "Unsupported libssh version < 0.7.3");
        }
        if (ssh_version(SSH_VERSION_INT(0,7,4)) != NULL ||
            ssh_version(SSH_VERSION_INT(0,7,90)) != NULL)
        {
            W("%s",
              "libssh versions > 0.7.3 may suffer "
              "from problems with the pki key generation/export");
        }
        version_logged = 1;
    }

    ctx->cbs = potd_ssh_callbacks;

    if (ssh_init())
        return 1;

    ssh_data *d = (ssh_data *) calloc(1, sizeof(*d));
    assert(d);
    d->sshbind = ssh_bind_new();
    d->ctx = ctx;
    ctx->src.data = d;

    ssh_set_log_callback(ssh_log_cb);
    ssh_set_log_level(SSH_LOG_FUNCTIONS);

    if (!d->sshbind)
        return 1;
    if (ssh_bind_options_set(d->sshbind, SSH_BIND_OPTIONS_BANNER,
        "OpenSSH_7.4p1"))
    {
        return 1;
    }
    if (gen_default_keys())
        return 1;
    if (set_default_keys(d->sshbind, 0, 0, 0))
        return 1;

    return 0;
}

int ssh_on_listen(protocol_ctx *ctx)
{
    pid_t p;
    int s;
    ssh_data *d = (ssh_data *) ctx->src.data;
#ifdef HAVE_SECCOMP
    pseccomp_ctx *psc = NULL;
#endif

    if (ssh_bind_options_set(d->sshbind, SSH_BIND_OPTIONS_BINDADDR,
                             ctx->src.host_buf))
        return 1;
    if (ssh_bind_options_set(d->sshbind, SSH_BIND_OPTIONS_BINDPORT_STR,
                             ctx->src.service_buf))
        return 1;

    s = ssh_bind_listen(d->sshbind);
    if (s < 0) {
        E_STRERR("Error listening to SSH socket: %s", ssh_get_error(d->sshbind));
        return s;
    }
    N("SSH bind and listen on %s:%s fd %d", ctx->src.host_buf,
        ctx->src.service_buf, ssh_bind_get_fd(d->sshbind));

    socket_close(&ctx->src.sock);

    p = fork();
    switch (p) {
        case -1:
            E_STRERR("SSH protocol daemonize on %s:%s fd %d",
                ctx->src.host_buf, ctx->src.service_buf,
                ssh_bind_get_fd(d->sshbind));
            return 1;
        case 0:
#ifdef HAVE_SECCOMP
            pseccomp_set_immutable();
            pseccomp_init(&psc, PS_ALLOW|PS_MINIMUM);
            s = pseccomp_protocol_rules(psc);
            pseccomp_free(&psc);
#endif
            if (s) {
                E_STRERR("%s", "Could not add seccomp rules");
                return -1;
            }
            if (change_default_user_group()) {
                E_STRERR("%s", "Change user/group");
                return -1;
            }
            ssh_mainloop(d);
            break;
    }
    D2("SSH protocol pid: %d", p);
    ssh_on_shutdown(ctx);

    return s != 0;
}

int ssh_on_shutdown(protocol_ctx *ctx)
{
    ssh_data *d;

    assert(ctx->src.data);

    d = (ssh_data *) ctx->src.data;
    ssh_bind_free(d->sshbind);
    free(d);
    ctx->src.data = NULL;
    ssh_finalize();

    return 0;
}

static int set_default_keys(ssh_bind sshbind, int rsa_already_set,
                             int dsa_already_set, int ecdsa_already_set)
{
    char path[PATH_MAX];

    if (!rsa_already_set) {
        snprintf(path, sizeof path, "%s/%s", getopt_str(OPT_SSH_RUN_DIR),
            rsa_key_suf);
        D2("RSA key path: '%s'", path);
        if (access(path, R_OK)) {
            E_STRERR("RSA key '%s' inaccessible", path);
            return 1;
        }
        if (ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, path)) {
            E2("Faled to set RSA key: %s", ssh_get_error(sshbind));
            return 1;
        }
    }
    if (!dsa_already_set) {
        snprintf(path, sizeof path, "%s/%s", getopt_str(OPT_SSH_RUN_DIR),
            dsa_key_suf);
        D2("DSA key path: '%s'", path);
        if (access(path, R_OK)) {
            W_STRERR("Access DSA key '%s'", path);
        } else
        if (ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, path)) {
            E2("Failed to set DSA key: %s", ssh_get_error(sshbind));
            return 1;
        }
    }
    if (!ecdsa_already_set) {
        snprintf(path, sizeof path, "%s/%s", getopt_str(OPT_SSH_RUN_DIR),
            ecdsa_key_suf);
        D2("ECDSA key path: '%s'", path);
        if (access(path, R_OK)) {
            W_STRERR("Access ECDSA key '%s'", path);
        } else
        if (ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_ECDSAKEY, path)) {
            E2("Failed to set ECDSA key: %s", ssh_get_error(sshbind));
            return 1;
        }
    }
    return 0;
}

static int gen_default_keys(void)
{
    char path[PATH_MAX];
    char cmd[BUFSIZ];
    int s = 0;
    struct passwd *pwd;

    errno = 0;
    pwd = getpwnam(getopt_str(OPT_CHUSER));
    if (mkdir(getopt_str(OPT_SSH_RUN_DIR), R_OK|W_OK|X_OK) && errno == ENOENT) {
        if (chmod(getopt_str(OPT_SSH_RUN_DIR), S_IRWXU))
            return 1;
        if (!pwd)
            return 1;
        if (chown(getopt_str(OPT_SSH_RUN_DIR), pwd->pw_uid, pwd->pw_gid))
            return 1;
    }

    snprintf(path, sizeof path, "%s/%s", getopt_str(OPT_SSH_RUN_DIR),
        rsa_key_suf);
    if (gen_export_sshkey(SSH_KEYTYPE_RSA, 1024, path)) {
        W("libssh %s key generation failed, using fallback ssh-keygen", "RSA");
        remove(path);
        if (snprintf(cmd, sizeof cmd, "ssh-keygen -t rsa -b 1024 -f %s -N '' "
            ">/dev/null 2>/dev/null", path) > 0)
        {
            s |= system(cmd);
        } else s++;
    }
    chmod(path, S_IRWXU);
    if (pwd)
        chown(path, pwd->pw_uid, pwd->pw_gid);

    snprintf(path, sizeof path, "%s/%s", getopt_str(OPT_SSH_RUN_DIR),
        dsa_key_suf);
    if (gen_export_sshkey(SSH_KEYTYPE_DSS, 1024, path)) {
        W("libssh %s key generation failed, using fallback ssh-keygen", "DSA");
        remove(path);
        if (snprintf(cmd, sizeof cmd, "ssh-keygen -t dsa -b 1024 -f %s -N '' "
            ">/dev/null 2>/dev/null", path) > 0)
        {
            s |= system(cmd);
        } else s++;
    }
    chmod(path, S_IRWXU);
    if (pwd)
        chown(path, pwd->pw_uid, pwd->pw_gid);

    snprintf(path, sizeof path, "%s/%s", getopt_str(OPT_SSH_RUN_DIR),
        ecdsa_key_suf);
    if (gen_export_sshkey(SSH_KEYTYPE_ECDSA, 1024, path)) {
        W("libssh %s key generation failed, using fallback ssh-keygen", "ECDSA");
        remove(path);
        if (snprintf(cmd, sizeof cmd, "ssh-keygen -t ecdsa -b 256 -f %s -N '' "
            ">/dev/null 2>/dev/null", path) > 0)
        {
            s |= system(cmd);
        } else s++;
    }
    chmod(path, S_IRWXU);
    if (pwd)
        chown(path, pwd->pw_uid, pwd->pw_gid);

    return s != 0;
}

static int gen_export_sshkey(enum ssh_keytypes_e type, int length, const char *path)
{
    ssh_key priv_key;
    const char *type_str = NULL;
    int s;

    assert(path);
    assert(length == 1024 || length == 2048 ||
           length == 4096);

    switch (type) {
        case SSH_KEYTYPE_DSS:
            type_str = "DSS";
            break;
        case SSH_KEYTYPE_RSA:
            type_str = "RSA";
            break;
        case SSH_KEYTYPE_ECDSA:
            type_str = "ECDSA";
            break;
        default:
            W2("Unknown SSH key type: %d", type);
            return 1;
    }
    D2("Generating %s key with length %d bits and save it on disk: '%s'",
        type_str, length, path);
    s = ssh_pki_generate(type, length, &priv_key);
    if (s != SSH_OK) {
        W2("Generating %s key failed: %d", type_str, s);
        return 1;
    }
    s = ssh_pki_export_privkey_file(priv_key, "", NULL,
                                    NULL, path);
    ssh_key_free(priv_key);

    if (s != SSH_OK) {
        W2("SSH private key export to file failed: %d", s);
        return 1;
    }

    return 0;
}

static void ssh_log_cb(int priority, const char *function,
                       const char *buffer, void *userdata)
{
    (void) function;
    (void) userdata;

    switch (priority) {
        case 0:
            W("libssh: %s", buffer);
            break;
        case 1:
            N("libssh: %s", buffer);
            break;
        default:
            D("libssh: %s", buffer);
            break;
    }
}

static void ssh_mainloop(ssh_data *arg)
{
    int s, auth = 0, shell = 0, is_child;
    ssh_session ses;
    ssh_message message;
    ssh_channel chan = NULL;
    ssh_client data;

    assert(arg);
    set_procname("[potd] ssh");
    assert( set_child_sighandler() == 0 );

    while (1) {
        ses = ssh_new();
        assert(ses);

        s = ssh_bind_accept(arg->sshbind, ses);
        if (s == SSH_ERROR) {
            W("SSH error while accepting a connection: %s",
                    ssh_get_error(ses));
            goto failed;
        }

        switch (fork()) {
            case -1:
                is_child = 0;
                W_STRERR("%s", "Fork for SSH Client");
                break;
            case 0:
                set_procname("[potd] ssh-client");
                assert( set_child_sighandler() == 0 );
                is_child = 1;
                break;
            default:
                ssh_free(ses);
                is_child = 0;
                break;
        }
        if (!is_child)
            continue;

        if (ssh_handle_key_exchange(ses)) {
            W("SSH key exchange failed: %s", ssh_get_error(ses));
            goto failed;
        }

        /* proceed to authentication */
        auth = authenticate(ses);
        if (!auth) {
            W("SSH authentication error: %s", ssh_get_error(ses));
            goto failed;
        }

        /* wait for a channel session */
        do {
            message = ssh_message_get(ses);
            if (message) {
                if (ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN &&
                    ssh_message_subtype(message) == SSH_CHANNEL_SESSION)
                {
                    chan = ssh_message_channel_request_open_reply_accept(message);
                    ssh_message_free(message);
                    break;
                } else {
                    ssh_message_reply_default(message);
                    ssh_message_free(message);
                }
            } else {
                break;
            }
        } while (!chan);

        if (!chan) {
            W("SSH client did not ask for a channel session: %s",
                ssh_get_error(ses));
            goto failed;
        }

	    /* wait for a shell */
        do {
            message = ssh_message_get(ses);
            if (message != NULL) {
                if (ssh_message_type(message) == SSH_REQUEST_CHANNEL) {
                    if (ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_SHELL) {
                        shell = 1;
                        ssh_message_channel_request_reply_success(message);
                        ssh_message_free(message);
                        break;
                    } else if (ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_PTY) {
                        ssh_message_channel_request_reply_success(message);
                        ssh_message_free(message);
                        continue;
                    }
                }
                ssh_message_reply_default(message);
                ssh_message_free(message);
            } else {
                break;
            }
        } while (!shell);

        if (!shell) {
            W("SSH client had no shell requested: %s", ssh_get_error(ses));
            goto failed;
        }

        N("%s", "Dropping user into shell");

        data.chan = chan;
        data.dst = arg->ctx->dst;
        if (client_mainloop(&data))
            W2("Client mainloop for fd %d failed",
                ssh_bind_get_fd(arg->sshbind));

failed:
        ssh_disconnect(ses);
        ssh_free(ses);
        exit(EXIT_SUCCESS);
    }
}

static int authenticate(ssh_session session)
{
    ssh_message message;

    do {
        message = ssh_message_get(session);
        if (!message)
            break;

        switch (ssh_message_type(message)) {

            case SSH_REQUEST_AUTH:
                switch (ssh_message_subtype(message)) {
                    case SSH_AUTH_METHOD_PASSWORD:
                        N("SSH: user '%s' wants to auth with pass '%s'",
                            ssh_message_auth_user(message),
                            ssh_message_auth_password(message));
                        if (auth_password(ssh_message_auth_user(message),
                            ssh_message_auth_password(message)))
                        {
                            ssh_message_auth_reply_success(message,0);
                            ssh_message_free(message);
                            return 1;
                        }
                        ssh_message_auth_set_methods(message,
                            SSH_AUTH_METHOD_PASSWORD |
                            SSH_AUTH_METHOD_INTERACTIVE);
                        /* not authenticated, send default message */
                        ssh_message_reply_default(message);
                        break;

                    case SSH_AUTH_METHOD_NONE:
                    default:
                        N("SSH: User '%s' wants to auth with unknown auth '%d'",
                            ssh_message_auth_user(message),
                            ssh_message_subtype(message));
                        ssh_message_auth_set_methods(message,
                            SSH_AUTH_METHOD_PASSWORD |
                            SSH_AUTH_METHOD_INTERACTIVE);
                        ssh_message_reply_default(message);
                        break;
                }
                break;

            default:
                ssh_message_auth_set_methods(message,
                    SSH_AUTH_METHOD_PASSWORD |
                    SSH_AUTH_METHOD_INTERACTIVE);
                ssh_message_reply_default(message);
        }
        ssh_message_free(message);
    } while (1);

    return 0;
}

static int auth_password(const char *user, const char *password)
{
    (void) user;
    (void) password;

/*
    if(strcmp(user, SSHD_USER))
        return 0;
    if(strcmp(password, SSHD_PASSWORD))
        return 0;
*/
    return 1; /* authenticated */
}

static int client_mainloop(ssh_client *data)
{
    ssh_channel chan = data->chan;
    ssh_session session = ssh_channel_get_session(chan);
    ssh_event event;
    short events;
    forward_ctx *ctx = &data->dst;

    if (fwd_connect_sock(ctx, NULL)) {
        E_STRERR("Connection to %s:%s",
            ctx->host_buf, ctx->service_buf);
        ssh_channel_close(chan);
        return 1;
    }

    ssh_channel_cb.userdata = &ctx->sock.fd;
    ssh_callbacks_init(&ssh_channel_cb);
    ssh_set_channel_callbacks(chan, &ssh_channel_cb);

    events = POLLIN | POLLPRI | POLLERR | POLLHUP | POLLNVAL;
    event = ssh_event_new();

    if (event == NULL) {
        E2("%s", "Couldn't get a event");
        return 1;
    }
    if (ssh_event_add_fd(event, ctx->sock.fd, events, copy_fd_to_chan, chan) != SSH_OK) {
        E2("Couldn't add fd %d to the event queue", ctx->sock.fd);
        return 1;
    }
    if (ssh_event_add_session(event, session) != SSH_OK) {
        E2("%s", "Couldn't add the session to the event");
        return 1;
    }

    do {
        ssh_event_dopoll(event, 1000);
    } while (!ssh_channel_is_closed(chan));

    ssh_disconnect(session);
    ssh_event_remove_fd(event, ctx->sock.fd);
    ssh_event_remove_session(event, session);
    ssh_event_free(event);
    return 0;
}

static int copy_fd_to_chan(socket_t fd, int revents, void *userdata)
{
    ssh_channel chan = (ssh_channel)userdata;
    char buf[BUFSIZ];
    int sz = 0;

    if(!chan) {
        close(fd);
        return -1;
    }
    if(revents & POLLIN) {
        sz = read(fd, buf, BUFSIZ);
        if(sz > 0) {
            ssh_channel_write(chan, buf, sz);
        }
    }
    if(revents & POLLHUP || sz <= 0) {
        ssh_channel_close(chan);
        sz = -1;
    }

    return sz;
}

static int copy_chan_to_fd(ssh_session session,
                           ssh_channel channel,
                           void *data,
                           uint32_t len,
                           int is_stderr,
                           void *userdata)
{
    int fd = *(int*)userdata;
    int sz;
    (void)session;
    (void)channel;
    (void)is_stderr;

    sz = write(fd, data, len);
    if (sz <= 0)
        ssh_channel_close(channel);

    return sz;
}

static void chan_close(ssh_session session, ssh_channel channel,
                       void *userdata)
{
    int fd = *(int*)userdata;
    (void)session;
    (void)channel;

    close(fd);
}
