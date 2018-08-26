/*
 * protocol_ssh.c
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
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <signal.h>
#include <poll.h>
#include <pwd.h>
#include <pthread.h>
#include <limits.h>
#include <linux/limits.h>
#include <libssh/callbacks.h>
#include <libssh/server.h>

#include "protocol_ssh.h"
#include "protocol.h"
#include "jail_packet.h"
#ifdef HAVE_SECCOMP
#include "pseccomp.h"
#endif
#include "options.h"
#include "compat.h"
#include "utils.h"
#include "log.h"

#if LIBSSH_VERSION_MAJOR != 0 || LIBSSH_VERSION_MINOR < 7 || \
    LIBSSH_VERSION_MICRO < 3
#pragma message "Unsupported libssh version < 0.7.3"
#endif
#define CACHE_MAX 32
#define CACHE_TIME (60 * 20) /* max cache time 20 minutes */
#define LOGIN_SUCCESS_PROB ((double)1/4) /* successful login probability */

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

typedef struct ssh_userdata {
    jail_packet_ctx *pkt_ctx;
    ssh_client *client;
    event_ctx *ev_ctx;
    event_buf proto_read;
    event_buf proto_fd;
    event_buf proto_chan;
} ssh_userdata;

struct protocol_cbs potd_ssh_callbacks = {
    .on_listen = ssh_on_listen,
    .on_shutdown = ssh_on_shutdown
};

typedef struct ssh_login_cache {
    char user[USER_LEN];
    char pass[PASS_LEN];
    time_t last_used;
    int deny_access;
    pthread_mutex_t cache_mtx;
} ssh_login_cache;

static int set_default_keys(ssh_bind sshbind, int rsa_already_set,
                            int dsa_already_set, int ecdsa_already_set);
static int gen_default_keys(void);
static int gen_export_sshkey(enum ssh_keytypes_e type, int length,
                             const char *path);
static void ssh_log_cb(int priority, const char *function, const char *buffer,
                       void *userdata);
static void ssh_mainloop(ssh_data *arg)
    __attribute__((noreturn));
static int authenticate(ssh_session session, ssh_login_cache *cache,
                        jail_packet_ctx *pkt_ctx);
static int auth_password(const char *user, const char *pass,
                         ssh_login_cache *cache);
static int client_mainloop(ssh_client *arg, jail_packet_ctx *ctx);
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
            return 1;
        }
        if (ssh_version(SSH_VERSION_INT(0,7,4)) == NULL &&
            ssh_version(SSH_VERSION_INT(0,7,90)) == NULL)
        {
            W("%s",
              "libssh versions <= 0.7.3 may suffer "
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
    //ssh_set_log_level(SSH_LOG_FUNCTIONS);
    //ssh_set_log_level(SSH_LOG_PROTOCOL);
    ssh_set_log_level(SSH_LOG_PACKET);

    if (!d->sshbind)
        return 1;
    if (ssh_bind_options_set(d->sshbind, SSH_BIND_OPTIONS_BANNER,
        /* "OpenSSH_7.4p1" */ "dropbear"))
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
    struct passwd pwd;

    errno = 0;
    if (potd_getpwnam(getopt_str(OPT_CHUSER), &pwd))
        return 1;

    if (mkdir(getopt_str(OPT_SSH_RUN_DIR), R_OK|W_OK|X_OK) && errno == ENOENT) {
        if (chmod(getopt_str(OPT_SSH_RUN_DIR), S_IRWXU))
            return 1;
        if (chown(getopt_str(OPT_SSH_RUN_DIR), pwd.pw_uid, pwd.pw_gid))
            return 1;
    }

    snprintf(path, sizeof path, "%s/%s", getopt_str(OPT_SSH_RUN_DIR),
        rsa_key_suf);
    if (gen_export_sshkey(SSH_KEYTYPE_RSA, 1024, path)) {
        W("libssh %s key generation failed, using fallback ssh-keygen", "RSA");
        if ((!remove(path) || errno == ENOENT) &&
            snprintf(cmd, sizeof cmd, "ssh-keygen -t rsa -b 1024 -f %s -N '' "
            ">/dev/null 2>/dev/null", path) > 0)
        {
            s |= system(cmd);
        } else s++;
    }
    if (chmod(path, S_IRUSR))
        return 1;
    if (chown(path, pwd.pw_uid, pwd.pw_gid))
        return 1;

    snprintf(path, sizeof path, "%s/%s", getopt_str(OPT_SSH_RUN_DIR),
        dsa_key_suf);
    if (gen_export_sshkey(SSH_KEYTYPE_DSS, 1024, path)) {
        W("libssh %s key generation failed, using fallback ssh-keygen", "DSA");
        if ((!remove(path) || errno == ENOENT) &&
            snprintf(cmd, sizeof cmd, "ssh-keygen -t dsa -b 1024 -f %s -N '' "
            ">/dev/null 2>/dev/null", path) > 0)
        {
            s |= system(cmd);
        } else s++;
    }
    if (chmod(path, S_IRUSR))
        return 1;
    if (chown(path, pwd.pw_uid, pwd.pw_gid))
        return 1;

    snprintf(path, sizeof path, "%s/%s", getopt_str(OPT_SSH_RUN_DIR),
        ecdsa_key_suf);
    if (gen_export_sshkey(SSH_KEYTYPE_ECDSA, 1024, path)) {
        W("libssh %s key generation failed, using fallback ssh-keygen", "ECDSA");
        if ((!remove(path) || errno == ENOENT) &&
            snprintf(cmd, sizeof cmd, "ssh-keygen -t ecdsa -b 256 -f %s -N '' "
            ">/dev/null 2>/dev/null", path) > 0)
        {
            s |= system(cmd);
        } else s++;
    }
    if (chmod(path, S_IRUSR))
        return 1;
    if (chown(path, pwd.pw_uid, pwd.pw_gid))
        return 1;

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
    s = ssh_pki_export_privkey_file(priv_key, NULL, NULL,
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
        default:
            P("libssh: %s", buffer);
            break;
    }
}

static void ssh_mainloop(ssh_data *arg)
{
    pthread_mutexattr_t shared;
    ssh_login_cache *cache = NULL;
    jail_packet_ctx pkt_ctx = INIT_PKTCTX(NULL,NULL);
    size_t i;
    int s, auth = 0, shell = 0, is_child;
    ssh_session ses;
    ssh_message message;
    ssh_channel chan = NULL;
    ssh_client data;

    assert(arg);
    set_procname("[potd] ssh");
    assert( set_child_sighandler() == 0 );
    cache = (ssh_login_cache *) mmap(NULL, sizeof(*cache) * CACHE_MAX,
                                     PROT_READ|PROT_WRITE,
                                     MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    assert( cache );
    memset(cache, 0, sizeof(*cache) * CACHE_MAX);
    pthread_mutexattr_init(&shared);
    pthread_mutexattr_setpshared(&shared, PTHREAD_PROCESS_SHARED);
    for (i = 0; i < CACHE_MAX; ++i) {
        pthread_mutex_init(&(cache[i].cache_mtx), &shared);
    }

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
        auth = authenticate(ses, cache, &pkt_ctx);
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
        if (client_mainloop(&data, &pkt_ctx))
            W2("Client mainloop for fd %d failed",
                ssh_bind_get_fd(arg->sshbind));

failed:
        munmap(cache, sizeof(*cache) * CACHE_MAX);
        ssh_disconnect(ses);
        ssh_free(ses);
        exit(EXIT_SUCCESS);
    }
}

static int authenticate(ssh_session session, ssh_login_cache *cache,
                        jail_packet_ctx *pkt_ctx)
{
    ssh_message message;
    ssh_key pubkey;
    int rc, auth_methods = SSH_AUTH_METHOD_PUBLICKEY | SSH_AUTH_METHOD_PASSWORD;
    char *pk_hashstr;
    unsigned char *pk_hash;
    size_t pk_hashlen;

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
                            ssh_message_auth_password(message), cache))
                        {
                            pkt_ctx->user = strdup(ssh_message_auth_user(message));
                            pkt_ctx->pass = strdup(ssh_message_auth_password(message));
                            ssh_message_auth_reply_success(message,0);
                            ssh_message_free(message);
                            return 1;
                        }

                        ssh_message_auth_set_methods(message, auth_methods);
                        /* not authenticated, send default message */
                        ssh_message_reply_default(message);
                        break;

                    case SSH_AUTH_METHOD_PUBLICKEY:
                        pubkey = ssh_message_auth_pubkey(message);
                        rc = ssh_get_publickey_hash(pubkey,
                            SSH_PUBLICKEY_HASH_SHA1, &pk_hash, &pk_hashlen);

                        pk_hashstr = NULL;
                        if (rc >= 0) {
                            pk_hashstr = ssh_get_hexa(pk_hash, pk_hashlen);
                        }

                        if (pk_hashstr) {
                            N("SSH: user '%s' wants to auth with public key '%s'",
                                ssh_message_auth_user(message),
                                pk_hashstr);
                            ssh_string_free_char(pk_hashstr);
                        }

                        ssh_message_auth_set_methods(message, auth_methods);
                        ssh_message_reply_default(message);
                        break;

                    case SSH_AUTH_METHOD_NONE:
                        N("SSH: User '%s' wants to auth with method '%d': NONE",
                            ssh_message_auth_user(message),
                            ssh_message_subtype(message));

                        ssh_message_auth_set_methods(message, auth_methods);
                        ssh_message_reply_default(message);
                        break;

                    default:
                        N("SSH: User '%s' wants to auth with unknown auth '%d'",
                            ssh_message_auth_user(message),
                            ssh_message_subtype(message));

                        ssh_message_auth_set_methods(message, auth_methods);
                        ssh_message_reply_default(message);
                        break;
                }
                break;

            default:
                ssh_message_auth_set_methods(message, auth_methods);
                ssh_message_reply_default(message);
        }
        ssh_message_free(message);
    } while (1);

    return 0;
}

static int auth_password(const char *user, const char *pass,
                         ssh_login_cache *cache)
{
    int got_auth = 0, deny_auth = 0, cached = 0;
    size_t i;
    double d;
    time_t o, t = time(NULL);
    struct tm tmp;
    char time_str[64] = {0};

    for (i = 0; i < CACHE_MAX; ++i) {
        pthread_mutex_lock(&cache[i].cache_mtx);
        if (cache[i].user[0] && cache[i].pass[0]) {
            o = cache[i].last_used;
            cache[i].last_used = t;

            if (strncmp(user, cache[i].user, USER_LEN) == 0 &&
                strnlen(user, USER_LEN) == strnlen(cache[i].user, USER_LEN) &&
                strncmp(pass, cache[i].pass, PASS_LEN) == 0 &&
                strnlen(pass, PASS_LEN) == strnlen(cache[i].pass, PASS_LEN))
            {
                if (!potd_localtime(&o, &tmp))
                    continue;
                if (!strftime(time_str, sizeof time_str, "%H:%M:%S", &tmp))
                    snprintf(time_str, sizeof time_str, "%s", "UNKNOWN_TIME");

                if (cache[i].deny_access) {
                    N("Got DENIED cached user/pass '%s'/'%s' from %s",
                        user, pass, time_str);
                    deny_auth = 1;
                } else {
                    N("Got cached user/pass '%s'/'%s' from %s",
                        user, pass, time_str);
                    got_auth = 1;
                }
            }

            d = difftime(t, o);
            if (d > CACHE_TIME) {
                D("Delete cached user/pass '%s'/'%s' (timeout)",
                    cache[i].user, cache[i].pass);
                cache[i].user[0] = 0;
                cache[i].pass[0] = 0;
                cache[i].deny_access = 0;
            }
        }
        pthread_mutex_unlock(&cache[i].cache_mtx);

        if (got_auth || deny_auth)
            break;
    }

    /* not auth'd but we have still some randomness */
    if (!got_auth && !deny_auth) {
        srandom(time(NULL));
        d = (double)(random() % RAND_MAX);
        d /= (double)RAND_MAX;

        for (i = 0; i < CACHE_MAX; ++i) {
            pthread_mutex_lock(&cache[i].cache_mtx);
            if (!cache[i].user[0] && !cache[i].pass[0]) {
                D("Caching user/pass '%s'/'%s'",
                    user, pass);
                snprintf(cache[i].user, sizeof cache[i].user, "%s", user);
                snprintf(cache[i].pass, sizeof cache[i].pass, "%s", pass);
                cache[i].last_used = t;
                cached = 1;

                if (d <= LOGIN_SUCCESS_PROB) {
                    N("Randomness won for user/pass '%s'/'%s': %.02f < %.02f",
                        user, pass, d, LOGIN_SUCCESS_PROB);
                    got_auth = 1;
                } else {
                    N("DENYING access for user/pass '%s'/'%s': %.02f >= %.02f",
                        user, pass, d, LOGIN_SUCCESS_PROB);
                    cache[i].deny_access = 1;
                }
            }
            pthread_mutex_unlock(&cache[i].cache_mtx);

            if (cached)
                break;
        }
    }

    return got_auth;
}

static int client_mainloop(ssh_client *data, jail_packet_ctx *pkt_ctx)
{
    ssh_channel chan = data->chan;
    ssh_session session = ssh_channel_get_session(chan);
    ssh_userdata userdata = { pkt_ctx, data, NULL,
                              EMPTY_BUF, EMPTY_BUF, EMPTY_BUF };
    ssh_event event;
    short events;
    forward_ctx *ctx = &data->dst;
    struct event_ctx *ev_ctx;

    if (fwd_connect_sock(ctx, NULL)) {
        E_STRERR("Connection to %s:%s",
            ctx->host_buf, ctx->service_buf);
        ssh_channel_close(chan);
        return 1;
    }

    ev_ctx = jail_client_handshake(ctx->sock.fd, pkt_ctx);
    if (!ev_ctx) {
        ssh_channel_close(chan);
        return 1;
    }

    pkt_ctx->connection.client_fd = pkt_ctx->writeback_buf.fd =
        userdata.proto_read.fd = ctx->sock.fd;
    if (jail_client_data(ev_ctx, &userdata.proto_read,
                         &userdata.proto_chan, pkt_ctx))
    {
        ssh_channel_close(chan);
        event_free(&ev_ctx);
        return 1;
    }
    pkt_ctx->ev_readloop = 0;

    userdata.ev_ctx = ev_ctx;
    ssh_channel_cb.userdata = &userdata;
    ssh_callbacks_init(&ssh_channel_cb);
    ssh_set_channel_callbacks(chan, &ssh_channel_cb);

    events = POLLIN | POLLPRI | POLLERR | POLLHUP | POLLNVAL;
    event = ssh_event_new();

    if (event == NULL) {
        E2("%s", "Couldn't get a event");
        event_free(&ev_ctx);
        return 1;
    }
    if (ssh_event_add_fd(event, ctx->sock.fd, events, copy_fd_to_chan,
        &userdata) != SSH_OK)
    {
        E2("Couldn't add fd %d to the event queue", ctx->sock.fd);
        event_free(&ev_ctx);
        return 1;
    }
    if (ssh_event_add_session(event, session) != SSH_OK) {
        E2("%s", "Couldn't add the session to the event");
        event_free(&ev_ctx);
        return 1;
    }

    do {
        ssh_event_dopoll(event, 1000);
    } while (!ssh_channel_is_closed(chan));

    ssh_disconnect(session);
    ssh_event_remove_fd(event, ctx->sock.fd);
    ssh_event_remove_session(event, session);
    ssh_event_free(event);
    event_free(&ev_ctx);

    return 0;
}

static int copy_fd_to_chan(socket_t fd, int revents, void *userdata)
{
    ssh_userdata *sudata = (ssh_userdata *) userdata;
    ssh_channel chan = sudata->client->chan;
    ssize_t sz = 0;
    int written;

    if (!chan) {
        close(fd);
        return -1;
    }
    if (revents & POLLIN) {
        sz = event_buf_read(&sudata->proto_read);
        if (sz > 0 &&
            !jail_client_data(sudata->ev_ctx, &sudata->proto_read,
                             &sudata->proto_chan, sudata->pkt_ctx))
        {
            written = ssh_channel_write(chan, sudata->proto_chan.buf,
                                        sudata->proto_chan.buf_used);
            event_buf_discard(&sudata->proto_chan, written);
        }
    }
    if (revents & POLLHUP || sz <= 0) {
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
    ssh_userdata *sudata = (ssh_userdata *) userdata;

    (void) session;
    (void) is_stderr;

    if (jail_client_send(sudata->pkt_ctx, data, len))
        ssh_channel_close(channel);

    return len;
}

static void chan_close(ssh_session session, ssh_channel channel,
                       void *userdata)
{
    ssh_userdata *sudata = (ssh_userdata *) userdata;
    int fd = sudata->proto_read.fd;

    (void) session;
    (void) channel;

    close(fd);
}
