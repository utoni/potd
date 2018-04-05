#include <stdlib.h>
#include <libssh/callbacks.h>
#include <libssh/server.h>

#include "server_ssh.h"
#include "server.h"

static void set_default_keys(ssh_bind sshbind, int rsa_already_set,
                      int dsa_already_set, int ecdsa_already_set);


int ssh_on_connect(struct server_data *data, struct server_session *ses)
{
    return 0;
}

int ssh_on_disconnect(struct server_data *data, struct server_session *ses)
{
    return 0;
}

int ssh_mainloop_cb(struct server_data *data, struct server_session *ses)
{
    return 0;
}

int ssh_init_cb(struct server_ctx *ctx)
{
    ctx->server_cbs.on_connect = ssh_on_connect;
    ctx->server_cbs.on_disconnect = ssh_on_disconnect;
    ctx->server_cbs.mainloop = ssh_mainloop_cb;
    ctx->server_cbs.on_free = ssh_free_cb;
    ctx->server_cbs.on_listen = ssh_listen_cb;
    ctx->server_cbs.on_shutdown = ssh_shutdown_cb;

    ssh_init();
    ssh_data *d = (ssh_data *) calloc(1, sizeof(*d));
    d->sshbind = ssh_bind_new();
    ctx->server_dat.data = d;
    if (!d->sshbind)
        return 1;

    set_default_keys(d->sshbind, 0, 0, 0);
    return 0;
}

int ssh_free_cb(struct server_data *data)
{
    return 0;
}

int ssh_listen_cb(struct server_data *data)
{
    return 0;
}

int ssh_shutdown_cb(struct server_data *data)
{
    return 0;
}

static void set_default_keys(ssh_bind sshbind, int rsa_already_set,
                             int dsa_already_set, int ecdsa_already_set)
{
    if (!rsa_already_set) {
        ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY,
                             "./ssh_host_rsa_key");
    }
    if (!dsa_already_set) {
        ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY,
                             "./ssh_host_dsa_key");
    }
    if (!ecdsa_already_set) {
        ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_ECDSAKEY,
                             "./ssh_host_ecdsa_key");
    }
}
