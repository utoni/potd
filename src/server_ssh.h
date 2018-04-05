#ifndef POTD_SERVER_SSH_H
#define POTD_SERVER_SSH_H 1

#include <libssh/server.h>

#include "server.h"

typedef struct ssh_data {
    ssh_bind sshbind;
} ssh_data;


int ssh_on_connect(struct server_data *data, struct server_session *ses);

int ssh_on_disconnect(struct server_data *data, struct server_session *ses);

int ssh_mainloop_cb(struct server_data *_data, struct server_session *ses);

int ssh_init_cb(struct server_ctx *ctx);

int ssh_free_cb(struct server_data *data);

int ssh_listen_cb(struct server_data *data);

int ssh_shutdown_cb(struct server_data *data);

#endif
