#ifndef POTD_SERVER_SSH_H
#define POTD_SERVER_SSH_H 1

#include <libssh/server.h>

#include "protocol.h"

int ssh_init_cb(protocol_ctx *ctx);

int ssh_on_listen(protocol_ctx *ctx);

int ssh_on_shutdown(protocol_ctx *ctx);

#endif
