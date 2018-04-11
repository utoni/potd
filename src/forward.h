#ifndef POTD_FORWARD_H
#define POTD_FORWARD_H 1

#include "socket.h"

typedef enum forward_type {
    FT_NONE = 0, FT_CLIENT, FT_SERVER
} forward_type;

typedef struct forward_ctx {
    forward_type fwd_type;
    psocket sock;
    char host_buf[NI_MAXHOST], service_buf[NI_MAXSERV];
    struct addrinfo *ai;
    void *data;
} forward_ctx;


int fwd_init_ctx(forward_ctx **ctx);

int fwd_setup_client(forward_ctx *ctx, const char *host, const char *port);

int fwd_setup_client_silent(forward_ctx *ctx, const char *host,
                            const char *port);

int fwd_setup_server(forward_ctx *ctx, const char *listen_addr,
                                       const char *listen_port);

int fwd_validate_ctx(const forward_ctx *ctx);

int fwd_connect_sock(forward_ctx *ctx, psocket *fwd_client);

int fwd_listen_sock(forward_ctx *ctx, psocket *fwd_server);

#endif
