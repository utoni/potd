#ifndef POTD_PROTOCOL_H
#define POTD_PROTOCOL_H 1

#include "forward.h"

#define PROTO_NAMELEN 16

struct protocol_ctx;

typedef int (*proto_init_cb) (struct protocol_ctx *ctx);
typedef int (*proto_listen_cb) (struct protocol_ctx *ctx);
typedef int (*proto_shutdown_cb) (struct protocol_ctx *ctx);

typedef struct protocol_cbs {
    proto_listen_cb on_listen;
    proto_shutdown_cb on_shutdown;
} protocol_cbs;

typedef struct protocol_ctx {
    const char name[PROTO_NAMELEN];
    forward_ctx src;
    forward_ctx dst;
    protocol_cbs cbs;
} protocol_ctx;


int proto_init_ctx(protocol_ctx **ctx, proto_init_cb init_fn);

int proto_setup(protocol_ctx *ctx, const char *listen_addr,
                const char *listen_port, const char *jail_host,
                const char *jail_port);

int proto_listen(protocol_ctx *ctx);

int proto_validate_ctx(const protocol_ctx *ctx);

#endif
