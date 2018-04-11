#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "protocol.h"
#include "log.h"
#include "socket.h"


int proto_init_ctx(protocol_ctx **ctx, proto_init_cb init_fn)
{
    assert(ctx && init_fn);
    if (!*ctx)
        *ctx = (protocol_ctx *) malloc(sizeof(**ctx));
    assert(*ctx);

    memset(*ctx, 0, sizeof(**ctx));
    if (init_fn(*ctx))
        return 1;

    return 0;
}

int proto_setup(protocol_ctx *ctx, const char *listen_addr,
                const char *listen_port, const char *jail_host,
                const char *jail_port)
{
    assert(ctx);

    if (fwd_setup_server(&ctx->src, listen_addr, listen_port))
        return 1;
    if (fwd_setup_client_silent(&ctx->dst, jail_host, jail_port))
        return 1;

    return 0;
}

int proto_listen(protocol_ctx *ctx)
{
    if (!ctx->cbs.on_listen)
        return 1;
    if (ctx->cbs.on_listen(ctx))
        return 1;

    return 0;
}

int proto_validate_ctx(const protocol_ctx *ctx)
{
    assert(ctx);
    assert(ctx->cbs.on_listen && ctx->cbs.on_shutdown);

    return 0;
}
