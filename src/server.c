#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "server.h"


server_ctx *
server_init_ctx(server_ctx *ctx, init_cb init_fn)
{
    if (!ctx)
        ctx = (server_ctx *) malloc(sizeof(*ctx));
    assert(ctx);

    memset(ctx, 0, sizeof(*ctx));
    if (!init_fn(ctx))
        return NULL;

    return ctx;
}

int server_validate_ctx(server_ctx *ctx)
{
    assert(ctx);
    assert(ctx->server_cbs.on_connect && ctx->server_cbs.on_disconnect
        && ctx->server_cbs.mainloop);
    assert(ctx->server_cbs.on_free && ctx->server_cbs.on_listen
        && ctx->server_cbs.on_shutdown);
    return 0;
}

int server_mainloop(server_ctx *ctx)
{
    while (1) {
        sleep(1);
    }
    return 0;
}
