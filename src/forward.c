#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "forward.h"
#include "log.h"


int fwd_init_ctx(forward_ctx **ctx)
{
    assert(ctx);
    if (!*ctx)
        *ctx = (forward_ctx *) malloc(sizeof(**ctx));
    assert(*ctx);

    memset(*ctx, 0, sizeof(**ctx));

    return 0;
}

int fwd_setup_client(forward_ctx *ctx, const char *host, const char *port)
{
    int s;

    assert(ctx);
    ctx->fwd_type = FT_CLIENT;

    s = socket_init_in(host, port, &ctx->ai);
    if (s) {
        E_GAIERR(s, "Could not initialise client forward socket");
        return 1;
    }

    s = socket_connectaddr_in(&ctx->sock, &ctx->ai,
                              ctx->host_buf,
                              ctx->service_buf);
    switch (s) {
        case -1:
            E_STRERR("Connection to forward socket %s:%s", host, port);
            break;
        case 0:
            break;
        default:
            E_GAIERR(s, "Convert forward socket address to string");
            break;
    }

    if (socket_close(&ctx->sock)) {
        E_STRERR("Forward socket to %s:%s close",
            ctx->host_buf, ctx->service_buf);
        return 1;
    }

    return s != 0;
}

int fwd_setup_client_silent(forward_ctx *ctx, const char *host,
                            const char *port)
{
    int s;

    assert(ctx);
    ctx->fwd_type = FT_CLIENT;

    s = socket_init_in(host, port, &ctx->ai);
    if (s) {
        E_GAIERR(s, "Could not initialise client forward socket");
        return 1;
    }

    return 0;
}

int fwd_setup_server(forward_ctx *ctx, const char *listen_addr,
                                       const char *listen_port)
{
    int s;
    struct addrinfo *fwd_addr = NULL;

    assert(ctx);
    ctx->fwd_type = FT_SERVER;

    s = socket_init_in(listen_addr, listen_port, &fwd_addr);
    if (s) {
        E_GAIERR(s, "Initialising server forward socket");
        return 1;
    }
    if (socket_bind_in(&ctx->sock, &fwd_addr)) {
        E_STRERR("Binding forward server socket to %s:%s",
            listen_addr, listen_port);
        return 1;
    }
    s = socket_addrtostr_in(&ctx->sock, ctx->host_buf, ctx->service_buf);
    if (s) {
        E_GAIERR(s, "Convert server forward socket address");
        return 1;
    }

    return 0;
}

int fwd_validate_ctx(const forward_ctx *ctx)
{
    assert(ctx);
    assert(ctx->fwd_type == FT_CLIENT ||
           ctx->fwd_type == FT_SERVER);
    assert(ctx->sock.addr_len > 0);
    assert(strnlen(ctx->host_buf, NI_MAXHOST) > 0);
    assert(strnlen(ctx->service_buf, NI_MAXSERV) > 0);

    return 0;
}

int fwd_connect_sock(forward_ctx *ctx, psocket *fwd_client)
{
    int s;
    psocket *dst;

    assert(ctx);
    assert(ctx->fwd_type == FT_CLIENT);
    if (fwd_client) {
        dst = fwd_client;
        socket_clone(&ctx->sock, fwd_client);
    } else {
        dst = &ctx->sock;
    }

    if (ctx->ai) {
        s = socket_connectaddr_in(dst, &ctx->ai,
                                  ctx->host_buf,
                                  ctx->service_buf);
        switch (s) {
            case -1:
                E_STRERR("Connection to forward socket with fd %d",
                    dst->fd);
                break;
            case 0:
                if (ctx->ai)
                    s = 1;
                break;
            default:
            E_GAIERR(s, "Convert forward socket address to string");
            break;
        }

        return s != 0;
    } else {
        return socket_reconnect_in(dst);
    }
}

int fwd_listen_sock(forward_ctx *ctx, psocket *fwd_server)
{
    psocket *dst;

    assert(ctx);
    assert(ctx->fwd_type == FT_SERVER);
    if (fwd_server) {
        dst = fwd_server;
        socket_clone(&ctx->sock, fwd_server);
    } else {
        dst = &ctx->sock;
    }

    if (socket_listen_in(dst)) {
        E_STRERR("Could not listen on forward server socket on %s:%s",
            ctx->host_buf, ctx->service_buf);
        return 1;
    }

    return 0;
}
