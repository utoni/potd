/*
 * protocol.c
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
