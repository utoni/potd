/*
 * forward.h
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
