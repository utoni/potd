/*
 * redirector.h
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

#ifndef POTD_SERVER_H
#define POTD_SERVER_H 1

#include "socket.h"
#include "forward.h"
#include "pevent.h"


typedef struct redirector_ctx { 
    forward_ctx fwd_ctx;
    psocket sock;
    char host_buf[NI_MAXHOST], service_buf[NI_MAXSERV];
} redirector_ctx;


int redirector_init_ctx(redirector_ctx **rdr_ctx);

void redirector_free_ctx(redirector_ctx **rdr_ctx);

int redirector_setup(redirector_ctx *rdr_ctx,
                     const char *listen_addr, const char *listen_port,
                     const char *host, const char *port);

int redirector_validate_ctx(const redirector_ctx *rdr_ctx);

int redirector_setup_event(redirector_ctx *rdr_ctx[], size_t siz,
                           event_ctx **ev_ctx);

pid_t redirector_daemonize(event_ctx **ev_ctx, redirector_ctx *rdr_ctx[], size_t siz);

#endif
