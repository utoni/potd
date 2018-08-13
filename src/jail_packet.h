/*
 * jail_packet.h
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

#ifndef POTD_JAIL_PACKET_H
#define POTD_JAIL_PACKET_H 1

#include <stdint.h>

#include "pevent.h"

#define PKT_INVALID 0x0 /* should not happen, otherwise error */
#define PKT_HELLO   0x1 /* request(PKT_HELLO) -> response(PKT_HELLO) */
#define PKT_USER    0x2 /* request(PKT_USER) -> response(PKT_USER) */
#define PKT_PASS    0x3 /* request(PKT_PASS) -> response(PKT_PASS) */

typedef enum jail_packet_state {
    JP_NONE, JP_INVALID, JP_HELLO
} jail_packet_state;

typedef struct jail_packet_ctx {
    int is_server;
    jail_packet_state pstate;
    on_data_cb on_data;
    void *user_data;
} jail_packet_ctx;


int jail_packet_loop(event_ctx *ctx, jail_packet_ctx *pkt_ctx);

#endif
