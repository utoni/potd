/*
 * socket.h
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

#ifndef POTD_SOCKET_H
#define POTD_SOCKET_H 1

#include <netdb.h>
#include <net/if.h>

#define POTD_BACKLOG 1

typedef struct psocket {
    int fd;
    socklen_t addr_len;
    struct sockaddr addr;
    int family;
    int socktype;
    int protocol;
} psocket;


int socket_nonblock(const psocket *psock);

int socket_init_in(const char *addr,
                   const char *port, struct addrinfo **results);

int socket_bind_in(psocket *psock, struct addrinfo **results);

int socket_listen_in(psocket *psock);

int socket_accept_in(const psocket *psock, psocket *client_psock);

int socket_connect_in(psocket *psock, struct addrinfo **results);

int socket_connectaddr_in(psocket *psock, struct addrinfo **results,
                          char host_buf[NI_MAXHOST],
                          char service_buf[NI_MAXSERV]);

int socket_addrtostr_in(const psocket *psock,
                        char hbuf[NI_MAXHOST], char sbuf[NI_MAXSERV]);

int socket_reconnect_in(psocket *psock);

int socket_close(psocket *psock);

void socket_clone(const psocket *src, psocket *dst);

ssize_t socket_get_ifnames(const psocket *test_sock, char name[][IFNAMSIZ],
                           size_t siz, int loopback_only);

int socket_set_ifaddr(const psocket *test_sock,
                      const char *ifname, const char *addr, const char *mask);

#endif
