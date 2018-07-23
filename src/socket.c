/*
 * socket.c
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

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>

#include "socket.h"
#include "utils.h"

static int socket_setopts(int sockfd);
static inline void socket_freeaddr(struct addrinfo **results);


static int socket_setopts(int sockfd)
{
    int s, enable = 1;

    s = fcntl(sockfd, F_GETFL, 0);
    if (s < 0)
        return 1;
    s |= O_CLOEXEC;
    if (fcntl(sockfd, F_SETFL, s) == -1)
        return 1;

    s = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
    if (s)
        return 1;

    return 0;
}

static inline void socket_freeaddr(struct addrinfo **results)
{
    if (*results) {
        freeaddrinfo(*results);
        *results = NULL;
    }
}

int socket_nonblock(const psocket *psock)
{
    return set_fd_nonblock(psock->fd);
}

int socket_init_in(const char *addr,
                   const char *port, struct addrinfo **results)
{
    int s;
    struct addrinfo hints;

    assert(addr || port); /* getaddrinfo wants either node or service */

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; /* IPV4 && IPV6 */
    hints.ai_socktype = SOCK_STREAM; /* TCP */
    hints.ai_flags = AI_PASSIVE; /* all interfaces */

    s = getaddrinfo(addr, port, &hints, results);
    if (s)
        socket_freeaddr(results);

    return s;
}

int socket_bind_in(psocket *psock, struct addrinfo **results)
{
    int s = 1, fd = -1, rv;
    struct addrinfo *rp = NULL;

    assert(psock && results && *results);
    psock->fd = -1;

    for (rp = *results; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0)
            continue;
        rv = bind(fd, rp->ai_addr, rp->ai_addrlen);
        if (!rv)
            break;
        close(fd);
    }

    if (!rp)
        goto finalise;

    s = socket_setopts(fd);
    if (s)
        goto finalise;

    psock->fd = fd;
    psock->addr_len = rp->ai_addrlen;
    psock->addr = *rp->ai_addr;
    psock->family = rp->ai_family;
    psock->socktype = rp->ai_socktype;
    psock->protocol = rp->ai_protocol;
    s = socket_nonblock(psock);

finalise:
    socket_freeaddr(results);

    /* suppress coverity fals-positive: fd out of scope */
    /* coverity[leaked_handle] */
    return s;
}

int socket_listen_in(psocket *psock)
{
    assert(psock);

    return listen(psock->fd, POTD_BACKLOG) != 0;
}

int socket_accept_in(const psocket *psock, psocket *client_psock)
{
    int fd;

    assert(psock && client_psock);

    *client_psock = *psock;
    fd = accept(psock->fd, &client_psock->addr,
                &client_psock->addr_len);
    if (fd < 0)
        return 1;
    if (socket_setopts(fd))
    {
        close(fd);
        return 1;
    }

    client_psock->fd = fd;
    if (socket_nonblock(client_psock)) {
        socket_close(client_psock);
        return 1;
    }

    return 0;
}

int socket_connect_in(psocket *psock, struct addrinfo **results)
{
    int s = 1, fd = -1, rv;
    struct addrinfo *rp = NULL;

    assert(psock && results && *results);
    psock->fd = -1;

    for (rp = *results; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0)
            continue;
        rv = connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (!rv)
            break;
        close(fd);
    }

    if (!rp)
        goto finalise;

    s = socket_setopts(fd);
    if (s)
        goto finalise;

    psock->fd = fd;
    psock->addr_len = rp->ai_addrlen;
    psock->addr = *(rp->ai_addr);
    psock->family = rp->ai_family;
    psock->socktype = rp->ai_socktype;
    psock->protocol = rp->ai_protocol;
    s = socket_nonblock(psock);

finalise:
    socket_freeaddr(results);

    /* suppress coverity fals-positive: fd out of scope */
    /* coverity[leaked_handle] */
    return s;
}

int socket_connectaddr_in(psocket *psock, struct addrinfo **results,
                          char host_buf[NI_MAXHOST],
                          char service_buf[NI_MAXSERV])
{
    if (socket_connect_in(psock, results))
        return -1;
    return socket_addrtostr_in(psock, host_buf, service_buf);
}

int socket_addrtostr_in(const psocket *psock,
                        char hbuf[NI_MAXHOST], char sbuf[NI_MAXSERV])
{
    int s;

    assert(psock);
    s = getnameinfo(&psock->addr,
                    psock->addr_len,
                    &hbuf[0], NI_MAXHOST,
                    &sbuf[0], NI_MAXSERV,
                    NI_NUMERICHOST | NI_NUMERICSERV);

    return s;
}

int socket_reconnect_in(psocket *psock)
{
    int rv;

    assert(psock);
    if (psock->fd >= 0)
        return 1;

    psock->fd = socket(psock->family, psock->socktype, psock->protocol);
    if (psock->fd < 0)
        return 1;
    rv = connect(psock->fd, &psock->addr, psock->addr_len);
    if (rv) {
        socket_close(psock);
        return 1;
    }

    if (socket_setopts(psock->fd)) {
        socket_close(psock);
        return 1;
    }

    return socket_nonblock(psock);
}

int socket_close(psocket *psock)
{
    int rv;

    assert(psock);
    if (psock->fd < 0)
        return 0;
    rv = close(psock->fd);
    psock->fd = -1;

    return rv;
}

void socket_clone(const psocket *src, psocket *dst)
{
    assert(src && dst);

    memcpy(dst, src, sizeof(*dst));
    dst->fd = -1;
}

ssize_t socket_get_ifnames(const psocket *test_sock, char name[][IFNAMSIZ],
                           size_t siz, int loopback_only)
{
    struct ifreq ifr;
    struct ifreq *it, *end;
    struct ifconf ifc;
    char buf[1024];
    int sock;
    size_t rc = 0;

    assert(test_sock);
    sock = socket(test_sock->family, test_sock->socktype,
                  test_sock->protocol);
    if (sock < 0)
        return -1;

    ifc.ifc_len = sizeof buf;
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
        close(sock);
        return -1;
    }
    it = ifc.ifc_req;
    end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strncpy(ifr.ifr_name, it->ifr_name, IFNAMSIZ);

        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (loopback_only && !(ifr.ifr_flags & IFF_LOOPBACK))
                continue;
            if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                strncpy(name[rc++], it->ifr_name, IFNAMSIZ);
                if (siz == rc)
                    break;
            }
        }
    }

    close(sock);

    return rc;
}

int socket_set_ifaddr(const psocket *test_sock,
                      const char *ifname, const char *addr, const char *mask)
{
    struct ifreq ifr;
    int sock;

    assert(test_sock);
    memset(&ifr, 0, sizeof ifr);
    sock = socket(test_sock->family, test_sock->socktype,
                  test_sock->protocol);
    if (sock < 0)
        return 1;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    ifr.ifr_addr.sa_family = AF_INET;
    inet_pton(AF_INET, addr, ifr.ifr_addr.sa_data + 2);
    ioctl(sock, SIOCSIFADDR, &ifr);

    inet_pton(AF_INET, mask, ifr.ifr_addr.sa_data + 2);
    ioctl(sock, SIOCSIFNETMASK, &ifr);

    ioctl(sock, SIOCGIFFLAGS, &ifr);
    /* coverity[buffer_size_warning] */
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);

    ioctl(sock, SIOCSIFFLAGS, &ifr);
    close(sock);

    return 0;
}
