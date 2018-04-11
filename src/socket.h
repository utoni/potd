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
