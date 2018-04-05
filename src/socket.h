#ifndef POTD_SOCKET_H
#define POTD_SOCKET_H 1

#include <netinet/in.h>

#define POTD_BACKLOG 3

typedef struct psocket {
    int fd;
    struct sockaddr_in sock;
} psocket;


int socket_init_in(psocket *psocket, const char *listen_addr,
                   unsigned int listen_port);

int socket_bind_listen(psocket *psocket);

#endif
