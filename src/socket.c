#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>

#include "socket.h"


int socket_init_in(psocket *psocket, const char *listen_addr, unsigned int listen_port)
{
    struct in_addr addr = {0};

    assert(psocket);
    if (!inet_aton(listen_addr, &addr))
        return 1;

    psocket->sock.sin_family = AF_INET;
    psocket->sock.sin_addr = addr;
    psocket->sock.sin_port = htons(listen_port);
    psocket->fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    return psocket->fd < 0;
}

int socket_bind_listen(psocket *psocket)
{
    assert(psocket);
    if (bind(psocket->fd, &psocket->sock, sizeof(psocket->sock)) < 0)
        return 1;
    return listen(psocket->fd, POTD_BACKLOG) < 0;
}
