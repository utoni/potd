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
