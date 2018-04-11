#ifndef POTD_JAIL_H
#define POTD_JAIL_H 1

#include <sys/types.h>
#include <unistd.h>

#include "forward.h"
#include "pevent.h"

#define MIN_STACKSIZE 2048
#define MAX_STACKSIZE BUFSIZ

typedef struct jail_ctx {
    forward_ctx fwd_ctx;
    char host_buf[NI_MAXHOST], service_buf[NI_MAXSERV];
    size_t stacksize;
    void *stack_ptr;
    void *stack_beg;
    char *newroot;
} jail_ctx;


void jail_init_ctx(jail_ctx **ctx, size_t stacksize);

int jail_setup(jail_ctx *ctx,
               const char *listen_addr, const char *listen_port);

int jail_validate_ctx(const jail_ctx *jail_ctx);

int jail_setup_event(jail_ctx *ctx[], size_t siz, event_ctx **ev_ctx);

pid_t jail_daemonize(event_ctx **ev_ctx, jail_ctx *ctx[], size_t siz);

#endif
