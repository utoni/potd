#ifndef POTD_SECCOMP_H
#define POTD_SECCOMP_H 1

#include <seccomp.h>

#define PS_ALLOW 0x1
#define PS_MINIMUM 0x2

typedef struct pseccomp_ctx {
    unsigned flags;
    scmp_filter_ctx sfilter;
} pseccomp_ctx;


int pseccomp_init(pseccomp_ctx **ctx, unsigned flags);

void pseccomp_free(pseccomp_ctx **ctx);

int pseccomp_set_immutable(void);

int pseccomp_default_rules(pseccomp_ctx *ctx);

int pseccomp_protocol_rules(pseccomp_ctx *ctx);

int pseccomp_jail_rules(pseccomp_ctx *ctx);

#endif
