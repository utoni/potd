#include <arpa/inet.h>

#include "jail_packet.h"
#include "utils.h"

typedef struct jail_packet {
    uint8_t type;
    uint16_t size;
} jail_packet;

typedef ssize_t (*packet_callback)(jail_packet_ctx *ctx, unsigned char *data,
                                   size_t siz);

typedef struct jail_packet_callback {
    uint8_t type;
    packet_callback pc;
} jail_packet_callback;

static ssize_t pkt_header_read(unsigned char *buf, size_t siz);
static ssize_t pkt_hello(jail_packet_ctx *ctx, unsigned char *data, size_t siz);

#define PKT_CB(type, cb) \
    { type, cb }
static const jail_packet_callback jpc[] = {
    PKT_CB(PKT_INVALID, NULL),
    PKT_CB(PKT_HELLO, pkt_hello)
};


static ssize_t pkt_header_read(unsigned char *buf, size_t siz)
{
    jail_packet *pkt;

    if (siz < sizeof(*pkt))
        return -1;
    pkt = (jail_packet *) buf;

    if (pkt->type >= SIZEOF(jpc))
        return -1;

    pkt->size = ntohs(pkt->size);
    if (siz < pkt->size)
        return -1;

    return pkt->size;
}

static ssize_t pkt_hello(jail_packet_ctx *ctx, unsigned char *data, size_t siz)
{
    return -1;
}

int jail_packet_loop(event_ctx *ctx, jail_packet_ctx *pkt_ctx,
                     on_data_cb on_data)
{
    return 1;
}
