#include <string.h>
#include <arpa/inet.h>
#include <assert.h>

#include "jail_packet.h"
#include "utils.h"

typedef struct jail_packet {
    uint8_t type;
    uint16_t size;
} jail_packet;

typedef ssize_t (*packet_callback)(jail_packet_ctx *ctx, event_buf *read_buf,
                                   event_buf *write_buf);

typedef struct jail_packet_callback {
    uint8_t type;
    packet_callback pc;
} jail_packet_callback;

static ssize_t pkt_header_read(unsigned char *buf, size_t siz);
static ssize_t pkt_hello(jail_packet_ctx *ctx, event_buf *read_buf,
                         event_buf *write_buf);
static int jail_event_loop(event_ctx *ctx, event_buf *buf, void *user_data);

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

static ssize_t pkt_hello(jail_packet_ctx *ctx, event_buf *read_buf,
                         event_buf *write_buf)
{
    return -1;
}

static int jail_event_loop(event_ctx *ctx, event_buf *buf, void *user_data)
{
    jail_packet_ctx *pkt_ctx = (jail_packet_ctx *) user_data;
    jail_packet *pkt;
    event_buf wbuf = { -1, {0}, 0, user_data };
    ssize_t pkt_siz;
    off_t pkt_off = 0;

    while (1) {
        pkt_siz = pkt_header_read((unsigned char *) buf->buf + pkt_off,
                                  buf->buf_used);
        if (pkt_siz < 0)
            break;
        pkt = (jail_packet *)(buf->buf + pkt_off);

        if (jpc[pkt->type].pc &&
            jpc[pkt->type].pc(pkt_ctx, buf, &wbuf) < 0)
        {
            pkt_ctx->pstate = JP_INVALID;
            break;
        }

        pkt_off += pkt_siz + sizeof *pkt;
        buf->buf_used -= pkt_off;
    }

    if (pkt_off)
        memmove(buf->buf, buf->buf + pkt_off, buf->buf_used);

    return pkt_ctx->pstate != JP_NONE && pkt_ctx->pstate != JP_INVALID;
}

int jail_packet_loop(event_ctx *ctx, jail_packet_ctx *pkt_ctx)
{
    assert(pkt_ctx->on_data && pkt_ctx->user_data);
    pkt_ctx->pstate = JP_NONE;

    return event_loop(ctx, jail_event_loop, pkt_ctx);
}
