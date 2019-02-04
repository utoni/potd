#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>

#include "jail_packet.h"
#include "pevent.h"
#include "log.h"
#include "utils.h"

#ifdef gcc_struct
#define JP_ATTRS __attribute__((packed, aligned(1), gcc_struct))
#else
#define JP_ATTRS __attribute__((packed,  aligned(1)))
#endif

typedef struct jail_packet {
    uint8_t type;
    uint16_t size;
} JP_ATTRS jail_packet;

#define PKT_SIZ(pkt) (sizeof(jail_packet) + sizeof(*pkt))
#define PKT_SUB(pkt_ptr) ((unsigned char *)pkt_ptr + sizeof(jail_packet))

#define JP_MAGIC1 0xDEADC0DE
#define JP_MAGIC2 0xDEADBEEF

typedef struct jail_packet_handshake {
    uint32_t magic1;
    uint32_t magic2;
} JP_ATTRS jail_packet_handshake;

typedef int (*packet_callback)(jail_packet_ctx *ctx, jail_packet *pkt,
                               event_buf *write_buf);

typedef struct jail_packet_callback {
    uint8_t type;
    packet_callback pc;
} jail_packet_callback;

static ssize_t pkt_header_read(unsigned char *buf, size_t siz);
static int pkt_handshake(jail_packet_ctx *ctx, jail_packet *pkt,
                         event_buf *write_buf);
static int pkt_user(jail_packet_ctx *ctx, jail_packet *pkt,
                    event_buf *write_buf);
static int pkt_pass(jail_packet_ctx *ctx, jail_packet *pkt,
                    event_buf *write_buf);
static int pkt_handshake_end(jail_packet_ctx *ctx, jail_packet *pkt,
                             event_buf *write_buf);
static int pkt_start(jail_packet_ctx *ctx, jail_packet *pkt,
                     event_buf *write_buf);
static int pkt_data(jail_packet_ctx *ctx, jail_packet *pkt,
                    event_buf *write_buf);
static int pkt_respok(jail_packet_ctx *ctx, jail_packet *pkt,
                      event_buf *write_buf);
static int pkt_resperr(jail_packet_ctx *ctx, jail_packet *pkt,
                       event_buf *write_buf);
static int jail_packet_io(event_ctx *ctx, int src_fd, void *user_data);
static int jail_packet_pkt(event_ctx *ev_ctx, event_buf *read_buf,
                           event_buf *write_buf, void *user_data);

#define PKT_CB(type, cb) \
    { type, cb }
static const jail_packet_callback jpc[] = {
    PKT_CB(PKT_INVALID, NULL),
    PKT_CB(PKT_HANDSHAKE, pkt_handshake),
    PKT_CB(PKT_USER,    pkt_user),
    PKT_CB(PKT_PASS,    pkt_pass),
    PKT_CB(PKT_HANDSHAKE_END, pkt_handshake_end),
    PKT_CB(PKT_START,   pkt_start),
    PKT_CB(PKT_DATA,    pkt_data),
    PKT_CB(PKT_RESPOK,  pkt_respok),
    PKT_CB(PKT_RESPERR, pkt_resperr)
};


static ssize_t pkt_header_read(unsigned char *buf, size_t siz)
{
    uint16_t pkt_size;
    jail_packet *pkt;

    if (siz < sizeof(*pkt))
        return 0;
    pkt = (jail_packet *) buf;

    if (pkt->type >= SIZEOF(jpc))
        return -1;

    pkt_size = ntohs(pkt->size);
    if (pkt_size > PKT_MAXSIZ - sizeof(*pkt))
        return -1;
    if (siz < pkt_size)
        return 0;

    pkt->size = pkt_size;
    return pkt_size + sizeof(*pkt);
}

static int pkt_write(event_buf *write_buf, uint8_t type, unsigned char *buf,
                     size_t siz)
{
    uint16_t pkt_size;
    jail_packet pkt;

    pkt.type = type;
    pkt_size = siz;

    do {
        pkt_size = (siz > PKT_MAXSIZ - sizeof(pkt) ?
            PKT_MAXSIZ - sizeof(pkt) : pkt_size);
        pkt.size = htons(pkt_size);

        if (event_buf_fill(write_buf, (char *) &pkt, sizeof pkt) ||
            (buf && event_buf_fill(write_buf, (char *) buf, pkt_size)))
        {
            return 1;
        }
        siz -= pkt_size;
    } while (siz > 0);

    return 0;
}

static int pkt_handshake(jail_packet_ctx *ctx, jail_packet *pkt,
                         event_buf *write_buf)
{
    jail_packet_handshake *pkt_hello;

    if (ctx->ctype != JC_SERVER)
        return 1;

    if (ctx->pstate != JP_HANDSHAKE)
        return 1;
    pkt_hello = (jail_packet_handshake *) PKT_SUB(pkt);
    pkt_hello->magic1 = ntohl(pkt_hello->magic1);
    pkt_hello->magic2 = ntohl(pkt_hello->magic2);
    if (pkt_hello->magic1 != JP_MAGIC1 ||
        pkt_hello->magic2 != JP_MAGIC2)
    {
        return 1;
    }

    if (pkt_write(&ctx->writeback_buf, PKT_RESPOK, NULL, 0))
        return 1;

    ctx->pstate = JP_HANDSHAKE_END;

    return 0;
}

static int pkt_user(jail_packet_ctx *ctx, jail_packet *pkt,
                    event_buf *write_buf)
{
    char *user;

    (void) write_buf;

    if (ctx->ctype != JC_SERVER || ctx->pstate != JP_HANDSHAKE_END ||
        !pkt->size || pkt->size > USER_LEN)
    {
        return 1;
    }
    user = (char *) PKT_SUB(pkt);
    ctx->user = strndup(user, pkt->size);

    return 0;
}

static int pkt_pass(jail_packet_ctx *ctx, jail_packet *pkt,
                    event_buf *write_buf)
{
    char *pass;

    (void) write_buf;

    if (ctx->ctype != JC_SERVER || ctx->pstate != JP_HANDSHAKE_END ||
        !pkt->size || pkt->size > PASS_LEN)
    {
        return 1;
    }
    pass = (char *) PKT_SUB(pkt);
    ctx->pass = strndup(pass, pkt->size);

    return 0;
}

static int pkt_handshake_end(jail_packet_ctx *ctx, jail_packet *pkt,
                             event_buf *write_buf)
{
    (void) write_buf;

    if (ctx->ctype != JC_SERVER || ctx->pstate != JP_HANDSHAKE_END ||
        pkt->size)
    {
        return 1;
    }

    ctx->is_valid = 1;
    ctx->ev_active = 0;

    return 0;
}

static int pkt_start(jail_packet_ctx *ctx, jail_packet *pkt,
                     event_buf *write_buf)
{
    if (ctx->ctype != JC_SERVER || ctx->pstate != JP_START ||
        pkt->size)
    {
        return 1;
    }

    (void) write_buf;
    ctx->pstate = JP_DATA;

    if (pkt_write(&ctx->writeback_buf, PKT_RESPOK, NULL, 0))
        return 1;

    return 0;
}

static int pkt_data(jail_packet_ctx *ctx, jail_packet *pkt,
                    event_buf *write_buf)
{
    unsigned char *data = PKT_SUB(pkt);

    if (ctx->ctype == JC_SERVER || ctx->ctype == JC_CLIENT) {
        if (event_buf_fill(write_buf, (char *) data, pkt->size))
            return 1;
        if (ctx->ctype == JC_CLIENT)
            ctx->ev_active = 0;
    } else {
        return 1;
    }

    return 0;
}

static int pkt_respok(jail_packet_ctx *ctx, jail_packet *pkt,
                      event_buf *write_buf)
{
    if (ctx->ctype == JC_CLIENT) {
        switch (ctx->pstate) {
            case JP_HANDSHAKE:
                ctx->pstate = JP_HANDSHAKE_END;
                ctx->ev_active = 0;
                break;
            case JP_START:
                ctx->pstate = JP_DATA;
                ctx->ev_active = 0;
                break;
            default: return 1;
        }
    } else return 1;

    return 0;
}

static int pkt_resperr(jail_packet_ctx *ctx, jail_packet *pkt,
                       event_buf *write_buf)
{
    (void) ctx;
    (void) pkt;
    (void) write_buf;

    return 1;
}

static int jail_packet_io(event_ctx *ev_ctx, int src_fd, void *user_data)
{
    int dest_fd;
    jail_packet_ctx *pkt_ctx = (jail_packet_ctx *) user_data;
    forward_state fwd_state;

    (void) ev_ctx;
    (void) src_fd;
    (void) pkt_ctx;

    if (pkt_ctx->ctype == JC_CLIENT) {
        dest_fd = src_fd;
    } else if (src_fd == pkt_ctx->connection.client_fd) {
        dest_fd = pkt_ctx->connection.jail_fd;
    } else if (src_fd == pkt_ctx->connection.jail_fd) {
        dest_fd = pkt_ctx->connection.client_fd;
    } else return 0;

    fwd_state = event_forward_connection(ev_ctx, dest_fd, jail_packet_pkt,
                                         user_data);

    switch (fwd_state) {
        case CON_IN_TERMINATED:
        case CON_OUT_TERMINATED:
            ev_ctx->active = 0;
        case CON_OK:
            return 1;
        case CON_IN_ERROR:
        case CON_OUT_ERROR:
            ev_ctx->has_error = 1;
            return 0;
    }

    return 1;
}

static int jail_packet_pkt(event_ctx *ev_ctx, event_buf *read_buf,
                           event_buf *write_buf, void *user_data)
{
    jail_packet_ctx *pkt_ctx = (jail_packet_ctx *) user_data;
    jail_packet *pkt;
    ssize_t pkt_siz;
    off_t pkt_off = 0;

    if (read_buf->fd == pkt_ctx->connection.jail_fd &&
        pkt_ctx->ctype == JC_SERVER)
    {
        if (pkt_ctx->pstate != JP_DATA)
            return 0;

        if (pkt_write(&pkt_ctx->writeback_buf, PKT_DATA,
                      (unsigned char *) read_buf->buf,
                      read_buf->buf_used))
        {
            return 1;
        }

        if (event_buf_drain(&pkt_ctx->writeback_buf) < 0)
            return 1;
        event_buf_discardall(read_buf);

        return 0;
    } else
    if (read_buf->fd != pkt_ctx->connection.client_fd &&
        pkt_ctx->ctype != JC_CLIENT)
    {
        W2("Unknown fd %d for jail packet", read_buf->fd);
        return 0;
    }

    while (1) {
        /* FIXME: not optimal for preventing buffer bloats */
        if (event_buf_avail(write_buf) < PKT_MAXSIZ)
            break;

        pkt_siz = pkt_header_read((unsigned char *) read_buf->buf + pkt_off,
                                  read_buf->buf_used);
        if (pkt_siz < 0) {
            /* invalid jail packet */
            pkt_ctx->pstate = JP_INVALID;
            break;
        } else if (pkt_siz == 0)
            /* require more data */
            break;

        pkt = (jail_packet *)(read_buf->buf + pkt_off);
        if (jpc[pkt->type].pc &&
            jpc[pkt->type].pc(pkt_ctx, pkt, write_buf))
        {
            pkt_ctx->pstate = JP_INVALID;
            break;
        }

        pkt_off += pkt_siz;
        read_buf->buf_used -= pkt_siz;
    }

    if (pkt_off)
        event_buf_discard(read_buf, pkt_off);

    if (event_buf_drain(write_buf) < 0)
        pkt_ctx->pstate = JP_INVALID;
    if (event_buf_drain(&pkt_ctx->writeback_buf) < 0)
        pkt_ctx->pstate = JP_INVALID;

    if (pkt_ctx->pstate == JP_NONE        /* default value not allowed */
        || pkt_ctx->pstate == JP_INVALID) /* an invalid state */
    {
        ev_ctx->has_error = 1;
        return 1;
    }

    ev_ctx->active = pkt_ctx->ev_active;

    return 0;
}

int jail_client_send(jail_packet_ctx *pkt_ctx, unsigned char *buf, size_t siz)
{
    if (pkt_write(&pkt_ctx->writeback_buf, PKT_DATA, buf, siz) ||
        event_buf_drain(&pkt_ctx->writeback_buf) < 0)
    {
        return 1;
    }
    return 0;
}

int jail_client_data(event_ctx *ctx, event_buf *in, event_buf *out,
                     jail_packet_ctx *pkt_ctx)
{
    assert(ctx && pkt_ctx);
    assert(in->fd >= 0 && out->fd < 0);
    assert(pkt_ctx->connection.client_fd >= 0 &&
           pkt_ctx->connection.jail_fd < 0);
    assert(pkt_ctx->pstate == JP_DATA ||
           pkt_ctx->pstate == JP_START ||
           pkt_ctx->pstate == JP_HANDSHAKE_END);

    if (pkt_ctx->pstate == JP_HANDSHAKE_END) {
        pkt_ctx->pstate = JP_START;
        if (pkt_write(&pkt_ctx->writeback_buf, PKT_START, NULL, 0) ||
            event_buf_drain(&pkt_ctx->writeback_buf) < 0)
        {
            return 1;
        }
    }

    if (pkt_ctx->ev_readloop)
        return event_loop(ctx, jail_packet_io, pkt_ctx) || ctx->has_error;
    else
        return jail_packet_pkt(ctx, in, out, pkt_ctx) || ctx->has_error;
}

int jail_server_loop(event_ctx *ctx, jail_packet_ctx *pkt_ctx)
{
    assert(ctx && pkt_ctx);
    assert(pkt_ctx->pstate == JP_START && pkt_ctx->ctype == JC_SERVER);
    assert(pkt_ctx->connection.client_fd >= 0 &&
           pkt_ctx->connection.jail_fd >= 0);
    pkt_ctx->ev_active = 1;

    return event_loop(ctx, jail_packet_io, pkt_ctx) || ctx->has_error;
}

event_ctx *jail_client_handshake(int server_fd, jail_packet_ctx *pkt_ctx)
{
    event_ctx *ev_ctx = NULL;
    event_buf write_buf = WRITE_BUF(server_fd);
    size_t user_len, pass_len;
    jail_packet_handshake pkt_hello;

    assert(pkt_ctx);
    assert(pkt_ctx->pstate == JP_NONE);
    assert(pkt_ctx->ctype == JC_CLIENT);

    pkt_ctx->pstate = JP_HANDSHAKE;
    pkt_ctx->ev_active = 1;

    event_init(&ev_ctx);
    if (event_setup(ev_ctx)) {
        E_STRERR("Jail protocol event context creation for jail tty fd %d",
            server_fd);
        goto finish;
    }
    if (set_fd_nonblock(server_fd)) {
        E_STRERR("Jail protocol nonblock for %d", server_fd);
        goto finish;
    }
    if (event_add_fd(ev_ctx, server_fd, NULL)) {
        E_STRERR("Jail protocol event context for fd %d", server_fd);
        goto finish;
    }

    pkt_hello.magic1 = htonl(JP_MAGIC1);
    pkt_hello.magic2 = htonl(JP_MAGIC2);
    if (pkt_write(&write_buf, PKT_HANDSHAKE,
                  (unsigned char *) &pkt_hello, sizeof(pkt_hello)))
    {
        goto finish;
    }

    if (pkt_ctx->user) {
        user_len = strnlen(pkt_ctx->user, USER_LEN);
        if (pkt_write(&write_buf, PKT_USER,
            (unsigned char *) pkt_ctx->user, user_len))
        {
            goto finish;
        }
    }
    if (pkt_ctx->pass) {
        pass_len = strnlen(pkt_ctx->pass, PASS_LEN);
        if (pkt_write(&write_buf, PKT_PASS,
            (unsigned char *) pkt_ctx->pass, pass_len))
        {
            goto finish;
        }
    }

    if (pkt_write(&write_buf, PKT_HANDSHAKE_END, NULL, 0))
        goto finish;

    if (event_buf_drain(&write_buf) < 0)
        goto finish;

    pkt_ctx->is_valid = 1;
    pkt_ctx->writeback_buf = write_buf;

    if (event_loop(ev_ctx, jail_packet_io, pkt_ctx) || ev_ctx->has_error ||
        pkt_ctx->pstate != JP_HANDSHAKE_END || !pkt_ctx->is_valid)
    {
        W_STRERR("Jail protocol handshake for fd %d", server_fd);
        goto finish;
    }

    return ev_ctx;
finish:
    event_free(&ev_ctx);
    return NULL;
}

int jail_server_handshake(event_ctx *ctx, jail_packet_ctx *pkt_ctx)
{
    int rc;

    assert(ctx && pkt_ctx);
    assert(pkt_ctx->pstate == JP_NONE);
    assert(pkt_ctx->ctype == JC_SERVER);

    struct event_buf write_buf = WRITE_BUF(pkt_ctx->connection.client_fd);
    pkt_ctx->pstate = JP_HANDSHAKE;
    pkt_ctx->ev_active = 1;
    pkt_ctx->writeback_buf = write_buf;

    rc = event_loop(ctx, jail_packet_io, pkt_ctx);
    if (!rc && pkt_ctx->is_valid)
        pkt_ctx->pstate = JP_START;

    return rc;
}
