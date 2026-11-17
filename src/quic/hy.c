#include "quic/hy.h"

#include "quic/pad.h"
#include "quic/varint.h"

#include <string.h>

/* The frame type that opens a proxied TCP connection. There is exactly one frame type on a Hysteria2
 * proxy stream, and it appears once, at the start. */
#define HY_FRAME_TCP_REQUEST 0x401u

long lc_hy_tcp_request(const char *addr, uint8_t *out, size_t cap)
{
    size_t addr_len = strlen(addr);
    if (addr_len == 0 || addr_len > LC_HY_ADDR_MAX)
        return -1;

    uint32_t pad_len = 0;
    if (lc_pad_draw(LC_PAD_TCP_REQ_MIN, LC_PAD_TCP_REQ_MAX, &pad_len) != 0)
        return -1;

    size_t n = 0, k;

/* Each writer returns zero when it would not fit, and a frame built past that point is one whose
 * length fields no longer describe it. */
#define ADD(expr)                                                                                  \
    do {                                                                                           \
        k = (expr);                                                                                \
        if (k == 0)                                                                                \
            return -1;                                                                             \
        n += k;                                                                                    \
    } while (0)

    ADD(lc_varint_put(out + n, cap - n, HY_FRAME_TCP_REQUEST));
    ADD(lc_varint_put(out + n, cap - n, addr_len));
    if (cap - n < addr_len)
        return -1;
    memcpy(out + n, addr, addr_len);
    n += addr_len;

    ADD(lc_varint_put(out + n, cap - n, pad_len));
    if (cap - n < pad_len || lc_pad_fill((char *)out + n, pad_len) != 0)
        return -1;
    n += pad_len;

#undef ADD

    return (long)n;
}

long lc_hy_tcp_response(const uint8_t *in, size_t len, lc_hy_tcp_reply *out)
{
    memset(out, 0, sizeof *out);

    size_t off = 0;
    if (len < 1u)
        return 0;
    uint8_t status = in[off++];

    uint64_t msg_len = 0;
    if (lc_varint_get(in, len, &off, &msg_len) != 0)
        return 0;
    /* Bounded while it is still sixty-two bits wide, and only then narrowed. On a thirty-two bit
     * router a length and an offset are not the same size, and a cast placed before the test would
     * turn a length too large to be true into a small one that passes. */
    if (msg_len > LC_HY_MSG_MAX)
        return -1;
    if (msg_len > (uint64_t)(len - off))
        return 0;

    /* The node's explanation of a refusal — "dial tcp: connection refused" and the like. Kept only
     * to be shown, and truncated to what a message worth showing needs, because its length is the
     * node's choice and this buffer is ours. */
    size_t keep = msg_len < sizeof out->message ? (size_t)msg_len : sizeof out->message - 1u;
    memcpy(out->message, in + off, keep);
    out->message[keep] = '\0';
    off += (size_t)msg_len;

    uint64_t pad_len = 0;
    if (lc_varint_get(in, len, &off, &pad_len) != 0)
        return 0;
    if (pad_len > LC_HY_PADDING_MAX)
        return -1;
    if (pad_len > (uint64_t)(len - off))
        return 0;
    off += (size_t)pad_len;

    /* Zero is the only "it worked". Every other value is a refusal, and treating an unknown one as
     * success would mean relaying bytes into a connection the node never opened. */
    out->ok = status == 0;
    return (long)off;
}

/* ---- UDP ---- */

/* Session, packet, fragment number and count are fixed-width and big-endian; only the address is a
 * length and bytes. Eight bytes before it, always. */
#define UDP_FIXED 8u

size_t lc_hy_udp_header_len(const char *addr)
{
    size_t n = strlen(addr);
    return UDP_FIXED + lc_varint_len(n) + n;
}

long lc_hy_udp_put(const lc_hy_udp *msg, uint8_t *out, size_t cap)
{
    size_t addr_len = strlen(msg->addr);
    if (addr_len == 0 || addr_len > LC_HY_ADDR_MAX)
        return -1;

    size_t need = lc_hy_udp_header_len(msg->addr) + msg->len;
    if (need > cap)
        return -1;

    out[0] = (uint8_t)(msg->session >> 24);
    out[1] = (uint8_t)(msg->session >> 16);
    out[2] = (uint8_t)(msg->session >> 8);
    out[3] = (uint8_t)msg->session;
    out[4] = (uint8_t)(msg->packet >> 8);
    out[5] = (uint8_t)msg->packet;
    out[6] = msg->frag;
    out[7] = msg->frag_count;

    size_t n = UDP_FIXED;
    n += lc_varint_put(out + n, cap - n, addr_len);
    memcpy(out + n, msg->addr, addr_len);
    n += addr_len;

    memcpy(out + n, msg->data, msg->len);
    return (long)(n + msg->len);
}

int lc_hy_udp_parse(const uint8_t *in, size_t len, lc_hy_udp *out)
{
    memset(out, 0, sizeof *out);
    if (len < UDP_FIXED)
        return -1;

    out->session = (uint32_t)in[0] << 24 | (uint32_t)in[1] << 16 | (uint32_t)in[2] << 8 | in[3];
    out->packet = (uint16_t)((uint16_t)in[4] << 8 | in[5]);
    out->frag = in[6];
    out->frag_count = in[7];

    size_t   off = UDP_FIXED;
    uint64_t addr_len = 0;
    if (lc_varint_get(in, len, &off, &addr_len) != 0)
        return -1;
    /* Bounded before it is narrowed, for the reason given in lc_hy_tcp_response. */
    if (addr_len == 0 || addr_len > LC_HY_ADDR_MAX || addr_len > (uint64_t)(len - off))
        return -1;

    memcpy(out->addr, in + off, (size_t)addr_len);
    out->addr[(size_t)addr_len] = '\0';
    off += (size_t)addr_len;

    /* At least one byte after the address, which the reference states outright rather than by
     * accident: ParseUDPMessage compares `len(bs) <= int(lAddr)` and says why in a comment beside
     * it — "We use <= instead of < here as we expect at least one byte of data after the address"
     * (vendor/hysteria/core/internal/protocol/proxy.go:216-218). We accepted the empty payload and
     * passed a zero-length datagram up. */
    if (len - off == 0)
        return -1;

    /* A fragment numbered past the count cannot be reassembled and is refused — but a count of ZERO
     * is not that, and refusing it was ours alone. The reference splits the two decisions across two
     * files: ParseUDPMessage does not look at these fields at all, and Defragger.Feed opens with
     * `if m.FragCount <= 1 { return m }` (vendor/hysteria/core/internal/frag/frag.go:47-50), so a
     * count of zero is delivered as a whole message exactly like a count of one. Only past that does
     * it drop `m.FragID >= m.FragCount`. Ours rejected the datagram outright, which means a node
     * that ever emits a zero count — legal to the reference and its own client — went unheard. */
    if (out->frag_count > 1u && out->frag >= out->frag_count)
        return -1;

    out->data = in + off;
    out->len = len - off;
    return 0;
}
