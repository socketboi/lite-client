/* Putting a proxied UDP packet back together from the pieces the node split it into.
 *
 * Split out of conn.c for the reason quic/txbuf.c and quic/dgram.c were: conn.c cannot be loaded by
 * a test without the whole vendored QUIC stack, so logic living there is logic nothing ever asks.
 * This is the last piece of that kind in the tree, and the one with the worst input — every byte
 * here arrives from the node, in whatever order and whatever number of copies the path produced.
 *
 * The parser is elsewhere and IS checked: quic/hy.c reads the eight fixed bytes and refuses a
 * fragment numbered at or past its own count (src/quic/hy.c:172, test/hy — written with its
 * directory so the sieve reads it as one of ours rather than trying, and failing, to find an
 * `hy.c` in vendor). What was never checked is what
 * happens after — the bitmap of which pieces have arrived, the offsets they were stored at, the
 * order they are put back in, and when the state is thrown away. Those are the parts that decide
 * whether a packet is delivered once, twice or not at all.
 *
 * The rules are the reference's, and each is named at the line that implements it
 * (vendor/hysteria/core/internal/frag/frag.go). */
#ifndef LC_QREASM_H
#define LC_QREASM_H

#include "quic/hy.h"

#include <stddef.h>
#include <stdint.h>

/* Fragments one UDP packet may be split into. Four is the most that a packet of LC_HY_UDP_MAX can
 * need at this datagram size; eight leaves room and puts a floor under how much state a sender can
 * make us hold for a packet it never finishes. */
#define LC_QUDP_FRAGS 8

/* What one session is holding of a packet that has not fully arrived.
 *
 * Fragments are kept in the order they ARRIVE and put together at the end, because nothing in a
 * fragment says where in the packet it belongs — only which number it is — and the ones before it
 * may not have come yet. */
typedef struct {
    uint16_t packet; /* the packet being reassembled */
    /* `seen` is a bitmap over fragment numbers, one bit each, and its width has to cover
     * LC_QUDP_FRAGS. Nothing in the code says so — a shift past the end of the type is undefined,
     * not a compile error — so the assertion in reasm.c says it instead. */
    uint8_t  count, have, seen;
    /* LC_HY_UDP_MAX bytes, owned by whoever opened the session: a session that is not carrying
     * anything should not be holding four kilobytes. */
    uint8_t *buf;
    size_t   used;
    struct {
        uint16_t off, len;
    } frag[LC_QUDP_FRAGS];
} lc_qreasm;

/* Throws away whatever was being held and starts on `packet`, expecting `count` pieces. */
void lc_qreasm_reset(lc_qreasm *r, uint16_t packet, uint8_t count);

/* Takes one parsed message and says what became of it.
 *
 *   -1  drop it — a duplicate, a count this build will not hold, or a piece that does not fit
 *    0  held; the packet is not complete yet
 *   >0  a whole packet, of that many bytes, at *data
 *
 * `out` is written only when pieces actually had to be joined. A packet that arrived whole is
 * handed back by pointing *data into the message itself, which is the usual case and costs no copy.
 * So *data is valid for exactly as long as whichever of the two it points at. */
long lc_qreasm_feed(lc_qreasm *r, const lc_hy_udp *msg, uint8_t *out, size_t out_cap,
                    const uint8_t **data);

#endif
