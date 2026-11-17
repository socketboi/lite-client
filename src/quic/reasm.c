#include "quic/reasm.h"

#include <string.h>

/* Raising LC_QUDP_FRAGS above eight stops the build rather than silently losing the top fragments:
 * `seen` is a uint8_t and a shift past the end of a type is undefined, not a compile error. */
_Static_assert(LC_QUDP_FRAGS <= 8, "seen is a uint8_t bitmap; widen it before raising this");

void lc_qreasm_reset(lc_qreasm *r, uint16_t packet, uint8_t count)
{
    r->packet = packet;
    r->count = count;
    r->have = 0;
    r->seen = 0;
    r->used = 0;
    memset(r->frag, 0, sizeof r->frag);
}

long lc_qreasm_feed(lc_qreasm *r, const lc_hy_udp *msg, uint8_t *out, size_t out_cap,
                    const uint8_t **data)
{
    /* The whole packet in one datagram, which is the usual case: handed on without a copy.
     *
     * `<= 1` rather than `== 1`, matching Defragger.Feed's own first line
     * (vendor/hysteria/core/internal/frag/frag.go:48) — a count of zero means the same thing as a
     * count of one there, and the parser lets it through instead of refusing it. */
    if (msg->frag_count <= 1u) {
        *data = msg->data;
        return (long)msg->len;
    }

    if (msg->frag_count > LC_QUDP_FRAGS || msg->len > LC_HY_UDP_MAX)
        return -1;

    /* The reference's condition has TWO halves — `m.PacketID != d.pktID || m.FragCount !=
     * uint8(len(d.frags))` (frag.go:55) — and the second is not decoration: without it a packet
     * reusing the id with a different piece count would be indexed into a table sized for the old
     * one. */
    if (msg->packet != r->packet || msg->frag_count != r->count)
        lc_qreasm_reset(r, msg->packet, msg->frag_count);

    /* `msg->frag` is already known to be below `frag_count`: the guard is in the parser, `if
     * (out->frag_count > 1u && out->frag >= out->frag_count)` at quic/hy.c:172, citing the
     * reference's own `m.FragID >= m.FragCount` (frag.go:51). With the count bound five lines above,
     * the index is inside frag[LC_QUDP_FRAGS] and inside the `seen` bitmap. */
    if (((unsigned)r->seen >> msg->frag & 1u) != 0)
        return -1; /* the same fragment twice */
    if (r->used + msg->len > LC_HY_UDP_MAX)
        return -1;

    r->frag[msg->frag].off = (uint16_t)r->used;
    r->frag[msg->frag].len = (uint16_t)msg->len;
    memcpy(r->buf + r->used, msg->data, msg->len);
    r->used += msg->len;
    r->seen = (uint8_t)(r->seen | 1u << msg->frag);
    r->have++;

    if (r->have < r->count)
        return 0;

    /* All there. Put together in fragment order, which is not the order they arrived in. */
    if (r->used > out_cap)
        return -1;
    size_t n = 0;
    for (unsigned i = 0; i < r->count; i++) {
        memcpy(out + n, r->buf + r->frag[i].off, r->frag[i].len);
        n += r->frag[i].len;
    }

    /* ⚠️ AND THE STATE STAYS, which is what stops the same packet being delivered twice.
     *
     * These lines used to be cleared here, on the reasonable-sounding ground that the packet was
     * finished with. The reference does not clear them: Defragger.Feed assembles and returns without
     * touching d.frags or d.count (vendor/hysteria/core/internal/frag/frag.go:66-77), so every slot
     * stays occupied — and the branch holding that assembly is ENTERED only through
     * `} else if d.frags[m.FragID] == nil {`
     * (vendor/hysteria/core/internal/frag/frag.go:62), which is what discards a duplicate: a
     * fragment id already filled fails the test, the branch is skipped, and Feed falls through to
     * its closing `return nil`. This used to say "the very next line of the function", which had
     * the direction backwards — the guard stands four lines ABOVE the assembly, not after it, and
     * because the quoted line carried no line number of its own the sieve mapped it onto 66-77,
     * where it does not appear. Found by lcquote.pl, the only check that reads the quotes.
     * Clearing `seen` put every slot back to "not yet arrived", so a retransmitted packet, which is
     * ordinary on a lossy path and is exactly what this client's path does, was reassembled a second
     * time and handed up again. A DNS answer delivered twice is harmless; a game or a QUIC-inside-
     * QUIC packet delivered twice is not.
     *
     * What replaces the state is the reset above, on the reference's two-part condition. */
    *data = out;
    return (long)n;
}
