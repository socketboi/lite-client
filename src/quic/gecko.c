#include "quic/gecko.h"

#include "core/rnd.h"

#include "quic/obfs.h"
#include "quic/pad.h"

#include <string.h>

int lc_gecko_init(lc_gecko *g, int on, unsigned min_packet, unsigned max_packet)
{
    memset(g, 0, sizeof *g);
    g->on = on != 0;
    g->min_packet = min_packet != 0 ? min_packet : LC_GECKO_MIN_PACKET;
    g->max_packet = max_packet != 0 ? max_packet : LC_GECKO_MAX_PACKET;
    /* The same three refusals the reference makes (WrapPacketConnGecko), and for the same reason:
     * a maximum below the minimum, or above what a frame buffer holds, is a configuration that
     * would fail later as dropped packets nobody could explain. */
    if (g->min_packet == 0u || g->min_packet > g->max_packet || g->max_packet > LC_GECKO_BUFFER)
        return -1;
    return 0;
}

int lc_gecko_applies(const lc_gecko *g, const uint8_t *pkt, size_t len)
{
    /* The long-header bit, which QUIC sets on exactly the packets of the handshake. Tested the way
     * the reference tests it — on the first byte and nothing else — rather than by parsing the
     * packet: what has to agree between the two ends is the DECISION, and a cleverer test that
     * disagreed once would split a packet the server expected whole. */
    return g->on && len > 0 && (pkt[0] & 0x80u) != 0u;
}

/* A number in [0, bound), drawn as the reference's randIntn draws it: four bytes of crypto/rand, big
 * endian, modulo the bound — `binary.BigEndian.Uint32(b[:]) % uint32(n)`, and 0 without a draw for a
 * bound of one or less (vendor/hysteria/extras/obfs/gecko.go:157-165). A modulo, so the low values
 * weigh a little more; that is the reference's draw.
 *
 * ⚠️ UNTIL 2026-09-27 this was the unbiased draw the padding uses, kept on the argument that the
 * bias was too small to see and that reproducing it was "not fidelity". Too small to see is still
 * another draw, and which draw is the reference's to decide. */
static int below(uint32_t bound, uint32_t *out)
{
    uint8_t b[4];
    if (bound <= 1u) {
        *out = 0;
        return 0;
    }
    if (lc_rnd(b, sizeof b) != 0)
        return -1;
    *out = ((uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | b[3]) % bound;
    return 0;
}

/* Padding chosen so the finished datagram — Salamander's salt, this header, the padding and the
 * chunk — lands inside [min_packet, max_packet]. A chunk already past the maximum takes none, which
 * is the reference's rule and the reason a large packet cut into two still goes out. */
static int pad_len(const lc_gecko *g, size_t chunk_len, uint32_t *out)
{
    size_t base = LC_OBFS_SALT + LC_GECKO_HEADER + chunk_len;
    size_t lo = base > g->min_packet ? base : g->min_packet;
    if (lo > g->max_packet) {
        *out = 0;
        return 0;
    }
    uint32_t extra = 0;
    if (below((uint32_t)(g->max_packet - lo + 1u), &extra) != 0)
        return 1;
    *out = (uint32_t)(lo - base) + extra;
    return 0;
}

int lc_gecko_split(lc_gecko *g, const uint8_t *pkt, size_t len, lc_gecko_out *out)
{
    memset(out, 0, sizeof *out);
    if (len == 0)
        return -1;

    uint32_t pick = 0;
    if (below(LC_GECKO_MAX_CHUNKS - LC_GECKO_MIN_CHUNKS + 1u, &pick) != 0)
        return -1;
    unsigned chunks = LC_GECKO_MIN_CHUNKS + pick;

    /* Integer division with the remainder on the last piece, exactly as upstream does it. A tidier
     * split — evening the pieces out — would be a different set of lengths on the wire, and the
     * lengths are the whole point of this layer. A packet shorter than the number of pieces gives
     * empty ones, which the frame format allows and the reference also produces. */
    size_t   chunk_size = len / chunks;
    uint8_t  msg_id = ++g->next_msg_id;

    for (unsigned i = 0; i < chunks; i++) {
        size_t start = (size_t)i * chunk_size;
        size_t end = i + 1u < chunks ? start + chunk_size : len;
        size_t take = end - start;

        uint32_t pad = 0;
        if (pad_len(g, take, &pad) != 0)
            return -1;

        size_t need = LC_GECKO_HEADER + pad + take;
        if (need > sizeof out->frame[i])
            return -1;

        uint8_t *f = out->frame[i];
        f[0] = 0x80u;
        f[1] = msg_id;
        f[2] = (uint8_t)((uint8_t)(i << 4) | (uint8_t)(chunks & 0x0fu));
        f[3] = (uint8_t)(pad >> 8);
        f[4] = (uint8_t)pad;
        /* UNIFORM RANDOM BYTES, not the alphanumeric alphabet Hysteria's other padding uses.
         *
         * encodeFrame fills this run with `rand.Read(out[geckoHeaderSize : geckoHeaderSize+padLen])`
         * (vendor/hysteria/extras/obfs/gecko_frame.go:54) — the whole byte range, every value. The
         * 62-character alphabet belongs to the protocol paddings in src/quic/pad.h, where it is
         * right because those travel inside HTTP/3 header values and their Huffman coding decides
         * the message size. Here nothing is Huffman-coded and the bytes are XORed by Salamander,
         * whose key repeats every 32 bytes: a long run drawn from 62 of 256 values keeps a bias
         * that survives the XOR, and a run of that shape appears in no Gecko frame the reference
         * produces. */
        if (pad > 0 && lc_rnd(f + LC_GECKO_HEADER, pad) != 0)
            return -1;
        memcpy(f + LC_GECKO_HEADER + pad, pkt + start, take);
        out->len[i] = (uint16_t)need;
    }

    out->count = chunks;
    return 0;
}

static void slot_drop(lc_gecko_slot *s)
{
    s->used = 0;
    s->got = 0;
    s->total = 0;
    s->seen = 0;
}

static void expire(lc_gecko *g, uint64_t now_ms)
{
    for (unsigned i = 0; i < LC_GECKO_SLOTS; i++)
        if (g->slot[i].used && now_ms >= g->slot[i].deadline_ms)
            slot_drop(&g->slot[i]);
}

long lc_gecko_take(lc_gecko *g, const uint8_t *frame, size_t len, uint64_t now_ms, uint8_t *dst,
                   size_t dst_cap)
{
    expire(g, now_ms);

    if (len < LC_GECKO_HEADER || (frame[0] & 0x80u) == 0u)
        return -1;

    uint8_t  msg_id = frame[1];
    uint8_t  idx = (uint8_t)(frame[2] >> 4);
    uint8_t  total = (uint8_t)(frame[2] & 0x0fu);
    uint16_t pad = (uint16_t)((uint16_t)frame[3] << 8 | frame[4]);

    if (total < LC_GECKO_MIN_CHUNKS || total > LC_GECKO_MAX_CHUNKS || idx >= total)
        return -1;
    if ((size_t)LC_GECKO_HEADER + pad > len)
        return -1;

    const uint8_t *payload = frame + LC_GECKO_HEADER + pad;
    size_t         payload_len = len - LC_GECKO_HEADER - pad;
    /* Against the buffer, not against the default: what may arrive is bounded by what the sender
     * was allowed to configure, and the reference lets that reach geckoBufferSize. */
    if (payload_len > LC_GECKO_BUFFER)
        return -1;

    lc_gecko_slot *s = NULL;
    for (unsigned i = 0; i < LC_GECKO_SLOTS; i++)
        if (g->slot[i].used && g->slot[i].msg_id == msg_id) {
            s = &g->slot[i];
            break;
        }

    if (s == NULL) {
        for (unsigned i = 0; i < LC_GECKO_SLOTS && s == NULL; i++)
            if (!g->slot[i].used)
                s = &g->slot[i];
        /* Full, and nothing is thrown out to make room: eight packets in flight from one node is
         * already more than a handshake produces, so a ninth is either a lost fragment holding a
         * slot until its time is up, or somebody filling the table on purpose. Refusing is the
         * cheaper mistake — the QUIC below retransmits. */
        if (s == NULL)
            return -1;
        memset(s, 0, sizeof *s);
        s->used = 1;
        s->msg_id = msg_id;
        s->total = total;
        s->deadline_ms = now_ms + LC_GECKO_TTL_MS;
    } else if (s->total != total) {
        /* THIS FRAME GOES AND THE PACKET STAYS, which is the reference's rule and was not ours.
         *
         * acceptChunk answers a disagreement about the piece count with `return nil, false`
         * (vendor/hysteria/extras/obfs/gecko.go:222-225) — the frame is not accepted and nothing
         * else happens; the entry is only ever removed by dropEntryLocked, which is reached from
         * the TTL sweep, from eviction, and from a completed packet. What stood here dropped the
         * whole half-built packet instead, on the ground that one of the two frames must be forged.
         *
         * That ground does not survive the arithmetic. msg_id is one byte and steps once per long
         * header, so after 256 of them the numbers come round again — and a frame from the previous
         * round, delayed on the path, disagrees about the count for entirely innocent reasons. Under
         * the old rule it took the live handshake with it; under this one it is ignored and the
         * packet completes. */
        return -1;
    }

    if ((s->seen & (uint8_t)(1u << idx)) != 0)
        return -1; /* a piece that has already arrived; the reference drops these too */

    memcpy(s->chunk[idx], payload, payload_len);
    s->len[idx] = (uint16_t)payload_len;
    s->seen |= (uint8_t)(1u << idx);
    s->got++;

    /* A zero-length piece is legal — a packet shorter than its piece count produces them — so
     * arrival is counted rather than inferred from the length. */
    if (s->got < s->total)
        return 0;

    size_t total_len = 0;
    for (unsigned i = 0; i < s->total; i++)
        total_len += s->len[i];
    if (total_len > dst_cap) {
        slot_drop(s);
        return -1;
    }

    size_t off = 0;
    for (unsigned i = 0; i < s->total; i++) {
        memcpy(dst + off, s->chunk[i], s->len[i]);
        off += s->len[i];
    }
    slot_drop(s);
    return (long)off;
}
