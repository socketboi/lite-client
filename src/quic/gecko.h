/* Gecko — the second obfuscation, which changes the SHAPE rather than the bytes.
 *
 * Salamander removes the structure of a QUIC packet; what it leaves is a datagram of exactly the
 * size QUIC produced. A handshake has a recognisable size pattern — a client Initial padded to
 * 1200, an answer of two or three packets, a distinctive back-and-forth — and that pattern survives
 * XOR untouched. Gecko breaks it: every LONG-HEADER packet, which is to say every packet of the
 * handshake, is cut into between two and eight pieces of its own, each padded to a random length
 * and sent as its own datagram. Short-header packets — the data, after the handshake — pass through
 * whole, because there the shape is traffic and hiding it would cost throughput.
 *
 * It WRAPS Salamander rather than replacing it: the frame below is built first and Salamander
 * scrambles each frame as an independent datagram. Order matters in both directions and is the
 * first thing to check when this does not interoperate.
 *
 *     [1 byte]  0x80        the fragment marker; low seven bits reserved
 *     [1 byte]  msgID       which original packet this belongs to
 *     [1 byte]  chunkIdx:4 | totalChunks:4
 *     [2 bytes] padLen      big-endian
 *     [padLen]  padding     random, ignored on receive
 *     [bytes]   chunk       this piece of the original packet
 *
 * Not implementing it is not a degraded mode. A server running Gecko treats every long-header
 * datagram as a frame and drops anything that does not decode: `h, payload, decErr :=
 * decodeFrame(buf[:n])` and then, on error, "Malformed frame; drop silently" followed by `continue`
 * and nothing else (vendor/hysteria/extras/obfs/gecko.go:186-189). Our Initial has 0x80 set (it is
 * a long header) and a version field whose second byte is zero, which decodes as totalChunks = 0
 * and is refused. Every packet, deterministically. So a node configured for Gecko is not slow for a
 * Salamander-only client, it is silent — and this client would report it as a path that ate the
 * handshake, which is the wrong answer written confidently.
 *
 * What is deliberately simpler here than upstream: reassembly is keyed by msgID alone, without the
 * sender's address — upstream keys it `reassemblyKey{addr: addr.String(), msgID: h.msgID}`
 * (vendor/hysteria/extras/obfs/gecko.go:200). That is not a shortcut but a difference in the job:
 * upstream is a server taking frames from every client at once, and this socket is connected to one
 * node, so the address is a constant. Everything else, including the drop rules, follows the
 * reference exactly, because a
 * receiver that accepts more than the reference does is a receiver that behaves differently under
 * exactly the conditions somebody is probing for. */

#ifndef LC_QGECKO_H
#define LC_QGECKO_H

#include <stddef.h>
#include <stdint.h>

/* The header before the padding: marker, msgID, indices, padLen. */
#define LC_GECKO_HEADER 5u

/* How many pieces one packet becomes. Both ends of the range are the reference's. */
#define LC_GECKO_MIN_CHUNKS 2u
#define LC_GECKO_MAX_CHUNKS 8u

/* Datagram sizes the padding aims for, before Salamander's salt is counted in. geckoDefaultMinPacket
 * and geckoDefaultMaxPacket (vendor/hysteria/extras/obfs/gecko.go:24-25). */
#define LC_GECKO_MIN_PACKET 512u
#define LC_GECKO_MAX_PACKET 1200u

/* AND THE CEILING, WHICH IS A DIFFERENT NUMBER FROM THE DEFAULT.
 *
 * The reference has two: geckoDefaultMaxPacket = 1200 is what a caller gets when it asks for
 * nothing, and geckoBufferSize = 2048 (vendor/hysteria/extras/obfs/gecko.go:22) is both the largest configuration it accepts
 * (`maxPkt > geckoBufferSize` is the refusal, vendor/hysteria/extras/obfs/gecko.go:45) and the size of the buffer it reads
 * into (vendor/hysteria/extras/obfs/gecko.go:89). We had only the default and used it for all three jobs, so a node configured
 * anywhere above 1200 — which its own client accepts up to 2048 — could neither be configured here
 * nor have its datagrams received: the receive path dropped anything longer as well. */
#define LC_GECKO_BUFFER 2048u

/* How long a half-arrived packet is kept, and how many may be in progress at once. Upstream keeps
 * eight per source and this client has one source, so eight is the whole table. */
#define LC_GECKO_TTL_MS 8000u
#define LC_GECKO_SLOTS 8u

/* One packet being put back together. */
typedef struct {
    uint8_t  used;
    uint8_t  msg_id;
    uint8_t  total;
    uint8_t  got;
    /* Which indices have arrived, one bit each — so that a duplicate is refused even when the
     * piece it repeats is empty, which a short packet cut into eight legitimately produces. */
    uint8_t  seen;
    uint64_t deadline_ms;
    /* Held by value rather than by pointer: a chunk is bounded by the datagram that carried it, and
     * eight of those is sixteen kilobytes for the whole table — less than one malloc'd stream, and
     * without a free to get wrong on a path that runs before the handshake completes. */
    uint16_t len[LC_GECKO_MAX_CHUNKS];
    uint8_t  chunk[LC_GECKO_MAX_CHUNKS][LC_GECKO_BUFFER];
} lc_gecko_slot;

typedef struct {
    int         on;
    unsigned    min_packet, max_packet;
    uint8_t     next_msg_id;
    lc_gecko_slot slot[LC_GECKO_SLOTS];
} lc_gecko;

/* One packet cut into frames, ready to be scrambled and sent one at a time. */
typedef struct {
    unsigned count;
    uint16_t len[LC_GECKO_MAX_CHUNKS];
    uint8_t  frame[LC_GECKO_MAX_CHUNKS][LC_GECKO_BUFFER];
} lc_gecko_out;

/* Arms it, or leaves it off when `on` is zero. Sizes of zero take the reference's defaults. */
int lc_gecko_init(lc_gecko *g, int on, unsigned min_packet, unsigned max_packet);

/* Whether this packet is one Gecko touches: a long header, which is the whole of the handshake.
 * Callers use it to decide between splitting and sending as-is, and it is exported because that
 * decision is the protocol rather than an implementation detail. */
int lc_gecko_applies(const lc_gecko *g, const uint8_t *pkt, size_t len);

/* Cuts `pkt` into frames. Returns 0 with `out->count` frames to send in order, or -1 if the packet
 * cannot be framed at all. */
int lc_gecko_split(lc_gecko *g, const uint8_t *pkt, size_t len, lc_gecko_out *out);

/* One arrived frame, already unscrambled.
 *
 * Returns the length of a whole packet written to `dst` when this frame completed one, 0 when more
 * are still owed, and -1 when the frame is refused — malformed, duplicated, or disagreeing with the
 * pieces already held. `now_ms` retires half-arrived packets whose time is up. */
long lc_gecko_take(lc_gecko *g, const uint8_t *frame, size_t len, uint64_t now_ms, uint8_t *dst,
                   size_t dst_cap);

#endif
