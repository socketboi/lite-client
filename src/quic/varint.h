/* QUIC's variable-length integer, RFC 9000 section 16.
 *
 * Two bits of length at the top, then the value: one, two, four or eight bytes. It appears in three
 * unrelated places in this client — QUIC's own frames, HTTP/3's, and Hysteria2's proxy framing —
 * which is why it lives here rather than three times over. */
#ifndef LC_VARINT_H
#define LC_VARINT_H

#include <stddef.h>
#include <stdint.h>

/* The largest value the encoding can hold: 2^62 - 1 — the same bound the QUIC library beside us
 * writes as an expression rather than a literal: `#define NGTCP2_MAX_VARINT ((1ULL << 62) - 1)`
 * (vendor/ngtcp2/lib/includes/ngtcp2/ngtcp2.h:357). Spelled out here so that a reader comparing
 * the two sees one number and not an arithmetic exercise; the value is identical. */
#define LC_VARINT_MAX 4611686018427387903ull

/* Bytes `v` takes, or 0 if it is too large to encode. */
size_t lc_varint_len(uint64_t v);

/* Writes `v` and returns how many bytes it took, or 0 if it did not fit. Always the shortest
 * encoding: longer ones are legal and nothing produces them, so producing one would be a mark. */
size_t lc_varint_put(uint8_t *out, size_t cap, uint64_t v);

/* Reads one, advancing `*off`. Returns 0, or -1 when the bytes are not all here yet — which is not
 * the same as malformed, and the caller usually wants to wait rather than fail. */
int lc_varint_get(const uint8_t *in, size_t len, size_t *off, uint64_t *out);

#endif
