/* Integers with a prefix, as HPACK and QPACK both spell them.
 *
 * RFC 7541 section 5.1 and RFC 9204 section 4.1.1 describe the same encoding in the same words: a
 * few bits sharing the first byte with a pattern, and if they are all ones, the remainder follows
 * seven bits at a time. Two protocols, one encoding — so one implementation, because two would be
 * identical on the day they were written and would not stay that way.
 *
 * It lives under quic/ for the same reason src/quic/huffman.c does: that is where the header
 * compression this client speaks was written first. Both are shared with HTTP/2, which is not QUIC
 * at all — a naming debt, not a layering one. */
#ifndef LC_PREFIX_H
#define LC_PREFIX_H

#include <stddef.h>
#include <stdint.h>

/* Writes `v` behind `bits` of prefix, with `pattern` in the bits above it. Returns the length, or 0
 * if it did not fit. */
size_t lc_prefix_put(uint8_t *out, size_t cap, uint8_t pattern, unsigned bits, uint64_t v);

/* Reads one, advancing `*off`. Returns 0, or -1 when the bytes are not all here yet or the value is
 * longer than anything real — a continuation that never ends is how a header block asks a decoder
 * to loop forever. */
int lc_prefix_get(const uint8_t *in, size_t len, size_t *off, unsigned bits, uint64_t *out);

/* A string as both compressions carry one: a length in a prefixed integer with the Huffman bit
 * immediately above `bits`, then the octets — coded when the coding is shorter and left alone when
 * it is not. Returns the total length written, or 0 if it did not fit or the coder disagreed with
 * its own length estimate.
 *
 * Here for the reason given at the top of this file, and it took a second near-copy to notice.
 * h2/hpack.c and quic/h3.c each grew one of these, identical in shape and different in rigour: the
 * HPACK one compared what lc_huff_encode actually wrote against the length it had just declared,
 * and the QPACK one only checked the sign. A frame whose declared length disagrees with its own
 * bytes is not a frame anything recovers from, and only one of the two would have caught it. */
size_t lc_prefix_put_string(uint8_t *out, size_t cap, uint8_t pattern, unsigned bits,
                            const char *s, size_t len);

/* The same with the octets Huffman-coded whatever their length: QPACK as quic-go writes it. */
size_t lc_prefix_put_huffman(uint8_t *out, size_t cap, uint8_t pattern, unsigned bits, const char *s,
                             size_t len);

#endif
