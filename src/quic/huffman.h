/* The Huffman coding HTTP/3 headers are written in.
 *
 * Not optional, and that is worth saying plainly: a QPACK literal carries one bit that says whether
 * its octets are Huffman-coded, and Go's encoder — which is what quic-go, and therefore every
 * Hysteria2 server, answers with — sets it whenever the coding comes out shorter. That is a rule
 * with a line rather than a habit: "s will be encoded in Huffman codes only when it produces
 * strictly shorter byte string", and then `if huffmanLength < uint64(len(s))`
 * (vendor/x-net/http2/hpack/encode.go:212-227). For a status line and a few hundred characters of
 * padding it always does. A client that cannot read this cannot read the answer to a single
 * question it asks.
 *
 * Encoding matters for a different reason. A server does not care which form a request arrives in,
 * but anything watching the connection can: sending literals in the clear where the reference
 * client sends them coded is a difference in every packet, visible without decrypting anything, and
 * the point of this client is to be the reference client. */
#ifndef LC_HUFFMAN_H
#define LC_HUFFMAN_H

#include <stddef.h>
#include <stdint.h>

/* Decodes `len` bytes into `out`, which is written up to `cap` bytes and always terminated.
 *
 * Returns the FULL decoded length, which may be larger than what was written — the caller decides
 * whether a value too long to keep is one it needed. Returns -1 if the input is not a valid coding:
 * a code that is not in the table, an end-of-string symbol (which RFC 7541 section 5.2 forbids in a
 * value), or padding that is anything other than up to seven one bits. */
long lc_huff_decode(const uint8_t *in, size_t len, char *out, size_t cap);

/* Bytes the coding of `in` would take. */
size_t lc_huff_len(const char *in, size_t len);

/* Encodes into `out`. Returns the number of bytes written, or -1 if it does not fit. */
long lc_huff_encode(const char *in, size_t len, uint8_t *out, size_t cap);

#endif
