#include "quic/prefix.h"

#include "quic/huffman.h"

#include <string.h>

size_t lc_prefix_put(uint8_t *out, size_t cap, uint8_t pattern, unsigned bits, uint64_t v)
{
    uint8_t max = (uint8_t)((1u << bits) - 1u);
    if (cap < 1u)
        return 0;
    if (v < max) {
        out[0] = (uint8_t)(pattern | v);
        return 1u;
    }
    out[0] = pattern | max;
    v -= max;
    size_t i = 1;
    while (v >= 128u) {
        if (i >= cap)
            return 0;
        out[i++] = (uint8_t)(v % 128u + 128u);
        v /= 128u;
    }
    if (i >= cap)
        return 0;
    out[i++] = (uint8_t)v;
    return i;
}

int lc_prefix_get(const uint8_t *in, size_t len, size_t *off, unsigned bits, uint64_t *out)
{
    if (*off >= len)
        return -1;
    uint64_t max = ((uint64_t)1 << bits) - 1u;
    uint64_t v = in[*off] & max;
    (*off)++;
    if (v < max) {
        *out = v;
        return 0;
    }

    /* The continuation is bounded, and the bound is the point: a run of bytes with the top bit set
     * is a header block asking this loop to run forever, and it costs one comparison to refuse. */
    unsigned shift = 0;
    for (;;) {
        if (*off >= len || shift > 56u)
            return -1;
        uint8_t  b = in[(*off)++];
        uint64_t add = b & 0x7fu;
        /* The two overflow checks the reference decoder makes, in the same order and for the same
         * reasons: nghttp2's decode_length refuses when the shift would push bits out of the
         * accumulator and again when the addition would wrap it
         * (vendor/nghttp2/lib/nghttp2_hd.c:911-926, "integer overflow on shift" and "integer
         * overflow on addition"). Ours bounded the shift and then added without either check, so a
         * long enough continuation wrapped silently and produced a small, plausible length from a
         * header block that asked for an enormous one — a refusal turned into a wrong answer, which
         * is the worse of the two outcomes for anything that acts on the value afterwards. */
        if ((UINT64_MAX >> shift) < add)
            return -1;
        add <<= shift;
        if (UINT64_MAX - add < v)
            return -1;
        v += add;
        if ((b & 0x80u) == 0)
            break;
        shift += 7u;
    }
    *out = v;
    return 0;
}

static size_t put_string(uint8_t *out, size_t cap, uint8_t pattern, unsigned bits, const char *s,
                         size_t len, int always)
{
    size_t coded = lc_huff_len(s, len);
    int    huffman = always || coded < len;
    size_t body = huffman ? coded : len;

    size_t n = lc_prefix_put(out, cap, (uint8_t)(huffman ? pattern | 1u << bits : pattern), bits,
                             body);
    if (n == 0 || cap - n < body)
        return 0;

    if (huffman) {
        /* Compared against what was declared one line above, not merely checked for failure. The
         * length is already on the wire by then, so a coder that wrote a different number of bytes
         * produces a field line whose length disagrees with its contents — and every field after it
         * in the block is read from the wrong offset. */
        long w = lc_huff_encode(s, len, out + n, cap - n);
        if (w < 0 || (size_t)w != body)
            return 0;
    } else {
        memcpy(out + n, s, len);
    }
    return n + body;
}

size_t lc_prefix_put_string(uint8_t *out, size_t cap, uint8_t pattern, unsigned bits,
                            const char *s, size_t len)
{
    /* Huffman when it is actually shorter, which is Go's HPACK: `if huffmanLength < uint64(len(s))`
     * (appendHpackString, vendor/x-net/http2/hpack/encode.go:217-229). Sending the longer
     * of the two would be legal and would say something about the sender. */
    return put_string(out, cap, pattern, bits, s, len, 0);
}

size_t lc_prefix_put_huffman(uint8_t *out, size_t cap, uint8_t pattern, unsigned bits, const char *s,
                             size_t len)
{
    /* Huffman ALWAYS, which is QPACK as quic-go writes it: qpack v0.6.0 encodes every name and
     * value with `hpack.AppendHuffmanString` and never the raw form, shorter or not
     * (vendor/qpack/encoder.go:66-75, :77-87) — so `hysteria-cc-rx: 0`, one byte either way, goes
     * out as 81 07 and not 01 30. */
    return put_string(out, cap, pattern, bits, s, len, 1);
}
