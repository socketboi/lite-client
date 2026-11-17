/* Prefixed integers, which HPACK and QPACK both spell the same way — and which the node writes.
 *
 * ⚠️ THE REFUSAL THIS FILE EXISTS FOR IS NAMED IN THE HEADER IT CHECKS: "a continuation that never
 * ends is how a header block asks a decoder to loop forever". That is a denial of service fed
 * entirely by the far end, costing it a handful of bytes, and until 2026-09-02 nothing in this tree
 * asked the decoder what it does with one.
 *
 * The encoder is here too, because the two are only useful against each other: an encoder that
 * writes what its own decoder reads is proof of nothing on its own, so the round trips below are
 * paired with byte-level assertions about what actually goes on the wire.
 *
 * ⚠️ THE THREE GUARDS ARE REDUNDANT, AND SAYING WHICH ONE FIRED IS NOT THIS FILE'S JOB. lc_prefix_get
 * bounds the shift at 56 and then makes the two overflow checks nghttp2's decode_length makes — one
 * for the shift, one for the addition (vendor/nghttp2/lib/nghttp2_hd.c:911-926). Measured by
 * deleting them one at a time: removing the bound leaves the overflow checks refusing the same
 * input, and removing the checks leaves the bound doing it. Only removing all three lets a value
 * past sixty-four bits through.
 *
 * That is belt and braces working as intended, and it is why the assertions below are written about
 * the ANSWER rather than about which line produced it. A test that pinned one guard would go green
 * on a rewrite that kept the property and moved the mechanism, which is the wrong thing to hold. */

#include "quic/prefix.h"

#include <stdio.h>
#include <string.h>

static int fails;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        fails++;
}

static int roundtrip(unsigned bits, uint64_t v)
{
    uint8_t  buf[32];
    uint64_t back = 0;
    size_t   off = 0;
    size_t   n = lc_prefix_put(buf, sizeof buf, 0x00u, bits, v);
    if (n == 0)
        return 0;
    if (lc_prefix_get(buf, n, &off, bits, &back) != 0)
        return 0;
    return back == v && off == n;
}

int main(void)
{
    printf("prefixed integers, as both header compressions spell them\n");

    /* The shape of the encoding, checked as bytes rather than only through the decoder. A value
     * below the prefix maximum is the prefix byte and nothing else; the maximum itself always costs
     * a second byte, because the first is what says "there is more". */
    {
        uint8_t b[8];
        ok(lc_prefix_put(b, sizeof b, 0x20u, 5u, 10u) == 1u && b[0] == 0x2au,
           "a value under the prefix maximum rides in the prefix byte, pattern and all");
        ok(lc_prefix_put(b, sizeof b, 0x20u, 5u, 31u) == 2u && b[0] == 0x3fu && b[1] == 0x00u,
           "the maximum itself costs a second byte holding zero");
        ok(lc_prefix_put(b, sizeof b, 0x00u, 5u, 1337u) == 3u && b[0] == 0x1fu && b[1] == 0x9au &&
               b[2] == 0x0au,
           "and RFC 7541's own example, 1337 in five bits, is 1f 9a 0a");
    }

    /* Round trips across the widths both compressions use and the values where an encoder slips:
     * either side of the prefix maximum, and either side of the seven-bit continuation boundary. */
    {
        static const unsigned widths[] = { 4u, 5u, 6u, 7u, 8u };
        static const uint64_t vals[] = { 0u,   1u,   14u,  15u,  16u,   30u,   31u,
                                         32u,  126u, 127u, 128u, 129u,  254u,  255u,
                                         256u, 1337u, 16383u, 16384u, 1000000u };
        int all = 1;
        for (size_t w = 0; w < sizeof widths / sizeof widths[0]; w++)
            for (size_t i = 0; i < sizeof vals / sizeof vals[0]; i++)
                if (!roundtrip(widths[w], vals[i]))
                    all = 0;
        ok(all, "every value round trips at every prefix width both compressions use");
        ok(roundtrip(7u, 0x800000000000007EULL), "and so does the largest the encoding can carry");
    }

    /* ⚠️ A RUN OF SET TOP BITS, WHICH IS THE WEAK VERSION OF THIS CASE AND IS HERE ANYWAY.
     *
     * It is weak because the loop advances `*off` every time round and stops when the buffer ends,
     * so this is refused even by a decoder with no guards at all — the header's phrase about a block
     * "asking this loop to run forever" describes the danger loosely. There is no forever; there is
     * a wrong answer, and the case below is the one that produces it. Measured: with both the shift
     * bound and the two overflow checks deleted, this assertion still passes. Kept because a
     * decoder that walked past the buffer would fail it, and that is a different fault worth
     * refusing. */
    {
        uint8_t  b[16];
        uint64_t v = 0;
        size_t   off = 0;
        memset(b, 0xff, sizeof b);
        ok(lc_prefix_get(b, sizeof b, &off, 7u, &v) != 0,
           "a run of continuation bytes that outlasts the buffer is refused");
    }

    /* ⚠️ AND THE ONE THAT ACTUALLY TESTS THE GUARDS: a continuation that ENDS properly, and whose
     * value does not fit.
     *
     * Twelve continuation bytes, the last of them closing the run, so nothing here is malformed in
     * any way a length check would notice. What it asks for is a number past sixty-four bits. A
     * decoder that shifts and adds without looking wraps it silently and returns something small and
     * plausible — and whatever acts on that number next, a header length or a field count, acts on a
     * value the sender never sent. That is the failure the guards exist for: not a hang, a lie.
     *
     * This is the assertion that goes red when the shift bound is removed, and red again when the
     * overflow checks are removed instead. Either alone refuses it; both gone and it is accepted. */
    {
        uint8_t  b[16];
        uint64_t v = 0;
        size_t   off = 0;
        b[0] = 0x7fu;
        memset(b + 1, 0xffu, 11); /* eleven that continue */
        b[12] = 0x01u;            /* and one that ends the run */
        ok(lc_prefix_get(b, 13u, &off, 7u, &v) != 0,
           "a well-formed continuation asking for more than sixty-four bits is refused, not wrapped");
    }

    /* And the longest one that is legal, which is what makes the refusal above a BOUND rather than
     * a blanket "long is bad": nine continuation bytes, the last of them ending the run. */
    {
        uint8_t  b[11];
        uint64_t v = 0;
        size_t   off = 0;
        b[0] = 0x7fu; /* seven bits, all ones: the prefix says there is more */
        memset(b + 1, 0xffu, 8);
        b[9] = 0x7fu; /* top bit clear: the run ends here */
        ok(lc_prefix_get(b, 10u, &off, 7u, &v) == 0 && v == 0x800000000000007EULL && off == 10u,
           "nine continuation bytes are accepted, and one more than that is what gets refused");
    }

    /* Truncation. A run that ends because the buffer did is not a value, and reading it as one
     * would hand the caller a length short by however much never arrived. */
    {
        uint8_t  b[4] = { 0x7fu, 0xffu, 0xffu, 0xffu };
        uint64_t v = 0;
        size_t   off = 0;
        ok(lc_prefix_get(b, sizeof b, &off, 7u, &v) != 0,
           "a continuation cut off by the end of the buffer is refused");
        off = 0;
        ok(lc_prefix_get(b, 0u, &off, 7u, &v) != 0, "and so is an empty buffer");
        off = 4u;
        ok(lc_prefix_get(b, 4u, &off, 7u, &v) != 0, "and an offset already at the end");
    }

    /* The encoder asks about room at every step rather than only at the start: the continuation's
     * length depends on the value, and a buffer that held the first byte need not hold the rest. */
    {
        uint8_t b[8];
        ok(lc_prefix_put(b, 0u, 0x00u, 5u, 1u) == 0u, "no room at all is refused");
        ok(lc_prefix_put(b, 1u, 0x00u, 5u, 1u) == 1u, "one byte is enough for a small value");
        ok(lc_prefix_put(b, 1u, 0x00u, 5u, 1337u) == 0u,
           "and not enough for one that needs a continuation");
        ok(lc_prefix_put(b, 2u, 0x00u, 5u, 1337u) == 0u, "nor is two, when three are needed");
    }

    /* Strings: the length carries a Huffman bit immediately above the prefix, and the coding is used
     * only when it is actually shorter. Sending the longer of the two would be legal and would say
     * something about the sender. */
    {
        uint8_t b[64];
        /* Lowercase ASCII codes well below eight bits a character. */
        size_t n = lc_prefix_put_string(b, sizeof b, 0x00u, 7u, "accept-encoding", 15u);
        ok(n > 0 && (b[0] & 0x80u) != 0u, "a string that codes shorter is sent Huffman-coded");
        ok(n > 0 && n < 1u + 15u, "and is shorter on the wire than the octets would have been");

        /* Bytes with no short code: coding them is longer than leaving them alone. */
        char raw[8];
        memset(raw, (char)0xff, sizeof raw);
        n = lc_prefix_put_string(b, sizeof b, 0x00u, 7u, raw, sizeof raw);
        ok(n == 1u + sizeof raw && (b[0] & 0x80u) == 0u,
           "one that does not is sent as it is, with the Huffman bit clear");

        ok(lc_prefix_put_string(b, 4u, 0x00u, 7u, "accept-encoding", 15u) == 0u,
           "and a buffer too small for the body is refused, not half filled");
    }

    printf("\n%s\n", fails == 0 ? "prefixed integers are read and written as both RFCs say"
                                : "the prefix coding has CHANGED");
    return fails == 0 ? 0 : 1;
}
