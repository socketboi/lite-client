/* Our HTTP/2 framing against nghttp2's.
 *
 * The preface and the frame header are the two things every peer reads before it will read anything
 * else, and both are short enough to look obviously right while being wrong in a way that produces
 * silence rather than an error. So neither is typed from the RFC here: the preface is compared to
 * the constant nghttp2 ships, and every header we write is unpacked by nghttp2's own unpacker. */

#include "h2/frame.h"

#include <nghttp2/nghttp2.h>
#include "nghttp2_frame.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

/* Writes a header with our code, reads it back with theirs, and checks the four fields survived. */
static void roundtrip(uint32_t len, uint8_t type, uint8_t flags, uint32_t stream, const char *what)
{
    uint8_t buf[LC_H2_HEADER];
    if (lc_h2_put_header(buf, sizeof buf, len, type, flags, stream) != LC_H2_HEADER) {
        printf("  FAIL  %s did not write\n", what);
        failures++;
        return;
    }

    nghttp2_frame_hd hd;
    nghttp2_frame_unpack_frame_hd(&hd, buf);

    /* nghttp2 holds the stream id signed, as the RFC's thirty-one bits allow it to; ours is
     * unsigned and never has the top bit set, so the comparison is made in one of the two. */
    int good = hd.length == len && hd.type == type && hd.flags == flags &&
               (uint32_t)hd.stream_id == stream;
    if (!good)
        printf("  FAIL  %s came back as len=%zu type=%u flags=%u stream=%d\n", what, hd.length,
               hd.type, hd.flags, hd.stream_id);
    else
        printf("  ok    %s\n", what);
    failures += good ? 0 : 1;
}

int main(void)
{
    printf("\nHTTP/2 framing against nghttp2\n");

    uint8_t buf[256];

    size_t n = lc_h2_preface(buf, sizeof buf);
    ok(n == NGHTTP2_CLIENT_MAGIC_LEN && memcmp(buf, NGHTTP2_CLIENT_MAGIC, n) == 0,
       "the client preface is the one nghttp2 defines, byte for byte");

    roundtrip(0, LC_H2_SETTINGS, LC_H2_ACK, 0, "an empty SETTINGS with ACK");
    roundtrip(18, LC_H2_SETTINGS, 0, 0, "our SETTINGS");
    roundtrip(1, LC_H2_HEADERS, LC_H2_END_HEADERS | LC_H2_END_STREAM, 1, "HEADERS ending a stream");
    roundtrip(LC_H2_MAX_FRAME, LC_H2_DATA, 0, 1, "a full-sized DATA frame");
    /* The largest stream id there is, which is also the one that shows whether the reserved bit was
     * left in the number. */
    roundtrip(4, LC_H2_WINDOW_UPDATE, 0, 0x7fffffffu, "WINDOW_UPDATE on the highest stream id");

    /* And the reserved bit itself: set in what we are given, it must not reach the wire, because a
     * peer reads the remaining thirty-one bits as the stream and would answer a different one. */
    uint8_t r[LC_H2_HEADER];
    lc_h2_put_header(r, sizeof r, 0, LC_H2_DATA, 0, 0x80000001u);
    ok((r[5] & 0x80u) == 0, "the reserved bit never reaches the wire");
    nghttp2_frame_hd rhd;
    nghttp2_frame_unpack_frame_hd(&rhd, r);
    ok(rhd.stream_id == 1, "and the stream is the one that was meant");

    /* Reading: a frame larger than what this client advertised is refused rather than believed.
     * Believing it means waiting for bytes that are not coming, which is a stall with no error. */
    uint8_t big[LC_H2_HEADER] = { 0xff, 0xff, 0xff, LC_H2_DATA, 0, 0, 0, 0, 1 };
    lc_h2_hd out;
    ok(lc_h2_get_header(big, sizeof big, &out) == -1, "an oversize frame is refused");
    ok(lc_h2_get_header(big, LC_H2_HEADER - 1u, &out) == -1, "and so is a header cut short");

    /* Zero credit is a protocol error in HTTP/2, not a harmless no-op. */
    ok(lc_h2_window_update(buf, sizeof buf, 1, 0) == 0, "a WINDOW_UPDATE of nothing is refused");

    /* THE FRAME IS THE FINGERPRINT, so it is checked value by value and in order rather than by
     * length. Go's client writes ENABLE_PUSH, INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE and
     * MAX_HEADER_LIST_SIZE, in that order, and writes HEADER_TABLE_SIZE only to ask for something
     * other than the default (vendor/x-net/http2/transport.go:527-537). This used to open with
     * HEADER_TABLE_SIZE of zero — a value that client never sends — and the check below existed to
     * hold it there. */
    size_t s = lc_h2_settings(buf, sizeof buf, 262144u);
    ok(s == LC_H2_HEADER + 24u, "SETTINGS carries the four the reference carries");

    static const struct {
        uint16_t id;
        uint32_t val;
        const char *what;
    } want[] = {
        { 0x2u, 0u, "ENABLE_PUSH: 0, and first" },
        { 0x4u, 262144u, "INITIAL_WINDOW_SIZE, the caller's" },
        { 0x5u, 1048576u, "MAX_FRAME_SIZE, a megabyte: a Transport's zero becomes the default under Go 1.27" },
        { 0x6u, LC_H2_MAX_HEADER_LIST, "MAX_HEADER_LIST_SIZE, ten megabytes" },
    };
    for (unsigned i = 0; i < 4u; i++) {
        const uint8_t *e = buf + LC_H2_HEADER + i * 6u;
        uint16_t id = (uint16_t)((uint16_t)e[0] << 8 | e[1]);
        uint32_t v = (uint32_t)e[2] << 24 | (uint32_t)e[3] << 16 | (uint32_t)e[4] << 8 | e[5];
        ok(id == want[i].id && v == want[i].val, want[i].what);
    }

    /* Named rather than implied by the count: a fifth setting appended later would keep the four
     * above correct and still change what this client looks like. */
    int has_table_size = 0;
    for (unsigned i = 0; i < 4u; i++)
        if (buf[LC_H2_HEADER + i * 6u] == 0 && buf[LC_H2_HEADER + i * 6u + 1u] == 0x1u)
            has_table_size = 1;
    ok(!has_table_size, "and HEADER_TABLE_SIZE is not among them, as the reference does not send it");

    /* The body of a DATA frame, padding cut off (RFC 9113 section 6.1): the whole payload when not
     * PADDED; after the length byte and short of that many bytes when it is; and nothing at all when
     * the padding would not fit, which x/net treats as a connection error. */
    {
        const uint8_t  plain[5] = { 'a', 'b', 'c', 'd', 'e' };
        const uint8_t  padded[8] = { 3, 'a', 'b', 'c', 'd', 0, 0, 0 };
        const uint8_t  over[4] = { 4, 'a', 0, 0 };
        const uint8_t *body = NULL;
        size_t         len = 0;
        lc_h2_hd       hd = { 5u, LC_H2_DATA, 0, 1 };
        ok(lc_h2_data_body(&hd, plain, &body, &len) == 0 && body == plain && len == 5u,
           "a DATA frame without padding is all body");
        hd = (lc_h2_hd){ 8u, LC_H2_DATA, LC_H2_PADDED, 1 };
        ok(lc_h2_data_body(&hd, padded, &body, &len) == 0 && body == padded + 1 && len == 4u,
           "a PADDED one loses its length byte and its padding");
        hd = (lc_h2_hd){ 4u, LC_H2_DATA, LC_H2_PADDED, 1 };
        ok(lc_h2_data_body(&hd, over, &body, &len) != 0, "and one whose padding does not fit has no body");
    }

    printf("\n%s\n", failures == 0 ? "the framing agrees" : "the framing is WRONG");
    return failures == 0 ? 0 : 1;
}
