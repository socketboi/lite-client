/* Gecko, checked against the frame the reference builds and the frames it refuses.
 *
 * There is no vendored parser to run beside ours — upstream's is Go in a module this cannot link —
 * so the reference here is gecko_frame.go read field by field, quoted in the assertions. What that
 * makes worth testing is not "a packet survives a round trip", which any self-consistent pair of
 * functions passes, but the two halves that talk to somebody else: the bytes we put on the wire,
 * checked against the layout rather than against our own reader, and the frames we accept, checked
 * against the ones the reference drops. A receiver that is more forgiving than the reference is a
 * client that behaves differently under exactly the conditions a prober creates.
 *
 * The split is random by design, so the assertions are about what must hold for every draw — piece
 * count in range, indices complete, the reassembly being the original — rather than about a
 * particular one. Repeated enough times that a rule broken on one draw in eight shows up. */

#include "quic/gecko.c"

#include <stdio.h>
#include <string.h>

static int failures;

static void expect(int cond, const char *what)
{
    if (cond) {
        printf("  ok    %s\n", what);
        return;
    }
    printf("  FAIL  %s\n", what);
    failures++;
}

/* Said once however many times the loop below finds it true. */
static void expect_once(int cond, int *said, const char *what)
{
    if (cond || *said)
        return;
    *said = 1;
    expect(0, what);
}

static uint8_t packet[1200];

static void fill_packet(size_t len)
{
    for (size_t i = 0; i < len; i++)
        packet[i] = (uint8_t)(i * 13u + 5u);
}

int main(void)
{
    printf("gecko: what goes on the wire\n");

    lc_gecko g;
    expect(lc_gecko_init(&g, 1, 0, 0) == 0, "defaults are the reference's 512 and 1200");
    expect(g.min_packet == LC_GECKO_MIN_PACKET && g.max_packet == LC_GECKO_MAX_PACKET,
           "and are taken when the caller says zero");

    lc_gecko bad;
    expect(lc_gecko_init(&bad, 1, 1300, 1200) != 0, "a minimum above the maximum is refused");
    expect(lc_gecko_init(&bad, 1, 512, 4096) != 0, "and a maximum past what a frame holds");

    /* Only the handshake. A short header is data, and cutting it up would cost throughput for a
     * shape that is traffic anyway. */
    uint8_t long_hdr = 0xc0, short_hdr = 0x40;
    expect(lc_gecko_applies(&g, &long_hdr, 1), "a long header is fragmented");
    expect(!lc_gecko_applies(&g, &short_hdr, 1), "a short header is not");
    lc_gecko off;
    lc_gecko_init(&off, 0, 0, 0);
    expect(!lc_gecko_applies(&off, &long_hdr, 1), "and nothing is, with gecko off");

    fill_packet(sizeof packet);

    lc_gecko_out out;
    expect(lc_gecko_split(&g, packet, sizeof packet, &out) == 0, "a packet splits");
    expect(out.count >= LC_GECKO_MIN_CHUNKS && out.count <= LC_GECKO_MAX_CHUNKS,
           "into between two and eight pieces");

    /* The header, byte by byte, against the layout in gecko_frame.go:22-28. */
    const uint8_t *f = out.frame[0];
    expect(f[0] == 0x80u, "byte 0 is the fragment marker 0x80");
    expect((f[2] & 0x0fu) == out.count, "the low nibble of byte 2 is the piece count");
    expect((f[2] >> 4) == 0u, "and the high nibble is this piece's index");
    uint16_t pad0 = (uint16_t)((uint16_t)f[3] << 8 | f[4]);
    expect(LC_GECKO_HEADER + pad0 <= out.len[0], "padLen is big-endian and inside the frame");

    /* Every piece carries the same msgID and its own index, and the whole datagram — salt included —
     * lands in the size band. That band is the entire purpose of the layer. */
    int said_id = 0, said_idx = 0, said_band = 0, said_count = 0;
    for (unsigned round = 0; round < 64u; round++) {
        size_t len = 64u + round * 17u;
        if (len > sizeof packet)
            len = sizeof packet;
        if (lc_gecko_split(&g, packet, len, &out) != 0) {
            expect(0, "a packet splits");
            break;
        }
        expect_once(out.count >= LC_GECKO_MIN_CHUNKS && out.count <= LC_GECKO_MAX_CHUNKS,
                    &said_count, "every draw is between two and eight pieces");
        uint8_t id = out.frame[0][1];
        for (unsigned i = 0; i < out.count; i++) {
            const uint8_t *fr = out.frame[i];
            expect_once(fr[1] == id, &said_id, "every piece of one packet carries the same msgID");
            expect_once((fr[2] >> 4) == i, &said_idx, "and its own index, in order");
            size_t   on_wire = LC_OBFS_SALT + out.len[i];
            uint16_t pad = (uint16_t)((uint16_t)fr[3] << 8 | fr[4]);
            size_t   bare = LC_OBFS_SALT + LC_GECKO_HEADER + (out.len[i] - LC_GECKO_HEADER - pad);
            expect_once(on_wire <= g.max_packet || bare > g.max_packet, &said_band,
                        "and a datagram inside the size band, unless the piece alone is past it");
        }
    }
    expect(!said_id && !said_idx && !said_band && !said_count,
           "sixty-four draws, and all of that held for every one of them");

    printf("\ngecko: putting it back together\n");

    lc_gecko r;
    lc_gecko_init(&r, 1, 0, 0);
    uint8_t whole[2048];

    fill_packet(900);
    expect(lc_gecko_split(&g, packet, 900, &out) == 0, "a nine-hundred-byte packet splits");

    long done = 0;
    for (unsigned i = 0; i < out.count; i++)
        done = lc_gecko_take(&r, out.frame[i], out.len[i], 1000, whole, sizeof whole);
    expect(done == 900, "and the last piece completes it, at its original length");
    expect(memcmp(whole, packet, 900) == 0, "byte for byte what went in");

    /* Order is not something the sender promises: these are separate datagrams. */
    lc_gecko_init(&r, 1, 0, 0);
    lc_gecko_split(&g, packet, 900, &out);
    done = 0;
    for (unsigned i = out.count; i > 0; i--)
        done = lc_gecko_take(&r, out.frame[i - 1], out.len[i - 1], 1000, whole, sizeof whole);
    expect(done == 900 && memcmp(whole, packet, 900) == 0, "arriving backwards changes nothing");

    /* Two packets at once, interleaved, which is what a handshake actually looks like. */
    lc_gecko_out first, second;
    lc_gecko_init(&r, 1, 0, 0);
    fill_packet(600);
    lc_gecko_split(&g, packet, 600, &first);
    lc_gecko_split(&g, packet, 300, &second);
    int first_done = 0, second_done = 0;
    for (unsigned i = 0; i < LC_GECKO_MAX_CHUNKS; i++) {
        if (i < first.count) {
            long rv = lc_gecko_take(&r, first.frame[i], first.len[i], 1000, whole, sizeof whole);
            if (rv == 600)
                first_done = 1;
        }
        if (i < second.count) {
            long rv = lc_gecko_take(&r, second.frame[i], second.len[i], 1000, whole, sizeof whole);
            if (rv == 300)
                second_done = 1;
        }
    }
    expect(first_done && second_done, "two packets in flight at once are told apart by msgID");

    printf("\ngecko: what is refused\n");

    lc_gecko_init(&r, 1, 0, 0);
    lc_gecko_split(&g, packet, 600, &out);

    uint8_t frame[1400];
    memcpy(frame, out.frame[0], out.len[0]);
    size_t flen = out.len[0];

    frame[0] &= 0x7fu;
    expect(lc_gecko_take(&r, frame, flen, 1000, whole, sizeof whole) < 0,
           "a frame without the 0x80 marker is not a frame");
    frame[0] |= 0x80u;

    uint8_t saved = frame[2];
    frame[2] = (uint8_t)(frame[2] & 0xf0u); /* totalChunks = 0 */
    expect(lc_gecko_take(&r, frame, flen, 1000, whole, sizeof whole) < 0,
           "zero pieces is refused — which is what our own QUIC Initial decodes to");
    frame[2] = 0x01u; /* totalChunks = 1, below the minimum of two */
    expect(lc_gecko_take(&r, frame, flen, 1000, whole, sizeof whole) < 0,
           "and one piece, because the reference's range starts at two");
    frame[2] = 0x52u; /* index 5 of 2 */
    expect(lc_gecko_take(&r, frame, flen, 1000, whole, sizeof whole) < 0,
           "an index past the count is refused");
    frame[2] = saved;

    frame[3] = 0xff;
    frame[4] = 0xff;
    expect(lc_gecko_take(&r, frame, flen, 1000, whole, sizeof whole) < 0,
           "padding longer than the frame is refused rather than read past");
    frame[3] = out.frame[0][3];
    frame[4] = out.frame[0][4];

    expect(lc_gecko_take(&r, frame, LC_GECKO_HEADER - 1u, 1000, whole, sizeof whole) < 0,
           "and a frame too short to hold a header");

    /* A duplicate, and a disagreement about the count. Both are the reference's drops. */
    lc_gecko_init(&r, 1, 0, 0);
    expect(lc_gecko_take(&r, out.frame[0], out.len[0], 1000, whole, sizeof whole) == 0,
           "the first piece of several completes nothing, and is not an error");
    expect(lc_gecko_take(&r, out.frame[0], out.len[0], 1000, whole, sizeof whole) < 0,
           "the same piece twice is refused");

    /* A DISAGREEMENT ABOUT THE COUNT COSTS THAT FRAME AND NOTHING ELSE.
     *
     * Which is what the reference does — acceptChunk answers it with `return nil, false` and leaves
     * the entry alone (vendor/hysteria/extras/obfs/gecko.go:222-225) — and is not what this code did
     * until it was asked the second half of the question. The first half, that the frame is refused,
     * was all this asserted, and it is true of both behaviours: the version that dropped the whole
     * half-built packet passed this line every time.
     *
     * The count is chosen rather than computed. It was `(out.count % LC_GECKO_MAX_CHUNKS) + 1`,
     * which for a packet that happened to split into eight gives one — below the minimum of two, so
     * the frame was then refused by the range check and never reached the branch under test at all.
     * A test whose subject depends on a random draw is a test that covers it most of the time. */
    unsigned wrong_count = out.count == 2u ? 3u : 2u;
    memcpy(frame, out.frame[1], out.len[1]);
    frame[2] = (uint8_t)((frame[2] & 0xf0u) | wrong_count);
    expect(lc_gecko_take(&r, frame, out.len[1], 1000, whole, sizeof whole) < 0,
           "a piece disagreeing about how many there are is refused");

    done = 0;
    for (unsigned i = 1; i < out.count; i++)
        done = lc_gecko_take(&r, out.frame[i], out.len[i], 1000, whole, sizeof whole);
    expect(done == 600, "and the packet it disagreed with still completes");
    expect(memcmp(whole, packet, 600) == 0, "byte for byte, so nothing of it was discarded");

    /* And time. A packet whose pieces stopped coming does not hold its slot for ever, or eight lost
     * fragments would be the whole table.
     *
     * Asked of the OUTCOME rather than of the slot: a two-piece packet whose second piece arrives
     * within the deadline completes, and the identical exchange with the deadline passed does not,
     * because by then the first piece is gone. Reading `used` instead would pass on an
     * implementation that expired the slot and then quietly rebuilt it. */
    do {
        lc_gecko_out two;
        unsigned     tries = 0;
        do {
            lc_gecko_split(&g, packet, 600, &two);
        } while (two.count != 2u && ++tries < 200u);
        if (two.count != 2u) {
            expect(0, "sixty tries and never a two-piece draw, which cannot happen");
            break;
        }

        lc_gecko_init(&r, 1, 0, 0);
        expect(lc_gecko_take(&r, two.frame[0], two.len[0], 1000, whole, sizeof whole) == 0,
               "the first of two pieces waits");
        expect(lc_gecko_take(&r, two.frame[1], two.len[1], 1000 + LC_GECKO_TTL_MS - 1u, whole,
                             sizeof whole) == 600,
               "and the second, arriving just inside the deadline, completes it");

        lc_gecko_init(&r, 1, 0, 0);
        (void)lc_gecko_take(&r, two.frame[0], two.len[0], 1000, whole, sizeof whole);
        expect(lc_gecko_take(&r, two.frame[1], two.len[1], 1000 + LC_GECKO_TTL_MS, whole,
                             sizeof whole) == 0,
               "one millisecond later the first piece has been retired, and nothing completes");
    } while (0);

    printf("\n%s\n", failures == 0 ? "all good" : "SOMETHING IS WRONG");
    return failures == 0 ? 0 : 1;
}
