/* XTLS Vision's framing, and the one distinction inside it that nothing else checks.
 *
 * "End" and "direct" both stop the padding, and for a long time this code treated them as the same
 * thing. They are not: after "end" the peer's payload still arrives inside the TLS record layer,
 * and after "direct" the socket carries the inner connection's own bytes with no record layer at
 * all. Reading records as payload does not fail — it delivers them, headers and authentication tags
 * and all, as though they were the answer. A download of a known length still finishes and still
 * reports success; only something that checks its own integrity notices, and what that looks like
 * from a chair is a page that does not load and a video that stops.
 *
 * So the assertions here are about which of the two flags each command sets, and about frames that
 * arrive split across reads — because a frame boundary and a record boundary have nothing to do
 * with each other, and treating one read as one frame is the other classic way to get this wrong.
 */

#include "vless/vision.h"

#include "reference_read.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

static const uint8_t uuid[LC_VLESS_UUID] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                             0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00 };

/* Builds one frame as the peer would send it: the UUID once at the very start of the direction,
 * then command, content length, padding length, the content and the padding. */
static size_t frame(uint8_t *out, int with_uuid, uint8_t command,
                    const uint8_t *content, size_t content_len, size_t padding)
{
    size_t i = 0;
    if (with_uuid) {
        memcpy(out, uuid, LC_VLESS_UUID);
        i = LC_VLESS_UUID;
    }
    out[i++] = command;
    out[i++] = (uint8_t)(content_len >> 8);
    out[i++] = (uint8_t)content_len;
    out[i++] = (uint8_t)(padding >> 8);
    out[i++] = (uint8_t)padding;
    memcpy(out + i, content, content_len);
    i += content_len;
    memset(out + i, 0xcc, padding);
    return i + padding;
}

static void test_end_is_not_direct(void)
{
    printf("\nend and direct are different commands\n");

    const uint8_t body[] = "hello";
    uint8_t       in[256];
    uint8_t       out[256];
    size_t        got = 0;
    int           direct = 0;

    lc_vision v;
    lc_vision_init(&v, uuid);
    size_t n = frame(in, 1, LC_VISION_END, body, sizeof body - 1, 7);
    ok(lc_vision_read(&v, in, n, out, sizeof out, &got, &direct) == 0, "end frame parses");
    ok(got == sizeof body - 1 && memcmp(out, body, got) == 0, "its content comes out whole");
    ok(direct == 0, "and it does NOT announce direct copy");

    /* What follows "end" is unframed payload — but it still arrives through the record layer, so
     * it comes through this function, and it must come out unchanged. */
    got = 0;
    const uint8_t more[] = "plain bytes after the end frame";
    ok(lc_vision_read(&v, more, sizeof more - 1, out, sizeof out, &got, &direct) == 0,
       "what follows still goes through the unpadder");
    ok(got == sizeof more - 1 && memcmp(out, more, got) == 0, "and comes out untouched");
    ok(direct == 0, "still not direct");

    lc_vision w;
    lc_vision_init(&w, uuid);
    n = frame(in, 1, LC_VISION_DIRECT, body, sizeof body - 1, 7);
    got = 0;
    direct = 0;
    ok(lc_vision_read(&w, in, n, out, sizeof out, &got, &direct) == 0, "direct frame parses");
    ok(got == sizeof body - 1 && memcmp(out, body, got) == 0, "its content comes out whole");
    ok(direct == 1, "and it DOES announce direct copy");
}

static void test_continue_then_direct(void)
{
    printf("\nseveral frames in one buffer\n");

    const uint8_t a[] = "first", b[] = "second";
    uint8_t       in[256];
    uint8_t       out[256];

    size_t n = frame(in, 1, LC_VISION_CONTINUE, a, sizeof a - 1, 3);
    n += frame(in + n, 0, LC_VISION_DIRECT, b, sizeof b - 1, 5);

    lc_vision v;
    lc_vision_init(&v, uuid);
    size_t got = 0;
    int    direct = 0;
    ok(lc_vision_read(&v, in, n, out, sizeof out, &got, &direct) == 0, "both frames parse");
    ok(got == sizeof a - 1 + sizeof b - 1 && memcmp(out, "firstsecond", got) == 0,
       "and their contents arrive in order with the padding gone");
    ok(direct == 1, "the second one announces direct copy");
}

static void test_trailing_raw_in_the_same_buffer(void)
{
    printf("\nwhat shares the buffer with the last frame\n");

    /* The announcement is the last thing that is framed, not the last thing in the record. Bytes
     * after it in the same buffer are already raw, and dropping them loses exactly the start of
     * the payload — which the inner TLS then reports as a bad record rather than as a gap. */
    const uint8_t body[] = "framed";
    const uint8_t raw[] = "raw tail";
    uint8_t       in[256];
    uint8_t       out[256];

    size_t n = frame(in, 1, LC_VISION_DIRECT, body, sizeof body - 1, 4);
    memcpy(in + n, raw, sizeof raw - 1);
    n += sizeof raw - 1;

    lc_vision v;
    lc_vision_init(&v, uuid);
    size_t got = 0;
    int    direct = 0;
    ok(lc_vision_read(&v, in, n, out, sizeof out, &got, &direct) == 0, "the buffer parses");
    ok(got == sizeof body - 1 + sizeof raw - 1 && memcmp(out, "framedraw tail", got) == 0,
       "the framed content and the raw tail both come out, in order");
    ok(direct == 1, "and direct copy is announced");
}

static void test_frame_split_across_reads(void)
{
    printf("\na frame split across reads\n");

    const uint8_t a[] = "first", body[] = "split across several reads";
    uint8_t       in[256];
    uint8_t       out[256];
    size_t        n = frame(in, 1, LC_VISION_CONTINUE, a, sizeof a - 1, 3);
    size_t        second = n;
    n += frame(in + n, 0, LC_VISION_DIRECT, body, sizeof body - 1, 11);

    /* Cuts the format does not care about: inside the first frame's content, inside the SECOND
     * frame's five-byte header once its content length is in, inside its content. The first read
     * has to hold the UUID and the whole first header — see test_uuid_cut_by_a_record for what
     * happens when it does not — and a cut BEFORE the second header's length is in is its own
     * case, test_direct_concluded_on_its_command, because the reference then decides early. */
    const size_t cuts[] = { LC_VLESS_UUID + 5 + 2, second + 3, second + 5 + 4 };

    lc_vision v;
    lc_vision_init(&v, uuid);
    size_t off = 0, total = 0;
    int    direct = 0, failed = 0;
    for (unsigned i = 0; i <= sizeof cuts / sizeof cuts[0]; i++) {
        size_t end = i < sizeof cuts / sizeof cuts[0] ? cuts[i] : n;
        size_t got = 0;
        if (lc_vision_read(&v, in + off, end - off, out + total, sizeof out - total, &got,
                           &direct) != 0) {
            failed = 1;
            break;
        }
        total += got;
        off = end;
    }
    ok(!failed, "every read is accepted");
    ok(total == sizeof a - 1 + sizeof body - 1 && memcmp(out, "firstsplit across several reads",
                                                         total) == 0,
       "and the content of both frames is whole");
    ok(direct == 1, "with direct copy announced at the end of it");

    /* And the most the format allows once the first header is in: one byte per read — over two
     * "continue" frames, because under "end" or "direct" a one-byte read that stops in a header
     * is exactly the early verdict of test_direct_concluded_on_its_command. */
    in[second] = LC_VISION_CONTINUE;
    lc_vision w;
    lc_vision_init(&w, uuid);
    total = 0;
    direct = 0;
    failed = 0;
    for (size_t i = 0; i < n && !failed;) {
        size_t step = i == 0 ? LC_VLESS_UUID + 5 : 1;
        size_t got = 0;
        if (lc_vision_read(&w, in + i, step, out + total, sizeof out - total, &got, &direct) != 0)
            failed = 1;
        total += got;
        i += step;
    }
    ok(!failed, "one byte per read after the first header, the frames still parse");
    ok(total == sizeof a - 1 + sizeof body - 1 && memcmp(out, "firstsplit across several reads",
                                                         total) == 0,
       "and the content is still whole");
    ok(direct == 0 && w.within_padding == 1, "and the reader is still unpadding");
}

/* ⚠️ A QUIRK OF THE REFERENCE, PINNED BECAUSE IT IS THE REFERENCE. The verdict after a read looks at
 * the content and padding still owed and at the command — not at how much of the header is still
 * to come (vendor/Xray-core/proxy/proxy.go:244-250). A read that stops right after a block's command
 * byte, before its content length, finds "content owed" still at the 0 the previous block left it,
 * and a command of 2 switches to direct copy then and there: the rest of the header, the content
 * and the padding all come out as they stand. It takes a frame split inside its header by a record
 * boundary, which Go's record sizing can do — and the reference would do this. */
static void test_direct_concluded_on_its_command(void)
{
    printf("\na read that stops after a \"direct\" command byte\n");

    const uint8_t a[] = "first", body[] = "short content";
    uint8_t       in[256];
    uint8_t       out[256];
    size_t        n = frame(in, 1, LC_VISION_CONTINUE, a, sizeof a - 1, 3);
    size_t        second = n;
    n += frame(in + n, 0, LC_VISION_DIRECT, body, sizeof body - 1, 4);

    lc_vision v;
    lc_vision_init(&v, uuid);
    size_t got = 0, total = 0;
    int    direct = 0;
    ok(lc_vision_read(&v, in, second + 1, out, sizeof out, &got, &direct) == 0 && direct == 1,
       "direct copy is concluded on the command byte alone");
    total = got;
    ok(lc_vision_read(&v, in + second + 1, n - second - 1, out + total, sizeof out - total, &got,
                      &direct) == 0,
       "the next read is accepted");
    total += got;
    ok(total == sizeof a - 1 + n - second - 1 && memcmp(out, a, sizeof a - 1) == 0 &&
           memcmp(out + sizeof a - 1, in + second + 1, n - second - 1) == 0,
       "and it comes out as it stands, header tail and padding included");
}

/* ⚠️ THE REFERENCE'S ANSWER, NOT THE FORGIVING ONE. XtlsUnpadding looks for the UUID only in a
 * buffer of at least 21 bytes that opens with it (vendor/Xray-core/proxy/proxy.go:556-563), and
 * carries nothing between buffers but its counters and command. A UUID cut by a record boundary is
 * therefore not a UUID: both halves, and everything after, come out as payload. This client held
 * the first half until 2026-09-24 and framed the stream the reference passes through. */
static void test_uuid_cut_by_a_record(void)
{
    printf("\na UUID cut by a record boundary\n");

    const uint8_t body[] = "content that the reference never unframes";
    uint8_t       in[256];
    uint8_t       out[256];
    size_t        n = frame(in, 1, LC_VISION_END, body, sizeof body - 1, 9);
    size_t        total = 0, got = 0;
    int           direct = 0, failed = 0;

    lc_vision v;
    lc_vision_init(&v, uuid);
    if (lc_vision_read(&v, in, 7, out, sizeof out, &got, &direct) != 0)
        failed = 1;
    total += got;
    ok(!failed && got == 7 && memcmp(out, in, 7) == 0, "seven bytes of it pass at once, as payload");
    if (lc_vision_read(&v, in + 7, n - 7, out + total, sizeof out - total, &got, &direct) != 0)
        failed = 1;
    total += got;
    ok(!failed && total == n && memcmp(out, in, n) == 0,
       "and so does the rest: the whole frame, header and padding, is the stream");
    ok(direct == 0, "with nothing announced");

    /* The edge itself: twenty bytes that are the UUID and four header bytes are not enough. */
    lc_vision w;
    lc_vision_init(&w, uuid);
    n = frame(in, 1, LC_VISION_CONTINUE, body, 0, 0);
    ok(n == 21u, "a UUID and an empty frame are 21 bytes");
    ok(lc_vision_read(&w, in, 20, out, sizeof out, &got, &direct) == 0 && got == 20 &&
           memcmp(out, in, 20) == 0,
       "twenty of them pass as payload");
    lc_vision_init(&w, uuid);
    ok(lc_vision_read(&w, in, 21, out, sizeof out, &got, &direct) == 0 && got == 0,
       "all twenty-one are a frame, with nothing in it");
}

/* The same rule from the other side: a buffer that does not open with the UUID leaves the state
 * where it was, so the NEXT buffer is looked at again — for as long as WithinPaddingBuffers holds,
 * which after a miss is for good, since the command is still 0
 * (vendor/Xray-core/proxy/proxy.go:244-245). This client latched "not Vision" after the first miss
 * until 2026-09-24. */
static void test_uuid_looked_for_again(void)
{
    printf("\nthe UUID, looked for in every buffer\n");

    const uint8_t raw[] = "no uuid here, just bytes and more of them to clear the header length";
    const uint8_t body[] = "framed after all";
    uint8_t       in[256];
    uint8_t       out[256];
    size_t        got = 0;
    int           direct = 0;

    lc_vision v;
    lc_vision_init(&v, uuid);
    ok(lc_vision_read(&v, raw, sizeof raw - 1, out, sizeof out, &got, &direct) == 0 &&
           got == sizeof raw - 1 && memcmp(out, raw, got) == 0,
       "a buffer without the UUID passes as it stands");
    for (int i = 0; i < 20; i++)
        (void)lc_vision_read(&v, raw, sizeof raw - 1, out, sizeof out, &got, &direct);
    ok(v.packets_to_filter <= 0, "twenty more of them, and the filter has stopped counting");

    size_t n = frame(in, 1, LC_VISION_END, body, sizeof body - 1, 5);
    ok(lc_vision_read(&v, in, n, out, sizeof out, &got, &direct) == 0 && got == sizeof body - 1 &&
           memcmp(out, body, got) == 0,
       "and a buffer that then opens with it is still unframed");

    /* After "end" the verdict is WithinPaddingBuffers = false, and what keeps the unpadder
     * looking is only the filter's count (vendor/Xray-core/proxy/proxy.go:235, :246-247). */
    lc_vision e;
    lc_vision_init(&e, uuid);
    n = frame(in, 1, LC_VISION_END, body, sizeof body - 1, 5);
    (void)lc_vision_read(&e, in, n, out, sizeof out, &got, &direct);
    ok(e.packets_to_filter > 0 &&
           lc_vision_read(&e, in, n, out, sizeof out, &got, &direct) == 0 &&
           got == sizeof body - 1 && memcmp(out, body, got) == 0,
       "after \"end\", while the filter still counts, a UUID-led buffer is unframed again");
    e.packets_to_filter = 0;
    ok(lc_vision_read(&e, in, n, out, sizeof out, &got, &direct) == 0 && got == n &&
           memcmp(out, in, n) == 0,
       "and once it has stopped, the same buffer passes as it stands");
}

/* A command the format does not define ends its block like "end" — the content comes out, the
 * padding is skipped, the state goes back to the start — and the verdict after the read is left as
 * it was, with only a log line (vendor/Xray-core/proxy/proxy.go:251-253, :604-615). This client
 * ended the connection on it until 2026-09-24. */
static void test_unknown_command(void)
{
    printf("\na command the format does not define\n");

    const uint8_t body[] = "kept";
    const uint8_t tail[] = " and the tail";
    const uint8_t next[] = "the next block";
    uint8_t       in[256];
    uint8_t       out[256];
    size_t        got = 0;
    int           direct = 0;

    size_t n = frame(in, 1, 0x03u, body, sizeof body - 1, 6);
    memcpy(in + n, tail, sizeof tail - 1);
    n += sizeof tail - 1;

    lc_vision v;
    lc_vision_init(&v, uuid);
    ok(lc_vision_read(&v, in, n, out, sizeof out, &got, &direct) == 0,
       "command 3 is accepted, not the end of the connection");
    ok(got == sizeof body - 1 + sizeof tail - 1 && memcmp(out, "kept and the tail", got) == 0,
       "its content comes out, its padding does not, and what follows it passes as it stands");
    ok(direct == 0 && v.within_padding == 1, "nothing is announced, and the reader still unpads");

    n = frame(in, 1, LC_VISION_CONTINUE, next, sizeof next - 1, 2);
    ok(lc_vision_read(&v, in, n, out, sizeof out, &got, &direct) == 0 && got == sizeof next - 1 &&
           memcmp(out, next, got) == 0,
       "so a buffer that then opens with the UUID starts a block again");
}

/* ONE READ IS AT MOST 8192 BYTES, AND THE UNPADDER SEES A BUFFER BEGIN AT EACH. A record carries up
 * to 16384, and the reference's reader takes it in two: a SingleReader's buf.Size buffer
 * (vendor/Xray-core/common/buf/reader.go:28-36, :157-160) filled by one Read, which stops at the
 * record (vendor/utls/u_conn.go:874-885). Everything above that is per buffer — the UUID test, the
 * verdict, the filter's count — happens twice in such a record. */
static void test_reads_cut_at_8192(void)
{
    printf("\na record longer than one read\n");

    static uint8_t in[16384];
    static uint8_t out[16384];
    const uint8_t  body[] = "the second read";
    size_t         got = 0;
    int            direct = 0;

    memset(in, 'r', 8192);
    size_t n = 8192 + frame(in + 8192, 1, LC_VISION_END, body, sizeof body - 1, 40);

    lc_vision v;
    lc_vision_init(&v, uuid);
    ok(lc_vision_read(&v, in, n, out, sizeof out, &got, &direct) == 0, "the record is accepted");
    ok(got == 8192 + sizeof body - 1 && memcmp(out, in, 8192) == 0 &&
           memcmp(out + 8192, body, sizeof body - 1) == 0,
       "the first 8192 pass as they stand, and the UUID at 8192 starts a frame");
    ok(v.packets_to_filter == LC_VISION_FILTER_PACKETS - 2, "the filter counted two reads");

    /* The same bytes one short of the boundary are one buffer's middle, not a buffer's start. */
    lc_vision w;
    lc_vision_init(&w, uuid);
    memset(in, 'r', 8191);
    n = 8191 + frame(in + 8191, 1, LC_VISION_END, body, sizeof body - 1, 40);
    ok(lc_vision_read(&w, in, n, out, sizeof out, &got, &direct) == 0 && got == n &&
           memcmp(out, in, n) == 0,
       "a UUID at 8191 is payload");

    /* "Direct" in the first read: the rest of the record is the connection's `input`, merged as it
     * stands and never shown to the filter (vendor/Xray-core/proxy/proxy.go:259-266). */
    lc_vision d;
    lc_vision_init(&d, uuid);
    n = frame(in, 1, LC_VISION_DIRECT, body, sizeof body - 1, 0);
    memset(in + n, 'z', sizeof in - n);
    ok(lc_vision_read(&d, in, sizeof in, out, sizeof out, &got, &direct) == 0 && direct == 1 &&
           got == sizeof body - 1 + sizeof in - n && memcmp(out + sizeof body - 1, in + n,
                                                            sizeof in - n) == 0,
       "after \"direct\" in the first read, the rest of the record comes out raw");
    ok(d.packets_to_filter == LC_VISION_FILTER_PACKETS - 1, "and the filter counted one read");

    /* A read that was nothing but padding yields nothing, and the reference drops it before the
     * filter counts (vendor/Xray-core/proxy/proxy.go:239-241). */
    lc_vision p;
    lc_vision_init(&p, uuid);
    n = frame(in, 1, LC_VISION_CONTINUE, body, 0, 100);
    ok(lc_vision_read(&p, in, n, out, sizeof out, &got, &direct) == 0 && got == 0 &&
           p.packets_to_filter == LC_VISION_FILTER_PACKETS,
       "a read that was all padding is not counted");
}

static void test_unframed_peer(void)
{
    printf("\na peer that never framed anything\n");

    /* Without the UUID at the front there is no Vision framing to remove, and inventing frame
     * boundaries in a stream that has none is worse than passing it through. */
    const uint8_t raw[] = "no uuid here, just bytes and more of them to clear the header length";
    uint8_t       out[256];
    size_t        got = 0;
    int           direct = 0;

    lc_vision v;
    lc_vision_init(&v, uuid);
    ok(lc_vision_read(&v, raw, sizeof raw - 1, out, sizeof out, &got, &direct) == 0,
       "the buffer is accepted");
    ok(got == sizeof raw - 1 && memcmp(out, raw, got) == 0, "and passes through untouched");
    ok(direct == 0, "with no direct copy announced");
}

static void test_output_bound(void)
{
    printf("\na record larger than the room offered for it\n");

    uint8_t body[600];
    memset(body, 'x', sizeof body);
    uint8_t in[1024];
    uint8_t out[64];
    size_t  n = frame(in, 1, LC_VISION_END, body, sizeof body, 0);

    lc_vision v;
    lc_vision_init(&v, uuid);
    size_t got = 0;
    int    direct = 0;
    ok(lc_vision_read(&v, in, n, out, sizeof out, &got, &direct) != 0,
       "refused rather than written past the end of the buffer");
}

/* A frame a real Xray client actually wrote, run through this client's reader.
 *
 * Everything else in this file builds its own frames with `frame()` and reads them back. That
 * checks the two halves against each other and would keep passing if BOTH were wrong in the same
 * way — which is the failure mode a hand-transcribed format has, and the one that put five extra
 * signature schemes into the other plane's hello on 2026-08-25.
 *
 * HOW IT WAS TAKEN. A TLS server printing the first bytes of the plaintext stream, with Xray built
 * from source pointed at it as a VLESS client with `flow: xtls-rprx-vision`. The capture
 * is the 52-byte VLESS request (pinned in test/vless) followed by exactly this frame. ⚠️ The
 * padding length is DRAWN PER CONNECTION — the first capture came out 134 bytes long and was cut
 * off by a 256-byte read; this one drew 108 and fits in the same 256. A capture that ends mid-frame
 * must be retaken, not completed by hand.
 *
 * The layout matches vendor/Xray-core/proxy/proxy.go:528 exactly — `{command, contentLen>>8,
 * contentLen, paddingLen>>8, paddingLen}` — and the padding is zeroes because XtlsPadding produces
 * it with `newbuffer.Extend(paddingLen)`, which reserves without writing. */
static void test_reference_frame(void)
{
    printf("\na frame captured from a real Xray client\n");

    static const uint8_t ref_uuid[LC_VLESS_UUID] = {
        0x8f, 0x2c, 0x1d, 0x3a, 0x4b, 0x5e, 0x4f, 0x60,
        0x9a, 0x7b, 0x0c, 0x1d, 0x2e, 0x3f, 0x4a, 0x5b,
    };
    static const char content[] =
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: curl/8.14.1\r\n"
        "Accept: */*\r\n"
        "\r\n";
    const size_t content_len = sizeof content - 1u; /* 0x004b */
    const size_t pad_len = 108u;                    /* 0x006c */

    uint8_t in[16u + 5u + 128u + 108u];
    size_t  n = 0;
    memcpy(in, ref_uuid, LC_VLESS_UUID);
    n += LC_VLESS_UUID;
    in[n++] = 0x00u; /* command */
    in[n++] = (uint8_t)(content_len >> 8);
    in[n++] = (uint8_t)content_len;
    in[n++] = (uint8_t)(pad_len >> 8);
    in[n++] = (uint8_t)pad_len;
    memcpy(in + n, content, content_len);
    n += content_len;
    memset(in + n, 0, pad_len);
    n += pad_len;

    ok(content_len == 0x4bu, "the captured content length is the 75 the wire carried");
    ok(n == 256u - 52u, "and the whole frame is the 204 bytes that followed the request");

    uint8_t   out[512];
    size_t    got = 0;
    int       direct = 0;
    lc_vision v;
    lc_vision_init(&v, ref_uuid);
    ok(lc_vision_read(&v, in, n, out, sizeof out, &got, &direct) == 0,
       "this client's reader accepts it");
    ok(got == content_len && memcmp(out, content, content_len) == 0,
       "and hands back exactly what Xray was asked to send");
    ok(direct == 0, "command zero is not a switch to direct copy");
}

/* The padding lengths this client draws, against the two ranges the reference draws from.
 *
 * XtlsPadding (vendor/Xray-core/proxy/proxy.go:500-537) takes four numbers, and the default is
 * `{900, 500, 900, 256}` (:311-313):
 *
 *     if contentLen < 900 && longPadding { paddingLen = rand(500) + 900 - contentLen }
 *     else                               { paddingLen = rand(256) }
 *
 * so a long-padded frame lands its content and padding together somewhere in [900, 1399] however
 * little it carries — that is what hides the VLESS header in the first one — and a short-padded one
 * adds at most 255 bytes.
 *
 * ⚠️ WHY THIS IS A TEST AND NOT A COMMENT. Frame sizes are what an observer sees; a client drawing
 * from a different range is distinguishable without a single byte being decoded. The constants
 * matched the reference by reading, and the SHORT branch had been seen on the wire — but the long
 * one had not, because a trap that only terminates never lets the inner TLS complete and
 * `longPadding := trafficState.IsTLS` never becomes true.
 *
 * It has now: putting the trap BETWEEN a reference client and a reference server (see
 * tools/vendorcap) produced, in one session, a frame with content 80 and padding 921 — 1001 in
 * total, and 921 = 101 + 900 - 80, so the draw was 101 out of 500 — and the switch out of padding
 * as command 2 with content 123 and padding 1159, which is 1282. Both in range, both from the
 * branch this asserts. */
static void test_padding_ranges(void)
{
    printf("\npadding lengths, against the reference's two ranges\n");

    const uint8_t body[64] = { 0 };
    uint8_t       out[LC_VISION_MAX_LONG + 128u];
    int           long_bad = 0, short_bad = 0, failed = 0;

    for (unsigned i = 0; i < 200u && !failed; i++) {
        lc_vision v;
        size_t    n = 0;

        lc_vision_init(&v, uuid);
        if (lc_vision_pad(&v, LC_VISION_CONTINUE, 1, body, sizeof body, out, sizeof out, &n) != 0) {
            failed = 1;
            break;
        }
        /* uuid once, then command, content length, padding length. */
        size_t at = LC_VLESS_UUID;
        size_t content = (size_t)out[at + 1u] << 8 | out[at + 2u];
        size_t padding = (size_t)out[at + 3u] << 8 | out[at + 4u];
        if (content + padding < 900u || content + padding > LC_VISION_MAX_LONG)
            long_bad++;

        lc_vision w;
        lc_vision_init(&w, uuid);
        if (lc_vision_pad(&w, LC_VISION_CONTINUE, 0, body, sizeof body, out, sizeof out, &n) != 0) {
            failed = 1;
            break;
        }
        padding = (size_t)out[at + 3u] << 8 | out[at + 4u];
        if (padding > 255u)
            short_bad++;
    }

    ok(!failed, "two hundred frames of each kind build");
    ok(long_bad == 0, "every long-padded frame lands in [900, 1399], as the reference's does");
    ok(short_bad == 0, "and every short-padded one adds at most 255 bytes");
}

/* THE READER AGAINST THE REFERENCE'S OWN, RUN — not against what reading it suggested.
 *
 * Every case above was worked out from proxy.go by hand, and one of them was worked out wrong the
 * first time (test_direct_concluded_on_its_command: the verdict ignores a half-read header, which
 * the hand model did not). test/vision/reference_read.h holds what vendor/Xray-core's VisionReader,
 * XtlsUnpadding and XtlsFilterTls actually returned for 240 streams cut into records at random —
 * each record in reads of at most 8192 bytes, as its reader takes them — produced by
 * tools/visionread. For every record: what came out, compared by length and FNV-1a, and every
 * field of the state after it, the filter's included. */
static uint64_t fnv1a(const uint8_t *b, size_t n)
{
    uint64_t h = 14695981039346656037ull;
    for (size_t i = 0; i < n; i++) {
        h ^= b[i];
        h *= 1099511628211ull;
    }
    return h;
}

static void test_against_the_reference(void)
{
    printf("\nstreams read by the reference's own VisionReader\n");

    static uint8_t stream[1u << 17];
    static uint8_t out[16384];
    unsigned       records = 0, bad = 0;
    const size_t   n_streams = sizeof vr_streams / sizeof vr_streams[0];

    for (size_t s = 0; s < n_streams; s++) {
        size_t len = 0;
        for (uint32_t p = vr_streams[s].piece; p < vr_streams[s].piece + vr_streams[s].pieces; p++) {
            size_t n = vr_pieces[p].len;
            if (len + n > sizeof stream) {
                printf("  FAIL  stream %u is longer than the buffer it is built in\n", (unsigned)s);
                bad++;
                break;
            }
            if (vr_pieces[p].fill == -1) {
                memcpy(stream + len, vr_pool + vr_pieces[p].off, n);
            } else if (vr_pieces[p].fill == -2) {
                uint32_t x = vr_pieces[p].off; /* the pattern tools/visionread draws */
                for (size_t i = 0; i < n; i++) {
                    x = x * 1103515245u + 12345u;
                    stream[len + i] = (uint8_t)(x >> 24);
                }
            } else {
                memset(stream + len, vr_pieces[p].fill, n);
            }
            len += n;
        }

        lc_vision v;
        lc_vision_init(&v, vr_uuid);
        size_t off = 0;
        for (uint32_t r = vr_streams[s].record; r < vr_streams[s].record + vr_streams[s].records;
             r++) {
            size_t got = 0;
            int    direct = 0;
            int    rc = lc_vision_read(&v, stream + off, vr_records[r].len, out, sizeof out, &got,
                                       &direct);
            off += vr_records[r].len;
            records++;
            if (rc != 0 || got != vr_records[r].out_len || fnv1a(out, got) != vr_records[r].out_fnv ||
                v.packets_to_filter != vr_records[r].filter ||
                v.within_padding != vr_records[r].within || v.direct_in != vr_records[r].direct ||
                direct != vr_records[r].direct || v.remaining_command != vr_records[r].rcommand ||
                v.remaining_content != vr_records[r].rcontent ||
                v.remaining_padding != vr_records[r].rpadding ||
                v.current_command != vr_records[r].command || v.is_tls != vr_records[r].is_tls ||
                v.is_tls12_or_above != vr_records[r].tls12 || v.enable_xtls != vr_records[r].xtls ||
                (int32_t)v.cipher != vr_records[r].cipher ||
                v.remaining_server_hello != vr_records[r].server_hello) {
                if (bad < 5)
                    printf("  FAIL  stream %u, record %u of %u bytes: out %u (want %u), filter %d "
                           "(%d), within %d (%d), direct %d (%d), counters %d/%d/%d (%d/%d/%d), "
                           "command %d (%d)\n",
                           (unsigned)s, (unsigned)(r - vr_streams[s].record),
                           (unsigned)vr_records[r].len, (unsigned)got,
                           (unsigned)vr_records[r].out_len, v.packets_to_filter,
                           vr_records[r].filter, v.within_padding, vr_records[r].within,
                           v.direct_in, vr_records[r].direct, v.remaining_command,
                           v.remaining_content, v.remaining_padding, vr_records[r].rcommand,
                           vr_records[r].rcontent, vr_records[r].rpadding, v.current_command,
                           vr_records[r].command);
                bad++;
                break;
            }
        }
    }

    char what[160];
    snprintf(what, sizeof what,
             "%u streams, %u records: every read's output and every field of the state as the "
             "reference's",
             (unsigned)n_streams, records);
    ok(bad == 0, what);
}

int main(void)
{
    printf("XTLS Vision framing\n");
    test_reference_frame();
    test_padding_ranges();
    test_end_is_not_direct();
    test_continue_then_direct();
    test_trailing_raw_in_the_same_buffer();
    test_frame_split_across_reads();
    test_unframed_peer();
    test_direct_concluded_on_its_command();
    test_uuid_cut_by_a_record();
    test_uuid_looked_for_again();
    test_unknown_command();
    test_reads_cut_at_8192();
    test_against_the_reference();
    test_output_bound();
    printf("\n%s\n", failures == 0 ? "every check passed" : "some checks failed");
    return failures == 0 ? 0 : 1;
}
