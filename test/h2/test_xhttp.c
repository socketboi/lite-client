/* The stream-one request, checked against what the reference actually sends.
 *
 * The shape here is not from the RFC or from Xray's source: it is what Xray's own client put on the
 * wire against the stand in build/xhttp, read out of GODEBUG=http2debug=2. Each assertion below is
 * a line from that log. */

#include "h2/frame.h"
#include "h2/hpack.h"
#include "h2/xhttp.h"

#include <nghttp2/nghttp2.h>

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

int main(void)
{
    printf("\nXHTTP stream-one against what the reference sends\n");

    lc_xhttp x;
    uint8_t  out[LC_XHTTP_OPEN_MAX];
    long     n = lc_xhttp_open(&x, "www.avito.ru", "/x", out, sizeof out);
    ok(n > 0, "the opening burst builds");
    if (n <= 0)
        return 1;

    size_t off = 0;
    ok(memcmp(out, NGHTTP2_CLIENT_MAGIC, NGHTTP2_CLIENT_MAGIC_LEN) == 0, "it opens with the preface");
    off += NGHTTP2_CLIENT_MAGIC_LEN;

    lc_h2_hd hd;
    ok(lc_h2_get_header(out + off, (size_t)n - off, &hd) == 0 && hd.type == LC_H2_SETTINGS,
       "then SETTINGS");

    /* ⚠️ THE NUMBERS, NOT ONLY THE FRAME TYPES — not pedantry, but a hole that was open.
     *
     * On 2026-08-19 the connection credit moved from a gigabyte to a megabyte and EVERY check
     * stayed green: what was compared here was the frame type and the stream number, and never the
     * value. The value is the whole reason these two frames are imitated at all — a client is
     * identified by them in the first three frames of a connection. A test that does not read them
     * guards nothing.
     *
     * Literals rather than `LC_XHTTP_*`: a comparison against the constant would have moved WITH
     * the constant and stayed silent in exactly the case it is written for. The numbers are the
     * reference's — `transportDefaultStreamFlow` (4 << 20) and `transportDefaultConnFlow`
     * (1 << 30), both from the client branch of `setConfigDefaults`. */
    uint32_t stream_window = 0;
    for (size_t p = 0; p + 6u <= hd.len; p += 6u) {
        const uint8_t *e = out + off + LC_H2_HEADER + p;
        if ((((uint32_t)e[0] << 8) | (uint32_t)e[1]) == 0x4u)
            stream_window = ((uint32_t)e[2] << 24) | ((uint32_t)e[3] << 16) |
                            ((uint32_t)e[4] << 8) | (uint32_t)e[5];
    }
    ok(stream_window == 4194304u, "SETTINGS carries the reference stream window, four mebibytes");
    off += LC_H2_HEADER + hd.len;

    ok(lc_h2_get_header(out + off, (size_t)n - off, &hd) == 0 && hd.type == LC_H2_WINDOW_UPDATE &&
           hd.stream == 0,
       "then the connection credit");

    /* The top bit is reserved and cleared by the sender (frame.c:148), so seven bits are read. */
    uint32_t credit = ((uint32_t)(out[off + LC_H2_HEADER] & 0x7fu) << 24) |
                      ((uint32_t)out[off + LC_H2_HEADER + 1] << 16) |
                      ((uint32_t)out[off + LC_H2_HEADER + 2] << 8) |
                      (uint32_t)out[off + LC_H2_HEADER + 3];
    ok(credit == 1073741824u,
       "and it is the reference CLIENT's gigabyte, not the server branch's megabyte");
    off += LC_H2_HEADER + hd.len;

    ok(lc_h2_get_header(out + off, (size_t)n - off, &hd) == 0 && hd.type == LC_H2_HEADERS,
       "then the request");
    ok(hd.stream == 1u, "on stream 1");
    ok((hd.flags & LC_H2_END_HEADERS) != 0, "with END_HEADERS");
    /* The detail that would have been wrong: the request body is the upload channel, so the stream
     * must NOT be ended by its own headers. */
    ok((hd.flags & LC_H2_END_STREAM) == 0, "and WITHOUT END_STREAM — the body is the tunnel");

    /* And the fields, read back with our own decoder. */
    lc_hpack_dec d;
    memset(&d, 0, sizeof d);
    d.in = out + off + LC_H2_HEADER;
    d.len = hd.len;

    int  seen_authority = 0, seen_method = 0, seen_path = 0, seen_referer = 0, pad_len = 0;
    /* The whole referer, however long xhttp.c made it: 1034 bytes at most today, the decoder hands
     * back any length, and a copy cut short here would test the copy. */
    char referer[8192] = { 0 };
    for (;;) {
        int r = lc_hpack_next(&d);
        if (r <= 0) {
            if (r < 0) {
                printf("  FAIL  the request does not decode at byte %zu\n", d.off);
                failures++;
            }
            break;
        }
        if (strcmp(d.name, ":authority") == 0)
            seen_authority = strcmp(d.value, "www.avito.ru") == 0;
        else if (strcmp(d.name, ":method") == 0)
            seen_method = strcmp(d.value, "POST") == 0;
        else if (strcmp(d.name, ":path") == 0)
            seen_path = strcmp(d.value, "/x/") == 0;
        else if (strcmp(d.name, "referer") == 0) {
            seen_referer = 1;
            snprintf(referer, sizeof referer, "%s", d.value);
        }
    }

    ok(seen_authority, ":authority is the REALITY server name");
    ok(seen_method, ":method is POST");
    ok(seen_path, ":path gained the trailing slash the configuration does not mention");
    ok(seen_referer, "the padding travels as a referer, not as a header of its own");

    const char *q = strstr(referer, "?x_padding=");
    ok(q != NULL && strncmp(referer, "https://www.avito.ru/x/", 23) == 0,
       "and that referer is a whole URL for the path being asked for");
    if (q != NULL) {
        pad_len = (int)strlen(q + 11);
        int all_x = 1;
        for (const char *p = q + 11; *p != '\0'; p++)
            if (*p != 'X')
                all_x = 0;
        ok(all_x, "whose query is a run of one letter");
        ok(pad_len >= (int)LC_XHTTP_PAD_MIN && pad_len < (int)LC_XHTTP_PAD_MAX,
           "of a length drawn from the range Xray uses when none is configured");
    }

    /* Flow control: nothing may be sent beyond what the peer has granted, and the default before
     * any SETTINGS arrives is 65 535 — not the four megabytes this client announces for itself. */
    lc_xhttp y;
    lc_xhttp_open(&y, "h", "/p", out, sizeof out);
    size_t  carried = 0;
    uint8_t dh[LC_H2_HEADER];
    size_t  w = lc_xhttp_data(&y, 100000u, dh, sizeof dh, &carried);
    ok(w == LC_H2_HEADER && carried == LC_H2_MAX_FRAME, "one frame at a time, never more");

    /* Spend the rest of the default window, then check it stops rather than overruns. */
    size_t spent = carried;
    while (spent < 65535u) {
        w = lc_xhttp_data(&y, 65535u - spent, dh, sizeof dh, &carried);
        if (w == 0 || carried == 0)
            break;
        spent += carried;
    }
    ok(spent == 65535u, "the default window is spent exactly");
    w = lc_xhttp_data(&y, 1u, dh, sizeof dh, &carried);
    ok(w == 0 && carried == 0, "and nothing goes out past it");

    /* A peer raising the window moves it by the difference from the default, not to the value. */
    uint8_t settings[LC_H2_HEADER + 6u];
    lc_h2_put_header(settings, sizeof settings, 6u, LC_H2_SETTINGS, 0, 0);
    settings[LC_H2_HEADER + 0] = 0;
    settings[LC_H2_HEADER + 1] = 0x4u;
    settings[LC_H2_HEADER + 2] = 0;
    settings[LC_H2_HEADER + 3] = 0x01u; /* 65536 + 65535 = 131071 */
    settings[LC_H2_HEADER + 4] = 0xffu;
    settings[LC_H2_HEADER + 5] = 0xffu;

    lc_xhttp_event ev;
    ok(lc_xhttp_read(&y, settings, sizeof settings, &ev) == 1, "a SETTINGS from the peer is read");
    ok(ev.reply_len == LC_H2_HEADER, "and answered with an ACK");

    /* Still nothing goes out, and that is right: SETTINGS moves the STREAM window, and the
     * connection's was spent by the same bytes. Two counters, and running out of either one stops
     * everything — which is the whole reason both are kept. */
    w = lc_xhttp_data(&y, 1u, dh, sizeof dh, &carried);
    ok(w == 0 && carried == 0, "but the connection window is still empty, so still nothing goes");

    uint8_t wu[LC_H2_HEADER + 4u];
    lc_h2_put_header(wu, sizeof wu, 4u, LC_H2_WINDOW_UPDATE, 0, 0);
    wu[LC_H2_HEADER + 0] = 0;
    wu[LC_H2_HEADER + 1] = 0;
    wu[LC_H2_HEADER + 2] = 0;
    wu[LC_H2_HEADER + 3] = 16u;
    ok(lc_xhttp_read(&y, wu, sizeof wu, &ev) == 1, "the peer grants connection credit");
    w = lc_xhttp_data(&y, 1u, dh, sizeof dh, &carried);
    ok(carried == 1u, "and only then does sending resume");

    /* ---- a peer that stops mid-message -------------------------------------
     *
     * The same principle as the prefix sweep over a header block, one layer down: build what a
     * server actually sends back, then hand the reader every prefix of it — a peer closing after
     * byte 0, after byte 1, and so on to the end.
     *
     * Two things must hold for every one of them. The reader may never consume more than it was
     * given, and it may never hand over the body of a frame whose bytes have not all arrived —
     * accepting a truncated message as a whole one is the failure that looks like success. */
    uint8_t stream[512];
    size_t  sn = 0;

    sn += lc_h2_put_header(stream + sn, sizeof stream - sn, 6u, LC_H2_SETTINGS, 0, 0);
    memset(stream + sn, 0, 6u);
    stream[sn + 1] = 0x4u;
    stream[sn + 4] = 0x80u; /* INITIAL_WINDOW_SIZE = 32768 */
    sn += 6u;

    sn += lc_h2_put_header(stream + sn, sizeof stream - sn, 4u, LC_H2_HEADERS,
                           LC_H2_END_HEADERS, 1u);
    memset(stream + sn, 0, 4u);
    sn += 4u;

    const char *payload = "the inner connection's own bytes";
    size_t      plen = strlen(payload);
    sn += lc_h2_put_header(stream + sn, sizeof stream - sn, (uint32_t)plen, LC_H2_DATA, 0, 1u);
    memcpy(stream + sn, payload, plen);
    sn += plen;

    sn += lc_h2_put_header(stream + sn, sizeof stream - sn, 4u, LC_H2_WINDOW_UPDATE, 0, 1u);
    stream[sn] = 0; stream[sn + 1] = 0; stream[sn + 2] = 0x10u; stream[sn + 3] = 0;
    sn += 4u;

    int overrun = 0, truncated_body = 0, cuts = 0;
    for (size_t cut = 0; cut <= sn; cut++) {
        lc_xhttp z;
        lc_xhttp_open(&z, "h", "/p", out, sizeof out);

        size_t pos = 0;
        for (;;) {
            lc_xhttp_event e;
            int            r = lc_xhttp_read(&z, stream + pos, cut - pos, &e);
            if (r <= 0)
                break;
            if (e.consumed > cut - pos) {
                overrun = 1;
                break;
            }
            /* Whatever body it hands over must lie inside the bytes that arrived. */
            if (e.body_len > 0 &&
                (e.body < stream + pos || e.body + e.body_len > stream + cut))
                truncated_body = 1;
            pos += e.consumed;
        }
        cuts++;
    }

    ok(cuts == (int)sn + 1, "every prefix of a server's answer is fed to the reader");
    ok(!overrun, "and none of them is read past the bytes that arrived");
    ok(!truncated_body, "nor is a half-arrived frame handed over as a whole one");

    printf("\nthe order of the ordinary headers\n");

    /* THE FOUR FIRST, AND THE REST IN NO FIXED ORDER — which is two claims, and the second is the
     * one that needs many draws. Go writes the pseudo-headers by name and then walks a map
     * (vendor/x-net/internal/httpcommon/request.go:138-156), so a client whose ordinary headers come
     * out the same way twice is telling anybody with two of its requests that it is not that client.
     *
     * Sixteen builds. Every one of them must put the four pseudo-headers first — that is HTTP/2's
     * rule and not a preference — and at least two of them must differ in the rest. With eight
     * ordinary fields a fixed order would fail this at once; a shuffle fails it with probability
     * around one in 8!^15, which is not a number anyone will meet. */
    char        first_seq[512] = { 0 };
    int         pseudo_first_always = 1, order_varies = 0;
    for (unsigned round = 0; round < 16u; round++) {
        uint8_t  o[LC_XHTTP_OPEN_MAX];
        lc_xhttp xx;
        long     on = lc_xhttp_open(&xx, "www.avito.ru", "/x", o, sizeof o);
        if (on <= 0) {
            ok(0, "the request builds on every round");
            break;
        }

        /* Walk to the HEADERS frame the way the checks above did. */
        size_t   p = NGHTTP2_CLIENT_MAGIC_LEN;
        lc_h2_hd h;
        for (unsigned k = 0; k < 2u; k++) {
            if (lc_h2_get_header(o + p, (size_t)on - p, &h) != 0)
                break;
            p += LC_H2_HEADER + h.len;
        }
        if (lc_h2_get_header(o + p, (size_t)on - p, &h) != 0 || h.type != LC_H2_HEADERS)
            continue;

        lc_hpack_dec dd;
        memset(&dd, 0, sizeof dd);
        dd.in = o + p + LC_H2_HEADER;
        dd.len = h.len;

        char seq[512] = { 0 };
        int  seen_ordinary = 0, n_pseudo = 0;
        for (;;) {
            int r = lc_hpack_next(&dd);
            if (r <= 0)
                break;
            if (dd.name[0] == ':') {
                n_pseudo++;
                /* A pseudo-header after an ordinary one is malformed by RFC 9113 section 8.3, and
                 * a Go server closes the stream for it. */
                if (seen_ordinary)
                    pseudo_first_always = 0;
            } else {
                seen_ordinary = 1;
                size_t have = strlen(seq);
                snprintf(seq + have, sizeof seq - have, "%.120s,", dd.name);
            }
        }
        if (n_pseudo != 4)
            pseudo_first_always = 0;

        if (round == 0)
            snprintf(first_seq, sizeof first_seq, "%s", seq);
        else if (strcmp(first_seq, seq) != 0)
            order_varies = 1;
    }
    ok(pseudo_first_always, "the four pseudo-headers lead every request, as HTTP/2 requires");
    ok(order_varies, "and the ordinary ones do not come out in the same order twice");

    printf("\n%s\n", failures == 0 ? "stream-one matches the reference" : "stream-one is WRONG");
    return failures == 0 ? 0 : 1;
}
