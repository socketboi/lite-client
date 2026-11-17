#include "quic/h3.h"

#include "core/gomap.h"
#include "core/rnd.h"

#include "quic/huffman.h"
#include "quic/pad.h"
#include "quic/prefix.h"
#include "quic/varint.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* HTTP/3 frame and stream types, RFC 9114. */
#define H3_STREAM_CONTROL 0x00u
#define H3_FRAME_DATA 0x00u
#define H3_FRAME_HEADERS 0x01u
#define H3_FRAME_SETTINGS 0x04u

/* The one setting the reference puts on the control stream, with the code it uses
 * (vendor/quic-go/http3/frames.go:168) — see lc_h3_control_preface. The QPACK ones are left at
 * their default of zero, no dynamic table and no blocked streams, which is what keeps the response
 * decodable by the small parser below: a server may not reference a table the default says we do
 * not have. */
#define H3_SETTING_MAX_FIELD_SECTION_SIZE 0x06u

/* QPACK static table indices, RFC 9204 appendix A, as vendor/qpack/static_table.go keeps them. Only
 * the seven this request needs. */
#define QPACK_AUTHORITY 0u
#define QPACK_PATH_ROOT 1u
#define QPACK_CONTENT_LENGTH_0 4u
#define QPACK_METHOD_POST 20u
#define QPACK_SCHEME_HTTPS 23u
#define QPACK_ACCEPT_ENCODING 31u
#define QPACK_USER_AGENT 95u

/* QPACK and HPACK integers: a prefix of `bits` inside the first byte, then continuation bytes. The
 * two differ in what the leading bits mean, never in this encoding. */
size_t lc_h3_control_preface(uint8_t *out, size_t cap)
{
    /* WHAT THE REFERENCE SENDS, WHICH IS NEITHER OF WHAT WE SENT.
     *
     * quic-go builds this frame in settingsFrame.Append (vendor/quic-go/http3/frames.go:267-290)
     * from what the client passed at openControlStream (vendor/quic-go/http3/client.go:122-126):
     * MaxFieldSectionSize and Datagram, plus anything in `Other` — and hysteria passes no
     * additional settings at all. So the frame carries
     *
     *   0x06 SETTINGS_MAX_FIELD_SECTION_SIZE = 10485760   (defaultMaxResponseHeaderBytes,
     *                                        vendor/quic-go/http3/client.go:32, 10 * 1<<20)
     *
     * and nothing else. We sent the two QPACK settings — max table capacity and blocked streams,
     * both zero — which quic-go never puts on the wire, and omitted the one it always sends. Zero
     * is the QPACK default, so saying it changed nothing about the exchange and everything about
     * who we look like: the control stream is the first thing a node reads, and this frame is a
     * three-line signature.
     *
     * AND 0x33 SETTINGS_H3_DATAGRAM IS NOT ONE OF THEM, though it stood here with "hysteria enables
     * datagrams" beside it. That was two different things read as one.
     *
     * `EnableDatagrams: true` in hysteria is a field of quic.Config — QUIC's own unreliable
     * datagrams, RFC 9221 — and it appears in exactly two places,
     * vendor/hysteria/core/client/client.go:91 and vendor/hysteria/core/server/server.go:62. The
     * http3.Transport beside it (vendor/hysteria/core/client/client.go:106-116) is built with
     * TLSClientConfig, QUICConfig and Dial, and NOTHING ELSE: quic-go's http3 has its own
     * EnableDatagrams field, the reference never sets it, and settingsFrame.Append only writes 0x33
     * when it is set (vendor/quic-go/http3/frames.go:277 and :288). So no hysteria client has ever
     * put this setting on the wire.
     *
     * What announcing it did was not cosmetic. SETTINGS_H3_DATAGRAM is RFC 9297 — datagrams
     * belonging to HTTP/3 — and a peer that sees it hands every QUIC datagram to its HTTP/3 layer
     * to be dispatched by quarter stream id (vendor/quic-go/http3/conn.go:236-247). A Hysteria2 UDP
     * message is not an HTTP/3 datagram and carries no such id, so the server's HTTP/3 layer took
     * ours and dropped them, and hysteria's own conn.ReceiveDatagram — the thing its UDP session
     * manager reads — never saw one. Measured on a local stand against the reference server: our
     * packets were ACKed, and the server logged not a single "UDP request" at debug level, while
     * the reference client's UDP forwarding through the same server answered normally.
     *
     * What goes out now is the reference's frame: the one explicit value, and the QPACK settings
     * left to their default of zero, as quic-go leaves them. */
    /* Every write is checked, because lc_varint_put says "it did not fit" by returning zero and
     * these used to be summed straight into the offset. A zero in the middle of the run would have
     * left the offset where it was and let the next value overwrite the previous one, producing a
     * frame that is the right length and the wrong contents — the one failure shape that reaches the
     * node looking legitimate. It cannot arise from the values below, all of which are fixed and
     * fit; that is an argument about today's constants, not about the code, and the check costs four
     * comparisons on a path that runs once per connection. */
#define PUT(dst, room, v)                                                                          \
    do {                                                                                           \
        size_t w = lc_varint_put((dst), (room), (v));                                              \
        if (w == 0)                                                                                \
            return 0;                                                                              \
        (dst) += w;                                                                                \
        (room) -= w;                                                                               \
    } while (0)

    uint8_t  body[16];
    uint8_t *bp = body;
    size_t   broom = sizeof body;
    PUT(bp, broom, H3_SETTING_MAX_FIELD_SECTION_SIZE);
    PUT(bp, broom, 10u * (1u << 20));
    size_t b = (size_t)(bp - body);

    uint8_t *op = out;
    size_t   oroom = cap;
    PUT(op, oroom, H3_STREAM_CONTROL);
    PUT(op, oroom, H3_FRAME_SETTINGS);
    PUT(op, oroom, b);
#undef PUT

    size_t n = (size_t)(op - out);
    if (b > oroom)
        return 0;
    memcpy(op, body, b);
    return n + b;
}

/* A string as QPACK carries one: a length in a prefixed integer, then the octets — Huffman-coded,
 * ALWAYS, whether or not that comes out shorter.
 *
 * That rule is not ours to choose: it is what quic-go's encoder does, so it is what every Hysteria2
 * client on the wire does. qpack v0.6.0 — the version vendor/quic-go/go.mod requires, vendored at
 * vendor/qpack — writes every name and value through `hpack.AppendHuffmanString` with the H bit set
 * (vendor/qpack/encoder.go:66-75, :77-87) and has no raw form at all.
 *
 * ⚠️ THIS SAID "WHEN THE CODING COMES OUT SHORTER" UNTIL 2026-09-27, AND CALLED THAT GO'S RULE. It is
 * Go's HPACK rule (lc_prefix_put_string, which the spider's HTTP/2 still uses and rightly), not
 * QPACK's: a one-byte `hysteria-cc-rx: 0` went out as 01 30 where the reference sends 81 07, in the
 * first stream of every connection. */
#define put_string lc_prefix_put_huffman

/* A field line whose name is in the static table and whose value is spelled out. The two bits after
 * the pattern say "static table", which is the only table this client admits to having. */
static size_t literal_with_name_ref(uint8_t *out, size_t cap, unsigned index, const char *value)
{
    size_t n = lc_prefix_put(out, cap, 0x50u, 4u, index);
    if (n == 0)
        return 0;
    size_t v = put_string(out + n, cap - n, 0x00u, 7u, value, strlen(value));
    return v == 0 ? 0 : n + v;
}

/* Both name and value spelled out, which is what a header nobody has ever heard of requires.
 * Lower-case on the wire, always: HTTP/3 forbids anything else and a server is entitled to treat a
 * capital letter as a malformed message. */
static size_t literal_with_name(uint8_t *out, size_t cap, const char *name, const char *value,
                                size_t value_len)
{
    size_t n = put_string(out, cap, 0x20u, 3u, name, strlen(name));
    if (n == 0)
        return 0;
    size_t v = put_string(out + n, cap - n, 0x00u, 7u, value, value_len);
    return v == 0 ? 0 : n + v;
}

long lc_h3_auth_request_with(const char *authority, const char *password, const char *rx,
                             const char *pad, size_t pad_len, const unsigned order[3], uint8_t *out,
                             size_t cap)
{
    if (strlen(password) > LC_H3_PASSWORD_MAX || cap < LC_H3_AUTH_REQ_MAX || pad_len > LC_PAD_AUTH_MAX)
        return -1;

    /* The frame header is written last but its size is known now: a one-byte type and a two-byte
     * length, which is the minimal encoding for every section this can produce — the padding alone
     * puts the total past what a one-byte length could hold. Knowing it lets the fields be built
     * where they will finally sit, instead of in a second buffer of the same size. */
    const size_t hdr = 3u;
    uint8_t     *fields = out + hdr;
    size_t       room = cap - hdr;
    size_t       f = 0, n;

/* Every writer below returns zero for "it did not fit", and a section built past that point would
 * be a well-formed frame with a field line missing from the middle. */
#define ADD(expr)                                                                                  \
    do {                                                                                           \
        n = (expr);                                                                                \
        if (n == 0)                                                                                \
            return -1;                                                                             \
        f += n;                                                                                    \
    } while (0)

    /* The field section prefix: no entries required, base zero. Two bytes that say "this section
     * references nothing that has to arrive first". */
    if (room < 2u)
        return -1;
    fields[f++] = 0x00;
    fields[f++] = 0x00;

    /* THE ORDER AND THE FULL SET, both taken from what the reference actually emits.
     *
     * quic-go's request writer (vendor/quic-go/http3/request_writer.go:148-210) enumerates
     * `:authority`, `:method`, then `:path` and `:scheme`, then the caller's own headers — which for
     * hysteria are the three set by AuthRequestToHeader
     * (vendor/hysteria/core/internal/protocol/http.go:41-45) — and then three of its own that
     * nothing in hysteria asks for and every request carries anyway:
     *
     *   content-length   because shouldSendReqContentLength returns true for POST with a
     *                    zero-length body (vendor/quic-go/http3/request_writer.go:302-317,
     *                    called at vendor/quic-go/http3/request_writer.go:201)
     *   accept-encoding  gzip, added when the caller set neither Accept-Encoding nor Range
     *   user-agent       the constant "quic-go HTTP/3" (vendor/quic-go/http3/client.go:32)
     *
     * Seven fields went out here against the reference's ten, and the three missing ones are the
     * three that identify the stack rather than the request. A Hysteria2 node sees an auth request
     * that no hysteria client produces, in the first stream of every connection.
     *
     * `:authority` leads because that is where the reference puts it; the old order began with
     * `:method`. Indexed field lines from the static table use the pattern 1 followed by the table
     * bit. */
    ADD(literal_with_name_ref(fields + f, room - f, QPACK_AUTHORITY, authority));
    ADD(lc_prefix_put(fields + f, room - f, 0xc0u, 6u, QPACK_METHOD_POST));
    ADD(literal_with_name_ref(fields + f, room - f, QPACK_PATH_ROOT, "/auth"));
    ADD(lc_prefix_put(fields + f, room - f, 0xc0u, 6u, QPACK_SCHEME_HTTPS));

    /* THE THREE HYSTERIA HEADERS GO OUT IN THE ORDER GO'S MAP ITERATION GIVES THEM — which is
     * neither one fixed order nor all six alike.
     *
     * The reference does not choose an order: quic-go writes the caller's headers by ranging over
     * the map they live in,
     *
     *     for k, vv := range req.Header {
     *                          (vendor/quic-go/http3/request_writer.go:168)
     *
     * and hysteria puts exactly these three into a fresh http.Header
     * (vendor/hysteria/core/client/client.go:126-128) by three Set calls, auth, then cc-rx, then
     * padding (vendor/hysteria/core/internal/protocol/http.go:42-44). Three keys make a SMALL map in
     * Go: one group of eight slots, filled from the front — putSlotSmall takes the first empty slot
     * (GOROOT/src/internal/runtime/maps/map.go:569-575, Go 1.26) — and ranged over from a random
     * slot, wrapping round: Iter.Init draws entryOffset
     * (GOROOT/src/internal/runtime/maps/table.go:694) and Next visits (entryIdx + entryOffset) % 8
     * (GOROOT/src/internal/runtime/maps/table.go:826). With the keys in slots 0, 1 and 2, a start in
     * 0 or anywhere in 3..7 reaches slot 0 first, a start in 1 gives cc-rx first, a start in 2
     * padding:
     *
     *     auth, cc-rx, padding     6 in 8
     *     cc-rx, padding, auth     1 in 8
     *     padding, auth, cc-rx     1 in 8        and the other three orders never.
     *
     * Measured, not only read: Go 1.26.6, the Dockerfile's, building the header exactly as hysteria
     * does, 800 000 times — 0.7498, 0.1256, 0.1246, and nothing else. The maps before Go 1.24 give
     * the same three in the same proportions: one bucket of eight, filled from the front, iterated
     * from a random offset.
     *
     * ⚠️ THIS WAS FISHER-YATES OVER SIX until 2026-09-23, on the reading "Go randomises map
     * iteration per range" — true, and not the same thing: half the orders it produced are orders the
     * reference never sends. Before that it was one fixed order. Nothing is learned from ONE request —
     * every order is legal, the lengths do not move, and it rides 1-RTT keys — it is the DISTRIBUTION
     * over a handful of connections from one client that a node, or anything holding the session
     * keys, can compare.
     *
     * So the walk is the iterator's own, through core/gomap — the one model of a Go map walk this
     * tree has, shared with the HTTP/2 headers of XHTTP and the spider, and held to Go's own maps
     * by test/gomap. For three keys it is exactly the rotation above: one start among eight slots.
     * A failure to draw is a refusal rather than a fixed order, for the same reason lc_rnd_grease
     * refuses. */
    const struct {
        const char *name;
        const char *value;
        size_t      len;
    } hy[3] = {
        { "hysteria-auth", password, strlen(password) },
        { "hysteria-cc-rx", rx, strlen(rx) },
        { "hysteria-padding", pad, pad_len },
    };

    /* The three go into a fresh map in the order Set put them, and come out in the order Go walks
     * it — `order`, drawn by lc_h3_auth_request. Why, and measured against Go, is the long comment
     * above. */
    for (unsigned k = 0; k < 3u; k++)
        ADD(literal_with_name(fields + f, room - f, hy[order[k]].name, hy[order[k]].value,
                              hy[order[k]].len));

    /* And the three quic-go adds after the caller's own, in this order — through the static table,
     * as qpack's WriteField looks every name up first (vendor/qpack/encoder.go:34-50):
     *
     *   content-length: 0   name AND value in the table, `{4, map[string]uint8{"0": 4}}`
     *                       (vendor/qpack/static_table.go:128): the indexed field line 0xc4;
     *   accept-encoding     name only, index 31 (static_table.go:172, whose one value is
     *                       "gzip, deflate, br"): a literal with a name reference;
     *   user-agent          name only, index 95 (static_table.go:249): the same.
     *
     * ⚠️ ALL THREE WENT OUT AS LITERALS WITH THE NAME SPELLED OUT until 2026-09-27 — about thirty
     * bytes more than the reference in the first stream of every connection, found by reading the
     * encoder, which is not in quic-go's tree but in the qpack module it requires. */
    ADD(lc_prefix_put(fields + f, room - f, 0xc0u, 6u, QPACK_CONTENT_LENGTH_0));
    ADD(literal_with_name_ref(fields + f, room - f, QPACK_ACCEPT_ENCODING, "gzip"));
    ADD(literal_with_name_ref(fields + f, room - f, QPACK_USER_AGENT, "quic-go HTTP/3"));

#undef ADD

    /* Non-minimal varints are legal and nobody writes them, so a section that would need a shorter
     * length than the three bytes reserved above is one this cannot emit honestly. It cannot arise
     * — the padding is 256 characters at its shortest — and saying so is cheaper than proving it
     * again every time someone changes a field. */
    if (f <= 63u || f > 16383u)
        return -1;

    out[0] = (uint8_t)H3_FRAME_HEADERS;
    out[1] = (uint8_t)(0x40u | f >> 8);
    out[2] = (uint8_t)f;
    return (long)(hdr + f);
}

long lc_h3_auth_request(const char *authority, const char *password, uint64_t rx_rate, uint8_t *out,
                        size_t cap)
{
    char rx[32];
    snprintf(rx, sizeof rx, "%llu", (unsigned long long)rx_rate);

    /* Padding of a random length, which is the point of it: a request that is always the same size
     * is a signature regardless of what is inside. */
    uint32_t padding_len = 0;
    char     pad[LC_PAD_AUTH_MAX];
    if (lc_pad_draw(LC_PAD_AUTH_MIN, LC_PAD_AUTH_MAX, &padding_len) != 0 ||
        lc_pad_fill(pad, padding_len) != 0)
        return -1;

    /* The order Go's map walk gives the three hysteria headers; see lc_h3_auth_request_with. */
    unsigned order[3];
    if (lc_gomap_fresh_walk(3u, order) != 0)
        return -1;
    return lc_h3_auth_request_with(authority, password, rx, pad, padding_len, order, out, cap);
}

/* A field's octets, in whichever of the two forms they arrived in, into a buffer that may be too
 * small for them.
 *
 * Truncating is deliberate and safe here: the only field that overruns is the padding, which exists
 * to be ignored, and a name too long to fit cannot become a shorter name this client acts on. What
 * is never skipped is the reading — the whole coded run is consumed and validated either way, since
 * the position of the next field line depends on it. */
static int read_octets(const uint8_t *in, size_t len, size_t *off, uint64_t n, int huffman,
                       char *out, size_t cap)
{
    /* n arrives from a QPACK prefixed integer the peer fully controls and which is independent of
     * the frame length, so it can name billions while the frame is a handful of bytes. The bound is
     * taken while it is still 64-bit: narrowing first and adding to *off would wrap on a 32-bit
     * size_t (the router target) and let the guard pass on a length that overruns the buffer. */
    if (cap == 0 || *off > len || n > (uint64_t)(len - *off))
        return -1;
    size_t nn = (size_t)n;

    if (huffman) {
        if (lc_huff_decode(in + *off, nn, out, cap) < 0)
            return -1;
    } else {
        size_t k = nn < cap - 1u ? nn : cap - 1u;
        memcpy(out, in + *off, k);
        out[k] = '\0';
    }
    *off += nn;
    return 0;
}

/* :status AS THE QPACK STATIC TABLE ACTUALLY INDEXES IT — TWO RUNS, NOT ONE.
 *
 * Five entries used to be recognised, 24..28, and they are right: nghttp3_qpack.c:216-220 is
 * `:status` 103, 200, 304, 404, 503. But the table puts nine MORE of them at 63..71 — 100, 204, 206,
 * 302, 400, 403, 421, 425, 500 (nghttp3_qpack.c:283-291, with the index mapping fixed at :69-77) —
 * and those were named `?68` and the like, which matches none of the arms in lc_h3_auth_response, so
 * the status came out as 0.
 *
 * Zero is the worst possible answer there, because that path exists precisely to DIAGNOSE. A node
 * that refuses a password answers with whatever its masquerade serves, and the status is the only
 * thing that tells one refusal from another: a reverse proxy returning 403, or an upstream site that
 * is down returning 500, are one byte each — 0xC4 and 0xC7 — and both were reported as "it answered
 * with HTTP status 0", which sends the operator looking for a transport fault instead of reading the
 * perfectly legible answer the node gave. The verdict itself was never wrong (neither is 233); what
 * was wrong was everything the log said about why. */
static const char *static_status(uint64_t index)
{
    static const char *const low[] = { "103", "200", "304", "404", "503" };
    static const char *const high[] = { "100", "204", "206", "302", "400",
                                        "403", "421", "425", "500" };
    if (index >= 24u && index <= 28u)
        return low[index - 24u];
    if (index >= 63u && index <= 71u)
        return high[index - 63u];
    return NULL;
}

/* Reads one field line and reports its name and value. Only the shapes our SETTINGS permit are
 * accepted; anything referencing the dynamic table is a protocol violation on the server's part and
 * is refused rather than guessed at. */
static int read_field(const uint8_t *in, size_t len, size_t *off, char *name, size_t name_cap,
                      char *value, size_t value_cap)
{
    if (*off >= len)
        return -1;
    uint8_t first = in[*off];
    uint64_t index = 0, vlen = 0;

    name[0] = '\0';
    value[0] = '\0';

    if ((first & 0x80u) != 0) {
        /* Indexed field line: name and value both come from a table, and our settings left only
         * the static one. Five of its entries are statuses; every other one is a header this client
         * has no use for.
         *
         * Those others must not be given a name it does act on. A real answer carries several —
         * content-length is an indexed line, and so is server — and calling them all ":status"
         * meant the last one landed on top of the status already read and turned 233 into nothing.
         * The field is named by its index instead, which matches nothing and reads as what it is. */
        if ((first & 0x40u) == 0)
            return -1;
        if (lc_prefix_get(in, len, off, 6u, &index) != 0)
            return -1;

        const char *status = static_status(index);
        if (status != NULL) {
            snprintf(name, name_cap, ":status");
            snprintf(value, value_cap, "%s", status);
        } else
            snprintf(name, name_cap, "?%llu", (unsigned long long)index);
        return 0;
    }

    if ((first & 0x40u) != 0) {
        /* Literal with a name from a table. */
        if ((first & 0x10u) == 0)
            return -1; /* dynamic table: forbidden by our settings */
        if (lc_prefix_get(in, len, off, 4u, &index) != 0)
            return -1;
        if (index == 0)
            snprintf(name, name_cap, ":authority");
        else if (static_status(index) != NULL)
            snprintf(name, name_cap, ":status");
        else
            snprintf(name, name_cap, "?%llu", (unsigned long long)index);
    } else if ((first & 0x20u) != 0) {
        /* Literal with a literal name. */
        int huffman = (first & 0x08u) != 0;
        if (lc_prefix_get(in, len, off, 3u, &index) != 0)
            return -1;
        if (read_octets(in, len, off, index, huffman, name, name_cap) != 0)
            return -1;
    } else {
        return -1;
    }

    if (*off >= len)
        return -1;
    int huffman = (in[*off] & 0x80u) != 0;
    if (lc_prefix_get(in, len, off, 7u, &vlen) != 0)
        return -1;
    return read_octets(in, len, off, vlen, huffman, value, value_cap);
}

/* What Go's strconv.ParseBool accepts, which is what the node's answer is read with.
 *
 * AuthResponseFromHeader passes Hysteria-UDP straight to it
 * (vendor/hysteria/core/internal/protocol/http.go:49), and it takes "1", "t", "T", "TRUE", "true",
 * "True" as true and the six matching forms as false; anything else is an error, which that call
 * discards, leaving false. Comparing against "true" alone is what stood here, and it is right about
 * every answer hysteria's own server sends — strconv.FormatBool writes "true" — which is exactly
 * why it would have been found only against something else speaking this protocol, as a client on
 * which UDP silently did not work. */
static int parse_bool(const char *v)
{
    return strcmp(v, "1") == 0 || strcmp(v, "t") == 0 || strcmp(v, "T") == 0 ||
           strcmp(v, "true") == 0 || strcmp(v, "TRUE") == 0 || strcmp(v, "True") == 0;
}

int lc_h3_auth_response(const uint8_t *in, size_t len, lc_h3_auth_result *out)
{
    memset(out, 0, sizeof *out);

    size_t off = 0;
    while (off < len) {
        uint64_t type = 0, flen = 0;
        size_t   save = off;
        if (lc_varint_get(in, len, &off, &type) != 0 || lc_varint_get(in, len, &off, &flen) != 0) {
            off = save;
            return 0; /* the frame header is not all here yet */
        }
        /* A length is a sixty-two bit number on the wire and an offset into a buffer here, and on a
         * thirty-two bit router those are not the same size. Compared as it arrived, narrowed only
         * once it is known to fit — a cast before this test would wrap a huge length into a small
         * one and turn a refusal into a read. */
        if (flen > (uint64_t)(len - off)) {
            off = save;
            return 0;
        }

        if (type != H3_FRAME_HEADERS) {
            /* DATA and anything unknown: skipped, which is what RFC 9114 asks for. */
            off += (size_t)flen;
            continue;
        }

        size_t end = off + (size_t)flen;
        /* THE FIELD SECTION PREFIX, NOW READ RATHER THAN ASSUMED.
         *
         * Required Insert Count and Delta Base. Both are zero here, and that is a consequence of
         * what we offer rather than a hope: we advertise no SETTINGS_QPACK_MAX_TABLE_CAPACITY at all
         * (see the settings written above), so the peer has no dynamic table, so both fields are
         * zero — and QPACK's prefixed integers have no non-minimal encoding, so a peer honouring
         * that cannot spell zero in more than one octet each. The live answer frozen in
         * test/h3/test_h3.c begins `01 44ed 00 00`, which is the two of them.
         *
         * This said all of the above in a comment and then skipped two bytes without looking at
         * them. The bytes are the same either way while the peer behaves; the difference is what
         * happens when it does not. Unchecked, a longer prefix shifts every field line that follows,
         * and the section is then parsed from the wrong offset — at best refused as malformed, at
         * worst decoded into a `:status` that was never sent, which lc_qconn_auth_poll reports as
         * the node answering with a status it did not answer with.
         *
         * The reference refuses instead of shifting: nghttp3 reads both as prefixed integers
         * (vendor/nghttp3/lib/nghttp3_qpack.c:3363 for the count, :3391 setting a 7-bit prefix for
         * the base) and turns a Required Insert Count above what the capacity allows into
         * NGHTTP3_ERR_QPACK_DECOMPRESSION_FAILED — with a capacity of zero, `full = 2 * max_ents` is
         * zero, so anything above zero fails (:3909-3925). Refusing the section is the same answer,
         * reached by reading the two octets we already require to be zero.
         *
         * Not a decoder for the general case: this client speaks to one node over an authenticated
         * connection and needs the prefix it asked for, not every prefix QPACK can express. What it
         * must not do is carry on through one it did not understand. */
        if (off + 2u > end)
            return -1;
        if (in[off] != 0x00u || in[off + 1u] != 0x00u)
            return -1;
        off += 2u;

        while (off < end) {
            char name[64], value[256];
            if (read_field(in, end, &off, name, sizeof name, value, sizeof value) != 0)
                return -1;

            if (strcmp(name, ":status") == 0)
                out->status = atoi(value);
            else if (strcmp(name, "hysteria-udp") == 0)
                out->udp_enabled = parse_bool(value);
            else if (strcmp(name, "hysteria-cc-rx") == 0) {
                /* Truncated deliberately rather than refused: this is a rate or the word "auto",
                 * and a value longer than the field is a server saying something we would not have
                 * understood anyway. */
                size_t n = strlen(value);
                if (n >= sizeof out->cc_rx)
                    n = sizeof out->cc_rx - 1u;
                memcpy(out->cc_rx, value, n);
                out->cc_rx[n] = '\0';

                if (strcmp(out->cc_rx, "auto") == 0)
                    out->rate_auto = 1;
                else
                    out->rate_bytes = strtoull(out->cc_rx, NULL, 10);
            }
        }
        return 1;
    }
    return 0;
}
