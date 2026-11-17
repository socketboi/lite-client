/* The VLESS request header, byte for byte, and the one string that decides its shape.
 *
 * There was no test here at all, which is why the defect this pins lived: `flow` was read twice, by
 * two rules that disagreed. The wire format asked "is the string empty" and wrote an addons block
 * for anything that was not; the framing decision beside it asked "is the string exactly Vision".
 * So a flow of "xtls-rprx-vision-udp443" — a name that has existed — or any typo produced a request
 * carrying an addons block naming it, with no Vision framing behind it. Xray's client cannot
 * produce that pairing: EncodeHeaderAddons marshals the message under `case vless.XRV` and writes a
 * bare zero under `default` (vendor/Xray-core/proxy/vless/encoding/addons.go:17-34).
 *
 * Nothing about that failure is visible from this side. The node reads a request it would never
 * have sent, answers by refusing, and the refusal is a stream that opens and then says nothing —
 * the same thing a wrong UUID, a wrong target and a dead node all look like.
 *
 * So what is pinned here is the header as bytes, against the layout in vendor/Xray-core/proxy/vless/
 * vless/encoding/encoding.go:30-61, and the predicate that both readings now share. */

#include "vless/vless.c"

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

static const uint8_t uuid[LC_VLESS_UUID] = {
    0xc4, 0x02, 0x53, 0xba, 0x8b, 0x09, 0x42, 0x4c,
    0xa2, 0x6e, 0xe9, 0x58, 0x08, 0xc4, 0xc4, 0xf9,
};

int main(void)
{
    uint8_t out[512];
    size_t  len = 0;

    printf("vless: which strings are flows\n");

    ok(lc_vless_flow(NULL) == 0, "no flow at all is the absence of one, not an error");
    ok(lc_vless_flow("") == 0, "and so is the empty string");
    ok(lc_vless_flow(LC_VLESS_FLOW_VISION) == 1, "xtls-rprx-vision is the one flow there is");
    /* AND ITS SECOND SPELLING, which the reference reaches by falling through into the same arm
     * (vendor/Xray-core/proxy/vless/outbound/outbound.go:247-252). This line used to assert the
     * opposite — "a name from the protocol's past is not one now" — and that reading came from
     * this client rather than from Xray, which accepts the value to this day and merely truncates
     * it before it reaches the wire. */
    ok(lc_vless_flow(LC_VLESS_FLOW_VISION_UDP443) == 1, "and so is its -udp443 spelling");
    /* A plausible typo and Xray's own word for "none" — the latter a configuration value, not
     * something that goes on the wire as a flow. */
    ok(lc_vless_flow("xtls-rprx-visionn") < 0, "a typo of the one that is, is not");
    ok(lc_vless_flow("none") < 0, "nor the word Xray uses for its absence");

    printf("\nvless: the request header\n");

    ok(lc_vless_request(uuid, NULL, "example.com", 443, out, sizeof out, &len) == 0,
       "a request without a flow builds");
    /* version, uuid, addons length, command, port, address type, address length, address. */
    ok(len == 1u + 16u + 1u + 1u + 2u + 1u + 1u + 11u, "and is exactly the header and nothing else");
    ok(out[0] == 0x00u, "version zero");
    ok(memcmp(out + 1, uuid, LC_VLESS_UUID) == 0, "then the account, unencoded");
    ok(out[17] == 0x00u, "then a zero addons length, which is what upstream's default arm writes");
    ok(out[18] == LC_VLESS_TCP, "then the command");
    ok(out[19] == 0x01u && out[20] == 0xbbu, "then the port, big-endian: 443");
    ok(out[21] == LC_VLESS_ADDR_DOMAIN, "then the address type, always a name");
    ok(out[22] == 11u && memcmp(out + 23, "example.com", 11) == 0, "then its length and the name");

    printf("\nvless: the addons block\n");

    ok(lc_vless_request(uuid, LC_VLESS_FLOW_VISION, "example.com", 443, out, sizeof out, &len) == 0,
       "a request with the Vision flow builds");
    /* protobuf: field 1, length-delimited, then the length and the name. Written by hand here and
     * by proto.Marshal there; one field of one wire type has exactly one encoding. */
    ok(out[17] == 2u + 16u, "the addons length counts the protobuf preamble as well as the name");
    ok(out[18] == 0x0au, "field one, wire type two");
    ok(out[19] == 16u, "the name's own length");
    ok(memcmp(out + 20, LC_VLESS_FLOW_VISION, 16) == 0, "and the name");

    /* THE TWO SPELLINGS PRODUCE THE SAME BYTES, and that is the reference's doing rather than ours.
     *
     *     case vless.XRV + "-udp443":
     *         allowUDP443 = true
     *         requestAddons.Flow = requestAddons.Flow[:16]
     *         fallthrough
     *     case vless.XRV:
     *                (vendor/Xray-core/proxy/vless/outbound/outbound.go:247-252)
     *
     * The permission is spent on the client, deciding whether a UDP/443 request is made at all; the
     * field is truncated before the header is encoded, so a node cannot tell the two apart and must
     * not be given the chance. This block used to assert the opposite — that "-udp443" is "a string
     * that is not a flow" and carries no addons — which was this client's own belief and not the
     * reference's: it turned a legal plane setting into a request Xray would never send. */
    uint8_t vision_out[256];
    size_t  vision_len = 0;
    ok(lc_vless_request(uuid, LC_VLESS_FLOW_VISION, "example.com", 443,
                        vision_out, sizeof vision_out, &vision_len) == 0,
       "a plain Vision request builds");
    ok(lc_vless_request(uuid, LC_VLESS_FLOW_VISION_UDP443, "example.com", 443,
                        out, sizeof out, &len) == 0,
       "and so does the -udp443 spelling");
    ok(len == vision_len && memcmp(out, vision_out, len) == 0,
       "byte for byte the same request: the suffix never reaches the wire");
    ok(out[17] == 2u + 16u && out[18] == 0x0au && out[19] == 16u &&
       memcmp(out + 20, LC_VLESS_FLOW_VISION, 16) == 0,
       "the addons carry the truncated sixteen bytes, not the twenty-three typed");

    /* Both halves of the reference's answer, asked separately because it asks them separately. */
    ok(lc_vless_flow(LC_VLESS_FLOW_VISION_UDP443) == 1, "-udp443 is Vision");
    ok(lc_vless_flow_allows_udp443(LC_VLESS_FLOW_VISION_UDP443) == 1, "and it carries allowUDP443");
    ok(lc_vless_flow_allows_udp443(LC_VLESS_FLOW_VISION) == 0, "which plain Vision does not");

    /* A string that genuinely is not a flow still is not one. */
    ok(lc_vless_flow("xtls-rprx-origin") == -1, "an unknown flow is refused, not guessed at");
    ok(lc_vless_request(uuid, "xtls-rprx-origin", "example.com", 443, out, sizeof out, &len) == 0,
       "a request with a string that is not a flow still builds");
    ok(out[17] == 0x00u, "and carries NO addons, which is upstream's default arm");
    ok(len == 1u + 16u + 1u + 1u + 2u + 1u + 1u + 11u, "so it is the same length as a flowless one");

    printf("\nvless: datagrams go out as Mux, not as command 2\n");

    ok(lc_vless_request_udp(uuid, "xtls-rprx-vision", "1.1.1.1", 53, out, sizeof out, &len) == 0,
       "a datagram request builds");
    /* The addons are NOT empty here, and that was the whole of the bug a live Xray found: the
     * rewrite to Mux touches Command, Address and Port and leaves requestAddons alone, so the flow
     * is still there. An inbound whose account has a flow refuses a request without one — "account
     * ... is rejected since the client flow is empty". Eighteen bytes: the 0x0a tag, the length, and
     * sixteen characters of xtls-rprx-vision. */
    ok(out[17] == 18u, "the addons carry the flow, as they do for a TCP request");
    ok(out[18] == 0x0au && out[19] == 16u, "field one, length-delimited, sixteen bytes");

    /* AND THE COMMAND IS MUX, NOT 2. A client with Vision rewrites the request before encoding it
     * — `request.Command = protocol.RequestCommandMux`, address v1.mux.cool, port 666
     * (vendor/Xray-core/proxy/vless/outbound/outbound.go:303-307) — so the real destination is not
     * in this header at all; it rides the xudp frame around each datagram. This asserted the old
     * shape, which is why it had to be changed with the code rather than merely re-run. */
    ok(out[36] == LC_VLESS_MUX, "and the Mux command");
    /* AND THE HEADER STOPS THERE: no address, no port. The encoder skips both for Mux
     * (vendor/Xray-core/proxy/vless/encoding/encoding.go:50-54) and the decoder puts v1.mux.cool
     * back from the command alone (:115-116), reporting the destination as v1.mux.cool:0. Writing
     * them anyway left two bytes the Mux reader took for its first frame — a live Xray answered
     * "common/mux: invalid metalen 666", 666 being the port we should not have written. */
    ok(len == 1u + 16u + 1u + 18u + 1u, "and the header ends at the command");

    /* AND THE WHOLE HEADER AGAINST BYTES A REAL XRAY CLIENT PUT ON A WIRE.
     *
     * Everything above pins the header against the layout in
     * vendor/Xray-core/proxy/vless/encoding/encoding.go:30-61 — that is, against a source file read
     * by a person. That is how the signature_algorithms defect of 2026-08-25 got in on the other
     * plane: the right constant taken out of the wrong context, with nothing able to notice. So one
     * assertion here is not a transcription but a capture.
     *
     * HOW IT WAS TAKEN, so it can be retaken rather than trusted. A TLS server was stood up that
     * accepts a connection and prints the first bytes of the plaintext stream, and Xray built from
     * Xray built from source was pointed at it as a VLESS client with `flow: xtls-rprx-vision` and
     * `security: tls`. REALITY is not needed for this and would only be in the way: the request is
     * written by encoding.EncodeRequestHeader, which knows nothing of the transport beneath it.
     * ⚠️ `allowInsecure` no longer exists in Xray — the self-signed certificate is accepted through
     * `pinnedPeerCertSha256`, which is sha256 over the whole certificate DER (transport/internet/
     * tls/pin.go:10-16), hex, not the SPKI hash this project's own pins use.
     *
     * What came back, with this uuid, example.com and port 80:
     *
     *   00                                version
     *   8f2c1d3a4b5e4f609a7b0c1d2e3f4a5b  uuid
     *   12                                addons length, 18
     *     0a 10 "xtls-rprx-vision"        protobuf field 1, sixteen bytes, the FULL name
     *   01                                TCP
     *   0050                              port 80
     *   02 0b "example.com"               domain
     *
     * and this client produced the same fifty-two bytes. The full flow name is worth noting on its
     * own: it is what lc_vless_flow_wire returns, and the truncation to sixteen that Xray applies
     * (`requestAddons.Flow[:16]`) is exactly why the -udp443 spelling reaches the wire as this. */
    static const uint8_t xray_uuid[LC_VLESS_UUID] = {
        0x8f, 0x2c, 0x1d, 0x3a, 0x4b, 0x5e, 0x4f, 0x60,
        0x9a, 0x7b, 0x0c, 0x1d, 0x2e, 0x3f, 0x4a, 0x5b,
    };
    static const uint8_t xray_request[] = {
        0x00,
        0x8f, 0x2c, 0x1d, 0x3a, 0x4b, 0x5e, 0x4f, 0x60,
        0x9a, 0x7b, 0x0c, 0x1d, 0x2e, 0x3f, 0x4a, 0x5b,
        0x12,
        0x0a, 0x10, 'x', 't', 'l', 's', '-', 'r', 'p', 'r', 'x', '-',
        'v', 'i', 's', 'i', 'o', 'n',
        0x01,
        0x00, 0x50,
        0x02, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
    };
    ok(lc_vless_request(xray_uuid, LC_VLESS_FLOW_VISION, "example.com", 80,
                        out, sizeof out, &len) == 0,
       "the request Xray's own capture was taken from builds");
    ok(len == sizeof xray_request && memcmp(out, xray_request, sizeof xray_request) == 0,
       "and is byte for byte what a real Xray client sent");

    /* THE RESPONSE HEADER, AS DecodeResponseHeader READS IT: across records, and the addons
     * unmarshalled as Addons (vendor/Xray-core/proxy/vless/encoding/encoding.go:153-172,
     * addons.go:40-58). */
    printf("\nvless: the response header, from the stream\n");
    {
        lc_vless_resp r;
        size_t        took = 0;
        memset(&r, 0, sizeof r);
        static const uint8_t v0[1] = { 0x00 };
        static const uint8_t rest[4] = { 0x00, 'd', 'a', 't' };
        int a = lc_vless_response_feed(&r, v0, 1, &took);
        int b = a == 0 && took == 1u ? lc_vless_response_feed(&r, rest, 4, &took) : -2;
        ok(a == 0 && b == 1 && took == 1u, "a header split across two records is waited for, then whole");

        static const uint8_t bad_v[2] = { 0x01, 0x00 };
        memset(&r, 0, sizeof r);
        ok(lc_vless_response_feed(&r, bad_v, 2, &took) == -1, "a version that is not ours is refused");

        static const struct { const uint8_t b[8]; size_t n; int good; const char *what; } ad[] = {
            { { 0x0a, 0x03, 'x', 'y', 'z' }, 5u, 1, "a Flow string unmarshals" },
            { { 0x0a, 0x01, 0xff }, 3u, 0, "a Flow that is not UTF-8 does not" },
            { { 0x12, 0x02, 0xff, 0xfe }, 4u, 1, "Seed is bytes, not UTF-8" },
            { { 0x18, 0x05 }, 2u, 1, "an unknown varint field is kept, no error" },
            { { 0x08, 0x05 }, 2u, 1, "Flow under the varint wire type is unknown, no error" },
            { { 0x00, 0x01 }, 2u, 0, "field number zero is an error" },
            { { 0x0b, 0x18, 0x01, 0x0c }, 4u, 1, "a group that ends is read" },
            { { 0x0b, 0x18, 0x01 }, 3u, 0, "one that does not end is an error" },
            { { 0x0c }, 1u, 0, "an end with no start is an error" },
            { { 0x0e }, 1u, 0, "wire type six is an error" },
            { { 0x0a, 0x05, 'a' }, 3u, 0, "a length past the end is an error" },
        };
        for (size_t i = 0; i < sizeof ad / sizeof ad[0]; i++)
            ok((lc_vless_addons_ok(ad[i].b, ad[i].n) != 0) == ad[i].good, ad[i].what);
    }

    /* WITHOUT A FLOW, DNS AND QUIC GO AS COMMAND 2. The rewrite into Mux is taken only for Vision,
     * or — with cone, the default — for a port other than 53 and 443
     * (vendor/Xray-core/proxy/vless/outbound/outbound.go:303); otherwise the request keeps its
     * command and its destination, and EncodeRequestHeader writes both
     * (vendor/Xray-core/proxy/vless/encoding/encoding.go:46-54). */
    printf("\nvless: without a flow, a datagram for 53 or 443 is command 2 to its own address\n");
    {
        static const uint8_t want[] = {
            0x00,                                           /* version */
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
            0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21, /* uuid */
            0x00,                                           /* no addons */
            0x02,                                           /* UDP */
            0x00, 0x35,                                     /* port 53 */
            0x01, 0x01, 0x01, 0x01, 0x01,                   /* IPv4 1.1.1.1 */
        };
        static const uint8_t id[16] = { 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                                        0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21 };
        ok(lc_vless_request_udp_plain(id, NULL, "1.1.1.1", 53, out, sizeof out, &len) == 0 &&
               len == sizeof want && memcmp(out, want, sizeof want) == 0,
           "version, uuid, no addons, command 2, port, then the address");
    }

    printf(failures == 0 ? "\nall good\n" : "\n%d failed\n", failures);
    return failures == 0 ? 0 : 1;
}
