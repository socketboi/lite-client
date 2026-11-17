/* The xudp frame, byte for byte against the layout derived from Xray's writer.
 *
 * The vector below is not a capture: it is what vendor/Xray-core/common/xudp/xudp.go:96-135 writes
 * for one datagram, worked out field by field, which is the only form available offline. That makes
 * it a check of THIS code against THAT reading — so the reading is spelled out beside it, and the
 * next person can disagree with the reading rather than with an opaque blob. */

#include "vless/xudp.c"

#include <stdio.h>

static int failures;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

static void show(const char *tag, const uint8_t *b, size_t n)
{
    printf("        %s:", tag);
    for (size_t i = 0; i < n; i++)
        printf(" %02x", b[i]);
    printf("\n");
}

int main(void)
{
    printf("the xudp frame\n");

    /* 1.1.1.1:53, payload "abc".
     *
     *   00 14           meta length: everything after this field up to the payload length
     *   00 00           Mux session id
     *   01              status New
     *   01              option: a payload follows
     *   02              network UDP
     *   00 35           port 53, and the port comes FIRST — PortThenAddress
     *   01              address type IPv4
     *   01 01 01 01     the address
     *   00 x8           global id, zero for a client that is not an Xray inbound
     *   00 03           payload length
     *   61 62 63        "abc"
     *
     * Twenty is 2 + 1 + 1 + 1 + 2 + 1 + 4 + 8, which is the session id through the global id. */
    static const uint8_t want_new[] = {
        0x00, 0x14, 0x00, 0x00, 0x01, 0x01, 0x02, 0x00, 0x35, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 'a',  'b',  'c'
    };

    uint8_t got[256];
    size_t  n = 0;
    ok(lc_xudp_wrap(1, "1.1.1.1", 53, NULL, (const uint8_t *)"abc", 3, got, sizeof got, &n) == 0,
       "the first frame builds");
    ok(n == sizeof want_new && memcmp(got, want_new, n) == 0,
       "and is the bytes the reference writes");
    if (n != sizeof want_new || memcmp(got, want_new, n) != 0) {
        show("ours", got, n);
        show("want", want_new, sizeof want_new);
    }

    /* A later datagram on the same stream: status Keep, and no global id — the reference writes
     * that one only in the New arm. */
    static const uint8_t want_keep[] = {
        0x00, 0x0c, 0x00, 0x00, 0x02, 0x01, 0x02, 0x00, 0x35, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x00, 0x02, 'h',  'i'
    };
    ok(lc_xudp_wrap(0, "1.1.1.1", 53, NULL, (const uint8_t *)"hi", 2, got, sizeof got, &n) == 0,
       "a later frame builds");
    ok(n == sizeof want_keep && memcmp(got, want_keep, n) == 0, "with status Keep and no global id");
    if (n != sizeof want_keep || memcmp(got, want_keep, n) != 0) {
        show("ours", got, n);
        show("want", want_keep, sizeof want_keep);
    }

    /* THE GLOBAL ID, WHICH IS WHAT THE NODE KEYS ITS NAT MAPPING ON. It rides the New frame and
     * nothing else: a Keep frame that carried one would be a different message. NULL still writes
     * eight zeros, which the node is required to ignore — "MUST ignore empty Global ID"
     * (vendor/Xray-core/common/mux/server.go:195) — so the two cases differ in the bytes and not
     * in the shape. */
    static const uint8_t gid[8] = { 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04 };
    ok(lc_xudp_wrap(1, "1.1.1.1", 53, gid, (const uint8_t *)"abc", 3, got, sizeof got, &n) == 0 &&
           n == sizeof want_new && memcmp(got + n - 3u - 2u - 8u, gid, 8) == 0,
       "a New frame carries the global id it was given, in the last eight bytes of the meta");
    ok(lc_xudp_wrap(0, "1.1.1.1", 53, gid, (const uint8_t *)"hi", 2, got, sizeof got, &n) == 0 &&
           n == sizeof want_keep && memcmp(got, want_keep, n) == 0,
       "and a Keep frame carries none, whatever it was given");

    /* WITHOUT AN ADDRESS OF ITS OWN — `b.UDP` nil, a listener that is not transparent — the New
     * frame has no global id and a Keep frame neither network nor address: four bytes of meta
     * (vendor/Xray-core/common/xudp/xudp.go:105-119). */
    static const uint8_t bare_new[] = { 0x00, 0x0c, 0x00, 0x00, 0x01, 0x01, 0x02, 0x00, 0x35,
                                        0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x03, 'a',  'b',  'c' };
    static const uint8_t bare_keep[] = { 0x00, 0x04, 0x00, 0x00, 0x02, 0x01, 0x00, 0x02, 'h', 'i' };
    ok(lc_xudp_wrap_unaddressed(1, "1.1.1.1", 53, (const uint8_t *)"abc", 3, got, sizeof got, &n) ==
               0 &&
           n == sizeof bare_new && memcmp(got, bare_new, n) == 0,
       "an unaddressed New frame carries the destination and no global id");
    ok(lc_xudp_wrap_unaddressed(0, "1.1.1.1", 53, (const uint8_t *)"hi", 2, got, sizeof got, &n) ==
               0 &&
           n == sizeof bare_keep && memcmp(got, bare_keep, n) == 0,
       "and an unaddressed Keep frame is status and option, nothing more");

    /* A name travels as a name, and the length byte belongs to the domain form only. */
    ok(lc_xudp_wrap(1, "example.com", 443, NULL, (const uint8_t *)"x", 1, got, sizeof got, &n) == 0 &&
           got[6] == 0x02u && got[7] == 0x01u && got[8] == 0xbbu && got[9] == LC_VLESS_ADDR_DOMAIN &&
           got[10] == 11u,
       "a domain destination is type 2 with a length, after the port");

    /* Reading back what a server sends: Keep frames, which is the only status a client receives. */
    const uint8_t *p = NULL;
    size_t         plen = 0, used = 0;
    char           from[256];
    uint16_t       fport = 0;
    ok(lc_xudp_next(want_keep, sizeof want_keep, from, sizeof from, &fport, &p, &plen, &used) == 1 && plen == 2u &&
           memcmp(p, "hi", 2) == 0 && used == sizeof want_keep,
       "a Keep frame reads back to its payload");

    /* AND TO THE ADDRESS IT STATES, which the reader used to skip along with the rest of the meta.
     *
     * Every Keep frame carries its own destination — that is what lets ONE xudp session serve every
     * destination a client talks to, because the session belongs to the client rather than to a
     * destination (vendor/Xray-core/common/xudp/xudp.go:117-121). A reader that drops it can only
     * ever attribute a reply to the single destination its stream was opened for. */
    ok(strcmp(from, "1.1.1.1") == 0 && fport == 53u,
       "and to the address that frame states, which is how one session serves many destinations");

    /* Short buffers are 'not yet', not an error — the ordinary case on a stream. */
    for (size_t cut = 1; cut < sizeof want_keep; cut++) {
        if (lc_xudp_next(want_keep, cut, from, sizeof from, &fport, &p, &plen, &used) != 0) {
            printf("  FAIL  a %zu-byte prefix was not answered with 'more please'\n", cut);
            failures++;
            break;
        }
    }
    ok(1, "every prefix of it asks for more rather than failing");

    /* WHAT ENDS THE STREAM RATHER THAN FAILING IT — both of the inputs the reference answers with
     * `io.EOF`, and the third case is the one that happens in the field.
     *
     * These two asserted -1 until 2026-09-10, and the second one's own wording admitted the
     * divergence while freezing it: "a status the reference reads as end-of-stream is refused". A
     * test can hold a defect in place by describing it accurately; this is what that looks like. */
    static const uint8_t tiny[] = { 0x00, 0x03, 0x00, 0x00, 0x02 };
    ok(lc_xudp_next(tiny, sizeof tiny, from, sizeof from, &fport, &p, &plen, &used) == LC_XUDP_ENDED,
       "a meta block under four ends the stream, which is what io.EOF means there");

    uint8_t bad_status[sizeof want_keep];
    memcpy(bad_status, want_keep, sizeof want_keep);
    bad_status[4] = 0x01u; /* New, which no server sends */
    ok(lc_xudp_next(bad_status, sizeof bad_status, from, sizeof from, &fport, &p, &plen, &used) == LC_XUDP_ENDED,
       "and a status outside Keep and KeepAlive ends it too");

    /* End (0x03) is not a corner case: it is how a node closes a datagram session. It fell to the
     * same refusal, so every ordinary teardown was reported as broken framing. */
    uint8_t end_frame[sizeof want_keep];
    memcpy(end_frame, want_keep, sizeof want_keep);
    end_frame[4] = 0x03u;
    ok(lc_xudp_next(end_frame, sizeof end_frame, from, sizeof from, &fport, &p, &plen, &used) == LC_XUDP_ENDED,
       "End is that status in the field, and it is an ending rather than a fault");

    /* KEEPALIVE IS EATEN, NOT DELIVERED. The reference reads the payload — it must, or the next
     * frame begins mid-frame — and then throws the buffer away instead of returning it:
     * `if !discard { return buf.MultiBuffer{b}, nil }`, with `discard` set by `case 4` alone
     * (vendor/Xray-core/common/xudp/xudp.go:181-204).
     *
     * Both halves are asserted, because each alone passes on a wrong reader: a reader that returns
     * the bytes gets `used` right, and a reader that refuses the frame outright gets `plen` right
     * by never answering at all. */
    uint8_t keepalive[sizeof want_keep];
    memcpy(keepalive, want_keep, sizeof want_keep);
    keepalive[4] = 0x04u; /* KeepAlive */
    p = (const uint8_t *)"unchanged";
    plen = 99u;
    ok(lc_xudp_next(keepalive, sizeof keepalive, from, sizeof from, &fport, &p, &plen, &used) == 1 &&
           p == NULL && plen == 0u,
       "a KeepAlive frame hands back no payload");
    ok(used == sizeof keepalive, "and still consumes it, so the next frame starts where it should");

    /* THE REST OF THE READER'S RULES, each the reference's to the letter
     * (vendor/Xray-core/common/xudp/xudp.go:164-204):
     *
     *   - the address is read only for Keep, and only when its network byte is 2 — `if l > 4 &&
     *     b.Byte(4) == 2` inside `case 2`. Any other network byte is not an error: the frame goes
     *     on with no address. This refused it;
     *   - so a KeepAlive's meta is never parsed at all, and a malformed address in one is thrown
     *     away with the frame. This parsed it and failed;
     *   - a payload follows only when the option byte IS 1 — `if b.Byte(3) == 1` — not when its low
     *     bit is set. This read a payload after any odd option, where the reference reads the next
     *     frame. */
    uint8_t other_net[sizeof want_keep];
    memcpy(other_net, want_keep, sizeof want_keep);
    other_net[6] = 0x01u;
    ok(lc_xudp_next(other_net, sizeof other_net, from, sizeof from, &fport, &p, &plen, &used) == 1 &&
           from[0] == '\0' && plen == 2u && memcmp(p, "hi", 2) == 0 && used == sizeof other_net,
       "a Keep whose network byte is not UDP carries its payload and no address");

    uint8_t bad_alive[sizeof want_keep];
    memcpy(bad_alive, want_keep, sizeof want_keep);
    bad_alive[4] = 0x04u; /* KeepAlive */
    bad_alive[9] = 0x09u; /* no such address type */
    ok(lc_xudp_next(bad_alive, sizeof bad_alive, from, sizeof from, &fport, &p, &plen, &used) == 1 &&
           p == NULL && used == sizeof bad_alive,
       "a KeepAlive's meta is not parsed, so a bad address in it is discarded with it");

    uint8_t odd_option[sizeof want_keep];
    memcpy(odd_option, want_keep, sizeof want_keep);
    odd_option[5] = 0x03u;
    p = (const uint8_t *)"unchanged";
    ok(lc_xudp_next(odd_option, sizeof odd_option, from, sizeof from, &fport, &p, &plen, &used) == 1 &&
           p == NULL && plen == 0u && used == 14u,
       "an option other than 1 means no payload, and the next frame starts after the meta");

    /* WHAT THE READER REFUSES, as PacketReader does: a meta block or a payload longer than one
     * buf.Size, refused before its bytes arrive, and a domain that is not letters, digits, '-', '.'
     * and '_' — while one that is an IP written as a domain becomes that IP
     * (vendor/Xray-core/common/xudp/xudp.go:159-196, vendor/Xray-core/common/protocol/address.go:
     * 204-221). */
    {
        static const uint8_t long_meta[2] = { 0x20, 0x01 };
        ok(lc_xudp_next(long_meta, sizeof long_meta, from, sizeof from, &fport, &p, &plen, &used) == -1,
           "a meta block of 8193 bytes is refused on its length alone");
        static const uint8_t long_data[8] = { 0x00, 0x04, 0x00, 0x00, 0x02, 0x01, 0x20, 0x01 };
        ok(lc_xudp_next(long_data, sizeof long_data, from, sizeof from, &fport, &p, &plen, &used) == -1,
           "and so is a payload of 8193");
        static const uint8_t bad_dom[] = { 0x00, 0x0c, 0x00, 0x00, 0x02, 0x01, 0x02, 0x00, 0x35,
                                           0x02, 0x03, 'a', '!', 'b', 0x00, 0x00 };
        ok(lc_xudp_next(bad_dom, sizeof bad_dom, from, sizeof from, &fport, &p, &plen, &used) == -1,
           "a domain with a character isValidDomain refuses is refused");
        static const uint8_t ip_dom[] = { 0x00, 0x10, 0x00, 0x00, 0x02, 0x01, 0x02, 0x00, 0x35, 0x02,
                                          0x07, '1',  '.',  '2',  '.',  '3',  '.',  '4',  0x00, 0x00 };
        ok(lc_xudp_next(ip_dom, sizeof ip_dom, from, sizeof from, &fport, &p, &plen, &used) == 1 &&
               strcmp(from, "1.2.3.4") == 0,
           "a domain that is an IP is read as that IP");
        static const uint8_t v6_dom[] = { 0x00, 0x0e, 0x00, 0x00, 0x02, 0x01, 0x02, 0x00, 0x35, 0x02,
                                          0x05, '[',  ':',  ':',  '1',  ']',  0x00, 0x00 };
        ok(lc_xudp_next(v6_dom, sizeof v6_dom, from, sizeof from, &fport, &p, &plen, &used) == 1 &&
               strcmp(from, "::1") == 0,
           "and a bracketed IPv6 one as that address");
    }

    printf("\n%s\n", failures == 0 ? "all good" : "THE XUDP FRAME IS WRONG");
    return failures == 0 ? 0 : 1;
}
