/* Hysteria2's proxy framing, and the integers underneath it.
 *
 * The cross-implementation check for this layer is not here: it is the node, which accepts our
 * request and connects, and whose own reply we parse — proved by lc-hyfetch against a live server.
 * Upstream's parser lives in an internal Go package that nothing outside its module may import, so
 * there is no offline equivalent of the nghttp3 check in test/h3.
 *
 * What is here is what that check cannot see: the boundaries. A varint that is one byte too long,
 * a length field that promises more than arrived, a message longer than the buffer meant to hold
 * it. Those are the cases a working connection never exercises and a hostile one always will. */

#include "quic/hy.h"
#include "quic/varint.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

static void test_varint(void)
{
    printf("\nQUIC variable-length integers\n");

    /* Each length and the value either side of where it changes. RFC 9000 section 16: one byte to
     * 63, two to 16383, four to 2^30-1, eight to 2^62-1. */
    const uint64_t values[] = { 0,          1,          63,          64,
                                16383,      16384,      1073741823,  1073741824,
                                LC_VARINT_MAX };
    const size_t   lengths[] = { 1, 1, 1, 2, 2, 4, 4, 8, 8 };

    int len_bad = -1, trip_bad = -1;
    for (unsigned i = 0; i < sizeof values / sizeof values[0]; i++) {
        uint8_t buf[8];
        size_t  n = lc_varint_put(buf, sizeof buf, values[i]);
        if (n != lengths[i]) {
            len_bad = (int)i;
            break;
        }
        size_t   off = 0;
        uint64_t back = 0;
        if (lc_varint_get(buf, n, &off, &back) != 0 || back != values[i] || off != n)
            trip_bad = (int)i;
    }
    ok(len_bad == -1, "every value takes the shortest encoding that fits it");
    ok(trip_bad == -1, "and reads back as itself");

    /* One byte short of what the first byte promises is not malformed — it is a message still
     * arriving, and the caller has to be able to tell those apart. */
    uint8_t two[2];
    lc_varint_put(two, sizeof two, 16383);
    size_t   off = 0;
    uint64_t v = 0;
    ok(lc_varint_get(two, 1, &off, &v) == -1 && off == 0,
       "a truncated integer is refused without consuming anything");

    ok(lc_varint_put(two, 1, 16383) == 0, "and is never written into a buffer too small for it");
    ok(lc_varint_len(LC_VARINT_MAX + 1u) == 0, "a value past 2^62 has no encoding at all");
}

/* Reads back a request the way the node does, so that what this test asserts is the wire format and
 * not our own writer's idea of it. */
static void test_request(void)
{
    printf("\nThe request that opens a proxied connection\n");

    uint8_t req[LC_HY_TCP_REQ_MAX];
    long    n = lc_hy_tcp_request("example.com:443", req, sizeof req);
    ok(n > 0, "it builds");
    if (n <= 0)
        return;

    size_t   off = 0;
    uint64_t type = 0, addr_len = 0, pad_len = 0;
    ok(lc_varint_get(req, (size_t)n, &off, &type) == 0 && type == 0x401u,
       "it opens with frame type 0x401");
    ok(lc_varint_get(req, (size_t)n, &off, &addr_len) == 0 && addr_len == 15u,
       "then the address length");
    ok(off + addr_len <= (size_t)n && memcmp(req + off, "example.com:443", 15) == 0,
       "then the address, as a name and a port and nothing else");
    off += addr_len;

    ok(lc_varint_get(req, (size_t)n, &off, &pad_len) == 0 && pad_len >= LC_PAD_TCP_REQ_MIN &&
           pad_len < LC_PAD_TCP_REQ_MAX,
       "then padding of the length hysteria's own client draws");
    ok(off + pad_len == (size_t)n, "and the frame ends exactly where the padding does");

    /* Two requests running to the same length would mean the padding is not doing its job. Ten
     * draws from a range of 448 collide with probability under a tenth of a percent. */
    int varies = 0;
    for (int i = 0; i < 10 && !varies; i++) {
        uint8_t again[LC_HY_TCP_REQ_MAX];
        long    m = lc_hy_tcp_request("example.com:443", again, sizeof again);
        varies = m > 0 && m != n;
    }
    ok(varies, "no two requests are reliably the same size");

    char too_long[LC_HY_ADDR_MAX + 8];
    memset(too_long, 'a', sizeof too_long - 1u);
    too_long[sizeof too_long - 1u] = '\0';
    ok(lc_hy_tcp_request(too_long, req, sizeof req) < 0,
       "an address past what the node will read is refused here rather than there");
    ok(lc_hy_tcp_request("", req, sizeof req) < 0, "and so is no address at all");
    ok(lc_hy_tcp_request("example.com:443", req, 8) < 0, "a buffer too small is refused");
}

/* Builds a reply the way a node does, so the parser is read against the format rather than against
 * the writer we would otherwise have written to feed it. */
static size_t build_reply(uint8_t *out, size_t cap, uint8_t status, const char *msg, size_t pad)
{
    size_t n = 0;
    out[n++] = status;
    n += lc_varint_put(out + n, cap - n, strlen(msg));
    memcpy(out + n, msg, strlen(msg));
    n += strlen(msg);
    n += lc_varint_put(out + n, cap - n, pad);
    memset(out + n, 'x', pad);
    return n + pad;
}

static void test_response(void)
{
    printf("\nThe node's answer to it\n");

    uint8_t         buf[2048];
    lc_hy_tcp_reply reply;

    size_t n = build_reply(buf, sizeof buf, 0, "", 300);
    long   got = lc_hy_tcp_response(buf, n, &reply);
    ok(got == (long)n && reply.ok, "a plain yes is read, padding and all");

    n = build_reply(buf, sizeof buf, 1, "dial tcp: connection refused", 128);
    got = lc_hy_tcp_response(buf, n, &reply);
    ok(got == (long)n && !reply.ok && strcmp(reply.message, "dial tcp: connection refused") == 0,
       "a no comes with the node's own explanation");

    /* Anything that is not zero is a refusal. Reading an unknown status as success would mean
     * relaying bytes into a connection the node never opened. */
    n = build_reply(buf, sizeof buf, 7, "", 0);
    ok(lc_hy_tcp_response(buf, n, &reply) == (long)n && !reply.ok,
       "a status nobody has defined is a refusal, not a maybe");

    /* Everything the reply is followed by belongs to the connection, and the caller is told exactly
     * where that starts. */
    n = build_reply(buf, sizeof buf, 0, "", 200);
    memcpy(buf + n, "HTTP/1.1 200 OK", 15);
    got = lc_hy_tcp_response(buf, n + 15u, &reply);
    ok(got == (long)n, "bytes arriving behind the reply are not swallowed with it");

    int impatient = 0;
    for (size_t cut = 0; cut < n; cut++)
        if (lc_hy_tcp_response(buf, cut, &reply) != 0) {
            impatient = (int)cut + 1;
            break;
        }
    ok(impatient == 0, "every prefix of a reply asks for more rather than failing");

    /* A length field is an invitation, and these are the two that can be made to say anything. */
    uint8_t hostile[16];
    size_t  h = 0;
    hostile[h++] = 0;
    h += lc_varint_put(hostile + h, sizeof hostile - h, LC_HY_MSG_MAX + 1u);
    ok(lc_hy_tcp_response(hostile, h, &reply) == -1,
       "a message longer than the protocol allows is refused, not waited for");

    h = 0;
    hostile[h++] = 0;
    h += lc_varint_put(hostile + h, sizeof hostile - h, 0);
    h += lc_varint_put(hostile + h, sizeof hostile - h, LC_HY_PADDING_MAX + 1u);
    ok(lc_hy_tcp_response(hostile, h, &reply) == -1, "and so is padding past the same line");

    /* The node chooses this length; the buffer that holds it is ours. */
    char shout[600];
    memset(shout, 'e', sizeof shout - 1u);
    shout[sizeof shout - 1u] = '\0';
    n = build_reply(buf, sizeof buf, 1, shout, 0);
    got = lc_hy_tcp_response(buf, n, &reply);
    ok(got == (long)n && !reply.ok && strlen(reply.message) == sizeof reply.message - 1u,
       "an explanation longer than we keep is truncated, and the frame still parses");
}

static void test_udp(void)
{
    printf("\nThe datagram a proxied UDP packet travels in\n");

    const uint8_t payload[] = "the quick brown fox";
    lc_hy_udp     msg = { .session = 0x01020304u, .packet = 0xbeefu, .frag = 2, .frag_count = 4,
                          .data = payload, .len = sizeof payload - 1u };
    snprintf(msg.addr, sizeof msg.addr, "%s", "8.8.8.8:53");

    uint8_t buf[256];
    long    n = lc_hy_udp_put(&msg, buf, sizeof buf);
    ok(n > 0, "it builds");
    if (n <= 0)
        return;

    ok((size_t)n == lc_hy_udp_header_len(msg.addr) + msg.len,
       "and is exactly as long as the header said it would be");

    /* The four fixed fields are big-endian and in this order; everything after them is the address
     * behind its length. Checked against the bytes rather than through our own reader, which would
     * agree with any consistent mistake. */
    ok(buf[0] == 0x01 && buf[1] == 0x02 && buf[2] == 0x03 && buf[3] == 0x04,
       "the session is four bytes, most significant first");
    ok(buf[4] == 0xbe && buf[5] == 0xef, "then the packet, two bytes the same way");
    ok(buf[6] == 2 && buf[7] == 4, "then which fragment this is, and how many there are");
    ok(buf[8] == 10 && memcmp(buf + 9, "8.8.8.8:53", 10) == 0, "then the address behind its length");

    lc_hy_udp back;
    ok(lc_hy_udp_parse(buf, (size_t)n, &back) == 0, "it reads back");
    ok(back.session == msg.session && back.packet == msg.packet && back.frag == msg.frag &&
           back.frag_count == msg.frag_count,
       "with every field as it went in");
    ok(strcmp(back.addr, msg.addr) == 0, "and the address as a string, not an address");
    ok(back.len == msg.len && memcmp(back.data, payload, back.len) == 0,
       "and the payload pointing into the datagram, not copied out of it");

    /* A packet whose fragments cannot be put together. Refused at the door: a reassembler that
     * accepted these would be one whose state a sender could steer from outside.
     *
     * A count of ZERO is not one of those, and this test used to say it was. Defragger.Feed opens
     * with `if m.FragCount <= 1 { return m }` (vendor/hysteria/core/internal/frag/frag.go:47-50):
     * zero and one mean the same thing to the reference, a message that is already whole. Refusing
     * it made this client deaf to a datagram its own node is free to send. */
    uint8_t bad[64];
    memcpy(bad, buf, (size_t)n < sizeof bad ? (size_t)n : sizeof bad);
    bad[7] = 0; /* no fragments at all — a whole message, as far as the reference is concerned */
    ok(lc_hy_udp_parse(bad, (size_t)n, &back) == 0,
       "a fragment count of zero parses, as a message already whole");
    bad[7] = 2;
    bad[6] = 5; /* fragment five of two */
    ok(lc_hy_udp_parse(bad, (size_t)n, &back) == -1, "a fragment numbered past the count is refused");

    ok(lc_hy_udp_parse(buf, 7u, &back) == -1, "a datagram shorter than the fixed fields is refused");
    ok(lc_hy_udp_parse(buf, 12u, &back) == -1,
       "and so is one whose address runs off the end of it");

    msg.addr[0] = '\0';
    ok(lc_hy_udp_put(&msg, buf, sizeof buf) == -1, "a packet with no destination is not written");
    snprintf(msg.addr, sizeof msg.addr, "%s", "8.8.8.8:53");
    ok(lc_hy_udp_put(&msg, buf, 8u) == -1, "and neither is one that would not fit");
}

int main(void)
{
    test_varint();
    test_request();
    test_response();
    test_udp();

    printf("\n%s\n",
           failures == 0 ? "the proxy framing holds" : "the proxy framing is WRONG");
    return failures == 0 ? 0 : 1;
}
