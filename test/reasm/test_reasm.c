/* Putting a proxied UDP packet back together, from pieces arriving the way a path actually
 * delivers them.
 *
 * WHY THIS FILE EXISTS. This logic sat in conn.c until 2026-09-02, and conn.c cannot be loaded by a
 * test without the whole vendored QUIC stack — so the one part of this client fed entirely by the
 * node, in whatever order and whatever number of copies, was the part nothing could ask anything.
 * The parser in front of it is checked (test/hy, including the fragment index guard this relies on);
 * what happens after it was not.
 *
 * WHAT MAKES IT WORTH CHECKING RATHER THAN READING. Every rule here has a plausible opposite, and
 * the code once held two of them:
 *
 *   - clearing the arrival bitmap once a packet is assembled reads as obviously correct, and turns a
 *     retransmission — ordinary on this client's path — into a second delivery of the same packet;
 *   - resetting on the packet id alone reads as sufficient, and lets a packet that reuses an id with
 *     a different piece count be indexed into a table sized for the old one;
 *   - reassembling in arrival order reads as harmless, because on a quiet link the pieces arrive in
 *     order and every test written by hand would pass.
 *
 * None of the three produces an error. They produce a wrong payload, or the right payload twice. */

#include "quic/reasm.h"

#include <stdio.h>
#include <string.h>

static int fails;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        fails++;
}

static uint8_t backing[LC_HY_UDP_MAX];
static uint8_t out[LC_HY_UDP_MAX];

static void fresh(lc_qreasm *r)
{
    memset(r, 0, sizeof *r);
    r->buf = backing;
}

/* One piece as the parser would have handed it over. `data` points at caller-owned bytes, which is
 * what lc_hy_udp_parse produces — it points into the datagram rather than copying. */
static lc_hy_udp piece(uint16_t packet, uint8_t frag, uint8_t count, const uint8_t *data, size_t len)
{
    lc_hy_udp m;
    memset(&m, 0, sizeof m);
    m.session = 1;
    m.packet = packet;
    m.frag = frag;
    m.frag_count = count;
    m.data = data;
    m.len = len;
    snprintf(m.addr, sizeof m.addr, "%s", "8.8.8.8:53");
    return m;
}

static void test_whole_packet(void)
{
    lc_qreasm r;
    fresh(&r);

    static const uint8_t body[] = { 1, 2, 3, 4, 5 };
    const uint8_t       *data = NULL;

    lc_hy_udp m = piece(7, 0, 1, body, sizeof body);
    long      n = lc_qreasm_feed(&r, &m, out, sizeof out, &data);
    ok(n == (long)sizeof body && data == body,
       "a packet that arrived whole is handed on without a copy");

    /* frag.go:47 is `if m.FragCount <= 1`, so zero and one mean the same thing. A node that emits a
     * zero count is legal to the reference and to its own client; refusing it made us deaf to one. */
    m = piece(8, 0, 0, body, sizeof body);
    n = lc_qreasm_feed(&r, &m, out, sizeof out, &data);
    ok(n == (long)sizeof body && data == body, "and so is one whose count is zero rather than one");
}

/* THE CASE THE ORDERING RULE EXISTS FOR. Two pieces, second first. Reassembled in arrival order the
 * answer is "BA"; in fragment order it is "AB", and only one of those is the packet that was sent. */
static void test_out_of_order(void)
{
    lc_qreasm r;
    fresh(&r);

    static const uint8_t a[] = { 'A', 'A', 'A' };
    static const uint8_t b[] = { 'B', 'B' };
    const uint8_t       *data = NULL;

    lc_hy_udp second = piece(3, 1, 2, b, sizeof b);
    ok(lc_qreasm_feed(&r, &second, out, sizeof out, &data) == 0,
       "the second piece of two is held rather than delivered");

    lc_hy_udp first = piece(3, 0, 2, a, sizeof a);
    long      n = lc_qreasm_feed(&r, &first, out, sizeof out, &data);
    ok(n == 5, "the first completes it");
    ok(n == 5 && memcmp(data, "AAABB", 5) == 0,
       "and the packet is joined in FRAGMENT order, not the order the pieces arrived");
}

/* ⚠️ THE RETRANSMISSION CASE. A duplicate must be dropped, and the state that makes that possible is
 * the state a finished packet leaves behind. */
static void test_duplicates(void)
{
    lc_qreasm r;
    fresh(&r);

    static const uint8_t a[] = { 'A' };
    static const uint8_t b[] = { 'B' };
    const uint8_t       *data = NULL;

    lc_hy_udp p0 = piece(9, 0, 2, a, sizeof a);
    lc_hy_udp p1 = piece(9, 1, 2, b, sizeof b);

    ok(lc_qreasm_feed(&r, &p0, out, sizeof out, &data) == 0, "one piece of two is held");
    ok(lc_qreasm_feed(&r, &p0, out, sizeof out, &data) == -1,
       "the same piece again is dropped rather than counted twice");
    ok(lc_qreasm_feed(&r, &p1, out, sizeof out, &data) == 2, "the other piece completes the packet");

    /* Both pieces again, as a retransmission delivers them. Nothing may come out a second time. */
    ok(lc_qreasm_feed(&r, &p0, out, sizeof out, &data) == -1,
       "a retransmitted piece after completion is dropped, not reassembled again");
    ok(lc_qreasm_feed(&r, &p1, out, sizeof out, &data) == -1, "and so is the other one");
}

/* ⚠️ THE RESET CONDITION HAS TWO HALVES, and only the first is obvious. */
static void test_reset(void)
{
    lc_qreasm r;
    fresh(&r);

    static const uint8_t a[] = { 'A' };
    static const uint8_t z[] = { 'Z' };
    const uint8_t       *data = NULL;

    lc_hy_udp p0 = piece(10, 0, 2, a, sizeof a);
    ok(lc_qreasm_feed(&r, &p0, out, sizeof out, &data) == 0, "a piece of packet 10 is held");

    /* A different packet id: what was held is abandoned, and the new one starts from nothing. */
    lc_hy_udp q0 = piece(11, 0, 2, z, sizeof z);
    lc_hy_udp q1 = piece(11, 1, 2, a, sizeof a);
    ok(lc_qreasm_feed(&r, &q0, out, sizeof out, &data) == 0, "a piece of packet 11 replaces it");
    long n = lc_qreasm_feed(&r, &q1, out, sizeof out, &data);
    ok(n == 2 && memcmp(data, "ZA", 2) == 0,
       "and packet 11 assembles from its own pieces, with nothing of 10 in it");

    /* The second half: the SAME id with a different count. Without this the new pieces would be
     * indexed into a table still sized and marked for the old shape. */
    fresh(&r);
    lc_hy_udp two = piece(12, 1, 2, a, sizeof a);
    ok(lc_qreasm_feed(&r, &two, out, sizeof out, &data) == 0, "piece 1 of 2 in packet 12 is held");
    lc_hy_udp three0 = piece(12, 0, 3, z, sizeof z);
    lc_hy_udp three1 = piece(12, 1, 3, z, sizeof z);
    lc_hy_udp three2 = piece(12, 2, 3, z, sizeof z);
    ok(lc_qreasm_feed(&r, &three0, out, sizeof out, &data) == 0,
       "the same id with a THREE-piece count starts over");
    ok(lc_qreasm_feed(&r, &three1, out, sizeof out, &data) == 0, "second of three held");
    n = lc_qreasm_feed(&r, &three2, out, sizeof out, &data);
    ok(n == 3 && memcmp(data, "ZZZ", 3) == 0,
       "and it assembles as three, with the stale piece of the two-piece shape gone");
}

static void test_refusals(void)
{
    lc_qreasm r;
    fresh(&r);

    static const uint8_t a[] = { 'A' };
    const uint8_t       *data = NULL;

    /* More pieces than this build will hold. Refused rather than indexed past the table. */
    lc_hy_udp many = piece(20, 0, LC_QUDP_FRAGS + 1u, a, sizeof a);
    ok(lc_qreasm_feed(&r, &many, out, sizeof out, &data) == -1,
       "a count past LC_QUDP_FRAGS is refused, not indexed past the table");

    lc_hy_udp edge = piece(21, 0, LC_QUDP_FRAGS, a, sizeof a);
    ok(lc_qreasm_feed(&r, &edge, out, sizeof out, &data) == 0,
       "and exactly LC_QUDP_FRAGS is accepted, so the bound is not off by one");

    /* A piece longer than a whole packet may be. */
    fresh(&r);
    static uint8_t big[LC_HY_UDP_MAX + 1];
    lc_hy_udp      huge = piece(22, 0, 2, big, sizeof big);
    ok(lc_qreasm_feed(&r, &huge, out, sizeof out, &data) == -1,
       "a piece larger than a whole packet is refused");

    /* Pieces that fit one at a time but not together: the total is what has to be bounded, and the
     * check is on the running sum rather than on each arrival. */
    fresh(&r);
    static uint8_t half[LC_HY_UDP_MAX - 1];
    lc_hy_udp      h0 = piece(23, 0, 2, half, sizeof half);
    lc_hy_udp      h1 = piece(23, 1, 2, half, sizeof half);
    ok(lc_qreasm_feed(&r, &h0, out, sizeof out, &data) == 0, "a piece just under the limit is held");
    ok(lc_qreasm_feed(&r, &h1, out, sizeof out, &data) == -1,
       "and a second one that would take the total past it is refused");

    /* The caller's own buffer is asked about too. A packet that assembles to more than it can hold
     * is refused rather than written past. */
    fresh(&r);
    static const uint8_t four[] = { 1, 2, 3, 4 };
    lc_hy_udp            s0 = piece(24, 0, 2, four, sizeof four);
    lc_hy_udp            s1 = piece(24, 1, 2, four, sizeof four);
    (void)lc_qreasm_feed(&r, &s0, out, sizeof out, &data);
    ok(lc_qreasm_feed(&r, &s1, out, 7u, &data) == -1,
       "an assembled packet too large for the caller's buffer is refused, not written past it");
}

int main(void)
{
    printf("a proxied UDP packet, put back together\n");

    test_whole_packet();
    test_out_of_order();
    test_duplicates();
    test_reset();
    test_refusals();

    printf("\n%s\n", fails == 0 ? "fragments are joined the way the reference joins them"
                                : "reassembly has DIVERGED");
    return fails == 0 ? 0 : 1;
}
