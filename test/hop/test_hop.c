/* Which port of the node's range the next dial goes to.
 *
 * ⚠️ THIS SUITE EXISTS BECAUSE CENTRALISING WITHOUT TESTING JUST CONCENTRATES THE RISK. The choice
 * was written twice inside conn.c — once for the first dial, once for each hop — in two shapes that
 * had already begun to drift. Pulling them into lc_hop_port is only an improvement if the one
 * function is pinned; otherwise it is the same danger with fewer eyes on it.
 *
 * ⚠️ AND THE RANDOMNESS IS SUPPLIED HERE, not linked. Two of the properties that matter cannot be
 * observed against a real source at all: that a draw below the rejection threshold is thrown away
 * and drawn again, and that a source which fails is reported rather than read as zero. Both are
 * invisible in the output — a modulus and a rejection agree on all but one draw in 2^32, and a
 * failed draw that leaves `r` at zero simply returns the bottom of the range, which is a legal
 * port. So this file defines lc_rnd itself and scripts what the source hands back; the recipe
 * deliberately does not link src/core/rnd.c. */

#include "quic/hop.c"
#include "core/portunion.c"

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

/* The scripted source. `queue` is handed out in order; past its end a generator takes over so the
 * bulk tests have something to run on. `fail_after` makes the source start refusing, which is the
 * case core/rnd.h says the caller must handle. */
static uint32_t queue[8];
static unsigned queued, taken;
static unsigned fail_after = 0xffffffffu;
static uint32_t state = 0x12345678u;

static void script(const uint32_t *v, unsigned n)
{
    if (n != 0)
        memcpy(queue, v, n * sizeof *v);
    queued = n;
    taken = 0;
    fail_after = 0xffffffffu;
}

int lc_rnd(uint8_t *out, size_t n)
{
    if (taken >= fail_after)
        return -1;
    uint32_t v;
    if (taken < queued) {
        v = queue[taken];
    } else {
        /* xorshift32 rather than an LCG: the low bits of an LCG are close to periodic, and this
         * function's answer is `r % span`, which reads exactly those bits. */
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        v = state;
    }
    taken++;
    if (n > sizeof v)
        return -1;
    memcpy(out, &v, n);
    return 0;
}

static void test_inside(void)
{
    printf("\nevery port is inside the range\n");

    script(NULL, 0);
    uint16_t lowest = 0xffffu, highest = 0;
    int outside = 0;
    for (int i = 0; i < 50000; i++) {
        uint16_t p = 0;
        if (lc_hop_port(20000, 30000, &p) != 0 || p < 20000 || p > 30000)
            outside = 1;
        if (p < lowest)
            lowest = p;
        if (p > highest)
            highest = p;
    }
    ok(!outside, "fifty thousand draws all land in [20000, 30000]");

    /* Not "both endpoints were hit" — that is a coin toss on the number of draws and would make
     * this suite fail on a good day. What is being asked is that the whole range is in play rather
     * than a corner of it, which a walk or a stuck draw would not manage. */
    ok(lowest < 20050 && highest > 29950, "and they reach within fifty of both ends");

    /* The width that used to be arithmetic rather than a range: hi - lo + 1 is 65535 here, and the
     * shape this replaced computed it in uint16_t, where the next value up wraps to zero. */
    script(NULL, 0);
    outside = 0;
    for (int i = 0; i < 20000; i++) {
        uint16_t p = 0;
        if (lc_hop_port(1, 65535, &p) != 0 || p < 1)
            outside = 1;
    }
    ok(!outside, "the widest legal range draws without wrapping");
}

static void test_single_port(void)
{
    printf("\na range of one\n");

    script(NULL, 0);
    int moved = 0;
    for (int i = 0; i < 100; i++) {
        uint16_t p = 0;
        if (lc_hop_port(20000, 20000, &p) != 0 || p != 20000)
            moved = 1;
    }
    ok(!moved, "20000-20000 always gives 20000");
    ok(taken == 100, "and still draws each time, as upstream does with a one-entry list");
}

static void test_rejection(void)
{
    printf("\nthe draw is uniform, not a modulus\n");

    /* span = 3 does not divide 2^32: 2^32 mod 3 is 1, so exactly one value — zero — has to be
     * thrown away, and a modulus would fold it into the bottom of the range instead.
     *
     * Feed that value first and a usable one second. Rejection answers from the SECOND draw;
     * `lo + r % span` answers from the first. The two disagree, which is the whole point. */
    uint16_t p = 0;
    script((const uint32_t[]){ 0u, 7u }, 2);
    ok(lc_hop_port(100, 102, &p) == 0 && p == 101,
       "a draw below the threshold is thrown away and the next one used");
    ok(taken == 2, "which costs exactly one extra draw");

    script((const uint32_t[]){ 7u }, 1);
    ok(lc_hop_port(100, 102, &p) == 0 && p == 101 && taken == 1,
       "a usable draw is used at once, with nothing spent on rejection");

    /* A span that divides 2^32 has nothing to reject, and must not spend a second draw looking. */
    script((const uint32_t[]){ 0u }, 1);
    ok(lc_hop_port(1000, 1255, &p) == 0 && p == 1000 && taken == 1,
       "a span that divides evenly rejects nothing, not even zero");
}

static void test_source_failure(void)
{
    printf("\na source that cannot deliver\n");

    /* Not a zero, and not the bottom of the range. Both sites this replaced dropped lc_rnd's result,
     * so a failing source picked `lo` every time — predictably, and without saying so. */
    uint16_t p = 0xbeefu;
    script(NULL, 0);
    fail_after = 0;
    ok(lc_hop_port(20000, 30000, &p) == -1, "a failed draw is reported, not absorbed");
    ok(p == 0xbeefu, "and nothing is written over the caller's port");

    /* Failing on the SECOND draw, after the first was rejected, must not loop and must not fall
     * through to the rejected value. */
    script((const uint32_t[]){ 0u }, 1);
    fail_after = 1;
    p = 0xbeefu;
    ok(lc_hop_port(100, 102, &p) == -1, "a source that fails mid-rejection is reported the same way");
    ok(p == 0xbeefu, "and still writes nothing");
}

/* Which sockets get DF. The reference's first socket of a hopping connection has it and every later
 * one does not; the whole connection has it when nothing hops. This set it on none when hopping
 * until 2026-09-25. */
static void test_df(void)
{
    ok(lc_hop_sets_df(0, 1) && lc_hop_sets_df(0, 0),
       "no hopping: every socket to the node gets DF, the first and any other");
    ok(lc_hop_sets_df(1, 1), "hopping: the FIRST socket gets DF, as setDF reaches it at setup");
    ok(!lc_hop_sets_df(1, 0), "hopping: a socket a hop opens does not — hop() does not carry DF");
}

/* THE PORT STRING, AS ParsePortUnion READS IT — every expectation below is what the reference's own
 * function printed for the same string (vendor/hysteria/extras/utils/portunion.go:21-86, run on
 * 2026-09-27): the ranges after normalizing, or nothing. */
static void test_union(void)
{
    static const struct {
        const char *s;
        const char *want; /* "lo-hi lo-hi ...", or NULL for the reference's nil */
    } v[] = {
        { "20000-50000", "20000-50000" }, { "50000-20000", "20000-50000" }, { "1,2,3", "1-3" },
        { "3,1,2", "1-3" },               { "10-20,15-30", "10-30" },       { "10-20,21-30", "10-30" },
        { "10-20,22-30", "10-20 22-30" }, { "443", "443-443" },             { "1-2-3", NULL },
        { "a-b", NULL },                  { "-5", NULL },                   { "5-", NULL },
        { "1,,2", NULL },                 { "", NULL },                     { "65535-0", "0-65535" },
        { "0080-0090", "80-90" },         { "70000", NULL },                { "all", "0-65535" },
        { "*", "0-65535" },               { "100-100", "100-100" },         { "1,1,1", "1-1" },
        { " 1", NULL },                   { "1 ", NULL },                   { "+1", NULL },
        { "30-40,1-5,6-10", "1-10 30-40" },
    };
    printf("\nthe port string, as ParsePortUnion reads it\n");
    unsigned bad = 0;
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        lc_hop_ports p;
        char         got[128] = "";
        int          rc = lc_hop_ports_parse(v[i].s, &p);
        if (rc == 0) {
            size_t at = 0;
            for (unsigned k = 0; k < p.n; k++)
                at += (size_t)snprintf(got + at, sizeof got - at, "%s%u-%u", k ? " " : "",
                                       (unsigned)p.lo[k], (unsigned)p.hi[k]);
            lc_hop_ports_free(&p);
        }
        int same = v[i].want == NULL ? rc != 0 : rc == 0 && strcmp(got, v[i].want) == 0;
        if (!same) {
            printf("        \"%s\": got %s, want %s\n", v[i].s, rc == 0 ? got : "nil",
                   v[i].want != NULL ? v[i].want : "nil");
            bad++;
        }
    }
    ok(bad == 0, "twenty-five strings, each read as the reference reads it");

    /* The draw is an index into the expanded list: twenty ports, 10-20 then 22-30, so index 11 is
     * 22 — and a value under 2^32 mod 20 is drawn again, as rand.Intn rejects it. */
    lc_hop_ports p;
    uint16_t     port = 0;
    int          parsed = lc_hop_ports_parse("10-20,22-30", &p) == 0;
    static const uint32_t draws[2] = { 11u, 111u };
    script(draws, 2);
    ok(parsed && p.total == 20u && lc_hop_ports_pick(&p, &port) == 0 && port == 22u,
       "a port is an index into all of them, the rejected draw drawn again");
    if (parsed)
        lc_hop_ports_free(&p);
}

int main(void)
{
    printf("the port a hop dials\n");

    test_inside();
    test_single_port();
    test_rejection();
    test_source_failure();
    test_df();
    test_union();

    printf("\n%s\n", failures == 0 ? "the hop port is chosen as upstream chooses it"
                                   : "the hop port's choice has CHANGED");
    return failures == 0 ? 0 : 1;
}
