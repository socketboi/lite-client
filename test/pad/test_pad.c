/* The padding's distribution, which a change of plumbing was not allowed to touch.
 *
 * Every character of Hysteria2 padding used to cost a getrandom(2) call — up to five hundred and
 * twelve of them for one TCPRequest, on kernels where that syscall has no vDSO entry and every one
 * of them traps. The draws now come from a pool that a single call fills. What that change had to
 * leave exactly as it was is what comes out: the padding travels on the wire, its alphabet decides
 * how it Huffman-codes as a header value and so decides the size of the message, and a client whose
 * padding is distributed differently from every other Hysteria client's can be picked out of a
 * stream by something that does no more than count bytes.
 *
 * Nothing else would catch getting this wrong. The padding is random, so wrong padding looks
 * exactly as plausible as right padding; a node accepts either, every transfer succeeds, and the
 * only party who can tell is the one watching the link.
 *
 * So what is pinned here is the arithmetic between the kernel and the wire: four bytes a character,
 * assembled big-endian, taken in the order the kernel produced them, with none skipped at a pool
 * boundary and none served twice.
 *
 * White box on purpose. The pool and the reduction are internal to pad.c and the property is about
 * them, not about the two functions the header exposes — driving this from outside could only
 * observe that the output is plausible, which it would be either way. test/hsframe includes
 * client.c for the same reason. */

#include "quic/pad.c"

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

/* memchr rather than strchr: a zero byte has to come back foreign, not found at the terminator. */
static int in_alphabet(char c)
{
    return memchr(pad_chars, c, sizeof pad_chars - 1u) != NULL;
}

static void test_alphabet(void)
{
    printf("\nthe alphabet\n");

    /* Written out again rather than referred to. "Every byte comes from pad_chars" holds just as
     * well after pad_chars itself has been edited, and the set of characters is precisely what a
     * header compressor sees. It is upstream's, from core/internal/protocol/padding.go. */
    static const char upstream[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    ok(sizeof pad_chars - 1u == 62u, "the alphabet holds sixty-two characters");
    ok(sizeof pad_chars == sizeof upstream && memcmp(pad_chars, upstream, sizeof upstream) == 0,
       "and they are upstream's, unchanged");
}

static void test_pool_order(void)
{
    printf("\nfour bytes a character, in the order they arrived\n");

    /* The pool is loaded by hand so that the draws have a known answer. Served in any other order —
     * a word at a time little-endian, four bytes lost at a refill, the tail of the pool discarded
     * because it looked too short — the padding is still the right length and still drawn from the
     * right alphabet, and it is no longer the padding upstream's client would have sent. */
    for (size_t i = 0; i < sizeof pool; i++)
        pool[i] = (uint8_t)(i * 37u + 11u);
    pool_next = 0;

    int bad = -1;
    for (unsigned d = 0; d < sizeof pool / 4u; d++) {
        uint8_t want[4];
        for (unsigned j = 0; j < 4u; j++)
            want[j] = (uint8_t)((d * 4u + j) * 37u + 11u);

        uint32_t got = 0;
        if (draw32(&got) != 0 ||
            got != ((uint32_t)want[0] << 24 | (uint32_t)want[1] << 16 | (uint32_t)want[2] << 8 |
                    want[3])) {
            bad = (int)d;
            break;
        }
    }
    ok(bad == -1, "every draw is the next four bytes of the pool, assembled big-endian");
    ok(pool_next == sizeof pool, "and sixty-four of them leave it exactly empty, with none wasted");

    uint32_t v = 0;
    ok(draw32(&v) == 0 && pool_next == 4u, "the draw after that refills and starts at the front");

    /* The one boundary the module has, from the side that is easy to get wrong: four bytes left is
     * enough for a draw. A check that refilled here instead would throw away the last four bytes of
     * every pool, which costs nothing anyone would notice and changes the stream. */
    const uint8_t *tail = pool + sizeof pool - 4u;
    uint8_t        last[4] = { tail[0], tail[1], tail[2], tail[3] };
    pool_next = sizeof pool - 4u;
    v = 0;
    ok(draw32(&v) == 0 &&
           v == ((uint32_t)last[0] << 24 | (uint32_t)last[1] << 16 | (uint32_t)last[2] << 8 |
                 last[3]),
       "and the last four bytes of a pool are served, not dropped at the boundary");
}

static void test_length(void)
{
    printf("\nexactly the length that was asked for\n");

    /* Zero and one, the values either side of the pool's own period of sixty-four characters, and
     * the largest run each caller can ask for: h3.c draws below LC_PAD_AUTH_MAX for the auth
     * request and hy.c below LC_PAD_TCP_REQ_MAX for every TCPRequest. The first of those spans
     * thirty-one refills, which is where a boundary check that is off by one shows up; a test of
     * short lengths alone would never reach a refill at all. */
    static const size_t lens[] = { 0u,   1u,   2u,   3u,   4u,   5u,   63u,  64u,  65u,  66u,
                                   127u, 128u, 255u, 256u, 257u, 258u,
                                   LC_PAD_TCP_REQ_MIN, LC_PAD_TCP_REQ_MAX - 1u,
                                   LC_PAD_AUTH_MIN,    LC_PAD_AUTH_MAX - 1u };
    static char         buf[LC_PAD_AUTH_MAX + 8u];

    int refused = -1, spilled = -1, foreign = -1;
    for (unsigned i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        size_t len = lens[i];
        memset(buf, '\1', sizeof buf);
        if (lc_pad_fill(buf, len) != 0) {
            refused = (int)i;
            break;
        }
        /* '\1' is not a character the alphabet contains, so it answers both halves of "exactly":
         * still there past the end means nothing was written too far, and gone from everywhere
         * inside means nothing stopped short — that second half is what the alphabet check below
         * is really proving. */
        if (buf[len] != '\1' || buf[len + 1u] != '\1')
            spilled = (int)i;
        for (size_t j = 0; j < len; j++) {
            if (!in_alphabet(buf[j])) {
                foreign = (int)i;
                break;
            }
        }
        if (spilled != -1 || foreign != -1)
            break;
    }
    ok(refused == -1, "every length a caller can produce is filled");
    ok(spilled == -1, "nothing is written past the length that was asked for");
    ok(foreign == -1, "and every byte inside it is from the alphabet, so nothing stopped short");

    /* The refill placed at each of the sixty-five positions it can occupy within one fill, rather
     * than wherever the previous test happened to leave it. Rewinding the cursor is not something
     * the module does — it re-serves bytes already handed out — but it is the only way to choose
     * where the boundary falls, and what is under test here is the length, not the bytes. */
    int phase_bad = -1;
    for (unsigned k = 0; k <= sizeof pool / 4u && phase_bad == -1; k++) {
        memset(buf, '\1', sizeof buf);
        pool_next = sizeof pool - 4u * (size_t)k;
        if (lc_pad_fill(buf, 200u) != 0 || buf[200] != '\1')
            phase_bad = (int)k;
        for (size_t j = 0; j < 200u && phase_bad == -1; j++) {
            if (!in_alphabet(buf[j]))
                phase_bad = (int)k;
        }
    }
    ok(phase_bad == -1, "and a refill falling at any character of a fill costs that fill none");
}

static void test_run(void)
{
    printf("\na long run of it\n");

    /* From a genuine refill: the sweep above left the cursor pointing at bytes it had already
     * served, and this section is about the bytes. */
    pool_next = sizeof pool;

    static char run[4096];
    int         filled = lc_pad_fill(run, sizeof run) == 0;

    unsigned seen[sizeof pad_chars - 1u] = { 0 };
    unsigned distinct = 0, repeats = 0;
    for (size_t i = 0; i < sizeof run; i++) {
        const char *p = memchr(pad_chars, run[i], sizeof pad_chars - 1u);
        if (p == NULL)
            continue;
        size_t idx = (size_t)(p - pad_chars);
        if (seen[idx]++ == 0u)
            distinct++;
        if (i > 0u && run[i] == run[i - 1u])
            repeats++;
    }

    char msg[96];
    ok(filled, "four kilobytes of padding, sixteen pools' worth");

    snprintf(msg, sizeof msg, "all %u of the %zu characters appear in it", distinct,
             sizeof pad_chars - 1u);
    ok(distinct == sizeof pad_chars - 1u, msg);

    /* A pool that never advanced, or one whose refill handed back the bytes it already had, still
     * produces padding of the right length out of the right alphabet — out of a handful of its
     * characters, over and over. Sixty-two symbols put the expected number of equal neighbours near
     * sixty-six; the failure this is guarding against puts it near four thousand. */
    snprintf(msg, sizeof msg, "%u equal neighbours in %zu characters", repeats, sizeof run);
    ok(repeats < sizeof run / 16u, msg);

    /* The first sixty-four characters are one pool exactly; the next sixty-four are the pool that
     * replaced it. */
    ok(memcmp(run, run + 64, 64u) != 0, "the pool after a refill is not the pool before it");

    char first[64], second[64];
    ok(lc_pad_fill(first, sizeof first) == 0 && lc_pad_fill(second, sizeof second) == 0 &&
           memcmp(first, second, sizeof first) != 0,
       "and two fills of one length are two different paddings");
}

static void test_bound(void)
{
    printf("\nthe bound\n");

    /* Where the remainder is taken. A value equal to the bound is an index one past the alphabet,
     * which for lc_pad_fill lands on the terminator: a zero byte in the middle of the padding, on
     * the wire, from a client that has otherwise done everything right. The bounds tested are the
     * ones the module is called with — the spans of the three ranges in pad.h, the alphabet, the
     * nine hundred src/h2/xhttp draws with — and the small values where an off-by-one has room to
     * show. */
    static const uint32_t bounds[] = { 1u,   2u,   3u,   62u,  63u,  64u,  255u, 256u, 257u, 900u,
                                       LC_PAD_TCP_REQ_MAX - LC_PAD_TCP_REQ_MIN,
                                       LC_PAD_TCP_RESP_MAX - LC_PAD_TCP_RESP_MIN,
                                       LC_PAD_AUTH_MAX - LC_PAD_AUTH_MIN,
                                       UINT32_MAX };
    const unsigned        per = 2000u;

    int refused = -1, over = -1;
    for (unsigned i = 0; i < sizeof bounds / sizeof bounds[0] && refused == -1 && over == -1; i++) {
        for (unsigned d = 0; d < per; d++) {
            uint32_t v = 0;
            if (below(bounds[i], &v) != 0) {
                refused = (int)i;
                break;
            }
            if (v >= bounds[i]) {
                over = (int)i;
                break;
            }
        }
    }

    char msg[96];
    snprintf(msg, sizeof msg, "%zu draws across %zu bounds, every one served",
             (size_t)per * (sizeof bounds / sizeof bounds[0]), sizeof bounds / sizeof bounds[0]);
    ok(refused == -1, msg);
    ok(over == -1, "and not one of them reaches its bound");

    int nonzero = 0;
    for (unsigned d = 0; d < 256u; d++) {
        uint32_t v = 1;
        if (below(1u, &v) != 0 || v != 0u)
            nonzero = 1;
    }
    ok(!nonzero, "a bound of one leaves nothing to choose and gives zero");

    /* An empty range must be turned away before it reaches the reduction, where the bound would be
     * zero and the remainder a division by it. */
    uint32_t drawn = 0;
    ok(lc_pad_draw(100u, 100u, &drawn) == -1 && lc_pad_draw(100u, 50u, &drawn) == -1,
       "and a range with nothing in it is refused before any bound is computed");
}

static void test_caller_ranges(void)
{
    printf("\nthe lengths the callers draw\n");

    static const uint32_t lo[] = { LC_PAD_AUTH_MIN, LC_PAD_TCP_REQ_MIN, LC_PAD_TCP_RESP_MIN };
    static const uint32_t hi[] = { LC_PAD_AUTH_MAX, LC_PAD_TCP_REQ_MAX, LC_PAD_TCP_RESP_MAX };

    int outside = -1, narrow = -1;
    for (unsigned i = 0; i < sizeof lo / sizeof lo[0] && outside == -1 && narrow == -1; i++) {
        uint32_t lowest = UINT32_MAX, highest = 0;
        for (unsigned d = 0; d < 4000u; d++) {
            uint32_t v = 0;
            if (lc_pad_draw(lo[i], hi[i], &v) != 0 || v < lo[i] || v >= hi[i]) {
                outside = (int)i;
                break;
            }
            if (v < lowest)
                lowest = v;
            if (v > highest)
                highest = v;
        }
        /* Half-open, so the minimum is reachable and the maximum is not. Four thousand draws over
         * ranges this wide land within a handful of both ends; a sixteenth of the range as slack
         * either side cannot fail by luck, and still catches a range that has collapsed into a
         * corner of itself. */
        uint32_t slack = (hi[i] - lo[i]) / 16u;
        if (outside == -1 && (lowest > lo[i] + slack || highest < hi[i] - 1u - slack))
            narrow = (int)i;
    }
    ok(outside == -1, "every drawn length is inside its half-open range");
    ok(narrow == -1, "and the draws reach both ends of it");
}

int main(void)
{
    printf("the padding Hysteria2 puts on its messages\n");

    test_alphabet();
    test_pool_order();
    test_length();
    test_run();
    test_bound();
    test_caller_ranges();

    printf("\n%s\n", failures == 0 ? "the padding is drawn as it always was"
                                   : "the padding's distribution has CHANGED");
    return failures == 0 ? 0 : 1;
}
