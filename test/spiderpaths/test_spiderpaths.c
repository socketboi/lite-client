/* What the spider asks for after it has read a page.
 *
 * The reference's map of paths is package-level, so the path of the SECOND and later connections to
 * a node that answers as a stranger is drawn from the hrefs of the page the FIRST one fetched
 * (vendor/Xray-core/transport/internet/reality/reality.go:220-231, :269-275, :312-322). The stand
 * tools/vendorcap/spiderlife measured that against a real Xray: `/`, `/two`, `/two`, `/three`, `/`
 * where this client asked for `/` five times. These are the checks that keep it closed.
 *
 * What is asserted is what the harvest DECIDES, drawn through the public interface rather than by
 * reaching into the set: two hundred draws over a small set land on every member, so "this path is
 * in it" and "that one is not" are both checkable without a window into the store. The store is
 * per ServerName and resets when the name changes, which is why every case here uses a name of its
 * own. */

#include "reality/paths.h"
#include "reality/spider.h"
#include "reality/browser.h"
#include "quic/huffman.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>


/* A byte string inside another: what memmem would do, without asking for _GNU_SOURCE. */
static int contains(const uint8_t *hay, size_t n, const uint8_t *needle, size_t m)
{
    if (m == 0u || m > n)
        return 0;
    for (size_t i = 0; i + m <= n; i++)
        if (memcmp(hay + i, needle, m) == 0)
            return 1;
    return 0;
}

static int failures;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

/* A drawn path into the test's own buffer: every path it harvests is short. */
#define TEST_PATH 4096

static int draw_into(const char *host, char p[TEST_PATH])
{
    char  *d = NULL;
    size_t n = 0;
    if (lc_spider_path(host, &d, &n) != 0)
        return -1;
    snprintf(p, TEST_PATH, "%s", d);
    free(d);
    return 0;
}

/* Two hundred draws, and what came back. Returns how many distinct paths were seen and fills `seen`
 * with them; a set of three is found with certainty long before the draws run out. */
static int drawn_set(const char *host, char seen[8][TEST_PATH], int cap)
{
    int n = 0;
    for (int i = 0; i < 200; i++) {
        char p[TEST_PATH];
        if (draw_into(host, p) != 0)
            return -1;
        int known = 0;
        for (int j = 0; j < n; j++)
            if (strcmp(seen[j], p) == 0)
                known = 1;
        if (!known && n < cap)
            snprintf(seen[n++], TEST_PATH, "%s", p);
    }
    return n;
}

static int has(char seen[8][TEST_PATH], int n, const char *want)
{
    for (int i = 0; i < n; i++)
        if (strcmp(seen[i], want) == 0)
            return 1;
    return 0;
}

static void feed_page(const char *host, const char *page)
{
    lc_spider_sink *sink = lc_spider_sink_new(host);
    lc_spider_sink_data(sink, (const uint8_t *)page, strlen(page));
    lc_spider_sink_commit(sink); /* the page was read to its end */
    lc_spider_sink_free(sink);
}

int main(void)
{
    printf("spider paths: what the next request asks for\n");

    /* SpiderX, and nothing else, until a page has been read. */
    char seen[8][TEST_PATH];
    int  n = drawn_set("fresh.example", seen, 8);
    ok(n == 1 && strcmp(seen[0], "/") == 0, "a name nothing was read for draws SpiderX and only it");

    /* The four rules of `href="([/h].*?)"` with the trim and the dot, in one page. */
    feed_page("one.example",
              "<a href=\"/shop\">x</a>"
              "<a href=\"https://one.example/deep/page\">y</a>" /* the prefix is trimmed off */
              "<a href=\"https://other.example/z\">z</a>"       /* a dot survives the trim: dropped */
              "<a href=\"/logo.png\">p</a>"                     /* a dot of its own: dropped */
              "<a href=\"#anchor\">a</a>"                       /* neither / nor h: no match */
              "<a href=\"?q=1\">q</a>");
    n = drawn_set("one.example", seen, 8);
    ok(n == 3, "a page with six links leaves two of them beside SpiderX");
    ok(has(seen, n, "/"), "SpiderX is still in the set");
    ok(has(seen, n, "/shop"), "a link within the site is kept");
    ok(has(seen, n, "/deep/page"), "an absolute link to the same name is kept with the prefix trimmed");
    ok(!has(seen, n, "/logo.png"), "a link with a dot in it is dropped");
    ok(!has(seen, n, "/z"), "a link to another host is dropped, because the dot survives the trim");

    /* Go's `.` does not match a newline, so a quote that never arrives on that line is no match. */
    feed_page("two.example", "<a href=\"/kept\">x</a>\n<a href=\"/lost\n\">y</a>");
    n = drawn_set("two.example", seen, 8);
    ok(has(seen, n, "/kept") && !has(seen, n, "/lost"),
       "an href whose quote is not on the same line is not a match");

    /* A page arrives as a dozen frames and a link lands on the seam of two of them. */
    {
        const char *page = "<a href=\"/split/across\">x</a>";
        size_t      cut = 12; /* inside the href, after the tag */
        lc_spider_sink *sink = lc_spider_sink_new("three.example");
        lc_spider_sink_data(sink, (const uint8_t *)page, cut);
        lc_spider_sink_data(sink, (const uint8_t *)page + cut, strlen(page) - cut);
        lc_spider_sink_commit(sink);
        lc_spider_sink_free(sink);
        n = drawn_set("three.example", seen, 8);
        ok(has(seen, n, "/split/across"), "a link split across two frames is still harvested");
    }

    /* A tag that does not make a match is not where the search jumps past: Go's FindAll tries the
     * next byte, and a second tag can begin inside the first one's would-be value. */
    feed_page("four.example", "<a href=\"Xhref=\"/inner\">t</a>");
    n = drawn_set("four.example", seen, 8);
    ok(has(seen, n, "/inner"), "a match that starts inside a failed one is found, as Go finds it");

    /* Harvested only once the page is read to its end, as the reference harvests only after
     * io.ReadAll returns without an error: a page the site cut short gives nothing — even the links
     * it had already passed. What the reading is — a gzip body through Go's reader included — is
     * the fetch's (test/fetch); the sink is handed the text. */
    {
        lc_spider_sink *sink = lc_spider_sink_new("five.example");
        lc_spider_sink_data(sink, (const uint8_t *)"<a href=\"/cut\">", 15u);
        lc_spider_sink_free(sink);
        n = drawn_set("five.example", seen, 8);
        ok(!has(seen, n, "/cut"), "a page never read to its end harvests nothing");
    }

    /* How OFTEN each path is asked for, which is where the reference's draw is easy to get wrong
     * twice over (reality.go:312-322): stopAt is RandBetween(0, len-1) with the upper bound
     * EXCLUDED (vendor/Xray-core/common/crypto/crypto.go:12-21), and it indexes a Go map WALK, whose
     * start is one of eight slots however few keys there are. Worked out from those two:
     *
     *   {"/", "/a"}        stopAt is always 0 and the walk starts with "/" 7/8 of the time;
     *   {"/", "/a", "/b"}  7/16, 7/16, 1/8 — the last one in is last in the walk 6/8 of the time.
     *
     * A uniform index over the insertion order gives 1/2 and 1/3 each; an inclusive bound over the
     * walk gives the same. Eight thousand draws put six standard errors at about 0.02, and the
     * nearest wrong answer is 0.2 away. */
    {
        feed_page("seven.example", "<a href=\"/a\">x</a>");
        int slash = 0, failed = 0;
        for (int i = 0; i < 8000; i++) {
            char p[TEST_PATH];
            if (draw_into("seven.example", p) != 0) {
                failed = 1;
                break;
            }
            slash += strcmp(p, "/") == 0;
        }
        ok(!failed && slash > 8000 * 7 / 8 - 180 && slash < 8000 * 7 / 8 + 180,
           "with SpiderX and one harvested path, SpiderX is asked for 7/8 of the time");

        feed_page("eight.example", "<a href=\"/a\">x</a><a href=\"/b\">y</a>");
        int last = 0;
        for (int i = 0; i < 8000 && !failed; i++) {
            char p[TEST_PATH];
            if (draw_into("eight.example", p) != 0)
                failed = 1;
            else
                last += strcmp(p, "/b") == 0;
        }
        ok(!failed && last > 8000 / 8 - 180 && last < 8000 / 8 + 180,
           "with three paths, the one harvested last is asked for 1/8 of the time");

        /* A link seen again is the same key: `paths[string(m[1])] = struct{}{}` sets what is
         * there. Harvested three times over, "/a" still makes {"/", "/a"}, and "/" is asked for
         * 7/8 of the time — a set that grew a key per sighting would ask for it less. */
        feed_page("again.example", "<a href=\"/a\">x</a><a href=\"/a\">x</a>");
        feed_page("again.example", "<a href=\"/a\">x</a>");
        slash = 0;
        for (int i = 0; i < 8000 && !failed; i++) {
            char p[TEST_PATH];
            if (draw_into("again.example", p) != 0)
                failed = 1;
            else
                slash += strcmp(p, "/") == 0;
        }
        ok(!failed && slash > 8000 * 7 / 8 - 180 && slash < 8000 * 7 / 8 + 180,
           "a link harvested again is the key it was: SpiderX still 7/8 of the time");

        /* And `.` does not cross a newline: an href whose quote closes on the next line is no
         * match, and the set stays SpiderX alone. */
        feed_page("line.example", "<a href=\"/x\ny\">x</a>");
        int other = 0;
        for (int i = 0; i < 200 && !failed; i++) {
            char p[TEST_PATH];
            if (draw_into("line.example", p) != 0)
                failed = 1;
            else
                other += strcmp(p, "/") != 0;
        }
        ok(!failed && other == 0, "an href broken by a newline is not a link");
    }

    /* ONE map for the life of the set, as the reference keeps one per ServerName
     * (reality.go:308-310, :224-230) — not a fresh one per draw. Past eight paths the difference is
     * visible: where each key sits comes from its hash under the map's seed, the key a walk reaches
     * last is the one before the widest run of empty slots, and so each map asks for its paths at a
     * fixed set of rates of its own. A fresh map per draw asks at one set of rates for every set,
     * since it averages over the layouts. So three sets of the same paths in the same order must not
     * agree with each other.
     *
     * Sixteen paths, because at sixteen the table is thirty-two slots with sixteen of them empty and
     * the layouts vary widely; at thirteen (sixteen slots, three empty) the end of each group is
     * nearly always the key inserted last into it, and three maps agree often enough to fail one run
     * in fifteen. Compared pairwise, key by key, as |a - b| / sqrt(a + b) on the counts, the worst of
     * the 48 comparisons measured on Go's own maps (reality.go's getPathLocked and crypto.go's
     * RandBetween copied verbatim, 200000 draws per set, twenty trials): 12.1 to 26.3 for one map per
     * set, 1.7 to 3.8 for a fresh map per draw. */
    {
        static const char *const names[3] = { "ten.example", "eleven.example", "twelve.example" };
        static long              freq[3][16];
        char                     page[512];
        size_t                   at = 0;
        for (int k = 1; k < 16; k++)
            at += (size_t)snprintf(page + at, sizeof page - at, "<a href=\"/p%d\">x</a>", k);
        int failed = 0;
        for (int s = 0; s < 3 && !failed; s++) {
            feed_page(names[s], page);
            for (int d = 0; d < 200000; d++) {
                char p[TEST_PATH];
                if (draw_into(names[s], p) != 0) {
                    failed = 1;
                    break;
                }
                freq[s][strcmp(p, "/") == 0 ? 0 : atoi(p + 2)]++;
            }
        }
        double worst = 0.0;
        for (int a = 0; a < 3; a++)
            for (int b = a + 1; b < 3; b++)
                for (int k = 0; k < 16; k++) {
                    double sum = (double)(freq[a][k] + freq[b][k]);
                    double z = sum > 0.0 ? fabs((double)(freq[a][k] - freq[b][k])) / sqrt(sum) : 0.0;
                    if (z > worst)
                        worst = z;
                }
        ok(!failed && worst > 6.0, "three sets of the same sixteen paths are drawn at rates of their own");
    }

    /* The empty path is a key: `href="https://nine.example"` trims to nothing, has no dot, and the
     * reference keeps it (reality.go:269-274). It is asked for as `/` — which is why the set being one
     * larger is the only trace it leaves, and why it is checked here at the draw. */
    feed_page("nine.example", "<a href=\"https://nine.example\">home</a>");
    n = drawn_set("nine.example", seen, 8);
    ok(n == 2 && has(seen, n, "/") && has(seen, n, ""), "a link to the bare name is kept as the empty path");

    /* And what the request then carries. A drawn path goes into `:path`, so a request built after
     * that page must sometimes carry the harvested one and sometimes SpiderX — which is the whole
     * difference this closes. The value is looked for in its HPACK form: the encoder writes a
     * literal in Huffman when that is shorter, and for a path it always is. */
    {
        lc_browser b;
        ok(lc_browser_chrome(&b, 20800LL * 86400, 0, LC_BROWSER_NAV) == 0, "the browser identity builds");

        feed_page("five.example", "<a href=\"/only\">x</a>");

        uint8_t coded[32];
        long    coded_len = lc_huff_encode("/only", 5u, coded, sizeof coded);
        ok(coded_len > 0, "and the test can write that path the way HPACK does");

        uint8_t out[8192u];
        int     saw_only = 0, saw_other = 0, failed = 0;
        for (int i = 0; i < 300; i++) {
            size_t opening = 0;
            long   len = lc_spider_request("five.example", &b, out, sizeof out, &opening);
            if (len <= 0) {
                failed = 1;
                break;
            }
            if (coded_len > 0 && contains(out, (size_t)len, coded, (size_t)coded_len))
                saw_only = 1;
            else
                saw_other = 1;
        }
        ok(!failed, "three hundred requests build");
        ok(saw_only, "a harvested path does reach the request");
        ok(saw_other, "and SpiderX still does too");
    }

    /* And what a request is when the drawn path makes none. `href="/100%"` does not parse, so the
     * reference's NewRequest fails and nothing is written at all; `href="h<x"` parses, runs into
     * the server name and gives a host x/net refuses after dialling, so the connection's opening
     * goes out alone. Either is drawn one time in eight beside SpiderX, so four hundred requests
     * see both outcomes with near certainty — and SpiderX's full request between them. */
    {
        lc_browser b;
        ok(lc_browser_chrome(&b, 20800LL * 86400, 0, LC_BROWSER_NAV) == 0, "the browser identity builds");
        static const char *const cases[2][2] = { { "fifteen.example", "<a href=\"/100%\">x</a>" },
                                                 { "sixteen.example", "<a href=\"h<x\">x</a>" } };
        int nothing = 0, opening_only = 0, full = 0, failed = 0;
        for (int c = 0; c < 2; c++) {
            feed_page(cases[c][0], cases[c][1]);
            for (int i = 0; i < 400 && !failed; i++) {
                uint8_t out[8192u];
                size_t  opening = 99;
                long    len = lc_spider_request(cases[c][0], &b, out, sizeof out, &opening);
                if (len < 0)
                    failed = 1;
                else if (len == 0)
                    nothing += c == 0 && opening == 0u;
                else if ((size_t)len == opening)
                    opening_only += c == 1 && memcmp(out, "PRI * HTTP/2.0", 14) == 0;
                else
                    full++;
            }
        }
        ok(!failed && nothing > 0, "a path that does not parse makes no request and writes nothing");
        ok(!failed && opening_only > 0, "a host x/net refuses gets the connection's opening and no request");
        ok(!failed && full > 0, "and SpiderX beside them still gets its whole request");
    }

    /* AS MANY AS THE PAGES CARRY, AS LONG AS THEY ARE, WHATEVER THEY HOLD — the reference's map has
     * no ceiling of any kind (reality.go:269-274), and neither has this set now. */
    {
        /* Two hundred links: every one of them drawable, where sixty-four were kept. */
        static char page[20000];
        size_t      at = 0;
        for (int k = 0; k < 200; k++)
            at += (size_t)snprintf(page + at, sizeof page - at, "<a href=\"/many/%d\">x</a>", k);
        feed_page("many.example", page);
        int  distinct = 0, failed = 0;
        static char got[200];
        for (int i = 0; i < 20000 && !failed; i++) {
            char p[TEST_PATH];
            if (draw_into("many.example", p) != 0) {
                failed = 1;
                break;
            }
            if (strncmp(p, "/many/", 6) == 0) {
                int k = atoi(p + 6);
                if (k >= 0 && k < 200 && !got[k]) {
                    got[k] = 1;
                    distinct++;
                }
            }
        }
        char line[120];
        snprintf(line, sizeof line, "a page of two hundred links: %d of them drawn", distinct);
        ok(!failed && distinct >= 190, line);

        /* A link of a thousand bytes, split across three pieces of the body. */
        static char longpath[1001];
        longpath[0] = '/';
        for (int i = 1; i < 1000; i++)
            longpath[i] = (char)('a' + i % 26);
        static char lpage[1100];
        int         ln = snprintf(lpage, sizeof lpage, "<a href=\"%s\">x</a>", longpath);
        lc_spider_sink *sink = lc_spider_sink_new("long.example");
        lc_spider_sink_data(sink, (const uint8_t *)lpage, 300);
        lc_spider_sink_data(sink, (const uint8_t *)lpage + 300, 500);
        lc_spider_sink_data(sink, (const uint8_t *)lpage + 800, (size_t)ln - 800u);
        lc_spider_sink_commit(sink);
        lc_spider_sink_free(sink);
        n = drawn_set("long.example", seen, 8);
        ok(has(seen, n, longpath), "a link of a thousand bytes across three pieces of the body is kept");

        /* A NUL inside the quotes: `.` matches it, and the key holds it. */
        static const uint8_t nul[] = "<a href=\"/a\0b\">x</a>";
        sink = lc_spider_sink_new("nul.example");
        lc_spider_sink_data(sink, nul, sizeof nul - 1u);
        lc_spider_sink_commit(sink);
        lc_spider_sink_free(sink);
        int four = 0;
        for (int i = 0; i < 200 && !four; i++) {
            char  *p = NULL;
            size_t pn = 0;
            if (lc_spider_path("nul.example", &p, &pn) == 0)
                four = pn == 4u && memcmp(p, "/a\0b", 4) == 0;
            free(p);
        }
        ok(four, "a link with a NUL in it is kept whole, NUL and all");

        /* A set per name, all of them kept: a second name does not take the first one's away. */
        feed_page("first-name.example", "<a href=\"/first\">x</a>");
        feed_page("second-name.example", "<a href=\"/second\">x</a>");
        n = drawn_set("first-name.example", seen, 8);
        ok(has(seen, n, "/first") && !has(seen, n, "/second"),
           "a set per ServerName: the first name keeps its path when a second is harvested");
    }

    /* One set for every worker. lc-tunnel forks a worker per CPU on the REALITY plane, and the
     * reference is one process with one map (reality.go:308-310): a path one worker harvested must
     * be one another can draw — which, with a set per process, it was not. Last in this file,
     * because from here on the set lives in shared memory. */
    {
        ok(lc_spider_paths_share() == 0, "the set moves into memory the workers share");
        pid_t pid = fork();
        if (pid == 0) {
            feed_page("thirteen.example", "<a href=\"/from-a-worker\">x</a>");
            _exit(0);
        }
        int status = -1;
        ok(pid > 0 && waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
               WEXITSTATUS(status) == 0,
           "a forked worker harvests a page and exits");
        n = drawn_set("thirteen.example", seen, 8);
        ok(has(seen, n, "/from-a-worker"), "and the path it harvested is drawn in this process");
    }

    printf("\n%s\n", failures == 0 ? "all good" : "FAILURES");
    return failures == 0 ? 0 : 1;
}
