/* The browser identity sent when REALITY has failed, against values the reference computed.
 *
 * This is not a self-consistency test. Every expected string below was produced by running Xray's
 * own algorithm — vendor/Xray-core/common/utils/browser.go, ChromeVersion and getGreasedChUa — over
 * the same inputs, and pasted here. A client that agrees only with itself would sail through a test
 * written any other way, and the whole value of this identity is that it agrees with Chrome.
 *
 * Two things are separately at risk and separately checked:
 *
 *   the version, whose formula carries a squared uniform draw scaled by 105 and floored, and whose
 *     draw is the fourth Float64 of Go's math/rand seeded from klauspost/cpuid's fields. Both
 *     against Xray itself: tools/xraybrowser runs its browser.go's package init for 127 CPUs and
 *     for this machine, and every draw and every version below is what that run printed.
 *
 *   Sec-CH-UA, whose GREASE brand is spelled out of two tables indexed by the version and whose
 *     three brands are then placed by a shuffle the version also selects. The shuffle is the part
 *     with two plausible readings — `shuffled[order[i]] = ungreased[i]` places brand i AT order[i],
 *     and the other reading differs for four of the six orders. Versions 151 and 152 below are
 *     exactly the ones where the two readings disagree, which is why they are here. */

#include "reality/browser.c"

#include "xraybrowser_vectors.h"

#include <stdio.h>
#include <string.h>

/* The largest Float64 Go's Rand returns: 1 - 2^-53, one ulp under the 1.0 it draws again on. */
#define LARGEST_DRAW 0x1.fffffffffffffp-1

static uint64_t bits(double d)
{
    uint64_t u;
    memcpy(&u, &d, sizeof u);
    return u;
}

static int failures;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

/* A day count turned into the seconds the caller would pass. */
static int64_t at_day(int64_t day)
{
    return day * 86400;
}

/* Which day makes the version come out at `v` with no draw: the formula walks 35 days per version
 * from 144, starting 35 days after the anchor. */
static int64_t day_for(int v)
{
    return 20466 + 35 + 35 * (int64_t)(v - 144);
}

static void expect_chua(int v, const char *want)
{
    lc_browser b;
    char       label[160];
    int        rv = lc_browser_chrome(&b, at_day(day_for(v)), 0, LC_BROWSER_NAV);
    snprintf(label, sizeof label, "Sec-CH-UA at version %d is the reference's", v);
    if (rv != 0 || b.version != v) {
        printf("  FAIL  %s (built %d, wanted %d)\n", label, rv == 0 ? b.version : -1, v);
        failures++;
        return;
    }
    ok(strcmp(b.chua, want) == 0, label);
    if (strcmp(b.chua, want) != 0) {
        printf("        ours: %s\n", b.chua);
        printf("        uTLS: %s\n", want);
    }
}

int main(void)
{
    printf("browser: the version curve\n");

    /* Thirty-five days past the anchor with no draw is the anchor version itself. */
    ok(lc_browser_chrome_version(at_day(20466 + 35), 0) == 144,
       "no draw, thirty-five days on: Chrome 144");
    ok(lc_browser_chrome_version(at_day(20851), 0) == 154, "no draw, day 20851: Chrome 154");

    /* The draw only ever moves the version BACKWARDS, and by at most three versions: the largest
     * possible subtraction is 104 days, which is two whole steps of thirty-five and a remainder. */
    int newest = lc_browser_chrome_version(at_day(20851), 0);
    int oldest = lc_browser_chrome_version(at_day(20851), LARGEST_DRAW);
    ok(oldest <= newest, "a draw never makes the version newer");
    ok(newest - oldest == 2 || newest - oldest == 3,
       "and never takes it back more than three versions");

    /* The endpoint of the curve, stated as the thing it actually is: floor(u^2 * 105) for the
     * largest Float64 Go returns is 104, so the largest draw is worth exactly 104 days.
     *
     * Asserted by moving the clock instead of by counting versions, because the version is a
     * truncating division and the difference between two of them is 2 or 3 depending on where in a
     * thirty-five day step the day happens to fall — a fact about the division, not about the
     * curve. Shifting the date by 104 days takes the phase out and leaves only the question worth
     * asking. */
    for (int v = 144; v <= 154; v += 5)
        ok(lc_browser_chrome_version(at_day(day_for(v) + 104), LARGEST_DRAW) ==
               lc_browser_chrome_version(at_day(day_for(v)), 0),
           "the largest draw is worth exactly 104 days");

    printf("\nbrowser: the draw, against Xray's package init\n");

    /* Each CPU's seed through math/rand: all four draws, which is the seed and the generator, and
     * the version AnchoredChromeVersion came out at on the day it ran, which is the fourth draw
     * taken and the curve. */
    size_t nvec = sizeof xb_vec / sizeof xb_vec[0], draws_bad = 0, version_bad = 0;
    for (size_t i = 0; i < nvec; i++) {
        lc_browser_cpu c = { xb_vec[i].cpu[0], xb_vec[i].cpu[1], xb_vec[i].cpu[2],
                             xb_vec[i].cpu[3], xb_vec[i].cpu[4], xb_vec[i].cpu[5] };
        lc_gorand      r;
        lc_gorand_seed(&r, lc_browser_cpu_seed(&c));
        for (int k = 0; k < 4; k++)
            if (bits(lc_gorand_float64(&r)) != xb_vec[i].f[k])
                draws_bad++;
        double u = lc_browser_chrome_draw(lc_browser_cpu_seed(&c));
        if (bits(u) != xb_vec[i].f[3] ||
            lc_browser_chrome_version(at_day(xb_vec[i].day), u) != xb_vec[i].version)
            version_bad++;
    }
    char line[160];
    snprintf(line, sizeof line, "%zu CPUs: the four draws of globalRng, bit for bit", nvec);
    ok(draws_bad == 0, line);
    snprintf(line, sizeof line, "%zu CPUs: the Chrome version Xray claimed that day", nvec);
    ok(version_bad == 0, line);

    /* And the machine itself: the six fields as cpuid reads them here, which is what the port of
     * detect_*.go is for, and the version the two then agree on. */
    lc_browser_cpu here;
    lc_browser_cpu_detect(&here);
    int same = here.family == xb_here.cpu[0] && here.model == xb_here.cpu[1] &&
               here.physical == xb_here.cpu[2] && here.logical == xb_here.cpu[3] &&
               here.cacheline == xb_here.cpu[4] && here.threads == xb_here.cpu[5];
    if (!same)
        printf("        ours %d %d %d %d %d %d, cpuid %d %d %d %d %d %d\n", here.family, here.model,
               here.physical, here.logical, here.cacheline, here.threads, xb_here.cpu[0],
               xb_here.cpu[1], xb_here.cpu[2], xb_here.cpu[3], xb_here.cpu[4], xb_here.cpu[5]);
    ok(same, "this machine: the fields klauspost/cpuid reads");
    ok(lc_browser_chrome_version(at_day(xb_here.day),
                                 lc_browser_chrome_draw(lc_browser_cpu_seed(&here))) == xb_here.version,
       "and the Chrome Xray claims on it");

    printf("\nbrowser: Sec-CH-UA\n");

    expect_chua(144, "\"Not(A:Brand\";v=\"8\", \"Chromium\";v=\"144\", \"Google Chrome\";v=\"144\"");
    expect_chua(150, "\"Not;A=Brand\";v=\"8\", \"Chromium\";v=\"150\", \"Google Chrome\";v=\"150\"");
    expect_chua(151, "\"Not=A?Brand\";v=\"99\", \"Google Chrome\";v=\"151\", \"Chromium\";v=\"151\"");
    expect_chua(152, "\"Chromium\";v=\"152\", \"Not?A_Brand\";v=\"24\", \"Google Chrome\";v=\"152\"");
    expect_chua(154, "\"Chromium\";v=\"154\", \"Google Chrome\";v=\"154\", \"Not A(Brand\";v=\"99\"");

    printf("\nbrowser: the header set\n");

    lc_browser b;
    ok(lc_browser_chrome(&b, at_day(day_for(151)), 0, LC_BROWSER_NAV) == 0, "the identity builds");

    /* The User-Agent carries the same version the brands do. A client whose two disagree is not a
     * browser, and the two are built from separate strings here. */
    char want_ua[160];
    snprintf(want_ua, sizeof want_ua,
             "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
             "Chrome/%d.0.0.0 Safari/537.36",
             b.version);
    ok(strcmp(b.ua, want_ua) == 0, "and the User-Agent names the same version as the brands");

    /* Every line applyMasqueradedHeaders writes for chrome+nav, none missing and none invented.
     * Names lower-case because HTTP/2 forbids anything else. */
    static const char *const want[] = {
        "sec-ch-ua",      "sec-ch-ua-mobile", "sec-ch-ua-platform",        "dnt",
        "user-agent",     "accept-language",  "cache-control",             "upgrade-insecure-requests",
        "accept",         "sec-fetch-site",   "sec-fetch-mode",            "sec-fetch-user",
        "sec-fetch-dest", "priority",
    };
    ok(sizeof want / sizeof want[0] == LC_BROWSER_HEADERS, "fourteen headers, as the reference sets");

    int all = 1;
    for (unsigned i = 0; i < LC_BROWSER_HEADERS; i++) {
        int found = 0;
        for (unsigned j = 0; j < LC_BROWSER_HEADERS; j++)
            if (strcmp(b.header[j].name, want[i]) == 0)
                found = 1;
        if (!found) {
            printf("        missing: %s\n", want[i]);
            all = 0;
        }
    }
    ok(all, "and every one of them is present");

    for (unsigned i = 0; i < LC_BROWSER_HEADERS; i++) {
        for (const char *p = b.header[i].name; *p != '\0'; p++)
            if (*p >= 'A' && *p <= 'Z')
                all = 0;
    }
    ok(all, "with names HTTP/2 accepts, which is to say lower-case");

    printf("\nbrowser: the fetch variant, which every XHTTP request wears\n");

    /* browser.go:240-262, reached because splithttp's GetRequestHeader asks for "fetch" by name.
     * Checked as a SET and against the nav set, because the failure worth catching is not a missing
     * line — that shows up as a count — but the two variants blurring into one: an XHTTP request
     * carrying `sec-fetch-dest: document` is a page navigation to an API path, which is stranger
     * than sending no headers at all. */
    lc_browser f;
    ok(lc_browser_chrome(&f, at_day(day_for(151)), 0, LC_BROWSER_FETCH) == 0,
       "the fetch identity builds");
    ok(f.count == 13u, "thirteen headers: the six of chrome and the seven of fetch");
    ok(strcmp(f.ua, b.ua) == 0 && strcmp(f.chua, b.chua) == 0,
       "and it is the SAME Chrome as the navigation wears, which is what one process presents");

    static const struct {
        const char *name;
        const char *value;
    } want_fetch[] = {
        { "sec-fetch-mode", "cors" },      { "sec-fetch-dest", "empty" },
        { "sec-fetch-site", "same-origin" }, { "priority", "u=1, i" },
        { "cache-control", "no-cache" },   { "pragma", "no-cache" },
        { "accept", "*/*" },
    };
    int fetch_ok = 1;
    for (unsigned i = 0; i < sizeof want_fetch / sizeof want_fetch[0]; i++) {
        int found = 0;
        for (unsigned j = 0; j < f.count; j++)
            if (strcmp(f.header[j].name, want_fetch[i].name) == 0 &&
                strcmp(f.header[j].value, want_fetch[i].value) == 0)
                found = 1;
        if (!found) {
            printf("        missing or wrong: %s\n", want_fetch[i].name);
            fetch_ok = 0;
        }
    }
    ok(fetch_ok, "every line the fetch variant sets, with the value the reference sets");

    /* The three the navigation adds and the fetch does not. Named one by one rather than counted:
     * a count would pass if one of them were swapped for another. */
    static const char *const not_in_fetch[] = { "sec-fetch-user", "upgrade-insecure-requests" };
    int clean = 1;
    for (unsigned i = 0; i < sizeof not_in_fetch / sizeof not_in_fetch[0]; i++)
        for (unsigned j = 0; j < f.count; j++)
            if (strcmp(f.header[j].name, not_in_fetch[i]) == 0) {
                printf("        the navigation's %s leaked into the fetch\n", not_in_fetch[i]);
                clean = 0;
            }
    ok(clean, "and nothing the navigation adds leaked into it");

    printf("\nbrowser: one identity per process\n");

    /* The reference builds its identity once, in package-level initialisation
     * (vendor/Xray-core/common/utils/browser.go:155-157), so one Xray process presents one Chrome
     * for its whole life. Ours drew a fresh one per connection, and a router that reconnects every
     * few seconds then showed the node and the masqueraded site a fleet of different Chromes —
     * something no browser does. Asked twice here because "anchored" is exactly the claim that the
     * second answer equals the first. */
    lc_browser a1, a2;
    ok(lc_browser_chrome_anchored(&a1, LC_BROWSER_NAV) == 0 && lc_browser_chrome_anchored(&a2, LC_BROWSER_NAV) == 0,
       "the anchored identity builds, twice");
    ok(a1.version == a2.version, "and claims the same Chrome version both times");
    ok(strcmp(a1.ua, a2.ua) == 0, "the same user-agent");
    ok(strcmp(a1.chua, a2.chua) == 0, "and the same sec-ch-ua, which is derived from that version");

    /* The header table holds pointers, and a struct copy would leave them aimed at the anchor's
     * strings rather than at the copy's. Harmless while the anchor outlives every caller — it is a
     * function-local static — but then b->ua and the `user-agent` line are two addresses for one
     * value, and only one of them is the caller's. */
    int aimed = 1;
    for (unsigned i = 0; i < LC_BROWSER_HEADERS; i++) {
        if (strcmp(a1.header[i].name, "user-agent") == 0 && a1.header[i].value != a1.ua)
            aimed = 0;
        if (strcmp(a1.header[i].name, "sec-ch-ua") == 0 && a1.header[i].value != a1.chua)
            aimed = 0;
    }
    ok(aimed, "and its header lines point into the copy the caller was given");

    printf(failures == 0 ? "\nall good\n" : "\n%d failed\n", failures);
    return failures == 0 ? 0 : 1;
}
