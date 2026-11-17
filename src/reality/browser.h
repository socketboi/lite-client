/* The browser this client claims to be when REALITY has failed and it has to look ordinary.
 *
 * Xray's client, on a connection whose certificate did not authenticate, does not hang up: it
 * fetches the masquerade site over the same TLS connection with a browser's headers — see
 * reality/spider.h for the whole of that behaviour and why. These are the headers.
 *
 * NONE OF THIS IS A CONSTANT, which is the reason it has a file of its own. The reference derives
 * the Chrome version from the date and a draw, and derives Sec-CH-UA from that version through two
 * lookup tables and a shuffle (vendor/Xray-core/common/utils/browser.go:25-160). A client sending a
 * fixed User-Agent, or a Sec-CH-UA whose GREASE brand does not match its version, is a browser that
 * does not exist — which on this path is worse than sending nothing, because the request is made
 * precisely to be looked at. */
#ifndef LC_BROWSER_H
#define LC_BROWSER_H

#include <stddef.h>
#include <stdint.h>

/* The largest any of the strings below becomes, with room to spare. */
#define LC_BROWSER_UA_MAX 128u
#define LC_BROWSER_CHUA_MAX 160u

/* One header line, name and value, both NUL-terminated. */
typedef struct {
    const char *name;
    const char *value;
} lc_browser_header;

/* Everything applyMasqueradedHeaders writes for "chrome" — Sec-CH-UA and its two companions, DNT,
 * User-Agent, Accept-Language — plus whatever the variant adds. The most is the "nav" variant's
 * eight, for fourteen lines; "fetch" adds seven, for thirteen. The array is the larger of the two
 * and `count` says how many of it are filled. */

/* ⚠️ "CHROME" HERE WHILE THE TLS IDENTITY IS FIREFOX, AND THAT IS THE REFERENCE'S DOING, NOT A SLIP.
 *
 * The packaged fingerprint table is Firefox's — the frozen vector the gate compares it against is
 * test/fphello's reference_firefox.h — so a server that looks at both layers sees a Firefox hello
 * carrying Sec-CH-UA, a header Firefox does not send. That combination is not one a real browser
 * produces, and it is the first thing a reader notices here.
 *
 * It is what Xray does. The REALITY masquerade fetch calls `utils.TryDefaultHeadersWith(req.Header,
 * "nav")` on a header set it has not touched
 * (vendor/Xray-core/transport/internet/reality/reality.go:250), and that function takes the empty
 * User-Agent branch and applies "chrome" flat out — `if len(header.Values("User-Agent")) < 1 {
 * applyMasqueradedHeaders(header, "chrome", variant) }`
 * (vendor/Xray-core/common/utils/browser.go:269-271). Nothing in it consults `config.Fingerprint`.
 * So an Xray configured with `fingerprint: firefox` sends exactly this pair, and matching it is the
 * rule.
 *
 * Which makes this a property to KNOW rather than a defect to fix: deriving the headers from the
 * fingerprint table would look more honest and would be a divergence from the reference in the one
 * place divergences are worth the most to an observer. If it is ever to be closed, the end to move
 * is the TABLE — a Chrome fingerprint would make both layers agree and would also be the commoner
 * deployment — and that is a decision about the whole identity, not a header. */
#define LC_BROWSER_HEADERS 14u

/* WHICH REQUEST THIS IDENTITY IS FOR, and it is not decoration: the reference switches on exactly
 * this (`switch variant` at vendor/Xray-core/common/utils/browser.go:195) and the two sets are not
 * interchangeable. A navigation says `sec-fetch-dest: document` and asks for HTML; a fetch says
 * `empty`, `cors`, `same-origin` and takes anything. Sending the navigation set on an XHTTP request
 * would be a browser fetching an API endpoint by typing it into the address bar, which is a shape
 * no page produces.
 *
 *   nav   — the masquerade fetch after a REALITY handshake that did not authenticate: a person
 *           opening the site. utils.TryDefaultHeadersWith(header, "nav").
 *   fetch — every XHTTP request, because splithttp asks for that one by name:
 *           `utils.TryDefaultHeadersWith(header, "fetch")` (transport/internet/splithttp/
 *           vendor/Xray-core/transport/internet/splithttp/config.go:61, reached from GetRequestHeader on every request it builds). */
typedef enum { LC_BROWSER_NAV = 0, LC_BROWSER_FETCH = 1 } lc_browser_variant;

typedef struct {
    int  version; /* the major Chrome version this identity claims */
    char ua[LC_BROWSER_UA_MAX];
    char chua[LC_BROWSER_CHUA_MAX];

    unsigned          count; /* how many of `header` this variant filled */
    lc_browser_header header[LC_BROWSER_HEADERS];
} lc_browser;

/* Builds the identity. `now` is the current time in seconds and `u` the reference's Float64 draw,
 * both passed in rather than taken here so that the result can be checked against known values.
 *
 * Returns 0, or -1 if the strings would not fit — which cannot happen for any version this century
 * and is checked because the alternative is a truncated User-Agent nobody would notice. */
int lc_browser_chrome(lc_browser *b, int64_t now, double u, lc_browser_variant variant);

/* The major version the reference would claim, given the same two inputs. Separate because it is
 * the part with arithmetic in it and the part worth checking on its own. */
int lc_browser_chrome_version(int64_t now, double u);

/* The six fields of klauspost/cpuid's CPU that Xray seeds its generator from (browser.go:16-19),
 * as that package fills them on this machine. */
typedef struct {
    int family, model, physical, logical, cacheline, threads;
} lc_browser_cpu;

void lc_browser_cpu_detect(lc_browser_cpu *c);

/* GetRandomizer's seed: int64 of the FNV-1 64 sum of the six in decimal. */
int64_t lc_browser_cpu_seed(const lc_browser_cpu *c);

/* The Float64 AnchoredChromeVersion is computed from, for that seed: the fourth globalRng gives. */
double lc_browser_chrome_draw(int64_t seed);

/* Package init: detects the CPU, draws, and reads the clock, once per process. Called by
 * lc_browser_chrome_anchored when nothing has yet; lc-tunnel calls it before its workers fork, so
 * every worker holds the clock of one start, as the one Xray process does. */
void lc_browser_anchor(void);

/* THE SAME IDENTITY EVERY TIME THIS PROCESS IS ASKED, which is what the reference has and what
 * calling lc_browser_chrome per connection did not.
 *
 * Upstream builds it once, at package initialisation:
 *
 *     AnchoredChromeVersion = ChromeVersion()
 *     ChromeUA   = "Mozilla/5.0 (...) Chrome/" + strconv.Itoa(AnchoredChromeVersion) + ".0.0.0 ..."
 *     ChromeUACH = getGreasedChUa(AnchoredChromeVersion, "chrome")
 *                                    (vendor/Xray-core/common/utils/browser.go:155-157)
 *
 * — package-level variables, evaluated once, so an Xray process presents ONE Chrome for its whole
 * lifetime. Everything downstream hangs off that one version: the User-Agent, the sec-ch-ua brand
 * versions, which of the eleven GREASE brand spellings is used, and the order the three brands
 * appear in. Redrawing per connection made a single router present a fleet of different Chromes
 * seconds apart, which no browser and no Xray process produces — and the audience for it is the
 * masqueraded site and the REALITY node itself, both of which see it in clear.
 *
 * AND THE SAME ACROSS RESTARTS, on the same machine: upstream's randomness is `globalRng`, seeded
 * from an FNV hash of cpuid fields (browser.go:15-22), and so is this one — lc_browser_anchor. Only
 * the date moves it.
 *
 * Returns 0, or -1 if the identity could not be built — the same failure lc_browser_chrome has. */
int lc_browser_chrome_anchored(lc_browser *b, lc_browser_variant variant);

#endif
