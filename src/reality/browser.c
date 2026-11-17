#include "reality/browser.h"

#include "quic/gorand.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

/* The two tables the GREASE brand is spelled from, and the six orders three brands are shuffled
 * into. Copied value for value from vendor/Xray-core/common/utils/browser.go:75-77; they are indexed
 * by the version number, so a table with an element added or moved produces a different brand for
 * the same Chrome and is a different client. */
static const char *const grease_na[] = { " ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_" };
static const char *const version_na[] = { "8", "99", "24" };
static const int         shuffle3[6][3] = {
    { 0, 1, 2 }, { 0, 2, 1 }, { 1, 0, 2 }, { 1, 2, 0 }, { 2, 0, 1 }, { 2, 1, 0 },
};

#define GREASE_NA_N (sizeof grease_na / sizeof grease_na[0])
#define VERSION_NA_N (sizeof version_na / sizeof version_na[0])

/* 2026-01-13 00:00:00 UTC in whole days since the epoch — `time.Date(2026, 1, 13, ...).Unix()/86400`
 * worked out here rather than at run time, because there is no portable way to ask for it and the
 * number is fixed for ever. Fifty-six years of 365 days plus fourteen leap days is 20454 days to
 * 2026-01-01, and twelve more to the thirteenth. */
#define CHROME_EPOCH_DAY 20466

int lc_browser_chrome_version(int64_t now, double u)
{
    /* ChromeVersion, vendor/Xray-core/common/utils/browser.go:25-32:
     *
     *   timeDiff := int(timeCurrent - timeStart - 35) - int(math.Floor(math.Pow(rng.Float64(), 2)*105))
     *   return 144 + (timeDiff / 35)
     *
     * The draw is a uniform double squared and scaled by 105, floored — a curve, not a range, so
     * versions just behind the current one are common and older ones are rare. In doubles, as Go
     * computes it, because the draw is Go's own double now (lc_browser_anchor) and a reduction to
     * integers would round it a second time. math.Pow with an exponent of 2 takes its integer-power
     * loop (GOROOT/src/math/pow.go): one rounded product of the mantissas and exact scaling of the
     * exponent, which is `u * u` rounded once — the product here. Without an FPU the compiler's soft
     * float is IEEE as well, and this runs once per process. No fused multiply-add can creep in,
     * there is no addition to fuse. The cast truncates, which for a value never negative is the
     * floor. */
    int64_t back = (int64_t)(u * u * 105.0);

    int64_t today = now / 86400;
    int64_t diff = today - CHROME_EPOCH_DAY - 35 - back;

    /* Truncating division, which is what Go's `/` does on int and is NOT what a floor would do: for
     * a negative difference — a clock set before 2026, which a freshly booted router has — the two
     * disagree by one. Written out because C's `/` truncates as well, so this line is correct by
     * agreement rather than by accident, and the next person should not have to check. */
    return 144 + (int)(diff / 35);
}

int lc_browser_chrome(lc_browser *b, int64_t now, double u, lc_browser_variant variant)
{
    memset(b, 0, sizeof *b);
    b->version = lc_browser_chrome_version(now, u);

    int n = snprintf(b->ua, sizeof b->ua,
                     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like "
                     "Gecko) Chrome/%d.0.0.0 Safari/537.36",
                     b->version);
    if (n < 0 || (size_t)n >= sizeof b->ua)
        return -1;

    /* getGreasedChUa: three brands — the invalid one, Chromium, Google Chrome — shuffled into the
     * order the version selects, then joined with ", ".
     *
     * The invalid brand is spelled from the two tables at the version's index, which is what makes
     * it move with the version rather than being a constant somebody could match on:
     *
     *   "Not" + greaseNA[v%11] + "A" + greaseNA[(v+1)%11] + "Brand";v="versionNA[v%3]"
     *
     * The modulus is taken on a version that is always positive here — a clock wrong enough to make
     * it negative would have to read before 2021, and C's % would then give a negative index. Guarded
     * rather than assumed, because the cost of being wrong is a read before the start of a table. */
    unsigned v = b->version < 0 ? 0u : (unsigned)b->version;

    char invalid[64];
    n = snprintf(invalid, sizeof invalid, "\"Not%sA%sBrand\";v=\"%s\"", grease_na[v % GREASE_NA_N],
                 grease_na[(v + 1u) % GREASE_NA_N], version_na[v % VERSION_NA_N]);
    if (n < 0 || (size_t)n >= sizeof invalid)
        return -1;

    char chromium[48], chrome[48];
    n = snprintf(chromium, sizeof chromium, "\"Chromium\";v=\"%d\"", b->version);
    if (n < 0 || (size_t)n >= sizeof chromium)
        return -1;
    n = snprintf(chrome, sizeof chrome, "\"Google Chrome\";v=\"%d\"", b->version);
    if (n < 0 || (size_t)n >= sizeof chrome)
        return -1;

    /* getGreasedChOrder for three brands is a lookup, and the shuffle is written the way the
     * reference writes it: `shuffled[order[i]] = ungreased[i]`, which places brand i AT position
     * order[i]. Reading it the other way round — taking brand order[i] into position i — produces a
     * different string for four of the six orders, and both readings look equally plausible. */
    const char *ungreased[3] = { invalid, chromium, chrome };
    const char *shuffled[3] = { NULL, NULL, NULL };
    const int  *order = shuffle3[v % 6u];
    for (unsigned i = 0; i < 3u; i++)
        shuffled[order[i]] = ungreased[i];

    n = snprintf(b->chua, sizeof b->chua, "%s, %s, %s", shuffled[0], shuffled[1], shuffled[2]);
    if (n < 0 || (size_t)n >= sizeof b->chua)
        return -1;

    /* applyMasqueradedHeaders("chrome"), browser.go:162-171 — the six that do not depend on what
     * the request is for. Order is not part of the identity: Go stores these in a map and its
     * HTTP/2 writer walks that map, so the reference itself emits them in a different order every
     * time. What has to match is the set and the values. */
    unsigned h = 0;
    b->header[h++] = (lc_browser_header){ "sec-ch-ua", b->chua };
    b->header[h++] = (lc_browser_header){ "sec-ch-ua-mobile", "?0" };
    b->header[h++] = (lc_browser_header){ "sec-ch-ua-platform", "\"Windows\"" };
    b->header[h++] = (lc_browser_header){ "dnt", "1" };
    b->header[h++] = (lc_browser_header){ "user-agent", b->ua };
    b->header[h++] = (lc_browser_header){ "accept-language", "en-US,en;q=0.9" };

    /* And then the variant, which is `switch variant` at browser.go:195. The two sets say what kind
     * of request this is, and a request wearing the wrong one is stranger than one wearing none:
     * `sec-fetch-dest: document` on a POST to an API path is a page navigation that no page makes. */
    switch (variant) {
    case LC_BROWSER_NAV:
        /* browser.go:196-220. */
        b->header[h++] = (lc_browser_header){ "cache-control", "max-age=0" };
        b->header[h++] = (lc_browser_header){ "upgrade-insecure-requests", "1" };
        b->header[h++] = (lc_browser_header){
            "accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,"
                      "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
        };
        b->header[h++] = (lc_browser_header){ "sec-fetch-site", "none" };
        b->header[h++] = (lc_browser_header){ "sec-fetch-mode", "navigate" };
        /* Set for every browser the reference knows except Safari, and this identity is Chrome. */
        b->header[h++] = (lc_browser_header){ "sec-fetch-user", "?1" };
        b->header[h++] = (lc_browser_header){ "sec-fetch-dest", "document" };
        b->header[h++] = (lc_browser_header){ "priority", "u=0, i" };
        break;

    case LC_BROWSER_FETCH:
        /* browser.go:240-262. The four guarded by `if header.Get(...) == ""` are unconditional
         * here for the reason the guard exists: it only steps aside for a value the caller already
         * set, and splithttp sets none of them — GetRequestHeader copies the user's `headers` map
         * and then calls this, so on a configuration that names no headers, which is the one this
         * client has, every guard is open. */
        b->header[h++] = (lc_browser_header){ "sec-fetch-mode", "cors" };
        b->header[h++] = (lc_browser_header){ "sec-fetch-dest", "empty" };
        b->header[h++] = (lc_browser_header){ "sec-fetch-site", "same-origin" };
        b->header[h++] = (lc_browser_header){ "priority", "u=1, i" };
        b->header[h++] = (lc_browser_header){ "cache-control", "no-cache" };
        b->header[h++] = (lc_browser_header){ "pragma", "no-cache" };
        b->header[h++] = (lc_browser_header){ "accept", "*/*" };
        break;

    default:
        return -1;
    }

    b->count = h;
    return h <= LC_BROWSER_HEADERS ? 0 : -1;
}

/* What klauspost/cpuid v2.4.0 — the version vendor/Xray-core/go.mod names — puts in the six fields
 * GetRandomizer hashes, on the machine this runs on. Each architecture is its detect_*.go, and
 * every field those files leave alone keeps what Detect set first (cpuid.go:480): zero, and one
 * thread per core. */
#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>

enum { X86_OTHER, X86_INTEL, X86_AMD, X86_HYGON };

/* asmCpuid clears ECX before CPUID, asmCpuidex loads it (cpuid_amd64.s). */
static void x86_cpuid(uint32_t op, uint32_t sub, uint32_t r[4])
{
    __cpuid_count(op, sub, r[0], r[1], r[2], r[3]);
}

static uint32_t x86_max(void)
{
    uint32_t r[4];
    x86_cpuid(0, 0, r);
    return r[0];
}

static uint32_t x86_max_ext(void)
{
    uint32_t r[4];
    x86_cpuid(0x80000000u, 0, r);
    return r[0];
}

/* vendorID, cpuid.go: EBX, EDX, ECX as twelve characters, looked up in vendorMapping. Only the
 * vendors the core counts branch on are told apart; every other answers as an unknown one does. */
static int x86_vendor(void)
{
    uint32_t r[4];
    char     v[12];
    x86_cpuid(0, 0, r);
    memcpy(v, &r[1], 4);
    memcpy(v + 4, &r[3], 4);
    memcpy(v + 8, &r[2], 4);
    if (memcmp(v, "GenuineIntel", 12) == 0)
        return X86_INTEL;
    if (memcmp(v, "AuthenticAMD", 12) == 0 || memcmp(v, "AMDisbetter!", 12) == 0)
        return X86_AMD;
    if (memcmp(v, "HygonGenuine", 12) == 0)
        return X86_HYGON;
    return X86_OTHER;
}

/* familyModel. */
static void x86_family_model(int *family, int *model)
{
    uint32_t r[4];
    *family = *model = 0;
    if (x86_max() < 1)
        return;
    x86_cpuid(1, 0, r);
    uint32_t eax = r[0];
    int      fam = (int)((eax >> 8) & 0xf);
    int      ext = fam == 0x6; /* Intel is 0x6, needs extended model. */
    if (fam == 0xf) {
        fam += (int)((eax >> 20) & 0xff);
        ext = 1;
    }
    int mod = (int)((eax >> 4) & 0xf);
    if (ext)
        mod += (int)((eax >> 12) & 0xf0);
    *family = fam;
    *model = mod;
}

/* threadsPerCore. */
static int x86_threads(void)
{
    uint32_t mfi = x86_max(), r[4];
    int      vend = x86_vendor();

    if (mfi < 0x4 || (vend != X86_INTEL && vend != X86_AMD))
        return 1;
    if (mfi < 0xb) {
        if (vend != X86_INTEL)
            return 1;
        x86_cpuid(1, 0, r);
        if ((r[3] & (1u << 28)) != 0) {
            uint32_t v = (r[1] >> 16) & 255;
            if (v > 1) {
                uint32_t a4[4];
                x86_cpuid(4, 0, a4);
                uint32_t v2 = (a4[0] >> 26) + 1;
                if (v2 > 0)
                    return (int)v / (int)v2;
            }
        }
        return 1;
    }
    x86_cpuid(0xb, 0, r);
    if ((r[1] & 0xffff) == 0) {
        if (vend == X86_AMD) {
            int      fam, mod;
            uint32_t d[4];
            x86_family_model(&fam, &mod);
            x86_cpuid(1, 0, d);
            if ((d[3] & (1u << 28)) != 0 && fam >= 23) {
                if (x86_max_ext() >= 0x8000001eu) {
                    uint32_t e[4];
                    x86_cpuid(0x8000001eu, 0, e);
                    return (int)((e[1] >> 8) & 0xff) + 1;
                }
                return 2;
            }
        }
        return 1;
    }
    return (int)(r[1] & 0xffff);
}

/* logicalCores. */
static int x86_logical(void)
{
    uint32_t mfi = x86_max(), r[4];
    switch (x86_vendor()) {
    case X86_INTEL:
        if (mfi < 0xb) {
            if (mfi < 1)
                return 0;
            x86_cpuid(1, 0, r);
            return (int)((r[1] >> 16) & 0xff);
        }
        x86_cpuid(0xb, 1, r);
        return (int)(r[1] & 0xffff);
    case X86_AMD:
    case X86_HYGON:
        x86_cpuid(1, 0, r);
        return (int)((r[1] >> 16) & 0xff);
    default:
        return 0;
    }
}

/* physicalCores. */
static int x86_physical(void)
{
    int vend = x86_vendor();
    if (vend != X86_INTEL && vend != X86_AMD && vend != X86_HYGON)
        return 0;
    int lc = x86_logical(), tpc = x86_threads();
    if (lc > 0 && tpc > 0)
        return lc / tpc;
    if (vend != X86_INTEL && x86_max_ext() >= 0x80000008u) {
        uint32_t r[4];
        x86_cpuid(0x80000008u, 0, r);
        if ((r[2] & 0xff) > 0)
            return (int)(r[2] & 0xff) + 1;
    }
    return 0;
}

/* cacheLine. */
static int x86_cacheline(void)
{
    uint32_t r[4];
    if (x86_max() < 1)
        return 0;
    x86_cpuid(1, 0, r);
    uint32_t cache = (r[1] & 0xff00) >> 5; /* cflush size */
    if (cache == 0 && x86_max_ext() >= 0x80000006u) {
        x86_cpuid(0x80000006u, 0, r);
        cache = r[2] & 0xff;
    }
    return (int)cache;
}

#elif defined(__aarch64__) && defined(__linux__)
#include <sched.h>
#include <sys/auxv.h>

/* runtime.NumCPU on Linux: the CPUs in the affinity mask the process started with, and one when
 * the mask cannot be had or is empty (getproccount, GOROOT/src/runtime/os_linux.go). */
static int go_numcpu(void)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    if (sched_getaffinity(0, sizeof set, &set) != 0)
        return 1;
    int n = CPU_COUNT(&set);
    return n > 0 ? n : 1;
}
#elif defined(__riscv)
#error "port klauspost/cpuid os_linux_riscv64.go before building for riscv64: the seed is its fields"
#endif

void lc_browser_cpu_detect(lc_browser_cpu *c)
{
    memset(c, 0, sizeof *c);
    c->threads = 1; /* Detect: CPU.ThreadsPerCore = 1, cpuid.go:480 */

#if defined(__x86_64__) || defined(__i386__)
    /* addInfo, detect_x86.go:21-32. */
    c->cacheline = x86_cacheline();
    x86_family_model(&c->family, &c->model);
    c->threads = x86_threads();
    c->logical = x86_logical();
    c->physical = x86_physical();
#elif defined(__aarch64__) && defined(__linux__)
    /* addInfo, detect_arm64.go:21-111, and detectOS, os_linux_arm64.go:122-177. MIDR is read only
     * when the kernel says it traps and emulates the read (HWCAP_CPUID); without that, the safe
     * default returns before it and family and model stay zero. */
    c->cacheline = 64;
    c->logical = go_numcpu();
    c->physical = c->logical;
    c->threads = 1;
    if ((getauxval(AT_HWCAP) & (1ul << 11)) == 0) /* hwcap_CPUID */
        return;
    uint64_t midr;
    __asm__ volatile("mrs %0, midr_el1" : "=r"(midr));
    c->family = (int)(midr >> 16) & 0xff;
    c->model = (int)midr & 0xffff;
#else
    /* detect_ref.go — mipsle, mips, 32-bit ARM: addInfo does nothing, so only Detect's default is
     * set. Every MT7621 hashes the same six fields, "000001", and claims the same Chrome. */
#endif
}

int64_t lc_browser_cpu_seed(const lc_browser_cpu *c)
{
    /* GetRandomizer, browser.go:16-19: the six fields in decimal, run together in this order,
     * hashed by fnv.New64 — FNV-1, multiply then xor — and the sum taken as an int64. */
    char s[6 * 12];
    int  n = snprintf(s, sizeof s, "%d%d%d%d%d%d", c->family, c->model, c->physical, c->logical,
                      c->cacheline, c->threads);
    uint64_t h = 14695981039346656037ull;
    for (int i = 0; i < n && i < (int)sizeof s; i++) {
        h *= 1099511628211ull;
        h ^= (uint8_t)s[i];
    }
    return (int64_t)h;
}

double lc_browser_chrome_draw(int64_t seed)
{
    /* globalRng = rand.New(rand.NewSource(seed)), and the Float64 ChromeVersion takes from it is the
     * FOURTH: Go initialises a package's variables in the order they are declared, and the block at
     * browser.go:148-156 declares CurlUA (CurlVersion, one draw), AnchoredFirefoxVersion (one),
     * SafariUA (SafariVersion, one) and only then AnchoredChromeVersion. Nothing else in the package
     * reads globalRng. tools/xraybrowser runs that initialisation itself. */
    lc_gorand r;
    lc_gorand_seed(&r, seed);
    (void)lc_gorand_float64(&r);
    (void)lc_gorand_float64(&r);
    (void)lc_gorand_float64(&r);
    return lc_gorand_float64(&r);
}

static int64_t anchor_now;
static double  anchor_u;
static int     anchor_have;

void lc_browser_anchor(void)
{
    /* Both inputs are frozen, not just the draw. The reference freezes the whole of ChromeVersion()
     * — which reads the clock as well as the randomness — at package init, so its version does not
     * step forward mid-run either. A version that advanced while the process ran would be a browser
     * that updated itself between two requests without restarting, which is not a thing. */
    if (anchor_have)
        return;
    lc_browser_cpu c;
    lc_browser_cpu_detect(&c);
    anchor_u = lc_browser_chrome_draw(lc_browser_cpu_seed(&c));
    anchor_now = (int64_t)time(NULL);
    anchor_have = 1;
}

int lc_browser_chrome_anchored(lc_browser *b, lc_browser_variant variant)
{
    /* WHAT IS FROZEN IS THE DRAW AND THE CLOCK, not the finished header table — and that is the
     * reference's shape rather than a convenience. Upstream anchors AnchoredChromeVersion, ChromeUA
     * and ChromeUACH at package init and then applies the variant to a fresh header map on every
     * request (TryDefaultHeadersWith is called per request, browser.go:266). So one process presents
     * one Chrome, and that one Chrome makes both kinds of request: a navigation to the masquerade
     * site and a fetch to an XHTTP endpoint, with the same User-Agent and the same greased brands.
     *
     * Caching the built table instead would have meant one table per variant and two identities to
     * keep in step — and the first time they drifted, the router would have been a browser whose
     * User-Agent changed depending on what it was asking for. */
    lc_browser_anchor();

    /* Built into the caller's struct, so every pointer in the header table addresses that struct's
     * own strings. The copy this used to make left `user-agent` and `sec-ch-ua` pointing at the
     * cached original, so b->ua and the header line were two addresses for one value. */
    return lc_browser_chrome(b, anchor_now, anchor_u, variant);
}
