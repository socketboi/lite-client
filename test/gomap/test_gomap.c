/* core/gomap against Go's own maps.
 *
 * tools/gomap builds fresh maps in Go and records, for each key count, where each key lands in a
 * walk, and how often two walks of one map start with the same key. This does the same with the
 * emulation and holds every cell to Go's within six standard errors of the difference — so a model
 * that got the group size, the growth point, the re-placement order or the walk wrong fails in
 * hundreds of cells at once, while one that is right fails nowhere.
 *
 * WHAT THOSE CELLS CANNOT SEE: Go seeds every map's hash afresh, so a key's hash is uniform, and a
 * model that read its group from other bits of it, probed in other steps, sent the other half of a
 * split to the other side or sized a hinted table otherwise makes walks distributed the same, or
 * too nearly so to measure. Those are held to Go's structure instead, with the model's own tables
 * in view (this file includes core/gomap.c): every key where Go's own lookup would look for it, and
 * the directory as Go lays it out.
 *
 * The randomness here is a fast generator of the test's own, standing in for lc_rnd: what is under
 * test is the model, and a syscall per insert would make a quarter of a billion of them take
 * minutes. */
#include "core/gomap.c"
#include "core/rnd.h"
#include "gomap_vectors.h"

#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>

static uint64_t prng;

/* splitmix64: fast, well mixed, and entirely the test's business. */
int lc_rnd(uint8_t *out, size_t n)
{
    while (n > 0) {
        prng += 0x9e3779b97f4a7c15ull;
        uint64_t z = prng;
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
        z ^= z >> 31;
        size_t k = n < sizeof z ? n : sizeof z;
        memcpy(out, &z, k);
        out += k;
        n -= k;
    }
    return 0;
}

static int failures;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

/* |a - b| over the standard error of the difference of two proportions out of `t` each. */
static double z(uint32_t a, uint32_t b, double t)
{
    double pa = a / t, pb = b / t;
    double se = sqrt((pa * (1.0 - pa) + pb * (1.0 - pb)) / t);
    if (se == 0.0)
        return a == b ? 0.0 : 1e9;
    return fabs(pa - pb) / se;
}

int main(void)
{
    if (getrandom(&prng, sizeof prng, 0) != (ssize_t)sizeof prng)
        prng = 0x1234567u;

    printf("\na Go map walk, emulated, against Go\n");
    static uint32_t us[LC_GOMAP_KEYS][LC_GOMAP_KEYS];
    double          t = (double)GOMAP_TRIALS;
    for (unsigned si = 0; si < GOMAP_SIZES; si++) {
        unsigned n = gomap_size[si];
        memset(us, 0, sizeof us);
        unsigned same = 0;
        for (unsigned trial = 0; trial < GOMAP_TRIALS; trial++) {
            lc_gomap m;
            lc_gomap_init(&m);
            for (unsigned i = 0; i < n; i++)
                (void)lc_gomap_insert(&m);
            unsigned order[LC_GOMAP_KEYS], again[LC_GOMAP_KEYS];
            (void)lc_gomap_walk(&m, order);
            (void)lc_gomap_walk(&m, again);
            for (unsigned p = 0; p < n; p++)
                us[order[p]][p]++;
            if (order[0] == again[0])
                same++;
        }
        double   worst = 0.0;
        unsigned bad = 0;
        for (unsigned k = 0; k < n; k++)
            for (unsigned p = 0; p < n; p++) {
                double d = z(us[k][p], gomap_counts[si][k * n + p], t);
                if (d > worst)
                    worst = d;
                if (d > 6.0)
                    bad++;
            }
        char what[160];
        snprintf(what, sizeof what, "%2u keys: every key at every position as in Go (worst %.1f SE)",
                 n, worst);
        ok(bad == 0, what);
        snprintf(what, sizeof what,
                 "%2u keys: two walks of one map start alike %.4f of the time, Go %.4f", n,
                 same / t, gomap_same_first[si] / t);
        ok(z(same, gomap_same_first[si], t) <= 6.0, what);
    }

    /* The hinted map, then the redirect's header map built from it (tools/gomap, pipelines). */
    printf("\nmake(map, 15), and a redirect's header map three maps deep\n");
    for (int which = 0; which < 3; which++) {
        unsigned        n = which == 0 ? 15u : which == 1 ? 16u : 15u;
        const uint32_t *go = which == 0   ? &gomap_hint15[0][0]
                             : which == 1 ? &gomap_redirect[0][0]
                                          : &gomap_redirect_strip[0][0];
        memset(us, 0, sizeof us);
        for (unsigned trial = 0; trial < GOMAP_TRIALS; trial++) {
            unsigned order[LC_GOMAP_KEYS];
            if (which == 0) {
                lc_gomap m;
                lc_gomap_init_hint(&m, 15);
                for (unsigned i = 0; i < 15u; i++)
                    (void)lc_gomap_insert(&m);
                (void)lc_gomap_walk(&m, order);
                for (unsigned p = 0; p < n; p++)
                    us[order[p]][p]++;
                continue;
            }
            /* The request's map, its clone, the redirect's map with one key more. */
            lc_gomap h, clone, r;
            unsigned clone_from[LC_GOMAP_KEYS], r_from[LC_GOMAP_KEYS];
            lc_gomap_init(&h);
            for (unsigned i = 0; i < 15u; i++)
                (void)lc_gomap_insert(&h);
            lc_gomap_init_hint(&clone, 15);
            (void)lc_gomap_copy(&h, &clone, ~0u, clone_from);
            unsigned skip = ~0u;
            if (which == 2)
                for (unsigned i = 0; i < clone.n; i++)
                    if (clone_from[i] == 14u)
                        skip = i;
            lc_gomap_init(&r);
            int copied = lc_gomap_copy(&clone, &r, skip, r_from);
            (void)lc_gomap_insert(&r); /* the referer */
            (void)lc_gomap_walk(&r, order);
            for (unsigned p = 0; p < n; p++) {
                unsigned k = order[p];
                unsigned key = k < (unsigned)copied ? clone_from[r_from[k]] : n - 1u;
                us[key][p]++;
            }
        }
        double   worst = 0.0;
        unsigned bad = 0;
        for (unsigned k = 0; k < n; k++)
            for (unsigned p = 0; p < n; p++) {
                double d = z(us[k][p], go[k * n + p], t);
                if (d > worst)
                    worst = d;
                if (d > 6.0)
                    bad++;
            }
        char what[160];
        snprintf(what, sizeof what, "%s: every key at every position as in Go (worst %.1f SE)",
                 which == 0 ? "make(map, 15), fifteen keys" : which == 1
                                  ? "a redirect's map, fifteen headers and the referer"
                                  : "a redirect's map to another domain, the cookie left behind",
                 worst);
        ok(bad == 0, what);
    }

    /* The spider's draw at the sizes a path set reaches (tools/gomap, draws): which key a walk to a
     * uniform index below len-1 lands on, for maps grown key by key past the first split and for
     * one made with a hint of four tables. Every bin within six standard errors of Go's, and the
     * bins together within six of what two samples of one distribution give — and every walk
     * visiting every key once. */
    printf("\nthe draw at the sizes a path set reaches, against Go\n");
    for (unsigned si = 0; si < GOMAP_DRAW_SIZES; si++) {
        unsigned  n = gomap_draw_size[si];
        unsigned  hint = si + 1u == GOMAP_DRAW_SIZES ? n : 0u;
        uint64_t *hash = malloc(n * sizeof *hash);
        unsigned *order = malloc(n * sizeof *order);
        uint32_t *draw = calloc(n, sizeof *draw);
        uint8_t  *seen = malloc(n);
        int       whole = hash != NULL && order != NULL && draw != NULL && seen != NULL;
        for (unsigned trial = 0; whole && trial < GOMAP_DRAW_TRIALS; trial++) {
            uint64_t off[3];
            (void)lc_rnd((uint8_t *)hash, n * sizeof *hash);
            (void)lc_rnd((uint8_t *)off, sizeof off);
            if (lc_gomap_order(hash, n, hint, off[0], off[1], order) != 0) {
                whole = 0;
                break;
            }
            if (trial < 50u) {
                memset(seen, 0, n);
                for (unsigned p = 0; p < n; p++)
                    whole &= order[p] < n && !seen[order[p]]++;
            }
            draw[order[off[2] % (n - 1u)]]++;
        }
        double worst = 0.0, sum = 0.0;
        for (unsigned k = 0; whole && k < n; k++) {
            double d = z(draw[k], gomap_draw[si][k], (double)GOMAP_DRAW_TRIALS);
            sum += d * d;
            if (d > worst)
                worst = d;
        }
        char what[200];
        snprintf(what, sizeof what,
                 "%4u keys%s: each key drawn as often as in Go (worst %.1f SE, together %.0f for %u)",
                 n, hint != 0u ? ", make(map, n)" : "", worst, sum, n);
        ok(whole && worst <= 6.0 && sum <= (double)n + 6.0 * sqrt(2.0 * n), what);
        free(hash);
        free(order);
        free(draw);
        free(seen);
    }

    /* THE STRUCTURE, which the statistics above cannot see — see the top of this file. Maps built
     * key by key and with hints, at the sizes above and past them, and in each: every key where
     * Go's lookup looks for it — the table the top bits of its hash pick in the directory, then
     * groups from h1 = hash >> 7 on the triangular probe sequence, never past a group with a free
     * slot (GOROOT/src/internal/runtime/maps/map.go:338-343, :407-424,
     * GOROOT/src/internal/runtime/maps/table.go:164-223, :1280-1292); every directory entry inside
     * its table's aligned range; and one table, grown in place, until the 897th key: the first
     * split comes when a table of 1024 is full, and none is ever larger
     * (GOROOT/src/internal/runtime/maps/table.go:83-85, :1145-1167). */
    printf("\nthe structure: where Go's lookup finds each key, and the directory\n");
    {
        static const unsigned sizes[] = { 1, 8, 9, 57, 448, 449, 896, 897, 1800, 3600, 12000, 40000 };
        static const unsigned hints[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 897, 1800, 3600 };
        int bad = 0, maps = 0;
        for (unsigned si = 0; si < sizeof hints / sizeof hints[0]; si++) {
            unsigned  n = si < sizeof sizes / sizeof sizes[0] ? sizes[si] : hints[si] + 700u;
            unsigned  hint = hints[si];
            uint64_t *hash = malloc(n * sizeof *hash);
            if (hash == NULL)
                return 1;
            for (unsigned trial = 0; trial < 20u; trial++, maps++) {
                (void)lc_rnd((uint8_t *)hash, n * sizeof *hash);
                gmap m;
                memset(&m, 0, sizeof m);
                for (unsigned i = 0; i < GROUP; i++)
                    m.group[i] = -1;
                m.hash = hash;
                int rc = make_map(&m, hint);
                for (unsigned k = 0; k < n && rc == 0; k++)
                    rc = put(&m, (int32_t)k);
                if (rc != 0) {
                    bad++;
                    unmake(&m);
                    continue;
                }
                if (hint == 0u && !m.small && (m.depth == 0u) != (n <= 896u))
                    bad++;
                for (uint64_t d = 0; !m.small && d < (1ull << m.depth); d++) {
                    const table *td = m.dir[d];
                    uint64_t     span = 1ull << (m.depth - td->local_depth);
                    if (td->index < 0 || (uint64_t)td->index % span != 0u || d < (uint64_t)td->index ||
                        d >= (uint64_t)td->index + span || td->cap > MAX_TABLE)
                        bad++;
                }
                for (unsigned k = 0; k < n; k++) {
                    int found = 0;
                    if (m.small) {
                        for (unsigned i = 0; i < GROUP; i++)
                            found |= m.group[i] == (int32_t)k;
                    } else {
                        uint64_t     h = hash[k];
                        const table *tk = m.dir[m.depth == 0u ? 0u : h >> (64u - m.depth)];
                        uint64_t     mask = tk->cap / GROUP - 1u, off = (h >> 7) & mask;
                        for (uint64_t step = 0; step <= mask && !found;) {
                            int free_slot = 0;
                            for (unsigned s = 0; s < GROUP; s++) {
                                found |= tk->slot[off * GROUP + s] == (int32_t)k;
                                free_slot |= tk->slot[off * GROUP + s] < 0;
                            }
                            if (free_slot)
                                break;
                            step++;
                            off = (off + step) & mask;
                        }
                    }
                    if (!found)
                        bad++;
                }
                unmake(&m);
            }
            free(hash);
        }
        char what[120];
        snprintf(what, sizeof what, "%d maps of 1 to 40000 keys: each key where Go looks, the directory Go's",
                 maps);
        ok(bad == 0, what);
    }

    /* And past them: a path set nothing bounds, at sizes of dozens of tables, where nothing holds
     * the draw but the walk itself — every key once.
     *
     * ONE BRANCH OF THE MODEL NO SIZE REACHES: a table splitting while the directory is two levels
     * deeper than it, when its twin no longer sits next to it. With a hash as uniform as Go's that
     * takes one prefix holding twice the keys of another of the same length, and at the sizes where
     * tables split the spread is a few percent. It is Go's branch, transcribed, and held to nothing. */
    printf("\npast them: dozens of tables\n");
    {
        static const unsigned big[] = { 12000u, 40000u };
        for (unsigned bi = 0; bi < sizeof big / sizeof big[0]; bi++) {
            unsigned  n = big[bi];
            uint64_t *hash = malloc(n * sizeof *hash);
            unsigned *order = malloc(n * sizeof *order);
            uint8_t  *seen = malloc(n);
            int       whole = hash != NULL && order != NULL && seen != NULL;
            for (unsigned trial = 0; whole && trial < 60u; trial++) {
                uint64_t off[2];
                (void)lc_rnd((uint8_t *)hash, n * sizeof *hash);
                (void)lc_rnd((uint8_t *)off, sizeof off);
                if (lc_gomap_order(hash, n, 0, off[0], off[1], order) != 0) {
                    whole = 0;
                    break;
                }
                memset(seen, 0, n);
                for (unsigned p = 0; p < n; p++)
                    whole &= order[p] < n && !seen[order[p]]++;
            }
            char what[120];
            snprintf(what, sizeof what, "%5u keys: every walk visits every key once, 60 maps", n);
            ok(whole, what);
            free(hash);
            free(order);
            free(seen);
        }
    }

    printf("\n%s\n", failures == 0 ? "the walk is Go's" : "THE WALK IS NOT GO'S");
    return failures == 0 ? 0 : 1;
}
