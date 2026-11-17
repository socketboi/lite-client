/* Exact orders from Go 1.27.1 Iter.Next, then the real path draw with scripted
 * entropy. This observes choice, not a small sample's selected-path frequency.
 * The reference is reality.go::getPathLocked and crypto.go::RandBetween: choose
 * a walk position below len-1, retaining root as an ordinary eligible key. */
#include "../../src/reality/paths.c"
#include "spiderchoice_vectors.h"

#include <sys/random.h>

static unsigned failures;
static int scripted, entropy_error;
static unsigned stage;
static uint32_t samples[2];
static unsigned sample_count;
static uint64_t offsets[2];
static uint32_t setup_rng = 1u;

/* Fail each real map-layout allocation in turn and check that cleanup frees
 * every successful allocation. Track caller-level requests only: static musl
 * can call wrapped malloc/free inside calloc/realloc. These wrappers are linked
 * only into this single-threaded test. */
void *__real_malloc(size_t n);
void *__real_calloc(size_t n, size_t size);
void *__real_realloc(void *p, size_t n);
void __real_free(void *p);
static int tracking, live_allocations;
static unsigned allocation_calls, fail_at;

static int allocation_fails(void)
{
    if (!tracking)
        return 0;
    allocation_calls++;
    return fail_at != 0u && allocation_calls == fail_at;
}

void *__wrap_malloc(size_t n)
{
    if (allocation_fails())
        return NULL;
    int active = tracking;
    tracking = 0;
    void *p = __real_malloc(n);
    tracking = active;
    if (tracking && p != NULL)
        live_allocations++;
    return p;
}

void *__wrap_calloc(size_t n, size_t size)
{
    if (allocation_fails())
        return NULL;
    int active = tracking;
    tracking = 0;
    void *p = __real_calloc(n, size);
    tracking = active;
    if (tracking && p != NULL)
        live_allocations++;
    return p;
}

void *__wrap_realloc(void *p, size_t n)
{
    if (allocation_fails())
        return NULL;
    int fresh = p == NULL;
    int active = tracking;
    tracking = 0;
    void *q = __real_realloc(p, n);
    tracking = active;
    if (tracking && fresh && q != NULL)
        live_allocations++;
    return q;
}

void __wrap_free(void *p)
{
    if (tracking && p != NULL)
        live_allocations--;
    int active = tracking;
    tracking = 0;
    __real_free(p);
    tracking = active;
}

/* Supply the real rnd.c sampler; do not replace lc_rnd_below with a test model. */
ssize_t getrandom(void *out, size_t n, unsigned int flags)
{
    (void)flags;
    if (entropy_error) {
        errno = EIO;
        return -1;
    }
    if (scripted) {
        if (stage < sample_count && n == 4u) {
            uint32_t sample = samples[stage];
            uint8_t *b = out;
            b[0] = (uint8_t)(sample >> 24);
            b[1] = (uint8_t)(sample >> 16);
            b[2] = (uint8_t)(sample >> 8);
            b[3] = (uint8_t)sample;
        } else if (stage == sample_count && n == sizeof offsets) {
            memcpy(out, offsets, n);
        } else {
            errno = EIO;
            return -1;
        }
        stage++;
    } else {
        uint8_t *b = out;
        for (size_t i = 0; i < n; i++) {
            setup_rng ^= setup_rng << 13;
            setup_rng ^= setup_rng >> 17;
            setup_rng ^= setup_rng << 5;
            b[i] = (uint8_t)setup_rng;
        }
    }
    return (ssize_t)n;
}

static void check(int pass, const char *what)
{
    printf("  %s  %s\n", pass ? "ok" : "FAIL", what);
    failures += !pass;
}

static int install(const char *host, const struct choice_map *m)
{
    if (store_lock() != 0)
        return 0;
    name_set *s = set_for(host);
    int good = s != NULL;
    for (unsigned i = 1; good && i < m->n; i++) {
        char key[32];
        int n = snprintf(key, sizeof key, "/h%u", i - 1u);
        good = add(s, (const uint8_t *)key, (size_t)n) == 0;
    }
    good = good && s->count == m->n;
    if (good)
        memcpy(AT(s->hash, uint64_t), m->hash, (size_t)m->n * sizeof *m->hash);
    store_unlock();
    return good;
}

static int choose(const char *host, const struct choice_map *m, unsigned wi, unsigned rank, int reject)
{
    unsigned bound = m->n - 1u;
    uint32_t sample = rank;
    if (bound != 0u) {
        uint32_t threshold = (uint32_t)(((UINT32_MAX % bound) + 1u) % bound);
        while (sample < threshold)
            sample += bound;
    }
    sample_count = reject ? 2u : 1u;
    samples[0] = reject ? 0u : sample;
    samples[sample_count - 1u] = sample;
    stage = 0;
    offsets[0] = m->walk[wi].entry;
    offsets[1] = m->walk[wi].dir;
    scripted = 1;
    char *path = NULL;
    size_t len = 0;
    int rc = lc_spider_path(host, &path, &len);
    scripted = 0;
    unsigned key = m->walk[wi].order[rank];
    char want[32];
    int n = key == 0u ? snprintf(want, sizeof want, "/") :
                       snprintf(want, sizeof want, "/h%u", key - 1u);
    int good = rc == 0 && len == (size_t)n && path != NULL && strcmp(path, want) == 0 &&
               stage == (m->n == 1u ? 0u : sample_count + 1u);
    free(path);
    return good;
}

int main(void)
{
    puts("spider choice: exact pinned Go iterator orders and the public path draw");
    char populated_host[64] = {0};
    for (unsigned mi = 0; mi < CHOICE_MAPS; mi++) {
        const struct choice_map *m = &choice_maps[mi];
        unsigned *order = malloc((size_t)m->n * sizeof *order);
        int good = order != NULL;
        for (unsigned wi = 0; good && wi < m->walks; wi++) {
            memset(order, 0xff, (size_t)m->n * sizeof *order);
            good = lc_gomap_order(m->hash, m->n, 0, m->walk[wi].entry, m->walk[wi].dir, order) == 0 &&
                   memcmp(order, m->walk[wi].order, (size_t)m->n * sizeof *order) == 0;
        }
        char what[160];
        snprintf(what, sizeof what, "map %u, %u keys: all %u exact Go 1.27 iterator orders", mi, m->n, m->walks);
        check(good, what);
        good = 1;
        for (unsigned wi = 0; good && wi < m->walks; wi++) {
            unsigned ranks[] = {0u, 1u, 7u, 8u, m->n / 2u, m->n - 1u};
            unsigned checks = m->n <= 21u ? m->n : (unsigned)(sizeof ranks / sizeof ranks[0]);
            for (unsigned ri = 0; good && ri < checks; ri++) {
                unsigned rank = m->n <= 21u ? ri : ranks[ri];
                if (rank >= m->n)
                    continue;
                unsigned key = ~0u;
                good = lc_gomap_at(m->hash, m->n, 0u, m->walk[wi].entry,
                                   m->walk[wi].dir, rank, &key) == 0 &&
                       key == m->walk[wi].order[rank];
            }
        }
        snprintf(what, sizeof what, "map %u: single-position walks match exact Go keys including the final rank", mi);
        check(good, what);
        good = 1;
        unsigned hints[] = {m->n, 2u * m->n + 1u};
        for (unsigned hi = 0; good && hi < (unsigned)(sizeof hints / sizeof hints[0]); hi++) {
            for (unsigned wi = 0; good && wi < m->walks; wi++) {
                good = lc_gomap_order(m->hash, m->n, hints[hi], m->walk[wi].entry,
                                      m->walk[wi].dir, order) == 0;
                unsigned ranks[] = {0u, m->n / 2u, m->n - 1u};
                for (unsigned ri = 0; good && ri < (unsigned)(sizeof ranks / sizeof ranks[0]); ri++) {
                    unsigned key = ~0u;
                    good = lc_gomap_at(m->hash, m->n, hints[hi], m->walk[wi].entry,
                                       m->walk[wi].dir, ranks[ri], &key) == 0 && key == order[ranks[ri]];
                }
            }
        }
        snprintf(what, sizeof what, "map %u: hinted selection agrees with full walks through empty and aliased tables", mi);
        check(good, what);
        /* Exercise cleanup through growth and table/directory splits too. */
        allocation_calls = 0;
        fail_at = 0;
        live_allocations = 0;
        tracking = 1;
        unsigned selected = ~0u;
        int rc = lc_gomap_at(m->hash, m->n, 0u, 0u, 0u, 0u, &selected);
        tracking = 0;
        unsigned allocations = allocation_calls;
        good = rc == 0 && live_allocations == 0;
        for (unsigned failure = 1; good && failure <= allocations; failure++) {
            allocation_calls = 0;
            fail_at = failure;
            live_allocations = 0;
            selected = ~0u;
            tracking = 1;
            rc = lc_gomap_at(m->hash, m->n, 0u, 0u, 0u, 0u, &selected);
            tracking = 0;
            good = rc != 0 && selected == ~0u && live_allocations == 0;
        }
        fail_at = 0;
        snprintf(what, sizeof what, "map %u: every layout allocation failure releases earlier allocations", mi);
        check(good, what);
        free(order);
        if (m->n > 21u)
            continue;
        char host[64];
        snprintf(host, sizeof host, "choice-%u.example", mi);
        good = install(host, m);
        for (unsigned wi = 0; good && wi < m->walks; wi++)
            for (unsigned rank = 0; good && rank < (m->n > 1u ? m->n - 1u : 1u); rank++)
                good = choose(host, m, wi, rank, 0);
        snprintf(what, sizeof what, "map %u: real path sampler agrees at every allowed rank and controlled offset", mi);
        check(good, what);
        good = store_lock() == 0;
        if (good) {
            name_set *s = set_for(host);
            good = s != NULL && s->count == m->n &&
                   memcmp(AT(s->hash, uint64_t), m->hash, (size_t)m->n * sizeof *m->hash) == 0;
            store_unlock();
        }
        check(good, "draws preserve every cached hash and the member count");
        if (m->n == 21u) {
            snprintf(populated_host, sizeof populated_host, "%s", host);
            check(choose(host, m, 0u, 0u, 1),
                  "the real 20-position sampler rejects zero before selecting an allowed rank");
        }
    }
    entropy_error = 1;
    char *path = NULL;
    size_t len = 0;
    check(populated_host[0] != '\0' && lc_spider_path(populated_host, &path, &len) != 0 && path == NULL,
          "failed entropy does not silently select root from the populated 21-path cache");
    entropy_error = 0;
    unsigned untouched = 123u;
    check(lc_gomap_at(NULL, 0u, 0u, 0u, 0u, 0u, &untouched) != 0 && untouched == 123u,
          "an empty map has no selected position");
    const uint64_t one_hash = 0u;
    check(lc_gomap_at(&one_hash, 1u, 0u, 0u, 0u, 1u, &untouched) != 0 && untouched == 123u,
          "an out-of-range rank fails without changing the output");
    check(lc_gomap_at(&one_hash, 1u, 0u, 0u, 0u, 0u, NULL) != 0,
          "a missing output pointer is rejected");
    return failures != 0u;
}
