/* Matched before/after CPU cost of real path draws and full header-map walks.
 * Entropy is deterministic so the output checksum also guards choice behavior.
 * This microbenchmark does not measure network throughput or close G2. */
#include "../../src/reality/paths.c"

#include <inttypes.h>
#include <sys/random.h>
#include <time.h>

static uint64_t rng = 1;

ssize_t getrandom(void *out, size_t n, unsigned int flags)
{
    (void)flags;
    uint8_t *p = out;
    for (size_t i = 0; i < n; i++) {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        p[i] = (uint8_t)rng;
    }
    return (ssize_t)n;
}

static uint64_t cpu_ns(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t) != 0)
        exit(1);
    return (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec;
}

static void paths(unsigned n, unsigned repetitions)
{
    char host[64];
    snprintf(host, sizeof host, "bench-%u.example", n);
    if (store_lock() != 0)
        exit(1);
    name_set *s = set_for(host);
    if (s == NULL)
        exit(1);
    for (unsigned i = 1; i < n; i++) {
        char key[32];
        int len = snprintf(key, sizeof key, "/h%u", i - 1u);
        if (len < 0 || add(s, (const uint8_t *)key, (size_t)len) != 0)
            exit(1);
    }
    store_unlock();
    uint64_t checksum = 0, start = cpu_ns();
    for (unsigned i = 0; i < repetitions; i++) {
        char *path = NULL;
        size_t len = 0;
        if (lc_spider_path(host, &path, &len) != 0)
            exit(1);
        for (size_t j = 0; j < len; j++)
            checksum = checksum * 33u + (uint8_t)path[j];
        free(path);
    }
    printf("BENCH path %u %u %" PRIu64 " %" PRIu64 "\n",
           n, repetitions, cpu_ns() - start, checksum);
}

static void headers(unsigned n, unsigned repetitions)
{
    uint64_t hashes[LC_GOMAP_KEYS];
    unsigned order[LC_GOMAP_KEYS];
    if (lc_rnd((uint8_t *)hashes, (size_t)n * sizeof hashes[0]) != 0)
        exit(1);
    uint64_t checksum = 0, start = cpu_ns();
    for (unsigned i = 0; i < repetitions; i++) {
        if (lc_gomap_order(hashes, n, 0, i, (uint64_t)i * 7u, order) != 0)
            exit(1);
        for (unsigned j = 0; j < n; j++)
            checksum = checksum * 33u + order[j];
    }
    printf("BENCH header %u %u %" PRIu64 " %" PRIu64 "\n",
           n, repetitions, cpu_ns() - start, checksum);
}

int main(void)
{
    paths(2u, 20000u);
    paths(8u, 20000u);
    paths(21u, 10000u);
    paths(128u, 3000u);
    paths(1024u, 500u);
    headers(3u, 20000u);
    headers(14u, 20000u);
    headers(21u, 10000u);
    return 0;
}
