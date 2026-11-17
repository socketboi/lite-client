/* Cold simultaneous constructors must publish the fixed table before use.
 * Fixture width is a test workload, not a client concurrency or RAM limit. */
#include "core/gozip.h"
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#define WORKERS 8u
#define ROUNDS 32u

typedef struct {
    const uint8_t *input, *expected;
    size_t input_len, expected_len, offset;
    pthread_barrier_t *start;
    int failed;
} worker;

static void require(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
    printf("  ok    %s\n", message);
}

static int source(void *ctx, size_t cap, const uint8_t **data, size_t *len, int *err)
{
    worker *w = ctx;
    size_t left = w->input_len - w->offset;
    *len = left < cap ? left : cap;
    *data = w->input + w->offset;
    *err = left == 0u ? LC_GZ_EOF : LC_GZ_NONE;
    w->offset += *len;
    return 0;
}

static void *decode(void *arg)
{
    worker *w = arg;
    int ready = pthread_barrier_wait(w->start);
    if (ready != 0 && ready != PTHREAD_BARRIER_SERIAL_THREAD) {
        w->failed = 1;
        return NULL;
    }
    for (unsigned round = 0; round < ROUNDS; round++) {
        w->offset = 0u;
        lc_gozip *z = lc_gozip_new(source, w);
        if (z == NULL) {
            w->failed = 1;
            return NULL;
        }
        size_t total = 0u;
        int done = 0;
        for (unsigned call = 0; call < 32u && !done; call++) {
            const uint8_t *data;
            size_t len;
            int err = LC_GZ_NONE;
            int rc = lc_gozip_read(z, 257u, &data, &len, &err);
            if (rc != 0 || len > w->expected_len - total ||
                memcmp(data, w->expected + total, len) != 0 ||
                (err != LC_GZ_NONE && err != LC_GZ_EOF) ||
                (len == 0u && err == LC_GZ_NONE)) {
                w->failed = 1;
                break;
            }
            total += len;
            done = err == LC_GZ_EOF;
        }
        if (!done || total != w->expected_len)
            w->failed = 1;
        lc_gozip_free(z);
        if (w->failed)
            return NULL;
    }
    return NULL;
}

int main(void)
{
    uint8_t plain[4096], wire[8192];
    for (size_t i = 0; i < sizeof plain; i++)
        plain[i] = (uint8_t)('a' + i % 23u);
    z_stream z = {0};
    require(deflateInit2(&z, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 31, 8, Z_FIXED) == Z_OK,
            "fixed-Huffman gzip fixture encoder");
    z.next_in = plain;
    z.avail_in = (uInt)sizeof plain;
    z.next_out = wire;
    z.avail_out = (uInt)sizeof wire;
    require(deflate(&z, Z_FINISH) == Z_STREAM_END && z.total_out > 10u &&
                ((wire[10] >> 1) & 3u) == 1u,
            "fixture actually uses the shared fixed-Huffman table");
    size_t wire_len = z.total_out;
    require(deflateEnd(&z) == Z_OK, "fixture encoder closes");
    pthread_barrier_t start;
    require(pthread_barrier_init(&start, NULL, WORKERS + 1u) == 0, "cold-constructor start barrier");
    pthread_t threads[WORKERS];
    worker jobs[WORKERS];
    for (unsigned i = 0; i < WORKERS; i++) {
        jobs[i] = (worker){ .input = wire, .input_len = wire_len,
                           .expected = plain, .expected_len = sizeof plain, .start = &start };
        require(pthread_create(&threads[i], NULL, decode, &jobs[i]) == 0,
                "parallel decoder worker created before any C gzip constructor");
    }
    int ready = pthread_barrier_wait(&start);
    require(ready == 0 || ready == PTHREAD_BARRIER_SERIAL_THREAD, "all cold constructors released");
    for (unsigned i = 0; i < WORKERS; i++)
        require(pthread_join(threads[i], NULL) == 0 && !jobs[i].failed,
                "independent decoder preserves every byte, trailer and EOF across 32 lifetimes");
    require(pthread_barrier_destroy(&start) == 0, "all decoder workers joined before fixture release");
    printf("parallel gzip: %u cold workers, %u complete decoder lifetimes\n", WORKERS, WORKERS * ROUNDS);
    return 0;
}
