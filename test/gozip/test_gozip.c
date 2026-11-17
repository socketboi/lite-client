/* core/gozip against Go's own gzip reader.
 *
 * tools/gozip runs compress/gzip, the way x/net reads an answer through it, over a body that arrives
 * in pieces, and logs every Read of the body with what it asked for and what it got, every piece that
 * arrived because the reader was waiting for it, and every Read the consumer got back. This replays
 * each case on the C machine — a wait is the machine returning to say so, and the next piece arrives
 * then — and compares the whole log, the text that came out and how it ended.
 *
 * The body and the two consumers are the harness's, transcribed from the same Go the tool runs:
 * transportResponseBody's pipe and Content-Length check, io.ReadAll's slices, and
 * io.CopyN(io.Discard, body, 2048)'s LimitedReader over a buffer of 8192. */
#include "core/gozip.h"

#include "gozip_vectors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#define N_STREAMS (sizeof gz_streams / sizeof gz_streams[0])
#define N_CASES   (sizeof gz_cases / sizeof gz_cases[0])

enum { END_EOF, END_ERR, END_HANG };
enum { MODE_ALL, MODE_SLURP, MODE_PLAIN_ALL, MODE_PLAIN_SLURP };
enum { SCHED_WHOLE, SCHED_FIXED, SCHED_RANDOM };
enum { WAIT = 1 };

typedef struct {
    uint64_t s;
} rng;

static uint64_t rng_next(rng *r)
{
    r->s += 0x9e3779b97f4a7c15ull;
    uint64_t z = r->s;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}

typedef struct {
    const uint8_t *data;
    size_t         len;
    const struct gz_case *c;
    rng            r;
    size_t         at, rd; /* arrived, and read: the pipe is data[rd:at] */
    int64_t        remain;
    int            rerr;
    uint64_t       hash;
    uint32_t       events;
} body;

static void hash_u32(body *b, uint32_t v)
{
    for (int i = 0; i < 4; i++) {
        b->hash ^= (uint8_t)(v >> (8 * i));
        b->hash *= 0x100000001b3ull;
    }
}

static void event(body *b, char kind, uint32_t x, uint32_t y, int err)
{
    hash_u32(b, (uint32_t)kind);
    hash_u32(b, x);
    hash_u32(b, y);
    hash_u32(b, (uint32_t)err);
    b->events++;
}

/* The next piece to arrive: 0 when there is none. */
static size_t next_piece(body *b)
{
    size_t left = b->len - b->at;
    if (left == 0u)
        return 0;
    size_t k = left;
    if (b->c->sched == SCHED_FIXED)
        k = b->c->param;
    else if (b->c->sched == SCHED_RANDOM)
        k = 1u + (size_t)(rng_next(&b->r) % b->c->param);
    return k < left ? k : left;
}

/* transportResponseBody.Read over the pipe: WAIT when the pipe is empty and it has not ended. */
static int source(void *ctx, size_t cap, const uint8_t **p, size_t *n, int *err)
{
    body *b = ctx;
    *p = b->data + b->rd;
    *n = 0;
    *err = LC_GZ_NONE;
    if (b->rerr != LC_GZ_NONE) {
        *err = b->rerr;
    } else {
        if (b->rd == b->at) {
            if (b->at < b->len || b->c->end == END_HANG)
                return WAIT;
            *err = b->c->end == END_EOF ? LC_GZ_EOF : LC_GZ_ERR;
        } else {
            size_t k = cap < b->at - b->rd ? cap : b->at - b->rd;
            b->rd += k;
            *n = k;
        }
        if (b->remain != -1) {
            if ((int64_t)*n > b->remain) {
                *n = (size_t)b->remain;
                if (*err == LC_GZ_NONE)
                    *err = LC_GZ_ERR;
                b->rerr = *err;
            } else {
                b->remain -= (int64_t)*n;
                if (*err == LC_GZ_EOF && b->remain > 0) {
                    *err = LC_GZ_ERR;
                    b->rerr = *err;
                }
            }
        }
    }
    /* A zero-byte EOF/error need not carry a storage pointer. Exercise that source contract in
     * every oracle case, including gzip's buffered and direct reads. */
    if (*n == 0u)
        *p = NULL;
    event(b, 'R', (uint32_t)cap, (uint32_t)*n, *err);
    return 0;
}

/* The size class `append` rounds a fresh slice up to (GOROOT/src/runtime/msize.go, sizeclasses.go)
 * — io.ReadAll's next slice. */
static size_t go_roundup(size_t n)
{
    static const uint16_t classes[] = {
        8,     16,    24,    32,    48,    64,    80,    96,    112,   128,   144,   160,
        176,   192,   208,   224,   240,   256,   288,   320,   352,   384,   416,   448,
        480,   512,   576,   640,   704,   768,   896,   1024,  1152,  1280,  1408,  1536,
        1792,  2048,  2304,  2688,  3072,  3200,  3456,  4096,  4864,  5376,  6144,  6528,
        6784,  6912,  8192,  9472,  9728,  10240, 10880, 12288, 13568, 14336, 16384, 18432,
        19072, 20480, 21760, 24576, 27264, 28672, 32768,
    };
    if (n <= 32768u - 8u)
        for (size_t i = 0; i < sizeof classes / sizeof classes[0]; i++)
            if (classes[i] >= n)
                return classes[i];
    return (n + 8191u) & ~(size_t)8191u;
}

static int failures;

static void run(size_t ci)
{
    const struct gz_case *c = &gz_cases[ci];
    body b = { .data = gz_streams[c->stream].data, .len = gz_streams[c->stream].len, .c = c,
               .r = { c->seed }, .remain = c->remain, .hash = 0xcbf29ce484222325ull };
    int       gzip = c->mode == MODE_ALL || c->mode == MODE_SLURP;
    int       all = c->mode == MODE_ALL || c->mode == MODE_PLAIN_ALL;
    lc_gozip *z = gzip ? lc_gozip_new(source, &b) : NULL;
    if (gzip && z == NULL) {
        printf("  FAIL  gozip case %zu: no memory\n", ci);
        failures++;
        return;
    }

    /* The consumer: io.ReadAll's slices, or the slurp's LimitedReader. */
    size_t   cap = 512, len = 0, next = 256;
    int64_t  limit = 2048;
    uint32_t out_len = 0;
    uLong    crc = crc32(0L, Z_NULL, 0);
    int      final = 0;
    for (;;) {
        size_t want;
        if (all) {
            want = cap - len;
        } else {
            if (limit <= 0)
                break; /* LimitedReader: EOF without a Read */
            want = limit < 8192 ? (size_t)limit : 8192u;
        }
        const uint8_t *out;
        size_t         n;
        int            err, r;
        if (gzip)
            r = lc_gozip_read(z, want, &out, &n, &err);
        else
            r = source(&b, want, &out, &n, &err);
        if (r < 0) {
            printf("  FAIL  gozip case %zu: no memory\n", ci);
            failures++;
            lc_gozip_free(z);
            return;
        }
        if (r == WAIT) {
            size_t k = next_piece(&b);
            if (k == 0u) {
                event(&b, 'H', 0, 0, 0);
                final = 3;
                break;
            }
            b.at += k;
            event(&b, 'B', (uint32_t)k, 0, 0);
            continue;
        }
        event(&b, 'O', (uint32_t)want, (uint32_t)n, err);
        if (n > 0u)
            crc = crc32(crc, out, (uInt)n);
        out_len += (uint32_t)n;
        if (all) {
            len += n;
            if (err != LC_GZ_NONE) {
                final = err == LC_GZ_EOF ? 0 : 2;
                break;
            }
            if (cap - len < cap / 16u) {
                cap = go_roundup(next);
                len = 0;
                next += next / 2u;
            }
        } else {
            limit -= (int64_t)n;
            if (err != LC_GZ_NONE) {
                /* CopyN: all 2048 is no error whatever came with the last of it */
                final = limit <= 0 || err == LC_GZ_EOF ? 0 : 2;
                break;
            }
        }
    }
    lc_gozip_free(z);

    if (b.events != c->events || b.hash != c->hash || out_len != c->out_len ||
        (uint32_t)crc != c->out_crc || final != c->final) {
        if (failures < 30)
            printf("  FAIL  gozip case %zu (stream %u, %u bytes, mode %u, end %u, sched %u/%u): "
                   "events %u/%u hash %s, out %u/%u crc %s, final %d/%u\n",
                   ci, c->stream, gz_streams[c->stream].len, c->mode, c->end, c->sched, c->param,
                   b.events, c->events, b.hash == c->hash ? "ok" : "differs", out_len, c->out_len,
                   (uint32_t)crc == c->out_crc ? "ok" : "differs", final, c->final);
        failures++;
    }
}

int main(int argc, char **argv)
{
    if (argc > 1) {
        size_t ci = (size_t)strtoul(argv[1], NULL, 10);
        if (ci < N_CASES)
            run(ci);
        return failures != 0;
    }
    for (size_t ci = 0; ci < N_CASES; ci++)
        run(ci);
    if (failures != 0) {
        printf("  FAIL  gozip: %d of %zu cases\n", failures, (size_t)N_CASES);
        return 1;
    }
    printf("  ok    gozip: %zu cases over %zu streams — every Read of the body, every Read "
           "returned and the text match Go's\n",
           (size_t)N_CASES, (size_t)N_STREAMS);
    return 0;
}
