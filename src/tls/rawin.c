/* uTLS's rawInput, its shape only — see tls/rawin.h. Everything below is Go's, go1.27.1: bytes.Buffer
 * (GOROOT/src/bytes/buffer.go) and the allocator's rounding that growSlice's append gets
 * (GOROOT/src/runtime/msize.go:16-36, GOROOT/src/internal/runtime/gc/sizeclasses.go). */
#include "tls/rawin.h"

/* bytes.MinRead (GOROOT/src/bytes/buffer.go:218). */
#define MIN_READ 512u

/* The size classes a small object is rounded to — SizeClassToSize (GOROOT/src/internal/runtime/gc/sizeclasses.go:98). The two
 * lookup tables beside it map a size to the smallest class that holds it, which is what the search
 * below finds; test/rawin holds the result to the runtime's, length by length. */
static const uint16_t size_classes[] = {
    0,     8,     16,    24,    32,    48,    64,    80,    96,    112,   128,   144,
    160,   176,   192,   208,   224,   240,   256,   288,   320,   352,   384,   416,
    448,   480,   512,   576,   640,   704,   768,   896,   1024,  1152,  1280,  1408,
    1536,  1792,  2048,  2304,  2688,  3072,  3200,  3456,  4096,  4864,  5376,  6144,
    6528,  6784,  6912,  8192,  9472,  9728,  10240, 10880, 12288, 13568, 14336, 16384,
    18432, 19072, 20480, 21760, 24576, 27264, 28672, 32768,
};

/* roundupsize(size, noscan = true), for a []byte: a small object to its class, and past
 * maxSmallSize - MallocHeaderSize to the next page of 8 KiB (GOROOT/src/runtime/msize.go:16-36). From 32 761 to 32 768
 * both give 32 768, so where the bound lies cannot be seen from outside; it is Go's. */
size_t lc_rawin_roundup(size_t c)
{
    if (c <= 32768u - 8u) {
        for (unsigned i = 0; i < sizeof size_classes / sizeof size_classes[0]; i++)
            if (size_classes[i] >= c)
                return size_classes[i];
    }
    return (c + 8191u) & ~(size_t)8191u;
}

size_t lc_rawin_len(const lc_rawin *r)
{
    return r->len - r->off;
}

size_t lc_rawin_cap(const lc_rawin *r)
{
    return r->cap;
}

/* Reset (GOROOT/src/bytes/buffer.go:124-128). */
static void reset(lc_rawin *r)
{
    r->len = 0;
    r->off = 0;
}

/* grow (GOROOT/src/bytes/buffer.go:144-175): where the next n bytes go, the buffer made to hold them. Go's first
 * allocation of a nil buffer asking for at most smallBufferSize is not here: the only calls are
 * readFromUntil's, whose Grow asks for MinRead and more on a nil buffer, and a nil buffer never
 * sees another. */
static size_t grow(lc_rawin *r, size_t n)
{
    size_t m = lc_rawin_len(r);
    if (m == 0u && r->off != 0u)
        reset(r);
    /* tryGrowByReslice (GOROOT/src/bytes/buffer.go:133-139) */
    if (n <= r->cap - r->len) {
        size_t l = r->len;
        r->len = l + n;
        return l;
    }
    size_t c = r->cap;
    if ((int64_t)n <= (int64_t)(c / 2u) - (int64_t)m) {
        /* Slid down to the front; the capacity stays. */
    } else {
        /* growSlice(b.buf[b.off:], b.off+n) (GOROOT/src/bytes/buffer.go:247-270): len(b) + n, at least twice
         * cap(b), rounded by the allocator. */
        size_t have = c - r->off;
        size_t want = m + r->off + n;
        if (want < 2u * have)
            want = 2u * have;
        r->cap = lc_rawin_roundup(want);
    }
    r->off = 0;
    r->len = m + n;
    return m;
}

size_t lc_rawin_ask(lc_rawin *r, size_t n)
{
    if (!r->until) {
        /* readFromUntil (vendor/utls/conn.go:808-841): nothing to read when the buffer holds n,
         * else Grow(needs + MinRead) once, then read into AvailableBuffer until needs is met. */
        size_t have = lc_rawin_len(r);
        if (have >= n)
            return 0;
        size_t needs = n - have;
        /* Grow (GOROOT/src/bytes/buffer.go:182-188) */
        r->len = grow(r, needs + MIN_READ);
        r->until = 1;
        r->left = (int64_t)needs;
    }
    /* vendor/utls/conn.go:822-825 no longer calls bytes.Buffer.ReadFrom, which
     * grew by MinRead on every iteration. A fragmented read now keeps the
     * remaining capacity established by the initial Grow. */
    return r->cap - r->len;
}

void lc_rawin_got(lc_rawin *r, size_t got)
{
    r->len += got;
    r->left -= (int64_t)got;
    /* readFromUntil returns once needs is met (vendor/utls/conn.go:827-831). */
    if (r->left <= 0)
        r->until = 0;
}

/* Next (GOROOT/src/bytes/buffer.go:358-370) */
void lc_rawin_next(lc_rawin *r, size_t n)
{
    size_t m = lc_rawin_len(r);
    if (n > m)
        n = m;
    r->off += n;
}
