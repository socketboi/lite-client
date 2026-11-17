#include "core/rnd.h"

#include <errno.h>
#include <sys/random.h>

int lc_rnd(uint8_t *out, size_t n)
{
    size_t done = 0;
    while (done < n) {
        /* getrandom returns short reads for large requests and can be interrupted; both are normal
         * and neither means failure, so only a real error ends the loop. */
        ssize_t r = getrandom(out + done, n - done, 0);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        done += (size_t)r;
    }
    return 0;
}

int lc_rnd_grease(uint16_t *out)
{
    uint8_t b;
    if (lc_rnd(&b, 1) != 0)
        return -1;
    uint16_t v = (uint16_t)((b & 0xf0) | 0x0a);
    *out = (uint16_t)((v << 8) | v);
    return 0;
}

/* Uniform in [0, n), by rejection rather than by remainder. The reference draws with Go's
 * rand.Rand.Intn and rand.Shuffle, both of which reject (math/rand int31n is Lemire's method with a
 * rejection loop), and a plain remainder would tilt the low indices — invisible in one hello and
 * exactly the kind of skew a census of many would find.
 *
 * Lived in tls/client.c as a static, for the cookie insert. It is here because the extension
 * shuffle in fp/hello.c draws the same way for the same reason, and two copies of a sampler are two
 * places for the bound to be written wrong. */
int lc_rnd_below(size_t n, size_t *out)
{
    if (n == 0u || n > 0xFFFFFFFFu)
        return -1;
    uint32_t bound = (uint32_t)n;
    /* 2 to the 32 modulo bound, written so it fits in 32 bits. */
    uint32_t threshold = (uint32_t)(((0xFFFFFFFFu % bound) + 1u) % bound);
    for (;;) {
        uint8_t b[4];
        if (lc_rnd(b, sizeof b) != 0)
            return -1;
        uint32_t r = (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | b[3];
        if (r >= threshold) {
            *out = r % bound;
            return 0;
        }
    }
}
