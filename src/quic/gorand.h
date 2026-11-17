/* Go's math/rand, as Salamander draws its salt from it.
 *
 * The reference does not take the salt from a cryptographic source. newSalamanderObfuscator builds
 * `RandSrc: rand.New(rand.NewSource(time.Now().UnixNano()))` once per obfuscated connection, and
 * Obfuscate takes the eight bytes of every packet with `o.RandSrc.Read(out[:smSaltLen])`
 * (vendor/hysteria/extras/obfs/salamander.go:43 and :65). So the salts on the wire are one stream
 * of Go's additive lagged Fibonacci generator, and this is that generator: rngSource and the byte
 * reader of Rand, from the toolchain the reference is built with (GOROOT/src/math/rand/rng.go and
 * rand.go, at the GO_VERSION docker/Dockerfile installs).
 *
 * Only the calls a reference makes are here: NewSource(seed), Read, and Float64 for Xray's
 * browser identity. Everything signed in
 * the original wraps on overflow, which C does not promise for signed types, so the arithmetic is
 * done in uint64_t — the same bits. */
#ifndef LC_QGORAND_H
#define LC_QGORAND_H

#include <stddef.h>
#include <stdint.h>

#define LC_GORAND_LEN 607 /* rngLen */

typedef struct {
    int      tap, feed;
    uint64_t vec[LC_GORAND_LEN];
    /* Rand's readVal and readPos: the bytes of the last Int63 not yet handed out. */
    uint64_t read_val;
    int      read_pos;
} lc_gorand;

/* rand.New(rand.NewSource(seed)). */
void lc_gorand_seed(lc_gorand *r, int64_t seed);

/* (*Rand).Float64 — what Xray's globalRng is asked for when it picks the Chrome version
 * (vendor/Xray-core/common/utils/browser.go:30), see reality/browser.c. */
double lc_gorand_float64(lc_gorand *r);

/* (*Rand).Read: seven bytes of each Int63, low byte first, carried across calls. */
void lc_gorand_read(lc_gorand *r, uint8_t *p, size_t n);

#endif
