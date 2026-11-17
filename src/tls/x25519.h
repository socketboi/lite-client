#ifndef LC_X25519_H
#define LC_X25519_H

#include <stdint.h>

/* X25519, computed with arithmetic written for 2^255-19 instead of a general-purpose bignum.
 *
 * WHY THIS EXISTS, AS A NUMBER. A REALITY handshake needs THREE scalar multiplications on this
 * curve: one to generate the ephemeral key, one for the TLS exchange, and one against the node's
 * static key, which is how REALITY authenticates (src/reality/reality.h). Through mbedTLS's generic
 * ECP ladder each of them costs 16.4 ms on the router this client is for (Xiaomi 4A, MT7621,
 * mipsel_24kc, test/bench/bench_kex.c) — 49 ms, and after the Ed25519 work of 2026-09-20 that is
 * HALF of everything a handshake spends on asymmetric work.
 *
 * The cost is structural and it is not mbedTLS being careless. Its ladder is the right one and its
 * reduction for this prime is the right fold; what it costs is that every field operation is a
 * handful of mbedtls_mpi calls over a heap-allocated, variable-length number. Measured two ways
 * that agree: this client's own Ed25519 does about 7 500 field operations in 47.95 ms, and mbedTLS's
 * ladder does about 2 550 in 16.4 ms — 6.4 microseconds each, both times.
 *
 * ⚠️ THIS IS NOT NEW CRYPTOGRAPHY AND IT IS NOT AN INVENTION. The representation is the one every
 * implementation of this curve on a 32-bit machine uses, down to the limb widths: ten limbs of
 * alternating 26 and 25 bits, the layout of djb's ref10. The reference reaches the same arithmetic
 * by two routes, and REALITY uses both: the TLS key exchange goes through Go's crypto/ecdh
 * (vendor/REALITY/key_agreement.go:9, vendor/REALITY/key_schedule.go:9) and the authentication
 * key through golang.org/x/crypto/curve25519 (vendor/REALITY/tls.go:55,
 * vendor/REALITY/tls.go:240), which since Go 1.20 is a wrapper over that same crypto/ecdh.
 * Underneath both is filippo.io's edwards25519 field, which is this with 64-bit limbs.
 * Nothing about the wire changes: X25519 has one answer and this computes the same one.
 *
 * WHAT IT BOUGHT, on that box: 16.40 ms per scalar multiplication became 5.30, so the three a
 * handshake needs went from 49 ms to 16 and a whole handshake from 135 ms to 69 — the four rows of
 * test/bench/bench_kex.c added up, which is where both totals come from.
 *
 * WHAT MAKES IT SAFE TO BELIEVE. test/x25519 runs RFC 7748 §5.2's vectors and its iterated §5.2
 * check, and then a DIFFERENTIAL test: random scalars and random points, both through this and
 * through the mbedTLS this build already links, asserting byte equality. A field implementation
 * that is wrong is wrong on almost every input, so a few hundred random pairs is not a formality.
 *
 * Constant time with respect to the scalar: the ladder does the same operations for every bit and
 * the conditional swap is a mask, never a branch. That matters because two of the three scalar
 * multiplications use a secret key. */

#define LC_X25519_LEN 32u

/* out = scalar * u, and out = scalar * 9. The scalar is clamped here, as RFC 7748 §5 requires, so
 * a caller hands over the 32 bytes it drew and nothing else; clamping twice changes nothing, which
 * matters because lc_x25519_keygen clamps its own copy for REALITY to use.
 *
 * ⚠️ NO POLICY HERE, DELIBERATELY. An all-zero result must be refused (RFC 7748 §6.1) and the top
 * bit of a received u must be ignored (§5) — the first is done by the one caller that performs a
 * Diffie-Hellman, src/tls/kex.c, where it already was, and the second falls out of the
 * representation below. These two do the arithmetic and nothing else, so there is one place that
 * decides what a peer is allowed to send rather than two that could disagree.
 *
 * `out` may alias neither input. */
void lc_x25519_mul(uint8_t out[LC_X25519_LEN], const uint8_t scalar[LC_X25519_LEN],
                   const uint8_t u[LC_X25519_LEN]);
void lc_x25519_basemul(uint8_t out[LC_X25519_LEN], const uint8_t scalar[LC_X25519_LEN]);

#endif
