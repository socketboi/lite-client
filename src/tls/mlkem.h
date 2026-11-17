/* ML-KEM-768, the post-quantum half of the key exchange REALITY needs.
 *
 * Current browser fingerprints put X25519MLKEM768 first in key_share, and the REALITY server
 * follows the client's preference — so without ML-KEM there is no handshake, not merely a weaker
 * one. mbedTLS has no ML-KEM at all, which is why mlkem-native is vendored: portable C90, no
 * assembly backend required, memory safety proved with CBMC.
 *
 * Only two of the three KEM operations appear here. Encapsulation is what the server does with our
 * key; a client never runs it. Leaving it out is not an omission — it is the reason the interop
 * test drives decapsulation against a ciphertext produced elsewhere. */
#ifndef LC_MLKEM_H
#define LC_MLKEM_H

#include <stddef.h>
#include <stdint.h>

/* FIPS 203 sizes for ML-KEM-768.
 *
 * ⚠️ CITED, BECAUSE A HEADER IS WHERE THE SIEVE IS BLIND: it holds no code, so no finding is ever
 * made about it, and every number below decides a length on the wire. The vendored library states
 * the same four:
 *
 *     #define MLKEM768_SECRETKEYBYTES 2400
 *     #define MLKEM768_PUBLICKEYBYTES 1184
 *     #define MLKEM768_CIPHERTEXTBYTES 1088
 *              (vendor/mlkem-native/mlkem/mlkem_native.h:59-61)
 *
 * and the shared secret is MLKEM_SYMBYTES, 32 (vendor/mlkem-native/mlkem/mlkem_native.h:69). The
 * seed is not one of the library's names — it is the pair of 32-byte values FIPS 203 calls d and z,
 * which the deterministic entry point takes as one `coins[2 * MLKEM_SYMBYTES]` buffer
 * (vendor/mlkem-native/mlkem/mlkem_native.h:185-188); the split into d and z is cited where it is
 * used, in tls/mlkem.c. */
#define LC_MLKEM_SEED 64u
#define LC_MLKEM_EK 1184u
#define LC_MLKEM_DK 2400u
#define LC_MLKEM_CT 1088u
#define LC_MLKEM_SS 32u

/* Generates a key pair from fresh randomness. */
int lc_mlkem_keygen(uint8_t ek[LC_MLKEM_EK], uint8_t dk[LC_MLKEM_DK]);

/* Generates a key pair from a 64-byte seed, as FIPS 203 defines key generation. Used by the
 * interop test so the encapsulation key itself can be compared, not just a secret derived from it. */
int lc_mlkem_keygen_seed(const uint8_t seed[LC_MLKEM_SEED],
                         uint8_t ek[LC_MLKEM_EK], uint8_t dk[LC_MLKEM_DK]);

/* Recovers the shared secret from the server's ciphertext.
 *
 * ML-KEM never reports a bad ciphertext: FIPS 203 requires implicit rejection, so a corrupted one
 * yields a different, deterministic secret rather than an error. The handshake finds out later,
 * when Finished fails to verify — which is the intended behaviour and not something to work around
 * here. */
int lc_mlkem_decap(const uint8_t ct[LC_MLKEM_CT], const uint8_t dk[LC_MLKEM_DK],
                   uint8_t ss[LC_MLKEM_SS]);

/* ML-KEM-1024, which only the second hello of a Hysteria2 client that does not parrot Chrome can
 * need: Go 1.26 advertises SecP384r1MLKEM1024 without sharing it
 * (GOROOT/src/crypto/tls/defaults.go:21-35, go1.26.6), so a server that prefers it asks for it in
 * a HelloRetryRequest. The sizes are the library's own:
 *
 *     #define MLKEM1024_SECRETKEYBYTES 3168
 *     #define MLKEM1024_PUBLICKEYBYTES 1568
 *     #define MLKEM1024_CIPHERTEXTBYTES 1568
 *              (vendor/mlkem-native/mlkem/mlkem_native.h:63-65)
 *
 * Built from the same sources as the 768 functions above, in a compilation unit of its own —
 * tls/mlkem1024.c says how. */
#define LC_MLKEM1024_EK 1568u
#define LC_MLKEM1024_DK 3168u
#define LC_MLKEM1024_CT 1568u

int lc_mlkem1024_keygen(uint8_t ek[LC_MLKEM1024_EK], uint8_t dk[LC_MLKEM1024_DK]);
int lc_mlkem1024_keygen_seed(const uint8_t seed[LC_MLKEM_SEED],
                             uint8_t ek[LC_MLKEM1024_EK], uint8_t dk[LC_MLKEM1024_DK]);
int lc_mlkem1024_decap(const uint8_t ct[LC_MLKEM1024_CT], const uint8_t dk[LC_MLKEM1024_DK],
                       uint8_t ss[LC_MLKEM_SS]);

#endif
