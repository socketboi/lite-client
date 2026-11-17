#include "tls/mlkem.h"

#include "core/rnd.h"

#include <mlkem_native.h>

/* mlkem-native asks the consumer for randomness under this exact name, and deliberately ships no
 * implementation of it. Ours is the client's single source; there is no weaker second path.
 *
 * ⚠️ AND "THIS EXACT NAME" IS A CONTRACT, not a convention, which until now this file asserted
 * without pointing at it — so the sieve, which builds pairs out of citations, never opened a file
 * whose whole job is to be the one place randomness enters the key exchange. The library says it in
 * two places: "mlkem-native does not provide a secure randombytes implementation ... expects a
 * function int randombytes(uint8_t *out, size_t outlen) ... zero on success, and non-zero on
 * failure" (vendor/mlkem-native/mlkem/mlkem_native_config.h:382-391), and the call itself is a
 * one-line forward, `return randombytes(out, outlen);`
 * (vendor/mlkem-native/mlkem/src/randombytes.h:46-49). A wrong return convention here would not
 * crash: it would hand the KEM whatever the buffer already held. */
int randombytes(uint8_t *out, size_t outlen)
{
    return lc_rnd(out, outlen) == 0 ? 0 : -1;
}

int lc_mlkem_keygen(uint8_t ek[LC_MLKEM_EK], uint8_t dk[LC_MLKEM_DK])
{
    return mlkem768_keypair(ek, dk) == 0 ? 0 : -1;
}

int lc_mlkem_keygen_seed(const uint8_t seed[LC_MLKEM_SEED],
                         uint8_t ek[LC_MLKEM_EK], uint8_t dk[LC_MLKEM_DK])
{
    /* FIPS 203 splits the 64-byte seed into d and z; mlkem-native takes them as one buffer in that
     * order, which is also the order Go's crypto/mlkem uses.
     *
     * The order is visible in the library rather than only in the standard, and it is worth having
     * the line: the first half goes to the IND-CPA key generation,
     * `mlk_indcpa_keypair_derand(pk, sk, coins, context)`
     * (vendor/mlkem-native/mlkem/src/kem.c:240), and the second half is copied out as the implicit
     * rejection value — `coins + MLKEM_SYMBYTES` under the comment "Value z for pseudo-random
     * output on reject" (vendor/mlkem-native/mlkem/src/kem.c:251). Swapping the halves gives a
     * key pair that works with itself and disagrees with every published vector. */
    return mlkem768_keypair_derand(ek, dk, seed) == 0 ? 0 : -1;
}

int lc_mlkem_decap(const uint8_t ct[LC_MLKEM_CT], const uint8_t dk[LC_MLKEM_DK],
                   uint8_t ss[LC_MLKEM_SS])
{
    return mlkem768_dec(ss, ct, dk) == 0 ? 0 : -1;
}
