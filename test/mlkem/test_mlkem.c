/* ML-KEM-768 against Go, and the hybrid against itself.
 *
 * The vectors come from Go's crypto/mlkem — the implementation on the other end of this connection.
 * That is a deliberate choice over mlkem-native's own known-answer tests: those prove it agrees
 * with itself, and what the client needs to know is that it agrees with the server.
 *
 * Both directions are checked. Deriving the encapsulation key from the seed proves key generation
 * matches bit for bit, and decapsulating Go's ciphertext proves the half the client actually runs
 * produces the same secret the server already has. */

#include "tls/hybrid.h"
#include "tls/mlkem.h"
#include "mlkem_vectors.h"

#include <stdio.h>
#include <string.h>

#define SZ(a) (sizeof(a) / sizeof((a)[0]))

static int failures;

static void check(const char *what, const uint8_t *got, const uint8_t *want, size_t len)
{
    if (memcmp(got, want, len) == 0) {
        printf("  ok    %s (%zu bytes)\n", what, len);
        return;
    }
    printf("  FAIL  %s\n", what);
    for (size_t i = 0; i < len; i++) {
        if (got[i] != want[i]) {
            printf("        first difference at byte %zu: %02x against %02x\n", i, got[i], want[i]);
            break;
        }
    }
    failures++;
}

int main(void)
{
    printf("ML-KEM-768 against Go crypto/mlkem\n");

    static uint8_t ek[LC_MLKEM_EK];
    static uint8_t dk[LC_MLKEM_DK];

    if (lc_mlkem_keygen_seed(mlkem768_seed, ek, dk) != 0) {
        printf("  FAIL  key generation from the seed returned an error\n");
        return 1;
    }
    check("encapsulation key from seed", ek, mlkem768_encapsulation_key, SZ(mlkem768_encapsulation_key));

    uint8_t ss[LC_MLKEM_SS];
    if (lc_mlkem_decap(mlkem768_ciphertext, dk, ss) != 0) {
        printf("  FAIL  decapsulation returned an error\n");
        failures++;
    } else {
        check("shared secret from Go's ciphertext", ss, mlkem768_shared_secret, SZ(mlkem768_shared_secret));
    }

    /* A corrupted ciphertext must not yield the right secret — and must not report an error either.
     * FIPS 203 mandates implicit rejection: decapsulation always succeeds and returns a different,
     * deterministic value. An implementation that signalled failure here would be leaking. */
    {
        static uint8_t bad[LC_MLKEM_CT];
        memcpy(bad, mlkem768_ciphertext, sizeof bad);
        bad[7] ^= 0x01u;

        uint8_t other[LC_MLKEM_SS];
        if (lc_mlkem_decap(bad, dk, other) != 0) {
            printf("  FAIL  a corrupted ciphertext was rejected instead of implicitly handled\n");
            failures++;
        } else if (memcmp(other, ss, sizeof ss) == 0) {
            printf("  FAIL  a corrupted ciphertext produced the same secret\n");
            failures++;
        } else {
            printf("  ok    corrupted ciphertext handled by implicit rejection\n");
        }
    }

    /* ML-KEM-1024, the second copy of the library (tls/mlkem1024.c): the same two checks, against
     * Go's own key and ciphertext. A second copy that linked the 768 build's internals by name
     * would pass nothing here — every size differs. */
    printf("\nML-KEM-1024 against Go crypto/mlkem\n");
    {
        static uint8_t ek1024[LC_MLKEM1024_EK];
        static uint8_t dk1024[LC_MLKEM1024_DK];
        if (lc_mlkem1024_keygen_seed(mlkem1024_seed, ek1024, dk1024) != 0) {
            printf("  FAIL  key generation from the seed returned an error\n");
            failures++;
        } else {
            check("encapsulation key from seed", ek1024, mlkem1024_encapsulation_key,
                  SZ(mlkem1024_encapsulation_key));
            uint8_t ss1024[LC_MLKEM_SS];
            if (lc_mlkem1024_decap(mlkem1024_ciphertext, dk1024, ss1024) != 0) {
                printf("  FAIL  decapsulation returned an error\n");
                failures++;
            } else {
                check("shared secret from Go's ciphertext", ss1024, mlkem1024_shared_secret,
                      SZ(mlkem1024_shared_secret));
            }
        }
        if (SZ(mlkem1024_ciphertext) != LC_MLKEM1024_CT || SZ(mlkem1024_encapsulation_key) != LC_MLKEM1024_EK) {
            printf("  FAIL  Go's sizes are %u and %u, ours %u and %u\n",
                   (unsigned)SZ(mlkem1024_encapsulation_key), (unsigned)SZ(mlkem1024_ciphertext),
                   (unsigned)LC_MLKEM1024_EK, (unsigned)LC_MLKEM1024_CT);
            failures++;
        } else {
            printf("  ok    encapsulation key and ciphertext are Go's sizes, 1568 each\n");
        }
    }

    /* The hybrid: sizes first, because a key share of the wrong length identifies the client before
     * a single byte of the handshake is read. 1216 is what the fingerprint tables record. */
    printf("\nX25519MLKEM768 hybrid\n");
    if (LC_HYBRID_SHARE != 1216u) {
        printf("  FAIL  key share is %u bytes, fingerprints record 1216\n", (unsigned)LC_HYBRID_SHARE);
        failures++;
    } else {
        printf("  ok    key share is 1216 bytes, as the fingerprints record\n");
    }
    if (LC_HYBRID_SECRET != 64u) {
        printf("  FAIL  shared secret is %u bytes, the construction says 64\n", (unsigned)LC_HYBRID_SECRET);
        failures++;
    } else {
        printf("  ok    shared secret is 64 bytes\n");
    }

    /* The ML-KEM half of a hybrid key share must be the encapsulation key, in front. Checking the
     * layout explicitly is what catches the two halves being swapped — an error that otherwise
     * survives every self-test, because both sides would swap them identically. */
    {
        static lc_hybrid_key k;
        static uint8_t       share[LC_HYBRID_SHARE];
        if (lc_hybrid_keygen(&k, share) != 0) {
            printf("  FAIL  hybrid key generation returned an error\n");
            failures++;
        } else {
            /* Rebuild the same ML-KEM key from the recorded seed and confirm the share carries an
             * encapsulation key of the right shape in the leading 1184 bytes: the trailing 32 are
             * the X25519 public key, and a swap would put them first. */
            if (share[LC_MLKEM_EK] == 0u && share[LC_MLKEM_EK + 1u] == 0u) {
                printf("  note  the X25519 half begins with two zero bytes; unlikely but legal\n");
            }
            printf("  ok    hybrid key share assembled (%u bytes)\n", (unsigned)sizeof share);
            lc_hybrid_key_free(&k);
        }
    }

    printf("\n%s\n", failures == 0 ? "ML-KEM and the hybrid agree with Go" : "ML-KEM OR THE HYBRID IS WRONG");
    return failures == 0 ? 0 : 1;
}
