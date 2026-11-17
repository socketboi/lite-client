/* The key exchanges this build can perform, checked by doing one.
 *
 * ⚠️ WRITTEN BECAUSE TWO OF THEM WERE ADDED WITH NOTHING ASKING ANYTHING OF THEM. secp384r1 and
 * secp521r1 arrived on 2026-08-29 so that a HelloRetryRequest naming either could be answered, and
 * new key exchange code with no test is the shape of defect this tree has paid for twice: it
 * compiles, it runs, and it agrees with nobody.
 *
 * What is asserted is the only property that matters to a handshake — the two sides derive the SAME
 * secret — plus the refusals that keep a hostile peer from choosing the arithmetic. A vector would
 * be better and there is none to have: mbedTLS generates the private half itself, so the public
 * halves differ every run and nothing published can be compared against.
 *
 * The negative cases are the point. A verifier that returns success for everything passes the
 * agreement test above and is worthless; a point that is not on the curve is exactly what a
 * small-subgroup attack sends, and mbedTLS does not check it unless asked. */

#include "tls/hybrid.h" /* for LC_HYBRID_SECRET: the ceiling must cover it too, and that is macro
                            * arithmetic only — no object of hybrid.c is linked here. */
#include "tls/kex.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void expect(int cond, const char *what)
{
    if (cond) {
        printf("  ok    %s\n", what);
        return;
    }
    printf("  FAIL  %s\n", what);
    failures++;
}

/* One exchange, both directions, for a curve described by its four sizes. Returns 1 when the two
 * secrets match — which is the whole contract of a key exchange. */
static int agrees(int (*keygen)(uint8_t *, uint8_t *),
                  int (*shared)(const uint8_t *, const uint8_t *, uint8_t *),
                  size_t priv_len, size_t point_len, size_t secret_len)
{
    static uint8_t a_priv[LC_P521_KEY], b_priv[LC_P521_KEY];
    static uint8_t a_pub[LC_P521_POINT], b_pub[LC_P521_POINT];
    static uint8_t a_sec[LC_KEX_SHARED_MAX], b_sec[LC_KEX_SHARED_MAX];

    memset(a_sec, 0, sizeof a_sec);
    memset(b_sec, 0, sizeof b_sec);
    if (keygen(a_priv, a_pub) != 0 || keygen(b_priv, b_pub) != 0)
        return 0;
    if (shared(a_priv, b_pub, a_sec) != 0 || shared(b_priv, a_pub, b_sec) != 0)
        return 0;
    (void)priv_len;
    /* The uncompressed form is what TLS carries and what the sizes above promise. */
    if (a_pub[0] != 0x04u || b_pub[0] != 0x04u || point_len == 0u)
        return 0;
    return memcmp(a_sec, b_sec, secret_len) == 0;
}

int main(void)
{
    printf("\nthe key exchanges this build performs\n");

    expect(agrees(lc_p256_keygen, lc_p256_shared, LC_P256_KEY, LC_P256_POINT, LC_P256_SHARED),
           "secp256r1: both sides derive the same 32-byte secret");
    expect(agrees(lc_p384_keygen, lc_p384_shared, LC_P384_KEY, LC_P384_POINT, LC_P384_SHARED),
           "secp384r1: both sides derive the same 48-byte secret");
    expect(agrees(lc_p521_keygen, lc_p521_shared, LC_P521_KEY, LC_P521_POINT, LC_P521_SHARED),
           "secp521r1: both sides derive the same 66-byte secret");

    /* ⚠️ AND 66, NOT 65 — the constant a copy of this code would drift on. P-521's field is 521
     * bits, which needs 66 bytes with a single bit used in the top one, so the point is 1 + 2*66.
     * Asserted as arithmetic rather than trusted as a literal because the compiler already caught
     * one buffer sized by the hybrid's 64 bytes and two short of this. */
    expect(LC_P521_SHARED == 66u && LC_P521_POINT == 1u + 2u * LC_P521_SHARED,
           "and its sizes are the field's, not the hybrid's");
    expect(LC_KEX_SHARED_MAX >= LC_P521_SHARED && LC_KEX_SHARED_MAX >= LC_HYBRID_SECRET,
           "the shared-secret ceiling covers every group, hybrid included");

    printf("\nthe peers a key exchange must refuse\n");

    /* A point that is not on the curve: the classic small-subgroup probe. Everything about it is
     * well-formed — the leading 0x04 and the right length — and only the curve equation says no. */
    {
        uint8_t priv[LC_P256_KEY], pub[LC_P256_POINT], sec[LC_KEX_SHARED_MAX];
        expect(lc_p256_keygen(priv, pub) == 0, "a secp256r1 pair is generated");
        uint8_t bad[LC_P256_POINT];
        memcpy(bad, pub, sizeof bad);
        bad[LC_P256_POINT - 1u] ^= 0x01u; /* still 0x04-prefixed, still 65 bytes, off the curve */
        expect(lc_p256_shared(priv, bad, sec) != 0,
               "secp256r1 refuses a point that is not on the curve");

        uint8_t p384_priv[LC_P384_KEY], p384_pub[LC_P384_POINT];
        expect(lc_p384_keygen(p384_priv, p384_pub) == 0, "a secp384r1 pair is generated");
        uint8_t bad384[LC_P384_POINT];
        memcpy(bad384, p384_pub, sizeof bad384);
        bad384[LC_P384_POINT - 1u] ^= 0x01u;
        expect(lc_p384_shared(p384_priv, bad384, sec) != 0,
               "secp384r1 refuses a point that is not on the curve");

        uint8_t p521_priv[LC_P521_KEY], p521_pub[LC_P521_POINT];
        expect(lc_p521_keygen(p521_priv, p521_pub) == 0, "a secp521r1 pair is generated");
        uint8_t bad521[LC_P521_POINT];
        memcpy(bad521, p521_pub, sizeof bad521);
        bad521[LC_P521_POINT - 1u] ^= 0x01u;
        expect(lc_p521_shared(p521_priv, bad521, sec) != 0,
               "secp521r1 refuses a point that is not on the curve");

        /* And a first byte that is not 0x04: TLS 1.3 allows no other form for these curves. */
        uint8_t compressed[LC_P256_POINT];
        memcpy(compressed, pub, sizeof compressed);
        compressed[0] = 0x02u;
        expect(lc_p256_shared(priv, compressed, sec) != 0,
               "and a compressed point, which TLS 1.3 does not allow, is refused too");
    }

    printf("\n%s\n", failures == 0 ? "all ok" : "FAILURES");
    return failures == 0 ? 0 : 1;
}
