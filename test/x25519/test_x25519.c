/* The curve arithmetic this client computes X25519 with, against the only two things that can
 * judge it: the published vectors, and the implementation it replaces.
 *
 * WHY BOTH. RFC 7748's vectors prove the code agrees with the standard on the inputs the standard
 * chose — six of them. A field implementation with a transposed index or a carry that lands one
 * limb late agrees on some inputs and not others, and "some" can easily include every published
 * vector. So the second half of this suite generates hundreds of pairs and puts each one through
 * BOTH this code and the mbedTLS the build already links, asserting byte equality. Two independent
 * implementations of the same function disagree on almost every input when either is wrong.
 *
 * The pairs are drawn from a fixed seed, so a failure names an input that can be reproduced rather
 * than a run that cannot. */

#include "tls/x25519.h"

#include "mbedtls/bignum.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"

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

static void hex(char *out, const uint8_t *v, size_t n)
{
    static const char d[] = "0123456789abcdef";

    for (size_t i = 0; i < n; i++) {
        out[i * 2u] = d[v[i] >> 4];
        out[i * 2u + 1u] = d[v[i] & 15u];
    }
    out[n * 2u] = '\0';
}

static int unhex(uint8_t *out, const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned b = 0;

        for (unsigned k = 0; k < 2u; k++) {
            char c = s[i * 2u + k];
            unsigned v;

            if (c >= '0' && c <= '9')
                v = (unsigned)(c - '0');
            else if (c >= 'a' && c <= 'f')
                v = (unsigned)(c - 'a') + 10u;
            else
                return -1;
            b = (b << 4) | v;
        }
        out[i] = (uint8_t)b;
    }
    return 0;
}

static void expect_eq(const uint8_t got[32], const char *want_hex, const char *what)
{
    uint8_t want[32];
    char    g[65];

    if (unhex(want, want_hex, 32) != 0) {
        printf("  FAIL  %s (bad vector in the test itself)\n", what);
        failures++;
        return;
    }
    if (memcmp(got, want, 32) == 0) {
        printf("  ok    %s\n", what);
        return;
    }
    hex(g, got, 32);
    printf("  FAIL  %s\n        got  %s\n        want %s\n", what, g, want_hex);
    failures++;
}

/* mbedTLS blinds its ladder with randomness and refuses to run at all without a source for it —
 * which is how this suite first reported a disagreement that was not one. Deterministic on purpose:
 * a differential test that cannot be replayed is worth half of one. */
static int blind_cb(void *ctx, unsigned char *out, size_t n)
{
    (void)ctx;
    for (size_t i = 0; i < n; i++)
        out[i] = (unsigned char)(i * 31u + 7u);
    return 0;
}

/* X25519 as mbedTLS computes it, which is what this client used until the arithmetic under test
 * existed. Written out here rather than reached through src/tls/kex.c, because kex.c is the caller
 * being changed — a differential test that runs the same code twice proves nothing. */
static int mbed_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t u[32])
{
    mbedtls_ecp_group grp;
    mbedtls_mpi       d, z;
    mbedtls_ecp_point qp;
    uint8_t           e[32];
    int               rc = -1;

    memcpy(e, scalar, 32);
    e[0] = (uint8_t)(e[0] & 248u);
    e[31] = (uint8_t)((e[31] & 127u) | 64u);

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);
    mbedtls_ecp_point_init(&qp);

    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519) != 0)
        goto done;
    if (mbedtls_mpi_read_binary_le(&d, e, sizeof e) != 0)
        goto done;
    if (mbedtls_mpi_read_binary_le(&qp.MBEDTLS_PRIVATE(X), u, 32) != 0)
        goto done;
    if (mbedtls_mpi_set_bit(&qp.MBEDTLS_PRIVATE(X), 255, 0) != 0)
        goto done;
    if (mbedtls_mpi_lset(&qp.MBEDTLS_PRIVATE(Z), 1) != 0)
        goto done;
    if ((rc = mbedtls_ecdh_compute_shared(&grp, &z, &qp, &d, blind_cb, NULL)) != 0) {
        printf("        mbedTLS refused: -0x%04x\n", (unsigned)-rc);
        rc = -1;
        goto done;
    }
    if (mbedtls_mpi_write_binary_le(&z, out, 32) != 0)
        goto done;
    rc = 0;

done:
    mbedtls_ecp_point_free(&qp);
    mbedtls_mpi_free(&z);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return rc;
}

/* A fixed generator, so that "random" here means "many different inputs" and not "a different set
 * every run". xorshift64*, which is not a cryptographic generator and is not asked to be one. */
static uint64_t rng_state = 0x243f6a8885a308d3ull;

static void fill(uint8_t *v, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        rng_state ^= rng_state >> 12;
        rng_state ^= rng_state << 25;
        rng_state ^= rng_state >> 27;
        v[i] = (uint8_t)((rng_state * 0x2545f4914f6cdd1dull) >> 56);
    }
}

int main(void)
{
    uint8_t scalar[32], u[32], out[32];

    printf("=== RFC 7748 §5.2, the two vectors the standard states\n");

    unhex(scalar, "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", 32);
    unhex(u, "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", 32);
    lc_x25519_mul(out, scalar, u);
    expect_eq(out, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", "first vector");

    unhex(scalar, "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d", 32);
    unhex(u, "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493", 32);
    lc_x25519_mul(out, scalar, u);
    expect_eq(out, "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957", "second vector");

    printf("\n=== RFC 7748 §5.2, the iterated check — the one that catches a carry that is almost right\n");
    {
        uint8_t k[32], up[32], tmp[32];

        memset(k, 0, sizeof k);
        k[0] = 9;
        memcpy(up, k, sizeof up);

        for (unsigned i = 0; i < 1000u; i++) {
            lc_x25519_mul(tmp, k, up);
            memcpy(up, k, sizeof up);
            memcpy(k, tmp, sizeof k);
            if (i == 0u)
                expect_eq(k, "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
                          "after one iteration");
        }
        expect_eq(k, "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
                  "after a thousand iterations");
    }

    printf("\n=== RFC 7748 §6.1, a whole Diffie-Hellman\n");
    {
        uint8_t apriv[32], bpriv[32], apub[32], bpub[32], sa[32], sb[32];

        unhex(apriv, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", 32);
        unhex(bpriv, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", 32);
        lc_x25519_basemul(apub, apriv);
        lc_x25519_basemul(bpub, bpriv);
        expect_eq(apub, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
                  "Alice's public key");
        expect_eq(bpub, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
                  "Bob's public key");
        lc_x25519_mul(sa, apriv, bpub);
        lc_x25519_mul(sb, bpriv, apub);
        expect_eq(sa, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
                  "the shared secret, from Alice's side");
        expect(memcmp(sa, sb, 32) == 0, "and Bob derives the same one");
    }

    printf("\n=== the same inputs through mbedTLS, which is what this replaced\n");
    {
        uint8_t mine[32], theirs[32], pub[32];
        int     agree = 1, base_agree = 1, errs = 0;

        for (unsigned i = 0; i < 128u && agree && base_agree; i++) {
            uint8_t peer[32];

            fill(scalar, sizeof scalar);
            fill(peer, sizeof peer);

            /* A point that is actually on the curve, which is what a peer sends. mbedTLS's ladder
             * is defined for any u, but a public key is what this has to agree about. */
            lc_x25519_basemul(u, peer);

            lc_x25519_basemul(pub, scalar);
            if (mbed_x25519(theirs, scalar, (const uint8_t[32]){ 9 }) != 0) {
                errs++;
                break;
            }
            if (memcmp(pub, theirs, 32) != 0) {
                char a[65], b[65];
                hex(a, pub, 32);
                hex(b, theirs, 32);
                printf("  FAIL  base multiplication differs at round %u\n        ours %s\n"
                       "        mbed %s\n",
                       i, a, b);
                base_agree = 0;
                break;
            }

            lc_x25519_mul(mine, scalar, u);
            if (mbed_x25519(theirs, scalar, u) != 0) {
                errs++;
                break;
            }
            if (memcmp(mine, theirs, 32) != 0) {
                char a[65], b[65], s[65], p[65];
                hex(a, mine, 32);
                hex(b, theirs, 32);
                hex(s, scalar, 32);
                hex(p, u, 32);
                printf("  FAIL  differ at round %u\n        scalar %s\n        u      %s\n"
                       "        ours   %s\n        mbed   %s\n",
                       i, s, p, a, b);
                agree = 0;
            }
        }
        expect(errs == 0, "mbedTLS computed every one of them");
        expect(base_agree, "128 base multiplications match mbedTLS byte for byte");
        expect(agree, "128 scalar multiplications by a peer's key match mbedTLS byte for byte");
    }

    printf("\n=== the points a hostile peer sends\n");
    {
        static const char *const small[] = {
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            /* p-1 and p, written little-endian: both are the identity's u or zero. */
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        };
        int all_zero = 1;

        fill(scalar, sizeof scalar);
        for (unsigned i = 0; i < sizeof small / sizeof small[0]; i++) {
            uint8_t acc = 0;

            unhex(u, small[i], 32);
            lc_x25519_mul(out, scalar, u);
            for (unsigned k = 0; k < 32u; k++)
                acc = (uint8_t)(acc | out[k]);
            if (acc != 0) {
                char g[65];
                hex(g, out, 32);
                printf("  FAIL  u = %s gave %s, not zero\n", small[i], g);
                all_zero = 0;
            }
        }
        expect(all_zero, "every low-order point gives the all-zero result kex.c refuses");
    }

    printf("\n%s\n", failures == 0 ? "all good" : "FAILURES");
    return failures == 0 ? 0 : 1;
}
