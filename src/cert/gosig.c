/* x509 checkSignature (GOROOT/src/crypto/x509/x509.go:1055-1141, go1.27.1) and the verifiers it
 * calls — see cert/gosig.h. Each rule below cites the Go it is; where two rules of Go refuse the
 * same input with the same words, the order between them cannot be observed and is not kept, and
 * the comment says so. */
#include "cert/gosig.h"

#include "cert/gocert.h"

/* ⚠️ THE ML-DSA HOOK. checkSignature's ML-DSA branch (x509.go:1115-1138) is dispatched here — the
 * key's type, its parameter set against the algorithm's — and the verification itself,
 * mldsa.Verify(pub, signed, signature, nil), is the ML-DSA port's lc_mldsa_verify. It answers 0 for
 * a nil error and -1 with mldsa.Verify's error text appended to `err`, which checkSignature wraps as
 * "x509: ML-DSA verification failure: %w"; anything else, or running out of memory for the words,
 * is taken as -2. `params` is LC_GOSIG_MLDSA44/65/87, which are cert/mldsa.h's LC_MLDSA_44/65/87;
 * `msg` is the signed bytes as they are, ML-DSA hashing its own input. test/gosig stands in for it
 * with what Go's mldsa.Verify answered. */
#include "cert/mldsa.h"

#include "tls/goerr.h"

#include <mbedtls/bignum.h>
#include <mbedtls/md.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- the words --------------------------------------------------------------------------------- */

static int fail(lc_obuf *e, const char *text)
{
    if (e != NULL)
        lc_obuf_add(e, text, strlen(text));
    return -1;
}

/* A Go format, the literal kept as Go's so that check-qgo-reasons can find it: %d takes an int, and
 * %s, %v, %T and %w a string the caller has already written as Go would. */
static int failf(lc_obuf *e, const char *gofmt, ...)
{
    if (e == NULL)
        return -1;
    va_list ap;
    va_start(ap, gofmt);
    for (const char *f = gofmt; *f != '\0'; f++) {
        if (f[0] != '%' || f[1] == '\0') {
            lc_obuf_byte(e, (uint8_t)*f);
            continue;
        }
        f++;
        if (*f == 'd') {
            char num[24];
            int  n = snprintf(num, sizeof num, "%d", va_arg(ap, int));
            lc_obuf_add(e, num, (size_t)n);
        } else {
            const char *s = va_arg(ap, const char *);
            lc_obuf_add(e, s, strlen(s));
        }
    }
    va_end(ap);
    return -1;
}

/* The errors that are one value in Go and so one text wherever they come from:
 * ErrUnsupportedAlgorithm (x509.go:965) and rsa.ErrVerification
 * (GOROOT/src/crypto/internal/fips140/rsa/rsa.go:385, handed on by fipsError,
 * GOROOT/src/crypto/rsa/fips.go:420-430). */
static int unsupported(lc_obuf *e)
{
    return fail(e, LC_GO("x509: cannot verify signature: algorithm unimplemented"));
}

static int rsa_verification(lc_obuf *e)
{
    return fail(e, LC_GO("crypto/rsa: verification error"));
}

/* ---- the algorithms ---------------------------------------------------------------------------- */

enum { H_NONE, H_MD5, H_SHA1, H_SHA256, H_SHA384, H_SHA512 };

/* signatureAlgorithmDetails (x509.go:376-404): name, the key type it wants, the hash, PSS or not.
 * SHA1WithRSA has two rows there, one per OID; the first is the one every lookup finds, and both
 * say the same. */
static const struct {
    int         alg;
    const char *name;
    int         pk, hash, pss;
} details[] = {
    { LC_GO_SIG_MD5_RSA, "MD5-RSA", LC_GOSIG_KEY_RSA, H_MD5, 0 },
    { LC_GO_SIG_SHA1_RSA, "SHA1-RSA", LC_GOSIG_KEY_RSA, H_SHA1, 0 },
    { LC_GO_SIG_SHA256_RSA, "SHA256-RSA", LC_GOSIG_KEY_RSA, H_SHA256, 0 },
    { LC_GO_SIG_SHA384_RSA, "SHA384-RSA", LC_GOSIG_KEY_RSA, H_SHA384, 0 },
    { LC_GO_SIG_SHA512_RSA, "SHA512-RSA", LC_GOSIG_KEY_RSA, H_SHA512, 0 },
    { LC_GO_SIG_SHA256_RSAPSS, "SHA256-RSAPSS", LC_GOSIG_KEY_RSA, H_SHA256, 1 },
    { LC_GO_SIG_SHA384_RSAPSS, "SHA384-RSAPSS", LC_GOSIG_KEY_RSA, H_SHA384, 1 },
    { LC_GO_SIG_SHA512_RSAPSS, "SHA512-RSAPSS", LC_GOSIG_KEY_RSA, H_SHA512, 1 },
    { LC_GO_SIG_DSA_SHA1, "DSA-SHA1", LC_GOSIG_KEY_DSA, H_SHA1, 0 },
    { LC_GO_SIG_DSA_SHA256, "DSA-SHA256", LC_GOSIG_KEY_DSA, H_SHA256, 0 },
    { LC_GO_SIG_ECDSA_SHA1, "ECDSA-SHA1", LC_GOSIG_KEY_ECDSA, H_SHA1, 0 },
    { LC_GO_SIG_ECDSA_SHA256, "ECDSA-SHA256", LC_GOSIG_KEY_ECDSA, H_SHA256, 0 },
    { LC_GO_SIG_ECDSA_SHA384, "ECDSA-SHA384", LC_GOSIG_KEY_ECDSA, H_SHA384, 0 },
    { LC_GO_SIG_ECDSA_SHA512, "ECDSA-SHA512", LC_GOSIG_KEY_ECDSA, H_SHA512, 0 },
    { LC_GO_SIG_PURE_ED25519, "Ed25519", LC_GOSIG_KEY_ED25519, H_NONE, 0 },
    { LC_GO_SIG_MLDSA44, "ML-DSA-44", LC_GOSIG_KEY_MLDSA, H_NONE, 0 },
    { LC_GO_SIG_MLDSA65, "ML-DSA-65", LC_GOSIG_KEY_MLDSA, H_NONE, 0 },
    { LC_GO_SIG_MLDSA87, "ML-DSA-87", LC_GOSIG_KEY_MLDSA, H_NONE, 0 },
};

static int detail_of(int alg)
{
    for (size_t i = 0; i < sizeof details / sizeof details[0]; i++)
        if (details[i].alg == alg)
            return (int)i;
    return -1;
}

const char *lc_go_sig_alg_name(int sig_alg, char buf[24])
{
    int d = detail_of(sig_alg);
    if (d >= 0)
        return details[d].name;
    snprintf(buf, 24, "%d", sig_alg); /* strconv.Itoa (x509.go:272) */
    return buf;
}

/* publicKeyAlgoName (x509.go:286-299). */
const char *lc_go_pk_alg_name(int pk_alg, char buf[24])
{
    static const char *const names[] = { NULL, "RSA", "DSA", "ECDSA", "Ed25519", "ML-DSA" };
    if (pk_alg > 0 && pk_alg < (int)(sizeof names / sizeof names[0]))
        return names[pk_alg];
    snprintf(buf, 24, "%d", pk_alg);
    return buf;
}

/* ---- digests ----------------------------------------------------------------------------------- */

static const mbedtls_md_info_t *md_of(int hash)
{
    switch (hash) {
    case H_SHA1: return mbedtls_md_info_from_type(MBEDTLS_MD_SHA1); /* TLS 1.2's schemes only */
    case H_SHA256: return mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    case H_SHA384: return mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
    case H_SHA512: return mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    default: return NULL;
    }
}

/* out = H(a || b || c); 0, or -2 when mbedTLS could not. */
static int md3(const mbedtls_md_info_t *info, const uint8_t *a, size_t an, const uint8_t *b,
               size_t bn, const uint8_t *c, size_t cn, uint8_t *out)
{
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    int rc = mbedtls_md_setup(&ctx, info, 0) != 0 || mbedtls_md_starts(&ctx) != 0 ||
             (an != 0u && mbedtls_md_update(&ctx, a, an) != 0) ||
             (bn != 0u && mbedtls_md_update(&ctx, b, bn) != 0) ||
             (cn != 0u && mbedtls_md_update(&ctx, c, cn) != 0) || mbedtls_md_finish(&ctx, out) != 0;
    mbedtls_md_free(&ctx);
    return rc ? -2 : 0;
}

/* Every mbedTLS call below: a failure is memory or a limit, never a verdict. */
#define F(x)                                                                                       \
    do {                                                                                           \
        if ((x) != 0) {                                                                            \
            rc = -2;                                                                               \
            goto done;                                                                             \
        }                                                                                          \
    } while (0)

/* ---- RSA --------------------------------------------------------------------------------------- */

/* x = a^e mod n, the public-key operation encrypt makes
 * (GOROOT/src/crypto/internal/fips140/rsa/rsa.go:375-381), by square-and-multiply from the top bit.
 * Not mbedtls_mpi_exp_mod, whose mbedtls_mpi_exp_mod_optionally_safe refuses a modulus past
 * MBEDTLS_MPI_MAX_BITS, 8192 (vendor/mbedtls/library/bignum.c:1623-1639): Go has no such limit,
 * and a 16384-bit key would stop verifying here and nowhere else. */
static int exp_short(mbedtls_mpi *x, const mbedtls_mpi *a, uint32_t e, const mbedtls_mpi *n)
{
    int         rc = 0;
    mbedtls_mpi t;
    mbedtls_mpi_init(&t);
    F(mbedtls_mpi_lset(x, 1));
    for (int i = 31; i >= 0; i--) {
        F(mbedtls_mpi_mul_mpi(&t, x, x));
        F(mbedtls_mpi_mod_mpi(x, &t, n));
        if ((e >> i & 1u) != 0u) {
            F(mbedtls_mpi_mul_mpi(&t, x, a));
            F(mbedtls_mpi_mod_mpi(x, &t, n));
        }
    }
done:
    mbedtls_mpi_free(&t);
    return rc;
}

/* The DigestInfo prefixes (GOROOT/src/crypto/internal/fips140/rsa/pkcs1v15.go:28-43). */
/* SHA-1's, which x509 never reaches (checkSignature refuses SHA-1 first) and TLS 1.2's
 * rsa_pkcs1_sha1 does. */
static const uint8_t PREFIX_SHA1[] = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03,
                                       0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };
static const uint8_t PREFIX_SHA256[] = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                         0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };
static const uint8_t PREFIX_SHA384[] = { 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                         0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30 };
static const uint8_t PREFIX_SHA512[] = { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                         0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 };

/* pkcs1v15ConstructEM and the comparison verifyPKCS1v15 makes with it
 * (GOROOT/src/crypto/internal/fips140/rsa/pkcs1v15.go:66-93, 126-132): the whole EM, byte for
 * byte, so that every padding rule is one memcmp — 00 01, PS all ff and at least eight long, 00,
 * the DigestInfo, the digest. */
static int pkcs1v15_check(const uint8_t *em, size_t k, int hash, const uint8_t *hashed, size_t hlen,
                          lc_obuf *e)
{
    const uint8_t *prefix = hash == H_SHA1     ? PREFIX_SHA1
                            : hash == H_SHA256 ? PREFIX_SHA256
                            : hash == H_SHA384 ? PREFIX_SHA384
                                               : PREFIX_SHA512;
    size_t         plen = hash == H_SHA1 ? sizeof PREFIX_SHA1 : sizeof PREFIX_SHA256;
    /* EM = 0x00 || 0x01 || PS || 0x00 || T, with PS eight bytes at least: pkcs1v15.go:80-84, whose
     * ErrMessageTooLong becomes ErrVerification at :126-129. */
    if (k < plen + hlen + 2u + 8u + 1u)
        return rsa_verification(e);
    uint8_t *want = calloc(k, 1);
    if (want == NULL)
        return -2;
    want[1] = 1;
    for (size_t i = 2; i < k - plen - hlen - 1u; i++)
        want[i] = 0xff;
    memcpy(want + k - plen - hlen, prefix, plen);
    memcpy(want + k - hlen, hashed, hlen);
    int same = memcmp(em, want, k) == 0;
    free(want);
    return same ? 0 : rsa_verification(e);
}

/* mgf1XOR (GOROOT/src/crypto/internal/fips140/rsa/pkcs1v22.go:53-70). */
static int mgf1_xor(uint8_t *out, size_t n, const mbedtls_md_info_t *info, const uint8_t *seed,
                    size_t seed_len)
{
    uint8_t  counter[4] = { 0, 0, 0, 0 }, dg[64];
    size_t   hl = mbedtls_md_get_size(info);
    uint32_t c = 0;
    for (size_t done = 0; done < n; c++) {
        counter[0] = (uint8_t)(c >> 24);
        counter[1] = (uint8_t)(c >> 16);
        counter[2] = (uint8_t)(c >> 8);
        counter[3] = (uint8_t)c;
        if (md3(info, seed, seed_len, counter, 4, NULL, 0, dg) != 0)
            return -2;
        for (size_t i = 0; i < hl && done < n; i++)
            out[done++] ^= dg[i];
    }
    return 0;
}

/* verifyPSS after the public-key operation, and emsaPSSVerify with sLen = hLen
 * (GOROOT/src/crypto/internal/fips140/rsa/pkcs1v22.go:342-361 and 149-251). `em` is k bytes, the
 * modulus's width; `bits` is N.BitLen(). */
static int pss_check(uint8_t *em, size_t k, size_t bits, int hash, const uint8_t *mhash, size_t hlen,
                     lc_obuf *e)
{
    const mbedtls_md_info_t *info = md_of(hash);
    size_t                   em_bits = bits - 1u, em_len = (em_bits + 7u) / 8u;
    size_t                   slen = hlen; /* PSSSaltLengthEqualsHash: fips.go:177-178 */

    /* EM is one byte shorter than N when modBits-1 is a multiple of 8, and the byte in front must
     * then be zero: pkcs1v22.go:354-359. */
    while (k > em_len && k > 0u) {
        if (em[0] != 0u)
            return rsa_verification(e);
        em++;
        k--;
    }
    /* emLen != len(em) is "rsa: internal error: inconsistent length" (pkcs1v22.go:153-156); the
     * loop above makes them equal, as it does in Go. hLen != len(mHash) (:163-165) cannot happen:
     * the digest is always the hash's own. */
    if (em_len < hlen + slen + 2u) /* :168-170 */
        return rsa_verification(e);
    if (em[em_len - 1u] != 0xbcu) /* :174-176 */
        return rsa_verification(e);
    uint8_t *db = em;
    size_t   db_len = em_len - hlen - 1u;
    uint8_t *h = em + db_len;
    uint8_t  bit_mask = (uint8_t)(0xffu >> (8u * em_len - em_bits)); /* :186-189 */
    if ((em[0] & (uint8_t)~bit_mask) != 0u)
        return rsa_verification(e);
    if (mgf1_xor(db, db_len, info, h, hlen) != 0) /* :194 */
        return -2;
    db[0] &= bit_mask; /* :198 */
    size_t ps_len = em_len - hlen - slen - 2u; /* :219-227 */
    for (size_t i = 0; i < ps_len; i++)
        if (db[i] != 0u)
            return rsa_verification(e);
    if (db[ps_len] != 0x01u)
        return rsa_verification(e);
    const uint8_t zero8[8] = { 0 };
    uint8_t       h0[64];
    if (md3(info, zero8, 8, mhash, hlen, db + db_len - slen, slen, h0) != 0) /* :230-244 */
        return -2;
    return memcmp(h0, h, hlen) == 0 ? 0 : rsa_verification(e); /* :247-250 */
}

/* rsa.VerifyPKCS1v15 and rsa.VerifyPSS with PSSSaltLengthEqualsHash, as checkSignature calls them
 * (x509.go:1094-1098): GOROOT/src/crypto/rsa/fips.go:380-418 and 137-182. The two run the same
 * key checks in the same order before they part — checkPublicKeySize, then (no BoringCrypto, no
 * FIPS 140-only mode in the reference's build) fipsPublicKey, then the FIPS module's
 * checkPublicKey — so they are one function here. */
static int rsa_verify(int pss, int hash, const uint8_t *hashed, size_t hlen, const uint8_t *sig,
                      size_t sig_len, const lc_gopubkey *k, lc_obuf *e)
{
    /* checkPublicKeySize (GOROOT/src/crypto/rsa/rsa.go:301-306). */
    if (k->rsa_n == NULL)
        return fail(e, LC_GO("crypto/rsa: missing public modulus"));

    int         rc = 0;
    uint8_t    *em = NULL;
    mbedtls_mpi n, s, m;
    mbedtls_mpi_init(&n);
    mbedtls_mpi_init(&s);
    mbedtls_mpi_init(&m);
    F(mbedtls_mpi_read_binary(&n, k->rsa_n, k->rsa_n_len));
    size_t bits = mbedtls_mpi_bitlen(&n);

    /* checkKeySize (rsa.go:290-299): rsa1024min=0 is not set, and a main module that says go 1.24
     * or later — Xray-core's says go 1.27 — does not get it as a default
     * (GOROOT/src/internal/godebugs/table.go:61). */
    if (bits < 1024u) {
        rc = failf(e,
                   LC_GO("crypto/rsa: %d-bit keys are insecure "
                         "(see https://go.dev/pkg/crypto/rsa#hdr-Minimum_key_size)"),
                   (int)bits);
        goto done;
    }
    /* fipsPublicKey (rsa.go:684-690): bigmod.NewModulus refuses N <= 1 with "modulus must be > 1"
     * (GOROOT/src/crypto/internal/fips140/bigmod/nat.go:578-589) — which a key that passed the
     * size check cannot be. */

    /* checkPublicKey (GOROOT/src/crypto/internal/fips140/rsa/rsa.go:326-364), whose errors
     * fipsError hands on unchanged. */
    if (mbedtls_mpi_get_bit(&n, 0) == 0) {
        rc = fail(e, LC_GO("crypto/rsa: public modulus is even"));
        goto done;
    }
    if (k->rsa_e < 2) {
        rc = fail(e, LC_GO("crypto/rsa: public exponent too small or negative"));
        goto done;
    }
    if ((k->rsa_e & 1) == 0) {
        rc = fail(e, LC_GO("crypto/rsa: public exponent is even"));
        goto done;
    }
    if (k->rsa_e > INT64_C(2147483647)) {
        rc = fail(e, LC_GO("crypto/rsa: public exponent too large"));
        goto done;
    }

    /* The signature is exactly k bytes (pkcs1v15.go:117-119, pkcs1v22.go:338-340) and below N:
     * bigmod's SetBytes refuses one at or above it (nat.go:182-191), and encrypt's error becomes
     * ErrVerification (pkcs1v15.go:121-124, pkcs1v22.go:344-347). */
    size_t kbytes = (bits + 7u) / 8u;
    if (sig_len != kbytes) {
        rc = rsa_verification(e);
        goto done;
    }
    F(mbedtls_mpi_read_binary(&s, sig, sig_len));
    if (mbedtls_mpi_cmp_mpi(&s, &n) >= 0) {
        rc = rsa_verification(e);
        goto done;
    }
    rc = exp_short(&m, &s, (uint32_t)k->rsa_e, &n);
    if (rc != 0)
        goto done;
    em = malloc(kbytes);
    if (em == NULL) {
        rc = -2;
        goto done;
    }
    F(mbedtls_mpi_write_binary(&m, em, kbytes));
    rc = pss ? pss_check(em, kbytes, bits, hash, hashed, hlen, e)
             : pkcs1v15_check(em, kbytes, hash, hashed, hlen, e);
done:
    free(em);
    mbedtls_mpi_free(&n);
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&m);
    return rc;
}

/* ---- ECDSA ------------------------------------------------------------------------------------- */

/* The four curves crypto/ecdsa verifies through the FIPS module (GOROOT/src/crypto/ecdsa/ecdsa.go:
 * 523-534), a = -3 on each: p, b, the generator, the order. Written out as elliptic.Curve.Params()
 * prints them, not taken from mbedTLS, whose curves the router's build may not have. */
typedef struct {
    const char *p, *b, *gx, *gy, *n;
    size_t      bytes; /* (BitSize+7)/8, the width of a coordinate */
} nist;

static const nist CURVES[4] = {
    { "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
      "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
      "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
      "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D", 28 },
    { "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
      "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
      "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
      "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
      "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 32 },
    { "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
      "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
      "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
      "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", 48 },
    { "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
      "51953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
      "C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
      "11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
      "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", 66 },
};

/* A point in Jacobian coordinates, x = X/Z², y = Y/Z³; Z = 0 is the point at infinity. */
typedef struct {
    mbedtls_mpi X, Y, Z;
} jpt;

static void jpt_init(jpt *a)
{
    mbedtls_mpi_init(&a->X);
    mbedtls_mpi_init(&a->Y);
    mbedtls_mpi_init(&a->Z);
}

static void jpt_free(jpt *a)
{
    mbedtls_mpi_free(&a->X);
    mbedtls_mpi_free(&a->Y);
    mbedtls_mpi_free(&a->Z);
}

static int jpt_copy(jpt *r, const jpt *a)
{
    if (mbedtls_mpi_copy(&r->X, &a->X) != 0 || mbedtls_mpi_copy(&r->Y, &a->Y) != 0 ||
        mbedtls_mpi_copy(&r->Z, &a->Z) != 0)
        return -2;
    return 0;
}

/* r = a·b mod p, a+b mod p, a-b mod p. mbedtls_mpi_mod_mpi leaves 0 <= r < p for any sign. */
static int fmul(mbedtls_mpi *r, const mbedtls_mpi *a, const mbedtls_mpi *b, const mbedtls_mpi *p)
{
    mbedtls_mpi t;
    mbedtls_mpi_init(&t);
    int rc = mbedtls_mpi_mul_mpi(&t, a, b) != 0 || mbedtls_mpi_mod_mpi(r, &t, p) != 0 ? -2 : 0;
    mbedtls_mpi_free(&t);
    return rc;
}

static int fadd(mbedtls_mpi *r, const mbedtls_mpi *a, const mbedtls_mpi *b, const mbedtls_mpi *p)
{
    return mbedtls_mpi_add_mpi(r, a, b) != 0 || mbedtls_mpi_mod_mpi(r, r, p) != 0 ? -2 : 0;
}

static int fsub(mbedtls_mpi *r, const mbedtls_mpi *a, const mbedtls_mpi *b, const mbedtls_mpi *p)
{
    return mbedtls_mpi_sub_mpi(r, a, b) != 0 || mbedtls_mpi_mod_mpi(r, r, p) != 0 ? -2 : 0;
}

static int fmul_int(mbedtls_mpi *r, const mbedtls_mpi *a, mbedtls_mpi_uint b, const mbedtls_mpi *p)
{
    return mbedtls_mpi_mul_int(r, a, b) != 0 || mbedtls_mpi_mod_mpi(r, r, p) != 0 ? -2 : 0;
}

/* r = 2a for a = -3 ("dbl-2001-b"). A point at infinity, or one with y = 0, comes out with Z = 0
 * on its own: Z3 = (Y+Z)² - Y² - Z² = 2YZ. */
static int jdbl(jpt *r, const jpt *a, const mbedtls_mpi *p)
{
    int         rc = 0;
    mbedtls_mpi delta, gamma, beta, alpha, t, u;
    mbedtls_mpi_init(&delta);
    mbedtls_mpi_init(&gamma);
    mbedtls_mpi_init(&beta);
    mbedtls_mpi_init(&alpha);
    mbedtls_mpi_init(&t);
    mbedtls_mpi_init(&u);
    F(fmul(&delta, &a->Z, &a->Z, p));
    F(fmul(&gamma, &a->Y, &a->Y, p));
    F(fmul(&beta, &a->X, &gamma, p));
    F(fsub(&t, &a->X, &delta, p));
    F(fadd(&u, &a->X, &delta, p));
    F(fmul(&alpha, &t, &u, p));
    F(fmul_int(&alpha, &alpha, 3, p));
    /* Z3 first: it reads Y and Z, which r may share with a. */
    F(fadd(&t, &a->Y, &a->Z, p));
    F(fmul(&t, &t, &t, p));
    F(fsub(&t, &t, &gamma, p));
    F(fsub(&r->Z, &t, &delta, p));
    F(fmul(&t, &alpha, &alpha, p));
    F(fmul_int(&u, &beta, 8, p));
    F(fsub(&r->X, &t, &u, p));
    F(fmul_int(&u, &beta, 4, p));
    F(fsub(&u, &u, &r->X, p));
    F(fmul(&u, &alpha, &u, p));
    F(fmul(&t, &gamma, &gamma, p));
    F(fmul_int(&t, &t, 8, p));
    F(fsub(&r->Y, &u, &t, p));
done:
    mbedtls_mpi_free(&delta);
    mbedtls_mpi_free(&gamma);
    mbedtls_mpi_free(&beta);
    mbedtls_mpi_free(&alpha);
    mbedtls_mpi_free(&t);
    mbedtls_mpi_free(&u);
    return rc;
}

/* r = a + b, for any two points: either at infinity, equal (a doubling), or each other's negation
 * (infinity). Go's nistec additions are complete, so a verifier that is not would refuse — or
 * accept — what Go does not. */
static int jadd(jpt *r, const jpt *a, const jpt *b, const mbedtls_mpi *p)
{
    if (mbedtls_mpi_cmp_int(&a->Z, 0) == 0)
        return jpt_copy(r, b);
    if (mbedtls_mpi_cmp_int(&b->Z, 0) == 0)
        return jpt_copy(r, a);

    int         rc = 0;
    mbedtls_mpi z1z1, z2z2, u1, u2, s1, s2, h, rr, t, hh, hhh, v, x3;
    mbedtls_mpi *all[] = { &z1z1, &z2z2, &u1, &u2, &s1, &s2, &h, &rr, &t, &hh, &hhh, &v, &x3 };
    for (size_t i = 0; i < sizeof all / sizeof all[0]; i++)
        mbedtls_mpi_init(all[i]);
    F(fmul(&z1z1, &a->Z, &a->Z, p));
    F(fmul(&z2z2, &b->Z, &b->Z, p));
    F(fmul(&u1, &a->X, &z2z2, p));
    F(fmul(&u2, &b->X, &z1z1, p));
    F(fmul(&t, &b->Z, &z2z2, p));
    F(fmul(&s1, &a->Y, &t, p));
    F(fmul(&t, &a->Z, &z1z1, p));
    F(fmul(&s2, &b->Y, &t, p));
    if (mbedtls_mpi_cmp_mpi(&u1, &u2) == 0) {
        if (mbedtls_mpi_cmp_mpi(&s1, &s2) == 0)
            rc = jdbl(r, a, p);
        else
            rc = mbedtls_mpi_lset(&r->X, 1) != 0 || mbedtls_mpi_lset(&r->Y, 1) != 0 ||
                         mbedtls_mpi_lset(&r->Z, 0) != 0
                     ? -2
                     : 0;
        goto done;
    }
    F(fsub(&h, &u2, &u1, p));
    F(fsub(&rr, &s2, &s1, p));
    F(fmul(&hh, &h, &h, p));
    F(fmul(&hhh, &h, &hh, p));
    F(fmul(&v, &u1, &hh, p));
    F(fmul(&x3, &rr, &rr, p));
    F(fsub(&x3, &x3, &hhh, p));
    F(fsub(&x3, &x3, &v, p));
    F(fsub(&x3, &x3, &v, p));
    F(fmul(&t, &a->Z, &b->Z, p));
    F(fmul(&r->Z, &t, &h, p));
    F(fsub(&t, &v, &x3, p));
    F(fmul(&t, &rr, &t, p));
    F(fmul(&s1, &s1, &hhh, p));
    F(fsub(&r->Y, &t, &s1, p));
    F(mbedtls_mpi_copy(&r->X, &x3));
done:
    for (size_t i = 0; i < sizeof all / sizeof all[0]; i++)
        mbedtls_mpi_free(all[i]);
    return rc;
}

/* The public key as publicKeyToFIPS makes it (GOROOT/src/crypto/ecdsa/ecdsa.go:581-587): the
 * uncompressed encoding, each coordinate below p, on the curve — nistec's SetBytes
 * (GOROOT/src/crypto/internal/fips140/nistec/p224.go:56-78 and its siblings), reached through
 * ecdsa.NewPublicKey (GOROOT/src/crypto/internal/fips140/ecdsa/ecdsa.go:185-197). ParseCertificate
 * has refused any other key already; a key that fails here is a false from VerifyASN1 all the same
 * (ecdsa.go:542-545). 1 when it is a point, 0 when not. */
static int ec_pub_ok(const lc_gopubkey *k, const nist *c, const mbedtls_mpi *p, const mbedtls_mpi *b,
                     mbedtls_mpi *qx, mbedtls_mpi *qy, int *rcp)
{
    int         rc = 0, ok = 0;
    mbedtls_mpi l, r;
    mbedtls_mpi_init(&l);
    mbedtls_mpi_init(&r);
    if (k->point == NULL || k->point_len != 1u + 2u * c->bytes || k->point[0] != 4u)
        goto done;
    F(mbedtls_mpi_read_binary(qx, k->point + 1, c->bytes));
    F(mbedtls_mpi_read_binary(qy, k->point + 1 + c->bytes, c->bytes));
    if (mbedtls_mpi_cmp_mpi(qx, p) >= 0 || mbedtls_mpi_cmp_mpi(qy, p) >= 0)
        goto done;
    /* y² = x³ - 3x + b */
    F(fmul(&l, qy, qy, p));
    F(fmul(&r, qx, qx, p));
    F(mbedtls_mpi_sub_int(&r, &r, 3));
    F(fmul(&r, &r, qx, p));
    F(fadd(&r, &r, b, p));
    ok = mbedtls_mpi_cmp_mpi(&l, &r) == 0;
done:
    mbedtls_mpi_free(&l);
    mbedtls_mpi_free(&r);
    *rcp = rc;
    return ok;
}

/* One element of cryptobyte's readASN1 (GOROOT/src/vendor/golang.org/x/crypto/cryptobyte/asn1.go:
 * 755-825), through ReadAnyASN1 (:625) and ReadASN1 (:599-605): a one-octet tag that is not the
 * high-tag-number form, a DER length (short form below 128, long form of one to four octets with no
 * leading zero octet), and that many bytes present. The contents go to `out`; 0 when it does not
 * read. */
static int asn1_read(const uint8_t **s, size_t *n, uint8_t want_tag, const uint8_t **out,
                     size_t *out_n)
{
    if (*n < 2u)
        return 0;
    uint8_t tag = (*s)[0], len_byte = (*s)[1];
    if ((tag & 0x1fu) == 0x1fu)
        return 0;
    size_t length, header;
    if ((len_byte & 0x80u) == 0u) {
        length = len_byte;
        header = 2;
    } else {
        size_t len_len = len_byte & 0x7fu;
        if (len_len == 0u || len_len > 4u || *n < 2u + len_len)
            return 0;
        uint32_t len32 = 0;
        for (size_t i = 0; i < len_len; i++)
            len32 = len32 << 8 | (*s)[2 + i];
        if (len32 < 128u)
            return 0;
        if ((len32 >> ((len_len - 1u) * 8u)) == 0u)
            return 0;
        /* headerLen + len32 overflowing uint32, and int(length) < 0 on a 32-bit Go, both refuse a
         * length no input here can supply: the comparison with what is left refuses it too. */
        length = len32;
        header = 2u + len_len;
    }
    if (length > *n - header)
        return 0;
    if (tag != want_tag)
        return 0; /* ReadASN1's t != tag, after the element was read (:600-603) */
    *out = *s + header;
    *out_n = length;
    *s += header + length;
    *n -= header + length;
    return 1;
}

/* ReadASN1Integer into a []byte: readASN1Bytes (asn1.go:335-348) with checkASN1Integer
 * (:298-311) — at least one octet, minimally encoded, not negative — and the leading zeros of a
 * positive value dropped. */
static int asn1_uint(const uint8_t **s, size_t *n, const uint8_t **out, size_t *out_n)
{
    const uint8_t *b;
    size_t         bn;
    if (!asn1_read(s, n, 0x02u, &b, &bn))
        return 0;
    if (bn == 0u)
        return 0;
    if (bn > 1u && ((b[0] == 0u && (b[1] & 0x80u) == 0u) || (b[0] == 0xffu && (b[1] & 0x80u) != 0u)))
        return 0;
    if ((b[0] & 0x80u) != 0u)
        return 0;
    while (bn > 1u && b[0] == 0u) {
        b++;
        bn--;
    }
    *out = b;
    *out_n = bn;
    return 1;
}

/* ecdsa.VerifyASN1 (GOROOT/src/crypto/ecdsa/ecdsa.go:509-535) for the four named curves: 1 when it
 * returns true, 0 when false, -2 when this could not answer. */
static int ecdsa_verify(const lc_gopubkey *k, const uint8_t *hash, size_t hlen, const uint8_t *sig,
                        size_t sig_len)
{
    /* len(hash) == 0 is false at once (ecdsa.go:510-512); x509 always hands a digest. A curve
     * outside the four goes to verifyLegacy (:532-533) in Go, and ParseCertificate makes none. */
    if (hlen == 0u || k->curve < LC_GOSIG_P224 || k->curve > LC_GOSIG_P521)
        return 0;
    const nist *c = &CURVES[k->curve - 1];

    /* parseSignature (ecdsa.go:552-563): SEQUENCE { INTEGER r, INTEGER s } and nothing after
     * either. */
    const uint8_t *in = sig, *body, *rb, *sb;
    size_t         in_n = sig_len, body_n, rn, sn;
    if (!asn1_read(&in, &in_n, 0x30u, &body, &body_n) || in_n != 0u ||
        !asn1_uint(&body, &body_n, &rb, &rn) || !asn1_uint(&body, &body_n, &sb, &sn) || body_n != 0u)
        return 0;

    int         rc = 0, ok = 0;
    mbedtls_mpi p, b, n, qx, qy, r, s, e, w, u1, u2, zinv, t;
    mbedtls_mpi *all[] = { &p, &b, &n, &qx, &qy, &r, &s, &e, &w, &u1, &u2, &zinv, &t };
    jpt          G, Q, GQ, R;
    for (size_t i = 0; i < sizeof all / sizeof all[0]; i++)
        mbedtls_mpi_init(all[i]);
    jpt_init(&G);
    jpt_init(&Q);
    jpt_init(&GQ);
    jpt_init(&R);
    F(mbedtls_mpi_read_string(&p, 16, c->p));
    F(mbedtls_mpi_read_string(&b, 16, c->b));
    F(mbedtls_mpi_read_string(&n, 16, c->n));

    /* publicKeyToFIPS comes after parseSignature (ecdsa.go:538-545); both are a plain false. */
    if (!ec_pub_ok(k, c, &p, &b, &qx, &qy, &rc)) {
        if (rc != 0)
            goto done;
        goto verdict;
    }

    /* verifyGeneric (GOROOT/src/crypto/internal/fips140/ecdsa/ecdsa.go:462-517): r and s below N —
     * bigmod's SetBytes (nat.go:182-191) — and not zero. */
    F(mbedtls_mpi_read_binary(&r, rb, rn));
    F(mbedtls_mpi_read_binary(&s, sb, sn));
    if (mbedtls_mpi_cmp_int(&r, 0) == 0 || mbedtls_mpi_cmp_mpi(&r, &n) >= 0 ||
        mbedtls_mpi_cmp_int(&s, 0) == 0 || mbedtls_mpi_cmp_mpi(&s, &n) >= 0)
        goto verdict;

    /* hashToNat (fips140/ecdsa/ecdsa.go:407-422): the digest cut to N's byte length when it is at
     * least that long, then shifted right by the bits the order does not have, then reduced modulo
     * N — SetOverflowingBytes subtracts N at most once, which for a value below 2^BitLen(N) is the
     * whole reduction. The shift is P-521's alone and needs a digest of 66 bytes or more, which no
     * algorithm x509 knows has: kept for the rule, and no vector can reach it. */
    {
        size_t nbits = mbedtls_mpi_bitlen(&n), size = (nbits + 7u) / 8u, use = hlen;
        if (hlen >= size)
            use = size;
        F(mbedtls_mpi_read_binary(&e, hash, use));
        if (hlen >= size && use * 8u > nbits)
            F(mbedtls_mpi_shift_r(&e, use * 8u - nbits));
        F(mbedtls_mpi_mod_mpi(&e, &e, &n));
    }

    /* u1 = e·s⁻¹, u2 = r·s⁻¹, R = [u1]G + [u2]Q. */
    F(mbedtls_mpi_inv_mod(&w, &s, &n));
    F(fmul(&u1, &e, &w, &n));
    F(fmul(&u2, &r, &w, &n));
    F(mbedtls_mpi_read_string(&G.X, 16, c->gx));
    F(mbedtls_mpi_read_string(&G.Y, 16, c->gy));
    F(mbedtls_mpi_lset(&G.Z, 1));
    F(mbedtls_mpi_copy(&Q.X, &qx));
    F(mbedtls_mpi_copy(&Q.Y, &qy));
    F(mbedtls_mpi_lset(&Q.Z, 1));
    F(jadd(&GQ, &G, &Q, &p));
    F(mbedtls_mpi_lset(&R.X, 1));
    F(mbedtls_mpi_lset(&R.Y, 1));
    F(mbedtls_mpi_lset(&R.Z, 0));
    {
        size_t b1 = mbedtls_mpi_bitlen(&u1), b2 = mbedtls_mpi_bitlen(&u2);
        for (size_t i = b1 > b2 ? b1 : b2; i > 0u; i--) {
            F(jdbl(&R, &R, &p));
            int         x1 = mbedtls_mpi_get_bit(&u1, i - 1u), x2 = mbedtls_mpi_get_bit(&u2, i - 1u);
            const jpt *add = x1 && x2 ? &GQ : x1 ? &G : x2 ? &Q : NULL;
            if (add != NULL)
                F(jadd(&R, &R, add, &p));
        }
    }
    /* BytesX refuses the point at infinity (fips140/ecdsa/ecdsa.go:502-506). */
    if (mbedtls_mpi_cmp_int(&R.Z, 0) == 0)
        goto verdict;
    /* v = Rx mod N — SetOverflowingBytes again, one subtraction, and p < 2N on these curves — and
     * v == r (:508-515). */
    F(mbedtls_mpi_inv_mod(&zinv, &R.Z, &p));
    F(fmul(&t, &zinv, &zinv, &p));
    F(fmul(&t, &R.X, &t, &p));
    F(mbedtls_mpi_mod_mpi(&t, &t, &n));
    ok = mbedtls_mpi_cmp_mpi(&t, &r) == 0;
verdict:
    rc = ok;
done:
    for (size_t i = 0; i < sizeof all / sizeof all[0]; i++)
        mbedtls_mpi_free(all[i]);
    jpt_free(&G);
    jpt_free(&Q);
    jpt_free(&GQ);
    jpt_free(&R);
    return rc;
}

/* ---- Ed25519 ----------------------------------------------------------------------------------- */

/* ⚠️ NOT tls/ed25519.c, AND ON PURPOSE. That verifier refuses a public key whose y is not reduced
 * modulo p, and one with x = 0 and the sign bit set — RFC 8032 §5.1.3's decoding. Go's does not:
 * edwards25519's Point.SetBytes takes both
 * (GOROOT/src/crypto/internal/fips140/edwards25519/edwards25519.go:140-150, field/fe.go:163-170),
 * and a key of small order under such an encoding has signatures Go accepts. So this is
 * ed25519.Verify as go1.27.1 has it, from the key's bytes to the comparison, on bignums like the
 * rest of this file.
 *
 * The curve, as tls/ed25519.c writes it: p = 2^255 - 19; d = -121665/121666, in decimal as RFC 8032
 * §5.1 prints it; the order l = 2^252 + 27742317777372353535851937790883648493 and
 * sqrt(-1) = 2^((p-1)/4), both in decimal; and the base point's encoding (y = 4/5, x even). */
#define ED_D   "37095705934669439343138083508754565189542113879843219016388785533085940283555"
#define ED_L   "7237005577332262213973186563042994240857116359379907606001950938285454250989"
#define ED_I   "19681161376707505956807079304988542015446066515923890162744021073123829784752"
static const uint8_t ED_B[32] = { 0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                                  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                                  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66 };

typedef struct {
    mbedtls_mpi p, d, d2, i, l;
} edc;

/* Extended coordinates: x = X/Z, y = Y/Z, xy = T/Z. */
typedef struct {
    mbedtls_mpi X, Y, Z, T;
} ept;

static void ept_init(ept *a)
{
    mbedtls_mpi_init(&a->X);
    mbedtls_mpi_init(&a->Y);
    mbedtls_mpi_init(&a->Z);
    mbedtls_mpi_init(&a->T);
}

static void ept_free(ept *a)
{
    mbedtls_mpi_free(&a->X);
    mbedtls_mpi_free(&a->Y);
    mbedtls_mpi_free(&a->Z);
    mbedtls_mpi_free(&a->T);
}

/* r = a + b, the unified formula for a = -1 ("add-2008-hwcd-3"), complete on this curve because d
 * is not a square: it doubles, and adds the identity and a point's negation, with no special case.
 * r may be a or b. */
static int eadd(ept *r, const ept *a, const ept *b, const edc *c)
{
    int         rc = 0;
    mbedtls_mpi A, B, C, D, E, Fv, G, H, t;
    mbedtls_mpi *all[] = { &A, &B, &C, &D, &E, &Fv, &G, &H, &t };
    for (size_t i = 0; i < sizeof all / sizeof all[0]; i++)
        mbedtls_mpi_init(all[i]);
    F(fsub(&A, &a->Y, &a->X, &c->p));
    F(fsub(&t, &b->Y, &b->X, &c->p));
    F(fmul(&A, &A, &t, &c->p));
    F(fadd(&B, &a->Y, &a->X, &c->p));
    F(fadd(&t, &b->Y, &b->X, &c->p));
    F(fmul(&B, &B, &t, &c->p));
    F(fmul(&C, &a->T, &c->d2, &c->p));
    F(fmul(&C, &C, &b->T, &c->p));
    F(fmul(&D, &a->Z, &b->Z, &c->p));
    F(fadd(&D, &D, &D, &c->p));
    F(fsub(&E, &B, &A, &c->p));
    F(fsub(&Fv, &D, &C, &c->p));
    F(fadd(&G, &D, &C, &c->p));
    F(fadd(&H, &B, &A, &c->p));
    F(fmul(&r->X, &E, &Fv, &c->p));
    F(fmul(&r->Y, &G, &H, &c->p));
    F(fmul(&r->T, &E, &H, &c->p));
    F(fmul(&r->Z, &Fv, &G, &c->p));
done:
    for (size_t i = 0; i < sizeof all / sizeof all[0]; i++)
        mbedtls_mpi_free(all[i]);
    return rc;
}

/* Point.SetBytes (GOROOT/src/crypto/internal/fips140/edwards25519/edwards25519.go:145-187): y is
 * the low 255 bits, taken modulo p whatever they are (field/fe.go:163-193); x = ±sqrt(u/v) with
 * u = y²-1, v = dy²+1, by SqrtRatio (field/fe.go:366-388), which counts u/v as square when v·r² is u
 * or -u and chooses the non-negative root; the sign bit then negates it, which leaves an x of zero
 * zero. 1 when the bytes decode, 0 when not, -2 when this could not answer. */
static int edecode(ept *r, const uint8_t in[32], const edc *c)
{
    int         rc = 0, ok = 0;
    uint8_t     le[32];
    mbedtls_mpi y2, u, v, t, x2, ex, negu;
    mbedtls_mpi *all[] = { &y2, &u, &v, &t, &x2, &ex, &negu };
    for (size_t i = 0; i < sizeof all / sizeof all[0]; i++)
        mbedtls_mpi_init(all[i]);
    memcpy(le, in, 32);
    unsigned sign = (unsigned)(le[31] >> 7);
    le[31] &= 0x7fu;
    F(mbedtls_mpi_read_binary_le(&r->Y, le, 32));
    F(mbedtls_mpi_mod_mpi(&r->Y, &r->Y, &c->p));
    F(fmul(&y2, &r->Y, &r->Y, &c->p));
    F(mbedtls_mpi_sub_int(&u, &y2, 1));
    F(mbedtls_mpi_mod_mpi(&u, &u, &c->p));
    F(fmul(&v, &y2, &c->d, &c->p));
    F(mbedtls_mpi_add_int(&v, &v, 1));
    F(mbedtls_mpi_mod_mpi(&v, &v, &c->p));
    /* r = (u·v³)·(u·v⁷)^((p-5)/8) */
    F(fmul(&t, &v, &v, &c->p));
    F(fmul(&t, &t, &v, &c->p)); /* v³ */
    F(fmul(&x2, &t, &t, &c->p));
    F(fmul(&x2, &x2, &v, &c->p)); /* v⁷ */
    F(fmul(&x2, &x2, &u, &c->p)); /* u·v⁷ */
    F(mbedtls_mpi_sub_int(&ex, &c->p, 5));
    F(mbedtls_mpi_shift_r(&ex, 3));
    F(mbedtls_mpi_exp_mod(&x2, &x2, &ex, &c->p, NULL));
    F(fmul(&t, &t, &u, &c->p)); /* u·v³ */
    F(fmul(&r->X, &t, &x2, &c->p));
    /* check = v·r² */
    F(fmul(&t, &r->X, &r->X, &c->p));
    F(fmul(&t, &t, &v, &c->p));
    F(mbedtls_mpi_sub_mpi(&negu, &c->p, &u));
    F(mbedtls_mpi_mod_mpi(&negu, &negu, &c->p));
    if (mbedtls_mpi_cmp_mpi(&t, &u) != 0) {
        if (mbedtls_mpi_cmp_mpi(&t, &negu) != 0)
            goto done; /* wasSquare == 0: edwards25519.go's "invalid point encoding" */
        F(fmul(&r->X, &r->X, &c->i, &c->p));
    }
    /* Absolute: the root whose canonical encoding is even. */
    if (mbedtls_mpi_get_bit(&r->X, 0) == 1)
        F(mbedtls_mpi_sub_mpi(&r->X, &c->p, &r->X));
    if (sign != 0u && mbedtls_mpi_cmp_int(&r->X, 0) != 0)
        F(mbedtls_mpi_sub_mpi(&r->X, &c->p, &r->X));
    F(mbedtls_mpi_lset(&r->Z, 1));
    F(fmul(&r->T, &r->X, &r->Y, &c->p));
    ok = 1;
done:
    for (size_t i = 0; i < sizeof all / sizeof all[0]; i++)
        mbedtls_mpi_free(all[i]);
    return rc != 0 ? rc : ok;
}

/* Point.Bytes (edwards25519.go:116-134): y = Y/Z canonical, the sign of x = X/Z in the top bit. */
static int eencode(uint8_t out[32], const ept *a, const edc *c)
{
    int         rc = 0;
    mbedtls_mpi zi, x, y;
    mbedtls_mpi_init(&zi);
    mbedtls_mpi_init(&x);
    mbedtls_mpi_init(&y);
    F(mbedtls_mpi_inv_mod(&zi, &a->Z, &c->p));
    F(fmul(&x, &a->X, &zi, &c->p));
    F(fmul(&y, &a->Y, &zi, &c->p));
    F(mbedtls_mpi_write_binary_le(&y, out, 32));
    out[31] = (uint8_t)(out[31] | (uint8_t)(mbedtls_mpi_get_bit(&x, 0) << 7));
done:
    mbedtls_mpi_free(&zi);
    mbedtls_mpi_free(&x);
    mbedtls_mpi_free(&y);
    return rc;
}

/* ed25519.Verify(pub, message, sig) (GOROOT/src/crypto/ed25519/ed25519.go:234-270) with Go's
 * checks and none of RFC 8032's others: 1 true, 0 false, -2 could not answer. */
static int ed25519_verify(const uint8_t pub[32], const uint8_t *msg, size_t msg_len, const uint8_t *sig,
                          size_t sig_len)
{
    /* verifyWithDom (GOROOT/src/crypto/internal/fips140/ed25519/ed25519.go:290-328): 64 bytes,
     * the top three bits of S clear, S below l (SetCanonicalBytes,
     * GOROOT/src/crypto/internal/fips140/edwards25519/scalar.go:159-171). A key that does not
     * decode is refused before any of it (newPublicKey,
     * GOROOT/src/crypto/internal/fips140/ed25519/ed25519.go:141-151); every refusal is the
     * same false to x509. */
    if (sig_len != 64u || (sig[63] & 224u) != 0u)
        return 0;

    int         rc = 0, ok = 0;
    edc         c;
    ept         A, B, BA, R;
    mbedtls_mpi S, k;
    mbedtls_mpi *all[] = { &c.p, &c.d, &c.d2, &c.i, &c.l, &S, &k };
    for (size_t i = 0; i < sizeof all / sizeof all[0]; i++)
        mbedtls_mpi_init(all[i]);
    ept_init(&A);
    ept_init(&B);
    ept_init(&BA);
    ept_init(&R);
    F(mbedtls_mpi_lset(&c.p, 1));
    F(mbedtls_mpi_shift_l(&c.p, 255));
    F(mbedtls_mpi_sub_int(&c.p, &c.p, 19));
    F(mbedtls_mpi_read_string(&c.d, 10, ED_D));
    F(fadd(&c.d2, &c.d, &c.d, &c.p));
    F(mbedtls_mpi_read_string(&c.i, 10, ED_I));
    F(mbedtls_mpi_read_string(&c.l, 10, ED_L));

    int dec = edecode(&A, pub, &c);
    if (dec < 0) {
        rc = dec;
        goto done;
    }
    if (dec == 0)
        goto verdict;

    /* k = SHA-512(R || A || M) mod l, over the key's own bytes
     * (pub.aBytes, GOROOT/src/crypto/internal/fips140/ed25519/ed25519.go:299-313). */
    {
        uint8_t dg[64];
        if (md3(mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), sig, 32, pub, 32, msg, msg_len, dg) != 0) {
            rc = -2;
            goto done;
        }
        F(mbedtls_mpi_read_binary_le(&k, dg, 64));
        F(mbedtls_mpi_mod_mpi(&k, &k, &c.l));
    }
    F(mbedtls_mpi_read_binary_le(&S, sig + 32, 32));
    if (mbedtls_mpi_cmp_mpi(&S, &c.l) >= 0)
        goto verdict;

    /* R' = [S]B + [k](-A), cofactorless
     * (GOROOT/src/crypto/internal/fips140/ed25519/ed25519.go:320-322), and its canonical encoding against
     * the signature's first half byte for byte (:324-326): an R encoded any other way is refused
     * however it decodes. */
    dec = edecode(&B, ED_B, &c);
    if (dec != 1) {
        rc = -2;
        goto done;
    }
    F(mbedtls_mpi_sub_mpi(&A.X, &c.p, &A.X));
    F(mbedtls_mpi_mod_mpi(&A.X, &A.X, &c.p));
    F(mbedtls_mpi_sub_mpi(&A.T, &c.p, &A.T));
    F(mbedtls_mpi_mod_mpi(&A.T, &A.T, &c.p));
    F(eadd(&BA, &B, &A, &c));
    F(mbedtls_mpi_lset(&R.X, 0));
    F(mbedtls_mpi_lset(&R.Y, 1));
    F(mbedtls_mpi_lset(&R.Z, 1));
    F(mbedtls_mpi_lset(&R.T, 0));
    {
        size_t b1 = mbedtls_mpi_bitlen(&S), b2 = mbedtls_mpi_bitlen(&k);
        for (size_t i = b1 > b2 ? b1 : b2; i > 0u; i--) {
            F(eadd(&R, &R, &R, &c));
            int        x1 = mbedtls_mpi_get_bit(&S, i - 1u), x2 = mbedtls_mpi_get_bit(&k, i - 1u);
            const ept *add = x1 && x2 ? &BA : x1 ? &B : x2 ? &A : NULL;
            if (add != NULL)
                F(eadd(&R, &R, add, &c));
        }
    }
    {
        uint8_t enc[32];
        F(eencode(enc, &R, &c));
        ok = memcmp(enc, sig, 32) == 0;
    }
verdict:
    rc = ok;
done:
    for (size_t i = 0; i < sizeof all / sizeof all[0]; i++)
        mbedtls_mpi_free(all[i]);
    ept_free(&A);
    ept_free(&B);
    ept_free(&BA);
    ept_free(&R);
    return rc;
}

/* ---- checkSignature ---------------------------------------------------------------------------- */

static int mismatch(lc_obuf *e, int pk, const char *type)
{
    char nb[24];
    /* signaturePublicKeyAlgoMismatchError (x509.go:1045-1047): %T of the key. */
    return failf(e,
                 LC_GO("x509: signature algorithm specifies an %s public key, "
                       "but have public key of type %T"),
                 lc_go_pk_alg_name(pk, nb), type);
}

static const char *mldsa_name(int params)
{
    return params == LC_GOSIG_MLDSA44   ? "ML-DSA-44"
           : params == LC_GOSIG_MLDSA65 ? "ML-DSA-65"
                                        : "ML-DSA-87";
}

static int check(int sig_alg, const uint8_t *signed_, size_t signed_len, const uint8_t *sig,
                 size_t sig_len, const lc_gopubkey *pub, lc_obuf *e)
{
    char nb[24];
    int  d = detail_of(sig_alg);
    int  hash = d >= 0 ? details[d].hash : H_NONE, pk = d >= 0 ? details[d].pk : LC_GOSIG_KEY_NONE;
    int  pss = d >= 0 && details[d].pss;

    /* The hash first, whatever the key (x509.go:1059-1087): none only for Ed25519 and ML-DSA,
     * MD5 never, SHA-1 not on this path (allowSHA1 is false from CheckSignatureFrom, :1018). */
    uint8_t        digest[64];
    const uint8_t *msg = signed_;
    size_t         msg_len = signed_len;
    switch (hash) {
    case H_NONE:
        if (pk != LC_GOSIG_KEY_ED25519 && pk != LC_GOSIG_KEY_MLDSA)
            return unsupported(e);
        break;
    case H_MD5:
    case H_SHA1:
        /* InsecureAlgorithmError (x509.go:969-973), %v of the algorithm */
        return failf(e, LC_GO("x509: cannot verify signature: insecure algorithm %v"),
                     lc_go_sig_alg_name(sig_alg, nb));
    default: {
        /* hashType.Available() (:1081-1083) is true for all three in any Go binary that links
         * x509; an mbedTLS without one is this client's limit, not a verdict. */
        const mbedtls_md_info_t *info = md_of(hash);
        if (info == NULL || md3(info, signed_, signed_len, NULL, 0, NULL, 0, digest) != 0)
            return -2;
        msg = digest;
        msg_len = mbedtls_md_get_size(info);
        break;
    }
    }

    /* Then the key's type (:1089-1140). */
    int kind = pub != NULL ? pub->kind : LC_GOSIG_KEY_NONE;
    switch (kind) {
    case LC_GOSIG_KEY_RSA:
        if (pk != LC_GOSIG_KEY_RSA)
            return mismatch(e, pk, "*rsa.PublicKey");
        return rsa_verify(pss, hash, msg, msg_len, sig, sig_len, pub, e);
    case LC_GOSIG_KEY_ECDSA: {
        if (pk != LC_GOSIG_KEY_ECDSA)
            return mismatch(e, pk, "*ecdsa.PublicKey");
        int ok = ecdsa_verify(pub, msg, msg_len, sig, sig_len);
        if (ok < 0)
            return ok;
        return ok ? 0 : fail(e, LC_GO("x509: ECDSA verification failure"));
    }
    case LC_GOSIG_KEY_ED25519: {
        if (pk != LC_GOSIG_KEY_ED25519)
            return mismatch(e, pk, "ed25519.PublicKey");
        int ok = ed25519_verify(pub->ed25519, msg, msg_len, sig, sig_len);
        if (ok < 0)
            return ok;
        return ok ? 0 : fail(e, LC_GO("x509: Ed25519 verification failure"));
    }
    case LC_GOSIG_KEY_MLDSA: {
        if (pk != LC_GOSIG_KEY_MLDSA)
            return mismatch(e, pk, "*mldsa.PublicKey");
        int want = pub->mldsa == LC_GOSIG_MLDSA44   ? LC_GO_SIG_MLDSA44
                   : pub->mldsa == LC_GOSIG_MLDSA65 ? LC_GO_SIG_MLDSA65
                   : pub->mldsa == LC_GOSIG_MLDSA87 ? LC_GO_SIG_MLDSA87
                                                    : -1;
        if (want < 0) {
            /* Unreachable from a parsed certificate: ParseCertificate makes no other key, and
             * Go's Parameters() panics on one (GOROOT/src/crypto/mldsa/mldsa_fips140v1.26.go:
             * 200-211). The number stands in for the name it does not have. */
            snprintf(nb, sizeof nb, "%d", pub->mldsa);
            return failf(e, LC_GO("x509: unknown ML-DSA parameters: %s"), nb);
        }
        if (sig_alg != want)
            return failf(e,
                         LC_GO("x509: signature algorithm specifies an ML-DSA public key with %s "
                               "parameters, but have a public key with %s parameters"),
                         lc_go_sig_alg_name(sig_alg, nb), mldsa_name(pub->mldsa));
        lc_obuf inner = { 0 };
        int     rc = lc_mldsa_verify(pub->mldsa, pub->mldsa_pk, pub->mldsa_pk_len, msg, msg_len, sig,
                                     sig_len, &inner);
        if (rc == -1 && !inner.oom)
            rc = failf(e, LC_GO("x509: ML-DSA verification failure: %w"),
                       inner.p != NULL ? inner.p : "");
        else if (rc != 0)
            rc = -2;
        free(inner.p);
        return rc;
    }
    default:
        /* nil, *dsa.PublicKey, anything else: no case matches (:1140). */
        return unsupported(e);
    }
}

int lc_go_check_signature(int sig_alg, const uint8_t *signed_, size_t signed_len, const uint8_t *sig,
                          size_t sig_len, const lc_gopubkey *pub, lc_obuf *err)
{
    int rc = check(sig_alg, signed_, signed_len, sig, sig_len, pub, err);
    if (rc == -1 && err != NULL && err->oom)
        return -2;
    return rc;
}

/* ---- for the handshake's own signatures -------------------------------------------------------- */

int lc_go_rsa_verify(int pss, int hash, const uint8_t *hashed, size_t hlen, const uint8_t *sig,
                     size_t sig_len, const lc_gopubkey *pub, lc_obuf *err)
{
    if (hash < LC_GOSIG_HASH_SHA1 || hash > LC_GOSIG_HASH_SHA512 || pub == NULL ||
        pub->kind != LC_GOSIG_KEY_RSA)
        return -2;
    return rsa_verify(pss, hash, hashed, hlen, sig, sig_len, pub, err);
}

int lc_go_ecdsa_verify_asn1(const lc_gopubkey *pub, const uint8_t *hash, size_t hlen, const uint8_t *sig,
                            size_t sig_len)
{
    if (pub == NULL || pub->kind != LC_GOSIG_KEY_ECDSA)
        return -2;
    return ecdsa_verify(pub, hash, hlen, sig, sig_len);
}

void lc_gopubkey_of(const lc_gocert *c, lc_gopubkey *k)
{
    memset(k, 0, sizeof *k);
    if (!c->pk_present)
        return; /* PublicKey nil: an algorithm the parser does not know */
    switch (c->pk_alg) {
    case LC_GO_PK_RSA:
        k->kind = LC_GOSIG_KEY_RSA;
        k->rsa_n = c->rsa_n.p;
        k->rsa_n_len = c->rsa_n.n;
        k->rsa_e = c->rsa_e;
        break;
    case LC_GO_PK_DSA:
        k->kind = LC_GOSIG_KEY_DSA;
        break;
    case LC_GO_PK_ECDSA:
        k->kind = LC_GOSIG_KEY_ECDSA;
        k->curve = c->curve; /* the same numbering, P-224 first */
        k->point = c->key;
        k->point_len = c->key_n;
        break;
    case LC_GO_PK_ED25519:
        k->kind = LC_GOSIG_KEY_ED25519;
        memcpy(k->ed25519, c->key, 32);
        break;
    case LC_GO_PK_MLDSA:
        k->kind = LC_GOSIG_KEY_MLDSA;
        k->mldsa = c->mldsa;
        k->mldsa_pk = c->key;
        k->mldsa_pk_len = c->key_n;
        break;
    default:
        break;
    }
}

const char *lc_gopubkey_type(const lc_gopubkey *k)
{
    switch (k->kind) {
    case LC_GOSIG_KEY_RSA: return "*rsa.PublicKey";
    case LC_GOSIG_KEY_DSA: return "*dsa.PublicKey";
    case LC_GOSIG_KEY_ECDSA: return "*ecdsa.PublicKey";
    case LC_GOSIG_KEY_ED25519: return "ed25519.PublicKey";
    case LC_GOSIG_KEY_MLDSA: return "*mldsa.PublicKey";
    default: return "<nil>";
    }
}
