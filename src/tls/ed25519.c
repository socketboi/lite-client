#include "tls/ed25519.h"

#include "core/wipe.h"
#include "tls/fe25519.h"

#include <string.h>

#include <mbedtls/bignum.h>
#include <mbedtls/md.h>

/* ⚠️ THE SIEVE CANNOT CHECK THIS FILE, AND THAT IS A BOUNDARY RATHER THAN A DEBT.
 *
 * COVERAGE.md lists it among the files nothing cites — 440 lines, the largest of them, and on the
 * REALITY hot path, since this is what decides whether the node's certificate signature holds. The
 * obvious reading is "the biggest hole in the audit". It is not, and the reason is worth stating
 * where somebody will meet it rather than in a report that is not even in git.
 *
 * There is nothing to cite, and that has to be said twice, because COVERAGE.md guesses otherwise:
 * it lists vendor/mbedtls/library/psa_crypto.c beside this file. That guess is mechanical and it is
 * wrong — the vendored mbedTLS carries no Ed25519 at all. Its config enables
 * MBEDTLS_ECP_DP_CURVE25519_ENABLED (vendor/mbedtls/include/mbedtls/mbedtls_config.h:772), which is
 * X25519, a different curve used for a different job; the only occurrence of the word in its
 * library sources is a name in a generated debug table. There is no implementation there to compare
 * against.
 *
 * The reference verifies with Go's `ed25519.Verify` — its standard
 * library, which is not vendored either — and matching an implementation of a verifier byte for
 * byte is not a meaningful goal:
 * two verifiers agree when they accept exactly the same signatures, not when they compute the
 * intermediate points the same way. Nothing about this code reaches the wire. What reaches the wire
 * is one bit: accepted, or not.
 *
 * So the criterion is the standard, and it is the same criterion Go's own implementation is held
 * to: RFC 8032 §7.1, TEST 1, 2, 3 and "TEST SHA(abc)", in test/ed25519 — which the gate runs.
 *
 * ⚠️ AND THE NEGATIVE CASES ARE THE POINT, because a verifier that returns success for
 * everything passes all four published vectors and is worthless — and that is not a hypothetical
 * failure mode here: it is what this client did before this file existed, by never checking the
 * signature at all. The test therefore also feeds it a flipped bit in each half of the signature,
 * the wrong public key, a mutated message, an S at and above the group order, and encodings that
 * are not points on the curve. A pair against a vendor line could not have asked any of that.
 *
 * The curve, written as decimal so that each constant can be read against RFC 8032 §5.1 without
 * decoding anything. They are parsed once per verification, which costs nothing measurable beside
 * two scalar multiplications and keeps this file free of a static initialiser that would have to be
 * synchronised with mbedTLS's internal representation. */
#define D_DEC  "37095705934669439343138083508754565189542113879843219016388785533085940283555"
#define L_DEC  "7237005577332262213973186563042994240857116359379907606001950938285454250989"
#define BX_DEC "15112221349535400772501151409588531511454012693041857206046113283949847762202"
#define BY_DEC "46316835694926478169428394003475163141307993866256225615783033603165251855960"
/* sqrt(-1) mod p, needed when the first square-root candidate is wrong by that factor. */
#define I_DEC  "19681161376707505956807079304988542015446066515923890162744021073123829784752"

/* A point in extended twisted-Edwards coordinates: x = X/Z, y = Y/Z, xy = T/Z.
 *
 * Extended rather than affine because the addition law below is then complete for a = -1: one
 * formula adds any two points and doubles any point, with no special case for equal inputs, for the
 * identity, or for a point and its negation. A verifier with a special case has a branch an
 * attacker chooses. */
typedef struct {
    lc_fe X, Y, Z, T;
} ge;

/* The two curve constants these routines need, as field elements.
 *
 * ⚠️ DECODED FROM THE DECIMAL STRINGS THIS FILE ALREADY CARRIED, NOT WRITTEN OUT AS LIMBS. The limb
 * form of d, of 2d and of sqrt(-1) is forty numbers that mean nothing to a reader and that no test
 * in this tree would catch a typo in — RFC 8032's vectors would simply stop passing, with no hint
 * which constant was wrong. The decimal strings are the ones the standard prints, they were already
 * here and already verified by those vectors, and turning one into limbs costs a bignum parse and a
 * 32-byte write once per verification: microseconds against the fifteen milliseconds below. */
typedef struct {
    lc_fe d;      /* the curve's d */
    lc_fe d2;     /* 2d, which the addition law uses */
    lc_fe sqrtm1; /* a square root of -1, for the decoder */
} ed_consts;

static int fe_from_dec(lc_fe out, const char *dec)
{
    mbedtls_mpi v;
    uint8_t     le[32];
    int         rc;

    mbedtls_mpi_init(&v);
    rc = mbedtls_mpi_read_string(&v, 10, dec) != 0 ||
         mbedtls_mpi_write_binary_le(&v, le, sizeof le) != 0;
    mbedtls_mpi_free(&v);
    if (rc)
        return -1;
    lc_fe_frombytes(out, le);
    lc_wipe(le, sizeof le);
    return 0;
}

static int ed_consts_load(ed_consts *c)
{
    if (fe_from_dec(c->d, D_DEC) != 0 || fe_from_dec(c->sqrtm1, I_DEC) != 0)
        return -1;
    lc_fe_add(c->d2, c->d, c->d);
    return 0;
}

/* r = p1 + p2, the unified extended-coordinate formula for a = -1 (Hisil–Wong–Carter–Dawson,
 * "add-2008-hwcd-3"). Complete on this curve because d is not a square, so it doubles as the
 * doubling routine and this file has one point operation rather than two.
 *
 *   A = (Y1-X1)(Y2-X2)   B = (Y1+X1)(Y2+X2)   C = T1·2d·T2   D = (Z1+Z1)·Z2
 *   E = B-A   F = D-C   G = D+C   H = B+A
 *   X3 = E·F  Y3 = G·H  T3 = E·H  Z3 = F·G
 *
 * ⚠️ D IS WRITTEN (Z1+Z1)·Z2 RATHER THAN 2·(Z1·Z2), AND THAT IS NOT COSMETIC. The field keeps its
 * limbs unreduced and guarantees only a bound: a product comes back at one level and a single
 * addition of two products is the most that may be fed back into a multiplication (fe25519.h spells
 * this out). Doubling a product and then subtracting another from it is TWO steps above a product,
 * which is outside what lc_fe_mul's accumulators are proved to hold. Folding the doubling into a
 * multiplicand instead — Z1+Z1 is one addition, and it is an input, not a result — keeps every
 * value inside the contract, and the arithmetic is identical. */
static int ge_add(ge *r, const ge *p1, const ge *p2, const ed_consts *c)
{
    lc_fe a, b, cc, d, e, f, g, h, t;

    lc_fe_sub(a, p1->Y, p1->X);
    lc_fe_sub(t, p2->Y, p2->X);
    lc_fe_mul(a, a, t);

    lc_fe_add(b, p1->Y, p1->X);
    lc_fe_add(t, p2->Y, p2->X);
    lc_fe_mul(b, b, t);

    lc_fe_mul(cc, p1->T, c->d2);
    lc_fe_mul(cc, cc, p2->T);

    lc_fe_add(t, p1->Z, p1->Z);
    lc_fe_mul(d, t, p2->Z);

    lc_fe_sub(e, b, a);
    lc_fe_sub(f, d, cc);
    lc_fe_add(g, d, cc);
    lc_fe_add(h, b, a);

    lc_fe_mul(r->X, e, f);
    lc_fe_mul(r->Y, g, h);
    lc_fe_mul(r->T, e, h);
    lc_fe_mul(r->Z, f, g);
    return 0;
}

/* r = [s]P + [k]Q, most significant bit first, both scalars in ONE pass.
 *
 * A verification needs exactly two scalar multiplications and never one, so it is written as the
 * pair rather than as a single multiplication called twice — and that is not a tidiness argument,
 * it is where a third of the cost went. Done separately, each pass doubles at every bit position:
 * 253 doublings apiece, 506 in total, and the doublings are the bulk of the work. Interleaved, one
 * doubling per position serves both scalars, and the price is a single precomputed P+Q: about 253
 * doublings and 190 additions instead of 506 and 253. Straus's method, called Shamir's trick nearly
 * everywhere.
 *
 * No precomputed table beyond that one sum, not even for the base point. The usual ref10 table is
 * some thirty kilobytes of flash to save a few milliseconds once per handshake, and flash is the
 * resource this whole client exists to fit into. No windowing either, for the same reason.
 *
 * Variable time by construction, and that is correct here: both scalars are public — one is read
 * from the signature, the other is a hash of public inputs. Nothing secret passes through here.
 *
 * ge_add is the complete unified formula, so `ge_add(r, r, r, …)` doubles and every aliasing below
 * is one it already handles; there is no special case for the identity, for equal inputs, or for a
 * point and its negation, which is exactly why interleaving is safe to write this plainly. */
static int ge_dual_scalarmult(ge *r, const mbedtls_mpi *s, const ge *P, const mbedtls_mpi *k,
                              const ge *Q, const ed_consts *c)
{
    ge sum;

    if (ge_add(&sum, P, Q, c) != 0)
        return -1;

    /* The identity in extended coordinates: (0 : 1 : 1 : 0). */
    lc_fe_0(r->X);
    lc_fe_1(r->Y);
    lc_fe_1(r->Z);
    lc_fe_0(r->T);

    size_t sb = mbedtls_mpi_bitlen(s);
    size_t kb = mbedtls_mpi_bitlen(k);
    size_t bits = sb > kb ? sb : kb;

    for (size_t i = bits; i > 0; i--) {
        if (ge_add(r, r, r, c) != 0)
            return -1;

        int       bs = mbedtls_mpi_get_bit(s, i - 1);
        int       bk = mbedtls_mpi_get_bit(k, i - 1);
        const ge *add = (bs && bk) ? &sum : bs ? P : bk ? Q : NULL;

        if (add != NULL && ge_add(r, r, add, c) != 0)
            return -1;
    }
    return 0;
}

/* Decodes a 32-byte encoding into a point, per RFC 8032 §5.1.3.
 *
 * The encoding is y in little-endian with the sign of x in the top bit. Recovering x means a square
 * root: x = ±sqrt((y²-1)/(dy²+1)), computed as a candidate and then CHECKED, because the exponent
 * (p-5)/8 gives the right answer only up to a factor of sqrt(-1) — and if neither candidate squares
 * back to the target, the encoding is not a point at all and must be refused rather than
 * approximated.
 *
 * A refusal here is the whole reason this function returns a value: an attacker chooses these bytes.
 *
 * ⚠️ THE CANONICALITY CHECK IS NOW A ROUND TRIP, and it has to be. The old code compared the decoded
 * y against p as bignums; the field here does not compare, it encodes — so the test is that
 * re-encoding the decoded y gives back the bytes that came in. An encoding of y >= p decodes to
 * y - p and re-encodes differently, which is exactly what must be refused.
 *
 * ⚠️ BUT ONLY FOR R, NOT FOR THE KEY — `lax` is the key's decoding. The reference decodes the public
 * key with edwards25519's Point.SetBytes, which takes both encodings RFC 8032 refuses: a y that is
 * not reduced, and an x of zero with the sign bit set
 * (GOROOT/src/crypto/internal/fips140/edwards25519/edwards25519.go:145-187, the same in go1.26.6
 * and go1.27.1). R it never decodes: it computes [S]B - [k]A, encodes that, and compares the bytes
 * (GOROOT/src/crypto/internal/fips140/ed25519/ed25519.go:320-326) — which this does by decoding R
 * strictly and comparing points, since only a canonical R can equal a canonical encoding. Refusing
 * the two lax key encodings refused fifteen signatures Go accepts, all of them with small-order
 * keys (test/ed25519's Go vectors). */
static int ge_decode(ge *r, const uint8_t in[32], const ed_consts *c, int lax)
{
    uint8_t  le[32], again[32];
    unsigned x_sign;
    lc_fe    u, v, v3, t, x2, one;
    int      rc = -1;

    memcpy(le, in, 32);
    x_sign = (unsigned)(le[31] >> 7);
    le[31] = (uint8_t)(le[31] & 0x7fu);

    lc_fe_frombytes(r->Y, le);
    lc_fe_tobytes(again, r->Y);
    if (!lax && memcmp(again, le, sizeof le) != 0)
        goto done; /* y >= p: not a canonical encoding, and not a point */

    lc_fe_1(one);
    lc_fe_sq(t, r->Y);            /* y² */
    lc_fe_sub(u, t, one);         /* u = y² - 1 */
    lc_fe_mul(v, t, c->d);        /* d·y² */
    lc_fe_add(v, v, one);         /* v = d·y² + 1 */

    /* x = u·v³·(u·v⁷)^((p-5)/8) */
    lc_fe_sq(v3, v);
    lc_fe_mul(v3, v3, v);         /* v³ */
    lc_fe_sq(t, v3);              /* v⁶ */
    lc_fe_mul(t, t, v);           /* v⁷ */
    lc_fe_mul(t, t, u);           /* u·v⁷ */
    lc_fe_pow22523(t, t);
    lc_fe_mul(r->X, u, v3);
    lc_fe_mul(r->X, r->X, t);

    /* Check v·x² == u; if not, multiply by sqrt(-1) and check again; if still not, refuse. */
    lc_fe_sq(x2, r->X);
    lc_fe_mul(x2, x2, v);
    lc_fe_sub(t, x2, u);
    if (!lc_fe_iszero(t)) {
        lc_fe_mul(r->X, r->X, c->sqrtm1);
        lc_fe_sq(x2, r->X);
        lc_fe_mul(x2, x2, v);
        lc_fe_sub(t, x2, u);
        if (!lc_fe_iszero(t))
            goto done; /* not a point */
    }

    /* x = 0 with the sign bit set has no encoding: RFC 8032 §5.1.3 refuses it by name, Go's key
     * decoding negates the zero and goes on. */
    if (!lax && lc_fe_iszero(r->X) && x_sign != 0u)
        goto done;
    if ((unsigned)lc_fe_isnegative(r->X) != x_sign)
        lc_fe_neg(r->X, r->X);

    lc_fe_1(r->Z);
    lc_fe_mul(r->T, r->X, r->Y);
    rc = 0;

done:
    lc_wipe(le, sizeof le);
    return rc;
}

/* Whether two points are equal, compared projectively: X1·Z2 == X2·Z1 and Y1·Z2 == Y2·Z1.
 *
 * Projectively rather than by normalising both to affine, because normalising needs a modular
 * inversion each and the comparison needs none. */
static int ge_equal(const ge *a, const ge *b)
{
    lc_fe l, r, t;

    lc_fe_mul(l, a->X, b->Z);
    lc_fe_mul(r, b->X, a->Z);
    lc_fe_sub(t, l, r);
    if (!lc_fe_iszero(t))
        return 0;

    lc_fe_mul(l, a->Y, b->Z);
    lc_fe_mul(r, b->Y, a->Z);
    lc_fe_sub(t, l, r);
    return lc_fe_iszero(t);
}
int lc_ed25519_verify(const uint8_t pub[LC_ED25519_PUBKEY], const uint8_t *msg, size_t msg_len,
                      const uint8_t sig[LC_ED25519_SIG])
{
    int rc = -1;

    ed_consts   c;
    mbedtls_mpi l, s, k;
    ge          A, R, B, lhs, negA;

    mbedtls_mpi_init(&l);
    mbedtls_mpi_init(&s);
    mbedtls_mpi_init(&k);

    if (ed_consts_load(&c) != 0)
        goto done;
    if (mbedtls_mpi_read_string(&l, 10, L_DEC) != 0)
        goto done;

    /* S, the second half of the signature, little-endian. RFC 8032 §5.1.7 requires S < L to be
     * CHECKED and the signature refused otherwise — not reduced. Reducing would make every
     * signature malleable: S and S+L would both verify, so one signature would have many encodings,
     * and anything upstream that treats a signature as an identity would be wrong. */
    {
        uint8_t be[32];
        for (size_t i = 0; i < 32u; i++)
            be[i] = sig[63u - i];
        if (mbedtls_mpi_read_binary(&s, be, sizeof be) != 0)
            goto done;
        memset(be, 0, sizeof be);
    }
    if (mbedtls_mpi_cmp_mpi(&s, &l) >= 0)
        goto done;

    /* A and R must both be points. A public key that is not one is refused here rather than
     * producing a comparison between two meaningless values. */
    if (ge_decode(&A, pub, &c, 1) != 0)
        goto done;
    if (ge_decode(&R, sig, &c, 0) != 0)
        goto done;

    /* The base point, from its affine coordinates. */
    if (fe_from_dec(B.X, BX_DEC) != 0 || fe_from_dec(B.Y, BY_DEC) != 0)
        goto done;
    lc_fe_1(B.Z);
    lc_fe_mul(B.T, B.X, B.Y);

    /* k = SHA-512(R || A || M) mod L */
    {
        const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
        if (info == NULL)
            goto done;
        mbedtls_md_context_t md;
        mbedtls_md_init(&md);
        uint8_t digest[64];
        int     mrc = mbedtls_md_setup(&md, info, 0) != 0 || mbedtls_md_starts(&md) != 0 ||
                  mbedtls_md_update(&md, sig, 32u) != 0 ||
                  mbedtls_md_update(&md, pub, LC_ED25519_PUBKEY) != 0 ||
                  (msg_len != 0u && mbedtls_md_update(&md, msg, msg_len) != 0) ||
                  mbedtls_md_finish(&md, digest) != 0;
        mbedtls_md_free(&md);
        if (mrc) {
            memset(digest, 0, sizeof digest);
            goto done;
        }
        uint8_t be[64];
        for (size_t i = 0; i < 64u; i++)
            be[i] = digest[63u - i];
        int krc = mbedtls_mpi_read_binary(&k, be, sizeof be) != 0 ||
                  mbedtls_mpi_mod_mpi(&k, &k, &l) != 0;
        memset(digest, 0, sizeof digest);
        memset(be, 0, sizeof be);
        if (krc)
            goto done;
    }

    /* [S]B == R + [k]A, rearranged to [S]B + [k](-A) == R so that both multiplications can share
     * their doublings — see ge_dual_scalarmult. The rearrangement is exact, not an approximation:
     * adding -[k]A to both sides of an equation between group elements.
     *
     * -(X : Y : Z : T) = (-X : Y : Z : -T) on a twisted Edwards curve with a = -1, because negating
     * a point negates its x and therefore its xy. Written as a negation rather than as p - c, which
     * is what this had to be while the coordinates were unsigned bignums: the field here keeps a
     * sign, so a coordinate of zero stays zero instead of arriving as p and needing to be brought
     * back. */
    lc_fe_neg(negA.X, A.X);
    lc_fe_copy(negA.Y, A.Y);
    lc_fe_copy(negA.Z, A.Z);
    lc_fe_neg(negA.T, A.T);

    if (ge_dual_scalarmult(&lhs, &s, &B, &k, &negA, &c) != 0)
        goto done;

    rc = ge_equal(&lhs, &R) ? 0 : -1;
done:
    mbedtls_mpi_free(&l);
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&k);
    return rc;
}
