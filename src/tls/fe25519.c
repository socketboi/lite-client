#include "tls/fe25519.h"

#include "core/wipe.h"

#if !defined(LC_FE_RADIX51)
/* ---- ref10: ten signed limbs of 25.5 bits, for 32-bit machines (the MIPS routers) ---- */

/* How wide limb i is. Written as a function of the index rather than a table because every loop
 * below needs it and a table would be one more thing to keep in step. */
static unsigned lc_fe_width(unsigned i)
{
    return (i & 1u) ? 25u : 26u;
}

/* Brings a wide accumulator back to ten limbs inside their widths.
 *
 * Each limb hands its overflow to the next, rounded rather than truncated — `+ half` before the
 * shift, so that a negative limb carries the way a positive one does and the remainder stays
 * centred on zero. Limb 9 wraps to limb 0 multiplied by 19, which is the fold again.
 *
 * TWELVE STEPS IN THIS ORDER, NOT A LOOP OVER TEN. Every limb must receive its incoming carry
 * before it is carried itself, and limb 0 must be carried again after limb 9 has wrapped into it;
 * the sequence below is ref10's, and it satisfies both with two limbs done twice. A plain loop
 * needs two full passes — twenty steps — to reach the same state, and a REALITY handshake runs it
 * about thirteen thousand times: three Montgomery ladders at roughly 2 800 each (255 steps of ten
 * field operations, plus the inversion) and an Ed25519 verification at roughly 4 500 (some 440 point
 * additions of nine multiplications each, plus its own inversion). */
static void lc_fe_carry(lc_fe h, int64_t t[10])
{
#define LC_FE_CARRY(i, next, w, extra)                                                             \
    do {                                                                                           \
        int64_t c = (t[i] + ((int64_t)1 << ((w) - 1))) >> (w);                                     \
        t[next] += c * (extra);                                                                    \
        t[i] -= c << (w);                                                                          \
    } while (0)

    LC_FE_CARRY(0, 1, 26, 1);
    LC_FE_CARRY(4, 5, 26, 1);
    LC_FE_CARRY(1, 2, 25, 1);
    LC_FE_CARRY(5, 6, 25, 1);
    LC_FE_CARRY(2, 3, 26, 1);
    LC_FE_CARRY(6, 7, 26, 1);
    LC_FE_CARRY(3, 4, 25, 1);
    LC_FE_CARRY(7, 8, 25, 1);
    LC_FE_CARRY(4, 5, 26, 1);
    LC_FE_CARRY(8, 9, 26, 1);
    LC_FE_CARRY(9, 0, 25, 19);
    LC_FE_CARRY(0, 1, 26, 1);
#undef LC_FE_CARRY

    for (unsigned i = 0; i < 10u; i++)
        h[i] = (int32_t)t[i];
}

/* THE MULTIPLICATION, AS THE WEIGHTS DICTATE IT.
 *
 * Limb i has weight 2^ceil(25.5i) and limb j weight 2^ceil(25.5j), so their product belongs at
 * weight 2^(ceil(25.5i)+ceil(25.5j)) while limb i+j carries 2^ceil(25.5(i+j)). Those agree except
 * when i and j are BOTH ODD: then each ceiling rounded up by a half and their sum is one whole bit
 * heavier than the target's, so the product is doubled going in. Above limb 9 the same arithmetic
 * gives the fold: limb i+j and limb i+j-10 differ in weight by exactly 2^255, which is 19 mod p.
 *
 * ⚠️ WRITTEN OUT, AND THE FIRST VERSION OF THIS FILE WAS NOT — IT WAS MEASURED AND IT WAS NO FASTER
 * THAN WHAT IT REPLACED. The rule above is four lines as a pair of loops, and that form states
 * what this does far better than a hundred named products do — but on the router it cost 18.27 ms
 * per scalar multiplication against the mbedTLS it was meant to beat at 16.40: the whole point of
 * the exercise, gone. Written out it is 5.30 on the same box. A field
 * multiplication is a hundred 32x32 products, which is about six hundred cycles on this processor;
 * everything else in that loop — two index computations, two branches, a multiply by 2 or by 19
 * chosen at run time — cost five thousand more.
 *
 * So the factors are hoisted, each limb of g multiplied by 19 once instead of nine times, and the
 * rows are spelled out. The differential test in test/x25519 is what makes that safe: a transposed
 * index here is wrong on almost every input, and 128 random pairs against mbedTLS find it at once.
 * That test was written before this unrolling, on purpose.
 *
 * THE BOUND. With every |f_i| and |g_i| below 1.65*2^26 — ref10's own precondition, which lc_fe_add
 * and lc_fe_sub maintain — each product is under 2^53.5 and a row of ten, some of them scaled by 19
 * and by 2, is under 2^62: inside int64 with a bit to spare. */
void lc_fe_mul(lc_fe h, const lc_fe f, const lc_fe g)
{
    int32_t f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4];
    int32_t f5 = f[5], f6 = f[6], f7 = f[7], f8 = f[8], f9 = f[9];
    int32_t g0 = g[0], g1 = g[1], g2 = g[2], g3 = g[3], g4 = g[4];
    int32_t g5 = g[5], g6 = g[6], g7 = g[7], g8 = g[8], g9 = g[9];

    /* The fold, applied once per limb of g rather than once per product that wraps. */
    int32_t g1_19 = 19 * g1, g2_19 = 19 * g2, g3_19 = 19 * g3, g4_19 = 19 * g4;
    int32_t g5_19 = 19 * g5, g6_19 = 19 * g6, g7_19 = 19 * g7, g8_19 = 19 * g8;
    int32_t g9_19 = 19 * g9;
    /* The odd-odd doubling, likewise: only the odd limbs of f ever need it. */
    int32_t f1_2 = 2 * f1, f3_2 = 2 * f3, f5_2 = 2 * f5, f7_2 = 2 * f7, f9_2 = 2 * f9;

    int64_t t[10];

    t[0] = f0 * (int64_t)g0 + f1_2 * (int64_t)g9_19 + f2 * (int64_t)g8_19 +
           f3_2 * (int64_t)g7_19 + f4 * (int64_t)g6_19 + f5_2 * (int64_t)g5_19 +
           f6 * (int64_t)g4_19 + f7_2 * (int64_t)g3_19 + f8 * (int64_t)g2_19 +
           f9_2 * (int64_t)g1_19;
    t[1] = f0 * (int64_t)g1 + f1 * (int64_t)g0 + f2 * (int64_t)g9_19 + f3 * (int64_t)g8_19 +
           f4 * (int64_t)g7_19 + f5 * (int64_t)g6_19 + f6 * (int64_t)g5_19 +
           f7 * (int64_t)g4_19 + f8 * (int64_t)g3_19 + f9 * (int64_t)g2_19;
    t[2] = f0 * (int64_t)g2 + f1_2 * (int64_t)g1 + f2 * (int64_t)g0 + f3_2 * (int64_t)g9_19 +
           f4 * (int64_t)g8_19 + f5_2 * (int64_t)g7_19 + f6 * (int64_t)g6_19 +
           f7_2 * (int64_t)g5_19 + f8 * (int64_t)g4_19 + f9_2 * (int64_t)g3_19;
    t[3] = f0 * (int64_t)g3 + f1 * (int64_t)g2 + f2 * (int64_t)g1 + f3 * (int64_t)g0 +
           f4 * (int64_t)g9_19 + f5 * (int64_t)g8_19 + f6 * (int64_t)g7_19 +
           f7 * (int64_t)g6_19 + f8 * (int64_t)g5_19 + f9 * (int64_t)g4_19;
    t[4] = f0 * (int64_t)g4 + f1_2 * (int64_t)g3 + f2 * (int64_t)g2 + f3_2 * (int64_t)g1 +
           f4 * (int64_t)g0 + f5_2 * (int64_t)g9_19 + f6 * (int64_t)g8_19 +
           f7_2 * (int64_t)g7_19 + f8 * (int64_t)g6_19 + f9_2 * (int64_t)g5_19;
    t[5] = f0 * (int64_t)g5 + f1 * (int64_t)g4 + f2 * (int64_t)g3 + f3 * (int64_t)g2 +
           f4 * (int64_t)g1 + f5 * (int64_t)g0 + f6 * (int64_t)g9_19 + f7 * (int64_t)g8_19 +
           f8 * (int64_t)g7_19 + f9 * (int64_t)g6_19;
    t[6] = f0 * (int64_t)g6 + f1_2 * (int64_t)g5 + f2 * (int64_t)g4 + f3_2 * (int64_t)g3 +
           f4 * (int64_t)g2 + f5_2 * (int64_t)g1 + f6 * (int64_t)g0 + f7_2 * (int64_t)g9_19 +
           f8 * (int64_t)g8_19 + f9_2 * (int64_t)g7_19;
    t[7] = f0 * (int64_t)g7 + f1 * (int64_t)g6 + f2 * (int64_t)g5 + f3 * (int64_t)g4 +
           f4 * (int64_t)g3 + f5 * (int64_t)g2 + f6 * (int64_t)g1 + f7 * (int64_t)g0 +
           f8 * (int64_t)g9_19 + f9 * (int64_t)g8_19;
    t[8] = f0 * (int64_t)g8 + f1_2 * (int64_t)g7 + f2 * (int64_t)g6 + f3_2 * (int64_t)g5 +
           f4 * (int64_t)g4 + f5_2 * (int64_t)g3 + f6 * (int64_t)g2 + f7_2 * (int64_t)g1 +
           f8 * (int64_t)g0 + f9_2 * (int64_t)g9_19;
    t[9] = f0 * (int64_t)g9 + f1 * (int64_t)g8 + f2 * (int64_t)g7 + f3 * (int64_t)g6 +
           f4 * (int64_t)g5 + f5 * (int64_t)g4 + f6 * (int64_t)g3 + f7 * (int64_t)g2 +
           f8 * (int64_t)g1 + f9 * (int64_t)g0;

    lc_fe_carry(h, t);
}

/* The square, which is the multiply with the two triangles folded together: every off-diagonal
 * product appears twice in f*f, so it is formed once and doubled, and the odd-odd rule doubles it
 * again where it applies. The constants below are those factors already multiplied out — 38 is
 * 2*19, and a doubled f against a 38 is the 4*19 that a wrapped odd-odd product needs. */
void lc_fe_sq(lc_fe h, const lc_fe f)
{
    int32_t f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4];
    int32_t f5 = f[5], f6 = f[6], f7 = f[7], f8 = f[8], f9 = f[9];

    int32_t f0_2 = 2 * f0, f1_2 = 2 * f1, f2_2 = 2 * f2, f3_2 = 2 * f3;
    int32_t f4_2 = 2 * f4, f5_2 = 2 * f5, f6_2 = 2 * f6, f7_2 = 2 * f7;
    int32_t f5_38 = 38 * f5, f6_19 = 19 * f6, f7_38 = 38 * f7, f8_19 = 19 * f8, f9_38 = 38 * f9;

    int64_t t[10];

    t[0] = f0 * (int64_t)f0 + f1_2 * (int64_t)f9_38 + f2_2 * (int64_t)f8_19 +
           f3_2 * (int64_t)f7_38 + f4_2 * (int64_t)f6_19 + f5 * (int64_t)f5_38;
    t[1] = f0_2 * (int64_t)f1 + f2 * (int64_t)f9_38 + f3_2 * (int64_t)f8_19 +
           f4 * (int64_t)f7_38 + f5_2 * (int64_t)f6_19;
    t[2] = f0_2 * (int64_t)f2 + f1_2 * (int64_t)f1 + f3_2 * (int64_t)f9_38 +
           f4_2 * (int64_t)f8_19 + f5_2 * (int64_t)f7_38 + f6 * (int64_t)f6_19;
    t[3] = f0_2 * (int64_t)f3 + f1_2 * (int64_t)f2 + f4 * (int64_t)f9_38 +
           f5_2 * (int64_t)f8_19 + f6 * (int64_t)f7_38;
    t[4] = f0_2 * (int64_t)f4 + f1_2 * (int64_t)f3_2 + f2 * (int64_t)f2 +
           f5_2 * (int64_t)f9_38 + f6_2 * (int64_t)f8_19 + f7 * (int64_t)f7_38;
    t[5] = f0_2 * (int64_t)f5 + f1_2 * (int64_t)f4 + f2_2 * (int64_t)f3 + f6 * (int64_t)f9_38 +
           f7_2 * (int64_t)f8_19;
    t[6] = f0_2 * (int64_t)f6 + f1_2 * (int64_t)f5_2 + f2_2 * (int64_t)f4 + f3_2 * (int64_t)f3 +
           f7_2 * (int64_t)f9_38 + f8 * (int64_t)f8_19;
    t[7] = f0_2 * (int64_t)f7 + f1_2 * (int64_t)f6 + f2_2 * (int64_t)f5 + f3_2 * (int64_t)f4 +
           f8 * (int64_t)f9_38;
    t[8] = f0_2 * (int64_t)f8 + f1_2 * (int64_t)f7_2 + f2_2 * (int64_t)f6 + f3_2 * (int64_t)f5_2 +
           f4 * (int64_t)f4 + f9 * (int64_t)f9_38;
    t[9] = f0_2 * (int64_t)f9 + f1_2 * (int64_t)f8 + f2_2 * (int64_t)f7 + f3_2 * (int64_t)f6 +
           f4_2 * (int64_t)f5;

    lc_fe_carry(h, t);
}
/* h = f * 121666, the one constant the ladder multiplies by. A limb is under 2^27 and 121666 is
 * under 2^17, so a product is under 2^44 and the accumulator cannot overflow whatever the input. */
void lc_fe_mul121666(lc_fe h, const lc_fe f)
{
    int64_t t[10];

    for (unsigned i = 0; i < 10u; i++)
        t[i] = (int64_t)f[i] * 121666;

    lc_fe_carry(h, t);
}

void lc_fe_0(lc_fe h)
{
    for (unsigned i = 0; i < 10u; i++)
        h[i] = 0;
}

void lc_fe_1(lc_fe h)
{
    lc_fe_0(h);
    h[0] = 1;
}

void lc_fe_copy(lc_fe h, const lc_fe f)
{
    for (unsigned i = 0; i < 10u; i++)
        h[i] = f[i];
}

/* Addition and subtraction limb by limb, with no carry at all: the result's limbs are at most one
 * bit wider than the inputs', and lc_fe_mul's precondition has room for that. This is what the signed,
 * unreduced representation buys — no conditional subtraction of p anywhere, and therefore nothing
 * whose timing depends on the value. */
void lc_fe_add(lc_fe h, const lc_fe f, const lc_fe g)
{
    for (unsigned i = 0; i < 10u; i++)
        h[i] = f[i] + g[i];
}

void lc_fe_sub(lc_fe h, const lc_fe f, const lc_fe g)
{
    for (unsigned i = 0; i < 10u; i++)
        h[i] = f[i] - g[i];
}

/* Swaps f and g when b is 1 and leaves them alone when b is 0, in the same instructions either way.
 *
 * The ladder consults a bit of the private key to decide this, so a branch here would put that bit
 * on the wire as a timing difference — which is the attack the ladder is shaped to avoid in the
 * first place. The mask is built by negating b as a signed value, so 1 becomes all ones and 0 stays
 * all zeros; the exclusive-ors then either exchange the limbs or exchange nothing. */
void lc_fe_cswap(lc_fe f, lc_fe g, unsigned b)
{
    uint32_t mask = (uint32_t)(-(int32_t)b);

    for (unsigned i = 0; i < 10u; i++) {
        uint32_t x = ((uint32_t)f[i] ^ (uint32_t)g[i]) & mask;

        f[i] = (int32_t)((uint32_t)f[i] ^ x);
        g[i] = (int32_t)((uint32_t)g[i] ^ x);
    }
}

/* Reads the 32 bytes of the wire encoding — little-endian, 255 bits — into limbs.
 *
 * The widths sum to 255 exactly, so the loop consumes the value and leaves bit 255 in the
 * accumulator untouched. RFC 7748 §5 says that bit is to be ignored on a u-coordinate, and ignoring
 * it is what falls out of the arithmetic rather than something this has to remember to do.
 *
 * ⚠️ AND IT CARRIES AT THE END, WHICH IS NOT DECORATION. Splitting the bytes gives limbs at their
 * FULL width — up to 2^26 on an even limb — while everything downstream is written against the
 * bound the carry chain leaves, which is half that. One addition of two full-width limbs is then
 * already outside what lc_fe_mul's accumulators are proved to hold.
 *
 * X25519 never noticed: its ladder multiplies the decoded u before it ever adds it. Ed25519 did,
 * the moment it moved to this field — ge_add starts with Y minus X of a DECODED point, and every
 * positive vector in RFC 8032 failed while every negative one passed, which is exactly what a
 * verifier that says no to everything looks like. */
void lc_fe_frombytes(lc_fe h, const uint8_t s[32])
{
    int64_t  t[10];
    uint64_t acc = 0;
    unsigned have = 0, at = 0;

    for (unsigned i = 0; i < 10u; i++) {
        unsigned w = lc_fe_width(i);

        while (have < w && at < 32u) {
            acc |= (uint64_t)s[at] << have;
            have += 8u;
            at++;
        }
        t[i] = (int64_t)(acc & (((uint64_t)1 << w) - 1u));
        acc >>= w;
        have -= w;
    }

    lc_fe_carry(h, t);
}

/* Writes the canonical encoding, which means the reduction this file has put off until now.
 *
 * The limbs at this point are within their widths but the value they spell may still be anywhere in
 * [0, 2p): the carry chain keeps limbs small, not the number below p. So the top limb is used to
 * guess how many times p must come off — q is 0 or 1 — and the guess is refined limb by limb
 * exactly as ref10 does it, with no comparison whose timing says which answer it found. Adding 19*q
 * and then carrying leaves the value below 2^255, and masking the top bit drops the borrow. */
void lc_fe_tobytes(uint8_t s[32], const lc_fe h)
{
    int32_t  t[10];
    int32_t  q;
    uint64_t acc = 0;
    unsigned have = 0, at = 0;

    for (unsigned i = 0; i < 10u; i++)
        t[i] = h[i];

    q = (19 * t[9] + (1 << 24)) >> 25;
    for (unsigned i = 0; i < 10u; i++)
        q = (t[i] + q) >> (int)lc_fe_width(i);

    t[0] += 19 * q;

    for (unsigned i = 0; i < 10u; i++) {
        unsigned w = lc_fe_width(i);
        int32_t  c = t[i] >> w;

        if (i != 9u)
            t[i + 1u] += c;
        t[i] -= c << w;
    }
    /* Limb 9 keeps whatever is left: after the subtraction above the value is below 2^255, so that
     * remainder is the top 25 bits and nothing is lost by not wrapping it. */

    for (unsigned i = 0; i < 10u; i++) {
        acc |= (uint64_t)(uint32_t)t[i] << have;
        have += lc_fe_width(i);
        while (have >= 8u && at < 32u) {
            s[at++] = (uint8_t)(acc & 0xffu);
            acc >>= 8;
            have -= 8u;
        }
    }
    while (at < 32u)
        s[at++] = (uint8_t)(acc & 0xffu);
}

/* h = -f. No reduction: negating limbs that are inside the bound leaves them inside it, and the
 * sign is what this representation carries rather than something it has to normalise away. */
void lc_fe_neg(lc_fe h, const lc_fe f)
{
    for (unsigned i = 0; i < 10u; i++)
        h[i] = -f[i];
}

#else
/* ---- radix 2^51: five unsigned limbs, Go's field, for 64-bit machines ----
 *
 * Each function is the Go function named beside it, from crypto/internal/fips140/edwards25519/field
 * (fe.go, fe_generic.go), Go 1.26. The invariant is Go's: after carry_propagate every limb is below
 * 2^51 + 2^13*19, which is what makes the sums fed to mul and sq safe. */

#define LC_FE_MASK51 ((UINT64_C(1) << 51) - 1u)

typedef unsigned __int128 lc_u128;

/* carryPropagateGeneric */
static void carry_propagate(lc_fe v)
{
    uint64_t c0 = v[0] >> 51, c1 = v[1] >> 51, c2 = v[2] >> 51, c3 = v[3] >> 51, c4 = v[4] >> 51;
    v[0] = (v[0] & LC_FE_MASK51) + c4 * 19u;
    v[1] = (v[1] & LC_FE_MASK51) + c0;
    v[2] = (v[2] & LC_FE_MASK51) + c1;
    v[3] = (v[3] & LC_FE_MASK51) + c2;
    v[4] = (v[4] & LC_FE_MASK51) + c3;
}

/* reduce: the light reduction, then the one conditional subtraction of p, done without a branch. */
static void reduce(lc_fe v)
{
    carry_propagate(v);
    uint64_t c = (v[0] + 19u) >> 51;
    c = (v[1] + c) >> 51;
    c = (v[2] + c) >> 51;
    c = (v[3] + c) >> 51;
    c = (v[4] + c) >> 51;
    v[0] += 19u * c;
    v[1] += v[0] >> 51;
    v[0] &= LC_FE_MASK51;
    v[2] += v[1] >> 51;
    v[1] &= LC_FE_MASK51;
    v[3] += v[2] >> 51;
    v[2] &= LC_FE_MASK51;
    v[4] += v[3] >> 51;
    v[3] &= LC_FE_MASK51;
    v[4] &= LC_FE_MASK51;
}

/* The five sums of products, carried and folded — the tail feMulGeneric and feSquareGeneric share. */
static void carry_wide(lc_fe v, lc_u128 r0, lc_u128 r1, lc_u128 r2, lc_u128 r3, lc_u128 r4)
{
    uint64_t c0 = (uint64_t)(r0 >> 51), c1 = (uint64_t)(r1 >> 51), c2 = (uint64_t)(r2 >> 51);
    uint64_t c3 = (uint64_t)(r3 >> 51), c4 = (uint64_t)(r4 >> 51);
    v[0] = ((uint64_t)r0 & LC_FE_MASK51) + c4 * 19u;
    v[1] = ((uint64_t)r1 & LC_FE_MASK51) + c0;
    v[2] = ((uint64_t)r2 & LC_FE_MASK51) + c1;
    v[3] = ((uint64_t)r3 & LC_FE_MASK51) + c2;
    v[4] = ((uint64_t)r4 & LC_FE_MASK51) + c3;
    carry_propagate(v);
}

/* feMulGeneric */
void lc_fe_mul(lc_fe h, const lc_fe f, const lc_fe g)
{
    uint64_t a0 = f[0], a1 = f[1], a2 = f[2], a3 = f[3], a4 = f[4];
    uint64_t b0 = g[0], b1 = g[1], b2 = g[2], b3 = g[3], b4 = g[4];
    uint64_t a1_19 = a1 * 19u, a2_19 = a2 * 19u, a3_19 = a3 * 19u, a4_19 = a4 * 19u;

    lc_u128 r0 = (lc_u128)a0 * b0 + (lc_u128)a1_19 * b4 + (lc_u128)a2_19 * b3 +
                 (lc_u128)a3_19 * b2 + (lc_u128)a4_19 * b1;
    lc_u128 r1 = (lc_u128)a0 * b1 + (lc_u128)a1 * b0 + (lc_u128)a2_19 * b4 +
                 (lc_u128)a3_19 * b3 + (lc_u128)a4_19 * b2;
    lc_u128 r2 = (lc_u128)a0 * b2 + (lc_u128)a1 * b1 + (lc_u128)a2 * b0 +
                 (lc_u128)a3_19 * b4 + (lc_u128)a4_19 * b3;
    lc_u128 r3 = (lc_u128)a0 * b3 + (lc_u128)a1 * b2 + (lc_u128)a2 * b1 + (lc_u128)a3 * b0 +
                 (lc_u128)a4_19 * b4;
    lc_u128 r4 = (lc_u128)a0 * b4 + (lc_u128)a1 * b3 + (lc_u128)a2 * b2 + (lc_u128)a3 * b1 +
                 (lc_u128)a4 * b0;
    carry_wide(h, r0, r1, r2, r3, r4);
}

/* feSquareGeneric */
void lc_fe_sq(lc_fe h, const lc_fe f)
{
    uint64_t l0 = f[0], l1 = f[1], l2 = f[2], l3 = f[3], l4 = f[4];
    uint64_t l0_2 = l0 * 2u, l1_2 = l1 * 2u;
    uint64_t l1_38 = l1 * 38u, l2_38 = l2 * 38u, l3_38 = l3 * 38u;
    uint64_t l3_19 = l3 * 19u, l4_19 = l4 * 19u;

    lc_u128 r0 = (lc_u128)l0 * l0 + (lc_u128)l1_38 * l4 + (lc_u128)l2_38 * l3;
    lc_u128 r1 = (lc_u128)l0_2 * l1 + (lc_u128)l2_38 * l4 + (lc_u128)l3_19 * l3;
    lc_u128 r2 = (lc_u128)l0_2 * l2 + (lc_u128)l1 * l1 + (lc_u128)l3_38 * l4;
    lc_u128 r3 = (lc_u128)l0_2 * l3 + (lc_u128)l1_2 * l2 + (lc_u128)l4_19 * l4;
    lc_u128 r4 = (lc_u128)l0_2 * l4 + (lc_u128)l1_2 * l3 + (lc_u128)l2 * l2;
    carry_wide(h, r0, r1, r2, r3, r4);
}

/* Mult32(x, 121666): each limb times a 32-bit constant splits into its low 51 bits and the rest,
 * and the rest is at most 32 bits plus excess, so no further carry is needed (fe.go, mul51). */
void lc_fe_mul121666(lc_fe h, const lc_fe f)
{
    uint64_t lo[5], hi[5];
    for (unsigned i = 0; i < 5u; i++) {
        lc_u128 m = (lc_u128)f[i] * 121666u;
        lo[i] = (uint64_t)m & LC_FE_MASK51;
        hi[i] = (uint64_t)(m >> 51);
    }
    h[0] = lo[0] + 19u * hi[4];
    h[1] = lo[1] + hi[0];
    h[2] = lo[2] + hi[1];
    h[3] = lo[3] + hi[2];
    h[4] = lo[4] + hi[3];
}

void lc_fe_0(lc_fe h)
{
    h[0] = h[1] = h[2] = h[3] = h[4] = 0;
}

void lc_fe_1(lc_fe h)
{
    lc_fe_0(h);
    h[0] = 1;
}

void lc_fe_copy(lc_fe h, const lc_fe f)
{
    for (unsigned i = 0; i < 5u; i++)
        h[i] = f[i];
}

/* Add */
void lc_fe_add(lc_fe h, const lc_fe f, const lc_fe g)
{
    for (unsigned i = 0; i < 5u; i++)
        h[i] = f[i] + g[i];
    carry_propagate(h);
}

/* Subtract: 2p added first so that nothing underflows, then carried. */
void lc_fe_sub(lc_fe h, const lc_fe f, const lc_fe g)
{
    h[0] = (f[0] + UINT64_C(0xFFFFFFFFFFFDA)) - g[0];
    h[1] = (f[1] + UINT64_C(0xFFFFFFFFFFFFE)) - g[1];
    h[2] = (f[2] + UINT64_C(0xFFFFFFFFFFFFE)) - g[2];
    h[3] = (f[3] + UINT64_C(0xFFFFFFFFFFFFE)) - g[3];
    h[4] = (f[4] + UINT64_C(0xFFFFFFFFFFFFE)) - g[4];
    carry_propagate(h);
}

/* Negate: 0 - f. */
void lc_fe_neg(lc_fe h, const lc_fe f)
{
    lc_fe zero;
    lc_fe_0(zero);
    lc_fe_sub(h, zero, f);
}

/* Swap, by mask: the same instructions whether b is 0 or 1. */
void lc_fe_cswap(lc_fe f, lc_fe g, unsigned b)
{
    uint64_t mask = (uint64_t)0 - (uint64_t)(b & 1u);
    for (unsigned i = 0; i < 5u; i++) {
        uint64_t t = mask & (f[i] ^ g[i]);
        f[i] ^= t;
        g[i] ^= t;
    }
}

static uint64_t le64(const uint8_t *p)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < 8u; i++)
        v |= (uint64_t)p[i] << (8u * i);
    return v;
}

/* SetBytes: the top bit is ignored, as RFC 7748 and ref10 both do. */
void lc_fe_frombytes(lc_fe h, const uint8_t s[32])
{
    h[0] = le64(s + 0) & LC_FE_MASK51;
    h[1] = (le64(s + 6) >> 3) & LC_FE_MASK51;
    h[2] = (le64(s + 12) >> 6) & LC_FE_MASK51;
    h[3] = (le64(s + 19) >> 1) & LC_FE_MASK51;
    h[4] = (le64(s + 24) >> 12) & LC_FE_MASK51;
}

/* Bytes: fully reduced, then the five limbs laid end to end, little-endian. */
void lc_fe_tobytes(uint8_t s[32], const lc_fe h)
{
    lc_fe t;
    lc_fe_copy(t, h);
    reduce(t);
    for (unsigned i = 0; i < 32u; i++)
        s[i] = 0;
    for (unsigned i = 0; i < 5u; i++) {
        unsigned off = 51u * i;
        uint64_t l = t[i] << (off % 8u);
        for (unsigned k = 0; k < 8u; k++) {
            unsigned at = off / 8u + k;
            if (at >= 32u)
                break;
            s[at] = (uint8_t)(s[at] | (uint8_t)(l >> (8u * k)));
        }
    }
    lc_wipe(t, sizeof t);
}
#endif

/* out = z^(p-2), which is 1/z, by the addition chain ref10 uses: 254 squarings and 11
 * multiplications. An inversion by exponentiation rather than by the extended Euclid, because
 * Euclid branches on the values it is dividing and this runs on a secret. */
void lc_fe_invert(lc_fe out, const lc_fe z)
{
    lc_fe       t0, t1, t2, t3;
    unsigned i;

    lc_fe_sq(t0, z);
    lc_fe_sq(t1, t0);
    lc_fe_sq(t1, t1);
    lc_fe_mul(t1, z, t1);
    lc_fe_mul(t0, t0, t1);
    lc_fe_sq(t2, t0);
    lc_fe_mul(t1, t1, t2);
    lc_fe_sq(t2, t1);
    for (i = 1; i < 5u; i++)
        lc_fe_sq(t2, t2);
    lc_fe_mul(t1, t2, t1);
    lc_fe_sq(t2, t1);
    for (i = 1; i < 10u; i++)
        lc_fe_sq(t2, t2);
    lc_fe_mul(t2, t2, t1);
    lc_fe_sq(t3, t2);
    for (i = 1; i < 20u; i++)
        lc_fe_sq(t3, t3);
    lc_fe_mul(t2, t3, t2);
    lc_fe_sq(t2, t2);
    for (i = 1; i < 10u; i++)
        lc_fe_sq(t2, t2);
    lc_fe_mul(t1, t2, t1);
    lc_fe_sq(t2, t1);
    for (i = 1; i < 50u; i++)
        lc_fe_sq(t2, t2);
    lc_fe_mul(t2, t2, t1);
    lc_fe_sq(t3, t2);
    for (i = 1; i < 100u; i++)
        lc_fe_sq(t3, t3);
    lc_fe_mul(t2, t3, t2);
    lc_fe_sq(t2, t2);
    for (i = 1; i < 50u; i++)
        lc_fe_sq(t2, t2);
    lc_fe_mul(t1, t2, t1);
    lc_fe_sq(t1, t1);
    for (i = 1; i < 5u; i++)
        lc_fe_sq(t1, t1);
    lc_fe_mul(out, t1, t0);

    lc_wipe(t0, sizeof t0);
    lc_wipe(t1, sizeof t1);
    lc_wipe(t2, sizeof t2);
    lc_wipe(t3, sizeof t3);
}

/* out = z^((p-5)/8), by ref10's addition chain: 250 squarings and 11 multiplications.
 *
 * This exponent is how a square root is taken here. On this field x^((p+3)/8) is a square root of x
 * up to a factor of sqrt(-1), which is why every caller CHECKS the candidate and multiplies by that
 * constant when it fails — see ge_decode in src/tls/ed25519.c. The chain below differs from
 * lc_fe_invert's only in its last two steps, and both are kept written out rather than expressed in
 * terms of one another: the shared prefix is an accident of the two exponents, not a property worth
 * building an abstraction on. */
void lc_fe_pow22523(lc_fe out, const lc_fe z)
{
    lc_fe    t0, t1, t2;
    unsigned i;

    lc_fe_sq(t0, z);
    lc_fe_sq(t1, t0);
    lc_fe_sq(t1, t1);
    lc_fe_mul(t1, z, t1);
    lc_fe_mul(t0, t0, t1);
    lc_fe_sq(t0, t0);
    lc_fe_mul(t0, t1, t0);
    lc_fe_sq(t1, t0);
    for (i = 1; i < 5u; i++)
        lc_fe_sq(t1, t1);
    lc_fe_mul(t0, t1, t0);
    lc_fe_sq(t1, t0);
    for (i = 1; i < 10u; i++)
        lc_fe_sq(t1, t1);
    lc_fe_mul(t1, t1, t0);
    lc_fe_sq(t2, t1);
    for (i = 1; i < 20u; i++)
        lc_fe_sq(t2, t2);
    lc_fe_mul(t1, t2, t1);
    lc_fe_sq(t1, t1);
    for (i = 1; i < 10u; i++)
        lc_fe_sq(t1, t1);
    lc_fe_mul(t0, t1, t0);
    lc_fe_sq(t1, t0);
    for (i = 1; i < 50u; i++)
        lc_fe_sq(t1, t1);
    lc_fe_mul(t1, t1, t0);
    lc_fe_sq(t2, t1);
    for (i = 1; i < 100u; i++)
        lc_fe_sq(t2, t2);
    lc_fe_mul(t1, t2, t1);
    lc_fe_sq(t1, t1);
    for (i = 1; i < 50u; i++)
        lc_fe_sq(t1, t1);
    lc_fe_mul(t0, t1, t0);
    lc_fe_sq(t0, t0);
    lc_fe_sq(t0, t0);
    lc_fe_mul(out, t0, z);

    lc_wipe(t0, sizeof t0);
    lc_wipe(t1, sizeof t1);
    lc_wipe(t2, sizeof t2);
}

/* Whether the value is zero, and whether its canonical encoding is odd — which is what "negative"
 * means for a coordinate on this curve, since the encoding carries the sign of x in one bit.
 *
 * Both go through lc_fe_tobytes rather than looking at the limbs, and that is not laziness: a value
 * has many limb representations here, so zero can arrive as ten zeros or as p, and an odd number
 * can arrive with an even limb 0. Encoding is the only thing that answers the question asked. */
int lc_fe_iszero(const lc_fe f)
{
    uint8_t s[32];
    uint8_t acc = 0;

    lc_fe_tobytes(s, f);
    for (unsigned i = 0; i < 32u; i++)
        acc = (uint8_t)(acc | s[i]);
    lc_wipe(s, sizeof s);
    return acc == 0;
}

int lc_fe_isnegative(const lc_fe f)
{
    uint8_t s[32];
    int     odd;

    lc_fe_tobytes(s, f);
    odd = s[0] & 1;
    lc_wipe(s, sizeof s);
    return odd;
}
