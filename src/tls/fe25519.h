#ifndef LC_FE25519_H
#define LC_FE25519_H

#include <stdint.h>

/* Arithmetic in the field of 2^255-19, which both curves this client uses are defined over.
 *
 * WHY IT IS ITS OWN MODULE. It was written for X25519 (src/tls/x25519.h says what that cost and
 * what it bought) and Ed25519 needs exactly the same field — a second copy would be a second place
 * for a carry to be subtly wrong, and the whole argument for believing this code is that ONE
 * implementation is checked against RFC vectors and against mbedTLS on hundreds of random inputs.
 * Two copies would halve the value of that test rather than double it.
 *
 * THE REPRESENTATION. Ten signed limbs of alternating width: limb i carries weight 2^ceil(25.5*i),
 * so limbs 0, 2, 4, 6, 8 hold 26 bits and limbs 1, 3, 5, 7, 9 hold 25. Ten times 25.5 is 255
 * exactly, which is the point of the split — it makes reduction a multiply by 19 rather than a
 * shift by a fractional number of bits. It is djb's ref10 layout, the one every implementation of
 * these curves on a 32-bit machine uses.
 *
 * Signed, and deliberately not reduced between operations. A limb may grow past its nominal width
 * and may go negative; what these operations guarantee is a BOUND — every |limb| stays under
 * 1.65*2^26 — not a canonical value. Only lc_fe_tobytes produces one. That is what lets addition
 * and subtraction be free of any conditional, and therefore free of any timing that depends on the
 * value.
 *
 * ⚠️ WHAT THAT BOUND COSTS A CALLER: the outputs of lc_fe_add and lc_fe_sub may be fed to
 * lc_fe_mul or lc_fe_sq, and nothing else may. Adding two sums before multiplying would exceed
 * what the accumulators in lc_fe_mul can hold — see the bound written out there. Every sequence in
 * this tree keeps to one addition between multiplications, which is also what the reference
 * formulas do. */
#if defined(__SIZEOF_INT128__) && !defined(LC_FE_REF10)
/* AND ON A 64-BIT MACHINE, THE REFERENCE'S OWN REPRESENTATION (2026-09-22). Go's field is five
 * unsigned 51-bit limbs multiplied through bits.Mul64, 64x64->128 — crypto/internal/fips140/
 * edwards25519/field, fe.go and fe_generic.go, which both X25519 and Ed25519 in the reference sit
 * on. Twenty-five of those products make a field multiplication where ref10 needs a hundred 32x32
 * ones, and on the AX3000T's Cortex-A53 the asymmetric half of a REALITY handshake (two X25519
 * ladders' worth of work, one more for REALITY's own key, one Ed25519 verification) cost 5.3 ms —
 * which a burst of twenty connections, handled one after another on one core, turned into ~50 ms of
 * extra time to first byte against the reference Xray. Chosen by the compiler: wherever the target
 * has a 128-bit product this is the representation, and the 32-bit MIPS routers keep ref10 below.
 * LC_FE_REF10 forces ref10 anyway, which is how the gate keeps testing the MIPS path on a 64-bit
 * build host. Every function below behaves the same either way; only lc_fe's contents differ, and
 * nothing outside src/tls/fe25519.c looks inside. */
#define LC_FE_RADIX51 1
typedef uint64_t lc_fe[5];
#else
typedef int32_t lc_fe[10];
#endif

void lc_fe_0(lc_fe h);
void lc_fe_1(lc_fe h);
void lc_fe_copy(lc_fe h, const lc_fe f);
void lc_fe_add(lc_fe h, const lc_fe f, const lc_fe g);
void lc_fe_sub(lc_fe h, const lc_fe f, const lc_fe g);
void lc_fe_neg(lc_fe h, const lc_fe f);
void lc_fe_mul(lc_fe h, const lc_fe f, const lc_fe g);
void lc_fe_sq(lc_fe h, const lc_fe f);
/* The one constant the Montgomery ladder multiplies by; see src/tls/x25519.c. */
void lc_fe_mul121666(lc_fe h, const lc_fe f);

/* Exchanges f and g when b is 1 and leaves them when b is 0, in the same instructions either way. */
void lc_fe_cswap(lc_fe f, lc_fe g, unsigned b);

/* out = 1/z, by exponentiation rather than by Euclid: Euclid branches on the values it divides and
 * these run on secrets. */
void lc_fe_invert(lc_fe out, const lc_fe z);
/* out = z^((p-5)/8), the exponent a square root on this curve is built from. */
void lc_fe_pow22523(lc_fe out, const lc_fe z);

void lc_fe_frombytes(lc_fe h, const uint8_t s[32]);
void lc_fe_tobytes(uint8_t s[32], const lc_fe h);

/* Both answer a question about the CANONICAL value, so both encode first: a field element has many
 * representations here and "is it zero" is not a question the limbs answer directly. */
int lc_fe_iszero(const lc_fe f);
int lc_fe_isnegative(const lc_fe f);

#endif
