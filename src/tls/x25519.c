#include "tls/x25519.h"

#include "tls/fe25519.h"

#include "core/wipe.h"

#include <string.h>


/* The Montgomery ladder of RFC 7748 §5, in ref10's ordering of the field operations.
 *
 * Every bit of the scalar costs the same five multiplications, four squarings, one multiply by
 * 121666 and eight additions or subtractions, whatever the bit is; the only thing the bit decides
 * is a conditional swap, and that is a mask. The running `swap` holds the previous bit so that two
 * consecutive equal bits cost no swap at all — which is ref10's trick, not a shortcut, since the
 * swap is constant time either way and this only saves work. */
static void ladder(lc_fe x2, lc_fe z2, const uint8_t e[32], const lc_fe x1)
{
    lc_fe       x3, z3, tmp0, tmp1;
    unsigned swap = 0;

    lc_fe_1(x2);
    lc_fe_0(z2);
    lc_fe_copy(x3, x1);
    lc_fe_1(z3);

    for (int pos = 254; pos >= 0; pos--) {
        unsigned b = (unsigned)(e[pos / 8] >> (pos & 7)) & 1u;

        swap ^= b;
        lc_fe_cswap(x2, x3, swap);
        lc_fe_cswap(z2, z3, swap);
        swap = b;

        lc_fe_sub(tmp0, x3, z3);
        lc_fe_sub(tmp1, x2, z2);
        lc_fe_add(x2, x2, z2);
        lc_fe_add(z2, x3, z3);
        lc_fe_mul(z3, tmp0, x2);
        lc_fe_mul(z2, z2, tmp1);
        lc_fe_sq(tmp0, tmp1);
        lc_fe_sq(tmp1, x2);
        lc_fe_add(x3, z3, z2);
        lc_fe_sub(z2, z3, z2);
        lc_fe_mul(x2, tmp1, tmp0);
        lc_fe_sub(tmp1, tmp1, tmp0);
        lc_fe_sq(z2, z2);
        lc_fe_mul121666(z3, tmp1);
        lc_fe_sq(x3, x3);
        lc_fe_add(tmp0, tmp0, z3);
        lc_fe_mul(z3, x1, z2);
        lc_fe_mul(z2, tmp1, tmp0);
    }

    lc_fe_cswap(x2, x3, swap);
    lc_fe_cswap(z2, z3, swap);

    lc_wipe(x3, sizeof x3);
    lc_wipe(z3, sizeof z3);
    lc_wipe(tmp0, sizeof tmp0);
    lc_wipe(tmp1, sizeof tmp1);
}

static void clamp(uint8_t e[32], const uint8_t scalar[32])
{
    memcpy(e, scalar, 32);
    e[0] = (uint8_t)(e[0] & 248u);
    e[31] = (uint8_t)(e[31] & 127u);
    e[31] = (uint8_t)(e[31] | 64u);
}

void lc_x25519_mul(uint8_t out[LC_X25519_LEN], const uint8_t scalar[LC_X25519_LEN],
                   const uint8_t u[LC_X25519_LEN])
{
    uint8_t e[32];
    lc_fe      x1, x2, z2;

    clamp(e, scalar);
    lc_fe_frombytes(x1, u);
    ladder(x2, z2, e, x1);
    lc_fe_invert(z2, z2);
    lc_fe_mul(x2, x2, z2);
    lc_fe_tobytes(out, x2);

    lc_wipe(e, sizeof e);
    lc_wipe(x1, sizeof x1);
    lc_wipe(x2, sizeof x2);
    lc_wipe(z2, sizeof z2);
}

void lc_x25519_basemul(uint8_t out[LC_X25519_LEN], const uint8_t scalar[LC_X25519_LEN])
{
    static const uint8_t base[32] = { 9 };
    uint8_t              e[32];
    lc_fe                   x1, x2, z2;

    clamp(e, scalar);
    lc_fe_frombytes(x1, base);
    ladder(x2, z2, e, x1);
    lc_fe_invert(z2, z2);
    lc_fe_mul(x2, x2, z2);
    lc_fe_tobytes(out, x2);

    lc_wipe(e, sizeof e);
    lc_wipe(x2, sizeof x2);
    lc_wipe(z2, sizeof z2);
}
