#include "tls/poly1305.h"

#include <string.h>

#if defined(LC_POLY1305_GO)

typedef unsigned __int128 u128;

/* binary.LittleEndian.Uint64 and PutUint64. Through memcpy, which is one load or store: written as a
 * loop over bytes it stayed a loop — eight byte loads, shifts and a branch, twice per sixteen bytes —
 * and that alone had this port at 56 ms per 8 MB on the AX3000T, where the reference's build of the
 * same function takes about 34 (its seal less its keystream, on the same box) and this one now 24. */
static inline uint64_t le64(const uint8_t *p)
{
    uint64_t v;
    memcpy(&v, p, sizeof v);
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    v = __builtin_bswap64(v);
#endif
    return v;
}

static inline void put_le64(uint8_t *p, uint64_t v)
{
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    v = __builtin_bswap64(v);
#endif
    memcpy(p, &v, sizeof v);
}

/* bits.Add64 and bits.Sub64, carry and borrow in and out — one ADDS/ADCS or SUBS/SBCS pair each. */
static inline uint64_t add64(uint64_t x, uint64_t y, uint64_t carry, uint64_t *carry_out)
{
    u128 s = (u128)x + y + carry;
    *carry_out = (uint64_t)(s >> 64);
    return (uint64_t)s;
}

static inline uint64_t sub64(uint64_t x, uint64_t y, uint64_t borrow, uint64_t *borrow_out)
{
    u128 d = (u128)x - y - borrow;
    *borrow_out = (uint64_t)(d >> 64) & 1u;
    return (uint64_t)d;
}

#define R_MASK0 0x0FFFFFFC0FFFFFFFULL
#define R_MASK1 0x0FFFFFFC0FFFFFFCULL
#define MASK_LOW2 0x0000000000000003ULL
#define MASK_NOT_LOW2 (~MASK_LOW2)

void lc_poly1305_init(lc_poly1305 *m, const uint8_t key[LC_POLY1305_KEY])
{
    memset(m, 0, sizeof *m);
    m->r[0] = le64(key + 0) & R_MASK0;
    m->r[1] = le64(key + 8) & R_MASK1;
    m->s[0] = le64(key + 16);
    m->s[1] = le64(key + 24);
}

/* updateGeneric. mul64 is bits.Mul64 and add128 the two Add64 of the same name; Go panics on a carry
 * out of the top of either, which the four bits masked off r make impossible, so here it is simply
 * not taken. */
static void update(uint64_t h[3], const uint64_t r[2], const uint8_t *msg, size_t len)
{
    uint64_t h0 = h[0], h1 = h[1], h2 = h[2];
    uint64_t r0 = r[0], r1 = r[1];

    while (len > 0) {
        uint64_t c;

        if (len >= LC_POLY1305_TAG) {
            h0 = add64(h0, le64(msg), 0, &c);
            h1 = add64(h1, le64(msg + 8), c, &c);
            h2 += c + 1u;
            msg += LC_POLY1305_TAG;
            len -= LC_POLY1305_TAG;
        } else {
            uint8_t buf[LC_POLY1305_TAG];
            memset(buf, 0, sizeof buf);
            memcpy(buf, msg, len);
            buf[len] = 1;
            h0 = add64(h0, le64(buf), 0, &c);
            h1 = add64(h1, le64(buf + 8), c, &c);
            h2 += c;
            len = 0;
        }

        u128 h0r0 = (u128)h0 * r0;
        u128 h1r0 = (u128)h1 * r0;
        u128 h2r0 = (u128)h2 * r0;
        u128 h0r1 = (u128)h0 * r1;
        u128 h1r1 = (u128)h1 * r1;
        u128 h2r1 = (u128)h2 * r1;

        u128 m0 = h0r0;
        u128 m1 = h1r0 + h0r1;
        u128 m2 = h2r0 + h1r1;
        u128 m3 = h2r1;

        uint64_t t0 = (uint64_t)m0;
        uint64_t t1 = add64((uint64_t)m1, (uint64_t)(m0 >> 64), 0, &c);
        uint64_t t2 = add64((uint64_t)m2, (uint64_t)(m1 >> 64), c, &c);
        uint64_t t3 = add64((uint64_t)m3, (uint64_t)(m2 >> 64), c, &c);

        h0 = t0, h1 = t1, h2 = t2 & MASK_LOW2;
        uint64_t cc_lo = t2 & MASK_NOT_LOW2, cc_hi = t3;

        h0 = add64(h0, cc_lo, 0, &c);
        h1 = add64(h1, cc_hi, c, &c);
        h2 += c;

        /* shiftRightBy2 */
        cc_lo = cc_lo >> 2 | (cc_hi & 3u) << 62;
        cc_hi = cc_hi >> 2;

        h0 = add64(h0, cc_lo, 0, &c);
        h1 = add64(h1, cc_hi, c, &c);
        h2 += c;
    }

    h[0] = h0, h[1] = h1, h[2] = h2;
}

/* macGeneric.Write. */
void lc_poly1305_write(lc_poly1305 *m, const uint8_t *p, size_t len)
{
    if (m->offset > 0) {
        size_t n = LC_POLY1305_TAG - m->offset;
        if (n > len)
            n = len;
        memcpy(m->buffer + m->offset, p, n);
        if (m->offset + n < LC_POLY1305_TAG) {
            m->offset += n;
            return;
        }
        p += n, len -= n;
        m->offset = 0;
        update(m->h, m->r, m->buffer, LC_POLY1305_TAG);
    }
    size_t n = len - len % LC_POLY1305_TAG;
    if (n > 0) {
        update(m->h, m->r, p, n);
        p += n, len -= n;
    }
    if (len > 0) {
        memcpy(m->buffer + m->offset, p, len);
        m->offset += len;
    }
}

/* macGeneric.Sum and finalize. */
void lc_poly1305_sum(lc_poly1305 *m, uint8_t out[LC_POLY1305_TAG])
{
    uint64_t h[3] = { m->h[0], m->h[1], m->h[2] };
    if (m->offset > 0)
        update(h, m->r, m->buffer, m->offset);

    uint64_t b;
    uint64_t h_minus_p0 = sub64(h[0], 0xFFFFFFFFFFFFFFFBULL, 0, &b);
    uint64_t h_minus_p1 = sub64(h[1], 0xFFFFFFFFFFFFFFFFULL, b, &b);
    (void)sub64(h[2], 0x0000000000000003ULL, b, &b);

    /* select64(v, x, y) = ^(v-1)&x | (v-1)&y: h if h - p borrowed, h - p if it did not. */
    uint64_t h0 = (~(b - 1u) & h[0]) | ((b - 1u) & h_minus_p0);
    uint64_t h1 = (~(b - 1u) & h[1]) | ((b - 1u) & h_minus_p1);

    uint64_t c;
    h0 = add64(h0, m->s[0], 0, &c);
    h1 = add64(h1, m->s[1], c, &c);

    put_le64(out, h0);
    put_le64(out + 8, h1);
}

const char *lc_poly1305_name(void)
{
    return "go";
}

#else

void lc_poly1305_init(lc_poly1305 *m, const uint8_t key[LC_POLY1305_KEY])
{
    mbedtls_poly1305_init(&m->ctx);
    (void)mbedtls_poly1305_starts(&m->ctx, key);
}

void lc_poly1305_write(lc_poly1305 *m, const uint8_t *p, size_t len)
{
    (void)mbedtls_poly1305_update(&m->ctx, p, len);
}

void lc_poly1305_sum(lc_poly1305 *m, uint8_t out[LC_POLY1305_TAG])
{
    (void)mbedtls_poly1305_finish(&m->ctx, out);
    mbedtls_poly1305_free(&m->ctx);
}

const char *lc_poly1305_name(void)
{
    return "mbedtls";
}

#endif
