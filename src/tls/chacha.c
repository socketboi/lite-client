#include "tls/chacha.h"

#include <string.h>

#if defined(__aarch64__)
#include <arm_neon.h>
#endif

/* "expand 32-byte k" (chacha_generic.go: j0..j3). */
#define J0 0x61707865u
#define J1 0x3320646eu
#define J2 0x79622d32u
#define J3 0x6b206574u

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint32_t rotl(uint32_t x, unsigned n)
{
    return (x << n) | (x >> (32u - n));
}

#define QR(a, b, c, d)                                                                             \
    do {                                                                                           \
        a += b;                                                                                    \
        d ^= a;                                                                                    \
        d = rotl(d, 16);                                                                           \
        c += d;                                                                                    \
        b ^= c;                                                                                    \
        b = rotl(b, 12);                                                                           \
        a += b;                                                                                    \
        d ^= a;                                                                                    \
        d = rotl(d, 8);                                                                            \
        c += d;                                                                                    \
        b ^= c;                                                                                    \
        b = rotl(b, 7);                                                                            \
    } while (0)

void lc_chacha_init(lc_chacha *c, const uint8_t key[LC_CHACHA_KEY], const uint8_t nonce[LC_CHACHA_NONCE])
{
    memset(c, 0, sizeof *c);
    for (unsigned i = 0; i < 8u; i++)
        c->key[i] = le32(key + 4u * i);
    for (unsigned i = 0; i < 3u; i++)
        c->nonce[i] = le32(nonce + 4u * i);
}

/* addXor: dst = src ^ (v + x), little-endian. */
static void add_xor(uint8_t *dst, const uint8_t *src, uint32_t v, uint32_t x)
{
    uint32_t k = v + x;
    dst[0] = (uint8_t)(src[0] ^ k);
    dst[1] = (uint8_t)(src[1] ^ (k >> 8));
    dst[2] = (uint8_t)(src[2] ^ (k >> 16));
    dst[3] = (uint8_t)(src[3] ^ (k >> 24));
}

/* xorKeyStreamBlocksGeneric: whole blocks, the first column round's three counter-free quarter
 * rounds taken from the cache and only the one with the counter in it done per block. */
static void blocks_generic(lc_chacha *s, uint8_t *dst, const uint8_t *src, size_t len)
{
    const uint32_t c0 = J0, c1 = J1, c2 = J2, c3 = J3;
    const uint32_t c4 = s->key[0], c5 = s->key[1], c6 = s->key[2], c7 = s->key[3];
    const uint32_t c8 = s->key[4], c9 = s->key[5], c10 = s->key[6], c11 = s->key[7];
    const uint32_t c13 = s->nonce[0], c14 = s->nonce[1], c15 = s->nonce[2];

    if (!s->precomp_done) {
        uint32_t a = c1, b = c5, c = c9, d = c13;
        QR(a, b, c, d);
        s->p1 = a, s->p5 = b, s->p9 = c, s->p13 = d;
        a = c2, b = c6, c = c10, d = c14;
        QR(a, b, c, d);
        s->p2 = a, s->p6 = b, s->p10 = c, s->p14 = d;
        a = c3, b = c7, c = c11, d = c15;
        QR(a, b, c, d);
        s->p3 = a, s->p7 = b, s->p11 = c, s->p15 = d;
        s->precomp_done = 1;
    }

    while (len >= LC_CHACHA_BLOCK) {
        uint32_t fcr0 = c0, fcr4 = c4, fcr8 = c8, fcr12 = s->counter;
        QR(fcr0, fcr4, fcr8, fcr12);

        uint32_t x0 = fcr0, x5 = s->p5, x10 = s->p10, x15 = s->p15;
        QR(x0, x5, x10, x15);
        uint32_t x1 = s->p1, x6 = s->p6, x11 = s->p11, x12 = fcr12;
        QR(x1, x6, x11, x12);
        uint32_t x2 = s->p2, x7 = s->p7, x8 = fcr8, x13 = s->p13;
        QR(x2, x7, x8, x13);
        uint32_t x3 = s->p3, x4 = fcr4, x9 = s->p9, x14 = s->p14;
        QR(x3, x4, x9, x14);

        for (int i = 0; i < 9; i++) {
            QR(x0, x4, x8, x12);
            QR(x1, x5, x9, x13);
            QR(x2, x6, x10, x14);
            QR(x3, x7, x11, x15);

            QR(x0, x5, x10, x15);
            QR(x1, x6, x11, x12);
            QR(x2, x7, x8, x13);
            QR(x3, x4, x9, x14);
        }

        add_xor(dst + 0, src + 0, x0, c0);
        add_xor(dst + 4, src + 4, x1, c1);
        add_xor(dst + 8, src + 8, x2, c2);
        add_xor(dst + 12, src + 12, x3, c3);
        add_xor(dst + 16, src + 16, x4, c4);
        add_xor(dst + 20, src + 20, x5, c5);
        add_xor(dst + 24, src + 24, x6, c6);
        add_xor(dst + 28, src + 28, x7, c7);
        add_xor(dst + 32, src + 32, x8, c8);
        add_xor(dst + 36, src + 36, x9, c9);
        add_xor(dst + 40, src + 40, x10, c10);
        add_xor(dst + 44, src + 44, x11, c11);
        add_xor(dst + 48, src + 48, x12, s->counter);
        add_xor(dst + 52, src + 52, x13, c13);
        add_xor(dst + 56, src + 56, x14, c14);
        add_xor(dst + 60, src + 60, x15, c15);

        s->counter += 1u;
        src += LC_CHACHA_BLOCK;
        dst += LC_CHACHA_BLOCK;
        len -= LC_CHACHA_BLOCK;
    }
}

#if defined(__aarch64__)

/* xorKeyStreamVX (chacha_arm64.s): 256 bytes at a time, block j of the four in lane j of every
 * register, the counter vector {c, c+1, c+2, c+3} and 4 added to c after each pass. Rotations as the
 * assembly does them: 16 by swapping halfwords (VREV32 .H8), 12 and 7 by a shift and a
 * shift-right-insert (VSHL/VSRI), 8 by a byte table (VTBL with incRotMatrix's second half). The
 * compiler schedules what the assembly interleaves by hand; the arithmetic is the same. */
static inline uint32x4_t rot16(uint32x4_t x)
{
    return vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x)));
}

static inline uint32x4_t rot12(uint32x4_t x)
{
    return vsriq_n_u32(vshlq_n_u32(x, 12), x, 20);
}

static inline uint32x4_t rot7(uint32x4_t x)
{
    return vsriq_n_u32(vshlq_n_u32(x, 7), x, 25);
}

#define VQR(a, b, c, d, r8)                                                                        \
    do {                                                                                           \
        a = vaddq_u32(a, b);                                                                       \
        d = rot16(veorq_u32(d, a));                                                                \
        c = vaddq_u32(c, d);                                                                       \
        b = rot12(veorq_u32(b, c));                                                                \
        a = vaddq_u32(a, b);                                                                       \
        d = vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(veorq_u32(d, a)), r8));          \
        c = vaddq_u32(c, d);                                                                       \
        b = rot7(veorq_u32(b, c));                                                                 \
    } while (0)

#define U64(v) vreinterpretq_u64_u32(v)
#define XOR16(off, v)                                                                              \
    vst1q_u8(dst + (off), veorq_u8(vld1q_u8(src + (off)), vreinterpretq_u8_u64(v)))
#define TRANSPOSE_XOR(a, b, c, d, q)                                                               \
    do {                                                                                           \
        uint32x4_t t0_ = vzip1q_u32(a, b), t1_ = vzip2q_u32(a, b);                                 \
        uint32x4_t t2_ = vzip1q_u32(c, d), t3_ = vzip2q_u32(c, d);                                 \
        XOR16(0u * 64u + 16u * (q), vzip1q_u64(U64(t0_), U64(t2_)));                               \
        XOR16(1u * 64u + 16u * (q), vzip2q_u64(U64(t0_), U64(t2_)));                               \
        XOR16(2u * 64u + 16u * (q), vzip1q_u64(U64(t1_), U64(t3_)));                               \
        XOR16(3u * 64u + 16u * (q), vzip2q_u64(U64(t1_), U64(t3_)));                               \
    } while (0)

static void blocks_vx(lc_chacha *s, uint8_t *dst, const uint8_t *src, size_t len)
{
    static const uint32_t inc[4] = { 0, 1, 2, 3 };
    static const uint8_t  r8_tbl[16] = { 3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14 };
    const uint8x16_t      r8 = vld1q_u8(r8_tbl);
    const uint32x4_t      vinc = vld1q_u32(inc);

    while (len >= LC_CHACHA_BUF) {
        uint32x4_t s0 = vdupq_n_u32(J0), s1 = vdupq_n_u32(J1), s2 = vdupq_n_u32(J2),
                   s3 = vdupq_n_u32(J3);
        uint32x4_t s4 = vdupq_n_u32(s->key[0]), s5 = vdupq_n_u32(s->key[1]),
                   s6 = vdupq_n_u32(s->key[2]), s7 = vdupq_n_u32(s->key[3]);
        uint32x4_t s8 = vdupq_n_u32(s->key[4]), s9 = vdupq_n_u32(s->key[5]),
                   s10 = vdupq_n_u32(s->key[6]), s11 = vdupq_n_u32(s->key[7]);
        uint32x4_t s12 = vaddq_u32(vdupq_n_u32(s->counter), vinc);
        uint32x4_t s13 = vdupq_n_u32(s->nonce[0]), s14 = vdupq_n_u32(s->nonce[1]),
                   s15 = vdupq_n_u32(s->nonce[2]);

        uint32x4_t x0 = s0, x1 = s1, x2 = s2, x3 = s3, x4 = s4, x5 = s5, x6 = s6, x7 = s7;
        uint32x4_t x8 = s8, x9 = s9, x10 = s10, x11 = s11, x12 = s12, x13 = s13, x14 = s14,
                   x15 = s15;

        for (int i = 0; i < 10; i++) {
            VQR(x0, x4, x8, x12, r8);
            VQR(x1, x5, x9, x13, r8);
            VQR(x2, x6, x10, x14, r8);
            VQR(x3, x7, x11, x15, r8);

            VQR(x0, x5, x10, x15, r8);
            VQR(x1, x6, x11, x12, r8);
            VQR(x2, x7, x8, x13, r8);
            VQR(x3, x4, x9, x14, r8);
        }

        x0 = vaddq_u32(x0, s0), x1 = vaddq_u32(x1, s1), x2 = vaddq_u32(x2, s2), x3 = vaddq_u32(x3, s3);
        x4 = vaddq_u32(x4, s4), x5 = vaddq_u32(x5, s5), x6 = vaddq_u32(x6, s6), x7 = vaddq_u32(x7, s7);
        x8 = vaddq_u32(x8, s8), x9 = vaddq_u32(x9, s9), x10 = vaddq_u32(x10, s10),
        x11 = vaddq_u32(x11, s11);
        x12 = vaddq_u32(x12, s12), x13 = vaddq_u32(x13, s13), x14 = vaddq_u32(x14, s14),
        x15 = vaddq_u32(x15, s15);

        /* The transpose: four words of one block out of four registers holding that word of every
         * block, by the same VZIP1/VZIP2 on words and then on doublewords as the assembly, and each
         * sixteen bytes XORed into place — block j at 64*j, its words 4q..4q+3 at 16*q within it. */
        TRANSPOSE_XOR(x0, x1, x2, x3, 0u);
        TRANSPOSE_XOR(x4, x5, x6, x7, 1u);
        TRANSPOSE_XOR(x8, x9, x10, x11, 2u);
        TRANSPOSE_XOR(x12, x13, x14, x15, 3u);

        s->counter += 4u;
        src += LC_CHACHA_BUF;
        dst += LC_CHACHA_BUF;
        len -= LC_CHACHA_BUF;
    }
}

/* xorKeyStreamBlocks as chacha_arm64.go defines it. */
static void blocks(lc_chacha *s, uint8_t *dst, const uint8_t *src, size_t len)
{
    blocks_vx(s, dst, src, len);
}

const char *lc_chacha_name(void)
{
    return "neon";
}

#else

/* chacha_noasm.go. */
static void blocks(lc_chacha *s, uint8_t *dst, const uint8_t *src, size_t len)
{
    blocks_generic(s, dst, src, len);
}

const char *lc_chacha_name(void)
{
    return "generic";
}

#endif

int lc_chacha_set_counter(lc_chacha *s, uint32_t counter)
{
    uint32_t output_counter = s->counter - (uint32_t)(s->len / LC_CHACHA_BLOCK);
    if (s->overflow || counter < output_counter)
        return -1;
    if (counter < s->counter) {
        s->len = (size_t)(s->counter - counter) * LC_CHACHA_BLOCK;
    } else {
        s->counter = counter;
        s->len = 0;
    }
    return 0;
}

int lc_chacha_xor(lc_chacha *s, uint8_t *dst, const uint8_t *src, size_t len)
{
    if (len == 0)
        return 0;

    if (s->len != 0) {
        const uint8_t *ks = s->buf + LC_CHACHA_BUF - s->len;
        size_t         n = len < s->len ? len : s->len;
        for (size_t i = 0; i < n; i++)
            dst[i] = (uint8_t)(src[i] ^ ks[i]);
        s->len -= n;
        dst += n, src += n, len -= n;
    }
    if (len == 0)
        return 0;

    uint64_t num_blocks = ((uint64_t)len + LC_CHACHA_BLOCK - 1u) / LC_CHACHA_BLOCK;
    if (s->overflow || (uint64_t)s->counter + num_blocks > (1ULL << 32))
        return -1;
    if ((uint64_t)s->counter + num_blocks == (1ULL << 32))
        s->overflow = 1;

    size_t full = len - len % LC_CHACHA_BUF;
    if (full > 0)
        blocks(s, dst, src, full);
    dst += full, src += full, len -= full;

    /* Too close to the end of the counter for a whole buffer: only the blocks needed, one at a
     * time, at the end of buf. */
    const unsigned blocks_per_buf = LC_CHACHA_BUF / LC_CHACHA_BLOCK;
    if ((uint64_t)s->counter + blocks_per_buf > (1ULL << 32)) {
        memset(s->buf, 0, sizeof s->buf);
        size_t   nb = (len + LC_CHACHA_BLOCK - 1u) / LC_CHACHA_BLOCK;
        uint8_t *b = s->buf + LC_CHACHA_BUF - nb * LC_CHACHA_BLOCK;
        memcpy(b, src, len);
        blocks_generic(s, b, b, nb * LC_CHACHA_BLOCK);
        memcpy(dst, b, len);
        s->len = nb * LC_CHACHA_BLOCK - len;
        return 0;
    }

    if (len > 0) {
        memset(s->buf, 0, sizeof s->buf);
        memcpy(s->buf, src, len);
        blocks(s, s->buf, s->buf, LC_CHACHA_BUF);
        memcpy(dst, s->buf, len);
        s->len = LC_CHACHA_BUF - len;
    }
    return 0;
}
