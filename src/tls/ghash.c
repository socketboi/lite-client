/* See ghash.h. The portable functions below are the Go functions of the same name in
 * crypto/internal/fips140/aes/gcm/ghash.go (Go 1.26), and read best side by side with it; the
 * hardware paths use carry-less multiplication where Go selects hardware GCM. */
#include "tls/ghash.h"
#include "core/wipe.h"

#include <string.h>

#if defined(__x86_64__)
#include <tmmintrin.h>
#include <wmmintrin.h>

/* The runtime condition is Go 1.27's gcm_asm.go: supportsAESGCM.
 * The multiply/reduction comes from pinned mbedTLS aesni.c,
 * gcm_clmul/gcm_shift/gcm_reduce/gcm_mix/mbedtls_aesni_gcm_mult.
 * Copyright The Mbed TLS Contributors
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 * One block at a time, unlike Go's interleaved assembly; the polynomial, padding
 * and result bytes are identical. Only this target function carries instructions
 * unavailable to older CPUs; no global compiler flag enables them. DIVERGES: O4. */
static int ghash_x86_hw(void)
{
    return __builtin_cpu_supports("aes") && __builtin_cpu_supports("pclmul") &&
           __builtin_cpu_supports("sse4.1") && __builtin_cpu_supports("ssse3");
}

#pragma GCC push_options
#pragma GCC target("pclmul,ssse3,sse4.1")

static __m128i x86_product(__m128i a, __m128i b)
{
    __m128i low = _mm_clmulepi64_si128(a, b, 0x00);
    __m128i high = _mm_clmulepi64_si128(a, b, 0x11);
    __m128i middle = _mm_xor_si128(_mm_clmulepi64_si128(a, b, 0x10),
                                 _mm_clmulepi64_si128(a, b, 0x01));
    low = _mm_xor_si128(low, _mm_slli_si128(middle, 8));
    high = _mm_xor_si128(high, _mm_srli_si128(middle, 8));
    __m128i carry = _mm_srli_epi64(low, 63);
    low = _mm_or_si128(_mm_slli_epi64(low, 1), _mm_slli_si128(carry, 8));
    high = _mm_or_si128(_mm_or_si128(_mm_slli_epi64(high, 1),
                                    _mm_slli_si128(_mm_srli_epi64(high, 63), 8)),
                        _mm_srli_si128(carry, 8));
    __m128i shifts = _mm_xor_si128(_mm_xor_si128(_mm_slli_epi64(low, 63),
                                               _mm_slli_epi64(low, 62)),
                                 _mm_slli_epi64(low, 57));
    __m128i reduced = _mm_xor_si128(low, _mm_slli_si128(shifts, 8));
    __m128i mixed = _mm_xor_si128(_mm_xor_si128(_mm_srli_epi64(reduced, 1),
                                              _mm_srli_epi64(reduced, 2)),
                                _mm_srli_epi64(reduced, 7));
    shifts = _mm_xor_si128(_mm_xor_si128(_mm_slli_epi64(reduced, 63),
                                        _mm_slli_epi64(reduced, 62)),
                          _mm_slli_epi64(reduced, 57));
    return _mm_xor_si128(high, _mm_xor_si128(reduced,
                             _mm_xor_si128(mixed, _mm_srli_si128(shifts, 8))));
}

static __m128i x86_reverse(__m128i a)
{
    return _mm_shuffle_epi8(a, _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7,
                                           8, 9, 10, 11, 12, 13, 14, 15));
}

static void x86_update(__m128i h, __m128i *y, const uint8_t *data, size_t len)
{
    while (len >= LC_GHASH_BLOCK) {
        __m128i block;
        memcpy(&block, data, sizeof block);
        *y = x86_product(_mm_xor_si128(*y, x86_reverse(block)), h);
        data += LC_GHASH_BLOCK;
        len -= LC_GHASH_BLOCK;
    }
    if (len != 0u) {
        uint8_t partial[LC_GHASH_BLOCK] = {0};
        __m128i block;
        memcpy(partial, data, len);
        memcpy(&block, partial, sizeof block);
        *y = x86_product(_mm_xor_si128(*y, x86_reverse(block)), h);
        lc_wipe(partial, sizeof partial);
    }
}

static void ghash_x86(uint8_t out[LC_GHASH_BLOCK], const uint8_t hb[LC_GHASH_BLOCK],
                      const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len,
                      const uint8_t *c, size_t c_len)
{
    __m128i h, y = _mm_setzero_si128();
    memcpy(&h, hb, sizeof h);
    h = x86_reverse(h);
    if (a_len != 0u)
        x86_update(h, &y, a, a_len);
    if (b_len != 0u)
        x86_update(h, &y, b, b_len);
    if (c_len != 0u)
        x86_update(h, &y, c, c_len);
    y = x86_reverse(y);
    memcpy(out, &y, sizeof y);
    lc_wipe(&h, sizeof h);
    lc_wipe(&y, sizeof y);
}

#pragma GCC pop_options
#endif

#if defined(__aarch64__)
#include <arm_neon.h>
#include <asm/hwcap.h>
#include <sys/auxv.h>

/* WHICH GHASH, CHOSEN THE WAY THE REFERENCE CHOOSES IT.
 *
 * Go does not have one GCM. `supportsAESGCM = ... || cpu.ARM64HasAES && cpu.ARM64HasPMULL`
 * (crypto/internal/fips140/aes/gcm/gcm_asm.go:34-35) sends an arm64 machine with both to assembly
 * that multiplies with PMULL, and everything else to the generic ghash.go above; uTLS keeps the
 * same test for its cipher preference (vendor/utls/cipher_suites.go:363). The AX3000T's Cortex-A53
 * has both, and there the difference is not a detail: measured on the box 2026-09-22, Go opens
 * AES-128-GCM at 4 700 Mbit/s, this client did 334 with the generic GHASH, and a REALITY download
 * against the reference Xray came out 121.6 against 175.8 Mbit/s over six alternating pairs, the
 * reference using a third of the processor. So the choice is made here as Go makes it — on the
 * running CPU, once — and the MIPS routers, which have neither instruction, keep the generic code.
 *
 * The multiply is mbedTLS's own for this instruction set, from the vendored tree:
 * pmull_low/pmull_high/poly_mult_128/poly_mult_reduce and the bit reflection of
 * mbedtls_aesce_gcm_mult (vendor/mbedtls/library/aesce.c:504-600). GHASH is linear, so the running
 * value is kept reflected across blocks and reflected back once at the end. */
static int ghash_hw(void)
{
    static int known = -1;
    if (known < 0) {
        unsigned long cap = getauxval(AT_HWCAP);
        known = (cap & HWCAP_AES) != 0 && (cap & HWCAP_PMULL) != 0;
    }
    return known;
}

#pragma GCC push_options
/* Add crypto without dropping the SDK's CPU features: its fortified string
 * wrappers are always_inline and must remain callable from this target. */
#pragma GCC target("+crypto")

static inline uint8x16_t pmull_low(uint8x16_t a, uint8x16_t b)
{
    return vreinterpretq_u8_p128(vmull_p64((poly64_t)vget_low_p64(vreinterpretq_p64_u8(a)),
                                           (poly64_t)vget_low_p64(vreinterpretq_p64_u8(b))));
}

static inline uint8x16_t pmull_high(uint8x16_t a, uint8x16_t b)
{
    return vreinterpretq_u8_p128(vmull_high_p64(vreinterpretq_p64_u8(a), vreinterpretq_p64_u8(b)));
}

/* 128x128 -> 256 as three 128-bit parts: high, middle, low. */
static inline uint8x16x3_t poly_mult_128(uint8x16_t a, uint8x16_t b)
{
    uint8x16x3_t ret;
    uint8x16_t   c = vextq_u8(b, b, 8);
    ret.val[0] = pmull_high(a, b);
    ret.val[1] = veorq_u8(pmull_high(a, c), pmull_low(a, c));
    ret.val[2] = pmull_low(a, b);
    return ret;
}

/* Reduction by x^128 + x^7 + x^2 + x + 1: the high half times r(x) folded into the low. */
static inline uint8x16_t poly_mult_reduce(uint8x16x3_t in)
{
    uint8x16_t const zero = vdupq_n_u8(0);
    uint64x2_t       r = vreinterpretq_u64_u8(vdupq_n_u8(0x87));
    __asm__ volatile("" : "+w"(r));
    uint8x16_t const modulo = vreinterpretq_u8_u64(vshrq_n_u64(r, 64 - 8));
    uint8x16_t       c = pmull_high(in.val[0], modulo);
    uint8x16_t       d = pmull_low(in.val[0], modulo);
    uint8x16_t       e = veorq_u8(c, in.val[1]);
    uint8x16_t       f = pmull_high(e, modulo);
    uint8x16_t       g = vextq_u8(zero, e, 8);
    uint8x16_t       n = veorq_u8(d, in.val[2]);
    return veorq_u8(veorq_u8(n, f), g);
}

static void pmull_update(uint8x16_t h, uint8x16_t *y, const uint8_t *data, size_t len)
{
    size_t full = (len >> 4) << 4;
    for (size_t off = 0; off < full; off += LC_GHASH_BLOCK) {
        *y = veorq_u8(*y, vrbitq_u8(vld1q_u8(data + off)));
        *y = poly_mult_reduce(poly_mult_128(*y, h));
    }
    if (len != full) {
        uint8_t partial[LC_GHASH_BLOCK];
        memset(partial, 0, sizeof partial);
        memcpy(partial, data + full, len - full);
        *y = veorq_u8(*y, vrbitq_u8(vld1q_u8(partial)));
        *y = poly_mult_reduce(poly_mult_128(*y, h));
    }
}

static void ghash_pmull(uint8_t out[LC_GHASH_BLOCK], const uint8_t hb[LC_GHASH_BLOCK],
                        const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len,
                        const uint8_t *c, size_t c_len)
{
    uint8x16_t h = vrbitq_u8(vld1q_u8(hb));
    uint8x16_t y = vdupq_n_u8(0);
    if (a_len > 0u)
        pmull_update(h, &y, a, a_len);
    if (b_len > 0u)
        pmull_update(h, &y, b, b_len);
    if (c_len > 0u)
        pmull_update(h, &y, c, c_len);
    vst1q_u8(out, vrbitq_u8(y));
}

/* ---- AES-CTR on the same extension ----------------------------------------------------------
 *
 * THE OTHER HALF OF GCM, which stayed mbedTLS's after the GHASH moved here, and which the AX3000T
 * then spent most of its REALITY time in. Measured on the box 2026-09-30, AES-128-GCM opened in
 * 16 KB records: Go 1.8 ms per MB, this client 7.0 — of which the counter mode, the device's
 * mbedtls_aes_crypt_ctr, was 5.5. That call does use the AES instructions, one block at a time;
 * AESE and AESMC take several cycles each and the A53 only goes fast when blocks are in flight
 * together. Go's gcm_arm64.s encrypts eight counter blocks side by side, and so does this. Over a
 * 100 MB download that was 0.7 s of processor against the reference's 0.18.
 *
 * The key schedule is FIPS-197's KeyExpansion (5.2), with SubWord taken from AESE itself: a word
 * repeated in all four columns comes through ShiftRows unmoved, so AESE with a zero round key is
 * SubBytes on it. The rounds are FIPS-197's Cipher (5.1): AESE is AddRoundKey, ShiftRows and
 * SubBytes; AESMC is MixColumns; the last round has no MixColumns and ends with AddRoundKey. The
 * counter is GCM's — the last thirty-two bits of the block, big-endian, and nothing above them
 * (vendor/mbedtls/library/gcm.c:524-529). test/aead holds every byte of it to mbedTLS's GCM. */

static uint32_t sub_word(uint32_t w)
{
    uint8x16_t v = vaeseq_u8(vreinterpretq_u8_u32(vdupq_n_u32(w)), vdupq_n_u8(0));
    return vgetq_lane_u32(vreinterpretq_u32_u8(v), 0);
}

static void aes_hw_expand(lc_aes_hw *k, const uint8_t *key, size_t key_len)
{
    static const uint8_t rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };
    unsigned             nk = (unsigned)(key_len / 4u), nr = nk + 6u;
    uint32_t             w[4u * 15u];
    /* Words in memory order: on this little-endian core, byte 0 of a word is its low byte, so
     * RotWord is a rotation right by eight and Rcon goes into the low byte. */
    memcpy(w, key, key_len);
    for (unsigned i = nk; i < 4u * (nr + 1u); i++) {
        uint32_t t = w[i - 1u];
        if (i % nk == 0u)
            t = sub_word(t >> 8 | t << 24) ^ rcon[i / nk - 1u];
        else if (nk > 6u && i % nk == 4u)
            t = sub_word(t);
        w[i] = w[i - nk] ^ t;
    }
    memcpy(k->rk, w, 16u * (nr + 1u));
    k->rounds = nr;
    lc_wipe(w, sizeof w);
}

#define AES_ROUND(b, key) b = vaesmcq_u8(vaeseq_u8(b, key))

static void aes_hw_ctr(const lc_aes_hw *k, const uint8_t block[LC_GHASH_BLOCK], const uint8_t *in,
                       size_t len, uint8_t *out)
{
    uint8x16_t rk[15];
    unsigned   nr = k->rounds;
    for (unsigned r = 0; r <= nr; r++)
        rk[r] = vld1q_u8(k->rk[r]);
    uint32x4_t base = vreinterpretq_u32_u8(vld1q_u8(block));
    uint32_t   ctr = __builtin_bswap32(vgetq_lane_u32(base, 3));
#define CTR_BLOCK(i) vreinterpretq_u8_u32(vsetq_lane_u32(__builtin_bswap32(ctr + (i)), base, 3))

    while (len >= 8u * LC_GHASH_BLOCK) {
        uint8x16_t b0 = CTR_BLOCK(0u), b1 = CTR_BLOCK(1u), b2 = CTR_BLOCK(2u), b3 = CTR_BLOCK(3u);
        uint8x16_t b4 = CTR_BLOCK(4u), b5 = CTR_BLOCK(5u), b6 = CTR_BLOCK(6u), b7 = CTR_BLOCK(7u);
        ctr += 8u;
        for (unsigned r = 0; r + 1u < nr; r++) {
            AES_ROUND(b0, rk[r]);
            AES_ROUND(b1, rk[r]);
            AES_ROUND(b2, rk[r]);
            AES_ROUND(b3, rk[r]);
            AES_ROUND(b4, rk[r]);
            AES_ROUND(b5, rk[r]);
            AES_ROUND(b6, rk[r]);
            AES_ROUND(b7, rk[r]);
        }
        uint8x16_t last = rk[nr];
        vst1q_u8(out, veorq_u8(vld1q_u8(in), veorq_u8(vaeseq_u8(b0, rk[nr - 1u]), last)));
        vst1q_u8(out + 16, veorq_u8(vld1q_u8(in + 16), veorq_u8(vaeseq_u8(b1, rk[nr - 1u]), last)));
        vst1q_u8(out + 32, veorq_u8(vld1q_u8(in + 32), veorq_u8(vaeseq_u8(b2, rk[nr - 1u]), last)));
        vst1q_u8(out + 48, veorq_u8(vld1q_u8(in + 48), veorq_u8(vaeseq_u8(b3, rk[nr - 1u]), last)));
        vst1q_u8(out + 64, veorq_u8(vld1q_u8(in + 64), veorq_u8(vaeseq_u8(b4, rk[nr - 1u]), last)));
        vst1q_u8(out + 80, veorq_u8(vld1q_u8(in + 80), veorq_u8(vaeseq_u8(b5, rk[nr - 1u]), last)));
        vst1q_u8(out + 96, veorq_u8(vld1q_u8(in + 96), veorq_u8(vaeseq_u8(b6, rk[nr - 1u]), last)));
        vst1q_u8(out + 112, veorq_u8(vld1q_u8(in + 112), veorq_u8(vaeseq_u8(b7, rk[nr - 1u]), last)));
        in += 8u * LC_GHASH_BLOCK;
        out += 8u * LC_GHASH_BLOCK;
        len -= 8u * LC_GHASH_BLOCK;
    }
    while (len > 0u) {
        uint8x16_t b = CTR_BLOCK(0u);
        ctr++;
        for (unsigned r = 0; r + 1u < nr; r++)
            AES_ROUND(b, rk[r]);
        b = veorq_u8(vaeseq_u8(b, rk[nr - 1u]), rk[nr]);
        if (len >= LC_GHASH_BLOCK) {
            vst1q_u8(out, veorq_u8(vld1q_u8(in), b));
            in += LC_GHASH_BLOCK;
            out += LC_GHASH_BLOCK;
            len -= LC_GHASH_BLOCK;
            continue;
        }
        uint8_t stream[LC_GHASH_BLOCK];
        vst1q_u8(stream, b);
        for (size_t i = 0; i < len; i++)
            out[i] = (uint8_t)(in[i] ^ stream[i]);
        lc_wipe(stream, sizeof stream);
        len = 0;
    }
#undef CTR_BLOCK
}

#undef AES_ROUND

#pragma GCC pop_options
#endif

int lc_aes_hw_init(lc_aes_hw *k, const uint8_t *key, size_t key_len)
{
    k->rounds = 0;
#if defined(__aarch64__)
    if ((key_len == 16u || key_len == 32u) && ghash_hw()) {
        aes_hw_expand(k, key, key_len);
        return 0;
    }
#else
    (void)key;
    (void)key_len;
#endif
    return -1;
}

void lc_aes_hw_ctr32(const lc_aes_hw *k, const uint8_t block[LC_GHASH_BLOCK], const uint8_t *in,
                     size_t len, uint8_t *out)
{
#if defined(__aarch64__)
    aes_hw_ctr(k, block, in, len, out);
#else
    (void)k;
    (void)block;
    (void)in;
    (void)len;
    (void)out;
#endif
}

const char *lc_aes_ctr_name(void)
{
#if defined(__aarch64__)
    if (ghash_hw())
        return "aese";
#endif
    return "mbedtls";
}

typedef struct {
    uint64_t low, high;
} gcm_field_element;

static uint64_t be_uint64(const uint8_t *b)
{
    return (uint64_t)b[0] << 56 | (uint64_t)b[1] << 48 | (uint64_t)b[2] << 40 |
           (uint64_t)b[3] << 32 | (uint64_t)b[4] << 24 | (uint64_t)b[5] << 16 |
           (uint64_t)b[6] << 8 | (uint64_t)b[7];
}

static void be_put_uint64(uint8_t *b, uint64_t v)
{
    for (unsigned i = 0; i < 8u; i++)
        b[i] = (uint8_t)(v >> (56u - 8u * i));
}

/* reverseBits reverses the order of the bits of the 4-bit number in i. */
static unsigned reverse_bits(unsigned i)
{
    i = ((i << 2) & 0xcu) | ((i >> 2) & 0x3u);
    i = ((i << 1) & 0xau) | ((i >> 1) & 0x5u);
    return i;
}

/* Addition in a characteristic 2 field is just XOR. */
static gcm_field_element ghash_add(const gcm_field_element *x, const gcm_field_element *y)
{
    gcm_field_element r = { x->low ^ y->low, x->high ^ y->high };
    return r;
}

/* Because of the bit-ordering, doubling is a right shift; a bit shifted out of x^127 becomes x^128,
 * which is reduced by the irreducible polynomial 1+x+x^2+x^7+x^128. */
static gcm_field_element ghash_double(const gcm_field_element *x)
{
    int               msb_set = (x->high & 1u) == 1u;
    gcm_field_element d;

    d.high = x->high >> 1;
    d.high |= x->low << 63;
    d.low = x->low >> 1;
    if (msb_set)
        d.low ^= 0xe100000000000000ull;
    return d;
}

static const uint16_t ghash_reduction_table[16] = {
    0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
    0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0,
};

/* y = y * H, by multiplying z by 16 and adding one of the precomputed multiples of H, four bits at a
 * time, the high word first. */
static void ghash_mul(const gcm_field_element product_table[16], gcm_field_element *y)
{
    gcm_field_element z = { 0, 0 };

    for (unsigned i = 0; i < 2u; i++) {
        uint64_t word = i == 0u ? y->high : y->low;

        for (unsigned j = 0; j < 64u; j += 4u) {
            unsigned msw = (unsigned)(z.high & 0xfu);
            z.high >>= 4;
            z.high |= z.low << 60;
            z.low >>= 4;
            z.low ^= (uint64_t)ghash_reduction_table[msw] << 48;

            /* The values in the table are ordered for little-endian bit positions. */
            const gcm_field_element *t = &product_table[word & 0xfu];
            z.low ^= t->low;
            z.high ^= t->high;
            word >>= 4;
        }
    }
    *y = z;
}

static void update_blocks(const gcm_field_element product_table[16], gcm_field_element *y,
                          const uint8_t *blocks, size_t len)
{
    for (size_t off = 0; off < len; off += LC_GHASH_BLOCK) {
        y->low ^= be_uint64(blocks + off);
        y->high ^= be_uint64(blocks + off + 8u);
        ghash_mul(product_table, y);
    }
}

/* A short last block is zero-padded, like `copy(partialBlock[:], data[fullBlocks:])`. */
static void ghash_update(const gcm_field_element product_table[16], gcm_field_element *y,
                         const uint8_t *data, size_t len)
{
    size_t full = (len >> 4) << 4;

    update_blocks(product_table, y, data, full);
    if (len != full) {
        uint8_t partial[LC_GHASH_BLOCK];
        memset(partial, 0, sizeof partial);
        memcpy(partial, data + full, len - full);
        update_blocks(product_table, y, partial, sizeof partial);
    }
}

const char *lc_ghash_name(void)
{
#if defined(__x86_64__)
    if (ghash_x86_hw())
        return "pclmul";
#endif
#if defined(__aarch64__)
    if (ghash_hw())
        return "pmull";
#endif
    return "generic";
}

void lc_ghash(uint8_t out[LC_GHASH_BLOCK], const uint8_t h[LC_GHASH_BLOCK],
              const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len,
              const uint8_t *c, size_t c_len)
{
#if defined(__x86_64__)
    if (ghash_x86_hw()) {
        ghash_x86(out, h, a, a_len, b, b_len, c, c_len);
        return;
    }
#endif
#if defined(__aarch64__)
    if (ghash_hw()) {
        ghash_pmull(out, h, a, a_len, b, b_len, c, c_len);
        return;
    }
#endif
    /* productTable contains the first sixteen multiples of H, in bit-reversed order: 4*H is at
     * index 0010 (base 2) = 2, not at 4, because lookups use bits of a field element. */
    gcm_field_element product_table[16];
    memset(product_table, 0, sizeof product_table);

    gcm_field_element x = { be_uint64(h), be_uint64(h + 8) };
    product_table[reverse_bits(1u)] = x;
    for (unsigned i = 2; i < 16u; i += 2u) {
        product_table[reverse_bits(i)] = ghash_double(&product_table[reverse_bits(i / 2u)]);
        product_table[reverse_bits(i + 1u)] = ghash_add(&product_table[reverse_bits(i)], &x);
    }

    gcm_field_element y = { 0, 0 };
    if (a_len > 0u)
        ghash_update(product_table, &y, a, a_len);
    if (b_len > 0u)
        ghash_update(product_table, &y, b, b_len);
    if (c_len > 0u)
        ghash_update(product_table, &y, c, c_len);

    be_put_uint64(out, y.low);
    be_put_uint64(out + 8, y.high);

    /* The table is H's multiples, which is key material; y is the hash before the mask. */
    lc_wipe(product_table, sizeof product_table);
    lc_wipe(&x, sizeof x);
    lc_wipe(&y, sizeof y);
}
