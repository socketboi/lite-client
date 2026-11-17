#include "tls/aead.h"
#include "core/wipe.h"
#include "tls/chacha.h"
#include "tls/ghash.h"
#include "tls/poly1305.h"

#include <string.h>

/* ⚠️ A STANDARD IS NOT A FILE:LINE, WHICH IS WHY THE SIEVE NEVER OPENED THIS ONE. The
 * citations below are new; the code is not. src/tls/aead.c stood in COVERAGE.md among the
 * files no pair reaches, and the reason was that every claim here named SP 800-38D — the
 * right authority for what GCM IS, and no help at all against the failure this file actually
 * has. A wrong AEAD does not crash: it produces bytes, the node rejects them, and the tunnel
 * connects and carries nothing, which looks exactly like a wrong uuid or a dead node.
 *
 * So the claims are pinned to the implementation this code REPLACED, and that implementation
 * is vendored: mbedtls_gcm_crypt_and_tag (vendor/mbedtls/library/gcm.c:703-736). test/aead
 * runs it at run time over the same inputs and demands every byte of ciphertext and tag
 * match — the head of that test says why fixed vectors alone would not do. Three places the
 * two could differ silently, each cited where it is written below: the counter block for a
 * twelve-byte nonce, which bits of it the counter advances, and the length block that closes
 * the hash. The fourth, the tag mask, is cited at the seal. */

/* AES-GCM's counter block for a twelve-byte nonce is the nonce with a 32-bit counter after it, and
 * TLS 1.3 has no other shape: "if len(IV) = 96, then J0 = IV || 0^31 || 1" (NIST SP 800-38D, 7.1
 * step 2). The data starts one block later, at 2 — the reference increments before the first
 * data block rather than after it (vendor/mbedtls/library/gcm.c:627, :640), which is the same
 * thing said as code. Its own J0 for this length is `memcpy(ctx->y, iv, iv_len); ctx->y[15] = 1;`
 * (gcm.c:403-405). */
#define GCM_BLOCK 16u

/* WHICH ALGORITHM A BOUND CONTEXT HOLDS, derived rather than stored: `is_gcm` and `key_len` already
 * determine it, and a field would be a second copy of the same fact for a caller to let drift.
 *
 * It exists because of a mistake made on 2026-09-19 that cost an hour and a wrong line in a note.
 * The Hysteria2 plane names its suite in the log; the REALITY plane named nothing, so the AES-GCM
 * ceiling measured by test/bench was reasoned onto a tunnel that turned out to be running
 * ChaCha20-Poly1305 — and the arithmetic agreed with the observed processor share by coincidence,
 * which is the worst way for a wrong number to be wrong. A plane that says which cipher it is using
 * cannot be guessed about. */
lc_aead_alg lc_aead_alg_of(const lc_aead *a)
{
    if (!a->is_gcm)
        return LC_AEAD_CHACHA20_POLY1305;

    return a->key_len == 16u ? LC_AEAD_AES_128_GCM : LC_AEAD_AES_256_GCM;
}

/* The one place the three names are spelled. lc_qconn_suite reaches them through this as well, from
 * a suite id, so a name cannot differ between the two planes. */
const char *lc_aead_alg_name(lc_aead_alg alg)
{
    switch (alg) {
    case LC_AEAD_AES_128_GCM:       return "AES-128-GCM";
    case LC_AEAD_AES_256_GCM:       return "AES-256-GCM";
    case LC_AEAD_CHACHA20_POLY1305: return "ChaCha20-Poly1305";
    default:                        return "an unknown suite";
    }
}

size_t lc_aead_key_len(lc_aead_alg alg)
{
    /* A switch, and zero for anything not listed, because the shape this had — "sixteen if
     * AES-128, otherwise thirty-two" — answers thirty-two for an algorithm that does not exist.
     * That answer is not a wrong number in a report; every caller uses it as a LENGTH. qcrypto.c
     * copies exactly this many bytes out of a key it was handed, so an enum value that never
     * belonged there would read sixteen bytes past the end of a sixteen-byte key and call the
     * result a header-protection key. Zero is refused everywhere a length is used, which is what an
     * unknown algorithm has to be. */
    switch (alg) {
    case LC_AEAD_AES_128_GCM: return 16u;
    case LC_AEAD_AES_256_GCM: return 32u;
    case LC_AEAD_CHACHA20_POLY1305: return 32u;
    }
    return 0;
}

/* One block encryption at a stated counter block, which is how both of GCM's uses of the raw
 * cipher are spelled: E(K, 0^128) for the hash subkey and E(K, J0) for the tag mask. */
static int aes_block(lc_aead *a, const uint8_t in[GCM_BLOCK], uint8_t out[GCM_BLOCK])
{
    return mbedtls_aes_crypt_ecb(&a->aes, MBEDTLS_AES_ENCRYPT, in, out) == 0 ? 0 : -1;
}

int lc_aead_init(lc_aead *a, lc_aead_alg alg, const uint8_t *key)
{
    /* Initialised whatever the suite, so that lc_aead_free needs no branch and stays correct on a
     * context that failed halfway. mbedTLS's init only zeroes a structure. */
    mbedtls_aes_init(&a->aes);
    a->hw.rounds = 0;
    a->ready = 0;
    a->is_gcm = (alg == LC_AEAD_AES_128_GCM || alg == LC_AEAD_AES_256_GCM);
    a->key_len = lc_aead_key_len(alg);
    memset(a->h, 0, sizeof a->h);
    memset(a->chacha_key, 0, sizeof a->chacha_key);
    if (a->key_len == 0)
        return -1;

    if (a->is_gcm) {
        /* ENCRYPT for both directions: CTR never decrypts, it produces a keystream, and the
         * keystream is its own inverse. A decrypt schedule here would be wrong, not merely
         * wasteful. */
        if (mbedtls_aes_setkey_enc(&a->aes, key, (unsigned)(a->key_len * 8u)) != 0) {
            mbedtls_aes_free(&a->aes);
            return -1;
        }
        (void)lc_aes_hw_init(&a->hw, key, a->key_len);
        /* The hash subkey, once. "Let H = CIPH(K, 0^128)" (SP 800-38D, 7.1 step 1): it depends on
         * the key and nothing else, so deriving it per record would be one wasted block encryption
         * per record for the life of the connection. */
        static const uint8_t zero_block[GCM_BLOCK] = { 0 };
        if (aes_block(a, zero_block, a->h) != 0) {
            mbedtls_aes_free(&a->aes);
            return -1;
        }
        a->ready = 1;
        return 0;
    }

    /* chacha20poly1305.New keeps the key and nothing else (chacha20poly1305.go), so this does the
     * same; there is nothing to allocate, which also means nothing to leak when a handshake is torn
     * down halfway — the case the mbedTLS context this replaced had to be freed by hand for. */
    memcpy(a->chacha_key, key, sizeof a->chacha_key);
    a->ready = 1;
    return 0;
}

void lc_aead_free(lc_aead *a)
{
    mbedtls_aes_free(&a->aes);
    lc_wipe(&a->hw, sizeof a->hw);
    lc_wipe(a->h, sizeof a->h);
    lc_wipe(a->chacha_key, sizeof a->chacha_key);
    a->is_gcm = 0;
    a->ready = 0;
}

static int tags_equal(const uint8_t *a, const uint8_t *b, size_t n);

/* CHACHA20-POLY1305, AS X/CRYPTO SEALS AND OPENS IT — chacha20poly1305_generic.go, which is what
 * both references run on every processor this client ships to (the assembly AEAD is amd64's alone).
 * One cipher per call from the key and the nonce; the Poly1305 key is the first 32 bytes of block 0;
 * the payload from block 1 (`s.SetCounter(1)`, which on arm64 reuses the three blocks already made
 * with block 0, since the keystream comes four blocks at a time there); the tag over the additional
 * data and the ciphertext, each padded to sixteen bytes, then both lengths as 64-bit little-endian
 * (writeWithPadding, writeUint64). */
static void chacha_poly_tag(const uint8_t poly_key[LC_POLY1305_KEY], const uint8_t *aad,
                            size_t aad_len, const uint8_t *ct, size_t ct_len,
                            uint8_t tag[LC_POLY1305_TAG])
{
    static const uint8_t zeros[16] = { 0 };
    uint8_t              lens[16];
    lc_poly1305          p;

    lc_poly1305_init(&p, poly_key);
    lc_poly1305_write(&p, aad, aad_len);
    if (aad_len % 16u != 0)
        lc_poly1305_write(&p, zeros, 16u - aad_len % 16u);
    lc_poly1305_write(&p, ct, ct_len);
    if (ct_len % 16u != 0)
        lc_poly1305_write(&p, zeros, 16u - ct_len % 16u);
    for (unsigned i = 0; i < 8u; i++) {
        lens[i] = (uint8_t)((uint64_t)aad_len >> (8u * i));
        lens[8u + i] = (uint8_t)((uint64_t)ct_len >> (8u * i));
    }
    lc_poly1305_write(&p, lens, sizeof lens);
    lc_poly1305_sum(&p, tag);
    lc_wipe(&p, sizeof p);
}

/* The cipher for one call, positioned at block 1 with the Poly1305 key taken out of block 0. */
static int chacha_start(const lc_aead *a, const uint8_t nonce[LC_AEAD_NONCE], lc_chacha *s,
                        uint8_t poly_key[LC_POLY1305_KEY])
{
    lc_chacha_init(s, a->chacha_key, nonce);
    memset(poly_key, 0, LC_POLY1305_KEY);
    if (lc_chacha_xor(s, poly_key, poly_key, LC_POLY1305_KEY) != 0)
        return -1;
    return lc_chacha_set_counter(s, 1u);
}

static int chacha_seal(lc_aead *a, const uint8_t nonce[LC_AEAD_NONCE],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *pt, size_t pt_len,
                       uint8_t *out, size_t *out_len)
{
    lc_chacha s;
    uint8_t   poly_key[LC_POLY1305_KEY];
    int       rc = -1;

    if (chacha_start(a, nonce, &s, poly_key) == 0 && lc_chacha_xor(&s, out, pt, pt_len) == 0) {
        /* Over the CIPHERTEXT, which is why an in-place seal is safe: `out` holds it by now. */
        chacha_poly_tag(poly_key, aad, aad_len, out, pt_len, out + pt_len);
        *out_len = pt_len + LC_AEAD_TAG;
        rc = 0;
    }
    lc_wipe(&s, sizeof s);
    lc_wipe(poly_key, sizeof poly_key);
    return rc;
}

static int chacha_open(lc_aead *a, const uint8_t nonce[LC_AEAD_NONCE],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t ct_len,
                       uint8_t *out, size_t *out_len)
{
    lc_chacha s;
    uint8_t   poly_key[LC_POLY1305_KEY], want[LC_POLY1305_TAG];
    size_t    body = ct_len - LC_AEAD_TAG;
    int       rc = -1;

    /* Authenticated before anything is decrypted, as openGeneric does: the tag over the ciphertext
     * is checked first and the keystream is applied only if it holds. */
    if (chacha_start(a, nonce, &s, poly_key) == 0) {
        chacha_poly_tag(poly_key, aad, aad_len, ct, body, want);
        if (tags_equal(want, ct + body, LC_AEAD_TAG) && lc_chacha_xor(&s, out, ct, body) == 0) {
            *out_len = body;
            rc = 0;
        }
    }
    lc_wipe(&s, sizeof s);
    lc_wipe(poly_key, sizeof poly_key);
    lc_wipe(want, sizeof want);
    return rc;
}

/* GHASH over what GCM authenticates: the additional data, then the ciphertext, then a block giving
 * both lengths in bits. Each of the first two is zero-padded to a block boundary, which is what
 * lc_ghash does with a short final piece by itself, so the three inputs below are the three parts
 * of the formula and not an approximation of it. It is the reference's GHASH — Go's generic
 * ghash.go, which is what Xray runs on a router — and Go's GCM calls it exactly so:
 * `ghash(&S, H, additionalData, ciphertext, lenBlock)`.
 *
 * `S = GHASH_H(A || 0^v || C || 0^u || [len(A)]_64 || [len(C)]_64)`   (SP 800-38D, 7.1 step 5)
 *
 * Both lengths are in BITS and the ADDITIONAL DATA's comes first — the two things a reader of
 * the formula alone gets backwards. The reference computes `orig_len = ctx->len * 8` and
 * `orig_add_len = ctx->add_len * 8` (vendor/mbedtls/library/gcm.c:668-669) and lays them out
 * add-first, big-endian, in one sixteen-byte block (gcm.c:688-691). */
static void ghash_gcm(const uint8_t h[GCM_BLOCK], const uint8_t *aad, size_t aad_len,
                      const uint8_t *ct, size_t ct_len, uint8_t out[GCM_BLOCK])
{
    uint8_t  len_block[GCM_BLOCK];
    uint64_t abits = (uint64_t)aad_len * 8u;
    uint64_t cbits = (uint64_t)ct_len * 8u;

    for (unsigned i = 0; i < 8u; i++) {
        len_block[i]      = (uint8_t)(abits >> (56u - 8u * i));
        len_block[8u + i] = (uint8_t)(cbits >> (56u - 8u * i));
    }
    lc_ghash(out, h, aad, aad_len, ct, ct_len, len_block, sizeof len_block);
}

/* J0 with a stated counter in its last four bytes.
 *
 * ⚠️ mbedtls_aes_crypt_ctr increments the WHOLE sixteen-byte block where GCM increments only the
 * last thirty-two bits — `x = MBEDTLS_GET_UINT32_BE(y, 12); x++; MBEDTLS_PUT_UINT32_BE(x, y, 12)`
 * (vendor/mbedtls/library/gcm.c:524-529), and nothing above byte twelve is touched. The two agree
 * exactly as long as that 32-bit field does not wrap. It cannot here: a TLS 1.3 record holds at
 * most LC_REC_MAX_PLAINTEXT bytes, so at most about 2^10 blocks, and the counter runs from 2 to
 * roughly 1025. The bound is the record layer's, not a hope — and test/aead drives a full-size
 * record to keep it that way. */
static void gcm_j0(const uint8_t nonce[LC_AEAD_NONCE], uint32_t counter, uint8_t out[GCM_BLOCK])
{
    memcpy(out, nonce, LC_AEAD_NONCE);
    out[12] = (uint8_t)(counter >> 24);
    out[13] = (uint8_t)(counter >> 16);
    out[14] = (uint8_t)(counter >> 8);
    out[15] = (uint8_t)counter;
}

/* Equal or not, without saying WHERE they stopped matching. A tag compared with memcmp leaks the
 * length of the matching prefix through timing, and that is enough to forge one byte at a time. */
static int tags_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

/* The payload, from counter 2 onward. In place is allowed and is what the record layer does. */
static int gcm_ctr(lc_aead *a, const uint8_t nonce[LC_AEAD_NONCE],
                   const uint8_t *in, size_t len, uint8_t *out)
{
    uint8_t counter[GCM_BLOCK], stream[GCM_BLOCK];
    size_t  nc_off = 0;
    int     rc;

    if (len == 0)
        return 0;
    gcm_j0(nonce, 2u, counter);
    /* Eight blocks at a time on the ARMv8 crypto extension, as Go does there — see tls/ghash.c. */
    if (a->hw.rounds != 0u) {
        lc_aes_hw_ctr32(&a->hw, counter, in, len, out);
        lc_wipe(counter, sizeof counter);
        return 0;
    }
    memset(stream, 0, sizeof stream);
    rc = mbedtls_aes_crypt_ctr(&a->aes, len, &nc_off, counter, stream, in, out);
    lc_wipe(stream, sizeof stream);
    lc_wipe(counter, sizeof counter);
    return rc == 0 ? 0 : -1;
}

static int gcm_seal(lc_aead *a, const uint8_t nonce[LC_AEAD_NONCE],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *pt, size_t pt_len,
                    uint8_t *out, size_t *out_len)
{
    uint8_t j0[GCM_BLOCK], mask[GCM_BLOCK], tag[GCM_BLOCK];

    gcm_j0(nonce, 1u, j0);
    if (aes_block(a, j0, mask) != 0)
        return -1;
    if (gcm_ctr(a, nonce, pt, pt_len, out) != 0) {
        lc_wipe(mask, sizeof mask);
        return -1;
    }

    /* Over the CIPHERTEXT, which is why this comes after the encryption and why an in-place call is
     * safe: `out` already holds C by the time it is read. The mask it is xored with is E(K, J0),
     * taken once at the start and kept — the reference calls it base_ectr, fills it while still
     * in gcm_starts (vendor/mbedtls/library/gcm.c:438-442, one line or the other depending on the
     * build) and finishes with `memcpy(tag, ctx->base_ectr, tag_len)` followed by the xor of the
     * hash (gcm.c:683-697). */
    ghash_gcm(a->h, aad, aad_len, out, pt_len, tag);
    for (unsigned i = 0; i < GCM_BLOCK; i++)
        out[pt_len + i] = (uint8_t)(tag[i] ^ mask[i]);

    *out_len = pt_len + LC_AEAD_TAG;
    lc_wipe(mask, sizeof mask);
    return 0;
}

static int gcm_open(lc_aead *a, const uint8_t nonce[LC_AEAD_NONCE],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ct, size_t ct_len,
                    uint8_t *out, size_t *out_len)
{
    uint8_t j0[GCM_BLOCK], mask[GCM_BLOCK], tag[GCM_BLOCK], want[GCM_BLOCK];
    size_t  body = ct_len - LC_AEAD_TAG;

    gcm_j0(nonce, 1u, j0);
    if (aes_block(a, j0, mask) != 0)
        return -1;

    /* ⚠️ AUTHENTICATED BEFORE ANYTHING IS DECRYPTED, which is the order SP 800-38D states and the
     * order that matters: "If T' != T, then return FAIL" comes before the plaintext exists at all
     * (7.2 step 7). Decrypting first and checking afterwards produces plaintext from a forged
     * record, and something always ends up reading it. */
    ghash_gcm(a->h, aad, aad_len, ct, body, tag);
    for (unsigned i = 0; i < GCM_BLOCK; i++)
        want[i] = (uint8_t)(tag[i] ^ mask[i]);
    if (!tags_equal(want, ct + body, LC_AEAD_TAG)) {
        lc_wipe(mask, sizeof mask);
        lc_wipe(want, sizeof want);
        return -1;
    }

    if (gcm_ctr(a, nonce, ct, body, out) != 0) {
        lc_wipe(mask, sizeof mask);
        return -1;
    }

    *out_len = body;
    lc_wipe(mask, sizeof mask);
    return 0;
}

int lc_aead_seal(lc_aead *a, const uint8_t nonce[LC_AEAD_NONCE],
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *pt, size_t pt_len,
                 uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!a->ready)
        return -1;
    if (out_cap < pt_len + LC_AEAD_TAG)
        return -1;

    if (a->is_gcm)
        return gcm_seal(a, nonce, aad, aad_len, pt, pt_len, out, out_len);
    return chacha_seal(a, nonce, aad, aad_len, pt, pt_len, out, out_len);
}

int lc_aead_open(lc_aead *a, const uint8_t nonce[LC_AEAD_NONCE],
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *ct, size_t ct_len,
                 uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!a->ready)
        return -1;
    if (ct_len < LC_AEAD_TAG)
        return -1;
    if (out_cap < ct_len - LC_AEAD_TAG)
        return -1;

    if (a->is_gcm) {
        if (gcm_open(a, nonce, aad, aad_len, ct, ct_len, out, out_len) != 0) {
            /* The same belt and braces as the ChaCha arm: gcm_open returns before it writes any
             * plaintext, and this makes sure a careless caller finds nothing to read anyway. */
            lc_wipe(out, out_cap);
            return -1;
        }
        return 0;
    }

    if (chacha_open(a, nonce, aad, aad_len, ct, ct_len, out, out_len) != 0) {
        /* chacha_open writes no plaintext before the tag holds, as openGeneric zeroes `out` when
         * it does not; wiping here makes sure a careless caller finds nothing to read anyway. */
        lc_wipe(out, out_cap);
        return -1;
    }
    return 0;
}
