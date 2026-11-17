/* AES-GCM assembled from two libraries, checked against the one it replaced.
 *
 * src/tls/aead.c stopped calling mbedTLS's AES-GCM and now builds it: mbedTLS's AES-CTR for the
 * keystream, the reference's GHASH (Go's ghash.go, src/tls/ghash.c; BearSSL's br_ghash_ctmul until
 * 2026-09-21) for the authentication, and the GCM construction in between.
 * The reason is measured and lives in src/tls/aead.h — 18 Mbit/s against 46 on the target router.
 *
 * ⚠️ WHAT MAKES THAT SAFE IS THIS FILE, and only this file. An AEAD that is wrong does not crash:
 * it produces bytes, and the node rejects them, and the symptom is a tunnel that connects and
 * carries nothing — which is indistinguishable from a wrong uuid, a dead node or a bad key. There
 * is no partial credit and no way to notice by looking.
 *
 * So the check is not a transcription. mbedtls_gcm_crypt_and_tag computes the answer HERE, at run
 * time, over the same inputs, and every byte of ciphertext and tag must match. That is the same
 * rule tools/vendorcap serves for the wire formats: where the reference can be run, run it, because
 * a test written from the same reading agrees with the same mistake.
 *
 * The two fixed vectors are the anchor under that. If our code and mbedTLS agreed with each other
 * but both disagreed with the published answer, the cross-check alone would call it green. */

#include "tls/aead.h"
#include "tls/chacha.h"
#include "tls/ghash.h"
#include "tls/poly1305.h"

#include <mbedtls/chacha20.h>
#include <mbedtls/chachapoly.h>
#include <mbedtls/gcm.h>
#include <mbedtls/poly1305.h>

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

/* GCM's own test cases 2 and 14 (McGrew & Viega, "The Galois/Counter Mode of Operation"): the
 * all-zero key, the all-zero 96-bit IV and one all-zero block of plaintext, for both key sizes. */
static const uint8_t tc2_ct[16] = { 0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
                                    0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78 };
static const uint8_t tc2_tag[16] = { 0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
                                     0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf };
static const uint8_t tc14_ct[16] = { 0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
                                     0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18 };
static const uint8_t tc14_tag[16] = { 0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
                                      0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19 };

static void known_answer(const char *name, lc_aead_alg alg, size_t key_len,
                         const uint8_t *want_ct, const uint8_t *want_tag)
{
    uint8_t key[32] = { 0 };
    uint8_t nonce[LC_AEAD_NONCE] = { 0 };
    uint8_t pt[16] = { 0 };
    uint8_t out[16 + LC_AEAD_TAG];
    size_t  out_len = 0;
    char    msg[96];

    (void)key_len;
    lc_aead a;
    if (lc_aead_init(&a, alg, key) != 0) {
        snprintf(msg, sizeof msg, "%s: init", name);
        ok(0, msg);
        return;
    }
    int rc = lc_aead_seal(&a, nonce, NULL, 0, pt, sizeof pt, out, sizeof out, &out_len);
    lc_aead_free(&a);

    snprintf(msg, sizeof msg, "%s: the published ciphertext, byte for byte", name);
    ok(rc == 0 && out_len == sizeof out && memcmp(out, want_ct, 16) == 0, msg);
    snprintf(msg, sizeof msg, "%s: the published tag, byte for byte", name);
    ok(rc == 0 && memcmp(out + 16, want_tag, LC_AEAD_TAG) == 0, msg);
}

/* Every size that has ever been where an AEAD goes wrong: nothing at all, one byte, one block short
 * of a boundary, exactly a boundary, one past it, and a full record. */
static const size_t sizes[] = { 0, 1, 15, 16, 17, 31, 32, 33, 255, 1024, 4096, 16384 };

static void against_reference(const char *name, lc_aead_alg alg, unsigned key_bits, size_t aad_len)
{
    static uint8_t pt[16384];
    static uint8_t ours[16384 + LC_AEAD_TAG];
    static uint8_t theirs[16384];
    static uint8_t theirs_tag[LC_AEAD_TAG];
    static uint8_t back[16384];
    uint8_t        key[32], nonce[LC_AEAD_NONCE], aad[32];
    char           msg[128];

    for (unsigned i = 0; i < sizeof key; i++)
        key[i] = (uint8_t)(0x40u + i);
    for (unsigned i = 0; i < sizeof nonce; i++)
        nonce[i] = (uint8_t)(0x90u + i);
    for (unsigned i = 0; i < sizeof aad; i++)
        aad[i] = (uint8_t)(0x11u * i);
    for (unsigned i = 0; i < sizeof pt; i++)
        pt[i] = (uint8_t)(i * 7u + 3u);

    lc_aead a;
    if (lc_aead_init(&a, alg, key) != 0) {
        snprintf(msg, sizeof msg, "%s: init", name);
        ok(0, msg);
        return;
    }

    mbedtls_gcm_context g;
    mbedtls_gcm_init(&g);
    if (mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, key_bits) != 0) {
        snprintf(msg, sizeof msg, "%s: reference setkey", name);
        ok(0, msg);
        lc_aead_free(&a);
        mbedtls_gcm_free(&g);
        return;
    }

    int all_ct = 1, all_tag = 1, all_round = 1;
    for (unsigned i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
        size_t n = sizes[i];
        size_t out_len = 0, back_len = 0;

        if (lc_aead_seal(&a, nonce, aad_len ? aad : NULL, aad_len, pt, n,
                         ours, sizeof ours, &out_len) != 0 || out_len != n + LC_AEAD_TAG) {
            all_ct = 0;
            continue;
        }
        if (mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, n, nonce, LC_AEAD_NONCE,
                                      aad_len ? aad : NULL, aad_len, pt, theirs,
                                      LC_AEAD_TAG, theirs_tag) != 0) {
            all_ct = 0;
            continue;
        }
        if (n > 0 && memcmp(ours, theirs, n) != 0)
            all_ct = 0;
        if (memcmp(ours + n, theirs_tag, LC_AEAD_TAG) != 0)
            all_tag = 0;

        /* And it opens what it sealed, which the comparison above does not show: a seal and an open
         * that are wrong in the same way agree with each other and with nothing else. */
        if (lc_aead_open(&a, nonce, aad_len ? aad : NULL, aad_len, ours, out_len,
                         back, sizeof back, &back_len) != 0 ||
            back_len != n || (n > 0 && memcmp(back, pt, n) != 0))
            all_round = 0;
    }

    snprintf(msg, sizeof msg, "%s%s: ciphertext matches mbedtls at every size",
             name, aad_len ? " with aad" : "");
    ok(all_ct, msg);
    snprintf(msg, sizeof msg, "%s%s: tag matches mbedtls at every size",
             name, aad_len ? " with aad" : "");
    ok(all_tag, msg);
    snprintf(msg, sizeof msg, "%s%s: opens what it sealed", name, aad_len ? " with aad" : "");
    ok(all_round, msg);

    lc_aead_free(&a);
    mbedtls_gcm_free(&g);
}

/* A record that was altered must not open. Checked at each of the three places an alteration can
 * land, because they fail through different code: the tag is compared, the ciphertext is hashed,
 * and the additional data is hashed but never transmitted. */
static void refuses_tampering(const char *name, lc_aead_alg alg)
{
    uint8_t key[32], nonce[LC_AEAD_NONCE], aad[16], pt[64];
    uint8_t sealed[64 + LC_AEAD_TAG], back[64];
    size_t  out_len = 0, back_len = 0;
    char    msg[128];

    memset(key, 0x7c, sizeof key);
    memset(nonce, 0x31, sizeof nonce);
    memset(aad, 0x5e, sizeof aad);
    memset(pt, 0xa4, sizeof pt);

    lc_aead a;
    if (lc_aead_init(&a, alg, key) != 0) {
        snprintf(msg, sizeof msg, "%s: init", name);
        ok(0, msg);
        return;
    }
    if (lc_aead_seal(&a, nonce, aad, sizeof aad, pt, sizeof pt, sealed, sizeof sealed,
                     &out_len) != 0) {
        snprintf(msg, sizeof msg, "%s: seal", name);
        ok(0, msg);
        lc_aead_free(&a);
        return;
    }

    sealed[sizeof sealed - 1] ^= 0x01u;
    snprintf(msg, sizeof msg, "%s: a flipped bit in the tag is refused", name);
    ok(lc_aead_open(&a, nonce, aad, sizeof aad, sealed, out_len, back, sizeof back,
                    &back_len) != 0, msg);
    sealed[sizeof sealed - 1] ^= 0x01u;

    sealed[0] ^= 0x01u;
    snprintf(msg, sizeof msg, "%s: a flipped bit in the ciphertext is refused", name);
    ok(lc_aead_open(&a, nonce, aad, sizeof aad, sealed, out_len, back, sizeof back,
                    &back_len) != 0, msg);
    sealed[0] ^= 0x01u;

    aad[0] ^= 0x01u;
    snprintf(msg, sizeof msg, "%s: a flipped bit in the additional data is refused", name);
    ok(lc_aead_open(&a, nonce, aad, sizeof aad, sealed, out_len, back, sizeof back,
                    &back_len) != 0, msg);
    aad[0] ^= 0x01u;

    snprintf(msg, sizeof msg, "%s: and the untouched record still opens", name);
    ok(lc_aead_open(&a, nonce, aad, sizeof aad, sealed, out_len, back, sizeof back,
                    &back_len) == 0 && back_len == sizeof pt && memcmp(back, pt, sizeof pt) == 0,
       msg);

    lc_aead_free(&a);
}

/* The record layer seals IN PLACE — lc_record_protect assembles the inner plaintext right after the
 * header and encrypts it from there into the same region, so that a router does not hold two copies
 * of every sixteen-kilobyte record.
 *
 * ⚠️ AND THE LENGTHS HERE ARE DELIBERATELY NOT MULTIPLES OF SIXTEEN. This test existed before and
 * used 512, and 512 is exactly the case that cannot fail: mbedtls_cipher_update refuses an in-place
 * call only when the length is NOT a whole number of blocks —
 *
 *     if (input == output && (ctx->unprocessed_len != 0 || ilen % block_size))
 *         return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
 *
 * — so a green in-place test sat next to an AEAD that failed on every real record, because a record
 * is 658 bytes or 37 or 3, never 512. The sizes below are the ones a payload actually takes, and
 * the largest is a full record so that the 32-bit counter's range is exercised too.
 *
 * The second thing this catches is order: GHASH reads the CIPHERTEXT, so gcm_seal must encrypt
 * before it hashes. Backwards, it authenticates the plaintext and produces a tag no peer accepts. */
static void in_place(const char *name, lc_aead_alg alg)
{
    static const size_t lens[] = { 1, 3, 17, 37, 51, 206, 658, 16383 };
    static uint8_t      buf[16384 + LC_AEAD_TAG];
    static uint8_t      apart[16384 + LC_AEAD_TAG];
    static uint8_t      copy[16384];
    uint8_t             key[32], nonce[LC_AEAD_NONCE], aad[5];
    char                msg[128];

    memset(key, 0x22, sizeof key);
    memset(nonce, 0x66, sizeof nonce);
    memset(aad, 0x17, sizeof aad);

    lc_aead a;
    if (lc_aead_init(&a, alg, key) != 0) {
        snprintf(msg, sizeof msg, "%s: init", name);
        ok(0, msg);
        return;
    }

    int all = 1;
    for (unsigned i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        size_t n = lens[i], a_len = 0, b_len = 0;
        for (size_t j = 0; j < n; j++)
            copy[j] = (uint8_t)((j * 11u) ^ 0x5au);
        memcpy(buf, copy, n);

        if (lc_aead_seal(&a, nonce, aad, sizeof aad, buf, n, buf, sizeof buf, &a_len) != 0 ||
            lc_aead_seal(&a, nonce, aad, sizeof aad, copy, n, apart, sizeof apart, &b_len) != 0 ||
            a_len != b_len || memcmp(buf, apart, a_len) != 0)
            all = 0;
    }

    snprintf(msg, sizeof msg,
             "%s: sealing in place matches sealing apart, at lengths no block divides", name);
    ok(all, msg);

    lc_aead_free(&a);
}

/* ---- ChaCha20-Poly1305: x/crypto's, ported (src/tls/chacha.c, poly1305.c) ----------------------
 *
 * The same rule as for GCM above: mbedTLS's ChaCha20-Poly1305, which this replaced, is run here over
 * the same inputs and must agree byte for byte, and one published vector anchors both. The pieces
 * below that are NOT the AEAD's own shape — keystream drawn in odd lengths, a counter moved inside
 * the buffer, a counter near its end — are there because the port keeps x/crypto's buffer of spare
 * keystream (four blocks on arm64, one elsewhere), and a buffer is where an off-by-one hides from a
 * test that always asks for whole records. */

/* RFC 8439 section 2.8.2, copied by hand from the vendored mbedTLS self-test that carries it
 * (vendor/mbedtls/library/chachapoly.c:325-409). */
static const uint8_t rfc_key[32] = {
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
};
static const uint8_t rfc_nonce[12] = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
                                       0x44, 0x45, 0x46, 0x47 };
static const uint8_t rfc_aad[12] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
                                     0xc4, 0xc5, 0xc6, 0xc7 };
static const char    rfc_pt[] = "Ladies and Gentlemen of the class of '99: If I could offer you only "
                                "one tip for the future, sunscreen would be it.";
static const uint8_t rfc_ct[114] = {
    0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
    0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
    0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
    0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
    0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
    0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
    0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
    0x61, 0x16
};
static const uint8_t rfc_tag[16] = { 0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
                                     0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91 };

static void chacha_known_answer(void)
{
    uint8_t out[114 + LC_AEAD_TAG], back[114];
    size_t  out_len = 0, back_len = 0;
    lc_aead a;

    if (lc_aead_init(&a, LC_AEAD_CHACHA20_POLY1305, rfc_key) != 0) {
        ok(0, "chacha20-poly1305: init");
        return;
    }
    int rc = lc_aead_seal(&a, rfc_nonce, rfc_aad, sizeof rfc_aad, (const uint8_t *)rfc_pt, 114u,
                          out, sizeof out, &out_len);
    ok(rc == 0 && out_len == sizeof out && memcmp(out, rfc_ct, sizeof rfc_ct) == 0,
       "chacha20-poly1305: RFC 8439's ciphertext, byte for byte");
    ok(rc == 0 && memcmp(out + 114, rfc_tag, sizeof rfc_tag) == 0,
       "chacha20-poly1305: RFC 8439's tag, byte for byte");
    ok(lc_aead_open(&a, rfc_nonce, rfc_aad, sizeof rfc_aad, out, out_len, back, sizeof back,
                    &back_len) == 0 && back_len == 114u && memcmp(back, rfc_pt, 114u) == 0,
       "chacha20-poly1305: and it opens to the sunscreen sentence");
    lc_aead_free(&a);
}

static void chacha_against_reference(size_t aad_len)
{
    static uint8_t pt[16384], ours[16384 + LC_AEAD_TAG], theirs[16384], back[16384];
    uint8_t        theirs_tag[LC_AEAD_TAG], key[32], nonce[LC_AEAD_NONCE], aad[32];
    char           msg[128];

    for (unsigned i = 0; i < sizeof key; i++)
        key[i] = (uint8_t)(0x40u + 3u * i);
    for (unsigned i = 0; i < sizeof nonce; i++)
        nonce[i] = (uint8_t)(0x90u + i);
    for (unsigned i = 0; i < sizeof aad; i++)
        aad[i] = (uint8_t)(0x11u * i);
    for (unsigned i = 0; i < sizeof pt; i++)
        pt[i] = (uint8_t)(i * 7u + 3u);

    lc_aead a;
    if (lc_aead_init(&a, LC_AEAD_CHACHA20_POLY1305, key) != 0) {
        ok(0, "chacha20-poly1305: init");
        return;
    }
    mbedtls_chachapoly_context m;
    mbedtls_chachapoly_init(&m);
    if (mbedtls_chachapoly_setkey(&m, key) != 0) {
        ok(0, "chacha20-poly1305: reference setkey");
        lc_aead_free(&a);
        return;
    }

    /* The GCM sizes, and the ones this AEAD's own geometry makes interesting: the Poly1305 key's
     * 32 bytes, the three blocks left in a four-block buffer after it (192), a QUIC packet. */
    static const size_t csizes[] = { 0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 191, 192, 193,
                                     255, 256, 257, 1024, 1350, 1452, 4096, 16384 };
    int all_ct = 1, all_tag = 1, all_round = 1;
    for (unsigned i = 0; i < sizeof csizes / sizeof csizes[0]; i++) {
        size_t n = csizes[i], out_len = 0, back_len = 0;
        if (lc_aead_seal(&a, nonce, aad_len ? aad : NULL, aad_len, pt, n, ours, sizeof ours,
                         &out_len) != 0 || out_len != n + LC_AEAD_TAG ||
            mbedtls_chachapoly_encrypt_and_tag(&m, n, nonce, aad_len ? aad : NULL, aad_len, pt,
                                               theirs, theirs_tag) != 0) {
            all_ct = 0;
            continue;
        }
        if (n > 0 && memcmp(ours, theirs, n) != 0)
            all_ct = 0;
        if (memcmp(ours + n, theirs_tag, LC_AEAD_TAG) != 0)
            all_tag = 0;
        if (lc_aead_open(&a, nonce, aad_len ? aad : NULL, aad_len, ours, out_len, back, sizeof back,
                         &back_len) != 0 || back_len != n || (n > 0 && memcmp(back, pt, n) != 0))
            all_round = 0;
    }
    snprintf(msg, sizeof msg, "chacha20-poly1305%s: ciphertext matches mbedtls at every size",
             aad_len ? " with aad" : "");
    ok(all_ct, msg);
    snprintf(msg, sizeof msg, "chacha20-poly1305%s: tag matches mbedtls at every size",
             aad_len ? " with aad" : "");
    ok(all_tag, msg);
    snprintf(msg, sizeof msg, "chacha20-poly1305%s: opens what it sealed", aad_len ? " with aad" : "");
    ok(all_round, msg);

    mbedtls_chachapoly_free(&m);
    lc_aead_free(&a);
}

/* The keystream drawn in pieces that straddle every boundary the buffer has — one byte, a block
 * less one, a block, a block and one, four blocks around — against mbedTLS's one-shot keystream from
 * the same counter; including a counter three blocks short of 2^32, where x/crypto stops filling a
 * whole buffer and makes only the blocks it needs. */
static void chacha_pieces(void)
{
    static const size_t    pieces[] = { 1, 63, 64, 65, 255, 256, 257, 3, 500, 191, 129 };
    static const uint32_t  counters[] = { 0u, 1u, 7u, 0xFFFFFFFDu };
    static uint8_t         zeros[4096], ours[4096], theirs[4096];
    uint8_t                key[32], nonce[12];
    int                    all = 1;

    for (unsigned i = 0; i < sizeof key; i++)
        key[i] = (uint8_t)(0xa0u ^ i);
    for (unsigned i = 0; i < sizeof nonce; i++)
        nonce[i] = (uint8_t)(0x0cu + 5u * i);

    for (unsigned c = 0; c < sizeof counters / sizeof counters[0]; c++) {
        size_t total = sizeof ours;
        if (counters[c] > 0xFFFFFF00u)
            total = (size_t)(0x100000000ULL - counters[c]) * 64u;
        if (mbedtls_chacha20_crypt(key, nonce, counters[c], total, zeros, theirs) != 0) {
            all = 0;
            continue;
        }
        lc_chacha s;
        lc_chacha_init(&s, key, nonce);
        if (lc_chacha_set_counter(&s, counters[c]) != 0) {
            all = 0;
            continue;
        }
        size_t off = 0;
        for (unsigned k = 0; off < total; k++) {
            size_t n = pieces[k % (sizeof pieces / sizeof pieces[0])];
            if (n > total - off)
                n = total - off;
            if (lc_chacha_xor(&s, ours + off, zeros + off, n) != 0) {
                all = 0;
                break;
            }
            off += n;
        }
        if (memcmp(ours, theirs, total) != 0) {
            printf("        counter %u: the keystream differs from mbedtls\n", (unsigned)counters[c]);
            all = 0;
        }
    }
    ok(all, "chacha20: keystream in odd pieces matches mbedtls from four counters, one near the end");

    /* The AEAD's own move: 32 bytes from block 0, then SetCounter(1) inside the buffer. */
    lc_chacha s;
    uint8_t   pk[32] = { 0 };
    lc_chacha_init(&s, key, nonce);
    int moved = lc_chacha_xor(&s, pk, pk, sizeof pk) == 0 && lc_chacha_set_counter(&s, 1u) == 0 &&
                lc_chacha_xor(&s, ours, zeros, 1000u) == 0 &&
                mbedtls_chacha20_crypt(key, nonce, 1u, 1000u, zeros, theirs) == 0 &&
                memcmp(ours, theirs, 1000u) == 0;
    ok(moved, "chacha20: moving the counter back to 1 inside the buffer continues the right stream");
    ok(lc_chacha_set_counter(&s, 0u) != 0, "chacha20: and moving it before what was output is refused");
}

/* Poly1305 written in odd pieces, against mbedTLS's one-shot MAC over the whole message. */
static void poly_pieces(void)
{
    static uint8_t msg[1100];
    uint8_t        key[32], ours[16], theirs[16];
    int            all = 1;

    for (unsigned i = 0; i < sizeof key; i++)
        key[i] = (uint8_t)(0xff - 7u * i);
    for (unsigned i = 0; i < sizeof msg; i++)
        msg[i] = (uint8_t)(i * 13u + 5u);

    for (size_t len = 0; len <= sizeof msg; len += (len < 70 ? 1u : 97u)) {
        lc_poly1305 p;
        lc_poly1305_init(&p, key);
        size_t off = 0, step = 1;
        while (off < len) {
            size_t n = step < len - off ? step : len - off;
            lc_poly1305_write(&p, msg + off, n);
            off += n;
            step = step * 3u % 37u + 1u;
        }
        lc_poly1305_sum(&p, ours);
        if (mbedtls_poly1305_mac(key, msg, len, theirs) != 0 || memcmp(ours, theirs, 16) != 0) {
            printf("        length %u: the tag differs from mbedtls\n", (unsigned)len);
            all = 0;
        }
    }
    ok(all, "poly1305: written in odd pieces, every length agrees with mbedtls");

    /* The key with every bit r's clamp removes set, which is where a carry the clamp was meant to
     * prevent would first show. */
    memset(key, 0xff, sizeof key);
    lc_poly1305 p;
    lc_poly1305_init(&p, key);
    lc_poly1305_write(&p, msg, sizeof msg);
    lc_poly1305_sum(&p, ours);
    ok(mbedtls_poly1305_mac(key, msg, sizeof msg, theirs) == 0 && memcmp(ours, theirs, 16) == 0,
       "poly1305: an all-ones key agrees too");
}

int main(void)
{
    printf("\nAES-GCM built from mbedTLS's AES-CTR and the reference's GHASH\n");
    /* Read by check-arm64, which must know which GHASH it just ran. */
    printf("GHASH: %s\n", lc_ghash_name());
    /* And its counter mode, taken under the same condition: on aarch64 "pmull" above means "aese". */
    printf("AES-CTR: %s\n", lc_aes_ctr_name());

    known_answer("aes-128-gcm", LC_AEAD_AES_128_GCM, 16u, tc2_ct, tc2_tag);
    known_answer("aes-256-gcm", LC_AEAD_AES_256_GCM, 32u, tc14_ct, tc14_tag);

    /* AAD and ciphertext are padded separately. Exercise both sides of the block
     * boundary against mbedTLS, not just full AAD blocks or our own round trip. */
    const size_t aad_sizes[] = {0u, 1u, 15u, 16u, 17u, 31u, 32u};
    for (unsigned i = 0; i < sizeof aad_sizes / sizeof aad_sizes[0]; i++) {
        against_reference("aes-128-gcm", LC_AEAD_AES_128_GCM, 128u, aad_sizes[i]);
        against_reference("aes-256-gcm", LC_AEAD_AES_256_GCM, 256u, aad_sizes[i]);
    }

    refuses_tampering("aes-128-gcm", LC_AEAD_AES_128_GCM);
    refuses_tampering("aes-256-gcm", LC_AEAD_AES_256_GCM);

    in_place("aes-128-gcm", LC_AEAD_AES_128_GCM);
    in_place("aes-256-gcm", LC_AEAD_AES_256_GCM);

    printf("\nChaCha20-Poly1305, x/crypto's, against the mbedTLS one it replaced\n");
    /* Read by check-arm64 too: an aarch64 run that did not take the NEON path tested nothing new. */
    printf("CHACHA: %s\n", lc_chacha_name());
    printf("POLY1305: %s\n", lc_poly1305_name());

    chacha_known_answer();
    chacha_against_reference(0);
    chacha_against_reference(32u);
    chacha_pieces();
    poly_pieces();
    refuses_tampering("chacha20-poly1305", LC_AEAD_CHACHA20_POLY1305);
    in_place("chacha20-poly1305", LC_AEAD_CHACHA20_POLY1305);

    printf("\n%s\n", failures == 0 ? "both AEADs agree with the reference"
                                   : "an AEAD DOES NOT agree with the reference");
    return failures == 0 ? 0 : 1;
}
