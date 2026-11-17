/* The ngtcp2 crypto backend, written against our own primitives.
 *
 * ngtcp2 ships backends for OpenSSL, BoringSSL, GnuTLS, wolfSSL and picotls, and OpenWrt packages
 * none of them — nor a wolfSSL built with QUIC support, which was checked rather than assumed: the
 * library in the feed exports eleven TLS 1.3 symbols and zero QUIC ones. Taking OpenSSL to fill the
 * gap would add 3.71 MB to a client that currently occupies 51 KB, which would end the reason this
 * project exists.
 *
 * So the backend is ours. That is less alarming than it sounds: ngtcp2's crypto/shared.c is
 * backend-independent and stays untouched, and the contract is seventeen functions, of which
 * thirteen are thin wrappers over code already written and tested here. Only the TLS handshake
 * itself (read_write_crypto_data, in qtls.c) is real work.
 *
 * native_handle is an opaque pointer that the backend defines, so the algorithm identifiers below
 * are stored directly in it rather than pointing at anything. */

#include "quic/qcrypto.h"

#include "core/rnd.h"
#include "tls/aead.h"
#include "tls/chacha.h"
#include "tls/hkdf.h"
#include "tls/suite.h"

#include <stdlib.h>
#include <string.h>

#include <mbedtls/aes.h>

#include <ngtcp2/ngtcp2_crypto.h>

/* For the AEAD usage limits of RFC 9001 section 6.6. They are ngtcp2's own constants, in the header
 * shared.c compiles against, and copying the four numbers here instead would mean this file quietly
 * disagreeing with the library the day upstream revises them. */
#include "shared.h"
#include "core/wipe.h"

/* native_handle carries our own algorithm identifier, offset by one so that a zeroed structure is
 * distinguishable from a valid selection. Storing lc_hash and lc_aead_alg themselves — rather than
 * a private numbering mapped back with a switch — means there is no mapping to get wrong and no
 * branch to guess on an unexpected value.
 *
 * Header protection needs no identifier of its own: in TLS 1.3 it follows from the AEAD, AES-ECB
 * for the two AES suites and ChaCha20 for the third, with the same key length. */
#define AS_HANDLE(v) ((void *)(uintptr_t)((v) + 1))
#define FROM_HANDLE(p) ((int)(uintptr_t)(p) - 1)

static lc_hash md_of(const ngtcp2_crypto_md *md)
{
    return (lc_hash)FROM_HANDLE(md->native_handle);
}

static lc_aead_alg aead_of(const ngtcp2_crypto_aead *aead)
{
    return (lc_aead_alg)FROM_HANDLE(aead->native_handle);
}

/* The limits on how long one key may be used, from RFC 9001 section 6.6. ngtcp2 enforces them and
 * initiates a key update on its own, so getting them right here is the whole of this client's part
 * in that; leaving them zero would read as "no limit" and quietly disable the mechanism.
 *
 * They sit on the context rather than on the AEAD because they depend on which is negotiated, and
 * the context is what a negotiation produces. */
static void ctx_limits(ngtcp2_crypto_ctx *ctx)
{
    if (aead_of(&ctx->aead) == LC_AEAD_CHACHA20_POLY1305) {
        ctx->max_encryption = NGTCP2_CRYPTO_MAX_ENCRYPTION_CHACHA20_POLY1305;
        ctx->max_decryption_failure = NGTCP2_CRYPTO_MAX_DECRYPTION_FAILURE_CHACHA20_POLY1305;
    } else {
        ctx->max_encryption = NGTCP2_CRYPTO_MAX_ENCRYPTION_AES_GCM;
        ctx->max_decryption_failure = NGTCP2_CRYPTO_MAX_DECRYPTION_FAILURE_AES_GCM;
    }
}

ngtcp2_crypto_aead *ngtcp2_crypto_aead_init(ngtcp2_crypto_aead *aead, void *aead_native_handle)
{
    aead->native_handle = aead_native_handle;
    aead->max_overhead = LC_AEAD_TAG;
    return aead;
}

/* ngtcp2_crypto_md_init belongs to shared.c, not to a backend, and defining it here would be a
 * duplicate symbol at link time. */

/* The Initial and Retry algorithms are fixed by RFC 9001 rather than negotiated: AES-128-GCM and
 * SHA-256, whatever the handshake later settles on. */
ngtcp2_crypto_aead *ngtcp2_crypto_aead_aes_128_gcm(ngtcp2_crypto_aead *aead)
{
    return ngtcp2_crypto_aead_init(aead, AS_HANDLE(LC_AEAD_AES_128_GCM));
}

ngtcp2_crypto_aead *ngtcp2_crypto_aead_retry(ngtcp2_crypto_aead *aead)
{
    return ngtcp2_crypto_aead_init(aead, AS_HANDLE(LC_AEAD_AES_128_GCM));
}

ngtcp2_crypto_md *ngtcp2_crypto_md_sha256(ngtcp2_crypto_md *md)
{
    md->native_handle = AS_HANDLE(LC_SHA256);
    return md;
}

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_initial(ngtcp2_crypto_ctx *ctx)
{
    memset(ctx, 0, sizeof *ctx);
    ctx->aead.native_handle = AS_HANDLE(LC_AEAD_AES_128_GCM);
    ctx->md.native_handle = AS_HANDLE(LC_SHA256);
    ctx->hp.native_handle = AS_HANDLE(LC_AEAD_AES_128_GCM);
    ctx->aead.max_overhead = LC_AEAD_TAG;
    /* Deliberately no usage limits: Initial keys are derived from a connection ID the whole network
     * can see, so counting their uses would protect nothing, and ngtcp2 expects zero here. */
    return ctx;
}

size_t ngtcp2_crypto_md_hashlen(const ngtcp2_crypto_md *md)
{
    return lc_hash_len(md_of(md));
}

size_t ngtcp2_crypto_aead_keylen(const ngtcp2_crypto_aead *aead)
{
    return lc_aead_key_len(aead_of(aead));
}

size_t ngtcp2_crypto_aead_noncelen(const ngtcp2_crypto_aead *aead)
{
    (void)aead;
    return LC_AEAD_NONCE;
}

int lc_qaead_init(lc_qaead *a, lc_aead_alg alg, const uint8_t *key)
{
    memset(a, 0, sizeof *a);
    a->alg = alg;
    a->key_len = lc_aead_key_len(alg);
    if (a->key_len == 0u || a->key_len > sizeof a->key)
        return -1;
    memcpy(a->key, key, a->key_len);
    if (lc_aead_init(&a->aead, alg, key) != 0) {
        lc_qaead_free(a);
        return -1;
    }
    return 0;
}

void lc_qaead_free(lc_qaead *a)
{
    lc_aead_free(&a->aead);
    lc_wipe(a, sizeof *a);
}

/* The AEAD context is allocated because ngtcp2 owns its lifetime and frees it through the callback
 * below — a fixed pool here would have to guess how many connections exist, which is the caller's
 * business and not ours. */
static int aead_ctx_init(ngtcp2_crypto_aead_ctx *aead_ctx, const ngtcp2_crypto_aead *aead,
                         const uint8_t *key)
{
    lc_qaead *a = calloc(1, sizeof *a);
    if (a == NULL)
        return -1;
    if (lc_qaead_init(a, aead_of(aead), key) != 0) {
        free(a);
        return -1;
    }
    aead_ctx->native_handle = a;
    return 0;
}

int ngtcp2_crypto_aead_ctx_encrypt_init(ngtcp2_crypto_aead_ctx *aead_ctx,
                                        const ngtcp2_crypto_aead *aead,
                                        const uint8_t *key, size_t noncelen)
{
    (void)noncelen;
    return aead_ctx_init(aead_ctx, aead, key);
}

int ngtcp2_crypto_aead_ctx_decrypt_init(ngtcp2_crypto_aead_ctx *aead_ctx,
                                        const ngtcp2_crypto_aead *aead,
                                        const uint8_t *key, size_t noncelen)
{
    /* AEAD contexts are directionless here: seal and open are separate calls on the same key. */
    (void)noncelen;
    return aead_ctx_init(aead_ctx, aead, key);
}

void ngtcp2_crypto_aead_ctx_free(ngtcp2_crypto_aead_ctx *aead_ctx)
{
    if (aead_ctx->native_handle == NULL)
        return;
    lc_qaead_free(aead_ctx->native_handle);
    free(aead_ctx->native_handle);
    aead_ctx->native_handle = NULL;
}

/* Header protection keeps the raw key, and for AES also the expanded key schedule.
 *
 * THIS IS WHAT THE REFERENCE BACKENDS DO, which is the first reason and was found last. ngtcp2's
 * own quictls backend builds an EVP_CIPHER_CTX in cipher_ctx_encrypt_init, installs the key there
 * once, fails the init if the key is refused, and stores the context in native_handle
 * (vendor/ngtcp2/crypto/quictls/quictls.c:463-481); its hp_mask then does nothing but
 * EVP_EncryptUpdate on that stored context (:785). The wolfSSL backend has the same shape
 * (vendor/ngtcp2/crypto/wolfssl/wolfssl.c:216-229). Every backend ngtcp2 ships installs the key
 * once per key phase, because that is when the key arrives and it does not change afterwards.
 *
 * So rebuilding the schedule per call was not a local trade-off, it was a deviation from all of
 * them, and the comment that stood here justified it on its own terms: that a single-block
 * operation does not pay for a held context. That is true of the CONTEXT and false of the
 * SCHEDULE — ten rounds of key expansion for AES-128, fourteen for AES-256, identical for every
 * packet. On a box with no AES instructions it is not free either: MT7621 expands in software, and
 * header protection runs once per packet in each direction. But the cycles are the second reason.
 * Written the other way round, this reads as an optimisation somebody invented, and the next
 * person weighing it has to re-derive whether it is safe instead of reading one line of quictls.c.
 *
 * ChaCha20 keeps taking the raw key, and so does the reference: quictls re-runs EVP_EncryptInit_ex
 * per call for NID_chacha20 (vendor/ngtcp2/crypto/quictls/quictls.c:791), because the counter and
 * nonce come out of the sample and differ for every packet. There is nothing to precompute, here
 * or there. */
int lc_qhp_init(lc_qhp *c, lc_aead_alg alg, const uint8_t *key)
{
    memset(c, 0, sizeof *c);
    /* The header protection key is as long as the AEAD key in every TLS 1.3 suite, so the length
     * comes from the same place rather than from a second table that could drift from it. */
    c->alg = alg;
    c->key_len = lc_aead_key_len(c->alg);
    if (c->key_len == 0u || c->key_len > sizeof c->key)
        return -1;
    memcpy(c->key, key, c->key_len);

    /* Expand once, here. A key that mbedtls refuses is refused now rather than at the first packet:
     * hp_mask has no way to report "this context was never usable" apart from failing every call it
     * is given, which reads as a connection that protects no headers instead of one that never
     * started. */
    if (c->alg != LC_AEAD_CHACHA20_POLY1305) {
        mbedtls_aes_init(&c->aes);
        if (mbedtls_aes_setkey_enc(&c->aes, c->key, (unsigned)(c->key_len * 8u)) != 0) {
            mbedtls_aes_free(&c->aes);
            lc_wipe(c, sizeof *c);
            return -1;
        }
        c->have_aes = 1;
    }
    return 0;
}

/* The key is wiped rather than merely freed: it protects packet numbers for the whole connection
 * and lives in memory that is about to be reused. The round keys are as good as the key for anyone
 * reading this memory, so mbedtls_aes_free zeroizes them first and the wipe then covers the struct
 * whole — including the raw key, which mbedtls knows nothing about. */
void lc_qhp_free(lc_qhp *c)
{
    if (c->have_aes)
        mbedtls_aes_free(&c->aes);
    lc_wipe(c, sizeof *c);
}

int ngtcp2_crypto_cipher_ctx_encrypt_init(ngtcp2_crypto_cipher_ctx *cipher_ctx,
                                          const ngtcp2_crypto_cipher *cipher,
                                          const uint8_t *key)
{
    lc_qhp *c = calloc(1, sizeof *c);
    if (c == NULL)
        return -1;
    if (lc_qhp_init(c, (lc_aead_alg)FROM_HANDLE(cipher->native_handle), key) != 0) {
        free(c);
        return -1;
    }
    cipher_ctx->native_handle = c;
    return 0;
}

void ngtcp2_crypto_cipher_ctx_free(ngtcp2_crypto_cipher_ctx *cipher_ctx)
{
    if (cipher_ctx->native_handle == NULL)
        return;
    lc_qhp_free(cipher_ctx->native_handle);
    free(cipher_ctx->native_handle);
    cipher_ctx->native_handle = NULL;
}

/* The hint for this thread's next callbacks — see lc_qhint in quic/qcrypto.h. Per thread, because
 * the threads that compute hints call the same primitives and must never see one. */
static __thread const lc_qhint *hint;

/* Of the decrypts called with a hint set, how many it answered: the one number that says the
 * threads are doing the work rather than every packet being opened twice. Counted on the thread
 * that sets hints, which is the only one that ever sees one. */
static __thread unsigned long long hint_answered, hint_missed;

void lc_qcrypto_hint(const lc_qhint *h)
{
    hint = h;
}

void lc_qcrypto_hint_counts(unsigned long long *answered, unsigned long long *missed)
{
    *answered = hint_answered;
    *missed = hint_missed;
}

static int same_key(lc_aead_alg alg, const uint8_t *key, size_t key_len, lc_aead_alg halg,
                    const uint8_t *hkey, size_t hkey_len)
{
    return alg == halg && key_len == hkey_len && memcmp(key, hkey, key_len) == 0;
}

int ngtcp2_crypto_hkdf_extract(uint8_t *dest, const ngtcp2_crypto_md *md,
                               const uint8_t *secret, size_t secretlen,
                               const uint8_t *salt, size_t saltlen)
{
    return lc_hkdf_extract(md_of(md), salt, saltlen, secret, secretlen, dest);
}

int ngtcp2_crypto_hkdf_expand(uint8_t *dest, size_t destlen, const ngtcp2_crypto_md *md,
                              const uint8_t *secret, size_t secretlen,
                              const uint8_t *info, size_t infolen)
{
    (void)secretlen; /* the PRK is always one digest long */
    return lc_hkdf_expand(md_of(md), secret, info, infolen, dest, destlen);
}

int ngtcp2_crypto_hkdf(uint8_t *dest, size_t destlen, const ngtcp2_crypto_md *md,
                       const uint8_t *secret, size_t secretlen,
                       const uint8_t *salt, size_t saltlen,
                       const uint8_t *info, size_t infolen)
{
    uint8_t prk[LC_HASH_MAX];
    if (lc_hkdf_extract(md_of(md), salt, saltlen, secret, secretlen, prk) != 0)
        return -1;
    int rc = lc_hkdf_expand(md_of(md), prk, info, infolen, dest, destlen);
    lc_wipe(prk, sizeof prk);
    return rc;
}

int ngtcp2_crypto_encrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                          const ngtcp2_crypto_aead_ctx *aead_ctx,
                          const uint8_t *plaintext, size_t plaintextlen,
                          const uint8_t *nonce, size_t noncelen,
                          const uint8_t *aad, size_t aadlen)
{
    (void)aead;
    (void)noncelen;
    size_t    written = 0;
    lc_qaead *a = aead_ctx->native_handle;
    return lc_aead_seal(&a->aead, nonce, aad, aadlen, plaintext, plaintextlen, dest,
                        plaintextlen + LC_AEAD_TAG, &written);
}

int ngtcp2_crypto_decrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                          const ngtcp2_crypto_aead_ctx *aead_ctx,
                          const uint8_t *ciphertext, size_t ciphertextlen,
                          const uint8_t *nonce, size_t noncelen,
                          const uint8_t *aad, size_t aadlen)
{
    (void)aead;
    if (ciphertextlen < LC_AEAD_TAG)
        return -1;
    lc_qaead *a = aead_ctx->native_handle;

    /* Answered from the hint only when it was computed from these very inputs: see lc_qhint. What
     * it answers is what lc_aead_open below would have — the plaintext, or on a tag that does not
     * verify, -1 with the output wiped as lc_aead_open wipes it. */
    const lc_qhint *h = hint;
    if (h != NULL && h->have_open && ciphertext == h->ct && ciphertextlen == h->ct_len &&
        noncelen == LC_AEAD_NONCE && memcmp(nonce, h->nonce, LC_AEAD_NONCE) == 0 &&
        aadlen == h->aad_len && memcmp(aad, h->aad, aadlen) == 0 &&
        same_key(a->alg, a->key, a->key_len, h->alg, h->key, h->key_len)) {
        hint_answered++;
        if (!h->opened) {
            lc_wipe(dest, ciphertextlen - LC_AEAD_TAG);
            return -1;
        }
        memcpy(dest, h->plain, ciphertextlen - LC_AEAD_TAG);
        return 0;
    }

    if (h != NULL)
        hint_missed++;
    size_t written = 0;
    return lc_aead_open(&a->aead, nonce, aad, aadlen, ciphertext, ciphertextlen, dest,
                        ciphertextlen - LC_AEAD_TAG, &written);
}

/* RFC 9001 section 5.4.3 and 5.4.4: the mask is either one AES-ECB block over the sample, or the
 * first five bytes of a ChaCha20 keystream whose counter and nonce come from the sample. Five bytes
 * are used — one for the header byte, four for the packet number. */
int ngtcp2_crypto_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                          const ngtcp2_crypto_cipher_ctx *hp_ctx_in, const uint8_t *sample)
{
    (void)hp;
    lc_qhp *c = hp_ctx_in->native_handle;
    if (c == NULL)
        return -1;

    /* From the hint only for the very sample bytes and the same key — see lc_qhint. */
    const lc_qhint *h = hint;
    if (h != NULL && h->have_mask && sample == h->sample &&
        same_key(c->alg, c->key, c->key_len, h->hp_alg, h->hp_key, h->hp_key_len)) {
        memcpy(dest, h->mask, sizeof h->mask);
        return 0;
    }
    return lc_qhp_mask(c, sample, dest);
}

int lc_qhp_mask(lc_qhp *c, const uint8_t *sample, uint8_t dest[5])
{
    if (c->alg == LC_AEAD_CHACHA20_POLY1305) {
        /* quic-go's own three calls: NewUnauthenticatedCipher(key, sample[4:]), SetCounter with the
         * first four bytes, XORKeyStream over the mask (vendor/quic-go/internal/handshake/
         * header_protector.go:116-121) — through the same port of x/crypto's chacha20 the AEAD uses. */
        uint32_t counter = (uint32_t)sample[0] | (uint32_t)sample[1] << 8 |
                           (uint32_t)sample[2] << 16 | (uint32_t)sample[3] << 24;
        lc_chacha s;
        uint8_t   mask[5] = { 0 };
        int       rc = -1;
        lc_chacha_init(&s, c->key, sample + 4);
        if (lc_chacha_set_counter(&s, counter) == 0 && lc_chacha_xor(&s, mask, mask, sizeof mask) == 0) {
            memcpy(dest, mask, sizeof mask);
            rc = 0;
        }
        lc_wipe(&s, sizeof s);
        return rc;
    }

    if (!c->have_aes)
        return -1;

    int     rc = -1;
    uint8_t block[16];
    if (mbedtls_aes_crypt_ecb(&c->aes, MBEDTLS_AES_ENCRYPT, sample, block) == 0) {
        memcpy(dest, block, 5);
        rc = 0;
    }
    lc_wipe(block, sizeof block);
    return rc;
}

int ngtcp2_crypto_random(uint8_t *data, size_t datalen)
{
    return lc_rnd(data, datalen);
}

/* The three TLS 1.3 suites, keyed by what the handshake negotiated. A suite outside them is
 * refused rather than approximated: picking a default here would produce a context that decrypts
 * nothing, and the failure would surface much later as an unexplained packet drop. */
int lc_qcrypto_ctx_from_suite(ngtcp2_crypto_ctx *ctx, uint16_t suite)
{
    lc_aead_alg aead;
    lc_hash     md;

    if (lc_tls_suite_params(suite, &aead, &md, NULL) != 0)
        return -1;

    memset(ctx, 0, sizeof *ctx);
    ctx->aead.native_handle = AS_HANDLE(aead);
    ctx->md.native_handle = AS_HANDLE(md);
    ctx->hp.native_handle = AS_HANDLE(aead);
    ctx->aead.max_overhead = LC_AEAD_TAG;
    ctx_limits(ctx);
    return 0;
}
