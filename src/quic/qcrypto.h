/* The ngtcp2 crypto backend (quic/qcrypto.c): what its contexts are, and the one way anything
 * outside ngtcp2 may take part in opening a packet — an answer computed ahead, which a callback uses
 * only when it was computed from exactly the inputs the callback is given (see lc_qhint). */
#ifndef LC_QCRYPTO_H
#define LC_QCRYPTO_H

#include "tls/aead.h"

#include <stddef.h>
#include <stdint.h>

#include <mbedtls/aes.h>
#include <ngtcp2/ngtcp2_crypto.h>

/* An AEAD context of this backend, what ngtcp2's aead_ctx->native_handle points to: the context the
 * record layer's lc_aead opens and seals with, and the key it was made from. The key is kept so
 * that a copy can be made on another thread — an mbedTLS context cannot be copied byte for byte, its
 * round keys sit at an offset chosen for the address they were first written at — and so that an
 * answer computed ahead can be checked against the key a callback is actually given. */
typedef struct {
    lc_aead     aead;
    lc_aead_alg alg;
    size_t      key_len;
    uint8_t     key[32];
} lc_qaead;

/* A header protection context, what cipher_ctx->native_handle points to: the raw key, and for AES
 * the key schedule — see ngtcp2_crypto_cipher_ctx_encrypt_init in qcrypto.c for why the schedule is
 * held. */
typedef struct {
    lc_aead_alg         alg;
    uint8_t             key[32];
    size_t              key_len;
    mbedtls_aes_context aes;
    int                 have_aes;
} lc_qhp;

int  lc_qaead_init(lc_qaead *a, lc_aead_alg alg, const uint8_t *key);
void lc_qaead_free(lc_qaead *a);
int  lc_qhp_init(lc_qhp *h, lc_aead_alg alg, const uint8_t *key);
void lc_qhp_free(lc_qhp *h);

/* RFC 9001 5.4: the five bytes of mask header protection XORs in, from the sixteen-byte sample. */
int lc_qhp_mask(lc_qhp *h, const uint8_t *sample, uint8_t mask[5]);

/* ngtcp2's context for a negotiated TLS 1.3 suite. */
int lc_qcrypto_ctx_from_suite(ngtcp2_crypto_ctx *ctx, uint16_t suite);

/* AN ANSWER COMPUTED AHEAD, for one packet, and the inputs it was computed from.
 *
 * ngtcp2 opens a packet through two callbacks, hp_mask and decrypt, and computes their inputs
 * itself: the sample's place, the key, the nonce from the key's IV and the packet number it decodes,
 * the header it has just unprotected. quic/rxopen.c computes the same on other threads before
 * ngtcp2 is called. A callback given a hint answers from it only when every input matches — the
 * very sample and ciphertext bytes (the same pointers into a buffer nobody writes meanwhile), the
 * same algorithm and key bytes, the same nonce and header — and otherwise computes as it always
 * does. Equal inputs to the same deterministic function are the whole argument: the answer is the
 * one the callback would have computed, byte for byte, including a tag that does not verify. */
typedef struct {
    int            have_mask;
    const uint8_t *sample;
    lc_aead_alg    hp_alg;
    const uint8_t *hp_key;
    size_t         hp_key_len;
    uint8_t        mask[5];

    int            have_open;
    const uint8_t *ct;
    size_t         ct_len;
    lc_aead_alg    alg;
    const uint8_t *key;
    size_t         key_len;
    uint8_t        nonce[LC_AEAD_NONCE];
    uint8_t        aad[32];
    size_t         aad_len;
    int            opened; /* lc_aead_open returned 0 */
    const uint8_t *plain;  /* ct_len - LC_AEAD_TAG bytes when opened */
} lc_qhint;

/* The hint this thread's next callbacks may answer from; NULL for none. Set around one
 * ngtcp2_conn_read_pkt and cleared after it. */
void lc_qcrypto_hint(const lc_qhint *h);

/* Of this thread's decrypts that had a hint set, how many it answered and how many were computed
 * after all. */
void lc_qcrypto_hint_counts(unsigned long long *answered, unsigned long long *missed);

#endif
