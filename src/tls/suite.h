/* The TLS 1.3 cipher-suite registry: the one place that maps a negotiated suite code to the AEAD,
 * hash and key length it implies.
 *
 * Two planes need this mapping — the TCP/REALITY handshake in tls/client.c and the QUIC crypto
 * context in quic/qcrypto.c — and keeping it in one function is the whole point. A second copy of
 * the table looks correct on its own and diverges silently: add a suite, or fix a key length, in one
 * plane and the other keeps the old behaviour, and the symptom is not a compile error but a
 * connection that decrypts nothing, surfacing much later as an unexplained packet drop. */
#ifndef LC_SUITE_H
#define LC_SUITE_H

#include <stddef.h>
#include <stdint.h>

#include "tls/aead.h"
#include "tls/hkdf.h"

/* Resolves one of the three TLS 1.3 suites (0x1301/0x1302/0x1303) into its AEAD, hash and key
 * length. Any other code returns non-zero and writes nothing — an unknown suite is refused, never
 * approximated. Each out pointer may be NULL when the caller has no use for that field. */
int lc_tls_suite_params(uint16_t suite, lc_aead_alg *aead, lc_hash *hash, size_t *key_len);

/* THE TLS 1.2 SUITES, for a server that answered the parrot's hello with TLS 1.2 (T3, closed
 * 29.09). uTLS's table, row for row — cipherSuites (vendor/utls/cipher_suites.go:151-174) and the two
 * utlsSupportedCipherSuites adds (vendor/utls/u_common.go:746-751) — except the five with 3DES or
 * RC4, which no fingerprint this client ships offers: `make check` refuses a table that does
 * (test/tls12), so the day one is added is the day they are written, not the day a server picks
 * one.
 *
 * mutualCipherSuite is this table and the hello together: a suite the server names must be in both
 * (vendor/utls/cipher_suites.go:643-659), and one that is not is handshake_failure. */
typedef enum {
    LC_KX_RSA,         /* rsaKeyAgreement: the premaster secret encrypted to the certificate's key */
    LC_KX_ECDHE_RSA,   /* ecdheKeyAgreement, the parameters signed with RSA */
    LC_KX_ECDHE_ECDSA, /* ecdheKeyAgreement, signed with ECDSA or Ed25519 (suiteECSign) */
} lc_tls12_kx;

typedef enum {
    LC_REC12_GCM,    /* aeadAESGCM: a four-byte implicit nonce and an explicit eight */
    LC_REC12_CHACHA, /* aeadChaCha20Poly1305: the IV exclusive-ored with the sequence, as 1.3 */
    LC_REC12_CBC,    /* cipherAES and an HMAC: MAC, then pad, then encrypt behind a random IV */
} lc_tls12_mode;

typedef struct {
    uint16_t      id;
    uint8_t       key_len; /* keyLen */
    uint8_t       mac_len; /* macLen: 20 for SHA-1, 32 for SHA-256, 0 for an AEAD */
    uint8_t       iv_len;  /* ivLen: 4 for GCM, 12 for ChaCha20, the block for CBC */
    lc_tls12_kx   kx;
    lc_tls12_mode mode;
    lc_hash       prf;     /* suiteSHA384 or not: the PRF's hash and the Finished transcript's */
    uint8_t       tls12_only; /* suiteTLS12 — always true of what this client can use */
} lc_tls12_suite;

/* The row for |id|, or NULL for a suite this build does not have. */
const lc_tls12_suite *lc_tls12_suite_by_id(uint16_t id);

/* Whether uTLS's table has |id| at all, 3DES and RC4 included: what separates a suite the server
 * should not have chosen from one this build did not write. */
int lc_tls12_suite_known_to_go(uint16_t id);

#endif
