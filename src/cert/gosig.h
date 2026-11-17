/* Go's x509 checkSignature, the signature half of Certificate.CheckSignatureFrom and so of
 * Certificate.Verify: the verdict and the words.
 *
 * The REALITY plane's reference is Xray-core built with go1.27.1, and when a node relays a real
 * site's certificates its client verifies them as a web chain — certs[0].Verify(opts) — and every
 * link of that chain is a call to checkSignature(algo, signed, signature, parentKey, false)
 * (GOROOT/src/crypto/x509/x509.go:1018). This is that function for go1.27.1 and everything under
 * it — crypto/rsa and crypto/internal/fips140/rsa, crypto/ecdsa and crypto/internal/fips140/ecdsa,
 * crypto/ed25519 and crypto/internal/fips140/ed25519 — rule for rule and in its order, with the
 * error each refusal returns. test/gosig holds it to what Go answered for every vector
 * tools/sigvec wrote down.
 *
 * ML-DSA is dispatched here, as checkSignature dispatches it, and verified by the ML-DSA port:
 * see lc_mldsa_verify in gosig.c.
 *
 * Arithmetic is mbedTLS's bignum and message digests; nothing here asks mbedTLS for a curve, an
 * RSA context or a PK context, because the router's own mbedTLS need not have P-224 or P-521 and
 * its RSA and PSS checks are not Go's. */
#ifndef LC_GOSIG_H
#define LC_GOSIG_H

#include "core/gotext.h"

#include <stddef.h>
#include <stdint.h>

/* x509.SignatureAlgorithm, Go's numbering (GOROOT/src/crypto/x509/x509.go:222-246). */
enum {
    LC_GO_SIG_UNKNOWN = 0,
    LC_GO_SIG_MD2_RSA,
    LC_GO_SIG_MD5_RSA,
    LC_GO_SIG_SHA1_RSA,
    LC_GO_SIG_SHA256_RSA,
    LC_GO_SIG_SHA384_RSA,
    LC_GO_SIG_SHA512_RSA,
    LC_GO_SIG_DSA_SHA1,
    LC_GO_SIG_DSA_SHA256,
    LC_GO_SIG_ECDSA_SHA1,
    LC_GO_SIG_ECDSA_SHA256,
    LC_GO_SIG_ECDSA_SHA384,
    LC_GO_SIG_ECDSA_SHA512,
    LC_GO_SIG_SHA256_RSAPSS,
    LC_GO_SIG_SHA384_RSAPSS,
    LC_GO_SIG_SHA512_RSAPSS,
    LC_GO_SIG_PURE_ED25519,
    LC_GO_SIG_MLDSA44,
    LC_GO_SIG_MLDSA65,
    LC_GO_SIG_MLDSA87,
};

/* What the parent's PublicKey holds — its dynamic type, which is what checkSignature switches on
 * (x509.go:1089-1140). Numbered as x509.PublicKeyAlgorithm is (x509.go:277-284), because
 * ParseCertificate makes exactly one type per algorithm and none (a nil PublicKey) for an unknown
 * one, so a certificate's PublicKeyAlgorithm can be passed as it is. */
enum {
    LC_GOSIG_KEY_NONE = 0, /* nil */
    LC_GOSIG_KEY_RSA,      /* *rsa.PublicKey */
    LC_GOSIG_KEY_DSA,      /* *dsa.PublicKey, which nothing here verifies with */
    LC_GOSIG_KEY_ECDSA,    /* *ecdsa.PublicKey */
    LC_GOSIG_KEY_ED25519,  /* ed25519.PublicKey */
    LC_GOSIG_KEY_MLDSA,    /* *mldsa.PublicKey */
};

/* The curves namedCurveFromOID knows, and the ML-DSA parameter sets — numbered as cert/gocert.h
 * numbers them. */
enum { LC_GOSIG_P224 = 1, LC_GOSIG_P256, LC_GOSIG_P384, LC_GOSIG_P521 };
enum { LC_GOSIG_MLDSA44 = 1, LC_GOSIG_MLDSA65, LC_GOSIG_MLDSA87 };

typedef struct {
    int kind; /* LC_GOSIG_KEY_* */

    /* RSA: N as big-endian bytes (leading zeros allowed; NULL is a nil N) and E as the Go int. */
    const uint8_t *rsa_n;
    size_t         rsa_n_len;
    int64_t        rsa_e;

    /* ECDSA: the curve and the point as 04 || X || Y, each coordinate the curve's width. */
    int            curve;
    const uint8_t *point;
    size_t         point_len;

    /* Ed25519: the 32 bytes of the key, which ParseCertificate has checked for length only. */
    uint8_t ed25519[32];

    /* ML-DSA: the parameter set and the encoded key. */
    int            mldsa;
    const uint8_t *mldsa_pk;
    size_t         mldsa_pk_len;
} lc_gopubkey;

/* checkSignature(sig_alg, signed_, sig, pub, allowSHA1=false). 0 for a nil error; -1 for an
 * error, with its text appended to `err` when that is not NULL; -2 when this could not answer —
 * memory ran out, or mbedTLS refused an operation: a product of two numbers the width of an RSA
 * modulus must fit MBEDTLS_MPI_MAX_LIMBS (10 000 limbs, so about 160 000 bits of modulus with 32-bit
 * limbs), where Go has no limit. `pub` NULL is a nil key. */
int lc_go_check_signature(int sig_alg, const uint8_t *signed_, size_t signed_len, const uint8_t *sig,
                          size_t sig_len, const lc_gopubkey *pub, lc_obuf *err);

/* SignatureAlgorithm.String() and PublicKeyAlgorithm.String() (x509.go:266-273, 294-299): the
 * name, or the number in decimal written into `buf` when it has none. */
const char *lc_go_sig_alg_name(int sig_alg, char buf[24]);
const char *lc_go_pk_alg_name(int pk_alg, char buf[24]);

/* THE HANDSHAKE'S OWN SIGNATURES, as uTLS's verifyHandshakeSignature makes them
 * (vendor/utls/auth.go:23-78; vendor/utls-hy/auth.go the same): rsa.VerifyPKCS1v15, rsa.VerifyPSS
 * with PSSSaltLengthEqualsHash, and ecdsa.VerifyASN1 — the same code as checkSignature's above,
 * which is go1.26.6's and go1.27.1's alike on this path (only an empty digest, which TLS never
 * hands over, is refused by one and not the other). TLS 1.2 adds SHA-1 (rsa_pkcs1_sha1,
 * ecdsa_sha1). `hashed` is the digest; `hash` names it. */
enum { LC_GOSIG_HASH_SHA1 = 2, LC_GOSIG_HASH_SHA256, LC_GOSIG_HASH_SHA384, LC_GOSIG_HASH_SHA512 };

/* 0 for nil, -1 with the crypto/rsa error's words, -2 when this could not answer. */
int lc_go_rsa_verify(int pss, int hash, const uint8_t *hashed, size_t hlen, const uint8_t *sig,
                     size_t sig_len, const lc_gopubkey *pub, lc_obuf *err);

/* 1 true, 0 false, -2 could not answer. */
int lc_go_ecdsa_verify_asn1(const lc_gopubkey *pub, const uint8_t *hash, size_t hlen, const uint8_t *sig,
                            size_t sig_len);

/* The key of a certificate the Go parser read (cert/gocert.h), as the type switch sees it — kind
 * NONE for a nil PublicKey — and %T of it. The key's bytes stay the certificate's. */
struct lc_gocert_s;
void        lc_gopubkey_of(const struct lc_gocert_s *c, lc_gopubkey *k);
const char *lc_gopubkey_type(const lc_gopubkey *k);

#endif
