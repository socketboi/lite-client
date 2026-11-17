/* Reading exactly as much of a certificate as REALITY needs.
 *
 * Two fields: the ed25519 public key, and the raw bytes of the signature field. The chain is never
 * validated, dates are never checked, names are never compared — and that is not a shortcut. A
 * REALITY server's certificate is not a certificate in the usual sense: its signature field holds
 * an HMAC over the public key, computed under a secret only the two ends share. Verifying it as a
 * signature would reject every genuine server and accept every impostor.
 *
 * That is why this is 200 lines of DER walking rather than a certificate library. Go's x509 is
 * 8300 lines; almost all of it exists to answer a question REALITY does not ask.
 *
 * The parser is strict everywhere it can be. Input arrives from the network before anything has
 * been authenticated, so every length is checked against what remains, and no field is read on the
 * assumption that an earlier one was well formed. */
#ifndef LC_CERT_H
#define LC_CERT_H

#include <stddef.h>
#include <stdint.h>

#define LC_ED25519_PUBLIC 32u
#define LC_CERT_SIGNATURE 64u /* ed25519, and also HMAC-SHA512 — which is the point */

typedef struct {
    const uint8_t *public_key; /* points into the certificate */
    size_t         public_key_len;
    const uint8_t *signature;
    size_t         signature_len;
} lc_cert;

/* Walks one DER certificate. Returns 0 when both fields were found, -1 on anything malformed or on
 * a public key that is not ed25519 — a REALITY server always uses ed25519, so anything else means
 * this is not the server we are talking to. */
int lc_cert_parse(const uint8_t *der, size_t len, lc_cert *out);

/* Walks the certificate_list of a TLS 1.3 Certificate message, one entry at a time.
 *
 * `*off` is the cursor and must start at zero; the header — request context and list length — is
 * read on that first call and skipped on every one after it. Each successful call points `der` at
 * one certificate, in the order the peer sent them, so the first is the leaf.
 *
 * Returns 0 for an entry, 1 when the list is exhausted, -1 on anything malformed. The distinction
 * between the last two matters to the only caller that needs the whole list: an empty list and a
 * truncated one are different refusals. */
int lc_cert_next_from_message(const uint8_t *body, size_t len, size_t *off,
                              const uint8_t **der, size_t *der_len);

/* Reads the leading certificate out of a TLS 1.3 Certificate message body, skipping the request
 * context and the per-entry extensions. Only the first entry is looked at: REALITY authenticates
 * the leaf and ignores the rest of the chain — the chain matters only when REALITY did NOT
 * authenticate, and cert/chain.h is where that case lives. */
int lc_cert_first_from_message(const uint8_t *body, size_t len,
                               const uint8_t **der, size_t *der_len);

/* The Certificate message as the reference hashes it: not the bytes the peer sent but what
 * certificateMsgTLS13.marshal makes again of what unmarshal kept, header included. `body` is a
 * message body lc_cert_next_from_message has walked to its end without a refusal. Returns the
 * length written to `out`, never more than `len` + 4, or 0 when `cap` is short or the SCTs
 * overflow the reference's builder. */
size_t lc_cert13_remarshal(const uint8_t *body, size_t len, uint8_t *out, size_t cap);

/* The certificate's SubjectPublicKeyInfo, whole — tag and length included, which is the form a key
 * parser expects to be handed.
 *
 * Separate from lc_cert_parse because that one answers a different question. It accepts only the
 * ed25519 shape REALITY generates, and refuses everything else on purpose: on that plane a
 * certificate of another kind is proof the server took us for a stranger. The QUIC plane pins an
 * ordinary node certificate — RSA or ECDSA — and has to verify a signature made with it, so it needs
 * the key whatever its type. The walk to the field is the same; only what may be found there
 * differs. */
int lc_cert_spki(const uint8_t *der, size_t len, const uint8_t **spki, size_t *spki_len);

/* Whether the leaf's public key is a kind the reference admits: RSA, ECDSA,
 * Ed25519 or, in Xray's TLS 1.3 reference, ML-DSA. Go runs this
 * switch on every parsed chain, before verification and regardless of InsecureSkipVerify
 * (vendor/utls/handshake_client.go:1239-1249), and answers anything else with
 * alertUnsupportedCertificate — so a prober serving, say, an Ed448 leaf reads 43 from every Go
 * client, and read a generic 42 from this one until 2026-09-03.
 *
 * Returns 1 for a classical kind, 2 for ML-DSA, 0 for a parsed-but-alien one (the caller's 43),
 * -1 when the SPKI
 * does not parse at all (the caller's existing decode/bad-certificate path — Go too alerts 42 from
 * ParseCertificate before this switch can run). Xray's current uTLS admits ML-DSA only in TLS 1.3;
 * the Hysteria reference still admits only result 1. Callers retain that distinction. */
int lc_cert_key_supported(const uint8_t *der, size_t len);

/* The size in bits of the leaf's RSA modulus, or 0 when the key is not RSA or does not parse. For
 * the reference's checkKeySize, which refuses a certificate carrying an RSA key over 8192 bits with
 * bad_certificate — after parsing it, and before anything is verified
 * (GOROOT/src/crypto/tls/handshake_client.go:1143-1148, go1.25.14). Read by hand from the SPKI
 * because mbedTLS will not parse such a key at all, and "does not parse" is a different answer. */
size_t lc_cert_rsa_bits(const uint8_t *der, size_t len);

/* Whether a TLS 1.3 signature scheme is one the certificate's key can sign with, as the standard
 * library decides it before it verifies anything: signatureSchemesForPublicKey
 * (GOROOT/src/crypto/tls/auth.go:149-203, go1.25.14) — Ed25519 for an Ed25519 key, the ECDSA scheme
 * of the key's own curve and no other, and the RSA-PSS schemes a modulus is large enough for (the
 * PKCS#1 v1.5 ones TLS 1.3 forbids before this is asked). 1 when it fits. uTLS asks no such
 * question and lets the verification fail instead, which is why only the QUIC plane calls this. */
int lc_cert_scheme_fits(const uint8_t *der, size_t len, uint16_t scheme);

#endif
