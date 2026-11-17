/* Ed25519 signature verification, RFC 8032.
 *
 * WHY THIS EXISTS AT ALL, given that everything else asymmetric in this client is mbedTLS's:
 * mbedTLS 3.6 does not have Ed25519. Not partially — at all. Its curve enumeration
 * (vendor/mbedtls/include/mbedtls/ecp.h:103-130) has no twisted-Edwards entry, its PSA headers
 * declare PSA_ALG_PURE_EDDSA and PSA_ECC_FAMILY_TWISTED_EDWARDS as interface constants and no file
 * under vendor/mbedtls/library implements either, and PSA_WANT_ALG_PURE_EDDSA appears in no
 * configuration. The OID is present in oid.h and leads nowhere.
 *
 * AND THE REALITY PLANE CANNOT DO WITHOUT IT. A REALITY node holds an Ed25519 key, and a server
 * holding one has exactly one signature scheme available to it:
 *
 *     case ed25519.PublicKey:
 *         return []SignatureScheme{Ed25519}        (vendor/REALITY/auth.go:240-241)
 *
 * so its CertificateVerify is Ed25519 or nothing. The reference client checks that signature like
 * any other — verifyHandshakeSignature is called unconditionally in
 * vendor/utls/handshake_client_tls13.go:865-869, with no branch on InsecureSkipVerify and none on
 * what the VerifyPeerCertificate callback decided; REALITY's own callback runs earlier and in
 * ADDITION to it, not instead of it. Until this file existed, this client folded the message into
 * the transcript and checked nothing, so a peer could answer with any certificate and sixty-four
 * bytes of noise and be believed.
 *
 * The alternative considered and rejected was a rule about when the signature may be skipped — on
 * the argument that REALITY's HMAC over the certificate's public key already proves possession of
 * the node's static key. That argument is true and it is not what the reference does, which makes
 * it an invention; and an invention in the one place where this client decides whether it is
 * talking to its node is the worst place to have one.
 *
 * VERIFICATION ONLY. There is no signing here and no key generation: this client never holds an
 * Ed25519 private key. That halves the surface and removes the timing question entirely — every
 * value this code touches is public, so nothing here needs to run in constant time, and nothing
 * here pretends to.
 *
 * The field arithmetic is mbedTLS's bignum rather than a hand-written 2^25.5 representation. It is
 * slower — a verification is a few tens of milliseconds on a 24kc rather than a few — and it is
 * once per handshake, against a hand-written field implementation being several hundred lines of
 * the easiest code in the world to get subtly wrong. */
#ifndef LC_ED25519_H
#define LC_ED25519_H

#include <stddef.h>
#include <stdint.h>

#define LC_ED25519_PUBKEY 32u
#define LC_ED25519_SIG 64u

/* Returns 0 when `sig` is a valid Ed25519 signature by `pub` over `msg`, -1 otherwise — including
 * for a public key or an R that is not a point on the curve, and for an S at or above the group
 * order, which RFC 8032 §5.1.7 requires be refused rather than reduced. */
int lc_ed25519_verify(const uint8_t pub[LC_ED25519_PUBKEY], const uint8_t *msg, size_t msg_len,
                      const uint8_t sig[LC_ED25519_SIG]);

#endif
