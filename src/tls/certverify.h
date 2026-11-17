/* CertificateVerify: the proof that whoever is talking holds the private key of the certificate it
 * just sent.
 *
 * This lives here, and not beside the caller that needed it first, because BOTH planes need it and
 * only one of them had it. The Hysteria2 plane has verified this message since qtls.c was written;
 * the REALITY plane folded it into the transcript and did nothing else, so an active prober could
 * answer our hello with any certificate and a signature of pure noise and watch this client carry
 * on where an Xray one has already sent decrypt_error and stopped. One implementation, two callers,
 * because two implementations of a signature check is one implementation and one liability.
 *
 * What the two planes do with the ANSWER differs, and that difference is at the call sites rather
 * than here: on the QUIC plane a refused signature ends the handshake and the pin has nothing to
 * stand on; on the REALITY plane it ends the handshake only when REALITY itself did not
 * authenticate the node — see the note in src/tls/client.c for why those are not the same case. */
#ifndef LC_CERTVERIFY_H
#define LC_CERTVERIFY_H

#include "tls/hkdf.h"

#include <stddef.h>
#include <stdint.h>

/* Checks a CertificateVerify body against the leaf certificate that preceded it.
 *
 * `transcript_hash` is the hash up to and INCLUDING Certificate — this message is not in it.
 * `err`/`err_cap` receive a reason on failure, because every refusal here looks identical from
 * outside the process and the reason is the only thing that tells them apart.
 *
 * Returns 0 when the signature verifies, -1 otherwise. */
/* THE ALERTS RFC 8446 GIVES THESE REFUSALS, which is how the peer learns which one happened.
 *
 * A refusal is two things: a sentence for our own log, and a number the other end reads. This
 * verifier produced only the first, so every way a certificate can be wrong reached the transport
 * as one indistinguishable failure — and on the QUIC plane that became one CONNECTION_CLOSE code
 * for all of them. The numbers below are the ones Go sends at the equivalent points, so a node
 * looking at why we left sees what it would see from any other client:
 *
 *   an unsupported signature scheme      alertIllegalParameter   (vendor/utls/handshake_client_tls13.go:853-855)
 *   a signature that does not verify     alertDecryptError       (:808-811)
 *   a message that does not parse        alertUnexpectedMessage  (vendor/utls/conn.go:1185-1186)
 *   a certificate that is not there      alertUnexpectedMessage  (vendor/utls/handshake_client_tls13.go:788)
 *
 * — on the REALITY plane, whose reference is uTLS. The QUIC plane's is the standard library, which
 * answers a message that does not parse with alertDecodeError
 * (GOROOT/src/crypto/tls/conn.go:1185-1186) and a scheme its key cannot sign with — wrong type,
 * wrong curve, a modulus too short — with alertIllegalParameter before verifying, where uTLS
 * verifies and fails with alertDecryptError. The third row here said decode_error for both planes
 * until the two were told apart; see `stdlib` below.
 */
#include "tls/alert.h"

/* The largest RSA key this client will spend a verification on. The reference's own ceiling:
 * `const defaultMaxRSAKeySize = 8192` (vendor/utls/handshake_client.go:1122). See the refusal in
 * certverify.c for why a certificate is hostile input and what it costs on a one-core router. */
#define LC_MAX_RSA_BITS 8192u

/* `go`, when not NULL, gets uTLS's own error text for the refusal (tls/goerr.h), "" where the
 * reference has none; the QUIC plane closes with it under the Chrome parrot. */
/* `alert` may be NULL for a caller that only wants the sentence; when it is not, it is written on
 * every failure and left alone on success. `stdlib` says which reference the caller's plane has:
 * 0 for uTLS (the REALITY plane), 1 for the standard library's crypto/tls (the QUIC plane) — the two
 * answer a malformed message and a scheme that does not fit the key with different numbers. `go127`
 * says which toolchain's parser and crypto the plane's reference was built with: 1 for Xray-core
 * (go1.27.1), 0 for hysteria (go1.26.6) — the QUIC plane under the Chrome parrot is uTLS's rules and
 * go1.26.6's parser. */
int lc_cert_verify(const uint8_t *cert_der, size_t cert_der_len,
                   lc_hash hash, const uint8_t *transcript_hash,
                   const uint8_t *body, size_t body_len, int stdlib, int go127,
                   char *err, size_t err_cap, uint8_t *alert,
                   char *go, size_t go_cap);

/* THE SIGNATURE ON A TLS 1.2 ServerKeyExchange: whether ecdheKeyAgreement.processServerKeyExchange
 * would accept it (vendor/utls/key_agreement.go:337-372) — the scheme on the hello's list
 * (|hello_sigalgs|, the signature_algorithms extension body), one Go has a hash for, the kind of key the
 * suite names (|rsa_suite|), and the signature itself over client_random || server_random || params
 * as verifyHandshakeSignature checks it (vendor/utls/auth.go:23-78). Every way this fails is one
 * answer in the reference — illegal_parameter, from doFullHandshake (vendor/utls/handshake_client.go:
 * 735-741) — so it answers yes or no. |sig| is what follows the parameters: the scheme, then the
 * two-byte-prefixed signature. */
int lc_skx12_verify(const uint8_t *cert_der, size_t cert_der_len, const uint8_t *hello_sigalgs,
                    size_t hello_sigalgs_len, int rsa_suite, const uint8_t client_random[32],
                    const uint8_t server_random[32], const uint8_t *params, size_t params_len,
                    const uint8_t *sig, size_t sig_len);

#endif
