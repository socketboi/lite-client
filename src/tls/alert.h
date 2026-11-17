/* The TLS alerts this client sends, by the number RFC 8446 gives each — one table for every plane
 * and every layer that refuses something, because the number is what the peer reads and two tables
 * are two chances to disagree about it. Which refusal earns which number is decided where the
 * refusal is made, each with the reference's line beside it; this file only names them.
 *
 * They used to live in tls/certverify.h, where the first of them were needed; the record layer
 * needs them now as well, and including a signature verifier to learn that 20 is bad_record_mac
 * was the wrong way round. */
#ifndef LC_ALERT_H
#define LC_ALERT_H

#define LC_ALERT_UNEXPECTED_MESSAGE 10u
#define LC_ALERT_RECORD_OVERFLOW 22u
/* handshake_failure: a TLS 1.2 suite the hello did not offer, a renegotiation_info that is not empty,
 * a server Finished that does not verify (vendor/utls/handshake_client.go:664-668, :937-943,
 * :1040-1045). */
#define LC_ALERT_HANDSHAKE_FAILURE 40u
#define LC_ALERT_BAD_CERTIFICATE 42u
/* The leaf parsed, and its public key is a kind this client does not do: not RSA, not ECDSA, not
 * Ed25519. Its own number because Go gives it one — the type switch in verifyServerCertificate
 * answers exactly this with alertUnsupportedCertificate (vendor/utls/handshake_client.go:1239-1249)
 * — and a prober serving an Ed448 leaf tells Go clients apart from anything that says 42 here.
 *
 * ⚠️ FORTY-THREE, which this said was forty-eight from the day it was written: `alertUnsupportedCertificate
 * alert = 43` (vendor/utls/alert.go:38). Forty-eight is unknown_ca (:43), so the one refusal that
 * existed to match the reference byte for byte sent a different byte, and every assertion of it
 * compared against this same constant and agreed. */
#define LC_ALERT_UNSUPPORTED_CERTIFICATE 43u
#define LC_ALERT_ILLEGAL_PARAMETER 47u
#define LC_ALERT_DECODE_ERROR 50u
#define LC_ALERT_DECRYPT_ERROR 51u
#define LC_ALERT_PROTOCOL_VERSION 70u

#define LC_ALERT_INTERNAL_ERROR 80u
#define LC_ALERT_MISSING_EXTENSION 109u
#define LC_ALERT_UNSUPPORTED_EXTENSION 110u
/* The peer selected an application protocol we did not offer, or none. Its own number rather than a
 * generic refusal because RFC 8446 gives it one, and because on QUIC it reaches the node as
 * CONNECTION_CLOSE 0x0178 — a code that says what happened, where a bare close says nothing. */
#define LC_ALERT_NO_APPLICATION_PROTOCOL 120u
#define LC_ALERT_CLOSE_NOTIFY 0u
/* no_renegotiation, a warning like close_notify (vendor/utls/conn.go:849-855): what a TLS 1.2 client
 * with Renegotiation left at RenegotiateNever answers a HelloRequest with (vendor/utls/conn.go:1283-1284). */
#define LC_ALERT_NO_RENEGOTIATION 100u
/* A record that does not open: the tag did not verify, the record is too short to hold one, or its
 * outer type is not the one TLS 1.3 protects under — which is the same failure, since that byte is
 * part of what the tag covers. `alertBadRecordMAC` at every exit of the reference's decrypt
 * (vendor/utls/conn.go:342-444). */
#define LC_ALERT_BAD_RECORD_MAC 20u

#endif
