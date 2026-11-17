/* What the QUIC plane's reference makes of a handshake message it did not expect.
 *
 * Go's crypto/tls hands every handshake message to unmarshalHandshakeMessage before the handshake
 * asks what type it is (GOROOT/src/crypto/tls/conn.go:1127-1193, go1.25.14 — the standard library
 * hysteria is built with). So a message out of place is refused with one of two numbers, decided
 * by the message and not by the place: unexpected_message (10) for a type the library has no
 * message for, decode_error (50) for one of its fifteen types that does not unmarshal, and 10 again
 * for one that does, at the type assertion that follows. A client that answers 10 to everything
 * out of place differs from it wherever a malformed message of a known type turns up — and on the
 * Initial level anybody who has seen the connection id can put one there.
 *
 * The REALITY plane's reference is uTLS, which answers 10 to every message that does not unmarshal
 * (vendor/utls/conn.go:1185-1186), so there the distinction does not arise; this is QUIC's. */
#ifndef LC_TLS_STDMSG_H
#define LC_TLS_STDMSG_H

#include <stddef.h>
#include <stdint.h>

/* The alert for `msg` — the whole message, four-byte header included, as the framing delivered it —
 * arriving where the handshake expected something else. `tls13` is the library's c.vers ==
 * VersionTLS13, which picks the TLS 1.3 or 1.2 form of NewSessionTicket, Certificate,
 * CertificateRequest and CertificateVerify: 0 until the first ServerHello or HelloRetryRequest has
 * been read, 1 after. */
uint8_t lc_std_misplaced_alert(const uint8_t *msg, size_t len, int tls13);

/* The two messages a TLS 1.3 client acts on after its handshake, read as their unmarshal reads them
 * — the same functions in uTLS and in the standard library (vendor/utls/handshake_messages.go and
 * GOROOT/src/crypto/tls/handshake_messages.go, compared line for line on 2026-09-24), which is why
 * the REALITY plane borrows them from here. 1 when the message reads; `update_requested` is its
 * one field. `msg` is the whole message, header included. */
int lc_std_ticket13_reads(const uint8_t *msg, size_t len);
int lc_std_key_update_reads(const uint8_t *msg, size_t len, int *update_requested);

#endif
