/* The check that happens when REALITY did NOT authenticate the node.
 *
 * A REALITY handshake has two outcomes and they are not success and failure. Either the leaf's
 * signature field is the HMAC only our key produces — the node — or it is a real certificate from
 * the site the node masquerades as, which means the node decided we were a stranger and is proxying
 * that site verbatim. The second case is ordinary web PKI, and the reference treats it as such:
 *
 *     opts := x509.VerifyOptions{ DNSName: c.ServerName, Intermediates: x509.NewCertPool() }
 *     for _, cert := range certs[1:] { opts.Intermediates.AddCert(cert) }
 *     if _, err := certs[0].Verify(opts); err != nil { return err }
 *                    (vendor/Xray-core/transport/internet/reality/reality.go:128-139)
 *
 * `Roots` is left nil, which in Go means the system store. So the fallback path of a REALITY client
 * is a full chain-and-hostname verification against the machine's certificate authorities, and a
 * failure there is returned from VerifyPeerCertificate — where crypto/tls answers it with
 * alertBadCertificate and abandons the handshake (vendor/utls/handshake_client.go:1251-1256).
 *
 * WITHOUT THIS, "the node did not know us" and "somebody is standing in the middle" are the same
 * event. Both give a completed handshake against a certificate we never examined, both set
 * reality_verified to zero, and both then get the spider — that is, this client answering an active
 * prober with a browser-shaped HTTP/2 request and a real browser's headers, over a TLS session the
 * prober terminated. The reference does not reach that path at all unless the certificate it was
 * given is genuinely valid for the name we asked for.
 *
 * WHAT THIS IS NOT: a second opinion on the REALITY path. When the HMAC matches, no chain is built
 * and no name is compared, because a REALITY leaf is generated on the spot, signed by nobody, and
 * valid for nothing — verifying it would reject every genuine node. See cert.h.
 *
 * The reference is Xray-core built with go1.27.1, so the parser and the verifier are that
 * toolchain's: cert/x509go.h reads every certificate and cert/goverify.h is Certificate.Verify, the
 * store included. mbedTLS did this until 2026-09-30 (DIVERGENCES.md G4), matching a Common Name
 * where there was no SAN and applying its own rules to name constraints, policies and key usages. */
#ifndef LC_CHAIN_H
#define LC_CHAIN_H

#include <stddef.h>
#include <stdint.h>

/* Verifies a TLS 1.3 Certificate message body as an ordinary web certificate chain.
 *
 * `body`/`len` are the message body — request context, certificate_list and all, exactly what the
 * handshake reader hands over. Every entry is parsed: the first is the leaf, the rest are offered as
 * intermediates, which is what `certs[1:]` does above.
 *
 * `hostname` is the name we put in SNI and the name the leaf must be valid for — the DNSName of
 * the options, which the reference fills from ServerName.
 *
 * `err`/`err_cap` receive the reason on failure, in Go's words. There is always a reason and it is
 * always worth printing: this refusal is the difference between a node that does not know us and
 * an attacker, and an operator staring at "handshake failed" has been told neither.
 *
 * Returns 0 when the chain and the name both verify, -1 otherwise. */
int lc_chain_verify(const uint8_t *body, size_t len, const char *hostname,
                    char *err, size_t err_cap);

/* Whether one certificate parses as go1.27.1's x509.ParseCertificate reads it — what uTLS runs on
 * every certificate a REALITY node relays (vendor/utls/handshake_client.go:1143-1154) — with
 * `*rsa_bits` (when not NULL) the bit length of an RSA key's modulus, 0 for any other key, for
 * uTLS's size check. 1 when it parses. */
int lc_x509_parses(const uint8_t *der, size_t len, size_t *rsa_bits);

/* Forgets the loaded root store. Called by test/chain, between its cases and at its end, so that a
 * leak checker's report there is about leaks; no program calls it, and none needs to — the store is
 * loaded at most once per process, as Go's sync.Once loads it, and is not secret. */
void lc_chain_forget_roots(void);

#endif
