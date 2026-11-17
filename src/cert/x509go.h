/* Go's x509.ParseCertificate, as the QUIC plane's reference runs it: the verdict and the words.
 *
 * The Hysteria client oracle uses go1.26.6, and uTLS hands every certificate the node sends to
 * x509.ParseCertificate before anything else looks at it (verifyServerCertificate,
 * vendor/utls-hy/handshake_client.go:1125-1130). Under the Chrome parrot the error it returns is
 * the reason the connection closes with — "tls: failed to parse certificate from server: " and
 * then this — so what has to match is not only whether a certificate parses but where the parse
 * stopped. This is GOROOT/src/crypto/x509/parser.go of that toolchain, rule for rule and in its
 * order, and test/x509go holds it to what Go answered for 19 429 certificates (tools/x509read).
 *
 * Two answers depend on the machine, as they do for the reference: an INTEGER read into a Go int
 * or uint is 32 bits wide on mipsel and 64 on aarch64 (an RSA exponent, a path length, a version),
 * and a P-256 point is checked by assembly on aarch64 and by fiat on mipsel, which word the same
 * refusal differently. Both follow the machine this is compiled for.
 *
 * The REALITY plane's reference is Xray-core built with go1.27.1, whose parser reads a Name's
 * values with readASN1Any, knows ML-DSA keys, refuses an IPv4-mapped address in a SAN or an IP
 * name constraint, and holds a mailbox's domain to domainNameValid. lc_x509_go127_parse is that
 * parser, and it can also hand back what it read (cert/gocert.h) for Certificate.Verify
 * (cert/goverify.h). */
#ifndef LC_X509GO_H
#define LC_X509GO_H

#include "cert/gocert.h"
#include "core/gotext.h"

#include <stddef.h>
#include <stdint.h>

/* 0 when go1.26.6's x509.ParseCertificate parses `der`, with `*rsa_bits` the modulus's bit length
 * for an RSA key (N.BitLen()) and 0 for any other; -1 when it does not, with its error's text
 * appended to `err` when that is not NULL. */
int lc_x509_go_parse(const uint8_t *der, size_t len, size_t *rsa_bits, lc_obuf *err);

/* The same for go1.27.1's. With `out` not NULL the certificate is also filled in — its own copy of
 * `der` and all — for the caller to release with lc_gocert_free; on failure there is nothing to
 * release. */
int lc_x509_go127_parse(const uint8_t *der, size_t len, lc_gocert *out, size_t *rsa_bits,
                        lc_obuf *err);

/* Either toolchain's, `go127` choosing, with the fields — go1.26.6's for the QUIC plane's own
 * uses of a certificate (its key, for CertificateVerify). */
int lc_x509_go_parse_fields(int go127, const uint8_t *der, size_t len, lc_gocert *out, size_t *rsa_bits,
                            lc_obuf *err);

#endif
