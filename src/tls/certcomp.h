/* RFC 8879: the server's certificate, compressed.
 *
 * A client that sends compress_certificate is inviting the server to answer its Certificate with a
 * CompressedCertificate instead, and a server behind Cloudflare takes that invitation every time.
 * Measured on 2026-08-18: of seven public sites, www.example.com, www.cloudflare.com and discord.com
 * compressed and every one of them chose brotli; google, avito, kinopoisk and microsoft did not
 * compress at all. On the authenticated REALITY path it never happens — the peer is Xray and Go's
 * TLS server implements no compression — so this is entirely about the OTHER path, the one where the
 * node took us for a stranger and is relaying the site it masquerades as.
 *
 * ALL THREE, AS THE CAPTURE HAS THEM — zlib, brotli, zstd, in that order, which is what
 * HelloFirefox_148 puts on the wire (vendor/utls/u_parrots.go:1650-1654) and therefore what the
 * table carries.
 *
 * ⚠️ AND THE LIST IS A CAPABILITY, NOT A WISH. RFC 8879 §4 is explicit that a client MUST be able to
 * decompress whatever it advertised, and the choice is not ours to steer: the server picks from our
 * list by ITS preference, not by our order. That is measured, not assumed — with zlib written FIRST,
 * every one of the three compressing sites in the 2026-08-18 survey answered in brotli. So a list
 * with an algorithm we cannot open is a handshake we abort on the server's ordinary reply, which is
 * louder on the wire than any byte count: a client that asks for a thing and then dies on receiving
 * it is unique.
 *
 * That is why this file spent two weeks advertising zlib alone. The list was trimmed to what the
 * client could honour, which was correct and was never the goal — the goal is the reference's hello,
 * and the way to it is the reference's decoders. Both are now built in (see BROTLI_SRC and ZSTD_SRC
 * in the Makefile): decompression only, 243 KB on mipsel, of which 122 KB is brotli's static
 * dictionary. The old note here claimed that dictionary was "larger than this entire program"; it is
 * not, and was not — the program is 645 KB — and a wrong number is a bad reason even for a decision
 * that was otherwise right.
 *
 * WHAT IT BUYS is one path and one only: the masquerade, where the node took us for a stranger and
 * relays the site it fronts. On the authenticated REALITY path the peer is Xray, and Go's TLS server
 * implements no compression at all, so a CompressedCertificate never arrives. On the Hysteria2 plane
 * the extension is not sent at all — quic-go rides crypto/tls, which has no RFC 8879 either, so its
 * hello has no such extension and neither does ours.
 *
 * The bytes below are the extension body as it goes on the wire, and they are used TWICE: src/fp/
 * hello.c emits them, and lc_certcomp_open refuses anything not in them. One definition, so the
 * thing we claim and the thing we can do cannot drift apart. */
#ifndef LC_CERTCOMP_H
#define LC_CERTCOMP_H

#include <stddef.h>
#include <stdint.h>

#define LC_EXT_COMPRESS_CERTIFICATE 27u
#define LC_CERTCOMP_ZLIB 1u
#define LC_CERTCOMP_BROTLI 2u
#define LC_CERTCOMP_ZSTD 3u

/* `CertificateCompressionAlgorithm algorithms<2..2^8-2>` — a length in BYTES, then the identifiers.
 * Spelled as a macro rather than an extern so that each user gets a function-local constant: no
 * link edge from the hello builder to the decompressor, which would drag three decoders into tools
 * that never complete a handshake. */
#define LC_CERTCOMP_EXT_BODY                            \
    {                                                   \
        0x06u, 0x00u, 0x01u, 0x00u, 0x02u, 0x00u, 0x03u \
    }
#define LC_CERTCOMP_EXT_BODY_LEN 7u

/* Opens one CompressedCertificate message body — `algorithm(2) | uncompressed_length(3) |
 * compressed<3>` — into the body of the Certificate message it stands for.
 *
 * `out` receives the certificate_list and its request context, exactly what the handshake reader
 * would have been handed had the server not compressed: the four-byte handshake header is NOT
 * written, because the caller works on bodies and the header it would reconstruct is one it already
 * knows. `out_cap` is the buffer's size; the handshake makes it the declared length, as the
 * reference allocates it (tls/client.c), so a length over it means only a caller that could not get
 * the memory — the peer's claim is bounded by the three bytes it is written in, as it is there.
 *
 * `offered` is the body of the compress_certificate extension our own hello carried — a length
 * byte, then the algorithms — or NULL when it carried none; the algorithm is checked against it,
 * as the reference checks against what it sent.
 *
 * Returns 0 on success, with exactly the declared length in `out`, or the alert the reference
 * sends, and `err` says why: unexpected_message for a header that does not read — too short, or a
 * compressed run longer than the message (vendor/utls/u_handshake_messages.go:43-54) — and
 * bad_certificate for an algorithm we never offered, a length over `out_cap`, or a stream that the
 * reference's ONE Read of the declared length would not fill without an error
 * (vendor/utls/u_handshake_client.go:66-139). What that one Read does not reach — the rest of the
 * stream, often its checksum, its end — is not looked at, by it or by this; the .c says what each
 * algorithm's reader hands over in one call. internal_error when memory runs out.
 *
 * `go`, when not NULL, receives the error decompressCert returned for a brotli stream it refused,
 * as utlsReadServerCertificate wraps it (vendor/utls-hy/u_handshake_client.go:35-38) — the words
 * the Hysteria2 plane closes with under the Chrome parrot, whose hello offers brotli alone — and ""
 * for anything else: the header and the algorithm are the caller's to name, and zlib and zstd are
 * never offered there. */
int lc_certcomp_open(const uint8_t *body, size_t len, const uint8_t *offered, size_t offered_len,
                     uint8_t *out, size_t out_cap, size_t *out_len,
                     char *err, size_t err_cap, char *go, size_t go_cap);

#endif
