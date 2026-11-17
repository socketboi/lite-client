# Third-party notices

lite-client is licensed under the Mozilla Public License 2.0 (see `LICENSE`). A lot of it is not
original work in the usual sense: it is a C translation of other projects' Go and C code, done
deliberately line by line so that the client behaves on the wire exactly as those projects do.
Comments in `src/` cite the upstream file and line they follow (`vendor/<project>/<file>:<line>`).

This file lists every upstream project the client builds from, translates from, or tests against,
under three headings, and then reproduces each licence in full.

None of the upstream source is committed to this repository. `tools/vendor/fetch.sh` fetches each
tree into `vendor/` at the revision listed in `docs/BUILD.md`.

## 1. Compiled into the binary

These are built from source and linked statically into `lc-tunnel`. Their notices must travel with
any binary or package you distribute. The OpenWrt package installs them, with `LICENSE`, under
`/usr/share/licenses/lite-client/` (`tools/public/notices.sh --device`: this file without the
licences of what the package does not ship).

| Project | Used for | Licence |
|---|---|---|
| [ngtcp2](https://github.com/ngtcp2/ngtcp2) | QUIC for the Hysteria2 plane, with the patches in `patches/ngtcp2/` | MIT |
| [nghttp3](https://github.com/ngtcp2/nghttp3) (with [sfparse](https://github.com/ngtcp2/sfparse)) | HTTP/3 and QPACK for Hysteria2 authentication | MIT |
| [mlkem-native](https://github.com/pq-code-package/mlkem-native) | ML-KEM-768 for the X25519MLKEM768 key share | Apache-2.0 OR ISC OR MIT (used under MIT) |
| [brotli](https://github.com/google/brotli) | decoder only, for compressed certificates | MIT |
| [zstd](https://github.com/facebook/zstd) | decoder only, for compressed certificates | BSD-3-Clause OR GPL-2.0 (used under BSD-3-Clause) |

Two more libraries are linked dynamically from the router's own firmware and are not shipped with
this package: [Mbed TLS](https://github.com/Mbed-TLS/mbedtls) (Apache-2.0 OR GPL-2.0-or-later) and
[zlib](https://github.com/madler/zlib) (zlib licence). Their headers are used at build time, and a
small part of Mbed TLS is also translated into the binary (see section 2), so its licence ships
with the package as well.

## 2. Translated into this code base

Parts of `src/` are C translations of the following projects. Where a file is a translation, its
comments say of what. The copyright of the original code stays with its authors; the translations
are distributed under the original licence's terms as well as MPL-2.0 where those differ.

| Project | What was translated | Licence |
|---|---|---|
| [Xray-core](https://github.com/XTLS/Xray-core) | VLESS, XTLS Vision, XUDP, mux, the REALITY client, the spider | MPL-2.0 |
| [REALITY](https://github.com/XTLS/REALITY) | server-side checks the client has to satisfy | MPL-2.0, © 2023 RPRX; its Go-derived parts BSD-3-Clause, © The Go Authors |
| [uTLS](https://github.com/refraction-networking/utls) | ClientHello construction, fingerprint tables (`package/files/fingerprint.fpt`), handshake messages | BSD-3-Clause, © The Go Authors |
| [Go](https://github.com/golang/go) standard library | `crypto/tls` behaviour, `crypto/x509` certificate parsing (`src/cert/x509go.c`), GHASH (`crypto/internal/fips140/aes/gcm`), the edwards25519 field arithmetic, `net/url`, `net/netip`, `strconv.Quote` and its print tables, `math/rand`, the runtime's map iteration order (`src/core/gomap.c`), `compress/flate` and `compress/gzip` reading, `net/http` HTTP/2 client behaviour | BSD-3-Clause, © The Go Authors |
| [golang.org/x/crypto](https://github.com/golang/crypto) | ChaCha20 and Poly1305 (`src/tls/chacha.c`, `src/tls/poly1305.c`), curve25519 | BSD-3-Clause, © The Go Authors |
| [Mbed TLS](https://github.com/Mbed-TLS/mbedtls) | the ARMv8 PMULL and x86-64 PCLMUL GHASH (`src/tls/ghash.c`, from `library/aesce.c` and `library/aesni.c`) | Apache-2.0 OR GPL-2.0-or-later (used under Apache-2.0) |
| [Chromium](https://chromium.googlesource.com/chromium/src/) QUIC | BBRv1 as hysteria ported it, in `patches/ngtcp2/0009-hysteria-bbr.patch` | BSD-3-Clause, © The Chromium Authors |
| [nghttp2](https://github.com/nghttp2/nghttp2) | the HPACK static table in `src/h2/hpack.c` is generated from its source | MIT |
| ref10 from [SUPERCOP](https://bench.cr.yp.to/supercop.html) | the 32-bit field arithmetic for X25519 and Ed25519 (`src/tls/fe25519.c`) | public domain |
| [golang.org/x/net](https://github.com/golang/net) | `http2`, `idna`, `http/httpguts` | BSD-3-Clause, © The Go Authors |
| [golang.org/x/text](https://github.com/golang/text) (as vendored in Go) | Unicode normalisation and bidi rules behind IDNA | BSD-3-Clause, © The Go Authors |
| [Hysteria](https://github.com/apernet/hysteria) | the Hysteria2 protocol client, Salamander and Gecko obfuscation, port hopping, Brutal congestion control | MIT, © 2023 Toby |
| [quic-go (apernet fork)](https://github.com/apernet/quic-go) | QUIC behaviour the ngtcp2 patches reproduce, Chrome parrot | MIT, © 2016 the quic-go authors & Google, Inc. |
| [qpack](https://github.com/quic-go/qpack) | the QPACK encoding of the Hysteria2 authentication request | MIT, © 2019 Marten Seemann |
| [andybalholm/brotli](https://github.com/andybalholm/brotli) | error behaviour of the Go brotli reader | MIT, © the Brotli Authors |
| Unicode Character Database | tables generated from Go's copies of the Unicode 17.0.0 data (`tools/unitables`) | Unicode License v3 |

## 3. Used only for building and testing

Nothing from these ends up in a shipped binary beyond what sections 1 and 2 already list.

| Project | Used for | Licence |
|---|---|---|
| [nghttp2](https://github.com/nghttp2/nghttp2) | checking our HPACK and HTTP/2 framing | MIT |
| brotli and zstd encoders | generating test vectors for the decoders | MIT; BSD-3-Clause |
| [Mbed TLS](https://github.com/Mbed-TLS/mbedtls) | headers and host builds for tests | Apache-2.0 OR GPL-2.0-or-later |
| [BearSSL](https://bearssl.org/) | earlier GHASH implementation, no longer compiled; one comment still compares against it | MIT, © 2016 Thomas Pornin |

## Licence texts

The Mozilla Public License 2.0, which covers Xray-core, REALITY and this project, is in `LICENSE`.
The other licences follow, each exactly as its project ships it.
