#!/bin/sh
# Regenerate THIRD_PARTY_NOTICES.md: the hand-written part (notices-head.md) followed by every
# upstream licence, copied from the pinned trees in vendor/ so that the text is exactly what each
# project ships. Run after tools/vendor/fetch.sh whenever a pin moves:
#
#   tools/public/notices.sh > THIRD_PARTY_NOTICES.md
#   tools/public/notices.sh --device        what the OpenWrt package installs
#
# --device leaves out the licences of what the package does not ship: zlib comes with the firmware
# and BearSSL is no longer compiled. Mbed TLS stays in: part of it is translated into the binary.
#
# `make check-notices` regenerates the full file and fails if the committed one differs.
set -eu
cd "$(dirname "$0")/../.."

device=0
[ "${1:-}" = "--device" ] && device=1

lic() {   # title  file  [first-line  last-line]
    [ -f "$2" ] || { echo "notices.sh: $2 is missing; run tools/vendor/fetch.sh" >&2; exit 1; }
    printf '\n### %s\n\n```text\n' "$1"
    if [ $# -ge 4 ]; then sed -n "$3,$4p" "$2"; else cat "$2"; fi | tr -d '\r' | sed -e 's/[[:space:]]*$//'
    printf '```\n'
}
full() { [ "$device" = 0 ] && lic "$@" || true; }

cat tools/public/notices-head.md
lic  'ngtcp2 (MIT)'                                   vendor/ngtcp2/COPYING
lic  'nghttp3 (MIT)'                                  vendor/nghttp3/COPYING
lic  'sfparse (MIT)'                                  vendor/nghttp3/lib/sfparse/COPYING
lic  'nghttp2 (MIT)'                                  vendor/nghttp2/COPYING
lic  'mlkem-native (Apache-2.0 OR ISC OR MIT)'        vendor/mlkem-native/LICENSE
lic  'brotli (MIT)'                                   vendor/brotli/LICENSE
lic  'zstd (BSD-3-Clause)'                            vendor/zstd/LICENSE
lic  'Go, golang.org/x/net, golang.org/x/text, golang.org/x/crypto (BSD-3-Clause)' vendor/x-net/LICENSE
lic  'Go: additional IP rights grant (PATENTS)'       vendor/x-net/PATENTS
lic  'uTLS (BSD-3-Clause)'                            vendor/utls/LICENSE
lic  'Hysteria (MIT)'                                 vendor/hysteria/LICENSE.md
lic  'quic-go (MIT)'                                  vendor/quic-go/LICENSE
lic  'qpack (MIT)'                                    vendor/qpack/LICENSE.md
lic  'andybalholm/brotli (MIT)'                       vendor/brotli-go/LICENSE
lic  'Mbed TLS (Apache-2.0 OR GPL-2.0-or-later)'      vendor/mbedtls/LICENSE
full 'zlib (zlib licence, from zlib.h)'               vendor/zlib/zlib.h 2 24
full 'BearSSL (MIT)'                                  tools/public/licenses/bearssl.txt
lic  'Chromium (BSD-3-Clause)'                       tools/public/licenses/chromium.txt
lic  'Unicode License v3'                             tools/public/licenses/unicode.txt
