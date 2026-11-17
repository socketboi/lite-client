#!/bin/sh
# Fetch every upstream tree this client is checked against into vendor/, each at the exact revision
# the code and its `vendor/…:N` citations were written against. Needs git 2.35 or newer
# (sparse-checkout set --cone).
#
#   sh tools/vendor/fetch.sh            fetch whatever is missing
#   sh tools/vendor/fetch.sh --force    re-fetch everything (deletes vendor/<name> first)
#
# Nothing here is committed to this repository: every tree keeps its own history and licence (see
# THIRD_PARTY_NOTICES.md). `make check-vendor` compares what is in vendor/ with the pinned table in
# docs/BUILD.md; this list and that table must name the same revisions, and check-vendor is what
# notices when they do not.
#
# Each tree is fetched at depth 1 by full commit id, so a clone costs the size of one checkout rather
# than the project's history. The large ones are sparse: only the directories that are compiled,
# cited or run by a tool are checked out.
set -eu

cd "$(dirname "$0")/../.."
mkdir -p vendor

force=0
[ "${1:-}" = "--force" ] && force=1

# name  url  commit  [sparse directories, comma separated]
PINS='
Xray-core     https://github.com/XTLS/Xray-core                  676eaf66f8f05d4d558ee7a74b4736623d3feeb9
REALITY       https://github.com/XTLS/REALITY                    4bb46b2afd8b4f1f082fbaccae34fd3c7a3f8973
utls          https://github.com/refraction-networking/utls      a13c59ffe98bb01b2ca14143eb2e887664b1f138
utls-hy       https://github.com/refraction-networking/utls      8fe0b08e9a0e7e2d08b268f451f2c79962e6acd0
mlkem-native  https://github.com/pq-code-package/mlkem-native    c4f993c3f1d20b77a7c3f0144c7ffaadc9943b0d
mbedtls       https://github.com/Mbed-TLS/mbedtls                0bebf8b8c7f07abe3571ded48a11aa907a1ffb20
zlib          https://github.com/madler/zlib                     51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf
brotli        https://github.com/google/brotli                   ed738e842d2fbdf2d6459e39267a633c4a9b2f5d
zstd          https://github.com/facebook/zstd                   f8745da6ff1ad1e7bab384bd1f9d742439278e99
brotli-go     https://github.com/andybalholm/brotli              17e5901d050574f228e7d5a3f754a30a7cb55d55
ngtcp2        https://github.com/ngtcp2/ngtcp2                   d7fb3ed0407e1333e4ecbd011fcfd9c16499d5e0
nghttp3       https://github.com/ngtcp2/nghttp3                  e4988cdb1ca9c5bfb2a591a5b132ddcadf5c739a
nghttp2       https://github.com/nghttp2/nghttp2                 fe17ea5b33f50a2ce781188b21496577f5207552  lib
hysteria      https://github.com/apernet/hysteria                ca8fbd874fd6ca82413948de6dc5924405e103e1  app,core,extras
quic-go       https://github.com/apernet/quic-go                 a10df75c260cee8161f3261d63a37bd125a6bb2a
qpack         https://github.com/quic-go/qpack                   1661efa70093a118695f62e222b94ce192119092
x-net         https://github.com/golang/net                      3de643db506517b3e652a13cc0b56034cea6b8e6  http2,internal/httpcommon,internal/httpsfv,internal/gate,internal/testcert,idna,http/httpguts
'

stale=0
while read -r name url rev sparse; do
    [ -n "$name" ] || continue
    dir="vendor/$name"
    # The two submodules the build needs: nghttp3 compiles lib/sfparse into itself, and mbedTLS 3.6
    # keeps part of its build scripts in framework/. The rest (test harnesses) are left out.
    case "$name" in
        nghttp3) sub=lib/sfparse ;;
        mbedtls) sub=framework ;;
        *)       sub= ;;
    esac
    # A checkout with no commit is what an interrupted fetch leaves behind, and one whose submodule
    # is empty is what an interrupted submodule update leaves: both are fetched again rather than
    # reported as fine. One at another revision is left alone and reported. Only a directory with
    # its own .git is asked: anywhere else git would walk up to the repository this one sits in and
    # answer with ITS head.
    have=
    [ -e "$dir/.git" ] && have=$(git -C "$dir" rev-parse -q --verify HEAD 2>/dev/null || true)
    if [ -n "$have" ] && [ "$force" = 0 ]; then
        if [ "$have" != "$rev" ]; then
            echo "  FAIL  $name is at $have, pinned $rev: run with --force to replace it"
            stale=1
            continue
        fi
        if [ -z "$sub" ] || [ -n "$(ls -A "$dir/$sub" 2>/dev/null)" ]; then
            echo "  ok    $name ${rev%"${rev#????????}"}"
            continue
        fi
        echo "  ...   $name is at its pin but $sub is empty: fetching it again"
    fi
    rm -rf "$dir"
    echo "  fetch $name ${rev%"${rev#????????}"}"
    git init -q "$dir"
    # Citations are line numbers and several generators read these files byte for byte, so the
    # checkout must be exactly upstream's: no CRLF conversion on Windows, and mlkem-native's proof
    # harnesses have paths past Windows' 260-character limit.
    git -C "$dir" config core.autocrlf false
    git -C "$dir" config core.longpaths true
    git -C "$dir" remote add origin "$url"
    if [ -n "${sparse:-}" ]; then
        git -C "$dir" sparse-checkout set --cone $(echo "$sparse" | tr ',' ' ')
    fi
    git -C "$dir" fetch -q --depth 1 origin "$rev"
    git -C "$dir" -c advice.detachedHead=false checkout -q FETCH_HEAD
    if [ -n "$sub" ]; then
        git -C "$dir" -c core.autocrlf=false submodule -q update --init --depth 1 "$sub"
    fi
    # zlib's zconf.h as ./configure leaves it on Linux, which is how the zlib on the router was
    # built: the two switches configure turns on for a system with unistd.h and stdarg.h.
    if [ "$name" = zlib ]; then
        sed -i -e 's|^#ifdef HAVE_UNISTD_H    /\* may be set to #if 1 by ./configure \*/|#if 1    /* was set to #if 1 by ./configure */|' \
               -e 's|^#ifdef HAVE_STDARG_H    /\* may be set to #if 1 by ./configure \*/|#if 1    /* was set to #if 1 by ./configure */|' \
               "$dir/zconf.h"
    fi
done <<EOF
$PINS
EOF

[ "$stale" = 0 ] || exit 1
echo "  done: vendor/ holds the pinned trees; next is 'make check' (see docs/BUILD.md)"
