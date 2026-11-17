#!/bin/sh
# The certificate decompressor, against a real TLS server that really compresses.
#
# WHY THIS EXISTS, AND WHY IT IS NOT REDUNDANT WITH test-certcomp BESIDE IT.
#
# test_certcomp.c drives lc_certcomp_open over fixtures produced by Go's compress/zlib. That checks
# the inflater against another implementation's output, which is worth having and is not the same
# thing as checking it against a TLS server: the fixture is a stream handed straight to the opener,
# while the live path has to recognise handshake message type 25, read its declared length and
# uncompressed size, inflate, and hand the result to the certificate parser as though it had arrived
# uncompressed.
#
# ⚠️ THAT PATH HAD NEVER RUN ANYWHERE, back when the client advertised zlib alone: nothing on the
# public web compresses with zlib — measured 2026-08-18, every site that compressed (example.com,
# cloudflare.com, discord.com) chose brotli, and the rest sent plain certificates. So the code that
# had to work on the single day a server picked zlib had no live exercise at all, and the note
# recording that concluded it could not have one. It can: openssl 3.2+ speaks RFC 8879, and
# `make check` already runs in an image that carries openssl 3.5.
#
# Since the client gained brotli and zstd the list is three long, and the choice is the SERVER'S —
# which is why the algorithm is now read out of its log below rather than named in the result line.
# This image's OpenSSL is built with zlib and zstd but not brotli, so two of the three can be proved
# here against a foreign implementation and the third cannot: brotli's only check is the round trip
# in test_certcomp.c, said out loud there too.
#
# ⚠️ THE CHECK MUST PROVE THAT COMPRESSION HAPPENED. A server that quietly decided not to compress
# would give a completed handshake and a green line that tested nothing — the exact shape of a test
# that guards nothing while looking like it does. So the server's own message log is read, and the
# absence of CompressedCertificate is a failure and not a skip.
#
# A missing or too-old openssl is likewise a failure rather than a silent pass. `make check` is
# documented to run in lc-build:local, which has one; if it does not, the honest answer is that this
# check did not run, said out loud.
set -eu

BUILD=${BUILD:-build}
PROBE="$BUILD/lc-probe"
TABLE=package/files/fingerprint.fpt
PORT=${LC_CERTCOMP_PORT:-44313}

SRV=
DIR=$(mktemp -d)
cleanup() {
    [ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true
    rm -rf "$DIR"
}
trap cleanup EXIT INT TERM

fail() { printf '  FAIL  %s\n' "$1"; exit 1; }

command -v openssl >/dev/null 2>&1 ||
    fail "no openssl, so the live certificate-compression check did not run"
openssl s_server -help 2>&1 | grep -q -- '-cert_comp' ||
    fail "this openssl cannot compress certificates (RFC 8879 needs 3.2+), so the check did not run"
[ -x "$PROBE" ] || fail "no $PROBE to drive the handshake with"
[ -r "$TABLE" ] || fail "no $TABLE, so there is no hello to send"

# A LONG certificate, deliberately. openssl compresses only when compression is worth it, and a
# short ECDSA leaf can come out larger compressed than plain — the server then sends it uncompressed
# and this check would pass having exercised nothing. RSA-4096 with repetitive subject fields and
# four SANs is comfortably past that line: measured 1505 bytes on the wire, compressed.
SUBJ="/C=NL/ST=Noord-Holland/L=Amsterdam-Zuidoost-Bijlmermeer\
/O=A Very Long Organisation Name For Compressibility BV\
/OU=Department Of Repeated Repeated Repeated Strings/CN=stand.local"
openssl req -x509 -newkey rsa:4096 -keyout "$DIR/k.pem" -out "$DIR/c.pem" -days 2 -nodes \
    -subj "$SUBJ" \
    -addext "subjectAltName=DNS:stand.local,DNS:www.stand.local,DNS:aaa.stand.local,DNS:bbb.stand.local" \
    >/dev/null 2>&1 || fail "could not generate a certificate for the stand"

# -msg is what makes the proof possible: it prints every handshake message the server sends, by
# name, so CompressedCertificate is visible rather than inferred.
openssl s_server -accept "$PORT" -cert "$DIR/c.pem" -key "$DIR/k.pem" -tls1_3 -cert_comp -msg \
    -quiet > "$DIR/srv.log" 2>&1 &
SRV=$!

# Readiness by connecting, not by sleeping: a fixed pause is either too short on a loaded machine or
# wasted on an idle one, and the failure it produces reads as "the client cannot handshake".
ready=0
i=0
while [ "$i" -lt 50 ]; do
    if openssl s_client -connect "127.0.0.1:$PORT" -tls1_3 </dev/null >/dev/null 2>&1; then
        ready=1
        break
    fi
    i=$((i + 1))
done
[ "$ready" = 1 ] || fail "the stand never came up on port $PORT"

out=$("$PROBE" "$TABLE" 127.0.0.1 "$PORT" stand.local 2>&1) || true

case "$out" in
    *"handshake complete"*) ;;
    *) fail "the handshake did not complete against a server that compresses its certificate: $out" ;;
esac

grep -q "CompressedCertificate" "$DIR/srv.log" ||
    fail "the server sent a PLAIN certificate, so nothing about decompression was tested"

# WHICH algorithm, read out of the server's own log rather than assumed.
#
# The client offers three now, and RFC 8879 leaves the choice to the server — measured on the public
# web, the choice is not our order: with zlib written first, every Cloudflare site answered brotli.
# So a line that names an algorithm has to name the one that was actually used, or it is the same
# kind of confident falsehood this whole test exists to prevent. `-msg` prints the message bytes,
# and the two after the four-byte handshake header are the algorithm.
#
# It also fails on an algorithm outside the three: that would mean the server ignored our list, and
# a completed handshake in that case would say something is wrong with what we sent, not right.
alg=$(sed -n '/CompressedCertificate/{n;s/^ *//;p;q;}' "$DIR/srv.log" | cut -d' ' -f5,6)
case "$alg" in
    "00 01") name=zlib ;;
    "00 02") name=brotli ;;
    "00 03") name=zstd ;;
    *) fail "the server compressed with algorithm [$alg], which is not one of the three offered" ;;
esac

echo "  ok    a certificate compressed by a real server (openssl, $name) opens and verifies"
