#!/bin/sh
# cert/goverify.c held to go1.27.1's Certificate.Verify: every call crypto/x509's own tests make,
# made again here from the same bytes, and the answers compared (test/goverify/test_goverify.c).
#
# The record is taken fresh on every run, because those tests make new keys each time. `go test
# -overlay` swaps two files into the package for this one build — nothing in GOROOT is written:
#
#   verify.go      the toolchain's own, with Verify and policiesValid renamed verifyInner and
#                  policiesValidInner (the two lines the sed below changes, and nothing else);
#   zz_record.go   tools/x509verify/zz_record.go, which puts a Verify and a policiesValid back in
#                  their place that call those and write down arguments and answer.
#
# Go's own tests still have to pass with the swap in, which says the wrappers change nothing. Then
# tools/x509verify/cases, under the same overlay, adds the chains Go's tests leave alone (see it
# for which rules, and why): a second record, its certificates numbered afresh.
#
# In the build image, from the repository root, after `make BUILD=<dir> <dir>/test-goverify`:
#
#   sh test/goverify/run.sh <dir>
set -eu
B=${1:?usage: run.sh BUILD}
GO=/usr/local/go1.27/bin/go
fail() { echo "  FAIL  $*"; exit 1; }

[ -x "$GO" ] || fail "no go1.27 at $GO"
R=$("$GO" env GOROOT)
W=$(cd "$B" && pwd)/goverify
mkdir -p "$W"
sed -e 's/^func (c \*Certificate) Verify(opts VerifyOptions)/func (c *Certificate) verifyInner(opts VerifyOptions)/' \
    -e 's/^func policiesValid(/func policiesValidInner(/' "$R/src/crypto/x509/verify.go" > "$W/verify.go"
[ "$(grep -c '^func (c \*Certificate) verifyInner(\|^func policiesValidInner(' "$W/verify.go")" = 2 ] ||
    fail "verify.go of $R no longer has the two functions the record wraps"
printf '{"Replace":{"%s":"%s","%s":"%s"}}\n' \
    "$R/src/crypto/x509/verify.go" "$W/verify.go" \
    "$R/src/crypto/x509/zz_record.go" "$(pwd)/tools/x509verify/zz_record.go" > "$W/overlay.json"

rm -f "$W/record"
if ! X509REC_OUT="$W/record" "$GO" test -overlay="$W/overlay.json" -count=1 crypto/x509 > "$W/go.log" 2>&1; then
    tail -20 "$W/go.log"
    fail "go1.27.1's crypto/x509 tests fail with the record in place"
fi
rm -f "$W/record2"
if ! (cd tools/x509verify/cases && X509REC_OUT="$W/record2" "$GO" run -overlay="$W/overlay.json" .) > "$W/cases.log" 2>&1; then
    tail -20 "$W/cases.log"
    fail "tools/x509verify/cases does not run"
fi
"$B/test-goverify" "$W/record" "$W/record2"
