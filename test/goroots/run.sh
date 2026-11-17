#!/bin/sh
# The certificate store REALITY's fallback verification trusts, as go1.27.1 builds it and as
# cert/goverify.c does (lc_go_load_roots): the same pool, certificate for certificate and in the
# same order, or the same error — for SSL_CERT_FILE and SSL_CERT_DIR each set, unset, empty and
# pointing at odd things, for directories with symbolic links of both kinds, and for PEM that
# pem.Decode reads in ways a reader would not guess (tools/x509roots gen writes it).
#
# Run in the build image, from the repository root, after `make BUILD=<dir> <dir>/goroots`:
#
#   sh test/goroots/run.sh <dir>
set -u
B=${1:?usage: run.sh BUILD}
GO=/usr/local/go1.27/bin/go
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
(cd tools/x509roots && "$GO" build -o "$T/x509roots" .) || { echo "  FAIL  tools/x509roots does not build"; exit 1; }
M=$T/m; mkdir -p "$M"
"$T/x509roots" gen "$M" || { echo "  FAIL  tools/x509roots gen"; exit 1; }

# the directories the scenarios point at
mkdir -p "$T/d1" "$T/d2/sub" "$T/empty" "$T/other"
cp "$M/one.pem" "$M/two.pem" "$T/d1/"
ln -s one.pem "$T/d1/a-samedir-link"           # another name for a file here: skipped
ln -s "$T/other/far.pem" "$T/d1/b-far-link"    # a file elsewhere: read
cp "$M/three.pem" "$T/other/far.pem"
ln -s missing.pem "$T/d1/c-dangling"
ln -s ../other/far.pem "$T/d1/d-relative-up"   # a '/' in the target: read, and a duplicate
cp "$M/bundle.pem" "$T/d2/"; cp "$M/twentythree.pem" "$T/d2/sub/"
: > "$T/d2/zero-length"

fails=0 n=0
scenario() { # name, then VAR=value settings (unset when the value is the word UNSET)
	name=$1; shift
	n=$((n + 1))
	go=$(env -u SSL_CERT_FILE -u SSL_CERT_DIR "$@" "$T/x509roots" pool 2>&1)
	lc=$(env -u SSL_CERT_FILE -u SSL_CERT_DIR "$@" "$B/goroots" 2>&1)
	if [ "$go" = "$lc" ]; then
		echo "  ok    $name ($(printf '%s\n' "$go" | grep -c '^[0-9a-f]') certificates$(printf '%s' "$go" | grep -q '^error' && echo ', an error'))"
	else
		echo "  FAIL  $name"; echo "--- go1.27.1"; printf '%s\n' "$go" | head -8; echo "--- this"; printf '%s\n' "$lc" | head -8
		fails=$((fails + 1))
	fi
}

for f in bundle crlf spaces headers types badb64 prefix nested noend notcert colon one; do
	scenario "PEM $f.pem" SSL_CERT_FILE="$M/$f.pem" SSL_CERT_DIR="$T/empty"
done
scenario "the file and a directory with links" SSL_CERT_FILE="$M/one.pem" SSL_CERT_DIR="$T/d1"
scenario "a directory list, empty entries and one missing" SSL_CERT_FILE="$M/two.pem" SSL_CERT_DIR=":$T/d1::$T/nope:$T/d2"
scenario "a directory holding a directory and an empty file" SSL_CERT_FILE="$T/nope.pem" SSL_CERT_DIR="$T/d2"
scenario "SSL_CERT_FILE a directory, no directories" SSL_CERT_FILE="$T/d1" SSL_CERT_DIR="$T/empty"
scenario "SSL_CERT_FILE a directory, a directory with certificates" SSL_CERT_FILE="$T/d1" SSL_CERT_DIR="$T/d2"
scenario "SSL_CERT_FILE missing, SSL_CERT_DIR empty" SSL_CERT_FILE="$T/nope.pem" SSL_CERT_DIR="$T/empty"
scenario "SSL_CERT_DIR a file" SSL_CERT_FILE="$M/one.pem" SSL_CERT_DIR="$M/two.pem"
scenario "SSL_CERT_DIR a file and nothing else" SSL_CERT_FILE="$T/nope.pem" SSL_CERT_DIR="$M/two.pem"
scenario "SSL_CERT_FILE empty: the list of files" SSL_CERT_FILE= SSL_CERT_DIR="$T/empty"
scenario "nothing set: this machine's store" 

if [ $fails -eq 0 ]; then
	echo "  ok    the certificate store is go1.27.1's in all $n scenarios"
else
	echo "  FAIL  $fails of $n scenarios differ"; exit 1
fi
