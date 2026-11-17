#!/bin/sh
# TLS 1.2 against Go's crypto/tls (T3, closed 29.09): every TLS 1.2 suite the shipped Firefox hello
# offers, with every key type that suite can be signed with and every curve the server may pick, and
# the three extras a site adds — a session ticket, an OCSP staple, a request for a client
# certificate. The server (srv/) is TLS 1.2 only and logs each handshake; lc-probe dials it as a
# REALITY client with a key the server has never heard of, so it takes the stranger's path: the chain
# checked against the stand's CA, the handshake finished, application data both ways.
#
# Run from the repository root, in the build image:
#   docker run --rm -v "$PWD:/w" -w /w lc-build:local sh test/tls12/run.sh
set -u
BUILD=${BUILD:-build}
make -s BUILD="$BUILD" "$BUILD/lc-probe" >/dev/null || exit 1
(cd test/tls12/srv && go build -o "$OLDPWD/$BUILD/tls12srv" .) || exit 1

fails=0 runs=0
one() {
	# $1 key, $2 suite, then server flags
	key=$1 suite=$2
	shift 2
	"$BUILD/tls12srv" -key "$key" -suite "$suite" "$@" >/tmp/tls12srv.log 2>&1 &
	pid=$!
	i=0
	until grep -q listening /tmp/tls12srv.log 2>/dev/null || [ $i -ge 50 ]; do sleep 0.1; i=$((i + 1)); done
	out=$(SSL_CERT_FILE=/tmp/tls12/ca.pem "$BUILD/lc-probe" package/files/fingerprint.fpt 127.0.0.1 4433 \
		tls12.test 1111111111111111111111111111111111111111111111111111111111111111 00 2>&1)
	sleep 0.3
	kill $pid 2>/dev/null
	wait $pid 2>/dev/null
	runs=$((runs + 1))
	srv=$(grep '^HS' /tmp/tls12srv.log | head -1)
	case "$out" in *"handshake complete"*) ok=1 ;; *) ok=0 ;; esac
	case "$srv" in "HS OK suite $suite"*"end <nil>"*) ;; *) ok=0 ;; esac
	if [ $ok = 1 ]; then
		echo "  ok    $key $suite $* — $(echo "$srv" | cut -d' ' -f5-7)"
	else
		echo "  FAIL  $key $suite $*"
		echo "        client: $(echo "$out" | tail -2 | tr '\n' ' ')"
		echo "        server: $srv"
		fails=$((fails + 1))
	fi
}

echo "TLS 1.2, every suite the Firefox hello offers"
for s in 0xc02f 0xc030 0xcca8 0xc013 0xc014; do one rsa $s; done
# Not ed25519: the Firefox hello does not list 0x0807, so a Go server will not sign with such a key
# ("peer doesn't support any of the certificate's signature algorithms") — for uTLS's hello as for ours.
for k in ecdsa ecdsa384; do
	for s in 0xc02b 0xc02c 0xcca9 0xc009 0xc00a; do one $k $s; done
done
for s in 0x009c 0x009d 0x002f 0x0035; do one rsa $s; done

echo "every curve"
for c in x25519 p256 p384 p521; do one rsa 0xc02f -curve $c; one ecdsa 0xc02b -curve $c; done

echo "a session ticket, an OCSP staple, a request for a client certificate"
one rsa 0xc02f -ticket
one ecdsa 0xc02b -ocsp
one rsa 0xc013 -clientauth
one rsa 0x002f -ticket -ocsp -clientauth

# And the refusals, each with the alert uTLS sends: a key exchange signed with a key the certificate
# does not carry is illegal_parameter (vendor/utls/handshake_client.go:735-741), a certificate for
# another name bad_certificate (VerifyPeerCertificate, vendor/utls/handshake_client.go:1251-1256).
refused() {
	# $1 the alert as Go's server prints it, $2 the SNI, then key, suite and server flags
	want=$1 sni=$2 key=$3 suite=$4
	shift 4
	"$BUILD/tls12srv" -key "$key" -suite "$suite" "$@" >/tmp/tls12srv.log 2>&1 &
	pid=$!
	i=0
	until grep -q listening /tmp/tls12srv.log 2>/dev/null || [ $i -ge 50 ]; do sleep 0.1; i=$((i + 1)); done
	out=$(SSL_CERT_FILE=/tmp/tls12/ca.pem "$BUILD/lc-probe" package/files/fingerprint.fpt 127.0.0.1 4433 \
		"$sni" 1111111111111111111111111111111111111111111111111111111111111111 00 2>&1)
	sleep 0.3
	kill $pid 2>/dev/null
	wait $pid 2>/dev/null
	runs=$((runs + 1))
	srv=$(grep '^HS' /tmp/tls12srv.log | head -1)
	case "$out" in *"handshake complete"*) ok=0 ;; *) ok=1 ;; esac
	case "$srv" in "HS FAIL remote error: tls: $want") ;; *) ok=0 ;; esac
	if [ $ok = 1 ]; then
		echo "  ok    $key $suite $* ($sni) — refused, $want"
	else
		echo "  FAIL  $key $suite $* ($sni), want $want"
		echo "        client: $(echo "$out" | tail -1)"
		echo "        server: $srv"
		fails=$((fails + 1))
	fi
}
echo "refusals"
refused "illegal parameter" tls12.test rsa 0xc02f -wrongkey
refused "illegal parameter" tls12.test ecdsa 0xc02b -wrongkey
refused "bad certificate" other.test rsa 0xc02f

echo
if [ $fails -eq 0 ]; then echo "all good ($runs handshakes)"; else echo "FAILURES: $fails of $runs"; exit 1; fi
