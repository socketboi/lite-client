// A small web PKI, for the check a REALITY client makes when the node did not authenticate it.
//
// src/cert/chain.c asks mbedTLS the question the reference asks Go's x509: does this chain reach a
// root the machine trusts, and is the leaf valid for the name we put in SNI. To test that, the test
// needs a machine whose trusted roots it controls — so this builds one: a root, an intermediate
// under it, and four leaves that differ in exactly one thing each.
//
// Every certificate here is ECDSA P-256, which is what the public web uses and what mbedTLS can
// verify. The ed25519 certificates in tools/cert are the other half of the story — those are what a
// REALITY server generates, and nothing verifies them as certificates at all.
//
//	go run ./tools/chain > build/gen/chain_vectors.h
package main

import (
	"bytes"
	"compress/zlib"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// A TLS 1.3 Certificate message BODY: an empty request context, then the list, each entry followed
// by its own empty extensions block. The same shape the C test builds by hand — built here too
// because what the compressed vectors have to open to is exactly this.
func certificateBody(ders ...[]byte) []byte {
	var list []byte
	for _, der := range ders {
		list = append(list, byte(len(der)>>16), byte(len(der)>>8), byte(len(der)))
		list = append(list, der...)
		list = append(list, 0x00, 0x00)
	}
	body := []byte{0x00}
	body = append(body, byte(len(list)>>16), byte(len(list)>>8), byte(len(list)))
	return append(body, list...)
}

// RFC 8879: `algorithm(2) | uncompressed_length(3) | compressed<3>`. zlib(1) means an RFC 1950
// stream, which is what compress/zlib writes and what libz's uncompress() reads — the two ends of
// the only algorithm this client offers.
func compressedCertificate(body []byte) []byte {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(body); err != nil {
		die("compressing the certificate message", err)
	}
	if err := w.Close(); err != nil {
		die("closing the compressor", err)
	}
	z := buf.Bytes()

	out := []byte{0x00, 0x01}
	out = append(out, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	out = append(out, byte(len(z)>>16), byte(len(z)>>8), byte(len(z)))
	return append(out, z...)
}

func die(msg string, err error) {
	fmt.Fprintln(os.Stderr, msg+":", err)
	os.Exit(1)
}

func emit(name string, b []byte) {
	fmt.Printf("static const uint8_t %s[] = {", name)
	for i, x := range b {
		if i > 0 {
			fmt.Print(",")
		}
		if i%12 == 0 {
			fmt.Print("\n    ")
		}
		fmt.Printf("0x%02x", x)
	}
	fmt.Println("\n};")
}

type key struct {
	priv *ecdsa.PrivateKey
}

func newKey() key {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		die("key generation", err)
	}
	return key{k}
}

// The dates are absolute rather than relative to now, so that a fixture regenerated next year is
// the same fixture. Far enough out that "valid" stays valid for the life of this code, and the
// expired one is expired by a decade rather than by a minute — a clock-skew failure and a genuine
// expiry would otherwise be the same test.
var (
	notBefore = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter  = time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC)
	longGone  = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
)

func sign(tmpl, parent *x509.Certificate, pub key, signer key) []byte {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &pub.priv.PublicKey, signer.priv)
	if err != nil {
		die("certificate creation", err)
	}
	return der
}

func parse(der []byte) *x509.Certificate {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		die("re-parsing the certificate", err)
	}
	return c
}

func caTemplate(serial int64, cn string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
}

func leafTemplate(serial int64, name string, until time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              []string{name},
		NotBefore:             notBefore,
		NotAfter:              until,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
}

func main() {
	rootKey, interKey, leafKey := newKey(), newKey(), newKey()

	rootDER := sign(caTemplate(1, "lite-client test root"), caTemplate(1, "lite-client test root"), rootKey, rootKey)
	root := parse(rootDER)

	interDER := sign(caTemplate(2, "lite-client test intermediate"), root, interKey, rootKey)
	inter := parse(interDER)

	leafDER := sign(leafTemplate(3, "www.example.com", notAfter), inter, leafKey, interKey)
	expiredDER := sign(leafTemplate(4, "www.example.com", longGone), inter, leafKey, interKey)

	// Signed by nobody the store knows. This is the shape an active prober produces: a certificate
	// that says the right name and reaches no root at all.
	strangerTmpl := leafTemplate(5, "www.example.com", notAfter)
	strangerKey := newKey()
	strangerDER := sign(strangerTmpl, strangerTmpl, strangerKey, strangerKey)

	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})

	fmt.Println("/* Generated by tools/chain with Go's crypto/x509: a root, an intermediate under it,")
	fmt.Println(" * and leaves that differ from the good one in exactly one way each. */")
	fmt.Println("#ifndef LC_CHAIN_VECTORS_H")
	fmt.Println("#define LC_CHAIN_VECTORS_H")
	fmt.Println()
	fmt.Println("#include <stdint.h>")
	fmt.Println()
	fmt.Println("/* The only root the test trusts, PEM, for writing to a file SSL_CERT_FILE points at. */")
	emit("chain_root_pem", rootPEM)
	fmt.Println()
	emit("chain_inter_der", interDER)
	fmt.Println()
	fmt.Println("/* Valid for www.example.com, and only through the intermediate above. */")
	emit("chain_leaf_der", leafDER)
	fmt.Println()
	fmt.Println("/* Same key, same name, same issuer — expired in 2021. */")
	emit("chain_expired_der", expiredDER)
	fmt.Println()
	fmt.Println("/* Says www.example.com and chains to nothing. */")
	emit("chain_stranger_der", strangerDER)
	fmt.Println()

	plain := certificateBody(leafDER, interDER)
	fmt.Println("/* The Certificate message body the compressed vector below has to open to. */")
	emit("certcomp_plain", plain)
	fmt.Println()
	fmt.Println("/* A CompressedCertificate body: zlib(1), by Go's compress/zlib, which writes the")
	fmt.Println(" * RFC 1950 stream that RFC 8879 names for that algorithm. */")
	emit("certcomp_message", compressedCertificate(plain))
	fmt.Println()
	fmt.Println("#endif")
}
