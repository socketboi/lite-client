// What go1.27.1 makes of a machine's certificate store — the pool loadSystemRoots builds from
// SSL_CERT_FILE, SSL_CERT_DIR and the files and directories it knows (GOROOT/src/crypto/x509/
// root.go, root_linux.go), which is the store REALITY's fallback verification trusts when Roots is
// nil. test/goroots/run.sh holds cert/goverify.c's lc_go_load_roots to it, scenario by scenario.
//
//	x509roots gen DIR   writes the material the scenarios are made of into DIR
//	x509roots pool      prints the system pool as this process finds it: one line per
//	                    certificate, its subject in hex, in the pool's order — or "error: " and the
//	                    error when there is none
//
// The certificates made by gen have subjects of their own, so that the subject names each one.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func cert(i int) []byte {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rngFor(i))
	if err != nil {
		panic(err)
	}
	t := &x509.Certificate{
		SerialNumber: big.NewInt(int64(i + 1)),
		Subject:      pkix.Name{CommonName: fmt.Sprintf("root %02d", i), Organization: []string{"x509roots"}},
		NotBefore:    time.Unix(1700000000, 0), NotAfter: time.Unix(2000000000, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rngFor(i+1000), t, t, &k.PublicKey, k)
	if err != nil {
		panic(err)
	}
	return der
}

// a deterministic reader, so that the material is the same on every run
type rng struct{ s uint64 }

func (r *rng) Read(p []byte) (int, error) {
	for i := range p {
		r.s ^= r.s << 13
		r.s ^= r.s >> 7
		r.s ^= r.s << 17
		p[i] = byte(r.s)
	}
	return len(p), nil
}

func rngFor(i int) *rng { return &rng{uint64(i)*0x9e3779b97f4a7c15 + 1} }

func block(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func write(dir, name, body string) {
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		panic(err)
	}
}

func gen(dir string) {
	var c []string
	for i := 0; i < 24; i++ {
		c = append(c, block(cert(i)))
	}
	b64 := func(s string) string { // the base64 lines of a block
		lines := strings.Split(strings.TrimSpace(s), "\n")
		return strings.Join(lines[1:len(lines)-1], "\n")
	}
	// PEM as pem.Decode meets it in the wild and at its edges
	write(dir, "bundle.pem", c[0]+"junk between\n"+c[1]+c[1]+"\n\n"+c[2])
	write(dir, "crlf.pem", strings.ReplaceAll(c[3], "\n", "\r\n"))
	write(dir, "spaces.pem", strings.ReplaceAll(c[4], "\n", " \t\n"))
	write(dir, "headers.pem", "-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n\n"+b64(c[5])+"\n-----END CERTIFICATE-----\n"+c[6])
	write(dir, "types.pem", strings.Replace(c[7], "CERTIFICATE", "TRUSTED CERTIFICATE", 2)+
		strings.Replace(c[8], "END CERTIFICATE", "END CERTIFICATEX", 1)+c[9])
	write(dir, "badb64.pem", "-----BEGIN CERTIFICATE-----\n"+b64(c[10])+"==\n-----END CERTIFICATE-----\n"+
		"-----BEGIN CERTIFICATE-----\n"+b64(c[11])+"!\n-----END CERTIFICATE-----\n"+c[12])
	write(dir, "prefix.pem", "text -----BEGIN CERTIFICATE-----\n"+b64(c[13])+"\n-----END CERTIFICATE-----\n"+
		"x\n"+c[14]+"-----BEGIN CERTIFICATE-----\n"+b64(c[15])+"\n-----END CERTIFICATE----- tail\n")
	write(dir, "nested.pem", "-----BEGIN CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n"+b64(c[16])+
		"\n-----END CERTIFICATE-----\n")
	write(dir, "noend.pem", "-----BEGIN CERTIFICATE-----\n"+b64(c[17])+"\n")
	write(dir, "notcert.pem", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"+
		"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"+c[18])
	write(dir, "colon.pem", "-----BEGIN CERTIFICATE-----\n"+strings.Replace(b64(c[19]), "\n", ":\n", 1)+
		"\n-----END CERTIFICATE-----\n")
	write(dir, "one.pem", c[20])
	write(dir, "two.pem", c[21])
	write(dir, "three.pem", c[22])
	write(dir, "twentythree.pem", c[23])
}

func pool() {
	p, err := x509.SystemCertPool()
	if err != nil {
		fmt.Println("error: " + err.Error())
		return
	}
	for _, s := range p.Subjects() {
		fmt.Println(hex.EncodeToString(s))
	}
}

func main() {
	switch {
	case len(os.Args) == 3 && os.Args[1] == "gen":
		gen(os.Args[2])
	case len(os.Args) == 2 && os.Args[1] == "pool":
		pool()
	default:
		fmt.Fprintln(os.Stderr, "usage: x509roots gen DIR | pool")
		os.Exit(2)
	}
}
