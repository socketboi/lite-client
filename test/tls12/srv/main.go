// A TLS 1.2-only server for test/tls12: Go's crypto/tls with one cipher suite, one key type and one
// curve, and the extras a site may add — a session ticket, an OCSP staple, a request for a client
// certificate. Every connection is logged as one line: the handshake's verdict, the suite and the
// curve Go settled on, and what the client did after it (EOF is a close_notify that opened under the
// client's TLS 1.2 key).
//
//	srv -listen :4433 -dir /tmp/tls12 -key rsa|ecdsa|ed25519 -suite 0xc02f [-curve x25519] [-ticket]
//	    [-ocsp] [-clientauth] [-send N] [-wrongkey]
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func key(kind string) crypto.Signer {
	switch kind {
	case "rsa":
		k, _ := rsa.GenerateKey(rand.Reader, 2048)
		return k
	case "ecdsa":
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		return k
	case "ecdsa384":
		k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		return k
	case "ed25519":
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		return k
	}
	panic("key: " + kind)
}

func main() {
	listen := flag.String("listen", ":4433", "")
	dir := flag.String("dir", "/tmp/tls12", "where ca.pem goes")
	kind := flag.String("key", "rsa", "")
	suite := flag.String("suite", "0xc02f", "")
	curve := flag.String("curve", "", "x25519, p256, p384, p521; empty for Go's order")
	ticket := flag.Bool("ticket", false, "")
	ocsp := flag.Bool("ocsp", false, "")
	clientAuth := flag.Bool("clientauth", false, "")
	send := flag.Int("send", 64, "bytes of application data after the handshake")
	wrongKey := flag.Bool("wrongkey", false, "sign the key exchange with a key the certificate does not carry")
	flag.Parse()

	caKey := key("ecdsa")
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tls12 stand CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	ca, _ := x509.ParseCertificate(caDER)
	os.MkdirAll(*dir, 0o755)
	os.WriteFile(filepath.Join(*dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644)

	leafKey := key(*kind)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "tls12.test"},
		DNSNames:  []string{"tls12.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, ca, leafKey.Public(), caKey)

	id, err := strconv.ParseUint(*suite, 0, 16)
	if err != nil {
		panic(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}
	if *wrongKey {
		cert.PrivateKey = key(*kind)
	}
	if *ocsp {
		cert.OCSPStaple = []byte("a staple the client does not check")
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		CipherSuites:           []uint16{uint16(id)},
		SessionTicketsDisabled: !*ticket,
		NextProtos:             []string{"h2", "http/1.1"},
	}
	if *clientAuth {
		cfg.ClientAuth = tls.RequestClientCert
	}
	switch *curve {
	case "x25519":
		cfg.CurvePreferences = []tls.CurveID{tls.X25519}
	case "p256":
		cfg.CurvePreferences = []tls.CurveID{tls.CurveP256}
	case "p384":
		cfg.CurvePreferences = []tls.CurveID{tls.CurveP384}
	case "p521":
		cfg.CurvePreferences = []tls.CurveID{tls.CurveP521}
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		panic(err)
	}
	fmt.Println("listening")
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			t := tls.Server(c, cfg)
			if err := t.Handshake(); err != nil {
				fmt.Printf("HS FAIL %v\n", err)
				return
			}
			st := t.ConnectionState()
			if *send > 0 {
				t.Write(make([]byte, *send))
			}
			n, err := io.Copy(io.Discard, t)
			fmt.Printf("HS OK suite 0x%04x curve %v alpn %q read %d end %v\n", st.CipherSuite,
				st.CurveID, st.NegotiatedProtocol, n, err)
		}(c)
	}
}
