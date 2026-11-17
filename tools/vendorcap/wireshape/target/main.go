package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"time"
)

func handler(w http.ResponseWriter, r *http.Request) {
	// The download half, for the scenarios that measure what a path sees while somebody is
	// receiving rather than sending — see `down` in the probe for why that direction was missing.
	// Zero bytes, because the shape is the point and the tunnel encrypts either way.
	if r.URL.Path == "/down" {
		n, _ := strconv.Atoi(r.URL.Query().Get("bytes"))
		if n <= 0 {
			n = 300000
		}
		w.Header().Set("Content-Length", strconv.Itoa(n))
		buf := make([]byte, 32*1024)
		for n > 0 {
			k := len(buf)
			if k > n {
				k = n
			}
			if _, err := w.Write(buf[:k]); err != nil {
				return
			}
			n -= k
		}
		return
	}

	n, _ := io.Copy(io.Discard, r.Body)
	fmt.Fprintf(w, "pool-stand-ok body=%d\n", n)
}

func main() {
	go func() {
		pc, err := net.ListenPacket("udp", "127.0.0.1:15353")
		if err != nil {
			panic(err)
		}
		buf := make([]byte, 65536)
		for {
			n, a, err := pc.ReadFrom(buf)
			if err != nil {
				continue
			}
			pc.WriteTo(append([]byte("echo:"), buf[:n]...), a)
		}
	}()
	go func() {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"t"}}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
		srv := &http.Server{Addr: "127.0.0.1:18443", Handler: http.HandlerFunc(handler),
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}}
		srv.SetKeepAlivesEnabled(false)
		panic(srv.ListenAndServeTLS("", ""))
	}()
	srv := &http.Server{Addr: "127.0.0.1:18080", Handler: http.HandlerFunc(handler)}
	srv.SetKeepAlivesEnabled(false)
	panic(srv.ListenAndServe())
}
