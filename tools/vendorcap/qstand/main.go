// A QUIC server built from the REFERENCE library, so that the reference records what our client
// sends instead of us deciding what to look at.
//
// tools/fp answers this question for the REALITY hello: it renders uTLS's own ClientHello and
// diffs. There was no equivalent for the other plane — the hello lc-tunnel builds by hand in
// src/quic/qtls.c — and on 2026-08-25 that showed: it offered twelve signature schemes where the
// reference offers seven, and omitted signature_algorithms_cert entirely. Both had been there since
// the extension was written, and nothing in the tree could have noticed.
//
// WHAT IT PRINTS, and why each half is needed:
//
//   - the parsed ClientHello through tls.Config.GetConfigForClient — SNI, ALPN, versions, ciphers,
//     curves, signature schemes, point formats. These are the fields JA3 and JA4 hash.
//   - chi.Extensions, which is the identifiers IN THE ORDER THEY WERE SENT. Nothing else exposes
//     that, and reading the source will not settle it: two QUIC libraries can agree on the set and
//     disagree on the order.
//   - the transport parameters, through quic-go's own qlog tracer (set QLOGDIR). Hysteria wires no
//     tracer at all, so its server cannot be asked this; that is the whole reason this file exists
//     rather than a config flag on the reference server.
//
// USAGE, from the repository root, inside the build image:
//
//	go build -o /tmp/qstand ./tools/vendorcap/qstand
//	openssl req -x509 -newkey rsa:2048 -keyout /tmp/hk.pem -out /tmp/hc.pem -days 2 -nodes \
//	    -subj "/CN=stand.local" -addext "subjectAltName=DNS:stand.local"
//	QLOGDIR=/tmp/ql /tmp/qstand 127.0.0.1:14451 &
//
// then point each client at it in turn and compare. The reference client is hysteria's own,
// built from vendor/hysteria/app; ours is build/lc-hy. Its authentication will fail against this
// server and that does not matter — parameters_set and the hello are recorded during the QUIC
// handshake, before a word of HTTP/3 is spoken.
//
// ⚠️ TWO WAYS TO GET A GREEN ANSWER THAT MEANS NOTHING, both of which happened while this was
// being written:
//
//   - `go mod tidy` before building, every time. Without it the build fails on go.sum, the server
//     never starts, and a diff of two empty captures says "no differences".
//   - wait for "accepted from", not for the qlog file to appear. The file is created when the
//     connection starts, so killing the client on that races the handshake and captures nothing.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strconv"

	quic "github.com/apernet/quic-go"
	"github.com/apernet/quic-go/qlog"
)

func main() {
	addr := "127.0.0.1:14451"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	cert, err := tls.LoadX509KeyPair("/tmp/hc.pem", "/tmp/hk.pem")
	if err != nil {
		fmt.Fprintln(os.Stderr, "cert:", err)
		os.Exit(1)
	}
	base := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}
	// QSTAND_CURVES=P256 (or P384, P521, SecP256r1MLKEM768, SecP384r1MLKEM1024) leaves the server one group, which both clients advertise
	// and neither key-shares — so it answers the first hello with a HelloRetryRequest, and the
	// second hello is printed below like the first.
	switch os.Getenv("QSTAND_CURVES") {
	case "P256":
		base.CurvePreferences = []tls.CurveID{tls.CurveP256}
	case "P384":
		base.CurvePreferences = []tls.CurveID{tls.CurveP384}
	case "P521":
		base.CurvePreferences = []tls.CurveID{tls.CurveP521}
	// The two hybrids Go 1.26 added, which a client that does not parrot Chrome advertises without
	// sharing: the retry makes it build one.
	case "SecP256r1MLKEM768":
		base.CurvePreferences = []tls.CurveID{tls.SecP256r1MLKEM768}
	case "SecP384r1MLKEM1024":
		base.CurvePreferences = []tls.CurveID{tls.SecP384r1MLKEM1024}
	}
	base.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		fmt.Printf("HELLO sni=%q alpn=%v\n", chi.ServerName, chi.SupportedProtos)
		fmt.Printf("HELLO versions=%v\n", chi.SupportedVersions)
		fmt.Printf("HELLO ciphers=%v\n", chi.CipherSuites)
		fmt.Printf("HELLO curves=%v\n", chi.SupportedCurves)
		fmt.Printf("HELLO sigalgs=%v\n", chi.SignatureSchemes)
		fmt.Printf("HELLO pointformats=%v\n", chi.SupportedPoints)
		fmt.Printf("HELLO extensions=%v\n", chi.Extensions)
		return nil, nil
	}
	conf := &quic.Config{
		EnableDatagrams:      true,
		MaxDatagramFrameSize: 1400,
		Tracer:               qlog.DefaultConnectionTracer,
	}
	// QSTAND_RAW=DIR keeps the first datagrams each client sends and writes, per client, its Initial
	// packets opened and its ClientHello reassembled — see raw.go.
	var ln *quic.Listener
	if dir := os.Getenv("QSTAND_RAW"); dir != "" {
		udp, uerr := net.ListenPacket("udp", addr)
		if uerr != nil {
			fmt.Fprintln(os.Stderr, "listen:", uerr)
			os.Exit(1)
		}
		rc := &rawConn{PacketConn: udp, dir: dir, limit: 16, seen: map[string][][]byte{}}
		ln, err = (&quic.Transport{Conn: rc}).Listen(base, conf)
	} else {
		ln, err = quic.ListenAddr(addr, base, conf)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	fmt.Println("qlog stand up on", addr)
	for {
		c, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		st := c.ConnectionState().TLS
		fmt.Println("accepted from", c.RemoteAddr(), "group", st.CurveID, "retry", st.HelloRetryRequest)
		// QSTAND_SERVE lets it in and feeds it: serve.go.
		if n, err := strconv.ParseInt(os.Getenv("QSTAND_SERVE"), 10, 64); err == nil && n > 0 {
			go serve(c, n)
		}
	}
}
