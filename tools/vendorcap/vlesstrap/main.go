// A TLS server that prints the plaintext a VLESS client writes into it.
//
// Everything Xray sends inside the tunnel — the VLESS request header, the Vision padding frames,
// the xudp frames around datagrams — is written into a TLS stream. Terminate that stream and the
// formats are simply there, in order, with no protocol implementation needed on this side.
//
// ⚠️ REALITY IS NOT NEEDED AND WOULD ONLY BE IN THE WAY. The request is written by
// encoding.EncodeRequestHeader, which knows nothing of the transport beneath it, so `security: tls`
// captures exactly the same bytes a REALITY connection would carry. Standing up a REALITY server to
// read them would be a day's work to learn nothing extra.
//
// USAGE, from the repository root, inside the build image:
//
//	go build -o /tmp/vlesstrap ./tools/vendorcap/vlesstrap
//	openssl req -x509 -newkey rsa:2048 -keyout /tmp/vk.pem -out /tmp/vc.pem -days 2 -nodes \
//	    -subj "/CN=trap.local" -addext "subjectAltName=DNS:trap.local"
//	/tmp/vlesstrap 127.0.0.1:14460 &
//
// then run Xray (built from source) as a client at it. The configuration that matters:
//
//	"outbounds": [{ "protocol": "vless",
//	  "settings": { "vnext": [{ "address": "127.0.0.1", "port": 14460,
//	    "users": [{ "id": "<uuid>", "encryption": "none", "flow": "xtls-rprx-vision" }] }]},
//	  "streamSettings": { "network": "tcp", "security": "tls",
//	    "tlsSettings": { "serverName": "trap.local", "pinnedPeerCertSha256": "<hex>" } },
//	  "mux": { "enabled": false, "concurrency": -1, "xudpConcurrency": 1 } }]
//
// ⚠️ `allowInsecure` NO LONGER EXISTS in Xray — it refuses to start and names the replacement. The
// self-signed certificate is accepted through `pinnedPeerCertSha256`, and that is sha256 over the
// WHOLE certificate DER (transport/internet/tls/pin.go:10-16), hex, NOT the SPKI hash this project
// pins with elsewhere:
//
//	openssl x509 -in /tmp/vc.pem -outform der | openssl dgst -sha256 -hex
//
// ⚠️ FOR UDP, THE INBOUND DECIDES WHAT YOU MEASURE, and getting this wrong produces a confident
// wrong answer. Xray writes the eight-byte global id only `if b.UDP != nil` — only when the packet
// carries its own destination. A dokodemo-door with a FIXED address does not, so it yields twelve
// bytes of xudp metadata and looks like the client omits the id. A socks inbound with `udp: true`,
// driven by a client doing UDP ASSOCIATE, yields twenty and the id is present and non-zero. A
// transparent interceptor is the second case, not the first.
//
// Reads are printed one line each, hex, because a frame boundary and a read boundary are not the
// same thing and pretending otherwise is how the format gets mis-read. Four reads is enough for a
// request plus a first frame; raise it if a capture ends mid-frame — and RETAKE rather than
// completing one by hand, since the Vision padding length is drawn per connection and a
// hand-finished capture stops being a measurement.
package main

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	addr := "127.0.0.1:14460"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	cert, err := tls.LoadX509KeyPair("/tmp/vc.pem", "/tmp/vk.pem")
	if err != nil {
		fmt.Fprintln(os.Stderr, "cert:", err)
		os.Exit(1)
	}
	ln, err := tls.Listen("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	upstream := ""
	if len(os.Args) > 2 {
		upstream = os.Args[2]
	}
	fmt.Println("vless trap up on", addr, "upstream", upstream)
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		if upstream == "" {
			go dump(c)
		} else {
			go relay(c, upstream)
		}
	}
}

// Terminate and print, nothing more. Enough for the request header and a first frame; the client's
// inner TLS never completes, so nothing after the first flight is ever seen.
func dump(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 8192)
	for i := 0; i < 4; i++ {
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := c.Read(buf)
		if n > 0 {
			fmt.Printf("READ %d %s\n", n, hex.EncodeToString(buf[:n]))
		}
		if err != nil {
			return
		}
	}
}

// Sit BETWEEN two references and copy, printing both directions.
//
// This is the mode that sees what terminating cannot. A trap that only terminates never lets the
// inner TLS complete, so the capture stops after the client's first flight — and several things
// only exist after it: the long-padding branch (`longPadding := trafficState.IsTLS`, which needs
// the inner handshake to have been recognised AND a frame under 900 bytes), the switch out of
// padding on the first ApplicationData record, and every frame the SERVER sends.
//
// The client pins this trap's certificate, so a real man in the middle is exactly what is wanted
// here: terminate towards the client with our certificate, open our own TLS towards a real Xray
// server, and copy. Both halves are the reference; only the wire between them is ours to read.
//
// InsecureSkipVerify is on the UPSTREAM leg only, and is correct: the upstream is a stand server
// with a self-signed certificate started seconds ago by the same script.
func relay(c net.Conn, upstream string) {
	defer c.Close()
	up, err := tls.Dial("tcp", upstream, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		fmt.Fprintln(os.Stderr, "upstream:", err)
		return
	}
	defer up.Close()

	done := make(chan struct{}, 2)
	go copyPrinting("UP", c, up, done)   // client -> server
	go copyPrinting("DOWN", up, c, done) // server -> client
	<-done
}

func copyPrinting(tag string, from, to net.Conn, done chan struct{}) {
	defer func() { done <- struct{}{} }()
	buf := make([]byte, 16384)
	for {
		_ = from.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := from.Read(buf)
		if n > 0 {
			fmt.Printf("%s %d %s\n", tag, n, hex.EncodeToString(buf[:n]))
			if _, werr := to.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}
