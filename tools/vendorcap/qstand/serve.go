package main

// QSTAND_SERVE=BYTES: past the handshake, as far as a download.
//
// Everything main.go records ends with the first flight — both clients fail to authenticate here.
// What a client does once it carries data — the receive windows it advertises and when it grows
// them, the Connection ID it moves to, the order of its first streams — needs a server that lets it
// in. This is the least of hysteria's server that does: the authentication answered 233 with the
// reference's headers (vendor/hysteria/core/internal/protocol/http.go:8-17, :60-68), and a TCP
// request (vendor/hysteria/core/internal/protocol/proxy.go:32-67) answered OK and followed by BYTES
// of data, which is what makes the client's windows move. The stream dispatch is hysteria's own
// shape (ProxyStreamHijacker, vendor/hysteria/core/server/server.go:240-259): the frame type is
// only peeked, so the 0x401 is read off before the request.
//
// Not a hysteria server: no password is checked, nothing is proxied, and the bytes come from here.
// It is the same quic-go, with the same qlog tracer, so the record is still the reference's.

import (
	"bufio"
	"fmt"
	"io"
	"net/http"

	quic "github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"
)

func serve(c *quic.Conn, n int64) {
	h3 := http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.Host != "hysteria" || r.URL.Path != "/auth" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Hysteria-UDP", "true")
			w.Header().Set("Hysteria-CC-RX", "auto")
			w.Header().Set("Hysteria-Padding", "qstand")
			w.WriteHeader(233)
		}),
		StreamDispatcher: func(ft http3.FrameType, str *quic.Stream, err error) (bool, error) {
			if err != nil || ft != 0x401 {
				return false, nil
			}
			go tcp(str, n)
			return true, nil
		},
	}
	fmt.Println("serving", c.RemoteAddr(), "until it goes:", h3.ServeQUICConn(c))
}

func tcp(str *quic.Stream, n int64) {
	defer str.Close()
	br := bufio.NewReader(str)
	if _, err := quicvarint.Read(quicvarint.NewReader(br)); err != nil { // 0x401
		return
	}
	addr, err := readTCPRequest(br)
	if err != nil {
		return
	}
	// WriteTCPResponse (proxy.go:131-149): OK, no message, no padding.
	if _, err := str.Write([]byte{0, 0, 0}); err != nil {
		return
	}
	var buf [32 << 10]byte
	sent, err := io.CopyBuffer(str, io.LimitReader(zeros{}, n), buf[:])
	fmt.Println("tcp", addr, "sent", sent, err)
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// readTCPRequest is ReadTCPRequest (vendor/hysteria/core/internal/protocol/proxy.go:39-67) without
// its bounds: the peer is ours.
func readTCPRequest(br *bufio.Reader) (string, error) {
	r := quicvarint.NewReader(br)
	alen, err := quicvarint.Read(r)
	if err != nil {
		return "", err
	}
	addr := make([]byte, alen)
	if _, err := io.ReadFull(br, addr); err != nil {
		return "", err
	}
	plen, err := quicvarint.Read(r)
	if err != nil {
		return "", err
	}
	_, err = io.CopyN(io.Discard, br, int64(plen))
	return string(addr), err
}
