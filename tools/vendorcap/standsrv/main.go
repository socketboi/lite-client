// The target end of a throughput stand: an HTTP source of arbitrary size and a UDP echo, in one
// program.
//
// WHY BOTH ROLES IN ONE BINARY, and why it must sit BEHIND the node. Measuring a tunnel against
// something on the open internet measures the internet: the far side's congestion control, its
// peering, its rate limits. What a tunnel measurement needs is a target whose only path from the
// client runs through the node, so that every byte counted crossed the thing under test. One
// binary, because the TCP and UDP paths through this client are different code — Vision splice on
// one side, xudp framing on the other — and comparing them is only meaningful when the far end is
// identical.
//
//   go build -o /tmp/standsrv .
//   /tmp/standsrv 0.0.0.0:18080 0.0.0.0:18081     # http, udp echo
//
// Then, from behind the tunnel:
//
//   curl -o /dev/null -w '%{speed_download}\n' http://<node-public-ip>:18080/bytes/50000000
//   /tmp/udpbench <node-public-ip>:18081 2000 1200
//
// ⚠️ THE TARGET MUST BE NAMED BY ITS PUBLIC ADDRESS, not by a private one. Xray's `freedom`
// outbound refuses private destinations, and the refusal reads as a client failure: the node logs
// `blocked target: tcp:10.99.2.1:18080` while the client simply reports that nothing came back.
// Bind wherever you like; ADDRESS it publicly.
//
// ⚠️ AND THE PORTS MUST ACTUALLY BE OPEN on the node. Exposing 18080/18081 to the internet for the
// duration of a measurement is what this costs; close them afterwards.
package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
)

func main() {
	httpAddr := "0.0.0.0:18080"
	udpAddr := "0.0.0.0:18081"
	if len(os.Args) > 1 {
		httpAddr = os.Args[1]
	}
	if len(os.Args) > 2 {
		udpAddr = os.Args[2]
	}

	go func() {
		pc, err := net.ListenPacket("udp", udpAddr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "udp:", err)
			return
		}
		fmt.Println("udp echo on", udpAddr)
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], from)
		}
	}()

	// /bytes/<N> returns exactly N bytes. Zeros: there is nothing to compress, and this client
	// compresses nothing, so what is measured is the tunnel rather than the content.
	http.HandleFunc("/bytes/", func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/bytes/"))
		if err != nil || n < 0 || n > 1<<30 {
			http.Error(w, "bad size", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(n))
		chunk := make([]byte, 64*1024)
		for n > 0 {
			k := len(chunk)
			if k > n {
				k = n
			}
			if _, err := w.Write(chunk[:k]); err != nil {
				return
			}
			n -= k
		}
	})
	fmt.Println("http on", httpAddr)
	_ = http.ListenAndServe(httpAddr, nil)
}
