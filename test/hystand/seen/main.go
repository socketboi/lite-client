// What the far end SEES: a UDP responder that answers with the source address the datagram arrived
// from, and the probe that reads those answers back.
//
// This exists for one question, and it is the last open one about the UDP path: how many sessions a
// client opens decides how many sockets the NODE opens, because the node keys its session map by the
// SessionID the client chose and dials one socket per session
// (vendor/hysteria/core/server/udp.go:309-340). One session for everything means every destination
// sees the same source port — an endpoint-independent mapping, which is what a game or a call needs
// to work through a NAT. A session per pair means a different port per destination, which is the
// mapping those applications fail on.
//
// So the answer is read off the far end rather than argued from the code: send from two local
// sockets and look at what the responder reports.
//
//	seen -listen :9101          answer every datagram with the source it came from
//	seen -probe 127.0.0.1:5301  send from two sockets and print both answers
//	seen -many 127.0.0.1:5301,100  send from that many sockets at once, count the answers
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	listen := flag.String("listen", "", "answer datagrams on this address")
	probe := flag.String("probe", "", "send from two sockets to this address and print the answers")
	pair := flag.String("pair", "", "send from ONE socket to these two addresses and print the answers")
	many := flag.String("many", "", "ADDR,N: send from N sockets at once and count the answers")
	flag.Parse()

	switch {
	case *listen != "":
		serve(*listen)
	case *probe != "":
		send(*probe)
	case *pair != "":
		sendPair(*pair)
	case *many != "":
		sendMany(*many)
	default:
		fmt.Fprintln(os.Stderr, "seen: -listen or -probe is required")
		os.Exit(2)
	}
}

func serve(addr string) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "seen: listen:", err)
		os.Exit(1)
	}
	buf := make([]byte, 2048)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		_ = n
		if _, err := pc.WriteTo([]byte(from.String()), from); err != nil {
			return
		}
	}
}

func send(addr string) {
	to, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "seen: resolve:", err)
		os.Exit(1)
	}

	// Two sockets, because the question is whether two of them come out of the node as one source
	// or as two. Sequential rather than concurrent: a tunnel that opens its session lazily should
	// have finished with the first before the second starts, so that what is measured is the
	// session model and not a race.
	for i := 1; i <= 2; i++ {
		c, err := net.DialUDP("udp", nil, to)
		if err != nil {
			fmt.Fprintln(os.Stderr, "seen: dial:", err)
			os.Exit(1)
		}
		if _, err := c.Write([]byte("who am I")); err != nil {
			fmt.Fprintln(os.Stderr, "seen: write:", err)
			os.Exit(1)
		}
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 256)
		n, err := c.Read(buf)
		if err != nil {
			fmt.Printf("socket %d: no answer (%v)\n", i, err)
			c.Close()
			continue
		}
		fmt.Printf("socket %d: the far end saw %s\n", i, string(buf[:n]))
		c.Close()
		time.Sleep(300 * time.Millisecond)
	}
}

// One socket, two destinations, which is the axis the session models differ on: a client that opens
// a session per destination gets two sockets at the node and two source ports at the far end; one
// that carries every destination in one session gets one of each.
func sendPair(spec string) {
	addrs := strings.Split(spec, ",")
	if len(addrs) != 2 {
		fmt.Fprintln(os.Stderr, "seen: -pair wants two addresses separated by a comma")
		os.Exit(2)
	}

	c, err := net.ListenPacket("udp", ":0")
	if err != nil {
		fmt.Fprintln(os.Stderr, "seen: listen:", err)
		os.Exit(1)
	}
	defer c.Close()

	for i, a := range addrs {
		to, err := net.ResolveUDPAddr("udp", a)
		if err != nil {
			fmt.Fprintln(os.Stderr, "seen: resolve:", err)
			os.Exit(1)
		}
		if _, err := c.WriteTo([]byte("who am I"), to); err != nil {
			fmt.Fprintln(os.Stderr, "seen: write:", err)
			os.Exit(1)
		}
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 256)
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			fmt.Printf("destination %d (%s): no answer (%v)\n", i+1, a, err)
			continue
		}
		fmt.Printf("destination %d (%s): the far end saw %s\n", i+1, a, string(buf[:n]))
		time.Sleep(300 * time.Millisecond)
	}
}

// N sockets at once, every one of them kept open until its answer is in, which makes N sessions in
// a client that opens one per local socket — what a resolver asking from a fresh port each time
// looks like, or a browser with a dozen HTTP/3 connections. The number that matters is how many
// are answered: a client with a ceiling on sessions answers that many and loses the rest.
func sendMany(spec string) {
	parts := strings.Split(spec, ",")
	var n int
	if len(parts) != 2 {
		fmt.Fprintln(os.Stderr, "seen: -many wants ADDR,N")
		os.Exit(2)
	}
	if _, err := fmt.Sscan(parts[1], &n); err != nil || n <= 0 {
		fmt.Fprintln(os.Stderr, "seen: -many wants ADDR,N")
		os.Exit(2)
	}
	to, err := net.ResolveUDPAddr("udp", parts[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "seen: resolve:", err)
		os.Exit(1)
	}
	conns := make([]*net.UDPConn, n)
	for i := range conns {
		c, err := net.DialUDP("udp", nil, to)
		if err != nil {
			fmt.Fprintln(os.Stderr, "seen: dial:", err)
			os.Exit(1)
		}
		defer c.Close()
		conns[i] = c
		c.Write([]byte("who am I"))
	}
	answered := make(chan string, n)
	for _, c := range conns {
		go func(c *net.UDPConn) {
			buf := make([]byte, 256)
			// Asked again every second, as a resolver retries: a first datagram lost on the way
			// is not a session refused.
			for try := 0; try < 8; try++ {
				c.SetReadDeadline(time.Now().Add(time.Second))
				if k, err := c.Read(buf); err == nil {
					answered <- string(buf[:k])
					return
				}
				c.Write([]byte("who am I"))
			}
			answered <- ""
		}(c)
	}
	got, seen := 0, map[string]bool{}
	for range conns {
		if a := <-answered; a != "" {
			got++
			seen[a] = true
		}
	}
	fmt.Printf("%d sockets at once: %d answered, from %d sources at the far end\n", n, got, len(seen))
}
