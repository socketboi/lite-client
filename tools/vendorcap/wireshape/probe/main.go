package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func last(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.LastIndex(s, "\n"); i >= 0 {
		s = s[i+1:]
	}
	return s
}

func tcp(addr string, wait time.Duration) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		fmt.Println("dial:", err)
		return
	}
	defer c.Close()
	time.Sleep(wait)
	c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprint(c, "GET / HTTP/1.0\r\nHost: t\r\n\r\n")
	b, err := io.ReadAll(bufio.NewReader(c))
	if s := last(b); s != "" {
		fmt.Println(s)
		return
	}
	fmt.Println("nothing back:", err)
}

// Asks, waits two seconds, then reads slowly — 8 KB a millisecond — so what the far end sends piles up
// in front of it and stays piled. The nodealert stand's `closeslow` needs a client that is behind
// for the whole of it, so that the node's close_notify is taken while records still wait for room;
// a reader that catches up at full speed once it starts empties the queue first, and then nothing
// past the close_notify is ever looked at, right or wrong. (It empties anyway on loopback — see
// closeslow in the nodealert stand — so this is the nearest the stand gets, not the state itself.)
func late(addr string) {
	// A 4 KB receive buffer, set before connect so it bounds the window: the sender's socket then
	// fills and takes a flush in pieces, which is the state closeslow is after.
	d := net.Dialer{Timeout: 5 * time.Second, Control: func(_, _ string, rc syscall.RawConn) error {
		return rc.Control(func(fd uintptr) { syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4096) })
	}}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		fmt.Println("dial:", err)
		return
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(60 * time.Second))
	fmt.Fprint(c, "GET / HTTP/1.0\r\nHost: t\r\n\r\n")
	time.Sleep(2 * time.Second)
	var b []byte
	buf := make([]byte, 8192)
	for {
		n, err := c.Read(buf)
		b = append(b, buf[:n]...)
		if err != nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if s := last(b); s != "" {
		fmt.Printf("%s (%d bytes)\n", s, len(b))
		return
	}
	fmt.Println("nothing back")
}

// Asks, then pushes 48 MB up and a last line "END" while it reads what comes back. The nodealert
// stand's `kufull` needs the way to the node full when its KeyUpdate arrives: the node reads none of
// this for two seconds, and 48 MB is more than the sockets on the way hold.
func up(addr string) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		fmt.Println("dial:", err)
		return
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(60 * time.Second))
	go func() {
		fmt.Fprint(c, "GET / HTTP/1.0\r\nHost: t\r\n\r\n")
		chunk := []byte(strings.Repeat("a", 65536))
		for i := 0; i < 768; i++ {
			if _, err := c.Write(chunk); err != nil {
				return
			}
		}
		fmt.Fprint(c, "END\n")
	}()
	b, err := io.ReadAll(bufio.NewReader(c))
	if s := last(b); s != "" {
		fmt.Println(s)
		return
	}
	fmt.Println("nothing back:", err)
}

func big(addr string, useTLS bool) {
	var c net.Conn
	var err error
	d := &net.Dialer{Timeout: 5 * time.Second}
	if useTLS {
		c, err = tls.DialWithDialer(d, "tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "t", MinVersion: tls.VersionTLS13})
	} else {
		c, err = d.Dial("tcp", addr)
	}
	if err != nil {
		fmt.Println("dial:", err)
		return
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))
	body := strings.Repeat("a", 300000)
	fmt.Fprintf(c, "POST / HTTP/1.0\r\nHost: t\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	b, err := io.ReadAll(bufio.NewReader(c))
	if s := last(b); s != "" {
		fmt.Println(s)
		return
	}
	fmt.Println("nothing back:", err)
}

// THE DIRECTION THE STAND DID NOT HAVE, and it is the one that carries the traffic: on the live
// router this client moved 1.86 GB down against 51 MB up in fourteen hours. Every scenario here was
// an upload — `big` posts 300 KB and reads a one-line answer — so what a path sees of this client
// while somebody is actually downloading had never been compared with the reference at all.
//
// The request is small and the answer is 300 KB, which is `big` turned around; everything else about
// it is deliberately the same, so the two can be read side by side.
func down(addr string, useTLS bool) {
	var c net.Conn
	var err error
	d := &net.Dialer{Timeout: 5 * time.Second}
	if useTLS {
		c, err = tls.DialWithDialer(d, "tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "t", MinVersion: tls.VersionTLS13})
	} else {
		c, err = d.Dial("tcp", addr)
	}
	if err != nil {
		fmt.Println("dial:", err)
		return
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))
	fmt.Fprintf(c, "GET /down?bytes=300000 HTTP/1.0\r\nHost: t\r\n\r\n")
	b, err := io.ReadAll(bufio.NewReader(c))
	if len(b) > 0 {
		fmt.Printf("down %d bytes\n", len(b))
		return
	}
	fmt.Println("nothing back:", err)
}

func main() {
	switch os.Args[1] {
	case "tcpdown":
		down(os.Args[2], false)
	case "tlsdown":
		down(os.Args[2], true)
	case "tcp":
		tcp(os.Args[2], 0)
	case "tcplate":
		late(os.Args[2])
	case "tcpup":
		up(os.Args[2])
	case "tcpslow":
		tcp(os.Args[2], 1200*time.Millisecond)
	case "tcpbig":
		big(os.Args[2], false)
	case "tlsbig":
		big(os.Args[2], true)
	case "udpsize":
		size, _ := strconv.Atoi(os.Args[3])
		c, err := net.Dial("udp", os.Args[2])
		if err != nil {
			fmt.Println("dial:", err)
			return
		}
		defer c.Close()
		c.Write([]byte(strings.Repeat("u", size)))
		c.SetDeadline(time.Now().Add(4 * time.Second))
		b := make([]byte, 65536)
		n, err := c.Read(b)
		if err != nil {
			fmt.Printf("udp %d: nothing back\n", size)
			return
		}
		fmt.Printf("udp %d: %d back\n", size, n)
	case "udp", "udpburst":
		n := 1
		if len(os.Args) > 3 {
			n, _ = strconv.Atoi(os.Args[3])
		}
		c, err := net.Dial("udp", os.Args[2])
		if err != nil {
			fmt.Println("dial:", err)
			return
		}
		defer c.Close()
		for i := 0; i < n; i++ {
			c.Write([]byte(fmt.Sprintf("ping-%02d-%s", i, strings.Repeat("x", 40))))
		}
		c.SetDeadline(time.Now().Add(6 * time.Second))
		got := 0
		b := make([]byte, 512)
		for got < n {
			if _, err := c.Read(b); err != nil {
				break
			}
			got++
		}
		fmt.Printf("udp: %d of %d echoed\n", got, n)
	}
}
