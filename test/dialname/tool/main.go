// The dialname stand's helper, three commands:
//
//	echo ADDR          a TCP echo server: what the tunnels carry to
//	hole ADDR          a listener whose accept queue is full, so every SYN to ADDR is dropped
//	ask  ADDR          one connection through a tunnel: writes four bytes, reads them back, and
//	                   prints "ok <ms>" or "fail <ms> <why>", the milliseconds from the connect
//
// A connect to a hole is what a black-holed path looks like to the dialer — no answer at all, so
// only its clock ends it — and it needs no firewall in the container: Linux drops a SYN whose
// listener's accept queue is full (tcp_conn_request, "sk_acceptq_is_full"). With a backlog of zero
// one connection nobody accepts fills it.
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: tool echo|hole|ask ADDR")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "echo":
		echo(os.Args[2])
	case "hole":
		hole(os.Args[2])
	case "ask":
		ask(os.Args[2])
	default:
		os.Exit(2)
	}
}

func echo(addr string) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}()
	}
}

func hole(addr string) {
	ta, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	family := syscall.AF_INET
	var sa syscall.Sockaddr
	if ip4 := ta.IP.To4(); ip4 != nil {
		s := &syscall.SockaddrInet4{Port: ta.Port}
		copy(s.Addr[:], ip4)
		sa = s
	} else {
		family = syscall.AF_INET6
		s := &syscall.SockaddrInet6{Port: ta.Port}
		copy(s.Addr[:], ta.IP.To16())
		sa = s
	}
	fd, err := syscall.Socket(family, syscall.SOCK_STREAM, 0)
	if err == nil {
		_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		err = syscall.Bind(fd, sa)
	}
	if err == nil {
		err = syscall.Listen(fd, 0)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "hole:", err)
		os.Exit(1)
	}
	// The one connection that fills the queue, never accepted.
	filler, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hole: cannot fill:", err)
		os.Exit(1)
	}
	// And the proof that the next SYN goes unanswered.
	if c, err := net.DialTimeout("tcp", addr, 1500*time.Millisecond); err == nil {
		c.Close()
		fmt.Fprintln(os.Stderr, "hole: a connect went through")
		os.Exit(1)
	}
	fmt.Println("hole ready", addr)
	_ = filler
	select {}
}

func ask(addr string) {
	t0 := time.Now()
	ms := func() string { return strconv.FormatInt(time.Since(t0).Milliseconds(), 10) }
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		fmt.Println("fail", ms(), err)
		return
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(60 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		fmt.Println("fail", ms(), err)
		return
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		fmt.Println("fail", ms(), "no echo", err)
		return
	}
	fmt.Println("ok", ms())
}
