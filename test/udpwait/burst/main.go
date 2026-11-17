// burst -listen ADDR: answer a datagram "N" with N numbered datagrams of 1000 bytes, back to back.
// burst -ask ADDR N: send "N" from one socket, count what comes back within 3 s, and say whether in order.
package main

import (
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

func main() {
	listen := flag.String("listen", "", "")
	ask := flag.String("ask", "", "")
	n := flag.Int("n", 200, "")
	flag.Parse()
	if *listen != "" {
		a, _ := net.ResolveUDPAddr("udp", *listen)
		c, err := net.ListenUDP("udp", a)
		if err != nil {
			panic(err)
		}
		b := make([]byte, 2048)
		for {
			m, from, err := c.ReadFromUDP(b)
			if err != nil {
				continue
			}
			k, _ := strconv.Atoi(strings.TrimSpace(string(b[:m])))
			for i := 0; i < k; i++ {
				p := []byte(fmt.Sprintf("%06d:", i))
				p = append(p, make([]byte, 1000-len(p))...)
				c.WriteToUDP(p, from)
				time.Sleep(500 * time.Microsecond)
			}
		}
	}
	a, _ := net.ResolveUDPAddr("udp", *ask)
	c, err := net.DialUDP("udp", nil, a)
	if err != nil {
		panic(err)
	}
	c.SetReadBuffer(4 << 20)
	c.Write([]byte(strconv.Itoa(*n)))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, inorder, last := 0, true, -1
	b := make([]byte, 2048)
	for {
		m, err := c.Read(b)
		if err != nil {
			break
		}
		i, _ := strconv.Atoi(string(b[:6]))
		if m != 1000 || i <= last {
			inorder = false
		}
		last = i
		got++
	}
	fmt.Printf("%d of %d back, in order: %v\n", got, *n, inorder)
}
