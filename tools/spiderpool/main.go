// Command spiderpool prints what the reference's spider writes on its one connection when a
// redirect sends it to another name: the next request on the connection it has, a second opening, or
// the connection closed.
//
// It runs the reference's own client — net/http of Go 1.27 under x/net's http2.Transport, built as
// Xray v26.9.9 builds its spider's (vendor/Xray-core/transport/internet/reality/reality.go:210-219),
// whose DialTLSContext hands back the one TLS connection whatever it is asked for — against a site
// that answers every request with the next Location of a chain. What the site sees is the vector:
//
//	R<authority>  a request on the ClientConns it has
//	P             a connection preface in the middle of the connection: a dial, and AddConn put a
//	              new ClientConn on the one connection
//	H             after P: a request on that new ClientConn
//	C             the client closed the connection
//	D             Do returned, and the connection is still open
//
// A chain stops at C, at the event after P — the site could not answer any further — or at D.
// The keys behind it are in reality/fetch.c, get_client_conn; test/fetch holds the fetch to these.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// The site: the preface, its SETTINGS, and a 302 to the next Location for every request — a 200 once
// they run out — until something other than a request comes.
func site(c net.Conn, locs []string, ev chan<- string) {
	defer c.Close()
	br := bufio.NewReader(c)
	pre := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(br, pre); err != nil {
		return
	}
	fr := http2.NewFramer(c, nil)
	fr.WriteSettings()
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	dec := hpack.NewDecoder(4096, nil)
	next, afterP := 0, false
	for {
		h, err := br.Peek(9)
		if err != nil {
			// The client closed: EOF, or a reset when it had not read all the site wrote. What
			// it wrote before the close has been read, so the order holds.
			ev <- "C"
			return
		}
		if string(h) == http2.ClientPreface[:9] {
			if _, err := io.ReadFull(br, pre); err != nil || string(pre) != http2.ClientPreface {
				return
			}
			ev <- "P"
			afterP = true
			continue
		}
		n := int(h[0])<<16 | int(h[1])<<8 | int(h[2])
		typ, flags, stream := h[3], h[4], binary.BigEndian.Uint32(h[5:])&0x7fffffff
		frame := make([]byte, 9+n)
		if _, err := io.ReadFull(br, frame); err != nil {
			return
		}
		p := frame[9:]
		switch {
		case typ == 0x1 && afterP:
			ev <- "H"
			return
		case typ == 0x1:
			authority := ""
			fs, err := dec.DecodeFull(p)
			if err != nil {
				return
			}
			for _, f := range fs {
				if f.Name == ":authority" {
					authority = f.Value
				}
			}
			ev <- "R" + authority
			hb.Reset()
			if next < len(locs) {
				enc.WriteField(hpack.HeaderField{Name: ":status", Value: "302"})
				enc.WriteField(hpack.HeaderField{Name: "location", Value: locs[next]})
				next++
			} else {
				enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
			}
			enc.WriteField(hpack.HeaderField{Name: "content-length", Value: "0"})
			fr.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, BlockFragment: hb.Bytes(),
				EndHeaders: true, EndStream: true})
		case typ == 0x4 && flags&0x1 == 0 && !afterP:
			fr.WriteSettingsAck()
		}
	}
}

func run(host string, locs []string) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	ev := make(chan string, 64)
	go func() {
		if c, err := ln.Accept(); err == nil {
			site(c, locs, ev)
		}
	}()
	// The one connection, which the dial hands out whatever it is asked for.
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	client := &http.Client{
		Transport: &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				return conn, nil
			},
		},
	}
	// The request's context only so that a Do left going round (see fetch.c) stops with the run.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+host+"/", nil)
	if err != nil {
		return ""
	}
	go func() {
		if resp, err := client.Do(req); err == nil {
			resp.Body.Close()
		}
		ev <- "D"
	}()
	// A close by the client comes before Do can return for it, but the site reads it later: after D,
	// what the site has still to say is waited for, and C, when it comes, stands for both.
	var out []string
	var grace <-chan time.Time
	for {
		select {
		case e := <-ev:
			if e == "D" {
				grace = time.After(500 * time.Millisecond)
				continue
			}
			out = append(out, e)
			if e == "C" || len(out) > 1 && out[len(out)-2] == "P" {
				return strings.Join(out, "|")
			}
		case <-grace:
			return strings.Join(append(out, "D"), "|")
		case <-time.After(20 * time.Second):
			panic("no end to " + host + " " + strings.Join(locs, " "))
		}
	}
}

func cstr(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' || c == '\\' || c < 0x20 || c >= 0x7f || c == '?' {
			fmt.Fprintf(&b, "\\%03o", c)
		} else {
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// Names that ToASCII and idna.Lookup make the same, and names where they part: case, a letter
// Lookup maps, one it refuses, an IP, a port.
var hosts = []string{
	"www.example.com", "WWW.EXAMPLE.COM", "Www.Example.Com", "wwé.example", "WWÉ.example",
	"xn--ww-cja.example", "XN--WW-CJA.example", "ｗｗｗ.example", "faß.de", "a_b.example",
	"é_b.example", "127.0.0.1", "[::1]", "www.example.com:443", "www.example.com:8443",
}

func main() {
	type chain struct {
		host string
		locs []string
	}
	var chains []chain
	for _, h := range hosts {
		chains = append(chains, chain{h, []string{"/next"}})
		for _, to := range hosts {
			chains = append(chains, chain{h, []string{"https://" + to + "/next"}})
		}
	}
	chains = append(chains,
		chain{"www.example.com", []string{"https://wwé.example/", "https://WWÉ.example/"}},
		chain{"wwé.example", []string{"https://other.example/", "https://WWÉ.example/"}},
		chain{"wwé.example", []string{"/a", "/b", "https://xn--ww-cja.example/c"}},
		chain{"WWW.EXAMPLE.COM", []string{"https://www.example.com/a", "https://WWW.EXAMPLE.COM/b"}},
		chain{"www.example.com", []string{"https://WWÉ.example/", "https://wwé.example/"}},
	)
	res := make([]string, len(chains))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, c := range chains {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			res[i] = run(c.host, c.locs)
			<-sem
		}()
	}
	wg.Wait()
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	fmt.Fprintln(w, "/* Generated by tools/spiderpool from the reference's own net/http and x/net. */")
	fmt.Fprintln(w, "static const struct { const char *host, *locs[4], *events; } spiderpool[] = {")
	for i, c := range chains {
		fmt.Fprintf(w, "    { %s, {", cstr(c.host))
		for _, l := range c.locs {
			fmt.Fprintf(w, " %s,", cstr(l))
		}
		fmt.Fprintf(w, " NULL }, %s },\n", cstr(res[i]))
	}
	fmt.Fprintln(w, "};")
}
