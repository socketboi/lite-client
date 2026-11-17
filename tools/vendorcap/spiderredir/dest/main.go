// The site a REALITY node pretends to be, answering with redirects, and writing down everything the
// spider sends it — frame by frame, header lists in the order they arrived.
//
//	dest CERT KEY SCENARIO_FILE [ADDR]
//
// Each connection reads SCENARIO_FILE when it is accepted ("label scenario [sample]"), serves it with
// x/net's own HTTP/2 server — the one a Go site runs — over a connection that keeps a copy of every
// byte the client wrote, and when the server is done with the connection decodes that copy and
// prints it. The copy is decoded apart from the server so that it shows what was SENT, including
// what the server refused: a second connection preface in the middle of the stream, which is what
// x/net writes when a redirect leaves the host and its dialer hands it the same connection back.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type capture struct {
	net.Conn
	mu  sync.Mutex
	got []byte

	// closeafter: the connection is closed — close_notify, then FIN — the moment the server has
	// written the frame that ends stream 1, so that the page and the close reach the client together.
	closeAfter bool
	out        []byte
	closed     bool

	// DEST_TIMING=1: every Read and Write, in microseconds from the end of the handshake, with the
	// frames it completed — how long the client took to its first request, and what of the answer
	// it had seen when it acknowledged, cancelled or asked again.
	timing   bool
	t0       time.Time
	tr, tw   []byte // frame bytes not yet whole, each way
	skipPref int    // preface bytes still to pass over on the read side
	events   []string
}

// frames takes the whole frames off the front of *buf and names them: SETTINGS, SETTINGS-ack,
// WU0, HEADERS1, DATA1:5000, DATA1:0e (END_STREAM), RST1, and the type number for anything else.
func frames(buf *[]byte) string {
	var s []string
	for len(*buf) >= 9 {
		b := *buf
		l := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
		if len(b) < 9+l {
			break
		}
		typ, flags := b[3], b[4]
		sid := (uint32(b[5])<<24 | uint32(b[6])<<16 | uint32(b[7])<<8 | uint32(b[8])) & 0x7fffffff
		*buf = b[9+l:]
		switch typ {
		case 0:
			e := ""
			if flags&1 != 0 {
				e = "e"
			}
			s = append(s, fmt.Sprintf("DATA%d:%d%s", sid, l, e))
		case 1:
			e := ""
			if flags&1 != 0 {
				e = "e"
			}
			s = append(s, fmt.Sprintf("HEADERS%d%s", sid, e))
		case 3:
			s = append(s, fmt.Sprintf("RST%d", sid))
		case 4:
			if flags&1 != 0 {
				s = append(s, "SETTINGS-ack")
			} else {
				s = append(s, "SETTINGS")
			}
		case 7:
			s = append(s, "GOAWAY")
		case 8:
			s = append(s, fmt.Sprintf("WU%d", sid))
		default:
			s = append(s, fmt.Sprintf("T%d/%d", typ, sid))
		}
	}
	return strings.Join(s, ",")
}

func (c *capture) note(dir string, b []byte, completed time.Time) {
	if !c.timing || len(b) == 0 {
		return
	}
	var f string
	if dir == "r" {
		if c.skipPref > 0 {
			k := min(c.skipPref, len(b))
			c.skipPref -= k
			b = b[k:]
		}
		c.tr = append(c.tr, b...)
		f = frames(&c.tr)
	} else {
		c.tw = append(c.tw, b...)
		f = frames(&c.tw)
	}
	// I/O completion precedes capture's mutex wait and frame parsing. Keep that boundary
	// separate from observation overhead; the latter must not become client latency.
	c.events = append(c.events, fmt.Sprintf("%s+%d %s capture+%d", dir,
		completed.Sub(c.t0).Microseconds(), f, time.Since(completed).Microseconds()))
}

func (c *capture) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	var completed time.Time
	if c.timing {
		completed = time.Now()
	}
	if !c.timing && !c.closeAfter {
		return n, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.note("w", b[:n], completed)
	if !c.closeAfter || c.closed {
		return n, err
	}
	c.out = append(c.out, b[:n]...)
	for len(c.out) >= 9 {
		l := int(c.out[0])<<16 | int(c.out[1])<<8 | int(c.out[2])
		if len(c.out) < 9+l {
			break
		}
		typ, flags := c.out[3], c.out[4]
		sid := (uint32(c.out[5])<<24 | uint32(c.out[6])<<16 | uint32(c.out[7])<<8 | uint32(c.out[8])) & 0x7fffffff
		c.out = c.out[9+l:]
		if typ == 0 && flags&1 != 0 && sid == 1 {
			c.closed = true
			c.Conn.Close()
			break
		}
	}
	return n, err
}

func (c *capture) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	var completed time.Time
	if c.timing {
		completed = time.Now()
	}
	c.mu.Lock()
	c.got = append(c.got, b[:n]...)
	c.note("r", b[:n], completed)
	c.mu.Unlock()
	return n, err
}

// The server's close is put off: when it gives up on a connection — as it does at the first nine
// bytes of a second preface — what the client wrote after those bytes is still on its way, and the
// point is to see it. main drains the connection for half a second and closes it then.
func (c *capture) Close() error { return nil }

const page = "<!doctype html><html><body>final page, no links</body></html>"

// closeafter's page: twenty links, so that a harvest shows as the next connection's first path being
// one of them nearly always — the draw walks the set in Go's map order, which is not uniform, and
// "/" is one of twenty-one (vendor/Xray-core/transport/internet/reality/reality.go:271-277).
var linked = func() string {
	var b strings.Builder
	b.WriteString("<!doctype html><html><body>")
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&b, "<a href=\"/h%d\">%d</a>", i, i)
	}
	b.WriteString("</body></html>")
	return b.String()
}()

// What each scenario answers for a path; anything not listed is the final page.
func respond(scenario string, w http.ResponseWriter, r *http.Request) {
	redirect := func(code int, loc string, body int) {
		if loc != "" {
			w.Header().Set("Location", loc)
		}
		w.Header().Set("Content-Type", "text/html")
		if body > 0 {
			w.Header().Set("Content-Length", strconv.Itoa(body))
		}
		w.WriteHeader(code)
		if body > 0 {
			w.Write(bytes.Repeat([]byte("r"), body))
		}
	}
	p := r.URL.Path
	switch scenario {
	case "rel":
		if p == "/" {
			redirect(302, "/a", 0)
			return
		}
	case "abs":
		if p == "/" {
			redirect(301, "https://stand.example/b?q=1", 0)
			return
		}
	case "dots":
		if p == "/" {
			redirect(307, "x/../y/./z?k=v#frag", 0)
			return
		}
	case "schemeless":
		if p == "/" {
			redirect(308, "//stand.example/s", 0)
			return
		}
	case "chain":
		if p == "/" || strings.HasPrefix(p, "/c") {
			n := 0
			if strings.HasPrefix(p, "/c") {
				n, _ = strconv.Atoi(p[2:])
			}
			redirect(302, "/c"+strconv.Itoa(n+1), 0)
			return
		}
	case "cross":
		if p == "/" {
			redirect(302, "https://other.example/o", 0)
			return
		}
	case "sub":
		if p == "/" {
			redirect(302, "https://sub.stand.example/u", 0)
			return
		}
	case "http":
		if p == "/" {
			redirect(302, "http://stand.example/h", 0)
			return
		}
	case "noloc":
		if p == "/" {
			redirect(302, "", 0)
			return
		}
	case "smallbody":
		if p == "/" {
			redirect(302, "/sb", 1000)
			return
		}
	case "bigbody":
		if p == "/" {
			redirect(302, "/bb", 5000)
			return
		}
	case "see":
		if p == "/" {
			redirect(303, "/see", 0)
			return
		}
	case "gzbody", "gzsmall":
		// A redirect whose body is gzip: the slurp reads it through gzip.Reader, which takes the body
		// in bufio's fills of 4096 and stops at the deflate block that brings the output to 2 KiB.
		// Hex from a xorshift compresses to about half, so the large one is several blocks.
		if p == "/" {
			n := 300
			if scenario == "gzbody" {
				n = 60000
			}
			plain := make([]byte, n)
			x := uint32(2463534242)
			for i := range plain {
				x ^= x << 13
				x ^= x >> 17
				x ^= x << 5
				plain[i] = "0123456789abcdef"[x&15]
			}
			var gz bytes.Buffer
			zw := gzip.NewWriter(&gz)
			zw.Write(plain)
			zw.Close()
			w.Header().Set("Location", "/gz")
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(302)
			w.Write(gz.Bytes())
			return
		}
	case "closeafter":
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, linked)
		return
	case "latebody", "latebig":
		// The body a read after the answer: 1000 bytes the slurp waits for, 5000 it does not.
		if p == "/" {
			n := 1000
			if scenario == "latebig" {
				n = 5000
			}
			w.Header().Set("Location", "/late")
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Content-Length", strconv.Itoa(n))
			w.WriteHeader(302)
			w.(http.Flusher).Flush()
			time.Sleep(300 * time.Millisecond)
			w.Write(bytes.Repeat([]byte("r"), n))
			return
		}
	}
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, page)
}

const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// What the client wrote, decoded: the frames of each connection preface in turn, header lists
// in the order they came, values cut to what is worth reading.
func decode(label, scenario string, b []byte, timing []string, sample string) {
	out := &strings.Builder{}
	fmt.Fprintf(out, "%s %s | %d bytes\n", label, scenario, len(b))
	if sample != "" {
		fmt.Fprintf(out, "  sample %s\n", sample)
	}
	if len(b) >= 16 {
		fmt.Fprintf(out, "  tail % x\n", b[len(b)-16:])
	}
	cut := func(s string) string {
		if len(s) > 60 {
			return s[:60] + "…"
		}
		return s
	}
	for n := 1; len(b) > 0; n++ {
		if !bytes.HasPrefix(b, []byte(preface)) {
			if len(b) < len(preface) && strings.HasPrefix(preface, string(b)) {
				fmt.Fprintf(out, "  PREFACE #%d, cut after %d bytes\n", n, len(b))
			} else {
				fmt.Fprintf(out, "  %d bytes that are not a preface: %q\n", len(b), cut(string(b)))
			}
			break
		}
		fmt.Fprintf(out, "  PREFACE #%d\n", n)
		b = b[len(preface):]
		r := bytes.NewReader(b)
		fr := http2.NewFramer(nil, r)
		fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
		fr.MaxHeaderListSize = 1 << 20
		for {
			if rest := b[len(b)-r.Len():]; bytes.HasPrefix(rest, []byte(preface)) ||
				(len(rest) > 0 && len(rest) < len(preface) && strings.HasPrefix(preface, string(rest))) {
				break
			}
			f, err := fr.ReadFrame()
			if err != nil {
				if err != io.EOF {
					fmt.Fprintf(out, "  frame error: %v\n", err)
				}
				break
			}
			h := f.Header()
			fmt.Fprintf(out, "  [%d]", h.Length)
			switch f := f.(type) {
			case *http2.MetaHeadersFrame:
				var names []string
				for _, hf := range f.Fields {
					names = append(names, hf.Name)
				}
				fmt.Fprintf(out, "  HEADERS stream=%d end=%v order=%s\n", h.StreamID, f.StreamEnded(), strings.Join(names, ","))
				for _, hf := range f.Fields {
					{
						fmt.Fprintf(out, "    %s: %s\n", hf.Name, cut(hf.Value))
					}
				}
			case *http2.SettingsFrame:
				var s []string
				f.ForeachSetting(func(st http2.Setting) error { s = append(s, st.String()); return nil })
				fmt.Fprintf(out, "  SETTINGS ack=%v %s\n", f.IsAck(), strings.Join(s, " "))
			case *http2.WindowUpdateFrame:
				fmt.Fprintf(out, "  WINDOW_UPDATE stream=%d +%d\n", h.StreamID, f.Increment)
			case *http2.RSTStreamFrame:
				fmt.Fprintf(out, "  RST_STREAM stream=%d %v\n", h.StreamID, f.ErrCode)
			case *http2.PingFrame:
				fmt.Fprintf(out, "  PING ack=%v\n", f.IsAck())
			case *http2.GoAwayFrame:
				fmt.Fprintf(out, "  GOAWAY %v\n", f.ErrCode)
			default:
				fmt.Fprintf(out, "  %v stream=%d len=%d\n", h.Type, h.StreamID, h.Length)
			}
		}
		if rest := b[len(b)-r.Len():]; len(rest) > 0 && !bytes.HasPrefix(rest, []byte(preface)) &&
			!(len(rest) < len(preface) && strings.HasPrefix(preface, string(rest))) {
			fmt.Fprintf(out, "  %d bytes left undecoded: %q\n", len(rest), cut(string(rest)))
			break
		}
		b = b[len(b)-r.Len():]
	}
	if len(timing) != 0 {
		fmt.Fprintln(out, "  timing clock=io-return-v2")
	}
	for _, e := range timing {
		fmt.Fprintf(out, "  timing %s\n", e)
	}
	fmt.Print(out.String())
}

func scenarioSpec(b []byte) (label, scenario, sample string) {
	f := strings.Fields(string(b))
	if len(f) == 2 {
		return f[0], f[1], ""
	}
	if len(f) == 3 {
		n, err := strconv.Atoi(f[2])
		if err == nil && n >= 1 && n <= 20 && strconv.Itoa(n) == f[2] {
			return f[0], f[1], f[2]
		}
	}
	return "?", "none", ""
}

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "dest CERT KEY SCENARIO_FILE [ADDR]")
		os.Exit(2)
	}
	addr := "127.0.0.1:18444"
	if len(os.Args) > 4 {
		addr = os.Args[4]
	}
	cert, err := tls.LoadX509KeyPair(os.Args[1], os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "dest: certificate:", err)
		os.Exit(1)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"}}
	// DEST_TLS12=1: a site that serves TLS 1.2 and nothing else, as mail.ru did on 2026-08-18 — both
	// clients then fetch it over TLS 1.2 (T3).
	if os.Getenv("DEST_TLS12") != "" {
		cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// Neither end closes a spider's connection, so the server does, three seconds after the last
	// frame: what is measured is what the client sent before that, printed when the server is done.
	h2s := &http2.Server{IdleTimeout: 3 * time.Second}
	for {
		raw, err := ln.Accept()
		if err != nil {
			continue
		}
		go func() {
			label, scenario, sample := "?", "none", ""
			if b, err := os.ReadFile(os.Args[3]); err == nil {
				label, scenario, sample = scenarioSpec(b)
			}
			tc := tls.Server(raw, cfg)
			if err := tc.Handshake(); err != nil {
				// The node's own probes of the target, and anything else that is not a spider.
				tc.Close()
				return
			}
			c := &capture{Conn: tc, closeAfter: scenario == "closeafter",
				timing: os.Getenv("DEST_TIMING") != "", t0: time.Now(), skipPref: len(preface)}
			h2s.ServeConn(c, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				respond(scenario, w, r)
			})})
			tc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			io.Copy(io.Discard, c)
			tc.Close()
			c.mu.Lock()
			got := append([]byte(nil), c.got...)
			ev := append([]string(nil), c.events...)
			c.mu.Unlock()
			decode(label, scenario, got, ev, sample)
		}()
	}
}
