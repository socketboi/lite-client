// The DNS server both resolvers are pointed at: it logs every query it receives — transport, the
// server address it arrived on, the name, the type, the flags, the EDNS(0) record — with the time
// since it started, and answers as the scenario file says. It exists to hold lite-client's
// transcription of Go's resolver (src/net/goresolve.c) to Go's resolver itself, query for query.
//
//	stub SCENARIO_FILE LOG_FILE ADDR...
//
// A scenario line is `SERVER QNAME QTYPE ACTION [ARG...]`, `*` matching anything; the first line
// that matches decides. Actions:
//
//	a IP...          A records (AAAA for an IPv6 IP), in order
//	cname TARGET IP...  a CNAME from QNAME to TARGET, then A/AAAA records owned by TARGET
//	nx               NXDOMAIN
//	servfail         SERVFAIL
//	lame             NOERROR, no AA, no RA, nothing in any section
//	empty            NOERROR, RA, no answers
//	tc IP...         over UDP: TC set and no answers; over TCP: the records
//	drop             no answer at all
//	badid IP...      first a response with another ID, then the right one
//	wrongq IP...     first a response to another name, then the right one
//	shortA IP        an A record whose RDLENGTH says 2
//	garbage IP       a good A record, then an answer that does not unmarshal
//	twoq IP          two questions in the response
//	onlyaaaa IP6     answers an A query with an AAAA record
//	extnx            RCODE 0 in the header and an OPT raising it to 16: server misbehaving
package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"dnsstand/dnsmessage" // GOROOT's vendored copy, put beside this by run.sh
)

type rule struct {
	server, name, qtype, action string
	args                        []string
}

var (
	rules []rule
	logMu sync.Mutex
	logF  *os.File
	start = time.Now()
)

func logq(transport, server string, msg []byte) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return
	}
	q, err := p.Question()
	if err != nil {
		return
	}
	_ = p.SkipAllQuestions()
	_ = p.SkipAllAnswers()
	_ = p.SkipAllAuthorities()
	edns := "noedns"
	for {
		ah, err := p.AdditionalHeader()
		if err != nil {
			break
		}
		if ah.Type == dnsmessage.TypeOPT {
			edns = fmt.Sprintf("edns=%d,ttl=%d,len=%d", ah.Class, ah.TTL, ah.Length)
		}
		_ = p.SkipAdditional()
	}
	flags := ""
	if h.RecursionDesired {
		flags += "rd"
	}
	if h.AuthenticData {
		flags += "ad"
	}
	if h.CheckingDisabled {
		flags += "cd"
	}
	logMu.Lock()
	fmt.Fprintf(logF, "%d %s %s %s %s q=%d an=%d ns=%d ar=%d %s %s len=%d\n",
		time.Since(start).Milliseconds(), transport, server, q.Name.String(), q.Type,
		binary.BigEndian.Uint16(msg[4:]), binary.BigEndian.Uint16(msg[6:]),
		binary.BigEndian.Uint16(msg[8:]), binary.BigEndian.Uint16(msg[10:]), flags, edns, len(msg))
	logMu.Unlock()
}

func match(server string, q dnsmessage.Question) *rule {
	name := strings.ToLower(q.Name.String())
	qt := strings.TrimPrefix(q.Type.String(), "Type")
	for i := range rules {
		r := &rules[i]
		if (r.server == "*" || r.server == server) && (r.name == "*" || strings.ToLower(r.name) == name) &&
			(r.qtype == "*" || r.qtype == qt) {
			return r
		}
	}
	return nil
}

func records(b *dnsmessage.Builder, owner dnsmessage.Name, ips []string) {
	for _, s := range ips {
		ip := net.ParseIP(s)
		if ip == nil {
			continue
		}
		if v4 := ip.To4(); v4 != nil && !strings.Contains(s, ":") {
			var a [4]byte
			copy(a[:], v4)
			_ = b.AResource(dnsmessage.ResourceHeader{Name: owner, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: a})
		} else {
			var a [16]byte
			copy(a[:], ip.To16())
			_ = b.AAAAResource(dnsmessage.ResourceHeader{Name: owner, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AAAAResource{AAAA: a})
		}
	}
}

// build answers one query; nil means send nothing.
func build(req []byte, server string, tcp bool) [][]byte {
	var p dnsmessage.Parser
	h, err := p.Start(req)
	if err != nil {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	r := match(server, q)
	action, args := "empty", []string(nil)
	if r != nil {
		action, args = r.action, r.args
	}
	hdr := dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true}
	one := func(hh dnsmessage.Header, qq dnsmessage.Question, body func(b *dnsmessage.Builder)) []byte {
		b := dnsmessage.NewBuilder(nil, hh)
		_ = b.StartQuestions()
		_ = b.Question(qq)
		_ = b.StartAnswers()
		if body != nil {
			body(&b)
		}
		out, _ := b.Finish()
		return out
	}
	qtypeMatches := func(ip string) bool {
		isv6 := strings.Contains(ip, ":")
		return (q.Type == dnsmessage.TypeA && !isv6) || (q.Type == dnsmessage.TypeAAAA && isv6)
	}
	filter := func(ips []string) []string {
		var o []string
		for _, s := range ips {
			if qtypeMatches(s) {
				o = append(o, s)
			}
		}
		return o
	}
	switch action {
	case "drop":
		return nil
	case "nx":
		hdr.RCode = dnsmessage.RCodeNameError
		return [][]byte{one(hdr, q, nil)}
	case "servfail":
		hdr.RCode = dnsmessage.RCodeServerFailure
		return [][]byte{one(hdr, q, nil)}
	case "lame":
		hdr.RecursionAvailable = false
		return [][]byte{one(hdr, q, nil)}
	case "empty":
		return [][]byte{one(hdr, q, nil)}
	case "a":
		return [][]byte{one(hdr, q, func(b *dnsmessage.Builder) { records(b, q.Name, filter(args)) })}
	case "cname":
		target := dnsmessage.MustNewName(args[0])
		return [][]byte{one(hdr, q, func(b *dnsmessage.Builder) {
			_ = b.CNAMEResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.CNAMEResource{CNAME: target})
			records(b, target, filter(args[1:]))
		})}
	case "tc":
		if !tcp {
			hdr.Truncated = true
			return [][]byte{one(hdr, q, nil)}
		}
		return [][]byte{one(hdr, q, func(b *dnsmessage.Builder) { records(b, q.Name, filter(args)) })}
	case "badid":
		bad := hdr
		bad.ID ^= 0x5555
		return [][]byte{one(bad, q, func(b *dnsmessage.Builder) { records(b, q.Name, []string{"9.9.9.9"}) }),
			one(hdr, q, func(b *dnsmessage.Builder) { records(b, q.Name, filter(args)) })}
	case "wrongq":
		other := q
		other.Name = dnsmessage.MustNewName("other.example.")
		return [][]byte{one(hdr, other, func(b *dnsmessage.Builder) { records(b, other.Name, []string{"9.9.9.9"}) }),
			one(hdr, q, func(b *dnsmessage.Builder) { records(b, q.Name, filter(args)) })}
	case "shortA", "garbage":
		out := one(hdr, q, func(b *dnsmessage.Builder) { records(b, q.Name, filter(args)) })
		if q.Type != dnsmessage.TypeA || len(filter(args)) == 0 {
			return [][]byte{out}
		}
		if action == "shortA" {
			// RDLENGTH of the one A record: the two bytes before its four of data.
			binary.BigEndian.PutUint16(out[len(out)-6:], 2)
			return [][]byte{out}
		}
		// A second answer: a name with a reserved label prefix.
		binary.BigEndian.PutUint16(out[6:], 2)
		out = append(out, 0x80, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4)
		return [][]byte{out}
	case "twoq":
		b := dnsmessage.NewBuilder(nil, hdr)
		_ = b.StartQuestions()
		_ = b.Question(q)
		_ = b.Question(q)
		_ = b.StartAnswers()
		records(&b, q.Name, filter(args))
		out, _ := b.Finish()
		return [][]byte{out}
	case "onlyaaaa":
		return [][]byte{one(hdr, q, func(b *dnsmessage.Builder) { records(b, q.Name, args) })}
	case "extnx":
		// RCODE 0 in the header and an OPT whose extended bits make it 16 + 0: not NXDOMAIN, and not
		// success — "server misbehaving".
		b := dnsmessage.NewBuilder(nil, hdr)
		_ = b.StartQuestions()
		_ = b.Question(q)
		_ = b.StartAdditionals()
		var rh dnsmessage.ResourceHeader
		_ = rh.SetEDNS0(1232, dnsmessage.RCode(16), false)
		_ = b.OPTResource(rh, dnsmessage.OPTResource{})
		out, _ := b.Finish()
		return [][]byte{out}
	}
	return [][]byte{one(hdr, q, nil)}
}

func serveUDP(addr string) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	host, _, _ := net.SplitHostPort(addr)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req := append([]byte(nil), buf[:n]...)
			logq("udp", host, req)
			for _, out := range build(req, host, false) {
				_, _ = pc.WriteTo(out, from)
			}
		}
	}()
}

func serveTCP(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	host, _, _ := net.SplitHostPort(addr)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var l [2]byte
				if _, err := c.Read(l[:]); err != nil {
					return
				}
				req := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err := ioReadFull(c, req); err != nil {
					return
				}
				logq("tcp", host, req)
				outs := build(req, host, true)
				if len(outs) == 0 {
					time.Sleep(10 * time.Second)
					return
				}
				out := outs[len(outs)-1]
				var pre [2]byte
				binary.BigEndian.PutUint16(pre[:], uint16(len(out)))
				_, _ = c.Write(append(pre[:], out...))
			}(c)
		}
	}()
}

func ioReadFull(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := c.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func main() {
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 4 || strings.HasPrefix(fl[0], "#") {
			continue
		}
		rules = append(rules, rule{fl[0], fl[1], fl[2], fl[3], fl[4:]})
	}
	f.Close()
	logF, err = os.Create(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, a := range os.Args[3:] {
		serveUDP(a)
		serveTCP(a)
	}
	select {}
}
