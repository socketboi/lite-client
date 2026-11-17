// What x/net's HPACK encoder writes across the blocks of one connection — the dynamic table filling,
// evicting and being resized — so that lc_hpack_enc can be held to the bytes and not to a reading.
// And what x/net's DECODER makes of those blocks, one per connection as the client keeps it: each
// block refused or read, and a hash of the fields it read, so that lc_hpack_dec is held to Go's
// reading of Go's bytes — the spider decodes every block a site sends (reality/fetch.c).
//
// One encoder per connection is what x/net keeps (cc.henc, vendor/x-net/http2/transport.go:518-519),
// and a second request on the connection is written with the table the first one left: the spider's
// redirect on the same host goes out as a 44-byte block where the first was 464
// (tools/vendorcap/spiderredir). This runs the vendored encoder itself — the package imports nothing
// outside the standard library, so it builds from vendor/ with no network:
//
//	cd tools/hpackenc && go run . > ../../test/hpack/reference_enc.h
//
// Each scenario is a sequence of operations on one fresh encoder: a block of fields, the peer's
// SETTINGS_HEADER_TABLE_SIZE (SetMaxDynamicTableSize), or a new limit (SetMaxDynamicTableSizeLimit).
// The first scenario is the spider's own: its first request, then a redirect's — the same fields and
// a referer, in another order.
package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"strings"

	"golang.org/x/net/http2/hpack"
)

type op struct {
	kind   int // 0 a block, 1 the peer's table size, 2 a new limit
	v      uint32
	fields []hpack.HeaderField
}

func f(n, v string) hpack.HeaderField { return hpack.HeaderField{Name: n, Value: v} }

// The spider's first request as x/net writes it for Chrome 150 (tools/vendorcap/spiderredir), in one
// of the orders a walk gives: the four pseudo-headers, the browser's fourteen and the cookie, then
// accept-encoding.
func spiderFirst() []hpack.HeaderField {
	return []hpack.HeaderField{
		f(":authority", "stand.example"), f(":method", "GET"), f(":path", "/"), f(":scheme", "https"),
		f("sec-fetch-site", "none"), f("sec-fetch-dest", "document"), f("cookie", "padding="),
		f("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"),
		f("cache-control", "max-age=0"), f("sec-fetch-user", "?1"), f("priority", "u=0, i"),
		f("sec-ch-ua", `"Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"`),
		f("sec-ch-ua-mobile", "?0"), f("sec-ch-ua-platform", `"Windows"`), f("dnt", "1"),
		f("sec-fetch-mode", "navigate"), f("accept-language", "en-US,en;q=0.9"),
		f("upgrade-insecure-requests", "1"),
		f("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
		f("accept-encoding", "gzip"),
	}
}

func spiderRedirect(path, referer string) []hpack.HeaderField {
	first := spiderFirst()
	out := []hpack.HeaderField{f(":authority", "stand.example"), f(":method", "GET"), f(":path", path), f(":scheme", "https")}
	rest := first[4 : len(first)-1]
	// Another walk: reversed, the referer in the middle.
	for i := len(rest) - 1; i >= 0; i-- {
		out = append(out, rest[i])
		if i == len(rest)/2 {
			out = append(out, f("referer", referer))
		}
	}
	return append(out, f("accept-encoding", "gzip"))
}

var names = []string{
	":authority", ":method", ":path", ":scheme", ":status", "accept", "accept-encoding", "cookie",
	"referer", "user-agent", "x-a", "x-b", "x-long-custom-name", "cache-control", "content-length",
	"location", "set-cookie", "priority", "dnt",
}

var values = []string{"", "/", "GET", "https", "gzip, deflate", "1", "x", "padding=", "/index.html",
	"a-value", "another value", "https://stand.example/"}

func randomField(r *rand.Rand) hpack.HeaderField {
	n := names[r.Intn(len(names))]
	switch r.Intn(12) {
	case 0: // long enough to push the table into eviction
		return f(n, strings.Repeat(string(rune('a'+r.Intn(26))), 600+r.Intn(1400)))
	case 1, 2:
		return f(n, fmt.Sprintf("v%d", r.Intn(20)))
	default:
		return f(n, values[r.Intn(len(values))])
	}
}

func scenarios() [][]op {
	var all [][]op
	all = append(all, []op{
		{kind: 0, fields: spiderFirst()},
		{kind: 0, fields: spiderRedirect("/a", "https://stand.example/")},
		{kind: 0, fields: spiderRedirect("/c2", "https://stand.example/a")},
	})
	// The peer announcing its table: the next block opens with an update, twice when it was lowered
	// and raised again before any block.
	all = append(all, []op{
		{kind: 0, fields: spiderFirst()},
		{kind: 1, v: 4096},
		{kind: 0, fields: spiderRedirect("/a", "https://stand.example/")},
		{kind: 1, v: 100},
		{kind: 1, v: 65536},
		{kind: 0, fields: spiderRedirect("/b", "https://stand.example/a")},
		{kind: 1, v: 0},
		{kind: 0, fields: spiderRedirect("/c", "https://stand.example/b")},
		{kind: 2, v: 2048},
		{kind: 1, v: 4096},
		{kind: 0, fields: spiderFirst()},
	})
	// An entry asked for again after it was evicted: Go writes a literal, an encoder that kept it
	// would write an index. Each of these fills most of the table on its own.
	a, b := strings.Repeat("a", 3000), strings.Repeat("b", 3000)
	all = append(all, []op{
		{kind: 0, fields: []hpack.HeaderField{f("x-a", a)}},
		{kind: 0, fields: []hpack.HeaderField{f("x-b", b)}},
		{kind: 0, fields: []hpack.HeaderField{f("x-a", a), f("x-b", b), f("x-b", b)}},
	})
	// What a site's answers look like to the client's decoder: a header sent again with another value
	// — a literal that borrows the dynamic entry's NAME — and a value longer than the whole table.
	all = append(all, []op{
		{kind: 0, fields: []hpack.HeaderField{f(":status", "302"), f("x-served-by", "cache-a"), f("location", "/a")}},
		{kind: 0, fields: []hpack.HeaderField{f(":status", "302"), f("x-served-by", "cache-b"), f("location", "/b")}},
		{kind: 0, fields: []hpack.HeaderField{f(":status", "200"), f("content-security-policy", strings.Repeat("c", 5000)), f("x-served-by", "cache-c")}},
		{kind: 0, fields: []hpack.HeaderField{f("x-served-by", "cache-c"), f("x-served-by", "cache-a")}},
		// And long values Go writes RAW, their Huffman form being longer: one the table keeps, one it cannot.
		{kind: 0, fields: []hpack.HeaderField{f("x-raw", strings.Repeat("|", 3000)), f("x-raw-long", strings.Repeat("|", 5000))}},
		{kind: 0, fields: []hpack.HeaderField{f("x-raw", strings.Repeat("|", 3000))}},
	})
	r := rand.New(rand.NewSource(20260924))
	for s := 0; s < 40; s++ {
		var ops []op
		for b := 0; b < 1+r.Intn(6); b++ {
			if r.Intn(5) == 0 {
				ops = append(ops, op{kind: 1, v: []uint32{0, 64, 300, 1024, 4096, 65536}[r.Intn(6)]})
			}
			if r.Intn(12) == 0 {
				ops = append(ops, op{kind: 2, v: []uint32{0, 512, 4096}[r.Intn(3)]})
			}
			var fs []hpack.HeaderField
			for i := 0; i < 1+r.Intn(14); i++ {
				fs = append(fs, randomField(r))
			}
			// Repeats within a block and across blocks, which is where the table is referred to.
			if len(ops) > 0 && r.Intn(2) == 0 {
				for _, o := range ops {
					if o.kind == 0 && len(o.fields) > 0 {
						fs = append(fs, o.fields[r.Intn(len(o.fields))])
					}
				}
			}
			ops = append(ops, op{kind: 0, fields: fs})
		}
		all = append(all, ops)
	}
	return all
}

// Each block is kept as its length and a 64-bit FNV-1a of the bytes Go wrote: the blocks that
// evict run to kilobytes, and a wrong byte anywhere still changes the hash.
func fnv(b []byte) uint64 {
	h := uint64(14695981039346656037)
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}

func cstr(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 0x20 || c > 0x7e:
			fmt.Fprintf(&b, "\\%03o", c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func main() {
	var fields, opsOut, scen strings.Builder
	nf, nops := 0, 0
	for _, sc := range scenarios() {
		var buf bytes.Buffer
		e := hpack.NewEncoder(&buf)
		// And the other end, as x/net's client keeps it: one decoder per connection, allowed the
		// table this client advertises (vendor/x-net/http2/transport.go, ReadMetaHeaders). Once it
		// has refused a block the connection is over — COMPRESSION_ERROR — and the blocks after it
		// are not decoded: 2.
		d := hpack.NewDecoder(4096, nil)
		dead := false
		first := nops
		for _, o := range sc {
			switch o.kind {
			case 1:
				e.SetMaxDynamicTableSize(o.v)
				fmt.Fprintf(&opsOut, "    { 1, %d, 0, 0, 0, 0, 0, 0 },\n", o.v)
			case 2:
				e.SetMaxDynamicTableSizeLimit(o.v)
				fmt.Fprintf(&opsOut, "    { 2, %d, 0, 0, 0, 0, 0, 0 },\n", o.v)
			default:
				buf.Reset()
				for _, hf := range o.fields {
					if err := e.WriteField(hf); err != nil {
						fmt.Fprintln(os.Stderr, err)
						os.Exit(1)
					}
				}
				dec, dfnv := 2, uint64(0)
				if !dead {
					hfs, err := d.DecodeFull(buf.Bytes())
					if err != nil {
						dec, dead = 0, true
					} else {
						var all []byte
						for _, hf := range hfs {
							all = append(append(append(append(all, hf.Name...), 0), hf.Value...), 0)
						}
						dec, dfnv = 1, fnv(all)
					}
				}
				fmt.Fprintf(&opsOut, "    { 0, 0, %d, %d, %d, 0x%016xull, %d, 0x%016xull },\n", nf, len(o.fields),
					buf.Len(), fnv(buf.Bytes()), dec, dfnv)
				for _, hf := range o.fields {
					// A long value of one letter repeated is written as the letter and the count,
					// so the file holds the vectors and not megabytes of 'q'.
					if v := hf.Value; len(v) > 64 && strings.Count(v, v[:1]) == len(v) {
						fmt.Fprintf(&fields, "    { %s, NULL, '%c', %d },\n", cstr(hf.Name), v[0], len(v))
					} else {
						fmt.Fprintf(&fields, "    { %s, %s, 0, 0 },\n", cstr(hf.Name), cstr(hf.Value))
					}
					nf++
				}
			}
			nops++
		}
		fmt.Fprintf(&scen, "    { %d, %d },\n", first, nops-first)
	}
	fmt.Println("/* Generated by tools/hpackenc from x/net's own HPACK encoder and decoder (vendor/x-net/http2/hpack). Do not edit. */")
	fmt.Println("typedef struct { const char *name, *value; char rep; unsigned rep_len; } ref_enc_field;")
	fmt.Println("typedef struct { int kind; unsigned v, first, n, len; unsigned long long fnv; int dec; unsigned long long dfnv; } ref_enc_op;")
	fmt.Printf("static const ref_enc_field ref_enc_fields[%d] = {\n%s};\n", nf, fields.String())
	fmt.Printf("static const ref_enc_op ref_enc_ops[%d] = {\n%s};\n", nops, opsOut.String())
	fmt.Printf("static const unsigned ref_enc_scenarios[][2] = {\n%s};\n", scen.String())
}
