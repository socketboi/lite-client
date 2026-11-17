// What x/net's HPACK decoder makes of header blocks fed the way a client's framer feeds them — one
// Write per HEADERS or CONTINUATION fragment, then Close — so that lc_hpack_write and
// lc_hpack_close can be held to Go's reading and not to a reading of Go.
//
// Each case is one decoder (as one connection keeps) with a SetMaxStringLength and, optionally, a
// field after which the emit function turns emission off — what x/net's framer does on the first
// invalid field (vendor/x-net/http2/frame.go readMetaFrame). For every Write it records whether Go
// returned an error, and a hash of the fields emitted during it; for every block, what Close
// returned. A case stops at its first error: a connection with a decoding error is over.
//
// The blocks: Go's own encoder's, cut into pieces anywhere; crafted ones that walk each of the
// decoder's refusals — varints that run out or overflow, indexes past the tables, size updates too
// large or out of place, Huffman that ends badly, strings past the limit, pending bytes past twice
// the limit; and valid blocks with bytes changed at random, to find what nobody thought to craft.
//
//	cd tools/hpackdec && go run . > ../../test/hpack/reference_dec.h
package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"

	"golang.org/x/net/http2/hpack"
)

type block struct {
	frags [][]byte
}

type tcase struct {
	name    string
	maxStr  int
	offAt   int // turn emission off after this many emitted fields, -1 never
	allowed uint32
	blocks  []block
}

func fnv(h uint64, b []byte) uint64 {
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}

func encode(fs []hpack.HeaderField, e *hpack.Encoder, buf *bytes.Buffer) []byte {
	buf.Reset()
	for _, f := range fs {
		e.WriteField(f)
	}
	return append([]byte(nil), buf.Bytes()...)
}

// Cuts b into pieces at the given offsets.
func cut(b []byte, at ...int) [][]byte {
	var out [][]byte
	prev := 0
	for _, a := range at {
		if a > prev && a < len(b) {
			out = append(out, b[prev:a])
			prev = a
		}
	}
	return append(out, b[prev:])
}

func one(b []byte) block { return block{frags: [][]byte{b}} }

func f(n, v string) hpack.HeaderField { return hpack.HeaderField{Name: n, Value: v} }

func cases() []tcase {
	var all []tcase
	r := rand.New(rand.NewSource(20260925))

	// Go's encoder, a connection's worth of blocks, each cut every way that matters: one piece,
	// byte by byte, and random cuts.
	var buf bytes.Buffer
	e := hpack.NewEncoder(&buf)
	var blocks [][]byte
	blocks = append(blocks, encode([]hpack.HeaderField{f(":status", "302"), f("location", "/a"),
		f("x-served-by", "cache-a"), f("set-cookie", strings.Repeat("s", 3000))}, e, &buf))
	blocks = append(blocks, encode([]hpack.HeaderField{f(":status", "200"), f("x-served-by", "cache-b"),
		f("content-security-policy", strings.Repeat("c", 6000)), f("set-cookie", strings.Repeat("s", 3000))}, e, &buf))
	blocks = append(blocks, encode([]hpack.HeaderField{f(":status", "301"), f("x-raw", strings.Repeat("|", 5000)),
		{Name: "secret", Value: "v", Sensitive: true}, f("x-served-by", "cache-b")}, e, &buf))
	// And a connection of short blocks, for the byte-by-byte cut and for the mutants: the long ones
	// above would make the file megabytes of hex for nothing a short one does not show.
	var sbuf bytes.Buffer
	se := hpack.NewEncoder(&sbuf)
	var small [][]byte
	small = append(small, encode([]hpack.HeaderField{f(":status", "302"), f("location", "/a"),
		f("x-served-by", "cache-a"), f("set-cookie", "a=1")}, se, &sbuf))
	small = append(small, encode([]hpack.HeaderField{f(":status", "200"), f("x-served-by", "cache-b"),
		f("content-type", "text/html"), f("set-cookie", "a=2")}, se, &sbuf))
	small = append(small, encode([]hpack.HeaderField{f(":status", "301"), {Name: "secret", Value: "v", Sensitive: true},
		f("x-served-by", "cache-b"), f("x-raw", "|||")}, se, &sbuf))
	for _, mode := range []string{"whole", "bytes", "random"} {
		c := tcase{name: "go encoder, " + mode, offAt: -1}
		src := blocks
		if mode == "bytes" {
			src = small
		}
		for _, b := range src {
			switch mode {
			case "whole":
				c.blocks = append(c.blocks, one(b))
			case "bytes":
				var fr [][]byte
				for i := range b {
					fr = append(fr, b[i:i+1])
				}
				c.blocks = append(c.blocks, block{frags: fr})
			default:
				var at []int
				for i := 0; i < 6; i++ {
					at = append(at, 1+r.Intn(len(b)-1))
				}
				// sorted
				for i := range at {
					for j := i + 1; j < len(at); j++ {
						if at[j] < at[i] {
							at[i], at[j] = at[j], at[i]
						}
					}
				}
				c.blocks = append(c.blocks, block{frags: cut(b, at...)})
			}
		}
		all = append(all, c)
	}

	// The limit on strings: declared past it, decoded past it, and pending bytes past twice it plus
	// the varint overhead — for a decoder whose limit is small enough to reach.
	for _, ms := range []int{5, 10, 64} {
		all = append(all, tcase{name: fmt.Sprintf("limit %d", ms), maxStr: ms, offAt: -1, blocks: []block{
			one(blocks[0]),
		}})
		all = append(all, tcase{name: fmt.Sprintf("limit %d, cut", ms), maxStr: ms, offAt: -1, blocks: []block{
			{frags: cut(blocks[1], 3, 40)},
		}})
	}
	// A literal whose declared length is past the limit but whose bytes are not in yet, and one that
	// leaves more pending than 2*(limit+8).
	all = append(all, tcase{name: "declared past the limit", maxStr: 10, offAt: -1, blocks: []block{
		{frags: [][]byte{{0x00, 0x7f, 0x05}}},
	}})
	all = append(all, tcase{name: "pending past twice the limit", maxStr: 10, offAt: -1, blocks: []block{
		{frags: [][]byte{append([]byte{0x00, 0x05, 'a', 'b', 'c', 'd', 'e', 0x0a}, bytes.Repeat([]byte{'z'}, 40)...)}},
	}})
	// An indexed field whose table strings are past the limit: :authority is ten letters.
	all = append(all, tcase{name: "table string past the limit", maxStr: 5, offAt: -1, blocks: []block{
		one([]byte{0x81}),
	}})

	// Varints: run out, overflow at the ninth continuation, and succeed at the eighth.
	var ff []byte
	for i := 0; i < 12; i++ {
		ff = append(ff, 0xff)
	}
	for _, n := range []int{1, 2, 5, 8, 9, 10, 12} {
		all = append(all, tcase{name: fmt.Sprintf("varint of %d continuation bytes", n), offAt: -1, blocks: []block{
			{frags: [][]byte{append([]byte{0xff}, ff[:n]...)}},
		}})
	}
	all = append(all, tcase{name: "varint that ends", offAt: -1, blocks: []block{
		{frags: [][]byte{{0xff, 0x80, 0x80, 0x00}}},
	}})
	// Indexes: zero, the last static one, one past it into an empty dynamic table, and past the
	// dynamic table once it has entries.
	all = append(all, tcase{name: "index zero", offAt: -1, blocks: []block{one([]byte{0x80})}})
	all = append(all, tcase{name: "index 61", offAt: -1, blocks: []block{one([]byte{0xbd})}})
	all = append(all, tcase{name: "index 62, empty table", offAt: -1, blocks: []block{one([]byte{0xbe})}})
	all = append(all, tcase{name: "literal with name index 62, empty table", offAt: -1, blocks: []block{one([]byte{0x7e, 0x01, 'x'})}})
	all = append(all, tcase{name: "literal with name index 62, value cut", offAt: -1, blocks: []block{{frags: [][]byte{{0x7e}, {0x01}, {'x'}}}}})
	all = append(all, tcase{name: "index past a filled table", offAt: -1, blocks: []block{
		one([]byte{0x40, 0x01, 'a', 0x01, 'b', 0xbe, 0xbf}),
	}})
	// Size updates: too large, first, second after the first emptied the table, second after it
	// did not, and after a field.
	all = append(all, tcase{name: "size update too large", offAt: -1, blocks: []block{one([]byte{0x3f, 0xe2, 0x1f})}})
	all = append(all, tcase{name: "size update, then another into an empty table", offAt: -1, blocks: []block{one([]byte{0x20, 0x3f, 0xe1, 0x1f, 0x82})}})
	all = append(all, tcase{name: "size update after a field, table empty", offAt: -1, blocks: []block{one([]byte{0x82, 0x20})}})
	all = append(all, tcase{name: "size update after a field, table filled", offAt: -1, blocks: []block{
		one([]byte{0x40, 0x01, 'a', 0x01, 'b', 0x3f, 0x01}),
	}})
	all = append(all, tcase{name: "size update first in the next block", offAt: -1, blocks: []block{
		one([]byte{0x40, 0x01, 'a', 0x01, 'b'}), one([]byte{0x3f, 0x01, 0xbe}),
	}})
	all = append(all, tcase{name: "size update first in a later piece of the same block", offAt: -1, blocks: []block{
		{frags: [][]byte{{0x40, 0x01, 'a', 0x01, 'b'}, {0x3f, 0x01}}},
	}})
	// Huffman: good, padding of eight bits, padding that is not ones, the EOS symbol.
	all = append(all, tcase{name: "huffman", offAt: -1, blocks: []block{one([]byte{0x00, 0x81, 0x1f, 0x82, 0x1f, 0xff})}})
	all = append(all, tcase{name: "huffman padding of a byte", offAt: -1, blocks: []block{one([]byte{0x00, 0x82, 0x1f, 0xff, 0x01, 'x'})}})
	all = append(all, tcase{name: "huffman padding not ones", offAt: -1, blocks: []block{one([]byte{0x00, 0x81, 0x18, 0x01, 'x'})}})
	all = append(all, tcase{name: "huffman EOS", offAt: -1, blocks: []block{one([]byte{0x00, 0x84, 0xff, 0xff, 0xff, 0xff, 0x01, 'x'})}})
	// Emission off: a bad Huffman string in a field not going into the table is not looked at; one
	// going into the table is.
	all = append(all, tcase{name: "emission off, bad huffman not indexed", offAt: 1, blocks: []block{
		one([]byte{0x82, 0x00, 0x81, 0x18, 0x81, 0x18, 0x82}),
	}})
	all = append(all, tcase{name: "emission off, bad huffman indexed", offAt: 1, blocks: []block{
		one([]byte{0x82, 0x40, 0x81, 0x18, 0x81, 0x18, 0x82}),
	}})
	all = append(all, tcase{name: "emission off after two, table kept", offAt: 2, blocks: []block{
		{frags: cut(blocks[0], 7)}, one(blocks[1]),
	}})
	// Close with bytes left over.
	all = append(all, tcase{name: "block ends inside a field", offAt: -1, blocks: []block{
		{frags: [][]byte{{0x00, 0x03, 'a', 'b'}}}, one([]byte{0x82}),
	}})
	all = append(all, tcase{name: "empty pieces", offAt: -1, blocks: []block{
		{frags: [][]byte{{}, {0x82}, {}, {0x40}, {}, {0x01, 'a'}, {0x01, 'b'}}},
	}})

	// Valid blocks with bytes changed at random.
	for i := 0; i < 400; i++ {
		// The blocks before the one changed go in whole: the later ones refer to what the earlier
		// ones put in the table.
		k := r.Intn(len(small))
		src := small[k]
		b := append([]byte(nil), src...)
		for k := 0; k < 1+r.Intn(3); k++ {
			b[r.Intn(len(b))] = byte(r.Intn(256))
		}
		c := tcase{name: fmt.Sprintf("mutant %d", i), offAt: -1}
		if i%4 == 1 {
			c.maxStr = 1 + r.Intn(4000)
		}
		if i%5 == 2 {
			c.offAt = r.Intn(3)
		}
		for _, before := range small[:k] {
			c.blocks = append(c.blocks, one(before))
		}
		if i%3 == 0 {
			c.blocks = append(c.blocks, block{frags: cut(b, 1+r.Intn(len(b)-1), 1+r.Intn(len(b)-1))})
		} else {
			c.blocks = append(c.blocks, one(b))
		}
		all = append(all, c)
	}
	return all
}

func cbytes(b []byte) string {
	var s strings.Builder
	s.WriteByte('"')
	for _, c := range b {
		fmt.Fprintf(&s, "\\x%02x", c)
	}
	s.WriteByte('"')
	return s.String()
}

func main() {
	var frags, pieces, blocksOut, casesOut strings.Builder
	nfr, nbl := 0, 0
	for _, c := range cases() {
		var emitted uint64
		var count, off int
		var cur uint64
		d := hpack.NewDecoder(4096, nil)
		d.SetMaxStringLength(c.maxStr)
		d.SetEmitFunc(func(hf hpack.HeaderField) {
			cur = fnv(cur, []byte(hf.Name))
			cur = fnv(cur, []byte{0})
			cur = fnv(cur, []byte(hf.Value))
			cur = fnv(cur, []byte{0})
			if hf.Sensitive {
				cur = fnv(cur, []byte{1})
			}
			count++
			if c.offAt >= 0 && count == c.offAt {
				d.SetEmitEnabled(false)
			}
		})
		_ = emitted
		dead := false
		firstBlock := nbl
		for _, b := range c.blocks {
			if dead {
				break
			}
			firstFrag := nfr
			closeErr := 2 // not reached
			for _, p := range b.frags {
				cur = 14695981039346656037
				count0 := count
				_, err := d.Write(p)
				e := 0
				if err != nil {
					e = 1
				}
				fmt.Fprintf(&pieces, "    { %s, %d, %d, %d, 0x%016xull },\n", cbytes(p), len(p), e, count-count0, cur)
				nfr++
				if err != nil {
					dead = true
					break
				}
			}
			if !dead {
				if d.Close() != nil {
					closeErr = 1
					dead = true
				} else {
					closeErr = 0
				}
			}
			fmt.Fprintf(&blocksOut, "    { %d, %d, %d },\n", firstFrag, nfr-firstFrag, closeErr)
			nbl++
		}
		_ = off
		fmt.Fprintf(&casesOut, "    { %q, %d, %d, %d, %d },\n", c.name, c.maxStr, c.offAt, firstBlock, nbl-firstBlock)
	}
	_ = frags
	fmt.Println("/* Generated by tools/hpackdec from x/net's own HPACK decoder (vendor/x-net/http2/hpack). Do not edit. */")
	fmt.Println("typedef struct { const char *bytes; unsigned len; int err; unsigned fields; unsigned long long fnv; } ref_dec_piece;")
	fmt.Println("typedef struct { unsigned first, n; int close; } ref_dec_block;")
	fmt.Println("typedef struct { const char *name; unsigned max_str; int off_at; unsigned first, n; } ref_dec_case;")
	fmt.Printf("static const ref_dec_piece ref_dec_pieces[%d] = {\n%s};\n", nfr, pieces.String())
	fmt.Printf("static const ref_dec_block ref_dec_blocks[%d] = {\n%s};\n", nbl, blocksOut.String())
	fmt.Printf("static const ref_dec_case ref_dec_cases[] = {\n%s};\n", casesOut.String())
}
