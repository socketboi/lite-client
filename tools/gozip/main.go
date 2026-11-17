// When Go's gzip reader reads, measured on Go's own reader — what src/core/gozip.c is held to.
//
// The spider reads a gzip answer through x/net's gzipReader: compress/gzip's Reader over a
// bufio.Reader of 4096 over the response body, and compress/flate under that
// (vendor/x-net/http2/transport.go:2802-2893, GOROOT/src/compress/gzip/gunzip.go,
// GOROOT/src/compress/flate/inflate.go). Every Read it makes of the body hands window back to the
// site, so WHEN it reads and how much is on the wire. This runs the real thing over a body that
// arrives in pieces and logs every Read of the body, every piece that arrives because the reader
// was waiting for it, and every Read the consumer gets back — for io.ReadAll, which is how the
// reference reads the page, and for io.CopyN(io.Discard, body, 2 << 10), which is how http.Client
// slurps a redirect's body before it closes it. The same for a plain body, whose reads are only the
// consumer's own. test/gozip replays each case on the C machine and compares.
//
// The body is transportResponseBody as far as reading goes: a pipe that hands out what has arrived,
// waits when it is empty, and ends with io.EOF, with an error, or never; and the Content-Length
// check it makes on every Read (vendor/x-net/http2/transport.go:2230-2279). Which piece arrives
// next and how big it is comes from one small generator that test/gozip carries too.
//
//	go run ./tools/gozip > build/gen/gozip_vectors.h
package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"runtime"
	"strings"
)

// splitmix64, which test/gozip carries too.
type rng struct{ s uint64 }

func (r *rng) next() uint64 {
	r.s += 0x9e3779b97f4a7c15
	z := r.s
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func (r *rng) intn(n int) int { return int(r.next() % uint64(n)) }

// A page: markup with links, words drawn from a small vocabulary so that it compresses the way a
// page does.
func page(size int, seed uint64) []byte {
	r := &rng{seed}
	words := []string{"the", "site", "of", "a", "shop", "news", "about", "contact", "and", "more",
		"price", "delivery", "order", "catalog", "service", "help", "login", "search", "home"}
	var b bytes.Buffer
	for b.Len() < size {
		switch r.intn(6) {
		case 0:
			fmt.Fprintf(&b, `<a href="/%s/%d">`, words[r.intn(len(words))], r.intn(1000))
		case 1:
			fmt.Fprintf(&b, "<div class=\"c%d\">", r.intn(40))
		case 2:
			b.WriteString("</div>\n")
		default:
			b.WriteString(words[r.intn(len(words))])
			b.WriteByte(' ')
		}
	}
	return b.Bytes()[:size]
}

// Noise, which does not compress: stored blocks at every level.
func noise(size int, seed uint64) []byte {
	r := &rng{seed}
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(r.next())
	}
	return b
}

// A raw deflate stream of `data` at `level`, flushed every `every` bytes of input when non-zero —
// each flush is an empty stored block, the sync marker.
func deflate(data []byte, level, every int) []byte {
	var out bytes.Buffer
	w, err := flate.NewWriter(&out, level)
	if err != nil {
		panic(err)
	}
	if every <= 0 {
		w.Write(data)
	} else {
		for off := 0; off < len(data); off += every {
			end := off + every
			if end > len(data) {
				end = len(data)
			}
			w.Write(data[off:end])
			w.Flush()
		}
	}
	w.Close()
	return out.Bytes()
}

type hdr struct {
	flags   byte // FTEXT, FHCRC, FEXTRA, FNAME, FCOMMENT as written; FHCRC computes the CRC
	extra   []byte
	name    string
	comment string
	badCRC  bool
}

// A gzip member around a raw deflate stream: the header as RFC 1952 lays it out, the stream, CRC-32
// and ISIZE of `data`.
func member(data, raw []byte, h hdr) []byte {
	var b bytes.Buffer
	b.Write([]byte{0x1f, 0x8b, 8, h.flags, 0, 0, 0, 0, 0, 3})
	if h.flags&0x04 != 0 {
		binary.Write(&b, binary.LittleEndian, uint16(len(h.extra)))
		b.Write(h.extra)
	}
	if h.flags&0x08 != 0 {
		b.WriteString(h.name)
		b.WriteByte(0)
	}
	if h.flags&0x10 != 0 {
		b.WriteString(h.comment)
		b.WriteByte(0)
	}
	if h.flags&0x02 != 0 {
		c := uint16(crc32.ChecksumIEEE(b.Bytes()))
		if h.badCRC {
			c++
		}
		binary.Write(&b, binary.LittleEndian, c)
	}
	b.Write(raw)
	binary.Write(&b, binary.LittleEndian, crc32.ChecksumIEEE(data))
	binary.Write(&b, binary.LittleEndian, uint32(len(data)))
	return b.Bytes()
}

func gz(data []byte, level, every int) []byte {
	return member(data, deflate(data, level, every), hdr{})
}

// ---- the body --------------------------------------------------------------------------------

const (
	endEOF  = 0 // the stream ended: io.EOF once what arrived is read
	endErr  = 1 // it was reset: an error once what arrived is read
	endHang = 2 // nothing more ever comes: the reader waits for good
)

var (
	errReset     = errors.New("stream reset")
	errTruncated = errors.New("net/http: server replied with more than declared Content-Length; truncated")
	errHang      = errors.New("hang")
)

type event struct {
	kind  byte
	a, b  uint32
	err   byte
	extra uint32
}

type body struct {
	data   []byte
	pieces []int
	next   int // index of the next piece
	at     int // bytes of data that have arrived
	pipe   []byte
	end    int
	remain int64 // cs.bytesRemain
	rerr   error // cs.readErr
	log    []event
}

func code(err error) byte {
	switch {
	case err == nil:
		return 0
	case err == io.EOF:
		return 1
	default:
		return 2
	}
}

// pipe.Read (vendor/x-net/http2/pipe.go:55-78): what has arrived, else wait — here, the next piece
// arrives because the reader waits for it — else the end.
func (bd *body) pipeRead(p []byte) (int, error) {
	for len(bd.pipe) == 0 {
		if bd.next < len(bd.pieces) {
			n := bd.pieces[bd.next]
			bd.next++
			bd.pipe = append(bd.pipe, bd.data[bd.at:bd.at+n]...)
			bd.at += n
			bd.log = append(bd.log, event{kind: 'B', a: uint32(n)})
			continue
		}
		switch bd.end {
		case endEOF:
			return 0, io.EOF
		case endErr:
			return 0, errReset
		default:
			bd.log = append(bd.log, event{kind: 'H'})
			panic(errHang)
		}
	}
	n := copy(p, bd.pipe)
	bd.pipe = bd.pipe[n:]
	return n, nil
}

// transportResponseBody.Read, the part that decides what a Read returns
// (vendor/x-net/http2/transport.go:2230-2261).
func (bd *body) Read(p []byte) (int, error) {
	n, err := bd.read(p)
	bd.log = append(bd.log, event{kind: 'R', a: uint32(len(p)), b: uint32(n), err: code(err)})
	return n, err
}

func (bd *body) read(p []byte) (n int, err error) {
	if bd.rerr != nil {
		return 0, bd.rerr
	}
	n, err = bd.pipeRead(p)
	if bd.remain != -1 {
		if int64(n) > bd.remain {
			n = int(bd.remain)
			if err == nil {
				err = errTruncated
			}
			bd.rerr = err
			return int(bd.remain), err
		}
		bd.remain -= int64(n)
		if err == io.EOF && bd.remain > 0 {
			err = io.ErrUnexpectedEOF
			bd.rerr = err
			return n, err
		}
	}
	return n, err
}

// x/net's gzipReader: a gzip.Reader made on the first Read, its error kept.
type gzipReader struct {
	body io.Reader
	zr   *gzip.Reader
	zerr error
}

func (gz *gzipReader) Read(p []byte) (int, error) {
	if gz.zerr != nil {
		return 0, gz.zerr
	}
	if gz.zr == nil {
		zr := new(gzip.Reader)
		if err := zr.Reset(gz.body); err != nil {
			gz.zerr = err
			return 0, err
		}
		gz.zr = zr
	}
	return gz.zr.Read(p)
}

// Every Read the consumer makes, and what it got.
type logged struct {
	r   io.Reader
	bd  *body
	out []byte
}

func (l *logged) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	l.out = append(l.out, p[:n]...)
	l.bd.log = append(l.bd.log, event{kind: 'O', a: uint32(len(p)), b: uint32(n), err: code(err)})
	return n, err
}

const (
	modeReadAll    = iota // gzip, io.ReadAll
	modeSlurp             // gzip, io.CopyN(io.Discard, body, 2048)
	modePlainAll          // plain, io.ReadAll
	modePlainSlurp        // plain, io.CopyN(io.Discard, body, 2048)
)

const (
	schedWhole = iota
	schedFixed
	schedRandom
)

type spec struct {
	stream int
	mode   int
	end    int
	sched  int
	param  int
	seed   uint64
	remain int64
}

func pieces(n int, s spec) []int {
	var ps []int
	r := &rng{s.seed}
	for left := n; left > 0; {
		k := left
		switch s.sched {
		case schedFixed:
			k = s.param
		case schedRandom:
			k = 1 + r.intn(s.param)
		}
		if k > left {
			k = left
		}
		ps = append(ps, k)
		left -= k
	}
	return ps
}

type result struct {
	events uint32
	hash   uint64
	outLen uint32
	outCRC uint32
	final  byte
}

func run(data []byte, s spec) (res result) {
	bd := &body{data: data, pieces: pieces(len(data), s), end: s.end, remain: s.remain}
	var src io.Reader = bd
	if s.mode == modeReadAll || s.mode == modeSlurp {
		src = &gzipReader{body: bd}
	}
	l := &logged{r: src, bd: bd}
	var final error
	func() {
		defer func() {
			if v := recover(); v != nil {
				if v != errHang {
					panic(v)
				}
				final = errHang
			}
		}()
		if s.mode == modeReadAll || s.mode == modePlainAll {
			_, final = io.ReadAll(l)
		} else {
			_, final = io.CopyN(io.Discard, l, 2<<10)
			if final == io.EOF {
				final = nil // what CopyN says of a short body does not matter to the slurp
			}
		}
	}()
	fin := code(final)
	if final == errHang {
		fin = 3
	}
	h := uint64(0xcbf29ce484222325)
	put := func(v uint32) {
		for i := 0; i < 4; i++ {
			h ^= uint64(byte(v >> (8 * i)))
			h *= 0x100000001b3
		}
	}
	for _, e := range bd.log {
		put(uint32(e.kind))
		put(e.a)
		put(e.b)
		put(uint32(e.err))
	}
	if os.Getenv("GOZIP_TRACE") != "" {
		for _, e := range bd.log {
			fmt.Fprintf(os.Stderr, "%c %d %d %d\n", e.kind, e.a, e.b, e.err)
		}
	}
	return result{uint32(len(bd.log)), h, uint32(len(l.out)), crc32.ChecksumIEEE(l.out), fin}
}

func main() {
	var streams [][]byte
	add := func(b []byte) int {
		streams = append(streams, b)
		return len(streams) - 1
	}
	var specs []spec

	// The body under every schedule: whole, byte by byte when it is small, at and around the
	// bufio's 4096, in frames of 16384, and in random pieces.
	schedules := func(n int) []spec {
		ss := []spec{{sched: schedWhole}, {sched: schedFixed, param: 4096},
			{sched: schedFixed, param: 4095}, {sched: schedFixed, param: 4097},
			{sched: schedFixed, param: 16384}, {sched: schedRandom, param: 9000, seed: 1},
			{sched: schedRandom, param: 700, seed: 2}}
		if n <= 3000 {
			ss = append(ss, spec{sched: schedFixed, param: 1})
		}
		return ss
	}
	both := func(id int, modes []int, ends []int) {
		for _, sc := range schedules(len(streams[id])) {
			for _, m := range modes {
				for _, e := range ends {
					s := sc
					s.stream, s.mode, s.end, s.remain = id, m, e, -1
					specs = append(specs, s)
				}
			}
		}
	}
	gzModes := []int{modeReadAll, modeSlurp}

	// Pages at every level, with and without sync flushes, around the sizes that matter: the
	// slurp's 2048 and flate's 32768 window.
	seed := uint64(100)
	for _, size := range []int{0, 1, 100, 2047, 2048, 2049, 5000, 32767, 32768, 32769, 40000, 70000} {
		for _, level := range []int{flate.HuffmanOnly, flate.NoCompression, flate.BestSpeed, 6, flate.BestCompression} {
			for _, every := range []int{0, 1000} {
				if every > 0 && size < 2000 {
					continue
				}
				seed++
				both(add(gz(page(size, seed), level, every)), gzModes, []int{endEOF})
			}
		}
	}
	// Noise: stored blocks of 65535 and more, read past the bufio into the window.
	for _, size := range []int{5000, 40000, 100000, 200000} {
		seed++
		both(add(gz(noise(size, seed), 6, 0)), gzModes, []int{endEOF, endHang})
		seed++
		both(add(gz(noise(size, seed), flate.NoCompression, 7000)), gzModes, []int{endEOF})
	}
	// The largest trees a block can carry: 286 literal/length codes, from a run long enough for a
	// match of 258, and 30 distance codes, from a match 24577 or more back.
	seed++
	runs := append(page(3000, seed), bytes.Repeat([]byte("a"), 5000)...)
	both(add(gz(runs, 6, 0)), gzModes, []int{endEOF})
	seed++
	head := page(1500, seed)
	far := append(append(append([]byte{}, head...), noise(29000, seed)...), head...)
	both(add(gz(far, 6, 0)), gzModes, []int{endEOF})

	// A big page: many windows.
	seed++
	both(add(gz(page(300000, seed), 6, 0)), gzModes, []int{endEOF, endErr, endHang})

	// How it ends, on a small page and a larger one.
	for _, size := range []int{1500, 50000} {
		seed++
		id := add(gz(page(size, seed), 6, 0))
		both(id, gzModes, []int{endErr, endHang})
		// With a Content-Length: right, one short, one long, and none.
		n := int64(len(streams[id]))
		for _, rem := range []int64{n, n - 1, n + 1, 0, 10} {
			for _, m := range gzModes {
				for _, e := range []int{endEOF, endHang} {
					specs = append(specs, spec{stream: id, mode: m, end: e, sched: schedRandom, param: 3000, seed: 7, remain: rem})
				}
			}
		}
	}

	// Headers: every flag, names and comments at and past the 512 gzip.Reader allows, an extra
	// field long enough to be read past the bufio, a header CRC right and wrong.
	seed++
	data := page(3000, seed)
	raw := deflate(data, 6, 0)
	long := strings.Repeat("n", 511)
	for _, h := range []hdr{
		{flags: 0x08, name: "index.html"}, {flags: 0x10, comment: "c"},
		{flags: 0x08, name: long}, {flags: 0x08, name: long + "x"}, {flags: 0x10, comment: long + "xy"},
		{flags: 0x08, name: "\xe9t\xe9"},
		{flags: 0x04, extra: make([]byte, 0)}, {flags: 0x04, extra: noise(10, 1)},
		{flags: 0x04, extra: noise(5000, 2)}, {flags: 0x04, extra: noise(65535, 3)},
		{flags: 0x02}, {flags: 0x02, badCRC: true}, {flags: 0x1e, extra: noise(300, 4), name: "a", comment: "b"},
		{flags: 0x1e, extra: noise(300, 4), name: "a", comment: "b", badCRC: true},
		{flags: 0xe0},
	} {
		both(add(member(data, raw, h)), gzModes, []int{endEOF})
	}

	// Several members, and what can follow one.
	seed++
	d1, d2 := page(1200, seed), page(40000, seed+1)
	m1, m2 := gz(d1, 6, 0), gz(d2, 1, 0)
	empty := gz(nil, 6, 0)
	for _, s := range [][]byte{
		append(append([]byte{}, m1...), m2...),
		append(append(append([]byte{}, m2...), m1...), empty...),
		append(append([]byte{}, empty...), m1...),
		append(append([]byte{}, m1...), 0x1f),
		append(append([]byte{}, m1...), 0x1f, 0x8b, 8, 0),
		append(append([]byte{}, m1...), []byte("<html>")...),
		append(append([]byte{}, m1...), make([]byte, 10)...),
	} {
		both(add(s), gzModes, []int{endEOF, endHang})
	}

	// Broken ones: every byte of a small member flipped in turn, a larger one at random places, and
	// both cut short everywhere.
	seed++
	small := gz(page(700, seed), 6, 0)
	fixed := gz(page(60, seed), flate.BestSpeed, 0)
	stored := gz(page(300, seed), flate.NoCompression, 0)
	huff := gz(page(900, seed), flate.HuffmanOnly, 0)
	mut := &rng{seed}
	for bi, base := range [][]byte{small, fixed, stored, huff} {
		for i := 0; i < len(base); i++ {
			if bi == 0 && i%3 != 0 {
				continue
			}
			b := append([]byte{}, base...)
			b[i] ^= 1 << uint(mut.intn(8))
			id := add(b)
			for _, m := range gzModes {
				specs = append(specs, spec{stream: id, mode: m, end: endEOF, sched: schedWhole, remain: -1})
				specs = append(specs, spec{stream: id, mode: m, end: endHang, sched: schedRandom, param: 50, seed: uint64(i), remain: -1})
			}
		}
		for cut := 0; cut < len(base); cut += 1 + len(base)/60 {
			id := add(append([]byte{}, base[:cut]...))
			for _, m := range gzModes {
				specs = append(specs, spec{stream: id, mode: m, end: endEOF, sched: schedRandom, param: 40, seed: uint64(cut), remain: -1})
			}
		}
	}
	big := gz(page(20000, seed+5), 6, 0)
	for k := 0; k < 120; k++ {
		b := append([]byte{}, big...)
		b[mut.intn(len(b))] ^= byte(1 + mut.intn(255))
		id := add(b)
		for _, m := range gzModes {
			specs = append(specs, spec{stream: id, mode: m, end: endEOF, sched: schedRandom, param: 5000, seed: uint64(k), remain: -1})
		}
	}
	// Random bytes behind a good header: whatever trees they make.
	for k := 0; k < 150; k++ {
		n := 12 + mut.intn(400)
		b := append([]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3}, noise(n, uint64(1000+k))...)
		b[10] = b[10]&^6 | byte(1+mut.intn(2))<<1 // a fixed or a dynamic block
		id := add(b)
		for _, m := range gzModes {
			specs = append(specs, spec{stream: id, mode: m, end: endEOF, sched: schedWhole, remain: -1})
		}
	}

	// Plain bodies: the consumer's reads alone.
	for _, size := range []int{0, 1, 511, 512, 513, 2047, 2048, 2049, 9000, 70000, 300000} {
		seed++
		both(add(page(size, seed)), []int{modePlainAll, modePlainSlurp}, []int{endEOF, endErr, endHang})
	}
	seed++
	plain := add(page(3000, seed))
	for _, rem := range []int64{3000, 2999, 3001, 0, 2048, 2049} {
		for _, m := range []int{modePlainAll, modePlainSlurp} {
			for _, e := range []int{endEOF, endHang} {
				specs = append(specs, spec{stream: plain, mode: m, end: e, sched: schedRandom, param: 900, seed: 9, remain: rem})
			}
		}
	}

	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	fmt.Fprintf(out, "/* Generated by tools/gozip with %s — do not edit. */\n", runtime.Version())
	for i, s := range streams {
		fmt.Fprintf(out, "static const uint8_t gz_s%d[] = {", i)
		for j, c := range s {
			if j%24 == 0 {
				fmt.Fprint(out, "\n")
			}
			fmt.Fprintf(out, "%d,", c)
		}
		if len(s) == 0 {
			fmt.Fprint(out, "0")
		}
		fmt.Fprintln(out, "};")
	}
	fmt.Fprintln(out, "static const struct { const uint8_t *data; uint32_t len; } gz_streams[] = {")
	for i, s := range streams {
		fmt.Fprintf(out, "{gz_s%d, %d},\n", i, len(s))
	}
	fmt.Fprintln(out, "};")
	fmt.Fprintln(out, "static const struct gz_case { uint16_t stream; uint8_t mode, end, sched; uint32_t param; uint64_t seed; int64_t remain; uint32_t events; uint64_t hash; uint32_t out_len, out_crc; uint8_t final; } gz_cases[] = {")
	for _, s := range specs {
		r := run(streams[s.stream], s)
		fmt.Fprintf(out, "{%d,%d,%d,%d,%d,%dull,%d,%d,0x%016xull,%d,0x%08xu,%d},\n", s.stream, s.mode, s.end,
			s.sched, s.param, s.seed, s.remain, r.events, r.hash, r.outLen, r.outCRC, r.final)
	}
	fmt.Fprintln(out, "};")
}
