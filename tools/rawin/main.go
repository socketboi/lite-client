// How much the reference asks the socket for, read by read — uTLS's rawInput, run. Writes
// test/rawin/reference.h, which test/rawin holds tls/rawin.c to, request for request.
//
// uTLS reads the node's records into c.rawInput, a bytes.Buffer, and only through readFromUntil:
// Grow(needs + bytes.MinRead), then Read into AvailableBuffer until `needs` bytes
// have come (vendor/utls/conn.go:808-841). Each Read asks for the buffer's remaining
// free capacity, and how large that is follows from bytes.Buffer's growth and from the size classes
// of Go's allocator, which growSlice's append rounds up to (GOROOT/src/bytes/buffer.go, go1.27.1,
// the toolchain used for this reference). What the reference leaves unread in the socket when
// it gives up on a connection is decided there — and that is on the wire: a socket closed with
// bytes unread goes out as a reset, not a FIN.
//
// A case is a stream of records, as readRecordOrCCS takes them (conn.go:612-688) — readFromUntil
// for the header, then, unless the header is refused, for the whole record, then Next — and the way
// the stream arrives: in chunks, a read returning what is left of the current chunk or what it asked
// for, whichever is less. For each case the header carries every size asked for and the buffer's
// shape at the end. And, apart, the capacity an empty bytes.Buffer grown by c ends with, for every
// c from 65 to 70 000, as the points where it changes — the allocator's rounding, as growSlice gets it.
//
// TWO ARCHITECTURES, as the reference runs on both: the header is written from GOARCH=amd64 and the
// run is repeated as GOARCH=386, which must print the same.
//
// Not built by the gate. Regenerate in the build image, from the repository root:
//
//	docker run --rm -v "$PWD:/w" -w /w lc-build:local sh -c 'cd tools/rawin && \
//	  /usr/local/go1.27/bin/go run . > /tmp/r64 && GOARCH=386 /usr/local/go1.27/bin/go run . > /tmp/r32 && \
//	  cmp /tmp/r64 /tmp/r32 && cp /tmp/r64 ../../test/rawin/reference.h'
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"runtime"
)

// ---- uTLS, as it is (vendor/utls/conn.go:808-841) ----

type conn struct {
	rawInput bytes.Buffer
}

func (c *conn) readFromUntil(r io.Reader, n int) error {
	if c.rawInput.Len() >= n {
		return nil
	}
	needs := n - c.rawInput.Len()
	// There might be extra input waiting on the wire. Make a best effort
	// attempt to fetch it so that it can be used in (*Conn).Read to
	// "predict" closeNotify alerts.
	c.rawInput.Grow(needs + bytes.MinRead)
	for {
		buf := c.rawInput.AvailableBuffer()[:c.rawInput.Available()]
		n, err := r.Read(buf)
		c.rawInput.Write(buf[:n])
		needs -= n
		if needs <= 0 {
			if err == io.EOF {
				err = nil
			}
			return err
		}
		if err == io.EOF {
			return io.ErrUnexpectedEOF
		}
		if err != nil {
			return err
		}
	}
}

// ---- the socket ----

type feed struct {
	chunks []int
	ci     int
	left   int
	asked  []int
}

func (f *feed) Read(p []byte) (int, error) {
	f.asked = append(f.asked, len(p))
	if f.left == 0 {
		if f.ci == len(f.chunks) {
			return 0, io.EOF
		}
		f.left = f.chunks[f.ci]
		f.ci++
	}
	n := len(p)
	if n > f.left {
		n = f.left
	}
	f.left -= n
	return n, nil
}

// A record's body length; a negative one is a record whose header is refused (its |length| is
// still on the wire behind it), and nothing after it is read.
type tcase struct {
	recs   []int
	chunks []int
}

type result struct {
	asked         []int
	off, len, cap int
}

func run(tc tcase) result {
	var c conn
	f := &feed{chunks: tc.chunks}
	for _, body := range tc.recs {
		if err := c.readFromUntil(f, 5); err != nil {
			panic(err)
		}
		if body < 0 {
			break
		}
		if err := c.readFromUntil(f, 5+body); err != nil {
			panic(err)
		}
		c.rawInput.Next(5 + body)
	}
	blen := c.rawInput.Cap() - c.rawInput.Available()
	return result{f.asked, blen - c.rawInput.Len(), blen, c.rawInput.Cap()}
}

// ---- the cases ----

type rng struct{ s uint64 }

func (r *rng) next() uint64 {
	r.s ^= r.s << 13
	r.s ^= r.s >> 7
	r.s ^= r.s << 17
	return r.s
}

func (r *rng) intn(n int) int { return int(r.next() % uint64(n)) }

// A body the node sends: a handshake's small records, the middle sizes, TLS 1.3's largest and
// around it, and TLS 1.2's, up to 2^14 + 2048.
func (r *rng) body() int {
	switch r.intn(7) {
	case 0:
		return 1 + r.intn(64)
	case 1:
		return 17 + r.intn(600)
	case 2:
		return 600 + r.intn(3500)
	case 3:
		return 4000 + r.intn(12402)
	case 4:
		return 16401
	case 5:
		return 16401 - 8 + r.intn(17)
	default:
		return 16384 + r.intn(2049)
	}
}

// How the stream arrives: byte by byte, a segment at a time, several, everything at once.
func (r *rng) chunk() int {
	switch r.intn(6) {
	case 0:
		return 1 + r.intn(16)
	case 1:
		return 1 + r.intn(1448)
	case 2:
		return 1448 * (1 + r.intn(12))
	case 3:
		return 4096 + r.intn(60000)
	case 4:
		return 16406 * (1 + r.intn(4))
	default:
		return 1 << 20
	}
}

func chunksFor(r *rng, total int, style int) []int {
	var cs []int
	for left := total; left > 0; {
		var n int
		switch style {
		case 0:
			n = r.chunk()
		case 1:
			n = left // all of it there at once
		default:
			n = 1 + r.intn(style)
		}
		if n > left {
			n = left
		}
		cs = append(cs, n)
		left -= n
	}
	return cs
}

func streamLen(recs []int) int {
	t := 0
	for _, b := range recs {
		if b < 0 {
			return t + 5 + -b
		}
		t += 5 + b
	}
	return t
}

func cases() []tcase {
	r := &rng{0x9e3779b97f4a7c15}
	var cs []tcase
	add := func(recs []int, style int) {
		cs = append(cs, tcase{recs, chunksFor(r, streamLen(recs), style)})
	}
	// The stand's `huge`, after a download's worth of records and after none.
	for _, before := range []int{0, 1, 3, 12} {
		recs := []int{}
		for i := 0; i < before; i++ {
			recs = append(recs, 16401)
		}
		recs = append(recs, -16641)
		for _, style := range []int{0, 1, 1448, 9000} {
			add(append([]int(nil), recs...), style)
		}
	}
	// A handshake's shape: small records, then a certificate chain, then a download.
	for i := 0; i < 24; i++ {
		recs := []int{90 + r.intn(40), 1, 20 + r.intn(40), 2000 + r.intn(4000), 200 + r.intn(300), 52}
		for j := 0; j < 5+r.intn(40); j++ {
			recs = append(recs, 16401)
		}
		add(recs, []int{0, 1, 1448, 16406, 40000, 700}[i%6])
	}
	// Anything.
	for i := 0; i < 400; i++ {
		n := 1 + r.intn(60)
		recs := make([]int, n)
		for j := range recs {
			recs[j] = r.body()
		}
		if r.intn(8) == 0 {
			recs[n-1] = -(16641 + r.intn(50000))
		}
		style := 0
		switch r.intn(5) {
		case 0:
			style = 1
		case 1:
			style = 1 + r.intn(3000)
		}
		add(recs, style)
	}
	return cs
}

func main() {
	all := cases()
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	fmt.Fprintf(w, "/* Generated by tools/rawin with %s — do not edit. */\n", runtime.Version())
	var recs, chunks, asked []int
	type ix struct{ r, nr, c, nc, a, na, off, blen, cap int }
	var idx []ix
	for _, tc := range all {
		res := run(tc)
		idx = append(idx, ix{len(recs), len(tc.recs), len(chunks), len(tc.chunks), len(asked), len(res.asked),
			res.off, res.len, res.cap})
		recs = append(recs, tc.recs...)
		chunks = append(chunks, tc.chunks...)
		asked = append(asked, res.asked...)
	}
	list := func(name string, v []int) {
		fmt.Fprintf(w, "static const int32_t %s[] = {", name)
		for i, x := range v {
			if i%16 == 0 {
				fmt.Fprint(w, "\n")
			}
			fmt.Fprintf(w, "%d,", x)
		}
		fmt.Fprintln(w, "\n};")
	}
	list("rw_recs", recs)
	list("rw_chunks", chunks)
	list("rw_asked", asked)
	fmt.Fprintln(w, "static const struct rw_case { uint32_t recs, nrecs, chunks, nchunks, asked, nasked, off, len, cap; } rw_cases[] = {")
	for _, x := range idx {
		fmt.Fprintf(w, "{%d,%d,%d,%d,%d,%d,%d,%d,%d},\n", x.r, x.nr, x.c, x.nc, x.a, x.na, x.off, x.blen, x.cap)
	}
	fmt.Fprintln(w, "};")

	var steps []int
	prev := -1
	// Through bytes.Buffer itself: an empty one grown by c goes to growSlice for any c over
	// smallBufferSize, and that is the path whose rounding the reference's rawInput gets.
	for c := 65; c <= 70000; c++ {
		var b bytes.Buffer
		b.Grow(c)
		k := b.Cap()
		if k != prev {
			steps = append(steps, c, k)
			prev = k
		}
	}
	list("rw_roundup", steps)
}
