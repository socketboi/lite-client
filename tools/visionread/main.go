// What the reference's Vision reader makes of a stream, record by record — its own ReadMultiBuffer,
// XtlsUnpadding and XtlsFilterTls, run rather than transcribed. Writes test/vision/reference_read.h,
// which test/vision holds lc_vision_read to.
//
// FROZEN, NOT BUILT BY THE GATE: this imports github.com/xtls/xray-core/proxy, whose module pulls
// dozens of dependencies, and `make check` runs with --network none. Regenerate in the build image
// with the network on, from the repository root:
//
//	docker run --rm -v "$PWD:/repo" lc-build:local sh -c 'cp -r /repo/vendor/Xray-core /tmp/x \
//	  && mkdir /tmp/x/visionread && cp /repo/tools/visionread/main.go /tmp/x/visionread/ \
//	  && cd /tmp/x && go run ./visionread /repo/test/vision/reference_read.h'
//
// To a file named on the command line, not to stdout: the reference's debug log goes there, one
// line per block it unpads.
//
// HOW THE READS ARE CUT is the one thing supplied here rather than run, and it is the reference's
// too: on the downlink the Vision reader reads through a SingleReader over the REALITY connection
// (vendor/Xray-core/common/buf/io.go:113-145), whose every read is one Read into an 8192-byte
// buffer (vendor/Xray-core/common/buf/reader.go:28-36, :157-160), and the connection's Read returns
// what is left of the current record and no more (vendor/utls/u_conn.go:874-885). So each record
// below is handed over in reads of at most 8192 bytes, and the connection's `input` — what the
// reader merges when it switches to direct copy — is the rest of that record.
//
// The streams are built the way a server frames them and then cut at random, with a lean towards
// cuts that land inside a UUID or a header, towards records longer than one read, and towards a
// UUID at the start of a read that is not the first. Every stream stops after the record that
// switches to direct copy: after that the reader no longer reads records.
package main

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/proxy"
)

var uuid = []byte{0x3c, 0x9a, 0x51, 0x07, 0xe2, 0x4b, 0x4d, 0x18, 0x9f, 0x60, 0x2a, 0xc7, 0x11, 0x85, 0xd3, 0x6e}

// A piece of a stream: literal bytes, n copies of one byte, or n bytes of a pattern drawn from a
// seed — so that a 16 KB record costs the header file a line rather than eight thousand, and
// content that must merely be distinct from its neighbours is not spelled out byte by byte.
type piece struct {
	lit  []byte
	n    int
	fill byte
	pat  bool
	seed uint32
}

// The pattern test/vision reproduces: a 32-bit LCG, the high byte of each step.
func pattern(seed uint32, n int) []byte {
	b := make([]byte, n)
	x := seed
	for i := range b {
		x = x*1103515245 + 12345
		b[i] = byte(x >> 24)
	}
	return b
}

type records struct {
	chunks [][]byte
	input  *bytes.Reader
	rest   [][]byte
}

// One record at a time, one read of at most 8192 bytes per call.
func (r *records) ReadMultiBuffer() (buf.MultiBuffer, error) {
	c := r.chunks[0]
	r.chunks = r.chunks[1:]
	var rest []byte
	for _, x := range r.chunks {
		rest = append(rest, x...)
	}
	r.input.Reset(rest)
	b := buf.New()
	b.Write(c)
	return buf.MultiBuffer{b}, nil
}

// A TLS 1.3 ServerHello as the filter reads it: the record and handshake headers, a 32-byte session
// id (so the suite sits where XtlsFilterTls looks, at 43 + 32 + 1), and supported_versions. The
// random, the id and the key share are a fixed pattern — the filter reads none of them.
func serverHello(cipher uint16) []byte {
	h := []byte{0x03, 0x03}
	h = append(h, pattern(1, 32)...)
	h = append(h, 0x20)
	h = append(h, pattern(2, 32)...)
	h = append(h, byte(cipher>>8), byte(cipher), 0x00)
	ext := []byte{0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20}
	ext = append(ext, pattern(3, 32)...)
	ext = append(ext, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04)
	h = append(h, byte(len(ext)>>8), byte(len(ext)))
	h = append(h, ext...)
	hs := append([]byte{0x02, 0x00, byte(len(h) >> 8), byte(len(h))}, h...)
	return append([]byte{0x16, 0x03, 0x03, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

func randomBytes(rng *rand.Rand, n int) piece {
	return piece{n: n, pat: true, seed: rng.Uint32()}
}

func frameHeader(withUUID bool, cmd byte, content, padding int) []byte {
	var h []byte
	if withUUID {
		h = append(h, uuid...)
	}
	return append(h, cmd, byte(content>>8), byte(content), byte(padding>>8), byte(padding))
}

// A frame: its header, its content (literal, a ServerHello, or filler) and its padding.
func frame(rng *rand.Rand, withUUID bool, cmd byte, hello bool) []piece {
	var content piece
	switch {
	case hello:
		ciphers := []uint16{0x1301, 0x1302, 0x1303, 0x1305, 0xc02f}
		content = piece{lit: serverHello(ciphers[rng.Intn(len(ciphers))])}
	case rng.Intn(4) == 0:
		content = piece{n: rng.Intn(8000), fill: 'c'}
	default:
		content = randomBytes(rng, rng.Intn(300))
	}
	clen := len(content.lit) + content.n
	padding := rng.Intn(256)
	if rng.Intn(3) == 0 {
		padding = rng.Intn(1400)
	}
	return []piece{{lit: frameHeader(withUUID, cmd, clen, padding)}, content, {n: padding, fill: 0}}
}

func lastCommand(rng *rand.Rand) byte {
	switch rng.Intn(6) {
	case 0, 1:
		return 1
	case 2, 3:
		return 2
	case 4:
		return byte(3 + rng.Intn(253))
	}
	return 0
}

func scenario(rng *rand.Rand, kind int) []piece {
	var s []piece
	switch kind {
	case 0: // what a server sends: the UUID once, frames, and a way out of them
		k := rng.Intn(5)
		for i := 0; i <= k; i++ {
			s = append(s, frame(rng, i == 0, 0, i == 0 && rng.Intn(2) == 0)...)
		}
		s = append(s, frame(rng, false, lastCommand(rng), false)...)
		if rng.Intn(2) == 0 {
			s = append(s, randomBytes(rng, rng.Intn(60)))
		}
		if rng.Intn(3) == 0 { // and the UUID again, which the reference may or may not look for
			s = append(s, frame(rng, true, lastCommand(rng), false)...)
			s = append(s, randomBytes(rng, 1+rng.Intn(100)))
		}
	case 1: // a peer that does not frame, with a framed stretch somewhere in it
		s = append(s, randomBytes(rng, 1+rng.Intn(80)))
		if rng.Intn(2) == 0 {
			s = append(s, piece{n: rng.Intn(9000), fill: 'r'})
		}
		s = append(s, frame(rng, true, byte(rng.Intn(4)), rng.Intn(3) == 0)...)
		s = append(s, randomBytes(rng, rng.Intn(100)))
	case 2: // a UUID exactly at the start of the second read of a long record
		s = append(s, piece{n: 8192, fill: 'r'})
		s = append(s, frame(rng, true, lastCommand(rng), false)...)
		s = append(s, randomBytes(rng, rng.Intn(100)))
	}
	return s
}

func flatten(s []piece) []byte {
	var b []byte
	for _, p := range s {
		b = append(b, p.lit...)
		if p.pat {
			b = append(b, pattern(p.seed, p.n)...)
		} else {
			b = append(b, bytes.Repeat([]byte{p.fill}, p.n)...)
		}
	}
	return b
}

func cuts(rng *rand.Rand, total, kind int) []int {
	var out []int
	for left := total; left > 0; {
		var n int
		switch r := rng.Intn(10); {
		case kind == 2 && len(out) == 0:
			n = 16384
		case r < 4:
			n = 1 + rng.Intn(40)
		case r < 7:
			n = 1 + rng.Intn(1500)
		case r < 9:
			n = 1 + rng.Intn(16384)
		default:
			n = 8192 + rng.Intn(200)
		}
		if n > left {
			n = left
		}
		out = append(out, n)
		left -= n
	}
	return out
}

func fnv(b []byte) uint64 {
	h := uint64(14695981039346656037)
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func main() {
	rng := rand.New(rand.NewSource(20260924))
	var pool []byte
	at := map[string]int{}
	var pieces, scen, recs []string
	a, _ := net.Pipe()

	for i := 0; i < 240; i++ {
		kind := i % 3
		s := scenario(rng, kind)
		stream := flatten(s)
		firstPiece := len(pieces)
		for _, p := range s {
			if p.lit != nil {
				o, seen := at[string(p.lit)]
				if !seen {
					o = len(pool)
					at[string(p.lit)] = o
					pool = append(pool, p.lit...)
				}
				pieces = append(pieces, fmt.Sprintf("{%d, %d, -1}", o, len(p.lit)))
			}
			if p.n > 0 && p.pat {
				pieces = append(pieces, fmt.Sprintf("{%du, %d, -2}", p.seed, p.n))
			} else if p.n > 0 {
				pieces = append(pieces, fmt.Sprintf("{0, %d, %d}", p.n, p.fill))
			}
		}

		ts := proxy.NewTrafficState(uuid)
		input := &bytes.Reader{}
		raw := &bytes.Buffer{}
		src := &records{input: input}
		vr := proxy.NewVisionReader(src, ts, false, context.Background(), a, input, &raw, nil)

		firstRec := len(recs)
		off := 0
		for _, n := range cuts(rng, len(stream), kind) {
			rec := stream[off : off+n]
			off += n
			src.chunks = nil
			for c := 0; c < len(rec); c += 8192 {
				e := c + 8192
				if e > len(rec) {
					e = len(rec)
				}
				src.chunks = append(src.chunks, rec[c:e])
			}
			var out []byte
			for len(src.chunks) > 0 && !ts.Outbound.DownlinkReaderDirectCopy {
				mb, err := vr.ReadMultiBuffer()
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
				for _, b := range mb {
					out = append(out, b.Bytes()...)
				}
				buf.ReleaseMulti(mb)
			}
			o := ts.Outbound
			recs = append(recs, fmt.Sprintf("{%d, %d, 0x%016xull, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d}",
				n, len(out), fnv(out), ts.NumberOfPacketToFilter, b2i(o.WithinPaddingBuffers),
				b2i(o.DownlinkReaderDirectCopy), o.RemainingCommand, o.RemainingContent, o.RemainingPadding,
				o.CurrentCommand, b2i(ts.IsTLS), b2i(ts.IsTLS12orAbove), b2i(ts.EnableXtls), ts.Cipher,
				ts.RemainingServerHello))
			if o.DownlinkReaderDirectCopy {
				break
			}
		}
		scen = append(scen, fmt.Sprintf("{%d, %d, %d, %d}", firstPiece, len(pieces)-firstPiece, firstRec, len(recs)-firstRec))
	}

	var w strings.Builder
	w.WriteString("/* Generated by tools/visionread from vendor/Xray-core's own VisionReader; see its header for how\n")
	w.WriteString(" * to regenerate. Do not edit. */\n#ifndef LC_VISION_REFERENCE_READ_H\n#define LC_VISION_REFERENCE_READ_H\n\n")
	w.WriteString("#include <stdint.h>\n\nstatic const uint8_t vr_uuid[16] = {")
	for i, c := range uuid {
		if i > 0 {
			w.WriteString(", ")
		}
		fmt.Fprintf(&w, "0x%02x", c)
	}
	w.WriteString("};\n\nstatic const uint8_t vr_pool[] = {")
	for i, c := range pool {
		if i%24 == 0 {
			w.WriteString("\n   ")
		}
		fmt.Fprintf(&w, " %d,", c)
	}
	w.WriteString("\n};\n\n/* -1: a literal, `off` into vr_pool; -2: a pattern, `off` its seed; else the byte a filler repeats */\n")
	w.WriteString("static const struct { uint32_t off, len; int fill; } vr_pieces[] = {\n")
	for _, p := range pieces {
		fmt.Fprintf(&w, "    %s,\n", p)
	}
	w.WriteString("};\n\n/* the record's length, then what the reads of it returned and the state after them */\n")
	w.WriteString("static const struct {\n    uint32_t len, out_len;\n    uint64_t out_fnv;\n")
	w.WriteString("    int32_t  filter, within, direct, rcommand, rcontent, rpadding, command, is_tls, tls12, xtls,\n")
	w.WriteString("             cipher, server_hello;\n} vr_records[] = {\n")
	for _, r := range recs {
		fmt.Fprintf(&w, "    %s,\n", r)
	}
	w.WriteString("};\n\nstatic const struct { uint32_t piece, pieces, record, records; } vr_streams[] = {\n")
	for _, s := range scen {
		fmt.Fprintf(&w, "    %s,\n", s)
	}
	w.WriteString("};\n\n#endif\n")
	if err := os.WriteFile(os.Args[1], []byte(w.String()), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
