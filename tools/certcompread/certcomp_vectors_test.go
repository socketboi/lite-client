// What the reference does with a CompressedCertificate — its own decompressCert, run rather than
// transcribed (vendor/utls/u_handshake_client.go:52-139). Writes test/certcomp/reference_open.h,
// which test/certcomp holds lc_certcomp_open to.
//
// A TEST OF uTLS's OWN PACKAGE, because decompressCert is unexported: this file is dropped into a
// copy of vendor/utls and run with `go test`, so the function called is the pinned one, with the
// brotli and zstd readers its go.mod pins — the same versions Xray-core's go.mod pins, which is
// what the reference binary is built with. FROZEN, NOT BUILT BY THE GATE: `make check` runs with
// --network none and these modules have to be fetched. Regenerate in the build image, from the
// repository root:
//
//	docker run --rm -v "$PWD:/repo" lc-build:local sh -c 'cp -r /repo/vendor/utls /tmp/u \
//	  && cp /repo/tools/certcompread/certcomp_vectors_test.go /tmp/u/ \
//	  && cd /tmp/u && CERTCOMP_OUT=/repo/test/certcomp/reference_open.h \
//	     go test -run TestCertcompVectors -count=1 .'
//
// WHAT IS RECORDED is what decides the client's answer: the alert decompressCert sent, read off the
// bytes it wrote to the connection (42 for a stream it would not take, 10 for one it took and could
// not read as a Certificate), or none; and for brotli, the one algorithm the Chrome parrot offers, the
// error it returned, which the Hysteria2 plane closes with under that parrot (vendor/utls-hy runs
// the same decompressCert, and hysteria's go.mod the same brotli decoder: v1.1.0, whose reader and
// decoder are v1.0.6's file for file). What an accepted stream opened to is not recorded, because
// there is only one thing it can be: the first `declared` bytes of the stream's output, which the
// C side already has.
//
// The streams: a Certificate message body of a chosen length — valid, so that what is being
// measured is the decompression and not the message — compressed by each algorithm's Go encoder,
// once in one piece and once flushed every 500 bytes (for zstd, as two frames); then mutated the
// ways a peer can: another declared length, cut short, a byte altered, bytes after the end, an
// empty run. One zstd frame names a dictionary nobody has (withDictID), one asks for a window over
// the reference's maximum (withWindow).
package tls

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

type sink struct{ w bytes.Buffer }

func (s *sink) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (s *sink) Write(b []byte) (int, error)      { return s.w.Write(b) }
func (s *sink) Close() error                     { return nil }
func (s *sink) LocalAddr() net.Addr              { return nil }
func (s *sink) RemoteAddr() net.Addr             { return nil }
func (s *sink) SetDeadline(time.Time) error      { return nil }
func (s *sink) SetReadDeadline(time.Time) error  { return nil }
func (s *sink) SetWriteDeadline(time.Time) error { return nil }

// The body test/certcomp builds too: an empty context, one certificate of n-9 bytes whose bytes
// repeat every 97 (so that a quarter of a megabyte compresses to a few kilobytes), no extensions.
func certBody(n int, seed uint32) []byte {
	b := make([]byte, n)
	list := n - 4
	cert := n - 9
	b[1], b[2], b[3] = byte(list>>16), byte(list>>8), byte(list)
	b[4], b[5], b[6] = byte(cert>>16), byte(cert>>8), byte(cert)
	x := seed
	var period [97]byte
	for i := range period {
		x = x*1103515245 + 12345
		period[i] = byte(x >> 24)
	}
	for i := 0; i < cert; i++ {
		b[7+i] = period[i%97]
	}
	return b
}

func compress(alg uint16, plain []byte, split bool) []byte {
	var out bytes.Buffer
	write := func(w io.Writer, flush func() error) {
		if !split {
			w.Write(plain)
			return
		}
		for off := 0; off < len(plain); off += 500 {
			w.Write(plain[off:min(off+500, len(plain))])
			flush()
		}
	}
	switch alg {
	case 1:
		w := zlib.NewWriter(&out)
		write(w, w.Flush)
		w.Close()
	case 2:
		w := brotli.NewWriter(&out)
		write(w, w.Flush)
		w.Close()
	case 3:
		enc, _ := zstd.NewWriter(nil)
		if split {
			half := len(plain) / 2
			out.Write(enc.EncodeAll(plain[:half], nil))
			out.Write(enc.EncodeAll(plain[half:], nil))
		} else {
			out.Write(enc.EncodeAll(plain, nil))
		}
		enc.Close()
	}
	return out.Bytes()
}

// The same zstd frame naming dictionary 7 — which no decoder here has, and which the frame never
// uses: a one-byte Dictionary_ID inserted after the descriptor (and the window byte, if there is
// one), its flag set in the descriptor.
func withDictID(run []byte) []byte {
	fhd := run[4]
	at := 6
	if fhd&0x20 != 0 {
		at = 5
	}
	out := append([]byte(nil), run[:at]...)
	out[4] = fhd | 1
	out = append(out, 7)
	return append(out, run[at:]...)
}

// The same zstd frame asking for a window of 1<<30, over klauspost's MaxWindowSize of 1<<29 and
// within libzstd's: the Window_Descriptor 0xa0 (exponent 20, so 1<<30), the single-segment flag
// cleared — and with it the one-byte content size such a frame carries when its size flag is 0.
func withWindow(run []byte) []byte {
	fhd := run[4]
	if fhd&0x20 == 0 {
		out := append([]byte(nil), run...)
		out[5] = 0xa0
		return out
	}
	rest := run[5:]
	if fhd>>6 == 0 {
		rest = rest[1:]
	}
	out := append([]byte(nil), run[:4]...)
	out = append(out, fhd&^0x20, 0xa0)
	return append(out, rest...)
}

// A mutation: the declared length, how many bytes to cut off the end, which byte to flip (-1: none;
// an offset from the start of the stream) and how many bytes of 0xa5 to append.
type mutation struct {
	declared, cut, flip, extra int
}

func open(alg uint16, declared int, run []byte) (alert int, why string) {
	s := &sink{}
	c := &Conn{conn: s, isClient: true, config: &Config{}}
	u := &UConn{Conn: c, certCompressionAlgs: []CertCompressionAlgo{CertCompressionZlib, CertCompressionBrotli, CertCompressionZstd}}
	hs := &clientHandshakeStateTLS13{c: c, uconn: u}
	m := utlsCompressedCertificateMsg{algorithm: alg, uncompressedLength: uint32(declared), compressedCertificateMessage: run}
	msg, err := hs.decompressCert(m)
	if err != nil {
		why = err.Error()
	}
	w := s.w.Bytes()
	switch {
	case len(w) >= 7 && w[0] == 0x15:
		return int(w[6]), why
	case msg != nil && err == nil:
		return 0, why
	}
	return -1, why // neither accepted nor refused with an alert: the header file says so, and the test fails
}

func TestCertcompVectors(t *testing.T) {
	var pool []byte
	var bases, cases []string
	sizes := []int{2000, 32768, 32769, 40000, 262144, 300000}
	seed := uint32(20260924)
	for _, alg := range []uint16{1, 2, 3} {
		for _, n := range sizes {
			for _, split := range []bool{false, true} {
				if split && n > 40000 {
					continue
				}
				seed++
				plain := certBody(n, seed)
				run := compress(alg, plain, split)
				if alg == 3 && split && n == 2000 {
					run = withDictID(compress(alg, plain, false))
				}
				if alg == 3 && split && n == 32769 {
					run = withWindow(compress(alg, plain, false))
				}
				b := len(bases)
				bases = append(bases, fmt.Sprintf("{%d, %d, %du, %d, %d}", alg, n, seed, len(pool), len(run)))
				pool = append(pool, run...)

				ms := []mutation{
					{n, 0, -1, 0}, {n - 1, 0, -1, 0}, {n + 1, 0, -1, 0}, {0, 0, -1, 0}, {1, 0, -1, 0},
					{n / 2, 0, -1, 0}, {n, 1, -1, 0}, {n, 4, -1, 0}, {n, 0, len(run) - 1, 0},
					{n, 0, len(run) / 2, 0}, {n / 2, 0, len(run) * 3 / 5, 0}, {n - 1, 0, len(run) - 1, 0},
					{n, 0, -1, 1}, {n, 0, -1, 7}, {n - 1, 0, -1, 1}, {n / 2, 4, -1, 0},
					{0, 0, 0, 0}, {0, len(run), -1, 0}, {n, 0, 0, 0},
				}
				for _, mu := range ms {
					r := append([]byte(nil), run[:len(run)-mu.cut]...)
					if mu.flip >= 0 && mu.flip < len(r) {
						r[mu.flip] ^= 0xff
					}
					r = append(r, bytes.Repeat([]byte{0xa5}, mu.extra)...)
					// zstd's reader runs ahead in goroutines and does not wait for a block after
					// the first, so the same stream can answer differently from one run to the
					// next: a block not yet ready is a short read, which is 42. The answer kept
					// is the one with the blocks ready — any run that did not refuse, out of
					// thirty. And the case is marked when that answer is not what one core gives,
					// where the decoder is synchronous and a read never passes its first block.
					a, why := open(alg, mu.declared, r)
					if alg != 2 {
						why = ""
					}
					racy := 0
					if alg == 3 {
						for k := 0; k < 30 && a == 42; k++ {
							a, _ = open(alg, mu.declared, r)
						}
						prev := runtime.GOMAXPROCS(1)
						if one, _ := open(alg, mu.declared, r); one != a {
							racy = 1
						}
						runtime.GOMAXPROCS(prev)
					}
					cases = append(cases, fmt.Sprintf("{%d, %d, %d, %d, %d, %d, %d, %q}", b, mu.declared, mu.cut, mu.flip, mu.extra, a, racy, why))
				}
			}
		}
	}

	var w strings.Builder
	w.WriteString("/* Generated by tools/certcompread from vendor/utls's own decompressCert; see its header for how\n")
	w.WriteString(" * to regenerate. Do not edit. */\n#ifndef LC_CERTCOMP_REFERENCE_OPEN_H\n#define LC_CERTCOMP_REFERENCE_OPEN_H\n\n")
	w.WriteString("#include <stdint.h>\n\nstatic const uint8_t co_pool[] = {")
	for i, c := range pool {
		if i%24 == 0 {
			w.WriteString("\n   ")
		}
		fmt.Fprintf(&w, " %d,", c)
	}
	w.WriteString("\n};\n\n/* algorithm, the body's length and seed (see certBody), and the stream: offset and length in\n")
	w.WriteString(" * co_pool; odd entries of the same algorithm and size were flushed every 500 bytes (zstd: two\n")
	w.WriteString(" * frames — but at 2000 bytes, the one-piece frame naming dictionary 7) */\n")
	w.WriteString("static const struct { unsigned alg, plain_len; uint32_t seed; uint32_t off, len; } co_bases[] = {\n")
	for _, b := range bases {
		fmt.Fprintf(&w, "    %s,\n", b)
	}
	w.WriteString("};\n\n/* base, the length declared, bytes cut off the end, the byte flipped (-1: none), bytes of 0xa5\n")
	w.WriteString(" * appended — and the alert the reference sent, 0 for none; then 1 where thirty runs of it\n")
	w.WriteString(" * disagreed, and the alert is the one with the next zstd block ready; then, for brotli, the\n")
	w.WriteString(" * error decompressCert returned, \"\" for none */\n")
	w.WriteString("static const struct { unsigned base; int declared, cut, flip, extra, alert, racy; const char *why; } co_cases[] = {\n")
	for _, c := range cases {
		fmt.Fprintf(&w, "    %s,\n", c)
	}
	w.WriteString("};\n\n#endif\n")
	if err := os.WriteFile(os.Getenv("CERTCOMP_OUT"), []byte(w.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}
