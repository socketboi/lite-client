package main

// The first flight as it crossed the wire, decrypted here rather than described by a tracer.
//
// qlog says which frames a packet carried and at what offsets, which settles the LAYOUT. It does not
// hand back the bytes, and two things this stand exists to compare are bytes: the ClientHello itself
// — every extension, in the order sent, with every length — and the transport parameters inside it
// as they were encoded, not as quic-go parsed them. So the server's socket is wrapped, every datagram
// a client sends is kept, and its Initial packets are opened with the keys RFC 9001 §5.2 derives from
// the destination connection ID of the client's first Initial. That derivation is public by design:
// anyone on the path can do exactly this, which is why the layout and the hello are a fingerprint.
//
// Written against the RFC and Go's standard library only — nothing from the library under test is
// used to read what that library produced.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/crypto/hkdf"
)

// rawConn keeps every datagram each source sends, until it has kept limit of them.
type rawConn struct {
	net.PacketConn
	dir   string
	limit int

	mu   sync.Mutex
	seen map[string][][]byte
}

func (c *rawConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err == nil && n > 0 {
		c.mu.Lock()
		key := addr.String()
		if len(c.seen[key]) < c.limit {
			c.seen[key] = append(c.seen[key], append([]byte(nil), p[:n]...))
			if err := c.flush(key); err != nil {
				fmt.Fprintln(os.Stderr, "raw:", err)
			}
		}
		c.mu.Unlock()
	}
	return n, addr, err
}

// flush rewrites the report for one source every time a datagram arrives, so that whatever point a
// client is killed at, the file holds everything it had sent.
func (c *rawConn) flush(key string) error {
	name := strings.NewReplacer(":", "_", "[", "", "]", "").Replace(key)
	var b strings.Builder
	hello := report(&b, c.seen[key])
	if err := os.WriteFile(filepath.Join(c.dir, name+".txt"), []byte(b.String()), 0o644); err != nil {
		return err
	}
	if len(hello) > 0 {
		return os.WriteFile(filepath.Join(c.dir, name+".hello"), hello, 0o644)
	}
	return nil
}

var initialSaltV1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}

// expandLabel is HKDF-Expand-Label from RFC 8446 §7.1 with an empty context.
func expandLabel(secret []byte, label string, n int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = binary.BigEndian.AppendUint16(info, uint16(n))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	out := make([]byte, n)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, secret, info), out); err != nil {
		panic(err)
	}
	return out
}

type initialKeys struct {
	aead cipher.AEAD
	iv   []byte
	hp   cipher.Block
}

func clientInitialKeys(dcid []byte) initialKeys {
	initial := hkdf.Extract(sha256.New, dcid, initialSaltV1)
	client := expandLabel(initial, "client in", 32)
	key := expandLabel(client, "quic key", 16)
	iv := expandLabel(client, "quic iv", 12)
	hp := expandLabel(client, "quic hp", 16)
	blk, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(blk)
	hpb, _ := aes.NewCipher(hp)
	return initialKeys{aead: aead, iv: iv, hp: hpb}
}

func varint(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, errors.New("short varint")
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0, errors.New("short varint")
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n, nil
}

type longPacket struct {
	typ     byte
	dcid    []byte
	scid    []byte
	token   []byte
	pn      uint64
	pnLen   int
	payload []byte // decrypted, Initial only
	size    int    // on the wire, this packet only
}

// parseDatagram walks every coalesced packet in a datagram. Initial packets are opened with keys
// from odcid; the others are reported by type and size only.
func parseDatagram(d []byte, odcid []byte) ([]longPacket, error) {
	var out []longPacket
	for len(d) > 0 {
		if d[0]&0x80 == 0 {
			out = append(out, longPacket{typ: 0xff, size: len(d)})
			return out, nil
		}
		if len(d) < 7 {
			return out, errors.New("short long header")
		}
		p := longPacket{typ: (d[0] >> 4) & 3}
		off := 5
		dl := int(d[off])
		off++
		if off+dl > len(d) {
			return out, errors.New("short dcid")
		}
		p.dcid = d[off : off+dl]
		off += dl
		sl := int(d[off])
		off++
		if off+sl > len(d) {
			return out, errors.New("short scid")
		}
		p.scid = d[off : off+sl]
		off += sl
		if p.typ == 0 {
			tl, n, err := varint(d[off:])
			if err != nil {
				return out, err
			}
			off += n
			p.token = d[off : off+int(tl)]
			off += int(tl)
		}
		length, n, err := varint(d[off:])
		if err != nil {
			return out, err
		}
		off += n
		pnOff := off
		end := pnOff + int(length)
		if end > len(d) {
			return out, errors.New("packet runs past the datagram")
		}
		p.size = end
		if p.typ == 0 && odcid != nil {
			k := clientInitialKeys(odcid)
			pkt := append([]byte(nil), d[:end]...)
			sample := pkt[pnOff+4 : pnOff+20]
			mask := make([]byte, 16)
			k.hp.Encrypt(mask, sample)
			pkt[0] ^= mask[0] & 0x0f
			p.pnLen = int(pkt[0]&3) + 1
			var pn uint64
			for i := 0; i < p.pnLen; i++ {
				pkt[pnOff+i] ^= mask[1+i]
				pn = pn<<8 | uint64(pkt[pnOff+i])
			}
			p.pn = pn
			nonce := append([]byte(nil), k.iv...)
			for i := 0; i < 8; i++ {
				nonce[11-i] ^= byte(pn >> (8 * i))
			}
			hdr := pkt[:pnOff+p.pnLen]
			pl, err := k.aead.Open(nil, nonce, pkt[pnOff+p.pnLen:end], hdr)
			if err != nil {
				return out, fmt.Errorf("Initial does not open: %w", err)
			}
			p.payload = pl
		}
		out = append(out, p)
		d = d[end:]
	}
	return out, nil
}

type cryptoPiece struct {
	off  uint64
	data []byte
}

// frames describes an Initial payload frame by frame, run-length folding PADDING, and collects the
// CRYPTO pieces it carries.
func frames(pl []byte, pieces *[]cryptoPiece) (string, error) {
	var parts []string
	for len(pl) > 0 {
		switch t := pl[0]; {
		case t == 0x00:
			n := 0
			for n < len(pl) && pl[n] == 0 {
				n++
			}
			parts = append(parts, fmt.Sprintf("pad(%d)", n))
			pl = pl[n:]
		case t == 0x01:
			parts = append(parts, "ping")
			pl = pl[1:]
		case t == 0x02 || t == 0x03:
			b := pl[1:]
			var vals [4]uint64
			for i := 0; i < 4; i++ {
				v, n, err := varint(b)
				if err != nil {
					return "", err
				}
				vals[i] = v
				b = b[n:]
			}
			// largest, delay, range count, first range; then count pairs of gap and range.
			for i := uint64(0); i < vals[2]*2; i++ {
				_, n, err := varint(b)
				if err != nil {
					return "", err
				}
				b = b[n:]
			}
			if t == 0x03 {
				for i := 0; i < 3; i++ {
					_, n, err := varint(b)
					if err != nil {
						return "", err
					}
					b = b[n:]
				}
			}
			parts = append(parts, fmt.Sprintf("ack(largest %d, %d bytes)", vals[0], len(pl)-len(b)))
			pl = b
		case t == 0x06:
			b := pl[1:]
			o, n, err := varint(b)
			if err != nil {
				return "", err
			}
			b = b[n:]
			l, n, err := varint(b)
			if err != nil {
				return "", err
			}
			b = b[n:]
			if uint64(len(b)) < l {
				return "", errors.New("short CRYPTO")
			}
			*pieces = append(*pieces, cryptoPiece{o, b[:l]})
			parts = append(parts, fmt.Sprintf("crypto(%d+%d)", o, l))
			pl = b[l:]
		default:
			parts = append(parts, fmt.Sprintf("frame 0x%02x (%d bytes left)", t, len(pl)))
			pl = nil
		}
	}
	return strings.Join(parts, " "), nil
}

var typeName = map[byte]string{0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry", 0xff: "1-RTT"}

// report writes the flight and returns the ClientHello reassembled from its CRYPTO pieces — the
// longest contiguous run from offset zero, which is the whole hello once the flight is complete.
func report(w *strings.Builder, dgrams [][]byte) []byte {
	var odcid []byte
	var pieces []cryptoPiece
	for i, d := range dgrams {
		if odcid == nil && len(d) > 6 && d[0]&0x80 != 0 && (d[0]>>4)&3 == 0 {
			odcid = append([]byte(nil), d[6:6+int(d[5])]...)
		}
		pkts, err := parseDatagram(d, odcid)
		fmt.Fprintf(w, "datagram %d: %d bytes\n", i, len(d))
		for _, p := range pkts {
			if p.typ == 0xff {
				fmt.Fprintf(w, "  1-RTT %d bytes\n", p.size)
				continue
			}
			fmt.Fprintf(w, "  %s dcid=%d scid=%d token=%d size=%d", typeName[p.typ], len(p.dcid), len(p.scid), len(p.token), p.size)
			if p.payload != nil {
				desc, ferr := frames(p.payload, &pieces)
				fmt.Fprintf(w, " pn=%d/%d payload=%d: %s", p.pn, p.pnLen, len(p.payload), desc)
				if ferr != nil {
					fmt.Fprintf(w, " [%v]", ferr)
				}
			}
			fmt.Fprintln(w)
		}
		if err != nil {
			fmt.Fprintf(w, "  [%v]\n", err)
		}
	}
	sort.SliceStable(pieces, func(i, j int) bool { return pieces[i].off < pieces[j].off })
	var hello []byte
	for _, p := range pieces {
		if p.off > uint64(len(hello)) {
			break
		}
		if end := p.off + uint64(len(p.data)); end > uint64(len(hello)) {
			hello = append(hello, p.data[uint64(len(hello))-p.off:]...)
		}
	}
	if len(hello) >= 4 {
		want := 4 + (int(hello[1])<<16 | int(hello[2])<<8 | int(hello[3]))
		if len(hello) >= want {
			hello = hello[:want]
			fmt.Fprintf(w, "ClientHello: %d bytes\n", len(hello))
			describeHello(w, hello)
		} else {
			fmt.Fprintf(w, "ClientHello: %d of %d bytes\n", len(hello), want)
		}
	}
	fmt.Fprintf(w, "odcid %s\n", hex.EncodeToString(odcid))
	return hello
}

func describeHello(w *strings.Builder, h []byte) {
	b := h[4:]
	if len(b) < 35 {
		return
	}
	fmt.Fprintf(w, "  legacy_version %04x\n", binary.BigEndian.Uint16(b))
	b = b[34:]
	sid := int(b[0])
	fmt.Fprintf(w, "  session_id %d bytes\n", sid)
	b = b[1+sid:]
	cs := int(binary.BigEndian.Uint16(b))
	var suites []string
	for i := 0; i < cs; i += 2 {
		suites = append(suites, fmt.Sprintf("%04x", binary.BigEndian.Uint16(b[2+i:])))
	}
	fmt.Fprintf(w, "  suites %s\n", strings.Join(suites, " "))
	b = b[2+cs:]
	b = b[1+int(b[0]):]
	b = b[2:]
	for len(b) >= 4 {
		t := binary.BigEndian.Uint16(b)
		n := int(binary.BigEndian.Uint16(b[2:]))
		body := b[4 : 4+n]
		fmt.Fprintf(w, "  ext %5d len %4d", t, n)
		switch t {
		case 57:
			fmt.Fprintf(w, "  %s", describeParams(body))
		case 0x0033:
			fmt.Fprintf(w, "  %s", describeKeyShare(body))
		case 0xfe0d:
			fmt.Fprintf(w, "  %s", hex.EncodeToString(body[:min(len(body), 8)]))
		default:
			if n <= 40 {
				fmt.Fprintf(w, "  %s", hex.EncodeToString(body))
			}
		}
		fmt.Fprintln(w)
		b = b[4+n:]
	}
}

func describeKeyShare(b []byte) string {
	var parts []string
	b = b[2:]
	for len(b) >= 4 {
		g := binary.BigEndian.Uint16(b)
		n := int(binary.BigEndian.Uint16(b[2:]))
		parts = append(parts, fmt.Sprintf("%04x:%d", g, n))
		b = b[4+n:]
	}
	return strings.Join(parts, " ")
}

func describeParams(b []byte) string {
	var parts []string
	for len(b) > 0 {
		id, n, err := varint(b)
		if err != nil {
			return strings.Join(parts, " ") + " [bad]"
		}
		b = b[n:]
		l, n, err := varint(b)
		if err != nil || uint64(len(b)-n) < l {
			return strings.Join(parts, " ") + " [bad]"
		}
		v := b[n : n+int(l)]
		b = b[n+int(l):]
		if val, vn, err := varint(v); err == nil && vn == len(v) && id != 0x0f {
			parts = append(parts, fmt.Sprintf("%x=%d(%dB)", id, val, len(v)))
		} else {
			parts = append(parts, fmt.Sprintf("%x=[%s]", id, hex.EncodeToString(v)))
		}
	}
	return strings.Join(parts, " ")
}
