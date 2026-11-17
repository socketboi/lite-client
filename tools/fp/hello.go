package main

// ClientHello parsing, down to individual extensions. All subcommands need it: `show` prints the
// breakdown, `diff` compares through it, `table` turns it into a fingerprint table.
//
// This is NOT a TLS implementation — records, state and ciphers are none of its business. It reads
// exactly one handshake message and lays it out as fields, because acceptance of the client is
// phrased in those fields: "extension order matches", "same groups in key_share", "GREASE sits in
// the same places".

import (
	"encoding/binary"
	"fmt"
)

// Extension is one extension as it appears on the wire: a number and an opaque body.
type Extension struct {
	Type uint16
	Data []byte
}

// ClientHello is the parsed message. Raw is kept whole — byte comparison works on it, and the
// breakdown only exists to explain WHERE two messages diverge.
type ClientHello struct {
	Raw           []byte
	LegacyVersion uint16
	Random        []byte
	SessionID     []byte
	CipherSuites  []uint16
	Compression   []uint8
	Extensions    []Extension

	// Offset of session_id within Raw. REALITY writes 32 bytes there at a fixed position, so the
	// client has to land exactly here — hence the offset is computed, not assumed to be 39.
	SessionIDOffset int
}

type reader struct {
	b   []byte
	off int
}

func (r *reader) need(n int) ([]byte, error) {
	if r.off+n > len(r.b) {
		return nil, fmt.Errorf("truncated at offset %d: need %d bytes, %d left", r.off, n, len(r.b)-r.off)
	}
	v := r.b[r.off : r.off+n]
	r.off += n
	return v, nil
}

func (r *reader) u8() (uint8, error) {
	v, err := r.need(1)
	if err != nil {
		return 0, err
	}
	return v[0], nil
}

func (r *reader) u16() (uint16, error) {
	v, err := r.need(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(v), nil
}

// ParseClientHello accepts either a bare handshake message or a whole TLS record (0x16 0x03 0x01
// len ...) — both turn up in captures, and confusing them is easy.
func ParseClientHello(raw []byte) (*ClientHello, error) {
	body := raw
	if len(raw) >= 5 && raw[0] == 0x16 {
		recLen := int(binary.BigEndian.Uint16(raw[3:5]))
		if 5+recLen > len(raw) {
			return nil, fmt.Errorf("record claims %d bytes, file holds %d", recLen, len(raw)-5)
		}
		body = raw[5 : 5+recLen]
	}
	if len(body) < 4 || body[0] != 0x01 {
		return nil, fmt.Errorf("not a ClientHello: handshake type is 0x%02x", body[0])
	}
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if 4+hsLen > len(body) {
		return nil, fmt.Errorf("handshake claims %d bytes, %d available", hsLen, len(body)-4)
	}

	ch := &ClientHello{Raw: body}
	r := &reader{b: body, off: 4}

	var err error
	if ch.LegacyVersion, err = r.u16(); err != nil {
		return nil, err
	}
	if ch.Random, err = r.need(32); err != nil {
		return nil, err
	}

	sidLen, err := r.u8()
	if err != nil {
		return nil, err
	}
	ch.SessionIDOffset = r.off
	if ch.SessionID, err = r.need(int(sidLen)); err != nil {
		return nil, err
	}

	csLen, err := r.u16()
	if err != nil {
		return nil, err
	}
	if csLen%2 != 0 {
		return nil, fmt.Errorf("cipher suite list length is odd: %d", csLen)
	}
	for i := 0; i < int(csLen)/2; i++ {
		cs, err := r.u16()
		if err != nil {
			return nil, err
		}
		ch.CipherSuites = append(ch.CipherSuites, cs)
	}

	compLen, err := r.u8()
	if err != nil {
		return nil, err
	}
	comp, err := r.need(int(compLen))
	if err != nil {
		return nil, err
	}
	ch.Compression = append(ch.Compression, comp...)

	// A hello may legitimately carry no extensions at all in TLS 1.0 — not from a browser, but the
	// parser should not fall over on it.
	if r.off == len(body) {
		return ch, nil
	}
	extTotal, err := r.u16()
	if err != nil {
		return nil, err
	}
	end := r.off + int(extTotal)
	if end > len(body) {
		return nil, fmt.Errorf("extension block claims %d bytes, %d available", extTotal, len(body)-r.off)
	}
	for r.off < end {
		t, err := r.u16()
		if err != nil {
			return nil, err
		}
		l, err := r.u16()
		if err != nil {
			return nil, err
		}
		d, err := r.need(int(l))
		if err != nil {
			return nil, err
		}
		ch.Extensions = append(ch.Extensions, Extension{Type: t, Data: d})
	}
	return ch, nil
}

// IsGREASE recognises the reserved values of RFC 8701: both bytes equal, low nibble 0xA. They are
// re-drawn on every connection, so comparing them between two dumps is meaningless — only the
// POSITION a GREASE value occupies carries information.
func IsGREASE(v uint16) bool {
	return byte(v>>8) == byte(v) && byte(v)&0x0f == 0x0a
}

const greasePlaceholder uint16 = 0x0a0a

// normGREASE folds every GREASE value onto one, so cipher and extension lists can be compared as
// plain sequences.
func normGREASE(v uint16) uint16 {
	if IsGREASE(v) {
		return greasePlaceholder
	}
	return v
}
