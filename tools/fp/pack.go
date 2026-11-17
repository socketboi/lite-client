package main

// The on-device form of a fingerprint table.
//
// JSON is the form people read and diff; this is the form the router gets. The client parses it
// with a few hundred bytes of code and no string handling at all, which matters twice: the table
// arrives over the network, and every kilobyte of parser is a kilobyte of flash.
//
// FORMAT — all integers big-endian, matching the wire format everything here ends up as:
//
//	"LCFP"                      magic
//	u8      version = 4
//	u32     required modes, one bit per mode number below
//	u8      required group count, then that many u16 — groups needing a real key share, GREASE
//	        slots excluded because nothing is computed for them
//	u8      name length, then the name
//	u8      flags: bit 0 = the X25519 key share reuses the X25519MLKEM768 share's classical half
//	u16     legacy_version
//	u8      session_id length
//	u16     cipher suite count, then that many u16
//	u8      compression method count, then that many u8
//	u16     extension count, then for each:
//	          u16   type
//	          u8    mode
//	          mode == 1 literal:        u16 length, bytes, u8 grease count, that many u16 offsets
//	          mode == 2 sni:            nothing
//	          mode == 3 key_share:      u8 group count, then that many (u16 group, u16 key length)
//	          mode == 4 random_payload: u16 length
//	          mode == 5 padding:        u16 target total length
//	          mode == 6 ech_grease:     u16 kdf, u8 count, that many u16 aead, u16 enc length,
//	                                    u8 count, that many u16 PRE-encryption payload lengths
//	          mode == 7 quic_params:    nothing — the body is the QUIC transport parameters, which the
//	                                    client supplies when it builds the hello
//
// GREASE is stored as the single value 0x0A0A wherever it occurs — in the cipher list, as an
// extension type, or as a key_share group. The client redraws a fresh value for each; storing the
// one that happened to be drawn during capture would pin a value that must vary.

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

const (
	// Version 2 added the requirement block: a table now states what it needs before it states what
	// it contains. There is no reader for version 1 — a stale table is refused, not interpreted.
	// 3: the GREASE-ECH record carries the candidate list. A version-2 table read as 3 does not
	// fail, it MISREADS — the count byte comes out of the old aead — so the number moves with the
	// layout, always.
	// 4: a flags byte after the name (key share reuse), and the GREASE-ECH record carries the
	// parrot's candidate payload lengths where it carried the one length a capture drew.
	fptVersion = 4

	flagKeyShareReuse = 0x01

	modeLiteral       = 1
	modeSNI           = 2
	modeKeyShare      = 3
	modeRandomPayload = 4
	modePadding       = 5
	modeECHGrease     = 6
	modeQUICParams    = 7
)

var fptMagic = []byte("LCFP")

// The mode names as they appear in a table, against the numbers the wire format and the C builder
// both use. One map, so the mapping is not restated in every place that needs it.
var modeNumber = map[Mode]int{
	ModeLiteral:       modeLiteral,
	ModeSNI:           modeSNI,
	ModeKeyShare:      modeKeyShare,
	ModeRandomPayload: modeRandomPayload,
	ModePadding:       modePadding,
	ModeECHGrease:     modeECHGrease,
	ModeQUICParams:    modeQUICParams,
}

// tableNeeds collects what a table requires of whoever builds it: the structural modes it uses and
// the groups it needs a real key share for.
//
// The distinction those two make is the whole point of the block. A browser adding an extension
// almost always adds fixed bytes, which any build can emit as a literal — nothing to declare and
// nothing to break. A browser adding a key exchange group is different in kind: a key share has to
// be a genuine public key, so no table format can describe it and no client can fake it. Writing
// the requirement down lets that difference be acted on before the table reaches a router, instead
// of being discovered by a device that quietly keeps its old fingerprint.
func tableNeeds(t *Table) (modes uint32, groups []uint16, err error) {
	seen := map[uint16]bool{}
	for _, e := range t.Extensions {
		m, ok := modeNumber[e.Mode]
		if !ok {
			return 0, nil, fmt.Errorf("extension %s: unknown mode %q", e.Name, e.Mode)
		}
		modes |= 1 << m
		if e.Mode != ModeKeyShare {
			continue
		}
		for _, g := range e.Groups {
			id, gerr := parseID(g.ID)
			if gerr != nil {
				return 0, nil, fmt.Errorf("extension %s: %w", e.Name, gerr)
			}
			// A GREASE slot names a group that does not exist, so nothing has to be computed for
			// it and it is not a requirement.
			if normGREASE(id) == greasePlaceholder || seen[id] {
				continue
			}
			seen[id] = true
			groups = append(groups, id)
		}
	}
	if len(groups) > 255 {
		return 0, nil, fmt.Errorf("%d key share groups is more than one byte holds", len(groups))
	}
	return modes, groups, nil
}

func PackTable(t *Table) ([]byte, error) {
	var b bytes.Buffer
	b.Write(fptMagic)
	b.WriteByte(fptVersion)

	modes, groups, err := tableNeeds(t)
	if err != nil {
		return nil, err
	}
	writeU32(&b, modes)
	b.WriteByte(byte(len(groups)))
	for _, g := range groups {
		writeU16(&b, g)
	}

	if len(t.Name) > 255 {
		return nil, fmt.Errorf("name of %d bytes does not fit in one byte of length", len(t.Name))
	}
	b.WriteByte(byte(len(t.Name)))
	b.WriteString(t.Name)

	var flags byte
	if t.KeyShareReuse {
		flags |= flagKeyShareReuse
	}
	b.WriteByte(flags)

	legacy, err := parseID(t.LegacyVersion)
	if err != nil {
		return nil, err
	}
	writeU16(&b, legacy)

	if t.SessionIDLen > 255 {
		return nil, fmt.Errorf("session_id of %d bytes is not representable", t.SessionIDLen)
	}
	b.WriteByte(byte(t.SessionIDLen))

	writeU16(&b, uint16(len(t.CipherSuites)))
	for _, cs := range t.CipherSuites {
		id, err := parseID(cs.ID)
		if err != nil {
			return nil, fmt.Errorf("cipher %s: %w", cs.Name, err)
		}
		writeU16(&b, normGREASE(id))
	}

	if len(t.Compression) > 255 {
		return nil, fmt.Errorf("%d compression methods is more than one byte holds", len(t.Compression))
	}
	b.WriteByte(byte(len(t.Compression)))
	b.Write(t.Compression)

	writeU16(&b, uint16(len(t.Extensions)))
	for _, e := range t.Extensions {
		if err := packExt(&b, e); err != nil {
			return nil, fmt.Errorf("extension %s: %w", e.Name, err)
		}
	}
	return b.Bytes(), nil
}

func packExt(b *bytes.Buffer, e TableExt) error {
	typ, err := parseID(e.ID)
	if err != nil {
		return err
	}
	writeU16(b, normGREASE(typ))

	switch e.Mode {
	case ModeLiteral:
		data, err := hex.DecodeString(e.Data)
		if err != nil {
			return fmt.Errorf("bad hex: %w", err)
		}
		if len(data) > 0xffff {
			return fmt.Errorf("body of %d bytes exceeds the wire limit", len(data))
		}
		if len(e.GreaseAt) > 255 {
			return fmt.Errorf("%d inline GREASE offsets is more than one byte holds", len(e.GreaseAt))
		}
		b.WriteByte(modeLiteral)
		writeU16(b, uint16(len(data)))
		b.Write(data)
		b.WriteByte(byte(len(e.GreaseAt)))
		for _, off := range e.GreaseAt {
			if off < 0 || off+1 >= len(data) {
				return fmt.Errorf("grease offset %d is outside a body of %d bytes", off, len(data))
			}
			writeU16(b, uint16(off))
		}

	case ModeSNI:
		b.WriteByte(modeSNI)

	case ModeKeyShare:
		if len(e.Groups) > 255 {
			return fmt.Errorf("%d key_share groups is more than one byte holds", len(e.Groups))
		}
		b.WriteByte(modeKeyShare)
		b.WriteByte(byte(len(e.Groups)))
		for _, g := range e.Groups {
			id, err := parseID(g.ID)
			if err != nil {
				return fmt.Errorf("group %s: %w", g.Name, err)
			}
			if g.KeyLen > 0xffff {
				return fmt.Errorf("group %s: key of %d bytes exceeds the wire limit", g.Name, g.KeyLen)
			}
			writeU16(b, normGREASE(id))
			writeU16(b, uint16(g.KeyLen))
		}

	case ModeRandomPayload:
		if e.Len > 0xffff {
			return fmt.Errorf("payload of %d bytes exceeds the wire limit", e.Len)
		}
		b.WriteByte(modeRandomPayload)
		writeU16(b, uint16(e.Len))

	case ModePadding:
		if e.TargetLen > 0xffff {
			return fmt.Errorf("padding target %d exceeds the wire limit", e.TargetLen)
		}
		b.WriteByte(modePadding)
		writeU16(b, uint16(e.TargetLen))

	case ModeECHGrease:
		kdf, err := parseID(e.KdfID)
		if err != nil {
			return fmt.Errorf("kdf: %w", err)
		}
		// The candidate list, counted. Empty is refused rather than filled in: uTLS with no
		// candidates generates a suite of its own (u_ech.go:95-98), and the client cannot copy
		// that faithfully — a table it would have to guess at is one to reject at the packer,
		// where the fault is still cheap.
		if len(e.AeadIDs) == 0 {
			return fmt.Errorf("ECH has no candidate cipher suites")
		}
		if len(e.AeadIDs) > 8 {
			return fmt.Errorf("ECH has %d candidates, the format carries 8", len(e.AeadIDs))
		}
		// The same refusal for the lengths as for the suites: uTLS with an empty list picks 128 of its
		// own (u_ech.go:131-133), which a table must not leave the client to guess.
		if len(e.PayloadLens) == 0 {
			return fmt.Errorf("ECH has no candidate payload lengths")
		}
		if len(e.PayloadLens) > 8 {
			return fmt.Errorf("ECH has %d payload lengths, the format carries 8", len(e.PayloadLens))
		}
		if e.EncLen > 0xffff {
			return fmt.Errorf("ECH lengths exceed the wire limit")
		}
		for _, l := range e.PayloadLens {
			if l < 0 || l+echTag > 0xffff {
				return fmt.Errorf("ECH payload length %d exceeds the wire limit", l)
			}
		}
		b.WriteByte(modeECHGrease)
		writeU16(b, kdf)
		b.WriteByte(byte(len(e.AeadIDs)))
		for _, s := range e.AeadIDs {
			aead, err := parseID(s)
			if err != nil {
				return fmt.Errorf("aead: %w", err)
			}
			writeU16(b, aead)
		}
		writeU16(b, uint16(e.EncLen))
		b.WriteByte(byte(len(e.PayloadLens)))
		for _, l := range e.PayloadLens {
			writeU16(b, uint16(l))
		}

	case ModeQUICParams:
		b.WriteByte(modeQUICParams)

	default:
		return fmt.Errorf("unknown mode %q", e.Mode)
	}
	return nil
}

func writeU32(b *bytes.Buffer, v uint32) {
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], v)
	b.Write(tmp[:])
}

func writeU16(b *bytes.Buffer, v uint16) {
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[:], v)
	b.Write(tmp[:])
}

func SavePacked(t *Table, path string) error {
	b, err := PackTable(t)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// SavePackedC writes the packed table as a C array, for a table that is part of the client rather
// than something the API sends it: the Hysteria2 plane's hello is the reference's own and does not
// vary by node, so it is compiled in. The bytes are exactly the ones `-format bin` writes.
func SavePackedC(t *Table, path, symbol string) error {
	if symbol == "" {
		return fmt.Errorf("-format c needs -symbol")
	}
	b, err := PackTable(t)
	if err != nil {
		return err
	}
	var s strings.Builder
	fmt.Fprintf(&s, "/* Generated by tools/fp from the %s parrot: `make fingerprint` writes it, and\n", t.Name)
	fmt.Fprintf(&s, " * check-fingerprint compares it with what the tool produces today. Do not edit. */\n")
	fmt.Fprintf(&s, "static const uint8_t %s[%d] = {", symbol, len(b))
	for i, v := range b {
		if i%12 == 0 {
			s.WriteString("\n   ")
		}
		fmt.Fprintf(&s, " 0x%02x,", v)
	}
	s.WriteString("\n};\n")
	return os.WriteFile(path, []byte(s.String()), 0o644)
}
