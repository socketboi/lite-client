package main

// The fingerprint table: everything needed to build a browser's ClientHello, as data rather than
// code. This is the format the C client reads, and the format the API ships when a fingerprint has
// to be refreshed without replacing the binary.
//
// The central decision here is the per-field Mode. A ClientHello is not constant — random,
// session_id, key_share keys, GREASE values and the SNI change on every connection — so a table
// that stored raw bytes would be wrong the moment it was used. Each extension therefore declares
// HOW it is produced, and the builder in build.go knows how to honour each mode.
//
// Anything not covered by a mode is stored verbatim and written verbatim. That is deliberate: an
// unknown extension must either be reproduced exactly or make the table invalid — never
// approximated. See LoadTable, which refuses a table it cannot fully honour.

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

// Mode says how one extension's body is produced at build time.
type Mode string

const (
	// ModeLiteral writes Data byte for byte. GREASE values inside the body are re-drawn at the
	// offsets listed in GreaseAt — a list-shaped extension such as supported_groups carries GREASE
	// inline, and freezing it would pin a value that must vary.
	ModeLiteral Mode = "literal"
	// ModeSNI builds server_name from the host being dialled.
	ModeSNI Mode = "sni"
	// ModeKeyShare emits one entry per group with a freshly generated public key of the recorded
	// length. Lengths are part of the fingerprint; the keys themselves are not.
	ModeKeyShare Mode = "key_share"
	// ModeRandomPayload fills Len bytes with fresh randomness. GREASE-ECH is the only user: its
	// payload is meaningless by construction, but its size is part of the fingerprint.
	ModeRandomPayload Mode = "random_payload"
	// ModePadding pads the hello up to TargetLen bytes. Absent from post-quantum fingerprints,
	// whose key_share alone pushes the hello past any padding threshold.
	ModePadding Mode = "padding"
	// ModeECHGrease builds a GREASE ECH extension: a real ECHClientHello structure whose key and
	// payload are random. It is NOT a blob of random bytes — servers parse this extension, and one
	// that does not parse is rejected outright, which is how this mode came to exist.
	ModeECHGrease Mode = "ech_grease"
	// ModeQUICParams is quic_transport_parameters, whose body is the transport's own and is handed
	// to the builder with the SNI: the table records where the extension goes and nothing of what
	// it holds. Only the Hysteria2 plane's table has one — a hello over TLS never carries it.
	ModeQUICParams Mode = "quic_transport_parameters"
)

// KeyShareEntry is one group in key_share: which group, and how long its public key is.
type KeyShareEntry struct {
	Name   string `json:"name"`
	ID     string `json:"id"`
	KeyLen int    `json:"key_len"`
}

// TableExt is one extension of the fingerprint.
type TableExt struct {
	Name string `json:"name"`
	ID   string `json:"id"`
	Mode Mode   `json:"mode"`

	Data      string `json:"data,omitempty"`       // ModeLiteral, hex
	GreaseAt  []int  `json:"grease_at,omitempty"`  // ModeLiteral: byte offsets of inline GREASE
	Len       int    `json:"len,omitempty"`        // ModeRandomPayload
	TargetLen int    `json:"target_len,omitempty"` // ModePadding

	Groups []KeyShareEntry `json:"groups,omitempty"` // ModeKeyShare

	// ModeECHGrease
	KdfID string `json:"kdf_id,omitempty"`
	// AeadIDs is the parrot's CandidateCipherSuites, not the one value the rendered hello showed.
	// Read off the extension object by echParrot; see the note there.
	AeadIDs []string `json:"aead_ids,omitempty"`
	EncLen  int      `json:"enc_len,omitempty"`
	// PayloadLens is the parrot's CandidatePayloadLens — PRE-encryption lengths, one drawn per hello
	// (vendor/utls/u_ech.go:160-166), and on the wire each grows by the AEAD's 16-byte tag
	// (u_hpke.go:29-36). It replaced a single payload_len copied off one rendered hello, which froze
	// Chrome's four-way draw (u_ech.go:328) into one length.
	PayloadLens []int `json:"payload_lens,omitempty"`
}

// echTag is what every HPKE AEAD uTLS accepts adds to a payload: `return mLen + 16` for AES-128-GCM,
// AES-256-GCM and ChaCha20-Poly1305, and a panic for anything else (vendor/utls/u_hpke.go:29-36).
const echTag = 16

// Table is a whole fingerprint. Cipher suites and extension types are stored by name AND by number:
// the name is what a human diffs against u_parrots.go, the number is what goes on the wire.
type Table struct {
	Name          string    `json:"name"`
	Source        string    `json:"source"`
	LegacyVersion string    `json:"legacy_version"`
	SessionIDLen  int       `json:"session_id_len"`
	CipherSuites  []NamedID `json:"cipher_suites"`
	Compression   []uint8   `json:"compression_methods"`
	// KeyShareReuse says the X25519 entry of key_share is the classical half of the X25519MLKEM768
	// entry rather than a key of its own. uTLS decides it per parrot — a profile wraps the pair in
	// ReuseHybridAndClassicalKeyShares (vendor/utls/u_parrots.go:1613, Firefox) or it does not
	// (:946-950, Chrome), and without the marker ApplyPreset generates a separate key (:3304). Read off
	// the capture itself: the classical public key equals the hybrid's last 32 bytes exactly when it
	// was reused, and two independently drawn keys never do.
	KeyShareReuse bool       `json:"key_share_reuse"`
	Extensions    []TableExt `json:"extensions"`
}

// NamedID is a wire number with the name it is known by.
type NamedID struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

func hexID(v uint16) string { return fmt.Sprintf("0x%04x", v) }

func parseID(s string) (uint16, error) {
	v, err := strconv.ParseUint(s, 0, 16)
	if err != nil {
		return 0, fmt.Errorf("bad id %q: %w", s, err)
	}
	return uint16(v), nil
}

// TableFrom derives a fingerprint table from a captured ClientHello. Source records where the
// capture came from, so a table can always be traced back to the thing it imitates.
func TableFrom(ch *ClientHello, name, source, sni, parrotsSrc string) (*Table, error) {
	t := &Table{
		Name:          name,
		Source:        source,
		LegacyVersion: hexID(ch.LegacyVersion),
		SessionIDLen:  len(ch.SessionID),
		Compression:   ch.Compression,
	}
	for _, e := range ch.Extensions {
		if e.Type != extKeyShare {
			continue
		}
		reuse, err := keyShareReused(e.Data)
		if err != nil {
			return nil, fmt.Errorf("key_share: %w", err)
		}
		t.KeyShareReuse = reuse
	}
	// GREASE is folded onto one value here rather than recorded as drawn: the table says "a GREASE
	// value goes in this slot", never "this particular GREASE value goes here". Freezing the value
	// captured at generation time would turn a randomised field into a constant one — which is the
	// definition of a fingerprint.
	for _, cs := range ch.CipherSuites {
		t.CipherSuites = append(t.CipherSuites, NamedID{Name: cipherName(cs), ID: hexID(normGREASE(cs))})
	}
	for _, e := range ch.Extensions {
		te, err := tableExt(e)
		if err != nil {
			return nil, fmt.Errorf("extension %s: %w", extName(e.Type), err)
		}
		t.Extensions = append(t.Extensions, te)
	}

	// THE ECH CANDIDATES COME FROM THE PARROT, NOT FROM THE RENDERED BYTES. tableExt can only see
	// the one suite this particular hello was drawn with; the list lives on the extension object,
	// and freezing the draw is exactly the fault this replaces. Best effort by design: a table
	// built from a capture of something we have no parrot for keeps what the bytes showed, and the
	// packer refuses it there rather than here, where the name may simply be unknown.
	//
	// The SNI is the CALLER'S, and it used to be a literal here — the same placeholder the Makefile
	// gives `dump`, written a second time in a place nobody editing the Makefile would look. The
	// candidate list does not depend on it (it is the parrot's, not the hello's), which is exactly
	// why a divergence would have gone unnoticed rather than been caught by the byte comparison.
	//
	// The payload lengths come from the same object for the same reason, and the one length this
	// capture drew is checked against them: a drawn length that is not a candidate means the object
	// read is not the one that wrote the hello.
	if g, err := echParrot(name, sni); err == nil && g != nil && len(g.CandidateCipherSuites) > 0 {
		for i := range t.Extensions {
			if t.Extensions[i].Mode != ModeECHGrease {
				continue
			}
			ids := make([]string, 0, len(g.CandidateCipherSuites))
			for _, cs := range g.CandidateCipherSuites {
				ids = append(ids, hexID(uint16(cs.AeadId)))
			}
			t.Extensions[i].AeadIDs = ids

			drawn := t.Extensions[i].PayloadLens
			lens := make([]int, 0, len(g.CandidatePayloadLens))
			seen := false
			for _, l := range g.CandidatePayloadLens {
				lens = append(lens, int(l))
				if len(drawn) == 1 && drawn[0] == int(l) {
					seen = true
				}
			}
			if len(lens) == 0 {
				return nil, fmt.Errorf("ECH: the parrot carries no payload lengths")
			}
			if !seen {
				return nil, fmt.Errorf("ECH: this capture's pre-encryption payload %v is not one of the parrot's %v", drawn, lens)
			}
			t.Extensions[i].PayloadLens = lens
		}
	}

	// THE ORDER A SHUFFLING PARROT STARTS FROM, not the one this capture happened to draw — see
	// order.go. A profile that does not shuffle is left in capture order, which is its literal order.
	// Asked of every profile, because only the parrot's source says whether it shuffles.
	if parrotsSrc == "" {
		return nil, fmt.Errorf("the base extension order is read from uTLS's u_parrots.go: pass -parrots")
	}
	base, shuffles, err := parrotBaseOrder(name, sni, parrotsSrc)
	if err != nil {
		return nil, fmt.Errorf("base order: %w", err)
	}
	if shuffles {
		if err := reorder(t, base); err != nil {
			return nil, err
		}
	}

	return t, nil
}

// reorder puts the table's extensions in the given order of wire types. GREASE, which occurs more
// than once, is matched in turn.
func reorder(t *Table, base []uint16) error {
	buckets := map[uint16][]TableExt{}
	for _, e := range t.Extensions {
		id, err := parseID(e.ID)
		if err != nil {
			return err
		}
		buckets[id] = append(buckets[id], e)
	}
	if len(base) != len(t.Extensions) {
		return fmt.Errorf("base order has %d extensions, the capture %d", len(base), len(t.Extensions))
	}
	out := make([]TableExt, 0, len(base))
	for _, id := range base {
		q := buckets[id]
		if len(q) == 0 {
			return fmt.Errorf("base order names %s, which the capture does not carry", hexID(id))
		}
		out = append(out, q[0])
		buckets[id] = q[1:]
	}
	t.Extensions = out
	return nil
}

// keyShareReused reports whether the X25519 entry is the X25519MLKEM768 entry's classical half. The
// hybrid share is ek || x25519 (vendor/utls/u_parrots.go:3270), so its last 32 bytes are the
// classical public key.
func keyShareReused(b []byte) (bool, error) {
	if len(b) < 2 {
		return false, fmt.Errorf("shorter than two bytes")
	}
	total := int(b[0])<<8 | int(b[1])
	if 2+total > len(b) {
		return false, fmt.Errorf("claims %d bytes, %d available", total, len(b)-2)
	}
	var hybrid, classical []byte
	for off := 2; off < 2+total; {
		if off+4 > len(b) {
			return false, fmt.Errorf("entry truncated at %d", off)
		}
		grp := uint16(b[off])<<8 | uint16(b[off+1])
		l := int(b[off+2])<<8 | int(b[off+3])
		if off+4+l > len(b) {
			return false, fmt.Errorf("key of %d bytes does not fit", l)
		}
		key := b[off+4 : off+4+l]
		switch grp {
		case 0x11ec:
			hybrid = key
		case 0x001d:
			classical = key
		}
		off += 4 + l
	}
	if len(hybrid) < 32 || len(classical) != 32 {
		return false, nil
	}
	return bytes.Equal(hybrid[len(hybrid)-32:], classical), nil
}

func tableExt(e Extension) (TableExt, error) {
	te := TableExt{Name: extName(e.Type), ID: hexID(normGREASE(e.Type))}
	switch e.Type {
	case extServerName:
		te.Mode = ModeSNI
		return te, nil

	case extKeyShare:
		groups, err := keyShareGroups(e.Data)
		if err != nil {
			return te, err
		}
		te.Mode = ModeKeyShare
		te.Groups = groups
		return te, nil

	case extECH:
		kdf, aead, encLen, payloadLen, err := echShape(e.Data)
		if err != nil {
			return te, err
		}
		te.Mode = ModeECHGrease
		te.KdfID = hexID(kdf)
		te.AeadIDs = []string{hexID(aead)} // provisional: replaced from the parrot in TableFrom
		te.EncLen = encLen
		if payloadLen < echTag {
			return te, fmt.Errorf("payload of %d bytes is shorter than the AEAD tag", payloadLen)
		}
		// Provisional too, and pre-encryption like the parrot's list it is checked against.
		te.PayloadLens = []int{payloadLen - echTag}
		return te, nil

	case extQUICParams:
		te.Mode = ModeQUICParams
		return te, nil

	case extPadding:
		te.Mode = ModePadding
		te.TargetLen = paddingTarget
		return te, nil

	default:
		te.Mode = ModeLiteral
		te.GreaseAt = inlineGreaseOffsets(e.Type, e.Data)
		// Inline GREASE is folded onto the placeholder here too, as the format says it is "wherever it
		// occurs": the client redraws these offsets, so the captured draw carried nothing — except a
		// table that differed between two captures of the same parrot, which is what kept a Chrome
		// table from being gated byte for byte.
		data := append([]byte(nil), e.Data...)
		for _, off := range te.GreaseAt {
			binary.BigEndian.PutUint16(data[off:], greasePlaceholder)
		}
		te.Data = hex.EncodeToString(data)
		return te, nil
	}
}

// Extension numbers the table treats specially. Named rather than inlined because they appear in
// three files and a typo in one of them would be silent.
const (
	extServerName          uint16 = 0x0000
	extSupportedGroups     uint16 = 0x000a
	extSignatureAlgorithms uint16 = 0x000d
	extKeyShare            uint16 = 0x0033
	extSupportedVersions   uint16 = 0x002b
	extPadding             uint16 = 0x0015
	extECH                 uint16 = 0xfe0d
	extPSK                 uint16 = 0x0029
	extQUICParams          uint16 = 0x0039
)

// paddingTarget is the size BoringSSL-style padding rounds a small hello up to. Modern
// post-quantum fingerprints never reach it — key_share alone is over a kilobyte — but a fingerprint
// without a PQ group still needs it.
const paddingTarget = 512

// inlineGreaseOffsets finds GREASE values embedded in a list-shaped extension body, so the builder
// can re-draw them. Only extensions whose layout is known are scanned: guessing at an arbitrary
// body would eventually mistake real data for GREASE and corrupt it.
func inlineGreaseOffsets(t uint16, data []byte) []int {
	var start int
	switch t {
	case extSupportedGroups, extSignatureAlgorithms:
		start = 2 // uint16 list length, then uint16 entries
	case extSupportedVersions:
		start = 1 // uint8 list length, then uint16 entries
	default:
		return nil
	}
	var out []int
	for off := start; off+1 < len(data); off += 2 {
		if IsGREASE(uint16(data[off])<<8 | uint16(data[off+1])) {
			out = append(out, off)
		}
	}
	return out
}

// keyShareGroups reads key_share as shape only: which groups, and how long each public key is.
func keyShareGroups(b []byte) ([]KeyShareEntry, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("shorter than two bytes")
	}
	total := int(b[0])<<8 | int(b[1])
	if 2+total > len(b) {
		return nil, fmt.Errorf("claims %d bytes, %d available", total, len(b)-2)
	}
	var out []KeyShareEntry
	for off := 2; off < 2+total; {
		if off+4 > len(b) {
			return nil, fmt.Errorf("entry truncated at %d", off)
		}
		grp := uint16(b[off])<<8 | uint16(b[off+1])
		l := int(b[off+2])<<8 | int(b[off+3])
		off += 4 + l
		if off > len(b) {
			return nil, fmt.Errorf("key of %d bytes does not fit", l)
		}
		out = append(out, KeyShareEntry{Name: groupName(grp), ID: hexID(normGREASE(grp)), KeyLen: l})
	}
	return out, nil
}

// echShape reads the ECHClientHello structure a GREASE extension carries:
//
//	u8 type (0 = outer), u16 kdf_id, u16 aead_id, u8 config_id,
//	opaque enc<0..2^16-1>, opaque payload<0..2^16-1>
//
// Only the shape is recorded. config_id, enc and payload are drawn fresh on every connection — a
// browser is pretending to attempt encrypted client hello, and pretending convincingly means the
// bytes vary while the structure does not.
func echShape(b []byte) (kdf, aead uint16, encLen, payloadLen int, err error) {
	if len(b) < 8 {
		return 0, 0, 0, 0, fmt.Errorf("shorter than an ECHClientHello header")
	}
	if b[0] != 0x00 {
		return 0, 0, 0, 0, fmt.Errorf("ECH type %#02x is not the outer form", b[0])
	}
	kdf = binary.BigEndian.Uint16(b[1:3])
	aead = binary.BigEndian.Uint16(b[3:5])
	encLen = int(binary.BigEndian.Uint16(b[6:8]))
	if 8+encLen+2 > len(b) {
		return 0, 0, 0, 0, fmt.Errorf("enc of %d bytes does not fit", encLen)
	}
	payloadLen = int(binary.BigEndian.Uint16(b[8+encLen : 10+encLen]))
	if 10+encLen+payloadLen != len(b) {
		return 0, 0, 0, 0, fmt.Errorf("payload of %d bytes leaves %d over", payloadLen, len(b)-10-encLen-payloadLen)
	}
	return kdf, aead, encLen, payloadLen, nil
}

// SaveTable writes the table as indented JSON — it is meant to be read and diffed by people.
func SaveTable(t *Table, path string) error {
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// LoadTable reads a table and refuses anything it cannot reproduce exactly. There is no lenient
// path on purpose: a table containing a mode this build does not implement must fail loudly here,
// because the alternative is a hello that is almost right — which is the one outcome that costs
// nothing to produce and everything to detect.
func LoadTable(path string) (*Table, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t Table
	dec := json.NewDecoder(bytesReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for i, e := range t.Extensions {
		switch e.Mode {
		case ModeLiteral, ModeSNI, ModeKeyShare, ModeRandomPayload, ModePadding, ModeECHGrease, ModeQUICParams:
		default:
			return nil, fmt.Errorf("%s: extension %d (%s) declares unknown mode %q", path, i, e.Name, e.Mode)
		}
	}
	return &t, nil
}
