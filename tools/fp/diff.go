package main

// Byte comparison of two ClientHellos — the acceptance criterion without which "it works" and
// "it is right" are indistinguishable.
//
// A plain bytes.Equal is useless here: two consecutive hellos from the SAME client differ, because
// random, session_id, key_share public keys and GREASE values are drawn afresh on every connection.
// So the comparison runs field by field, and those four are compared by SHAPE — length, group list,
// the position a GREASE value occupies.
//
// Everything else must match to the byte. A difference here means a different JA4, which means
// REALITY has lost its point while the connection keeps working perfectly.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// Diff is one divergence. Field is named the way one thinks about it while debugging, not the way
// the RFC names it.
type Diff struct {
	Field string
	Want  string
	Got   string
}

func (d Diff) String() string {
	if d.Got == "" {
		return fmt.Sprintf("  %s\n      %s", d.Field, d.Want)
	}
	return fmt.Sprintf("  %s\n      want: %s\n      got:  %s", d.Field, d.Want, d.Got)
}

// Compare matches two parsed hellos. shuffled=true relaxes the extension-order check to a set
// check: Chrome permutes its extensions on every connection since version 110, so demanding a
// fixed order would be demanding the impossible.
func Compare(want, got *ClientHello, shuffled bool) []Diff {
	var out []Diff
	add := func(field, w, g string) { out = append(out, Diff{field, w, g}) }

	if want.LegacyVersion != got.LegacyVersion {
		add("legacy_version", hex16(want.LegacyVersion), hex16(got.LegacyVersion))
	}
	// The CONTENT of random and session_id is deliberately not compared — it is random. The length
	// must match: REALITY writes exactly 32 bytes into session_id, and a client with a different
	// length will not authenticate.
	if len(want.SessionID) != len(got.SessionID) {
		add("session_id length", fmt.Sprint(len(want.SessionID)), fmt.Sprint(len(got.SessionID)))
	}
	if want.SessionIDOffset != got.SessionIDOffset {
		add("session_id offset", fmt.Sprint(want.SessionIDOffset), fmt.Sprint(got.SessionIDOffset))
	}

	if !equalNormalised(want.CipherSuites, got.CipherSuites) {
		add("cipher suites", listU16(want.CipherSuites), listU16(got.CipherSuites))
	}
	if !bytes.Equal(want.Compression, got.Compression) {
		add("compression_methods", fmt.Sprintf("%v", want.Compression), fmt.Sprintf("%v", got.Compression))
	}

	// When the fingerprint pads, the padded TOTAL is the whole point of padding — the individual
	// padding body is not compared, so without this the hello could come out short and still pass.
	// It did, on the first run: ios and edge rebuilt to 508 bytes against a 512-byte reference.
	if hasPadding(want) || hasPadding(got) {
		if len(want.Raw) != len(got.Raw) {
			add("padded hello length", fmt.Sprint(len(want.Raw)), fmt.Sprint(len(got.Raw)))
		}
	}

	compareOrder(want, got, shuffled, add)
	compareBodies(want, got, add)
	return out
}

func hasPadding(ch *ClientHello) bool {
	for _, e := range ch.Extensions {
		if e.Type == extPadding {
			return true
		}
	}
	return false
}

func compareOrder(want, got *ClientHello, shuffled bool, add func(string, string, string)) {
	w, g := extTypes(want), extTypes(got)
	if !shuffled {
		if !equalRaw(w, g) {
			add("extension order", listExt(w), listExt(g))
		}
		return
	}
	ws, gs := append([]uint16(nil), w...), append([]uint16(nil), g...)
	sort.Slice(ws, func(i, j int) bool { return ws[i] < ws[j] })
	sort.Slice(gs, func(i, j int) bool { return gs[i] < gs[j] })
	if !equalRaw(ws, gs) {
		add("extension set", listExt(w), listExt(g))
	}
}

// compareBodies walks extensions by type, keeping duplicates apart. Chrome sends GREASE twice — once
// empty, once with a single byte — and folding both onto one key would compare the wrong pair and
// invent a difference that is not there.
func compareBodies(want, got *ClientHello, add func(string, string, string)) {
	pending := map[uint16][][]byte{}
	for _, e := range got.Extensions {
		t := normGREASE(e.Type)
		pending[t] = append(pending[t], e.Data)
	}
	for _, e := range want.Extensions {
		t := normGREASE(e.Type)
		queue := pending[t]
		if len(queue) == 0 {
			continue // absence is already reported by the order/set check
		}
		gd := queue[0]
		pending[t] = queue[1:]
		if d := compareExtension(e.Type, e.Data, gd); d != "" {
			add("extension "+extName(t), d, "")
		}
	}
}

// compareExtension knows what inside each extension is per-connection and what has to match.
// An empty result means no difference.
func compareExtension(t uint16, want, got []byte) string {
	switch t {
	case extKeyShare:
		// Public keys are ephemeral; the groups and their key lengths are the fingerprint.
		ws, werr := keyShareShape(want)
		gs, gerr := keyShareShape(got)
		if werr != nil || gerr != nil {
			return fmt.Sprintf("cannot parse (%v / %v)", werr, gerr)
		}
		if ws != gs {
			return fmt.Sprintf("groups/lengths %s vs %s", ws, gs)
		}
		return ""

	case extECH:
		// The whole GREASE-ECH payload is meaningless by construction; only its size is a signal.
		if len(want) != len(got) {
			return fmt.Sprintf("length %d vs %d", len(want), len(got))
		}
		return ""

	case extPSK:
		// Identity and binder live for exactly one connection.
		if len(want) != len(got) {
			return fmt.Sprintf("length %d vs %d", len(want), len(got))
		}
		return ""

	case extPadding:
		// Padding length follows from the length of everything else, SNI included.
		return ""

	default:
		// Inline GREASE inside list-shaped extensions is re-drawn per connection, so it is masked
		// on both sides before comparing. The offsets come from the same function the table
		// generator uses, so the two can never disagree about where GREASE lives.
		w := maskInlineGrease(t, want)
		g := maskInlineGrease(t, got)
		if !bytes.Equal(w, g) {
			return fmt.Sprintf("%s vs %s", short(want), short(got))
		}
		return ""
	}
}

// maskInlineGrease returns a copy with every inline GREASE value folded onto one, leaving the rest
// of the body untouched.
func maskInlineGrease(t uint16, data []byte) []byte {
	offs := inlineGreaseOffsets(t, data)
	if len(offs) == 0 {
		return data
	}
	out := append([]byte(nil), data...)
	for _, off := range offs {
		binary.BigEndian.PutUint16(out[off:], greasePlaceholder)
	}
	return out
}

// keyShareShape describes key_share without the secrets: which groups, and how long each public key
// is. That, and only that, is what gets checked.
func keyShareShape(b []byte) (string, error) {
	if len(b) < 2 {
		return "", fmt.Errorf("shorter than two bytes")
	}
	total := int(binary.BigEndian.Uint16(b[:2]))
	if 2+total > len(b) {
		return "", fmt.Errorf("claims %d bytes, %d available", total, len(b)-2)
	}
	var parts []string
	for off := 2; off < 2+total; {
		if off+4 > len(b) {
			return "", fmt.Errorf("entry truncated at %d", off)
		}
		grp := binary.BigEndian.Uint16(b[off : off+2])
		l := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		off += 4 + l
		if off > len(b) {
			return "", fmt.Errorf("key of %d bytes does not fit", l)
		}
		parts = append(parts, fmt.Sprintf("%s:%d", groupName(grp), l))
	}
	return strings.Join(parts, " "), nil
}

func equalNormalised(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if normGREASE(a[i]) != normGREASE(b[i]) {
			return false
		}
	}
	return true
}

func equalRaw(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func extTypes(ch *ClientHello) []uint16 {
	out := make([]uint16, 0, len(ch.Extensions))
	for _, e := range ch.Extensions {
		out = append(out, normGREASE(e.Type))
	}
	return out
}

func hex16(v uint16) string { return fmt.Sprintf("0x%04x", v) }

func listU16(v []uint16) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = cipherName(x)
	}
	return strings.Join(parts, " ")
}

func listExt(v []uint16) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = extName(x)
	}
	return strings.Join(parts, " ")
}

func short(b []byte) string {
	if len(b) <= 16 {
		return fmt.Sprintf("% x", b)
	}
	return fmt.Sprintf("% x… (%d bytes)", b[:16], len(b))
}
