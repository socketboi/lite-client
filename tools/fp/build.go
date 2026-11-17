package main

// Building a ClientHello from a fingerprint table. This is the Go twin of what the C client will
// do, and it exists first for one reason: it proves the table format is complete.
//
// The round trip is the test. Take a reference hello from uTLS, derive a table from it, build a
// hello back out of the table, and compare the two with the same comparator that will later accept
// the C client. If a field is missing from the table, the round trip fails here — in a Go tool with
// a stack trace — instead of failing later as a subtly wrong fingerprint on a live router.

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// Build produces the ClientHello body (handshake message, no record header) for the given table
// and SNI. Per-connection material — random, session_id, key_share keys, GREASE, ECH payload — is
// generated fresh, exactly as it would be on a real connection.
func Build(t *Table, sni string) ([]byte, error) {
	legacy, err := parseID(t.LegacyVersion)
	if err != nil {
		return nil, err
	}

	var body bytes.Buffer
	body.Write(be16(legacy))

	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	body.Write(random)

	// session_id is filled with randomness here. On a live connection REALITY overwrites these
	// exact bytes with its authentication payload after serialisation — which is why the table
	// records the length and the parser records the offset.
	sid := make([]byte, t.SessionIDLen)
	if _, err := rand.Read(sid); err != nil {
		return nil, err
	}
	body.WriteByte(byte(len(sid)))
	body.Write(sid)

	var suites bytes.Buffer
	for _, cs := range t.CipherSuites {
		id, err := parseID(cs.ID)
		if err != nil {
			return nil, fmt.Errorf("cipher %s: %w", cs.Name, err)
		}
		if IsGREASE(id) {
			id = freshGREASE()
		}
		suites.Write(be16(id))
	}
	body.Write(be16(uint16(suites.Len())))
	body.Write(suites.Bytes())

	body.WriteByte(byte(len(t.Compression)))
	body.Write(t.Compression)

	exts, padding, err := buildExtensions(t, sni)
	if err != nil {
		return nil, err
	}

	// Padding, when the fingerprint has it, is sized against the finished message: everything is
	// already known except the padding body itself, so it is computed last and spliced in.
	// fixedLen already accounts for the padding extension's own 4-byte header — counting it twice
	// here is what made the first version land four bytes short of the target.
	if padding != nil {
		fixed := 4 + body.Len() + 2 + exts.fixedLen // handshake header + body so far + ext block length
		if want := padding.TargetLen - fixed; want > 0 {
			padding.fill = make([]byte, want)
		}
		exts.rebuild()
	}

	body.Write(be16(uint16(len(exts.bytes))))
	body.Write(exts.bytes)

	out := make([]byte, 0, 4+body.Len())
	out = append(out, 0x01, byte(body.Len()>>16), byte(body.Len()>>8), byte(body.Len()))
	out = append(out, body.Bytes()...)
	return out, nil
}

// extBlock accumulates serialised extensions and can re-serialise them once padding is sized.
type extBlock struct {
	items    []extItem
	bytes    []byte
	fixedLen int // total serialised length of everything except the padding body
}

type extItem struct {
	typ  uint16
	data []byte
	pad  *padState
}

type padState struct {
	TargetLen int
	fill      []byte
}

func (b *extBlock) rebuild() {
	var buf bytes.Buffer
	for _, it := range b.items {
		data := it.data
		if it.pad != nil {
			data = it.pad.fill
		}
		buf.Write(be16(it.typ))
		buf.Write(be16(uint16(len(data))))
		buf.Write(data)
	}
	b.bytes = buf.Bytes()
}

func buildExtensions(t *Table, sni string) (*extBlock, *padState, error) {
	blk := &extBlock{}
	var pad *padState

	for _, e := range t.Extensions {
		typ, err := parseID(e.ID)
		if err != nil {
			return nil, nil, fmt.Errorf("extension %s: %w", e.Name, err)
		}
		if IsGREASE(typ) {
			typ = freshGREASE()
		}

		var data []byte
		switch e.Mode {
		case ModeLiteral:
			data, err = hex.DecodeString(e.Data)
			if err != nil {
				return nil, nil, fmt.Errorf("extension %s: bad hex: %w", e.Name, err)
			}
			for _, off := range e.GreaseAt {
				if off+1 >= len(data) {
					return nil, nil, fmt.Errorf("extension %s: grease_at %d is outside %d bytes", e.Name, off, len(data))
				}
				binary.BigEndian.PutUint16(data[off:], freshGREASE())
			}

		case ModeSNI:
			data = sniExtension(sni)

		case ModeKeyShare:
			data, err = keyShareBody(e.Groups)
			if err != nil {
				return nil, nil, fmt.Errorf("extension %s: %w", e.Name, err)
			}

		case ModeRandomPayload:
			data = make([]byte, e.Len)
			if _, err := rand.Read(data); err != nil {
				return nil, nil, err
			}

		case ModeECHGrease:
			data, err = echGrease(e)
			if err != nil {
				return nil, nil, fmt.Errorf("extension %s: %w", e.Name, err)
			}

		case ModeQUICParams:
			// What the reference rendered with, so a rebuild compares equal to it; see
			// quicPlaceholderParams. The client writes its own parameters here.
			data = append([]byte(nil), quicPlaceholderParams...)

		case ModePadding:
			if pad != nil {
				return nil, nil, fmt.Errorf("two padding extensions in one table")
			}
			pad = &padState{TargetLen: e.TargetLen}
			blk.items = append(blk.items, extItem{typ: typ, pad: pad})
			blk.fixedLen += 4
			continue

		default:
			// Unreachable: LoadTable rejects unknown modes. Kept as a hard failure rather than a
			// silent skip, because a skipped extension is precisely a wrong-but-working hello.
			return nil, nil, fmt.Errorf("extension %s: unhandled mode %q", e.Name, e.Mode)
		}

		blk.items = append(blk.items, extItem{typ: typ, data: data})
		blk.fixedLen += 4 + len(data)
	}

	blk.rebuild()
	return blk, pad, nil
}

// echGrease builds an ECHClientHello in its outer form. The structure is real and the contents are
// not: config_id, the HPKE key and the payload are drawn fresh, because a browser doing GREASE ECH
// is pretending to attempt encryption it never performs. Servers parse this extension, so a blob of
// random bytes in its place is rejected outright.
func echGrease(e TableExt) ([]byte, error) {
	kdf, err := parseID(e.KdfID)
	if err != nil {
		return nil, err
	}
	// The reference rendering picks the FIRST candidate rather than drawing: this path exists to
	// produce a byte-for-byte comparison target, and a target that moved between runs would be
	// useless for exactly the diff it is built for. The client draws; the yardstick does not.
	if len(e.AeadIDs) == 0 {
		return nil, fmt.Errorf("ECH has no candidate cipher suites")
	}
	aead, err := parseID(e.AeadIDs[0])
	if err != nil {
		return nil, err
	}

	// The first candidate length, for the same reason as the first suite; cmdCheck narrows the list to
	// the length its reference drew before it gets here.
	if len(e.PayloadLens) == 0 {
		return nil, fmt.Errorf("ECH has no candidate payload lengths")
	}
	payloadLen := e.PayloadLens[0] + echTag

	out := make([]byte, 0, 8+e.EncLen+payloadLen)
	out = append(out, 0x00) // outer
	out = append(out, be16(kdf)...)
	out = append(out, be16(aead)...)

	var cfg [1]byte
	if _, err := rand.Read(cfg[:]); err != nil {
		return nil, err
	}
	out = append(out, cfg[0])

	enc := make([]byte, e.EncLen)
	if _, err := rand.Read(enc); err != nil {
		return nil, err
	}
	out = append(out, be16(uint16(e.EncLen))...)
	out = append(out, enc...)

	payload := make([]byte, payloadLen)
	if _, err := rand.Read(payload); err != nil {
		return nil, err
	}
	out = append(out, be16(uint16(payloadLen))...)
	out = append(out, payload...)
	return out, nil
}

// sniExtension encodes server_name for one host name. Only the host_name type exists in practice,
// and an IP literal is not allowed here — REALITY needs a real donor name anyway.
func sniExtension(host string) []byte {
	h := []byte(host)
	out := make([]byte, 0, 5+len(h))
	out = append(out, be16(uint16(len(h)+3))...)
	out = append(out, 0x00)
	out = append(out, be16(uint16(len(h)))...)
	out = append(out, h...)
	return out
}

// keyShareBody emits one entry per group with a fresh key of the recorded length. The key material
// is random here: the comparator ignores key bytes, and the real client substitutes actual public
// keys at the same offsets and lengths.
func keyShareBody(groups []KeyShareEntry) ([]byte, error) {
	var inner bytes.Buffer
	for _, g := range groups {
		id, err := parseID(g.ID)
		if err != nil {
			return nil, fmt.Errorf("group %s: %w", g.Name, err)
		}
		if IsGREASE(id) {
			id = freshGREASE()
		}
		key := make([]byte, g.KeyLen)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		inner.Write(be16(id))
		inner.Write(be16(uint16(len(key))))
		inner.Write(key)
	}
	out := make([]byte, 0, 2+inner.Len())
	out = append(out, be16(uint16(inner.Len()))...)
	out = append(out, inner.Bytes()...)
	return out, nil
}

// freshGREASE draws one of the sixteen reserved values, as RFC 8701 requires: both bytes equal,
// low nibble 0xA.
func freshGREASE() uint16 {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Randomness failing here is not recoverable and must not be papered over: a fixed GREASE
		// value is itself a fingerprint.
		panic("fp: no randomness available for GREASE: " + err.Error())
	}
	v := uint16(b[0]&0xf0 | 0x0a)
	return v<<8 | v
}

func be16(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
