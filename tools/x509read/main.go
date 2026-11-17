// What the QUIC plane's reference says of a certificate it cannot parse — Go's own
// x509.ParseCertificate, run (GOROOT/src/crypto/x509/parser.go, go1.26.6, the toolchain hysteria
// client oracles are pinned to). Writes test/x509go/reference.h, which test/x509go holds
// lc_x509_go_parse (cert/x509go.c) to, error text for error text.
//
// Under the Chrome parrot uTLS reports a certificate that does not parse as "tls: failed to parse
// certificate from server: " and the parser's error (vendor/utls-hy/handshake_client.go:1125-1132),
// and quic-go closes with that text (DIVERGES was Q7). Those words are x509's, and they name the
// exact place the parse stopped — so the parser is what has to be the reference's, not only its
// verdict.
//
// THE CERTIFICATES are written here byte by byte, not made by CreateCertificate: nothing checks a
// signature at parse time, and hand-written DER is the same on every run, where generated keys are
// not. A few bases carry every key type the parser reads and every extension it looks into; each
// base is then mutated at every byte — flipped, bumped, zeroed, set to 0x80 and to 0x7f — and cut
// at every length. Random mutation seldom reaches a rule that needs a well-formed value of a
// particular shape, so those are written out one by one (edges): the strings of a Name, times, SAN
// URIs, name constraints, integers at the edge of int, and the rest.
//
// TWO TOOLCHAINS. The REALITY plane's reference, Xray-core, is built with go1.27.1, whose parser
// reads a Name's values, ML-DSA keys, IPv4-mapped addresses and a mailbox constraint's domain
// otherwise (lc_x509_go127_parse); so every case is answered by both toolchains, and the header
// carries both.
//
// TWO ARCHITECTURES. Where the parser reads an INTEGER into a Go int or uint — an RSA exponent, a
// path length — the answer depends on how wide int is, and the reference runs on the router:
// 32 bits on mipsel, 64 on aarch64. So the texts are taken twice, as GOARCH=amd64 and GOARCH=386
// answer them, and the header carries both.
//
// Not built by the gate. Regenerate in the build image, from the repository root:
//
//	docker run --rm -v "$PWD:/w" -w /w lc-build:local sh -c 'cd tools/x509read && G=/usr/local/go1.27/bin/go && \
//	  go run . -texts > /tmp/t64 && GOARCH=386 go run . -texts > /tmp/t32 && \
//	  $G run . -texts > /tmp/u64 && GOARCH=386 $G run . -texts > /tmp/u32 && \
//	  go run . -header /tmp/t64 /tmp/t32 /tmp/u64 /tmp/u32 > ../../test/x509go/reference.h'
package main

import (
	"bufio"
	"bytes"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strconv"
	"strings"
)

// ---- DER, by hand -----------------------------------------------------------------------------

func tlv(tag byte, parts ...[]byte) []byte {
	body := bytes.Join(parts, nil)
	n := len(body)
	var h []byte
	switch {
	case n < 0x80:
		h = []byte{tag, byte(n)}
	case n < 0x100:
		h = []byte{tag, 0x81, byte(n)}
	case n < 0x10000:
		h = []byte{tag, 0x82, byte(n >> 8), byte(n)}
	default:
		h = []byte{tag, 0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return append(h, body...)
}

func seq(p ...[]byte) []byte        { return tlv(0x30, p...) }
func set(p ...[]byte) []byte        { return tlv(0x31, p...) }
func octets(b []byte) []byte        { return tlv(0x04, b) }
func null() []byte                  { return []byte{0x05, 0x00} }
func boolean(v bool) []byte         { return tlv(0x01, []byte{map[bool]byte{false: 0, true: 0xff}[v]}) }
func bits(b []byte) []byte          { return tlv(0x03, append([]byte{0}, b...)) }
func str(tag byte, s string) []byte { return tlv(tag, []byte(s)) }

// An INTEGER from a decimal (or 0x) literal, minimally encoded, two's complement.
func integer(s string) []byte {
	v, ok := new(big.Int).SetString(s, 0)
	if !ok {
		panic(s)
	}
	return tlv(0x02, intBytes(v))
}

func intBytes(v *big.Int) []byte {
	if v.Sign() >= 0 {
		b := v.Bytes()
		if len(b) == 0 || b[0]&0x80 != 0 {
			b = append([]byte{0}, b...)
		}
		return b
	}
	// two's complement of a negative number, minimal
	n := new(big.Int).Neg(v)
	n.Sub(n, big.NewInt(1))
	b := n.Bytes()
	for i := range b {
		b[i] = ^b[i]
	}
	if len(b) == 0 || b[0]&0x80 == 0 {
		b = append([]byte{0xff}, b...)
	}
	return b
}

func oid(s string) []byte {
	var arcs []uint64
	for _, p := range strings.Split(s, ".") {
		v, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			panic(s)
		}
		arcs = append(arcs, v)
	}
	body := base128(arcs[0]*40 + arcs[1])
	for _, a := range arcs[2:] {
		body = append(body, base128(a)...)
	}
	return tlv(0x06, body)
}

func base128(v uint64) []byte {
	out := []byte{byte(v & 0x7f)}
	for v >>= 7; v > 0; v >>= 7 {
		out = append([]byte{byte(v&0x7f) | 0x80}, out...)
	}
	return out
}

func ctx(n byte, constructed bool, p ...[]byte) []byte {
	t := 0x80 | n
	if constructed {
		t |= 0x20
	}
	return tlv(t, p...)
}

// ---- the parts of a certificate ----------------------------------------------------------------

func rdn(typ string, tag byte, value string) []byte { return set(seq(oid(typ), str(tag, value))) }

func plainName(cn string) []byte { return seq(rdn("2.5.4.3", 0x13, cn)) }

// Every string type the parser reads, and a set with two values in it.
func richName() []byte {
	return seq(
		rdn("2.5.4.6", 0x13, "RU"),
		rdn("2.5.4.10", 0x0c, "Организация"),
		rdn("2.5.4.11", 0x14, "T61 \xe9t\xe9"),
		rdn("2.5.4.7", 0x1e, "\x00M\x00o\x00s\x00c\x00o\x00w"),
		rdn("1.2.840.113549.1.9.1", 0x16, "ca@example.com"),
		rdn("2.5.4.5", 0x12, "0123 4567"),
		set(seq(oid("2.5.4.3"), str(0x13, "one")), seq(oid("2.5.4.4"), str(0x0c, "two"))),
	)
}

func utc(s string) []byte { return str(0x17, s) }
func gen(s string) []byte { return str(0x18, s) }
func validity() []byte    { return seq(utc("250101000000Z"), utc("351231235959Z")) }
func sigRSA() []byte      { return seq(oid("1.2.840.113549.1.1.11"), null()) }
func sigECDSA() []byte    { return seq(oid("1.2.840.10045.4.3.2")) }

func rsaKey(e string) []byte {
	n := make([]byte, 65)
	for i := 1; i < len(n); i++ {
		n[i] = byte(0xc5 ^ i*7)
	}
	return seq(seq(oid("1.2.840.113549.1.1.1"), null()), bits(seq(tlv(0x02, n), integer(e))))
}

func ecKey(curve string) []byte {
	var c elliptic.Curve
	var id string
	switch curve {
	case "p224":
		c, id = elliptic.P224(), "1.3.132.0.33"
	case "p256":
		c, id = elliptic.P256(), "1.2.840.10045.3.1.7"
	case "p384":
		c, id = elliptic.P384(), "1.3.132.0.34"
	case "p521":
		c, id = elliptic.P521(), "1.3.132.0.35"
	}
	p := c.Params()
	size := (p.BitSize + 7) / 8
	pt := make([]byte, 1+2*size)
	pt[0] = 4
	p.Gx.FillBytes(pt[1 : 1+size])
	p.Gy.FillBytes(pt[1+size:])
	return seq(seq(oid("1.2.840.10045.2.1"), oid(id)), bits(pt))
}

func ed25519Key() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i * 13)
	}
	return seq(seq(oid("1.3.101.112")), bits(k))
}

func x25519Key() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i*29 + 1)
	}
	return seq(seq(oid("1.3.101.110")), bits(k))
}

func dsaKey() []byte {
	return seq(seq(oid("1.2.840.10040.4.1"), seq(integer("0x00e1d3"), integer("0x0065"), integer("0x02"))),
		bits(integer("0x1234")))
}

func ext(id string, critical bool, value []byte) []byte {
	if critical {
		return seq(oid(id), boolean(true), octets(value))
	}
	return seq(oid(id), octets(value))
}

func exts(e ...[]byte) []byte { return ctx(3, true, seq(e...)) }

func richExts() []byte {
	return exts(
		ext("2.5.29.15", true, bits([]byte{0x86, 0x00})),
		ext("2.5.29.19", true, seq(boolean(true), integer("3"))),
		ext("2.5.29.17", false, seq(
			ctx(2, false, []byte("a.example")),
			ctx(1, false, []byte("x@y.example")),
			ctx(7, false, []byte{192, 0, 2, 1}),
			ctx(7, false, []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
			ctx(6, false, []byte("https://u.example:8443/p?q=1#f")),
			ctx(0, true, oid("1.2.3.4"), ctx(0, true, str(0x0c, "other"))),
			ctx(4, true, plainName("dir")),
		)),
		ext("2.5.29.30", true, seq(
			ctx(0, true,
				seq(ctx(2, false, []byte(".example.com"))),
				seq(ctx(7, false, []byte{10, 0, 0, 0, 255, 0, 0, 0})),
				seq(ctx(1, false, []byte("example.com"))),
				seq(ctx(1, false, []byte("a@example.com"))),
				seq(ctx(6, false, []byte("uri.example"))),
				seq(ctx(4, true, plainName("dirc"))),
			),
			ctx(1, true,
				seq(ctx(7, false, append(bytes.Repeat([]byte{0xfe}, 16), append(bytes.Repeat([]byte{0xff}, 8), make([]byte, 8)...)...))),
			),
		)),
		ext("2.5.29.31", false, seq(seq(ctx(0, true, ctx(0, true, ctx(6, false, []byte("http://crl.example/c.crl"))))), seq(ctx(1, false, []byte{0x06, 0x40})))),
		ext("2.5.29.35", false, seq(ctx(0, false, []byte{1, 2, 3, 4, 5}))),
		ext("2.5.29.14", false, octets([]byte{9, 8, 7, 6})),
		ext("2.5.29.37", false, seq(oid("1.3.6.1.5.5.7.3.1"), oid("1.3.6.1.5.5.7.3.2"), oid("1.2.3.99"))),
		ext("2.5.29.32", false, seq(seq(oid("2.5.29.32.0")), seq(oid("1.2.3.4"), seq(seq(oid("1.3.6.1.5.5.7.2.1"), str(0x16, "http://cps")))))),
		ext("2.5.29.33", false, seq(seq(oid("1.2.3.4"), oid("1.2.3.5")))),
		ext("2.5.29.36", true, seq(ctx(0, false, []byte{1}), ctx(1, false, []byte{2}))),
		ext("2.5.29.54", true, integer("0")),
		ext("1.3.6.1.5.5.7.1.1", false, seq(
			seq(oid("1.3.6.1.5.5.7.48.1"), ctx(6, false, []byte("http://ocsp.example"))),
			seq(oid("1.3.6.1.5.5.7.48.2"), ctx(6, false, []byte("http://ca.example/ca.crt"))),
			seq(oid("1.3.6.1.5.5.7.48.3"), ctx(1, false, []byte("other"))),
		)),
		ext("1.2.3.4.5", true, octets([]byte("unknown"))),
		ext("2.5.29.99", false, null()),
	)
}

type tbsParts struct {
	version, serial, sigAI, issuer, validity, subject, spki, uids, exts []byte
	outerAI, signature, trailing                                        []byte
}

func (p tbsParts) der() []byte {
	tbs := seq(p.version, p.serial, p.sigAI, p.issuer, p.validity, p.subject, p.spki, p.uids, p.exts)
	return append(seq(tbs, p.outerAI, p.signature), p.trailing...)
}

func v3(spki []byte, e []byte) tbsParts {
	return tbsParts{
		version: ctx(0, true, integer("2")), serial: integer("0x0102030405"), sigAI: sigRSA(),
		issuer: plainName("issuer"), validity: validity(), subject: plainName("subject"), spki: spki,
		exts: e, outerAI: sigRSA(), signature: bits([]byte{0xaa, 0xbb, 0xcc, 0xdd}),
	}
}

func bases() [][]byte {
	rich := v3(rsaKey("65537"), richExts())
	rich.issuer, rich.subject = richName(), richName()

	san := func(names ...[]byte) []byte { return exts(ext("2.5.29.17", false, seq(names...))) }
	p256 := v3(ecKey("p256"), san(ctx(2, false, []byte("node.example"))))
	p256.sigAI, p256.outerAI = sigECDSA(), sigECDSA()
	p384 := v3(ecKey("p384"), nil)
	p384.validity = seq(gen("20250101000000Z"), gen("20351231235959Z"))
	p521 := v3(ecKey("p521"), nil)
	p224 := v3(ecKey("p224"), nil)
	ed := v3(ed25519Key(), san(ctx(2, false, []byte("ed.example"))))
	x := v3(x25519Key(), nil)
	dsa := v3(dsaKey(), nil)
	v1 := v3(rsaKey("3"), nil)
	v1.version = nil
	v2 := v3(rsaKey("65537"), nil)
	v2.version = ctx(0, true, integer("1"))
	v2.uids = append(ctx(1, false, []byte{0, 1, 2}), ctx(2, false, []byte{0, 3, 4})...)
	// ML-DSA-44, which go1.27.1 reads as a key and go1.26.6 as an algorithm it does not know
	mk := make([]byte, 1312)
	for i := range mk {
		mk[i] = byte(i*17 + 3)
	}
	ml := v3(seq(seq(oid("2.16.840.1.101.3.4.3.17")), bits(mk)), san(ctx(2, false, []byte("ml.example"))))
	return [][]byte{rich.der(), p256.der(), p384.der(), p521.der(), p224.der(), ed.der(), x.der(), dsa.der(), v1.der(), v2.der(), ml.der()}
}

// ---- the edges ---------------------------------------------------------------------------------

type edge struct {
	what string
	der  []byte
}

func edges() []edge {
	var out []edge
	add := func(what string, p tbsParts) { out = append(out, edge{what, p.der()}) }
	base := func() tbsParts { return v3(rsaKey("65537"), nil) }

	// Strings of a Name, one attribute each.
	for _, c := range []struct {
		tag byte
		v   string
	}{
		{0x13, "ok Printable"}, {0x13, "not<printable"}, {0x13, "wild*card&"}, {0x13, ""},
		{0x0c, "ok ✓"}, {0x0c, "bad \xff utf8"}, {0x0c, "\xed\xa0\x80"},
		{0x14, "\x00\x7f\x80\xff"},
		{0x1e, "\x00A"}, {0x1e, "\x00"}, {0x1e, "\x00A\x00\x00"}, {0x1e, "\xd8\x00"}, {0x1e, "\xff\xfe"},
		{0x1e, "\xfd\xd0"}, {0x1e, "\xfd\xef"}, {0x1e, "\xfd\xf0"}, {0x1e, "\x00\x00"}, {0x1e, ""},
		{0x16, "ia5 ok"}, {0x16, "ia5 é"}, {0x16, "\x7f"},
		{0x12, "12 34"}, {0x12, "12a"},
		{0x1a, "visible"}, {0x04, "octets"}, {0x02, "\x01"}, {0x1c, "univ"}, {0x80, "ctx"},
		// what go1.27.1's readASN1Any reads besides strings, and where each of its readers refuses
		{0x02, "\x00\x01"}, {0x02, ""}, {0x02, "\x01\x02\x03\x04\x05\x06\x07\x08\x09"}, {0x02, "\xff\x80"},
		{0x03, "\x00\x01"}, {0x03, "\x08"}, {0x03, ""}, {0x03, "\x01\x01"}, {0x03, "\x01\x02"},
		{0x06, "\x2a\x03"}, {0x06, "\x80\x01"}, {0x06, ""}, {0x06, "\x2a\x83"},
		{0x17, "250101000000Z"}, {0x17, "2501010000Z"}, {0x17, "bad"}, {0x17, "250101000000+0000"},
		{0x18, "20250101000000Z"}, {0x18, "2025"}, {0x18, "20250101000000.5Z"},
		{0x01, "\xff"}, {0x01, "\x00"}, {0x01, "\x01"}, {0x01, ""}, {0x01, "\xff\xff"},
		{0x05, ""}, {0x05, "x"}, {0x2c, "x"}, {0x30, ""}, {0x31, ""}, {0x40, "app"}, {0xa0, ""},
	} {
		p := base()
		p.subject = seq(set(seq(oid("2.5.4.3"), str(c.tag, c.v))))
		add(fmt.Sprintf("name %#x %q", c.tag, c.v), p)
	}
	for _, n := range [][]byte{
		seq(), seq(set()), seq(tlv(0x30)), seq(set(tlv(0x31))), seq(set(seq(str(0x13, "x")))),
		seq(set(seq(oid("2.5.4.3")))), seq(set(seq(oid("2.5.4.3"), []byte{0x1f, 0x01, 0x00}))),
		tlv(0x31), set(seq(oid("2.5.4.3"), str(0x13, "x"))),
	} {
		p := base()
		p.issuer = n
		add(fmt.Sprintf("issuer % x", n), p)
	}

	// Times.
	for _, t := range []string{
		"250101000000Z", "2501010000Z", "250101000000+0300", "250101000000-0000", "250101000000+0000",
		"250101000000+2400", "250101000000+2500", "250101000000+0060", "250101000000+0059", "250229000000Z",
		"240229000000Z", "000229000000Z", "500101000000Z", "491231235959Z", "690101000000Z", "680101000000Z",
		"251301000000Z", "250001000000Z", "250100000000Z", "250132000000Z", "250431000000Z", "250101240000Z",
		"250101236000Z", "250101235960Z", "250101000000.5Z", "25010100000Z", "2501010000000Z", "250101000000",
		"250101000000z", " 50101000000Z", "2501010000+0100", "250101000000+01", "250101000000+01:00", "",
		"2a0101000000Z", "250101000000Z ", "-50101000000Z",
	} {
		p := base()
		p.validity = seq(utc(t), utc("351231235959Z"))
		add("utc "+t, p)
	}
	for _, t := range []string{
		"20250101000000Z", "20250101000000.5Z", "202501010000Z", "20250101000000+0300", "20250229000000Z",
		"20240229000000Z", "21000229000000Z", "20000229000000Z", "00000101000000Z", "99991231235959Z",
		"20250101000000", "20250101000000+0000", "2025010100000Z", "20251301000000Z", "20250101240000Z",
		"+2025010100000Z", "20250101000000-1230",
	} {
		p := base()
		p.validity = seq(gen("20250101000000Z"), gen(t))
		add("generalized "+t, p)
	}
	for _, v := range [][]byte{
		seq(), seq(utc("250101000000Z")), seq(str(0x13, "x"), utc("250101000000Z")),
		seq(utc("250101000000Z"), utc("250101000000Z"), utc("250101000000Z")), set(utc("250101000000Z")),
	} {
		p := base()
		p.validity = v
		add(fmt.Sprintf("validity % x", v), p)
	}

	// Version and serial number.
	for _, v := range []string{"0", "1", "2", "3", "-1", "256", "0x7fffffffffffffff", "0x8000000000000000", "-0x8000000000000000"} {
		p := base()
		p.version = ctx(0, true, integer(v))
		add("version "+v, p)
	}
	for _, raw := range [][]byte{
		{0x02, 0x00}, {0x02, 0x01, 0x00}, {0x02, 0x02, 0x00, 0x01}, {0x02, 0x02, 0xff, 0x80},
		{0x02, 0x01, 0xff}, {0x02, 0x01, 0x80}, {0x02, 0x02, 0x00, 0x80},
	} {
		p := base()
		p.serial = raw
		add(fmt.Sprintf("serial % x", raw), p)
	}
	for _, raw := range [][]byte{
		{0xa0, 0x03, 0x02, 0x01, 0x02, 0x00}, ctx(0, true, integer("2"), integer("2")), ctx(0, true),
		ctx(0, true, []byte{0x02, 0x02, 0x00, 0x02}), ctx(0, false, integer("2")),
	} {
		p := base()
		p.version = raw
		add(fmt.Sprintf("version field % x", raw), p)
	}

	// Algorithm identifiers.
	for _, ai := range [][]byte{
		seq(), seq(oid("1.2.840.113549.1.1.11")), seq(oid("1.2.840.113549.1.1.11"), null(), null()),
		seq(null()), seq(oid("1.2.840.113549.1.1.11"), []byte{0x05}), seq([]byte{0x06, 0x00}),
		seq([]byte{0x06, 0x01, 0x80}), seq([]byte{0x06, 0x02, 0x80, 0x01}), seq(oid("2.999.1")),
	} {
		p := base()
		p.sigAI, p.outerAI = ai, ai
		add(fmt.Sprintf("ai % x", ai), p)
	}
	{
		p := base()
		p.outerAI = sigECDSA()
		add("inner and outer AI differ", p)
		p = base()
		p.outerAI = null()
		add("outer AI not a sequence", p)
	}

	// Public keys.
	for _, e := range []string{"65537", "3", "1", "0", "-3", "0x7fffffff", "0x80000000", "0xffffffff", "0x100000001",
		"0x7fffffffffffffff", "0x8000000000000000", "0x10000000000000000"} {
		add("rsa e "+e, v3(rsaKey(e), nil))
	}
	rsaAI := seq(oid("1.2.840.113549.1.1.1"), null())
	for _, k := range [][]byte{
		seq(rsaAI, bits(seq(integer("0"), integer("3")))),
		seq(rsaAI, bits(seq(integer("-5"), integer("3")))),
		seq(rsaAI, bits(seq(integer("5")))),
		seq(rsaAI, bits(seq(integer("5"), integer("3"), integer("3")))),
		seq(rsaAI, bits(seq(tlv(0x02, []byte{0x00, 0x05}), integer("3")))),
		seq(rsaAI, bits(integer("5"))),
		seq(rsaAI, bits(append(seq(integer("5"), integer("3")), 0))),
		seq(seq(oid("1.2.840.113549.1.1.1")), bits(seq(integer("5"), integer("3")))),
		seq(seq(oid("1.2.840.113549.1.1.1"), seq()), bits(seq(integer("5"), integer("3")))),
		seq(rsaAI, tlv(0x03, []byte{0x01, 0x80})),
		seq(rsaAI, tlv(0x03, []byte{0x08})),
		seq(rsaAI, tlv(0x03, nil)),
		seq(rsaAI, octets(nil)),
		seq(rsaAI),
		seq(seq(oid("1.2.840.10045.2.1"), oid("1.2.840.10045.3.1.7")), bits([]byte{4, 1, 2})),
		seq(seq(oid("1.2.840.10045.2.1"), oid("1.2.840.10045.3.1.1")), bits([]byte{4})),
		seq(seq(oid("1.2.840.10045.2.1"), null()), bits([]byte{4})),
		seq(seq(oid("1.2.840.10045.2.1")), bits([]byte{4})),
		seq(seq(oid("1.2.840.10045.2.1"), oid("1.2.840.10045.3.1.7")), bits(nil)),
		seq(seq(oid("1.2.840.10045.2.1"), oid("1.2.840.10045.3.1.7")), bits(append([]byte{2}, make([]byte, 32)...))),
		seq(seq(oid("1.2.840.10045.2.1"), oid("1.2.840.10045.3.1.7")), bits(append([]byte{4}, make([]byte, 64)...))),
		seq(seq(oid("1.2.840.10045.2.1"), oid("1.2.840.10045.3.1.7")), bits(append([]byte{4}, bytes.Repeat([]byte{0xff}, 64)...))),
		seq(seq(oid("1.2.840.10045.2.1"), oid("1.2.840.10045.3.1.7")), bits(append([]byte{4}, bytes.Repeat([]byte{0x11}, 64)...))),
		seq(seq(oid("1.3.101.112")), bits(make([]byte, 31))),
		seq(seq(oid("1.3.101.112"), null()), bits(make([]byte, 32))),
		seq(seq(oid("1.3.101.110")), bits(make([]byte, 33))),
		seq(seq(oid("1.3.101.110"), null()), bits(make([]byte, 32))),
		seq(seq(oid("1.2.840.10040.4.1"), seq(integer("7"), integer("5"))), bits(integer("3"))),
		seq(seq(oid("1.2.840.10040.4.1"), seq(integer("7"), integer("5"), integer("0"))), bits(integer("3"))),
		seq(seq(oid("1.2.840.10040.4.1"), seq(integer("7"), integer("5"), integer("2"))), bits(integer("-3"))),
		seq(seq(oid("1.2.840.10040.4.1"), seq(integer("7"), integer("5"), integer("2"))), bits(octets(nil))),
		seq(seq(oid("1.2.840.10040.4.1")), bits(integer("3"))),
		seq(seq(oid("1.3.101.113")), bits(make([]byte, 57))),
		seq(seq(oid("1.2.3.4")), bits([]byte{1})),
		seq(seq(oid("1.2.840.113549.1.1.10")), bits(seq(integer("5"), integer("3")))),
		seq(seq(oid("1.3.101.112")), bits(make([]byte, 32)), null()),
		seq(seq(oid("1.3.101.112"))),
		seq(),
		seq(null(), bits(nil)),
		set(seq(oid("1.3.101.112")), bits(make([]byte, 32))),
	} {
		add(fmt.Sprintf("spki % x", k), v3(k, nil))
	}

	// Extensions, one at a time.
	one := func(id string, critical bool, v []byte) tbsParts { return v3(ed25519Key(), exts(ext(id, critical, v))) }
	for _, c := range []struct {
		id string
		cr bool
		v  []byte
	}{
		{"2.5.29.15", false, bits(nil)}, {"2.5.29.15", false, tlv(0x03, []byte{0x07, 0x80})}, {"2.5.29.15", false, octets(nil)},
		{"2.5.29.15", false, append(bits([]byte{0x80}), 0)},
		{"2.5.29.19", false, seq()}, {"2.5.29.19", false, seq(boolean(false))}, {"2.5.29.19", false, seq(tlv(0x01, []byte{1}))},
		{"2.5.29.19", false, seq(boolean(true), integer("-1"))}, {"2.5.29.19", false, seq(boolean(true), integer("0x7fffffff"))},
		{"2.5.29.19", false, seq(boolean(true), integer("0x80000000"))}, {"2.5.29.19", false, seq(boolean(true), integer("0xffffffff"))},
		{"2.5.29.19", false, seq(boolean(true), integer("0x100000000"))}, {"2.5.29.19", false, seq(boolean(true), integer("0x7fffffffffffffff"))},
		{"2.5.29.19", false, seq(boolean(true), integer("0x8000000000000000"))}, {"2.5.29.19", false, seq(integer("3"))},
		{"2.5.29.19", false, seq(boolean(true), str(0x13, "x"))}, {"2.5.29.19", false, set()},
		{"2.5.29.17", false, seq()}, {"2.5.29.17", true, seq()}, {"2.5.29.17", true, seq(ctx(0, true, oid("1.2.3")))},
		{"2.5.29.17", false, seq(ctx(7, false, []byte{1, 2, 3, 4, 5}))}, {"2.5.29.17", false, seq(ctx(7, false, nil))},
		{"2.5.29.17", false, seq(ctx(2, false, []byte("é.example")))}, {"2.5.29.17", false, seq(ctx(1, false, []byte("a\xff")))},
		{"2.5.29.17", false, seq(ctx(6, false, []byte("\x01\"é\\")))}, {"2.5.29.17", false, seq(ctx(2, false, nil))},
		{"2.5.29.17", false, seq(ctx(2, false, []byte("..")))}, {"2.5.29.17", false, seq([]byte{0x1f, 0x01, 0x00})},
		{"2.5.29.17", false, set()}, {"2.5.29.17", false, append(seq(), 0)},
		{"2.5.29.35", false, seq()}, {"2.5.29.35", true, seq()}, {"2.5.29.35", false, seq(ctx(0, true))},
		{"2.5.29.35", false, octets(nil)}, {"2.5.29.35", false, seq(ctx(1, false, nil))},
		{"2.5.29.14", true, octets(nil)}, {"2.5.29.14", false, seq()}, {"2.5.29.14", false, append(octets(nil), 0)},
		{"2.5.29.37", false, seq()}, {"2.5.29.37", false, seq(null())}, {"2.5.29.37", false, set()},
		{"2.5.29.37", false, seq(oid("2.5.29.37.0"), oid("1.3.6.1.5.5.7.3.9"), oid("1.3.6.1.4.1.311.10.3.3"))},
		{"2.5.29.32", false, seq()}, {"2.5.29.32", false, seq(seq(oid("1.2.3")), seq(oid("1.2.3")))},
		{"2.5.29.32", false, seq(seq(null()))}, {"2.5.29.32", false, seq(seq(tlv(0x06, []byte{0x2a, 0x80})))},
		{"2.5.29.32", false, seq(seq(tlv(0x06, []byte{0x2a, 0x80, 0x01})))}, {"2.5.29.32", false, seq(seq(tlv(0x06, nil)))},
		{"2.5.29.32", false, seq(seq(tlv(0x06, []byte{0x2a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f})))},
		{"2.5.29.32", false, set()},
		{"2.5.29.33", false, seq()}, {"2.5.29.33", false, seq(seq(oid("1.2")))}, {"2.5.29.33", false, set()},
		{"2.5.29.33", false, seq(seq(oid("1.2"), oid("1.3"), oid("1.4")))},
		{"2.5.29.36", false, seq()}, {"2.5.29.36", false, seq(ctx(0, false, []byte{0x80}))},
		{"2.5.29.36", false, seq(ctx(0, false, []byte{0x7f, 0xff, 0xff, 0xff}))}, {"2.5.29.36", false, seq(ctx(0, false, []byte{0x00, 0x80, 0x00, 0x00, 0x00}))},
		{"2.5.29.36", false, seq(ctx(1, false, []byte{0x01, 0x00, 0x00, 0x00, 0x00}))}, {"2.5.29.36", false, seq(ctx(0, false, nil))},
		{"2.5.29.36", false, seq(ctx(1, false, []byte{0x00, 0x01}))}, {"2.5.29.36", false, set()},
		{"2.5.29.36", false, seq(ctx(0, false, bytes.Repeat([]byte{0x11}, 9)))},
		{"2.5.29.54", false, integer("-1")}, {"2.5.29.54", false, integer("0x7fffffff")}, {"2.5.29.54", false, integer("0x80000000")},
		{"2.5.29.54", false, integer("0x100000000")}, {"2.5.29.54", false, octets(nil)},
		{"2.5.29.31", false, seq()}, {"2.5.29.31", false, seq(seq())}, {"2.5.29.31", false, seq(null())},
		{"2.5.29.31", false, seq(seq(ctx(0, true, null())))}, {"2.5.29.31", false, seq(seq(ctx(0, true, ctx(0, true, ctx(2, false, []byte("x")), ctx(6, false, []byte("u"))))))},
		{"2.5.29.31", false, seq(seq(ctx(0, true, ctx(0, true, ctx(6, false, []byte("u")), []byte{0x86, 0x05}))))},
		{"2.5.29.31", false, set()},
		{"1.3.6.1.5.5.7.1.1", true, seq()}, {"1.3.6.1.5.5.7.1.1", false, seq(seq())}, {"1.3.6.1.5.5.7.1.1", false, seq(null())},
		{"1.3.6.1.5.5.7.1.1", false, seq(seq(oid("1.3.6.1.5.5.7.48.1"), []byte{0x86, 0x09}))}, {"1.3.6.1.5.5.7.1.1", false, set()},
		{"1.3.6.1.5.5.7.1.1", false, seq(seq(oid("1.3.6.1.5.5.7.48.1")))},
		{"2.5.29.30", false, seq()}, {"2.5.29.30", false, seq(ctx(0, true))}, {"2.5.29.30", false, seq(ctx(1, true))},
		{"2.5.29.30", false, append(seq(ctx(0, true, seq(ctx(2, false, []byte("a"))))), 0)},
		{"2.5.29.30", false, seq(ctx(0, true, seq(ctx(2, false, []byte("a")))), null())},
		{"2.5.29.30", false, seq(ctx(1, true, seq(ctx(2, false, []byte("a")))), ctx(0, true, seq(ctx(2, false, []byte("a")))))},
		{"2.5.29.30", false, seq(ctx(0, true, null()))}, {"2.5.29.30", false, seq(ctx(0, true, seq()))},
		{"2.5.29.30", true, seq(ctx(0, true, seq(ctx(3, true, null()))))},
		{"2.5.29.30", false, seq(ctx(0, false, nil))},
		{"2.5.29.98", true, null()}, {"2.5.29.15", false, null()}, {"2.5.29", false, null()},
	} {
		add(fmt.Sprintf("ext %s %v % x", c.id, c.cr, c.v), one(c.id, c.cr, c.v))
	}

	// SAN URIs, whole url.Parse on each.
	for _, u := range []string{
		"", "http://a", "http://a:80/p", "http://[::1]:8080/", "http://a b", "http://a%zz", "%zz", "a:b", ":", "//host",
		"http://host:port", "http://h:1:2/", "http://[fe80::1%25en0]/", "http://[fe80::1%en0]/", "mailto:x@y", "http://ex ample",
		"http://a\x01", "\x7f", "http://%41", "http://a.", "http://a..b", "http://.a", "ht tp://a", "1http://a",
		"http://user:pa ss@a", "http://u@s@a", "http://a?%zz", "http://a#%zz", "/path", "http://a/%2", "http://[::1", "http://::1/",
		"*", "http://a b.example/", "http://[::1]x/", "http://[::1]:x/", "http://a:/", "http://a:00080/", "http://[x]/",
		"http://%zz/", "http://a%2eb/", "http://a%20b/", "http://ü/", "http://[::1%zz]/", "?q", "#f", "mailto:%zz",
		"http://a\\b/", "http://a/b c", "file:///etc/passwd", "urn:isbn:0451450523", "http://[1.2.3.4]/", "http://a:1a/",
		"HTTP://A/", "http://-a-/", "http://a_b/", "http://:80/", "http://@a/", "http://a@/", "http://%41%42/", "http:a",
		"http:/a", "http:///a", "//a:1/", "a/b:c", "./a:b", "http://a\x00", "http://a\t/", "http://a{b}/", "http://a|/",
		"http://[::ffff:1.2.3.4]:65535/", "http://[::1]:65536/", "http://a%25/",
	} {
		add(fmt.Sprintf("san uri %q", u), v3(ed25519Key(), exts(ext("2.5.29.17", false, seq(ctx(6, false, []byte(u)))))))
	}

	// Name constraints, one subtree each.
	nc := func(base []byte) tbsParts {
		return v3(ed25519Key(), exts(ext("2.5.29.30", true, seq(ctx(0, true, seq(base))))))
	}
	for _, d := range []string{"", ".", ".a", "a.", "a..b", "a b", "é", "\xff", "\x00a", "\t", "a.b.example", ".a.b", "..a", "*.a", "a\x7f"} {
		add(fmt.Sprintf("nc dns %q", d), nc(ctx(2, false, []byte(d))))
	}
	for _, e := range []string{"a@b", "@b", "a@", "\"q\"@b", "\"q q\"@b", "a b@c", "a@b.", "a@b..c", "a.@b", ".a@b", "a..b@c", "a\\@b@c",
		"\"a\\\"b\"@c", "\"\x01\"@c", "é@b", "b", ".b", "b.", "", "a@@b", "a@b@c", "\"unterminated@b", "a@[1.2.3.4]", "a+tag@b",
		strings.Repeat("a", 65) + "@b", strings.Repeat("a", 64) + "@b", "a@" + strings.Repeat("b", 300)} {
		add(fmt.Sprintf("nc email %q", e), nc(ctx(1, false, []byte(e))))
	}
	for _, u := range []string{"1.2.3.4", "::1", "a.b", ".a.b", "a..b", "[::1]", "", "a.", "é", "1.2.3", "::ffff:1.2.3.4", "01.2.3.4", "1.2.3.4.5", "fe80::1%en0", "a:b"} {
		add(fmt.Sprintf("nc uri %q", u), nc(ctx(6, false, []byte(u))))
	}
	for _, ip := range [][]byte{
		nil, {1, 2, 3, 4}, {10, 0, 0, 0, 255, 0, 0, 0}, {10, 0, 0, 0, 255, 0, 255, 0}, {10, 0, 0, 0, 0xfe, 0, 0, 0},
		{10, 0, 0, 0, 0x80, 0, 0, 1}, {10, 0, 0, 0, 0, 0, 0, 0}, {10, 0, 0, 0, 255, 255, 255, 255}, {10, 0, 0, 0, 0x7f, 0, 0, 0},
		make([]byte, 16), make([]byte, 32), append(make([]byte, 16), append([]byte{0xff, 0x01}, make([]byte, 14)...)...), make([]byte, 33),
	} {
		add(fmt.Sprintf("nc ip % x", ip), nc(ctx(7, false, ip)))
	}
	for _, g := range [][]byte{
		ctx(0, true, oid("1.2")), ctx(3, true), ctx(4, true, plainName("x")), ctx(5, true), ctx(8, false, oid("1.2")),
		ctx(2, true, []byte("a")), str(0x13, "x"), null(),
	} {
		add(fmt.Sprintf("nc other % x", g), nc(g))
	}
	add("nc subtree without base", v3(ed25519Key(), exts(ext("2.5.29.30", true, seq(ctx(0, true, seq()))))))
	add("nc subtree not a sequence", v3(ed25519Key(), exts(ext("2.5.29.30", true, seq(ctx(0, true, null()))))))
	add("nc subtree with min and max", nc(append(ctx(2, false, []byte("a")), append(ctx(0, false, []byte{0}), ctx(1, false, []byte{1})...)...)))

	// The extension block and the extension record.
	for _, e := range [][]byte{
		ctx(3, true, seq()), ctx(3, true), ctx(3, true, seq(), null()), ctx(3, true, set()), ctx(3, false, seq()),
		ctx(3, true, seq(seq(oid("1.2.3"), octets(nil)), seq(oid("1.2.3"), octets(nil)))),
		ctx(3, true, seq(seq(oid("2.5.29.15"), octets(bits([]byte{0x80}))), seq(oid("2.5.29.15"), boolean(true), octets(bits([]byte{0x80}))))),
		ctx(3, true, seq(seq(oid("1.2.3")))), ctx(3, true, seq(seq(octets(nil)))), ctx(3, true, seq(seq(oid("1.2.3"), boolean(true)))),
		ctx(3, true, seq(seq(oid("1.2.3"), tlv(0x01, []byte{1}), octets(nil)))), ctx(3, true, seq(seq(oid("1.2.3"), boolean(false), octets(nil)))),
		ctx(3, true, seq(seq(oid("1.2.3"), octets(nil), null()))), ctx(3, true, seq(null())), ctx(3, true, seq(seq(oid("1.2.3"), null(), octets(nil)))),
		ctx(3, true, seq(seq(tlv(0x06, []byte{0x80, 0x01}), octets(nil)))),
		ctx(3, true, seq(seq(oid("2.999.3"), octets(nil)), seq(oid("2.999.3"), octets(nil)))),
	} {
		p := v3(ed25519Key(), nil)
		p.exts = e
		add(fmt.Sprintf("extensions % x", e), p)
	}
	for _, v := range []string{"0", "1"} {
		p := v3(ed25519Key(), exts(ext("1.2.3", true, nil)))
		p.version = ctx(0, true, integer(v))
		add("extensions in version "+v, p)
		p = v3(ed25519Key(), nil)
		p.version = ctx(0, true, integer(v))
		p.uids = ctx(1, false, []byte{0})
		add("unique id in version "+v, p)
	}
	for _, u := range [][]byte{
		ctx(1, false, nil), ctx(2, false, nil), append(ctx(2, false, nil), ctx(1, false, nil)...), ctx(1, true), ctx(1, false, []byte{1}),
		append(ctx(1, false, nil), ctx(1, false, nil)...), null(),
	} {
		p := v3(ed25519Key(), nil)
		p.uids = u
		add(fmt.Sprintf("unique ids % x", u), p)
	}

	// What go1.27.1 reads that go1.26.6 does not, or reads otherwise (parser.go of each).
	for _, c := range []struct {
		id     string
		params []byte
		n      int
	}{
		{"2.16.840.1.101.3.4.3.17", nil, 1312}, {"2.16.840.1.101.3.4.3.17", nil, 1311}, {"2.16.840.1.101.3.4.3.17", nil, 0},
		{"2.16.840.1.101.3.4.3.17", null(), 1312}, {"2.16.840.1.101.3.4.3.18", nil, 1952},
		{"2.16.840.1.101.3.4.3.18", nil, 1312}, {"2.16.840.1.101.3.4.3.19", nil, 2592},
		{"2.16.840.1.101.3.4.3.19", nil, 2593}, {"2.16.840.1.101.3.4.3.20", nil, 1312},
	} {
		k := make([]byte, c.n)
		for i := range k {
			k[i] = byte(i*31 + 7)
		}
		ai := seq(oid(c.id))
		if c.params != nil {
			ai = seq(oid(c.id), c.params)
		}
		add(fmt.Sprintf("ML-DSA key %s of %d bytes, parameters % x", c.id, c.n, c.params), v3(seq(ai, bits(k)), nil))
	}
	{
		p := v3(rsaKey("65537"), nil)
		p.sigAI, p.outerAI = seq(oid("2.16.840.1.101.3.4.3.18"), null()), seq(oid("2.16.840.1.101.3.4.3.18"), null())
		add("ML-DSA-65 signature algorithm with parameters", p)
	}
	for _, ip := range [][]byte{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1}, append(make([]byte, 10), 0xff, 0xff, 0, 0, 0, 0),
		append(make([]byte, 10), 0xff, 0xfe, 1, 2, 3, 4), append(make([]byte, 12), 1, 2, 3, 4),
	} {
		add(fmt.Sprintf("SAN IP % x", ip), v3(rsaKey("65537"), exts(ext("2.5.29.17", false, seq(ctx(7, false, ip))))))
		c := append(append([]byte{}, ip...), bytes.Repeat([]byte{0xff}, 16)...)
		add(fmt.Sprintf("IP constraint % x", c),
			v3(rsaKey("65537"), exts(ext("2.5.29.30", true, seq(ctx(0, true, seq(ctx(7, false, c))))))))
	}
	for _, m := range []string{"a@b@c", "a@b", "a@", "a@b..c", "a@.b", `"q@x"@b@c`, "a@b.c@", "a.@b"} {
		add("email constraint "+m,
			v3(rsaKey("65537"), exts(ext("2.5.29.30", false, seq(ctx(1, true, seq(ctx(1, false, []byte(m)))))))))
	}

	// The envelope.
	{
		p := v3(ed25519Key(), nil)
		p.trailing = []byte{0}
		add("one byte after the certificate", p)
		p = v3(ed25519Key(), nil)
		p.signature = tlv(0x03, []byte{0x08})
		add("signature with 8 unused bits", p)
		p = v3(ed25519Key(), nil)
		p.signature = octets([]byte{1})
		add("signature not a bit string", p)
		p = v3(ed25519Key(), nil)
		p.signature = append(bits([]byte{1}), 0)
		add("bytes after the signature", p)
		p = v3(ed25519Key(), nil)
		p.signature = nil
		add("no signature", p)
		p = v3(ed25519Key(), nil)
		p.exts = null()
		add("bytes after the tbs fields", p)
		out = append(out, edge{"empty", nil}, edge{"one byte", []byte{0x30}}, edge{"empty sequence", seq()},
			edge{"sequence of nothing but a sequence", seq(seq())}, edge{"long form length of 5", []byte{0x30, 0x81, 0x05, 0, 0, 0, 0, 0}},
			edge{"length with a leading zero", append([]byte{0x30, 0x82, 0x00, 0x80}, make([]byte, 0x80)...)},
			edge{"indefinite length", []byte{0x30, 0x80, 0, 0}}, edge{"high tag number", []byte{0x3f, 0x01, 0x00}},
			edge{"five length bytes", []byte{0x30, 0x85, 0, 0, 0, 0, 1, 0}})
	}
	return out
}

// ---- the cases ---------------------------------------------------------------------------------

type mutation struct {
	base, pos int
	op        byte // 0 none, 1 xor, 2 set, 3 cut at pos
	val       byte
}

func mutations(bs [][]byte) []mutation {
	var ms []mutation
	for b, der := range bs {
		ms = append(ms, mutation{b, 0, 0, 0})
		for i := range der {
			ms = append(ms, mutation{b, i, 1, 0xff}, mutation{b, i, 1, 0x01}, mutation{b, i, 2, 0x00},
				mutation{b, i, 2, 0x80}, mutation{b, i, 2, 0x7f}, mutation{b, i, 3, 0})
		}
	}
	return ms
}

func apply(der []byte, m mutation) []byte {
	out := append([]byte(nil), der...)
	switch m.op {
	case 1:
		out[m.pos] ^= m.val
	case 2:
		out[m.pos] = m.val
	case 3:
		out = out[:m.pos]
	}
	return out
}

func verdict(der []byte) string {
	_, err := x509.ParseCertificate(der)
	if err != nil {
		return err.Error()
	}
	return ""
}

func main() {
	bs := bases()
	es := edges()
	ms := mutations(bs)
	if len(os.Args) == 2 && os.Args[1] == "-texts" {
		w := bufio.NewWriter(os.Stdout)
		for _, m := range ms {
			fmt.Fprintf(w, "%q\n", verdict(apply(bs[m.base], m)))
		}
		for _, e := range es {
			fmt.Fprintf(w, "%q\n", verdict(e.der))
		}
		w.Flush()
		return
	}
	if len(os.Args) != 6 || os.Args[1] != "-header" {
		fmt.Fprintln(os.Stderr, "usage: x509read -texts | -header texts64 texts32 texts64-go1.27 texts32-go1.27")
		os.Exit(2)
	}
	t64, t32 := readTexts(os.Args[2]), readTexts(os.Args[3])
	u64, u32 := readTexts(os.Args[4]), readTexts(os.Args[5])
	if len(t64) != len(ms)+len(es) || len(t32) != len(t64) || len(u64) != len(t64) || len(u32) != len(t64) {
		fmt.Fprintln(os.Stderr, "the text files do not match the cases")
		os.Exit(1)
	}

	index := map[string]int{"": 0}
	texts := []string{""}
	id := func(s string) int {
		if i, ok := index[s]; ok {
			return i
		}
		index[s] = len(texts)
		texts = append(texts, s)
		return len(texts) - 1
	}

	var w strings.Builder
	w.WriteString("/* Generated by tools/x509read from Go's own x509.ParseCertificate (go1.26.6 and go1.27.1); see its header\n")
	w.WriteString(" * for how to regenerate. Do not edit. */\n#ifndef LC_X509GO_REFERENCE_H\n#define LC_X509GO_REFERENCE_H\n\n#include <stdint.h>\n\n")
	w.WriteString("static const uint8_t xg_pool[] = {")
	var pool []byte
	var baseOff []int
	for _, b := range bs {
		baseOff = append(baseOff, len(pool))
		pool = append(pool, b...)
	}
	var edgeOff []int
	for _, e := range es {
		edgeOff = append(edgeOff, len(pool))
		pool = append(pool, e.der...)
	}
	for i, c := range pool {
		if i%24 == 0 {
			w.WriteString("\n   ")
		}
		fmt.Fprintf(&w, " %d,", c)
	}
	w.WriteString("\n};\n\n/* Each base certificate: its offset and length in xg_pool. */\n")
	w.WriteString("static const struct { uint32_t off, len; } xg_bases[] = {\n")
	for i, b := range bs {
		fmt.Fprintf(&w, "    {%d, %d},\n", baseOff[i], len(b))
	}
	// Texts are indexed in case order, so that the table is stable from run to run.
	caseIDs := make([][4]int, len(t64))
	for i := range t64 {
		caseIDs[i] = [4]int{id(t64[i]), id(t32[i]), id(u64[i]), id(u32[i])}
	}
	w.WriteString("};\n\n/* What x509.ParseCertificate returned, \"\" for a certificate it parsed. */\n")
	w.WriteString("static const char *const xg_texts[] = {\n")
	for _, t := range texts {
		fmt.Fprintf(&w, "    %s,\n", cString(t))
	}
	w.WriteString("};\n\n/* A base mutated: the base, the byte, the operation (0 none, 1 xor, 2 set, 3 cut there) and its\n")
	w.WriteString(" * value; then the text as a 64-bit go1.26.6 answers it and as a 32-bit one, and the same two\n")
	w.WriteString(" * of go1.27.1. */\n")
	w.WriteString("static const struct { uint16_t base; uint16_t pos; uint8_t op, val; uint16_t t64, t32, u64, u32; } xg_mutations[] = {\n")
	for i, m := range ms {
		c := caseIDs[i]
		fmt.Fprintf(&w, "    {%d, %d, %d, %d, %d, %d, %d, %d},\n", m.base, m.pos, m.op, m.val, c[0], c[1], c[2], c[3])
	}
	w.WriteString("};\n\n/* The edges: what each is, where it is in xg_pool, and the four texts. */\n")
	w.WriteString("static const struct { const char *what; uint32_t off, len; uint16_t t64, t32, u64, u32; } xg_edges[] = {\n")
	for i, e := range es {
		c := caseIDs[len(ms)+i]
		fmt.Fprintf(&w, "    {%s, %d, %d, %d, %d, %d, %d},\n", cString(e.what), edgeOff[i], len(e.der), c[0], c[1], c[2], c[3])
	}
	w.WriteString("};\n\n#endif\n")
	os.Stdout.WriteString(w.String())

	var differ []string
	toolchains := 0
	for i := range t64 {
		if t64[i] != t32[i] || u64[i] != u32[i] {
			differ = append(differ, t64[i]+" | "+t32[i])
		}
		if t64[i] != u64[i] || t32[i] != u32[i] {
			toolchains++
		}
	}
	sort.Strings(differ)
	fmt.Fprintf(os.Stderr, "%d cases, %d distinct texts, %d where 32 and 64 bits differ, %d where go1.26.6 and go1.27.1 differ\n",
		len(t64), len(texts), len(differ), toolchains)
}

func readTexts(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		s, err := strconv.Unquote(sc.Text())
		if err != nil {
			panic(err)
		}
		out = append(out, s)
	}
	return out
}

// A C string literal for any bytes: printable ASCII as it is, everything else in octal, and the
// literal broken after an escape so that a digit that follows cannot extend it.
func cString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c == '?':
			b.WriteString("\\?") // no trigraphs
		case c >= 0x20 && c < 0x7f:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "\\%03o", c)
		}
	}
	b.WriteByte('"')
	return b.String()
}
