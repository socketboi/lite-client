// What the QUIC plane's reference answers a handshake message it did not expect — Go's own
// unmarshalHandshakeMessage, run (GOROOT/src/crypto/tls/conn.go, go1.25.14). Writes
// test/qpin/reference_misplaced.h, which test/qpin holds lc_std_misplaced_alert to.
//
// A TEST OF THE STANDARD LIBRARY'S OWN PACKAGE, because the function and every unmarshal it calls
// are unexported: this file is dropped into crypto/tls of the go1.25.14 toolchain hysteria is built
// with and run with `go test`. FROZEN, NOT BUILT BY THE GATE: the toolchain has to be fetched.
// Regenerate in the build image, from the repository root:
//
//	docker run --rm -v "$PWD:/repo" lc-build:local sh -c 'export GOTOOLCHAIN=go1.25.14 && \
//	  R=$(go env GOROOT) && chmod -R u+w $R/src/crypto/tls && \
//	  cp /repo/tools/misplaced/zz_misplaced_test.go $R/src/crypto/tls/ && \
//	  MISPLACED_OUT=/repo/test/qpin/reference_misplaced.h \
//	  go test crypto/tls -run TestMisplacedVectors -count=1'
//
// WHAT IS RECORDED: for every message and for both versions the reader can be at — 0 before the
// first ServerHello, TLS 1.3 after it — the alert unmarshalHandshakeMessage sent (10 for a type it
// has no message for, 50 for one that does not unmarshal), or 10 when it unmarshalled, because the
// handshake's type assertion that follows it then fails. The messages: one well-formed message of
// every type the reference knows, marshalled by the reference, then each mutated at random — a byte
// changed, the tail cut, a byte added, a length field bent — with the four-byte header rewritten to
// the length that results, since the framing that hands a message over has already read it; a set
// of types the reference has no message for; and the edges random mutation seldom reaches, written
// out one rule at a time (mpEdges) - added because six of eleven mutants of the C readers
// survived the random set alone.
package tls

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

type mpSink struct{ w bytes.Buffer }

func (s *mpSink) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (s *mpSink) Write(b []byte) (int, error)      { return s.w.Write(b) }
func (s *mpSink) Close() error                     { return nil }
func (s *mpSink) LocalAddr() net.Addr              { return nil }
func (s *mpSink) RemoteAddr() net.Addr             { return nil }
func (s *mpSink) SetDeadline(time.Time) error      { return nil }
func (s *mpSink) SetReadDeadline(time.Time) error  { return nil }
func (s *mpSink) SetWriteDeadline(time.Time) error { return nil }

func mpAnswer(msg []byte, vers uint16) int {
	s := &mpSink{}
	c := &Conn{conn: s, isClient: true, config: &Config{}, vers: vers}
	_, err := c.unmarshalHandshakeMessage(append([]byte(nil), msg...), nil)
	w := s.w.Bytes()
	if len(w) >= 7 && w[0] == 0x15 {
		return int(w[6])
	}
	if err == nil {
		return 10 // unmarshalled; the type assertion after it is the refusal
	}
	return -1
}

func mpMust(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

func mpBases() [][]byte {
	cert := bytes.Repeat([]byte{0x30}, 40)
	return [][]byte{
		{typeHelloRequest, 0, 0, 0},
		mpMust((&clientHelloMsg{vers: VersionTLS12, random: make([]byte, 32), sessionId: []byte{1, 2},
			cipherSuites: []uint16{0x1301, 0x1302}, compressionMethods: []uint8{0}, serverName: "a.example",
			supportedCurves: []CurveID{X25519, CurveP256}, supportedPoints: []uint8{0},
			supportedSignatureAlgorithms:     []SignatureScheme{ECDSAWithP256AndSHA256},
			supportedSignatureAlgorithmsCert: []SignatureScheme{PSSWithSHA256},
			alpnProtocols:                    []string{"h3"}, supportedVersions: []uint16{VersionTLS13},
			keyShares: []keyShare{{group: X25519, data: make([]byte, 32)}}, pskModes: []uint8{1},
			quicTransportParameters: []byte{1, 2, 3}, cookie: []byte{9, 9}, ocspStapling: true, scts: true,
			extendedMasterSecret: true, secureRenegotiationSupported: true}).marshal()),
		mpMust((&serverHelloMsg{vers: VersionTLS12, random: make([]byte, 32), sessionId: []byte{},
			cipherSuite: 0x1301, supportedVersion: VersionTLS13,
			serverShare: keyShare{group: X25519, data: make([]byte, 32)}}).marshal()),
		mpMust((&newSessionTicketMsgTLS13{lifetime: 1, ageAdd: 2, nonce: []byte{3}, label: []byte{4, 5},
			maxEarlyData: 7}).marshal()),
		mpMust((&newSessionTicketMsg{ticket: []byte{1, 2, 3}}).marshal()),
		{typeEndOfEarlyData, 0, 0, 0},
		mpMust((&encryptedExtensionsMsg{alpnProtocol: "h3", quicTransportParameters: []byte{1, 2},
			earlyData: true, serverNameAck: true}).marshal()),
		mpMust((&certificateMsgTLS13{certificate: Certificate{Certificate: [][]byte{cert, cert},
			OCSPStaple: []byte{1}, SignedCertificateTimestamps: [][]byte{{2}}}, ocspStapling: true,
			scts: true}).marshal()),
		mpMust((&certificateMsg{certificates: [][]byte{cert, cert[:7]}}).marshal()),
		mpMust((&serverKeyExchangeMsg{key: []byte{1, 2, 3}}).marshal()),
		mpMust((&certificateRequestMsgTLS13{ocspStapling: true, scts: true,
			supportedSignatureAlgorithms:     []SignatureScheme{ECDSAWithP256AndSHA256},
			supportedSignatureAlgorithmsCert: []SignatureScheme{PSSWithSHA256},
			certificateAuthorities:           [][]byte{{1, 2}}}).marshal()),
		mpMust((&certificateRequestMsg{certificateTypes: []byte{1, 64},
			certificateAuthorities: [][]byte{{1, 2, 3}}}).marshal()),
		mpMust((&certificateRequestMsg{hasSignatureAlgorithm: true, certificateTypes: []byte{1},
			supportedSignatureAlgorithms: []SignatureScheme{PKCS1WithSHA256},
			certificateAuthorities:       [][]byte{{1}}}).marshal()),
		{typeServerHelloDone, 0, 0, 0},
		mpMust((&certificateVerifyMsg{hasSignatureAlgorithm: true, signatureAlgorithm: Ed25519,
			signature: []byte{1, 2, 3}}).marshal()),
		mpMust((&certificateVerifyMsg{signature: []byte{1, 2, 3}}).marshal()),
		mpMust((&clientKeyExchangeMsg{ciphertext: []byte{1, 2, 3}}).marshal()),
		mpMust((&finishedMsg{verifyData: make([]byte, 32)}).marshal()),
		mpMust((&certificateStatusMsg{response: []byte{1, 2}}).marshal()),
		mpMust((&keyUpdateMsg{updateRequested: true}).marshal()),
		{3, 0, 0, 1, 0}, {6, 0, 0, 0}, {7, 0, 0, 0}, {9, 0, 0, 0}, {17, 0, 0, 0}, {25, 0, 0, 1, 1},
		{254, 0, 0, 32}, {255, 0, 0, 0},
	}
}

// A message from its type and body parts, header written.
func mpMsg(t byte, parts ...[]byte) []byte {
	var body []byte
	for _, p := range parts {
		body = append(body, p...)
	}
	n := len(body)
	return append([]byte{t, byte(n >> 16), byte(n >> 8), byte(n)}, body...)
}

// Two-byte-prefixed bytes, and an extension: identifier then prefixed data.
func mpP16(b ...byte) []byte { return append([]byte{byte(len(b) >> 8), byte(len(b))}, b...) }
func mpP24(b ...byte) []byte {
	return append([]byte{byte(len(b) >> 16), byte(len(b) >> 8), byte(len(b))}, b...)
}
func mpExt(id uint16, data ...byte) []byte {
	return append([]byte{byte(id >> 8), byte(id)}, mpP16(data...)...)
}
func mpCat(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

// The edges random mutation seldom reaches, each a rule of one of the readers: written out, and
// kept as they are rather than mutated.
func mpEdges() [][]byte {
	chHead := mpCat([]byte{3, 3}, make([]byte, 32), []byte{0}, mpP16(0x13, 0x01), []byte{1, 0})
	psk := mpCat(mpP16(mpCat(mpP16('a', 'b', 'c'), []byte{0, 0, 0, 1})...), mpP16(1, 0xff))
	sni := func(names ...[]byte) []byte {
		var l []byte
		for _, n := range names {
			l = append(l, 0)
			l = append(l, mpP16(n...)...)
		}
		return mpExt(0, mpP16(l...)...)
	}
	return [][]byte{
		mpMsg(typeCertificate, []byte{0, 0, 3, 0, 0, 0}),                      // one empty certificate: len(d) < 4
		mpMsg(typeCertificate, []byte{0, 0, 4, 0, 0, 1, 0x41}),                // one byte of certificate
		mpMsg(typeKeyUpdate, []byte{2}),                                       // neither 0 nor 1
		mpMsg(typeKeyUpdate, []byte{0}),                                       // 0 is a value
		mpMsg(typeKeyUpdate, []byte{1, 0}),                                    // a byte too many
		mpMsg(typeEncryptedExtensions, mpP16(mpExt(0, 0)...)),                 // server_name with a body
		mpMsg(typeEncryptedExtensions, mpP16(mpExt(0)...)),                    // server_name empty, as allowed
		mpMsg(typeEncryptedExtensions, mpP16(mpCat(mpExt(42), mpExt(42))...)), // early_data twice
		mpMsg(typeEncryptedExtensions, mpP16(mpExt(16, mpP16(2, 'h', '3', 2, 'h', '2')...)...)),
		// TLS 1.3: a bad OCSP extension on the SECOND certificate, which the reader skips; the same
		// on the first, which it reads; an empty SCT list on the first.
		mpMsg(typeCertificate, []byte{0}, mpP24(mpCat([]byte{0, 0, 1, 'A'}, mpP16(),
			[]byte{0, 0, 1, 'B'}, mpP16(mpExt(5, 0)...))...)),
		mpMsg(typeCertificate, []byte{0}, mpP24(mpCat([]byte{0, 0, 1, 'A'}, mpP16(mpExt(5, 0)...),
			[]byte{0, 0, 1, 'B'}, mpP16())...)),
		mpMsg(typeCertificate, []byte{0}, mpP24(mpCat([]byte{0, 0, 1, 'A'},
			mpP16(mpExt(18, 0, 0)...))...)),
		mpMsg(typeCertificateStatus, []byte{0, 0, 0, 1, 7}),                           // status type 0
		mpMsg(typeCertificateStatus, []byte{1, 0, 0, 0}),                              // an empty response
		mpMsg(typeCertificateStatus, []byte{1, 0, 0, 1, 7}),                           // well formed
		mpMsg(typeClientHello, chHead, mpP16(mpCat(mpExt(41, psk...), mpExt(23))...)), // psk not last
		mpMsg(typeClientHello, chHead, mpP16(mpCat(mpExt(23), mpExt(41, psk...))...)), // psk last
		mpMsg(typeClientHello, chHead, mpP16(mpCat(mpExt(23), mpExt(23))...)),         // twice
		mpMsg(typeClientHello, chHead, mpP16(sni([]byte("a.example."))...)),           // trailing dot
		mpMsg(typeClientHello, chHead, mpP16(sni([]byte("a"), []byte("b"))...)),       // two host names
		mpMsg(typeClientHello, chHead),                                                // no extensions
		mpMsg(typeNewSessionTicket, []byte{0, 0, 0, 1, 0, 0, 0, 2}, []byte{0}, mpP16(),
			mpP16(mpExt(42, 0, 0, 0)...)), // early_data three bytes long
		mpMsg(typeCertificateRequest, []byte{0}, mpP16(mpExt(47, mpP16(mpP16()...)...)...)), // an empty CA
	}
}

func mpMutate(rng *rand.Rand, m []byte) []byte {
	b := append([]byte(nil), m...)
	switch rng.Intn(6) {
	case 0: // a byte of the body changed
		if len(b) > 4 {
			b[4+rng.Intn(len(b)-4)] ^= byte(1 + rng.Intn(255))
		}
	case 1: // the tail cut
		if len(b) > 4 {
			b = b[:4+rng.Intn(len(b)-4)]
		}
	case 2: // a byte added
		b = append(b, byte(rng.Intn(256)))
	case 3: // a byte of the body set to zero or 0xff, which is where lengths go wrong
		if len(b) > 4 {
			v := byte(0)
			if rng.Intn(2) == 1 {
				v = 0xff
			}
			b[4+rng.Intn(len(b)-4)] = v
		}
	case 4: // a byte inserted inside
		if len(b) > 4 {
			at := 4 + rng.Intn(len(b)-4)
			b = append(b[:at], append([]byte{byte(rng.Intn(256))}, b[at:]...)...)
		}
	case 5: // two changes
		return mpMutate(rng, mpMutate(rng, b))
	}
	n := len(b) - 4
	b[1], b[2], b[3] = byte(n>>16), byte(n>>8), byte(n)
	return b
}

func TestMisplacedVectors(t *testing.T) {
	rng := rand.New(rand.NewSource(20260924))
	var msgs [][]byte
	for _, base := range mpBases() {
		msgs = append(msgs, base)
		for i := 0; i < 40; i++ {
			msgs = append(msgs, mpMutate(rng, base))
		}
	}
	msgs = append(msgs, mpEdges()...)
	var pool []byte
	var cases []string
	for _, m := range msgs {
		off := len(pool)
		pool = append(pool, m...)
		for _, v := range []uint16{0, VersionTLS13} {
			a := mpAnswer(m, v)
			tls13 := 0
			if v == VersionTLS13 {
				tls13 = 1
			}
			cases = append(cases, fmt.Sprintf("{%d, %d, %d, %d}", off, len(m), tls13, a))
		}
	}

	var w strings.Builder
	w.WriteString("/* Generated by tools/misplaced from the go1.25.14 standard library's own\n")
	w.WriteString(" * unmarshalHandshakeMessage; see its header for how to regenerate. Do not edit. */\n")
	w.WriteString("#ifndef LC_REFERENCE_MISPLACED_H\n#define LC_REFERENCE_MISPLACED_H\n\n#include <stdint.h>\n\n")
	w.WriteString("static const uint8_t mp_pool[] = {")
	for i, c := range pool {
		if i%24 == 0 {
			w.WriteString("\n   ")
		}
		fmt.Fprintf(&w, " %d,", c)
	}
	w.WriteString("\n};\n\n/* offset and length in mp_pool, 1 when the reader is at TLS 1.3, and the alert */\n")
	w.WriteString("static const struct { uint32_t off, len; int tls13, alert; } mp_cases[] = {\n")
	for _, c := range cases {
		fmt.Fprintf(&w, "    %s,\n", c)
	}
	w.WriteString("};\n\n#endif\n")
	if err := os.WriteFile(os.Getenv("MISPLACED_OUT"), []byte(w.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}
