package main

// The SECOND ClientHello — the one uTLS builds after a HelloRetryRequest, which nothing here could
// produce before and which the C client therefore had no way to be checked against.
//
// Why it needs a real exchange rather than another BuildHandshakeState: hello2 is not a fresh
// message. Go mutates the SAME hello object and re-marshals it, so the random, the session id, the
// cipher order and every GREASE draw are hello1's, unchanged, and only key_share (and the cookie,
// when one comes) differ. A vector captured any other way would not show that.
//
// The server side here is hand-written on purpose: it sends exactly one HelloRetryRequest and
// nothing else, so what comes back is hello2 and not the result of a negotiation.

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"

	"flag"

	utls "github.com/refraction-networking/utls"
)

// The random every HelloRetryRequest carries, RFC 8446 4.1.3: SHA-256 of "HelloRetryRequest".
var helloRetryRequestRandom = []byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

// buildHRR frames a HelloRetryRequest that names `group`, echoing the session id the client sent.
// When cookie is non-empty a cookie extension carries it. That is the only way to learn where the
// reference puts the echo: RFC 8446 4.2.2 says it must come back verbatim and says nothing at all
// about position, and position is the whole of what a fingerprint is made of.
func buildHRR(sessionID []byte, cipher uint16, group uint16, cookie []byte) []byte {
	var ext []byte
	ext = append(ext, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04) // supported_versions: TLS 1.3
	ext = append(ext, 0x00, 0x33, 0x00, 0x02)             // key_share: the group, no share
	ext = binary.BigEndian.AppendUint16(ext, group)
	if len(cookie) > 0 {
		ext = append(ext, 0x00, 0x2c)
		ext = binary.BigEndian.AppendUint16(ext, uint16(len(cookie)+2))
		ext = binary.BigEndian.AppendUint16(ext, uint16(len(cookie)))
		ext = append(ext, cookie...)
	}

	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, helloRetryRequestRandom...)
	body = append(body, byte(len(sessionID)))
	body = append(body, sessionID...)
	body = binary.BigEndian.AppendUint16(body, cipher)
	body = append(body, 0x00) // legacy_compression_method
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)

	msg := []byte{0x02, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	msg = append(msg, body...)

	rec := []byte{0x16, 0x03, 0x03, byte(len(msg) >> 8), byte(len(msg))}
	return append(rec, msg...)
}

// readHandshakeRecord reads one TLS record and returns its payload, skipping ChangeCipherSpec —
// which uTLS sends between the two hellos for middlebox compatibility and which is not a message.
func readHandshakeRecord(r io.Reader) ([]byte, error) {
	for {
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(r, hdr); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(hdr[3:5]))
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, err
		}
		if hdr[0] == 0x14 { // change_cipher_spec
			continue
		}
		if hdr[0] == 0x15 && len(body) >= 2 {
			return nil, fmt.Errorf("the client answered with alert level %d description %d", body[0], body[1])
		}
		if hdr[0] != 0x16 {
			return nil, fmt.Errorf("record type 0x%02x where a handshake was expected", hdr[0])
		}
		return body, nil
	}
}

func cmdRetry(args []string) {
	fs := flag.NewFlagSet("retry", flag.ExitOnError)
	name := fs.String("fp", "firefox", "fingerprint name")
	sni := fs.String("sni", "fp.example", "SNI")
	group := fs.Int("group", 0x0018, "group the retry asks for (0x0018 = secp384r1)")
	out1 := fs.String("o1", "", "write the FIRST hello here")
	out2 := fs.String("o2", "", "write the SECOND hello here")
	cookieHex := fs.String("cookie", "", "hex cookie the retry asks to be echoed (empty: none)")
	fs.Parse(args)

	var cookie []byte
	if *cookieHex != "" {
		var err error
		cookie, err = hex.DecodeString(*cookieHex)
		fail(err)
	}

	id, ok := fingerprints[*name]
	if !ok {
		fail(fmt.Errorf("unknown fingerprint %q", *name))
	}

	client, server := net.Pipe()
	u := utls.UClient(client, &utls.Config{
		ServerName:             *sni,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
	}, *id)

	done := make(chan error, 1)
	go func() { done <- u.Handshake() }()

	first, err := readHandshakeRecord(server)
	fail(err)
	ch1, err := ParseClientHello(first)
	fail(err)

	// The suite has to be one the client offered AND a TLS 1.3 one: uTLS answers a retry naming
	// anything else with an alert, which is what the first version of this got back.
	cipher := uint16(0)
	for _, c := range ch1.CipherSuites {
		if c == 0x1301 || c == 0x1302 || c == 0x1303 {
			cipher = c
			break
		}
	}
	if cipher == 0 {
		fail(fmt.Errorf("the fingerprint offers no TLS 1.3 cipher suite"))
	}
	_, err = server.Write(buildHRR(ch1.SessionID, cipher, uint16(*group), cookie))
	fail(err)

	second, err := readHandshakeRecord(server)
	fail(err)
	ch2, err := ParseClientHello(second)
	fail(err)

	/* The handshake is abandoned here: the point was the second message, and going further would
	 * need a certificate this tool has no business owning. */
	client.Close()
	server.Close()
	<-done

	if *out1 != "" {
		fail(os.WriteFile(*out1, first, 0o644))
	}
	if *out2 != "" {
		fail(os.WriteFile(*out2, second, 0o644))
	}
	fmt.Printf("hello1 %d bytes, hello2 %d bytes\n", len(first), len(second))
	fmt.Printf("random carried over: %v\n", equalBytes(ch1.Random, ch2.Random))
	fmt.Printf("session id carried over: %v\n", equalBytes(ch1.SessionID, ch2.SessionID))

	reportExtensions("hello1", ch1)
	reportExtensions("hello2", ch2)
	for i, e := range ch2.Extensions {
		if e.Type == 0x002c {
			fmt.Printf("cookie echoed at index %d of %d, extension_data %d bytes, verbatim %v"+"\n",
				i, len(ch2.Extensions), len(e.Data), len(e.Data) == len(cookie)+2 && equalBytes(e.Data[2:], cookie))
		}
	}
	_ = sha256.New
}

func equalBytes(a, b []byte) bool {
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

// reportExtensions prints the extension types in the order they appear. Order is the whole of a
// fingerprint, so it is also the only way to see where an echoed cookie lands.
func reportExtensions(label string, ch *ClientHello) {
	fmt.Printf("%s extensions:", label)
	for _, e := range ch.Extensions {
		fmt.Printf(" 0x%04x", e.Type)
	}
	fmt.Println()
}
