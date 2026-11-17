package main

// Human names for the numbers on the wire. Taken from dicttls — the same dictionary uTLS uses — so
// that names in our fingerprint tables and names in its sources are literally the same strings and
// a diff between the two can be read by eye.

import (
	"fmt"

	"github.com/refraction-networking/utls/dicttls"
)

// What the uTLS dictionary does not carry yet. Neither entry is exotic: X25519MLKEM768 is what the
// REALITY handshake is built on today, and GREASE-ECH takes 281 bytes of the Firefox hello — with
// no name it reads as "ext_0xfe0d".
var extraNames = map[uint16]string{
	0x11ec: "X25519MLKEM768",
	0x6399: "X25519Kyber768Draft00",
	0xfe0d: "encrypted_client_hello",
}

func lookup(m map[uint16]string, v uint16, prefix string) string {
	if IsGREASE(v) {
		return "GREASE"
	}
	if s, ok := m[v]; ok {
		return s
	}
	if s, ok := extraNames[v]; ok {
		return s
	}
	return fmt.Sprintf("%s_0x%04x", prefix, v)
}

func extName(v uint16) string    { return lookup(dicttls.DictExtTypeValueIndexed, v, "ext") }
func cipherName(v uint16) string { return lookup(dicttls.DictCipherSuiteValueIndexed, v, "cipher") }
func groupName(v uint16) string  { return lookup(dicttls.DictSupportedGroupsValueIndexed, v, "group") }
func sigName(v uint16) string    { return lookup(dicttls.DictSignatureSchemeValueIndexed, v, "sig") }

func certCompName(v uint16) string {
	return lookup(dicttls.DictCertificateCompressionAlgorithmValueIndexed, v, "certcomp")
}
