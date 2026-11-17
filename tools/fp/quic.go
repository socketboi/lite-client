package main

// The ClientHello the Hysteria2 plane sends, rendered the way the reference renders it.
//
// hysteria parrots Chrome's QUIC stack by default from 2.11 (DisableChromeParrot,
// vendor/hysteria/core/client/client.go:95), and the parrot's ClientHello is not one of uTLS's
// presets: the fork builds its own spec, chromeQUICClientHelloSpec, and hands it to a uTLS QUIC
// connection (newUTLSQUICClient, vendor/quic-go/internal/handshake/tls_conn_utls.go:33-45). This file
// does the same thing with the same calls, so the hello below is what that code path emits:
//
//	UQUICClient(&QUICConfig{TLSConfig: uConf}, HelloCustom) -> ApplyPreset(spec)
//	    -> SetTransportParameters, with the blob written into the spec's extension as well
//	    -> Start, and the first QUICWriteData at the Initial level is the ClientHello.
//
// The spec itself cannot be imported — it lives in an internal package of the fork — so it is
// COPIED below, and `fp speccheck` holds the copy to the original token for token. A copy nobody
// compares is a second opinion; this one is the reference's text or the gate fails.
//
// Run this profile through build/fp-hysteria, built with hysteria.mod and Go 1.26.
// It pins the same uTLS v1.8.2 as the fork (vendor/quic-go/go.mod:8). Xray's
// generator uses go.mod and Go 1.27 independently; an Xray upgrade cannot
// silently redefine Hysteria's reference handshake.

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"os"
	"reflect"
	"slices"
	"time"

	utls "github.com/refraction-networking/utls"
)

// The profile name. It begins with "chrome" because that is what makes src/fp/hello.c shuffle —
// and this parrot does shuffle, through the same ShuffleChromeTLSExtensions.
const chromeQUIC = "chrome-quic"

// chromeQUICClientHelloSpec returns the TLS ClientHello Chrome sends over QUIC.
//
// This is deliberately NOT one of uTLS's HelloChrome_* presets. Those are
// TLS-over-TCP (h2) fingerprints, and the QUIC ClientHello is a materially
// different message; using a TCP preset over QUIC produces a combination
// matching no real client, which is worse than not trying at all.
//
// The extension order is permuted per connection, hence the shuffle.
//
// alpn comes from the caller's tls.Config rather than being hardcoded:
// advertising a protocol the peer doesn't speak breaks the connection outright,
// which is worse than an imperfect fingerprint. The match is exact only for the
// protocol Chrome would negotiate.
func chromeQUICClientHelloSpec(alpn []string) *utls.ClientHelloSpec {
	if len(alpn) == 0 {
		alpn = []string{"h3"}
	}
	return &utls.ClientHelloSpec{
		// No GREASE suite here, unlike the TCP hello.
		CipherSuites: []uint16{
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
		},
		CompressionMethods: []byte{0x00},
		Extensions: utls.ShuffleChromeTLSExtensions([]utls.TLSExtension{
			&utls.SNIExtension{},
			// No GREASE curve, unlike the TCP hello.
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519MLKEM768,
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
			}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
				utls.PKCS1WithSHA1,
			}},
			&utls.ALPNExtension{AlpnProtocols: alpn},
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionBrotli,
			}},
			// TLS 1.3 only, again with no GREASE version.
			&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			// The ML-KEM share is what pushes the ClientHello past a single packet,
			// giving the characteristic two Initial datagrams.
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519MLKEM768},
				{Group: utls.X25519},
			}},
			// Populated from quic-go's own marshalled parameters; see
			// utlsQUICConn.SetTransportParameters.
			&utls.QUICTransportParametersExtension{},
			// ALPS at the newer codepoint; uTLS's presets use the older one.
			&utls.ApplicationSettingsExtensionNew{SupportedProtocols: alpn},
			// An ECH extension is always present: real when a config is available
			// from DNS, GREASE otherwise. GREASE is right here, and is structurally
			// indistinguishable from the real thing without decrypting it.
			utls.BoringGREASEECH(),
			// uTLS has no native support for trust_anchors, so it goes out raw.
			&utls.GenericExtension{Id: extensionTrustAnchors, Data: chromeTrustAnchorsData},
		}),
	}
}

// extensionTrustAnchors is the TLS trust_anchors extension
// (draft-ietf-tls-trust-anchor-ids).
const extensionTrustAnchors uint16 = 0xca34

// chromeTrustAnchorIDs are the trust anchor IDs Chrome requests, in binary
// relative OID form. The set follows Chrome's root store and changes across
// releases, so it is pinned like the transport parameter values.
var chromeTrustAnchorIDs = [][]byte{
	{0x82, 0xdf, 0x13, 0x02, 0x01},
	{0x82, 0xdf, 0x13, 0x02, 0x06},
	{0x82, 0xdf, 0x13, 0x02, 0x0d},
	{0x82, 0xdf, 0x13, 0x02, 0x0e},
	{0x82, 0xdf, 0x13, 0x02, 0x0f},
	{0x82, 0xdf, 0x13, 0x02, 0x12},
	{0x82, 0xdf, 0x13, 0x02, 0x13},
	{0x82, 0xdf, 0x13, 0x02, 0x14},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x07},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x08},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x09},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0a},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0b},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0c},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0d},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x12},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x13},
	{0xd6, 0x79, 0x09, 0x01},
	{0xd6, 0x79, 0x09, 0x04},
	{0xd6, 0x79, 0x09, 0x05},
	{0xd6, 0x79, 0x09, 0x06},
	{0xd6, 0x79, 0x09, 0x07},
	{0xd6, 0x79, 0x09, 0x08},
	{0xd6, 0x79, 0x09, 0x0a},
	{0xd6, 0x79, 0x09, 0x0b},
	{0xd6, 0x79, 0x09, 0x0c},
	{0xd6, 0x79, 0x09, 0x0d},
	{0xd6, 0x79, 0x09, 0x0f},
}

var chromeTrustAnchorsData = encodeTrustAnchorIDs(chromeTrustAnchorIDs)

// encodeTrustAnchorIDs encodes the extension body: a 16-bit length, then each ID
// 8-bit length-prefixed. The IDs are sorted first, as Chrome encodes them, so the
// order is the same on every connection.
func encodeTrustAnchorIDs(ids [][]byte) []byte {
	sorted := slices.Clone(ids)
	slices.SortFunc(sorted, bytes.Compare)

	var list []byte
	for _, id := range sorted {
		list = append(list, byte(len(id)))
		list = append(list, id...)
	}
	return append([]byte{byte(len(list) >> 8), byte(len(list))}, list...)
}

// What stands in for the transport parameters while rendering. The table records extension 57 as a
// mode whose body the client supplies (quic_transport_parameters), so no byte of this reaches it; it
// exists because the reference writes SOME blob there and an empty extension is a different hello.
// One parameter, max_idle_timeout = 30000 ms, in quic-go's encoding.
var quicPlaceholderParams = []byte{0x01, 0x04, 0x80, 0x00, 0x75, 0x30}

// quicReference renders the parrot's ClientHello and returns it with the spec it was built from —
// the spec's extension objects, in the order they went out, are what typeIDs and echParrot read.
func quicReference(sni string) ([]byte, *utls.ClientHelloSpec, error) {
	// utlsConfigFromStd (vendor/quic-go/internal/handshake/tls_conn_utls.go:53-111) applied to what
	// hysteria's client builds (vendor/hysteria/core/client/client.go:75-82) once http3 has put its
	// protocol in NextProtos. InsecureSkipVerify because the reference client pins rather than
	// verifies; nothing here reaches a certificate either way.
	uConf := &utls.Config{
		ServerName:             sni,
		InsecureSkipVerify:     true,
		NextProtos:             []string{"h3"},
		MinVersion:             utls.VersionTLS13,
		MaxVersion:             utls.VersionTLS13,
		SessionTicketsDisabled: true,
	}
	spec := chromeQUICClientHelloSpec(uConf.NextProtos)
	conn := utls.UQUICClient(&utls.QUICConfig{TLSConfig: uConf}, utls.HelloCustom)
	if err := conn.ApplyPreset(spec); err != nil {
		return nil, nil, fmt.Errorf("ApplyPreset: %w", err)
	}
	conn.SetTransportParameters(quicPlaceholderParams)
	for _, ext := range spec.Extensions {
		if qtp, ok := ext.(*utls.QUICTransportParametersExtension); ok {
			qtp.TransportParameters = utls.TransportParameters{
				&utls.FakeQUICTransportParameter{Id: 0x01, Val: quicPlaceholderParams[2:]},
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.Start(ctx); err != nil {
		return nil, nil, fmt.Errorf("Start: %w", err)
	}
	defer conn.Close()
	for {
		ev := conn.NextEvent()
		switch ev.Kind {
		case utls.QUICNoEvent:
			return nil, nil, fmt.Errorf("the QUIC connection produced no ClientHello")
		case utls.QUICWriteData:
			if ev.Level == utls.QUICEncryptionLevelInitial {
				return append([]byte(nil), ev.Data...), spec, nil
			}
		}
	}
}

// Where the fork's spec is read from, for the literal order and for speccheck. Set by -spec.
var quicSpecSrc string

const quicSpecFunc = "chromeQUICClientHelloSpec"

// quicSpecExtensions returns the elements of the list the fork's spec hands to
// ShuffleChromeTLSExtensions, in the order its source lists them.
func quicSpecExtensions() ([]ast.Expr, bool, error) {
	if quicSpecSrc == "" {
		return nil, false, fmt.Errorf("%s reads its literal order from the fork's spec: pass -spec", chromeQUIC)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, quicSpecSrc, nil, 0)
	if err != nil {
		return nil, false, err
	}
	fd := findFunc(f, quicSpecFunc)
	if fd == nil || fd.Body == nil {
		return nil, false, fmt.Errorf("%s has no function %s", quicSpecSrc, quicSpecFunc)
	}
	var elems []ast.Expr
	found := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok || typeIdent(call.Fun) != "ShuffleChromeTLSExtensions" || len(call.Args) != 1 {
			return true
		}
		if cl, ok := call.Args[0].(*ast.CompositeLit); ok {
			elems = cl.Elts
			found = true
		}
		return false
	})
	if !found {
		return nil, false, fmt.Errorf("%s in %s passes no literal list to ShuffleChromeTLSExtensions", quicSpecFunc, quicSpecSrc)
	}
	return elems, true, nil
}

func findFunc(f *ast.File, name string) *ast.FuncDecl {
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == name {
			return fd
		}
	}
	return nil
}

// quicTypeIDs is typeIDs for the QUIC parrot: the spec's extension objects are already in the order
// the hello carries them, because ShuffleChromeTLSExtensions permuted that very slice.
func quicTypeIDs(sni string) (map[string][]uint16, error) {
	raw, spec, err := quicReference(sni)
	if err != nil {
		return nil, err
	}
	ch, err := ParseClientHello(raw)
	if err != nil {
		return nil, err
	}
	var objs []utls.TLSExtension
	for _, e := range spec.Extensions {
		if e.Len() > 0 {
			objs = append(objs, e)
		}
	}
	if len(objs) != len(ch.Extensions) {
		return nil, fmt.Errorf("%d extension objects write bytes, the hello carries %d", len(objs), len(ch.Extensions))
	}
	out := map[string][]uint16{}
	for i, e := range objs {
		t := reflect.TypeOf(e)
		if t.Kind() == reflect.Ptr {
			t = t.Elem()
		}
		out[t.Name()] = append(out[t.Name()], ch.Extensions[i].Type)
	}
	return out, nil
}

// cmdSpecCheck holds the copy above to the fork's function, token for token, comments aside. Any
// difference — a group, a scheme, an extension, their order — fails, and says where.
func cmdSpecCheck(args []string) {
	fs := flag.NewFlagSet("speccheck", flag.ExitOnError)
	spec := fs.String("spec", "", "the fork's chrome_client_hello.go")
	cp := fs.String("copy", "", "the file holding this tool's copy (tools/fp/quic.go)")
	fs.Parse(args)
	if *spec == "" || *cp == "" {
		usage()
	}
	fail(checkQUICSpecCopy(*spec, *cp))
	fmt.Printf("%s: the function and trust-anchor declarations match the fork\n", quicSpecFunc)
}

func checkQUICSpecCopy(spec, cp string) error {
	// The hello now references data outside its function. Comparing the function
	// alone would accept changed anchor IDs or an encoder producing different bytes.
	for _, name := range []string{quicSpecFunc, "extensionTrustAnchors", "chromeTrustAnchorIDs",
		"chromeTrustAnchorsData", "encodeTrustAnchorIDs"} {
		want, err := declarationTokens(spec, name)
		if err != nil {
			return err
		}
		got, err := declarationTokens(cp, name)
		if err != nil {
			return err
		}
		for i := 0; i < len(want) || i < len(got); i++ {
			if i >= len(want) || i >= len(got) || want[i].text != got[i].text {
				var w, g string
				if i < len(want) {
					w = fmt.Sprintf("%q at %s", want[i].text, want[i].pos)
				}
				if i < len(got) {
					g = fmt.Sprintf("%q at %s", got[i].text, got[i].pos)
				}
				return fmt.Errorf("the copy of %s differs from the fork's at token %d: fork %s, copy %s", name, i, w, g)
			}
		}
	}
	return nil
}

type specToken struct {
	text string
	pos  token.Position
}

func declarationTokens(path, name string) ([]specToken, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, err
	}
	var decl ast.Node
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil && d.Name.Name == name {
				decl = d
			}
		case *ast.GenDecl:
			for _, s := range d.Specs {
				if value, ok := s.(*ast.ValueSpec); ok {
					for _, id := range value.Names {
						if id.Name == name {
							decl = d
						}
					}
				}
			}
		}
	}
	if decl == nil {
		return nil, fmt.Errorf("%s has no declaration %s", path, name)
	}
	start, end := fset.Position(decl.Pos()).Offset, fset.Position(decl.End()).Offset
	body := src[start:end]
	var s scanner.Scanner
	tf := token.NewFileSet().AddFile(path, -1, len(body))
	s.Init(tf, body, nil, 0) // comments skipped
	var out []specToken
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		text := tok.String()
		if lit != "" {
			text = lit
		}
		p := tf.Position(pos)
		p.Line += fset.Position(decl.Pos()).Line - 1
		out = append(out, specToken{text, p})
	}
	return out, nil
}
