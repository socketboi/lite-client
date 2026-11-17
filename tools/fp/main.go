// fp — fingerprint acceptance tooling. The client is accepted by these, not by "it connects":
// a wrong ClientHello does not break the connection, it only makes the client visible, so there is
// no way to notice the failure from inside.
//
//	fp dump  -fp firefox -sni HOST [-o FILE]   reference ClientHello, straight from uTLS
//	fp show  FILE                              field-by-field breakdown
//	fp diff  REF FILE [-shuffled]              comparison; non-zero exit on a real difference
//	fp table -o T.fpt [-format bin] FILE       derive a fingerprint table from a capture
//	fp build -sni HOST [-o FILE] T.json        build a ClientHello from a table
//	fp check -fp firefox -sni HOST             round trip: dump -> table -> build -> diff
//
// The reference comes from the same uTLS revision pinned in Xray's go.mod. Comparing against
// anything else would be comparing against something a router running Xray never sends.
package main

import (
	"fmt"
	"net"
	"os"
	"strings"

	"flag"

	utls "github.com/refraction-networking/utls"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "retry":
		cmdRetry(os.Args[2:])
	case "dump":
		cmdDump(os.Args[2:])
	case "show":
		cmdShow(os.Args[2:])
	case "diff":
		cmdDiff(os.Args[2:])
	case "table":
		cmdTable(os.Args[2:])
	case "build":
		cmdBuild(os.Args[2:])
	case "check":
		cmdCheck(os.Args[2:])
	case "speccheck":
		cmdSpecCheck(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `fp — ClientHello fingerprint acceptance tooling

  fp dump  -fp NAME -sni HOST [-o FILE]   reference ClientHello from uTLS
  fp show  FILE                           field-by-field breakdown
  fp diff  REF FILE [-shuffled]           compare; non-zero exit on a real difference
  fp table -o T.fpt [-format bin] -parrots U_PARROTS.GO FILE
                                          derive a fingerprint table from a capture
  fp build -sni HOST [-o FILE] T.json     build a ClientHello from a table
  fp check -fp NAME -sni HOST -parrots U_PARROTS.GO
                                          round trip: dump -> table -> build -> diff

  Flags come BEFORE the file in every one of these. Go's flag package stops at the first
  non-flag argument, so "fp table FILE -o T.fpt" parses no -o at all and prints this text — which
  is the order this list itself used to give.

Fingerprint names are the ones reality_fp accepts: chrome, firefox, safari, ios, android, edge,
360, qq. The default is firefox, matching plane-reality.sh.

chrome-quic is the Hysteria2 plane's: the ClientHello hysteria's client sends over QUIC while it
parrots Chrome. table and check take -spec for it, the fork's chrome_client_hello.go, and
  fp speccheck -spec CHROME_CLIENT_HELLO.GO -copy QUIC.GO
holds this tool's copy of that spec to the fork's, token for token.
`)
	os.Exit(2)
}

// fingerprints mirrors PresetFingerprints in Xray so a name from reality_fp means exactly the same
// thing here. The randomised variants are deliberately absent: they have no reference to compare
// against, which is the only thing this tool does.
var fingerprints = map[string]*utls.ClientHelloID{
	"chrome":  &utls.HelloChrome_Auto,
	"firefox": &utls.HelloFirefox_Auto,
	"safari":  &utls.HelloSafari_Auto,
	"ios":     &utls.HelloIOS_Auto,
	"android": &utls.HelloAndroid_11_OkHttp,
	"edge":    &utls.HelloEdge_Auto,
	"360":     &utls.Hello360_Auto,
	"qq":      &utls.HelloQQ_Auto,
}

// buildReference assembles a ClientHello without sending it — the same move REALITY makes in
// transport/internet/reality/reality.go: UClient over a connection, then BuildHandshakeState,
// after which hello.Raw is already populated. The pipe exists only to satisfy the constructor.
func buildReference(name, sni string) ([]byte, error) {
	if name == chromeQUIC {
		raw, _, err := quicReference(sni)
		return raw, err
	}
	id, ok := fingerprints[name]
	if !ok {
		return nil, fmt.Errorf("unknown fingerprint %q; have: %s", name, strings.Join(sortedNames(), ", "))
	}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	u := utls.UClient(c1, &utls.Config{
		ServerName:             sni,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true, // as REALITY sets it
	}, *id)
	if err := u.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("BuildHandshakeState: %w", err)
	}
	raw := u.HandshakeState.Hello.Raw
	if len(raw) == 0 {
		return nil, fmt.Errorf("uTLS produced no raw ClientHello")
	}
	return append([]byte(nil), raw...), nil
}

func sortedNames() []string {
	out := make([]string, 0, len(fingerprints))
	for k := range fingerprints {
		out = append(out, k)
	}
	return out
}

// The placeholder every subcommand offers when the caller names no SNI.
//
// ⚠️ ONE NAME, BECAUSE FOUR FLAGS TOOK IT AND A FIFTH PLACE USED TO SPELL IT DIFFERENTLY. `table`
// read its ECH candidate list off a parrot rendered with "www.avito.ru", written as a literal
// inside table.go while the flags here said "www.kinopoisk.ru" — so what the packer did depended on
// which of the two a reader happened to find.
//
// ⚠️ AND IT IS INERT FOR `table` BUT NOT FOR `dump`, WHICH IS WHY THE DISAGREEMENT NEVER ANNOUNCED
// ITSELF AND WHY THIS PARAGRAPH MUST NOT BE READ AS "the SNI does not matter". Measured, same
// capture, both spellings: `table` gives byte-identical output either way — it stores server_name as
// a MODE and reads the candidate list off the parrot, not off the hello. `dump` does NOT: the same
// profile renders 1882 bytes for www.avito.ru and 1886 for www.kinopoisk.ru, because padding follows
// the length of the name. So a wrong default here is invisible in a packed table and visible in a
// captured hello.
//
// The Makefile passes -sni explicitly on both halves of the capture, so this default decides nothing
// that ships; it decides what a person gets running the tool by hand, and that should be one
// answer. tools/fp/retry.go keeps "fp.example" on purpose: that is the SNI the frozen test vector
// was captured with, not a placeholder — see test/fphello/reference_firefox.h.
const defaultSNI = "www.kinopoisk.ru"

func cmdDump(args []string) {
	fs := flag.NewFlagSet("dump", flag.ExitOnError)
	name := fs.String("fp", "firefox", "fingerprint name")
	sni := fs.String("sni", defaultSNI, "SNI (affects padding length)")
	out := fs.String("o", "", "write raw bytes here; without it, print the breakdown")
	fs.Parse(args)

	raw, err := buildReference(*name, *sni)
	fail(err)
	if *out != "" {
		fail(os.WriteFile(*out, raw, 0o644))
		fmt.Printf("%s: %d bytes -> %s\n", *name, len(raw), *out)
		return
	}
	ch, err := ParseClientHello(raw)
	fail(err)
	printHello(*name, ch)
}

func cmdShow(args []string) {
	if len(args) < 1 {
		usage()
	}
	raw, err := os.ReadFile(args[0])
	fail(err)
	ch, err := ParseClientHello(raw)
	fail(err)
	printHello(args[0], ch)
}

func cmdDiff(args []string) {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	shuffled := fs.Bool("shuffled", false, "fingerprint permutes extensions (Chrome 110+): compare the set, not the order")
	fs.Parse(args)
	if fs.NArg() < 2 {
		usage()
	}
	want, err := readHello(fs.Arg(0))
	fail(err)
	got, err := readHello(fs.Arg(1))
	fail(err)

	if diffs := Compare(want, got, *shuffled); len(diffs) > 0 {
		reportDiffs(fs.Arg(0), fs.Arg(1), diffs)
		os.Exit(1)
	}
	fmt.Printf("match: %s and %s differ only in random, session_id, key_share and GREASE\n", fs.Arg(0), fs.Arg(1))
}

func cmdTable(args []string) {
	fs := flag.NewFlagSet("table", flag.ExitOnError)
	out := fs.String("o", "", "write the table here")
	name := fs.String("name", "", "table name")
	format := fs.String("format", "json", "json for people, bin for the device, c for a table compiled in")
	symbol := fs.String("symbol", "", "for -format c: the name of the array")
	fs.StringVar(&quicSpecSrc, "spec", "", "the fork's chrome_client_hello.go, for "+chromeQUIC)
	// Not the SNI of the capture being packed — that one is already in the bytes. This is the SNI
	// the PARROT is rendered with so its ECH candidate list can be read off the extension object;
	// see echParrot. It does not reach the table, and the caller passes it so that one command
	// line describes the whole capture.
	sni := fs.String("sni", defaultSNI, "SNI for the parrot the ECH candidate list is read from")
	parrots := fs.String("parrots", "", "u_parrots.go of the uTLS module fp is built against, for the base extension order")
	fs.Parse(args)
	if fs.NArg() < 1 || *out == "" {
		usage()
	}
	ch, err := readHello(fs.Arg(0))
	fail(err)
	t, err := TableFrom(ch, *name, fs.Arg(0), *sni, *parrots)
	fail(err)

	switch *format {
	case "json":
		fail(SaveTable(t, *out))
	case "bin":
		fail(SavePacked(t, *out))
	case "c":
		fail(SavePackedC(t, *out, *symbol))
	default:
		fail(fmt.Errorf("unknown format %q: json, bin or c", *format))
	}
	fmt.Printf("table -> %s (%s, %d cipher suites, %d extensions)\n",
		*out, *format, len(t.CipherSuites), len(t.Extensions))
}

func cmdBuild(args []string) {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	sni := fs.String("sni", defaultSNI, "SNI to put into server_name")
	out := fs.String("o", "", "write raw bytes here; without it, print the breakdown")
	fs.Parse(args)
	if fs.NArg() < 1 {
		usage()
	}
	t, err := LoadTable(fs.Arg(0))
	fail(err)
	raw, err := Build(t, *sni)
	fail(err)
	if *out != "" {
		fail(os.WriteFile(*out, raw, 0o644))
		fmt.Printf("%s: %d bytes -> %s\n", t.Name, len(raw), *out)
		return
	}
	ch, err := ParseClientHello(raw)
	fail(err)
	printHello(t.Name, ch)
}

// cmdCheck is the gate the table format has to pass before any of this is ported to C: reference
// in, table out, hello back in, and the two must be indistinguishable to the comparator. A field
// the table forgets shows up here rather than on a router.
func cmdCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	name := fs.String("fp", "firefox", "fingerprint name")
	sni := fs.String("sni", defaultSNI, "SNI")
	shuffled := fs.Bool("shuffled", false, "fingerprint permutes extensions (Chrome 110+)")
	parrots := fs.String("parrots", "", "u_parrots.go of the uTLS module fp is built against, for the base extension order")
	fs.StringVar(&quicSpecSrc, "spec", "", "the fork's chrome_client_hello.go, for "+chromeQUIC)
	fs.Parse(args)

	raw, err := buildReference(*name, *sni)
	fail(err)
	ref, err := ParseClientHello(raw)
	fail(err)

	t, err := TableFrom(ref, *name, "uTLS "+*name, *sni, *parrots)
	fail(err)

	// The rebuild is a comparison target, so it takes the GREASE-ECH length THIS reference drew —
	// TableFrom has already refused a draw that is not one of the parrot's candidates. Left to the
	// table's list, the two would differ in length three times in four for Chrome.
	for _, e := range ref.Extensions {
		if e.Type != extECH {
			continue
		}
		_, _, _, payloadLen, err := echShape(e.Data)
		fail(err)
		for i := range t.Extensions {
			if t.Extensions[i].Mode == ModeECHGrease {
				t.Extensions[i].PayloadLens = []int{payloadLen - echTag}
			}
		}
	}

	rebuiltRaw, err := Build(t, *sni)
	fail(err)
	rebuilt, err := ParseClientHello(rebuiltRaw)
	fail(err)

	fmt.Printf("%s: reference %d bytes, rebuilt %d bytes, %d extensions\n",
		*name, len(ref.Raw), len(rebuilt.Raw), len(t.Extensions))

	if diffs := Compare(ref, rebuilt, *shuffled); len(diffs) > 0 {
		reportDiffs("reference", "rebuilt from table", diffs)
		os.Exit(1)
	}
	fmt.Println("round trip clean: the table carries everything needed to rebuild this fingerprint")
}

func readHello(path string) (*ClientHello, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseClientHello(raw)
}

func reportDiffs(left, right string, diffs []Diff) {
	fmt.Printf("%d difference(s) between %s and %s\n", len(diffs), left, right)
	for _, d := range diffs {
		fmt.Println(d)
	}
}

func printHello(title string, ch *ClientHello) {
	fmt.Printf("%s — %d bytes\n", title, len(ch.Raw))
	fmt.Printf("  legacy_version   %s\n", hex16(ch.LegacyVersion))
	fmt.Printf("  session_id       %d bytes at offset %d\n", len(ch.SessionID), ch.SessionIDOffset)
	fmt.Printf("  cipher suites (%d)\n", len(ch.CipherSuites))
	for _, cs := range ch.CipherSuites {
		fmt.Printf("      %s\n", cipherName(cs))
	}
	fmt.Printf("  extensions (%d), in the order sent\n", len(ch.Extensions))
	for _, e := range ch.Extensions {
		fmt.Printf("      %-38s %4d bytes%s\n", extName(e.Type), len(e.Data), extDetail(e))
	}
}

// extDetail expands the extensions implementations most often disagree about.
func extDetail(e Extension) string {
	switch normGREASE(e.Type) {
	case extSupportedGroups:
		return "  " + joinU16(skip(e.Data, 2), groupName)
	case 0x000d: // signature_algorithms
		return "  " + joinU16(skip(e.Data, 2), sigName)
	case extKeyShare:
		if s, err := keyShareShape(e.Data); err == nil {
			return "  " + s
		}
	case extSupportedVersions:
		return "  " + joinU16(skip(e.Data, 1), hex16)
	case 0x001b: // compress_certificate
		return "  " + joinU16(skip(e.Data, 1), certCompName)
	case 0x0010: // ALPN
		return "  " + alpnDetail(e.Data)
	}
	return ""
}

func skip(b []byte, n int) []byte {
	if len(b) < n {
		return nil
	}
	return b[n:]
}

func joinU16(b []byte, name func(uint16) string) string {
	var parts []string
	for i := 0; i+1 < len(b); i += 2 {
		parts = append(parts, name(uint16(b[i])<<8|uint16(b[i+1])))
	}
	return strings.Join(parts, " ")
}

func alpnDetail(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	var parts []string
	for off := 2; off < len(b); {
		l := int(b[off])
		off++
		if off+l > len(b) {
			break
		}
		parts = append(parts, string(b[off:off+l]))
		off += l
	}
	return strings.Join(parts, " ")
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// echParrot returns the PARROT's GREASE-ECH extension object, so the cipher suite list and the
// payload lengths are read off it rather than off the rendered hello — the whole reason the client
// can stop carrying either as a constant.
//
// A rendered hello shows ONE suite and ONE length: uTLS draws an index over CandidateCipherSuites and
// another over CandidatePayloadLens for every ClientHello (vendor/utls/u_ech.go:99-107, 160-166).
// Reading the drawn values and writing them into the table froze coin flips into a fingerprint. The
// lists live on the extension object, which this tool has in hand because it drives uTLS itself —
// BuildHandshakeState leaves uconn.Extensions populated with the spec's objects.
//
// An empty suite list is refused downstream: uTLS with no candidates generates a suite of its own
// (u_ech.go:95-98), and a client that cannot reproduce that must say so rather than substitute
// something plausible. Nil when the profile carries no GREASE ECH at all.
func echParrot(name, sni string) (*utls.GREASEEncryptedClientHelloExtension, error) {
	if name == chromeQUIC {
		_, spec, err := quicReference(sni)
		if err != nil {
			return nil, err
		}
		for _, ext := range spec.Extensions {
			if g, ok := ext.(*utls.GREASEEncryptedClientHelloExtension); ok {
				return g, nil
			}
		}
		return nil, nil
	}
	id, ok := fingerprints[name]
	if !ok {
		return nil, fmt.Errorf("unknown fingerprint %q", name)
	}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	u := utls.UClient(c1, &utls.Config{
		ServerName:             sni,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
	}, *id)
	if err := u.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("BuildHandshakeState: %w", err)
	}
	for _, ext := range u.Extensions {
		if g, ok := ext.(*utls.GREASEEncryptedClientHelloExtension); ok {
			return g, nil
		}
	}
	return nil, nil
}
