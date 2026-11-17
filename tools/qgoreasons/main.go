// check-qgo-reasons: every reason patches/ngtcp2 gives a CONNECTION_CLOSE through
// ngtcp2_conn_qgo_close must be quic-go's own words — the format string, with C's conversions
// read as Go's, found in vendor/quic-go. A reason typed from memory, or one quic-go has since
// reworded, fails here; the vectors of tools/qgovec hold the ones quic-go's packages can be run
// for, and this holds the rest to the source.
//
//	go run ./tools/qgoreasons              (from the repository root)
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

// Reasons quic-go puts together from more than one place, each with the pieces that must be in
// its source.
var composed = map[string][]string{
	// TransportError.Error: the code's name, "(local)", then the message
	// (vendor/quic-go/internal/qerr/errors.go:33-51), as wrapError passes it on.
	"TRANSPORT_PARAMETER_ERROR (local): %s": {`"%s (%s)"`, `"TRANSPORT_PARAMETER_ERROR"`, `"local"`, `str + ": " + msg`},
	// sendConnectionClose's reason for an error it knows no type of, and StatelessResetError's text.
	"connection BUG: unspecified error type (msg: received a stateless reset)": {
		`"connection BUG: unspecified error type (msg: %s)"`, `"received a stateless reset"`},
	// The encryption level is always 1-RTT there: only its history keeps skipped numbers.
	"received an ACK for skipped packet number: %d (1-RTT)": {
		`"received an ACK for skipped packet number: %d (%s)"`, `"1-RTT"`},
	// The text of io.EOF and io.ErrUnexpectedEOF (GOROOT/src/io/io.go), which quic-go's parsers
	// return — the second turned into the first inside a frame (replaceUnexpectedEOF).
	"EOF":            {`io.EOF`, `func replaceUnexpectedEOF(`},
	"unexpected EOF": {`io.ErrUnexpectedEOF`},
	// ConnectionID.String of a zero-length ID.
	"retired connection ID %d ((empty)), which was used as the Destination Connection ID on this packet": {
		`"retired connection ID %d (%s), which was used as the Destination Connection ID on this packet"`,
		`"(empty)"`},
}

var conv = regexp.MustCompile(`%(#?)(?:ll|z)?([udxs])`)

func goFormat(c string) string {
	return conv.ReplaceAllStringFunc(c, func(m string) string {
		sub := conv.FindStringSubmatch(m)
		switch sub[2] {
		case "s":
			return "%s"
		case "x":
			return "%" + sub[1] + "x"
		default:
			return "%d"
		}
	})
}

func main() {
	patches, _ := filepath.Glob("patches/ngtcp2/*.patch")
	var added strings.Builder
	for _, p := range patches {
		b, err := os.ReadFile(p)
		if err != nil {
			fmt.Println("  FAIL  ", err)
			os.Exit(1)
		}
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "+") && !strings.HasPrefix(l, "+++") {
				added.WriteString(l[1:])
				added.WriteString("\n")
			}
		}
	}
	text := added.String()

	// Each call, from its name to the ")" that closes it, and the string literals in it joined as
	// C joins adjacent ones.
	lit := regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)
	var reasons []string
	for i := 0; ; {
		j := strings.Index(text[i:], "ngtcp2_conn_qgo_close(")
		if j < 0 {
			break
		}
		start := i + j + len("ngtcp2_conn_qgo_close(")
		depth, k := 1, start
		for ; k < len(text) && depth > 0; k++ {
			switch text[k] {
			case '"':
				for k++; k < len(text) && text[k] != '"'; k++ {
					if text[k] == '\\' {
						k++
					}
				}
			case '(':
				depth++
			case ')':
				depth--
			}
		}
		call := text[start:k]
		i = k
		if strings.Contains(call, "const char *fmt") {
			continue // the declaration and the definition
		}
		var s strings.Builder
		for _, m := range lit.FindAllStringSubmatch(call, -1) {
			s.WriteString(m[1])
		}
		reasons = append(reasons, s.String())
	}

	var src strings.Builder
	filepath.Walk("vendor/quic-go", func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
			b, _ := os.ReadFile(p)
			src.Write(b)
		}
		return nil
	})
	code := src.String()

	seen := map[string]bool{}
	bad := 0
	for _, r := range reasons {
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		g := goFormat(r)
		if parts, ok := composed[g]; ok {
			for _, p := range parts {
				if !strings.Contains(code, p) {
					fmt.Printf("  FAIL  %q: vendor/quic-go has no %s\n", r, p)
					bad++
				}
			}
			continue
		}
		if !strings.Contains(code, `"`+g+`"`) && !strings.Contains(code, "`"+g+"`") {
			fmt.Printf("  FAIL  %q is not quic-go's: vendor/quic-go has no %q\n", r, g)
			bad++
		}
	}
	if len(seen) < 30 {
		fmt.Printf("  FAIL  only %d reasons found in patches/ngtcp2 — the extraction broke\n", len(seen))
		os.Exit(1)
	}
	if bad > 0 {
		os.Exit(1)
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Printf("  ok    %d reasons a client closes with, each quic-go's own words (vendor/quic-go)\n", len(keys))

	checkTLS()
}

// The TLS stack's words: every LC_GO("...") in src/ (tls/goerr.h), against the uTLS the Chrome
// parrot runs (vendor/utls-hy), the hysteria client that hands it the pin check (vendor/hysteria),
// the brotli reader it opens a compressed certificate with (vendor/brotli-go), and the Go packages
// uTLS hands on errors from (GOROOT).
func checkTLS() {
	// And the REALITY plane's toolchain, go1.27.1 (vendor/Xray-core is built with it): the words of
	// its x509 parser and verifier, and of crypto/mldsa, which cert/x509go.c, cert/goverify.c,
	// cert/gosig.c and cert/mldsa.c carry. GOROOT_REALITY names another place for it.
	go127 := os.Getenv("GOROOT_REALITY")
	if go127 == "" {
		go127 = "/usr/local/go1.27"
	}
	var src strings.Builder
	for _, root := range []string{"vendor/utls-hy", "vendor/utls", "vendor/hysteria", "vendor/brotli-go",
		filepath.Join(runtime.GOROOT(), "src", "crypto"), filepath.Join(runtime.GOROOT(), "src", "net"),
		filepath.Join(runtime.GOROOT(), "src", "io"),
		filepath.Join(go127, "src", "crypto"), filepath.Join(go127, "src", "net"),
		filepath.Join(go127, "src", "encoding")} {
		filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
			if err == nil && !fi.IsDir() && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
				b, _ := os.ReadFile(p)
				src.Write(b)
			}
			return nil
		})
	}
	code := src.String()
	if !strings.Contains(code, "func checkPublicKeySize(") {
		fmt.Println("  FAIL  GOROOT's crypto/rsa is not where this looks: " + runtime.GOROOT())
		os.Exit(1)
	}
	if !strings.Contains(code, "func NewPublicKey(params Parameters") {
		fmt.Println("  FAIL  go1.27.1's crypto/mldsa is not where this looks: " + go127)
		os.Exit(1)
	}
	if !strings.Contains(code, "func decoderErrorString(") {
		fmt.Println("  FAIL  vendor/brotli-go is missing: fetch it as docs/BUILD.md says")
		os.Exit(1)
	}
	has := func(s string) bool { return strings.Contains(code, `"`+s+`"`) || strings.Contains(code, "`"+s+"`") }

	// How uTLS puts some of its errors together: the prefix it writes before another error's text,
	// with the place it is written; and the error a TLS alert becomes on QUIC — sendAlertLocked's
	// net.OpError (vendor/utls-hy/conn.go:837-840), whose text is Op, ": ", then the alert's
	// (GOROOT/src/net/net.go, OpError.Error; vendor/utls-hy/alert.go, alert.String).
	prefixes := map[string]string{
		"tls: invalid signature by the server certificate: ": `errors.New("tls: invalid signature by the server certificate: " + err.Error())`,
		"tls: failed to parse certificate from server: ":     `"tls: failed to parse certificate from server: " + err.Error()`,
		"tls: failed to decompress certificate message: ":    `"tls: failed to decompress certificate message: %w"`,
		// decodeError.Error (vendor/brotli-go/reader.go:10-12), before a name of decoderErrorString's
		"brotli: ": `return "brotli: " + string(decoderErrorString(int(err)))`,
	}
	localError := []string{`&net.OpError{Op: "local error", Err: err}`, `s += ": " + e.Err.Error()`, `return "tls: " + s`}
	alertText := regexp.MustCompile(`^local error: tls: (.+)$`)

	// The texts Go puts together from a literal and a %q'd value, written here as the one format they
	// amount to, each with the pieces that must be in the source: net/url's EscapeError and
	// InvalidHostError and url.Error (GOROOT/src/net/url/url.go:40, :67-77), and netip's
	// parseAddrError (GOROOT/src/net/netip/netip.go:143-149) — what x509 quotes of a SAN URI it
	// cannot parse (cert/x509go.c) — and x509's own length of an IP SAN.
	composedTLS := map[string][]string{
		// Xray's uTLS wraps crypto/mldsa.Verify with %w; the C caller
		// receives the already-rendered error string, preserving its text.
		"ML-DSA verification failure: %s":          {`"ML-DSA verification failure: %w"`},
		"invalid URL escape %q":                    {`"invalid URL escape " + strconv.Quote(string(e))`},
		"invalid character %q in host name":        {`"invalid character " + strconv.Quote(string(e)) + " in host name"`},
		"parse %q: %s":                             {`fmt.Sprintf("%s %q: %s", e.Op, e.URL, e.Err)`, `&Error{"parse", u, err}`},
		"x509: cannot parse IP address of length ": {`errors.New("x509: cannot parse IP address of length " + strconv.Itoa(len(data)))`},
	}
	parseAddr := []string{`"ParseAddr(" + q(err.in) + "): " + err.msg`, `" (at " + q(err.at) + ")"`}

	var check func(s string) []string
	check = func(s string) []string {
		if has(s) {
			return nil // whole, as one literal: "brotli: excessive input" is one, not the prefix and a name
		}
		if pieces, ok := composedTLS[s]; ok {
			var missing []string
			for _, p := range pieces {
				if !strings.Contains(code, p) {
					missing = append(missing, p)
				}
			}
			return missing
		}
		// A netip message, which parseAddrError puts after ParseAddr(%q): and, where it names the
		// place, before (at %q): what is checked is the message, and that the two pieces are there.
		if strings.HasPrefix(s, "ParseAddr(") {
			var missing []string
			for _, p := range parseAddr {
				if !strings.Contains(code, p) {
					missing = append(missing, p)
				}
			}
			return missing
		}
		for p, where := range prefixes {
			if strings.HasPrefix(s, p) {
				if s[len(p):] == "%s" {
					// the prefix before another error's whole text, which is checked where it is made
					if !strings.Contains(code, where) {
						return []string{where}
					}
					return nil
				}
				missing := check(s[len(p):])
				if !strings.Contains(code, where) {
					missing = append(missing, where)
				}
				return missing
			}
		}
		if m := alertText.FindStringSubmatch(s); m != nil {
			var missing []string
			for _, piece := range localError {
				if !strings.Contains(code, piece) {
					missing = append(missing, piece)
				}
			}
			// alertText's entry, aligned by gofmt: `alertUnexpectedMessage:   "unexpected message",`
			if !regexp.MustCompile(`alert[A-Za-z]+:\s+"` + regexp.QuoteMeta(m[1]) + `",`).MatchString(code) {
				missing = append(missing, "the alert text "+m[1])
			}
			return missing
		}
		if !has(s) {
			return []string{fmt.Sprintf("%q", s)}
		}
		return nil
	}

	lit := regexp.MustCompile(`LC_GO\(((?:"(?:[^"\\]|\\.)*"\s*)+)\)`)
	part := regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)
	found, bad := map[string]bool{}, 0
	filepath.Walk("src", func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || !(strings.HasSuffix(p, ".c") || strings.HasSuffix(p, ".h")) {
			return nil
		}
		b, _ := os.ReadFile(p)
		for _, m := range lit.FindAllStringSubmatch(string(b), -1) {
			var s strings.Builder
			for _, q := range part.FindAllStringSubmatch(m[1], -1) {
				s.WriteString(q[1])
			}
			t := s.String()
			if found[t] {
				continue
			}
			found[t] = true
			if missing := check(t); len(missing) > 0 {
				fmt.Printf("  FAIL  %s: %q is not the reference's words: no %s\n", p, t, strings.Join(missing, ", "))
				bad++
			}
		}
		return nil
	})
	if len(found) < 30 {
		fmt.Printf("  FAIL  only %d LC_GO texts found in src/ — the extraction broke\n", len(found))
		os.Exit(1)
	}
	if bad > 0 {
		os.Exit(1)
	}
	fmt.Printf("  ok    %d texts a TLS failure closes with under the Chrome parrot, each the reference's (vendor/utls-hy, vendor/hysteria, vendor/brotli-go, GOROOT)\n", len(found))
	checkBrotliNames()
}

// A name is not enough for a brotli code: src/tls/certcomp.c keys its texts by the decoder's number,
// and each number has to be the one decoderErrorString gives that name for — the constants and the
// switch of vendor/brotli-go/decode.go:22-50, :2518-2584 — with every error code the decoder has
// among them.
func checkBrotliNames() {
	b, err := os.ReadFile("vendor/brotli-go/decode.go")
	if err != nil {
		fmt.Println("  FAIL  ", err)
		os.Exit(1)
	}
	goSrc := strings.ReplaceAll(string(b), "\r", "")
	value := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^\s*(decoder\w+)\s*=\s*(-?\d+)\s*$`).FindAllStringSubmatch(goSrc, -1) {
		value[m[1]] = m[2]
	}
	byValue := map[string]string{}
	for _, m := range regexp.MustCompile(`case (decoder\w+):\s*return "([A-Z0-9_]+)"`).FindAllStringSubmatch(goSrc, -1) {
		if v, ok := value[m[1]]; ok && strings.HasPrefix(v, "-") {
			byValue[v] = m[2]
		}
	}
	c, err := os.ReadFile("src/tls/certcomp.c")
	if err != nil {
		fmt.Println("  FAIL  ", err)
		os.Exit(1)
	}
	ours := map[string]string{}
	for _, m := range regexp.MustCompile(`\{\s*(-\d+),\s*LC_GO\("tls: failed to decompress certificate message: brotli: ([A-Z0-9_]+)"\)\s*\}`).FindAllStringSubmatch(string(c), -1) {
		ours[m[1]] = m[2]
	}
	bad := 0
	for v, name := range byValue {
		if ours[v] != name {
			fmt.Printf("  FAIL  brotli code %s is %s in vendor/brotli-go, and %q in src/tls/certcomp.c\n", v, name, ours[v])
			bad++
		}
	}
	for v := range ours {
		if _, ok := byValue[v]; !ok {
			fmt.Printf("  FAIL  src/tls/certcomp.c names brotli code %s, which vendor/brotli-go does not have\n", v)
			bad++
		}
	}
	if len(byValue) < 20 || bad > 0 {
		if bad == 0 {
			fmt.Printf("  FAIL  only %d brotli error codes found in vendor/brotli-go — the extraction broke\n", len(byValue))
		}
		os.Exit(1)
	}
	fmt.Printf("  ok    %d brotli error codes, each named as decoderErrorString names it (vendor/brotli-go)\n", len(byValue))
}
