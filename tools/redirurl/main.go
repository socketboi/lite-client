// What the reference's spider makes of a redirect's Location, computed by the reference's own code:
// a real http.Client sends the first request — with the padding cookie, as reality.go:262 sets it —
// to a RoundTripper that answers it with a 302 and the Location, then looks at the request Do makes
// next: its URL — `req.URL.Parse(loc)` (GOROOT/src/net/http/client.go:655-666) — whether the cookie
// survived shouldCopyHeaderOnRedirect (GOROOT/src/net/http/client.go:700-706, :1017-1062), its
// Referer (refererForURL, GOROOT/src/net/http/client.go:149-173) and the Authorization send adds
// for userinfo (GOROOT/src/net/http/client.go:253-258). Then what the HTTP/2 client makes of that
// request: the ClientConn it goes on — authorityAddr, copied because it is unexported, with
// GOROOT's idna.ToASCII in it — a new one with a second preface on the same TLS connection when that
// is not the base's, and EncodeHeaders' checks: httpguts.PunycodeHostPort and ValidHostHeader and
// the :path rule.
//
// Xray v26.9.9 is built with Go 1.27, and under it the HTTP/2 client is net/http's own
// (GOROOT/src/net/http/internal/http2, reached through x/net's transport_wrap.go), whose idna and
// httpguts are the copies Go ships in GOROOT/src/vendor. So this is built with Go 1.27 — go.mod says
// `go 1.27`, which also sets the GODEBUG defaults the reference runs with — and golang.org/x/net and
// golang.org/x/text are those GOROOT copies (tools/.goroot-x, made by the Makefile with $(GO127)).
//
// Four outcomes, four different things on the wire:
//
//	none      the Location does not parse: Do returns an error and nothing more is sent
//	scheme    it resolves to something other than https: the client refuses it before dialling
//	preface   a new connection is dialled — the second preface goes out — and EncodeHeaders then
//	          refuses the request, so no HEADERS follow; on the SAME connection the same refusal
//	          sends nothing, and is marked `request` with no authority
//	request   :authority, :path, the URL's String(), the connection's key, the cookie, the
//	          referer and the authorization
//
//	go run ./tools/redirurl > build/gen/redirurl_vectors.h
package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/idna"
)

// GOROOT/src/net/http/internal/http2/transport.go:385-406 (Go 1.27), verbatim.
func authorityAddr(scheme string, authority string) (addr string) {
	host, port, err := net.SplitHostPort(authority)
	if err != nil { // authority didn't have a port
		host = authority
		port = ""
	}
	if port == "" { // authority's port was empty
		port = "443"
		if scheme == "http" {
			port = "80"
		}
	}
	if a, err := idna.ToASCII(host); err == nil {
		host = a
	}
	// IPv6 address literal, without a port:
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host + ":" + port
	}
	return net.JoinHostPort(host, port)
}

func validPseudoPath(v string) bool {
	return (len(v) > 0 && v[0] == '/') || v == "*"
}

func cstr(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' || c == 92 {
			b.WriteByte(92)
			b.WriteByte(c)
		} else if c < 0x20 || c >= 0x7f || c == '?' {
			fmt.Fprintf(&b, "%c%03o", 92, c)
		} else {
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func cnull(s string, ok bool) string {
	if !ok {
		return "NULL"
	}
	return cstr(s)
}

// The request a redirect answers: the spider's first, built from "https://" + ServerName + a path,
// and a later hop's, which is whatever an earlier Location resolved to.
var bases = []string{
	"https://www.example.com/",
	"https://www.example.com/a/b/c?x=1#top",
	"https://www.example.com:443/p/q",
	"https://sub.www.example.com/deep/",
	"https://www.example.com",
	"https://www.example.com/a%2Fb/c;p?q",
	// A host url.Parse takes and ValidHostHeader refuses. No request of the spider's has one — the
	// first is refused before it is written — but on it a relative Location lands on the same
	// connection and is refused there, which is the one outcome the others never reach.
	"https://a<b>.example/",
	// A first host that is not ASCII — a harvested path glued to the server name makes one — or
	// that idna.Lookup would give back from one: the cookie follows the Lookup forms of the two.
	"https://ww\xc3\xa9.example/", "https://xn--ww-cja.example/", "https://\xd7\x90\xd7\x91.example/",
	// Userinfo on the base: every relative Location inherits it, and the referer loses it.
	"https://u:p@www.example.com/a/b",
	"https://www.example.com@evil.example/x",
	// Paths a relative `..` pops back to an empty segment on.
	"https://www.example.com/b/b/", "https://www.example.com/a//",
}

var locations = []string{
	"/", "", "/a", "a", "./a", "../a", "../../../../a", "a/../b", "/a/./b/../c", "a/", "/a/.", "/a/..",
	".", "..", "./", "../", "/.", "/..", "a/b/..", "//x/../y", "?", "?q=1", "?q=1#f", "#", "#f", "#%zz",
	"/?", "/a?b?c", "/a?b?", "??", "/?#", "/a#b#c", "x?y#z", ";p", "/;p",
	"https://www.example.com/x", "https://www.example.com:443/x", "https://www.example.com:444/x",
	"https://WWW.EXAMPLE.COM/x", "https://www.example.com.", "https://other.example/o",
	"https://sub.www.example.com/u", "https://example.com/p", "https://evilwww.example.com/",
	"https://x.sub.www.example.com/", "https://[::1]/v6", "https://[::1]:8443/v6", "https://127.0.0.1/ip",
	"https://127.0.0.1:443/ip", "https://www.example.com:/empty-port", "https://:443/nohost",
	"https:///nohost", "https:/onlyslash", "https:/..//evil/p", "https:/..///evil/p", "https:/x/../..///y//", "https:/x/..//y", "https:/%2F/z", "https:/a:b//c", "https:noslash", "HTTPS://www.example.com/upper",
	"//www.example.com/s", "//other.example/s", "///x", "////x",
	"http://www.example.com/h", "HTTP://www.example.com/", "ftp://www.example.com/", "mailto:a@b",
	"javascript:alert(1)", "a:b", "a:b/c", "1a:b", "+a:b", ":", ":a", "/:a", "./a:b",
	"/a b", "/a%20b", "/a%2Fb", "/a%2fb", "/a%zz", "/a%", "/%41", "/a+b", "/é", "/a\tb", "/a\x7fb",
	"/a?b c", "/a?%zz", "https://www.example.com/a?b#c d", "https://w w.example.com/", "https://w%41.example.com/",
	"https://w%zz.example.com/", "https://www.example.com%2F/", "https://a{b}.example/", "https://a<b>.example/",
	"https://a_b.example/", "https://a!b.example/", "https://a\"b.example/", "https://[::1%25eth0]/zone",
	"https://www.example.com:99999/big", "https://www.example.com:12a/port", "https://www.example.com::1/x",
	"*", "/*", "?*", "  /lead", "/trail  ", "\\a", "/a\\b",
	// Brackets: netip.ParseAddr in Go, inet_pton here, and the zone and port rules around them.
	"https://[::ffff:1.2.3.4]/", "https://[1.2.3.4]/", "https://[::1%25]/", "https://[fe80::1%25en0]:8443/",
	"https://[::ffff:01.2.3.4]/", "https://[::g]/", "https://[:::1]/", "https://[1::2::3]/",
	"https://[::1]x/", "https://[::1]:/", "https://[::1]:80:/", "https://x[::1]/", "https://[::1/",
	"https://[FE80::A%25en0%2541]/", "https://[::1%25%zz]/", "https://[::1%25a%20b]/",
	// What a path keeps as written and what it has escaped: validEncoded and setPath.
	"/a[b]", "/a%5Bb%5D", "/a'b", "/a!b(c)*", "/a@b:c", "/a\"b", "/a<b>", "/a^b", "/a`b", "/a{b}",
	"/a|b", "/a%41b", "/a%2fb%2F", "/%7e", "/~", "?a b", "#a b", "#a%20b", "#%41", "/a%00b", "#a%00b",
	// Userinfo, which Go refuses — validUserinfo, then its unescape — or keeps: then send adds
	// Authorization, and the next hop's referer does without it.
	"https://a b@www.example.com/", "https://a%zz@www.example.com/", "https://a^b@www.example.com/",
	"https://u@www.example.com/", "https://u:p@other.example/", "https://u:@www.example.com/",
	"https://:p@www.example.com/", "https://@www.example.com/", "https://a:b:c@www.example.com/",
	"https://a%40b:c%3Ad@www.example.com/", "https://a@b@www.example.com/", "https://%00:%0A@www.example.com/",
	"https://u@sub.www.example.com/", "https://u@www.example.com:444/", "//u:p@www.example.com/s",
	"https://www.example.com@www.example.com/", "https://u:p@www.example.com", "https://é@www.example.com/",
	// Hosts that are not ASCII, and ASCII ones idna.ToASCII rewrites: the key and the :authority.
	// Whether the cookie stays for them is idna.Lookup's to say: mapping, NFC, the joiners, bidi.
	"https://wwé.example/", "https://xn--ww-cja.example/", "https://XN--WW-CJA.example/",
	"https://www.xn--abc-.example/", "https://www.xn--.example/", "https://www.xn--ABC.example/",
	"https://\xff.example/", "https://%ff.example/", "https://é:8443/", "https://é:/", "https://[é]/",
	"https://%C3%A9/", "https://www.example.com.xn--zz/", "https://xn---abc.example/",
	"https://xn--ib9b.example/", "https://ww\xc3\xa9.example:8443/", "https://WW\xc3\x89.example/",
	"https://\xef\xbd\x97\xef\xbd\x97\xc3\xa9.example/", "https://wwe\xcc\x81.example/",
	"https://sub.ww\xc3\xa9.example/", "https://sub.xn--ww-cja.example/", "https://a\xe2\x80\x8d.example/",
	"https://\xd7\x90\xd7\x91.example/", "https://\xd7\x901.example/", "https://x.\xd7\x90\xd7\x91.example/",
	"https://ww\xc3\xa9.example\xe3\x80\x82/", "https://ww\xc3\xa9\xc2\xad.example/",
	// `..` back to the root after an empty segment: Go 1.27 starts over there and Go 1.26 did not
	// (resolvePath, GOROOT/src/net/url/url.go:1046-1097, `first = len(dst) == 1`).
	"/x/..//y", "/b/..//", "x/..//y", "/..//a", ".//../y", "/x//..//y", "a/..//", "/x/../..//y//",
	// Userinfo with nothing after it, which String writes with its "//" all the same.
	"https://u@", "https://u:p@", "//u@/x", "//u:p@", "//u@",
}

type script struct {
	loc  string
	seen []*http.Request
}

func (s *script) RoundTrip(r *http.Request) (*http.Response, error) {
	s.seen = append(s.seen, r)
	if len(s.seen) == 1 {
		h := http.Header{}
		h["Location"] = []string{s.loc}
		return &http.Response{StatusCode: 302, Header: h, Body: io.NopCloser(strings.NewReader("")),
			ContentLength: 0, Request: r}, nil
	}
	return nil, errors.New("seen")
}

func main() {
	// Long ones: nothing in this client holds a URL of fixed size any more.
	locations = append(locations, "/"+strings.Repeat("abcdefgh", 700), "https://"+strings.Repeat("h", 4000)+"/x",
		"?"+strings.Repeat("q", 5000), "#"+strings.Repeat("%41", 2000),
		"https://"+strings.Repeat("u", 3000)+":"+strings.Repeat("p", 3000)+"@www.example.com/")

	fmt.Println("/* Generated by tools/redirurl from the reference's own net/http, net/url and x/net. */")
	fmt.Println("enum { REDIR_NONE, REDIR_SCHEME, REDIR_PREFACE, REDIR_REQUEST };")
	fmt.Println("static const struct { const char *base, *location; int outcome; const char *url, *authority, *path, *key, *referer, *authorization; int same, strip; } redirurl[] = {")
	for _, b := range bases {
		for _, loc := range locations {
			if loc == "" {
				continue // no redirect at all: Do returns the answer (GOROOT/src/net/http/client.go:655-660)
			}
			first, err := http.NewRequest("GET", b, nil)
			if err != nil {
				panic(err)
			}
			first.Header["Cookie"] = []string{"padding="}
			s := &script{loc: loc}
			(&http.Client{Transport: s}).Do(first)
			if len(s.seen) < 2 {
				fmt.Printf("    { %s, %s, REDIR_NONE, NULL, NULL, NULL, NULL, NULL, NULL, 0, 0 },\n", cstr(b), cstr(loc))
				continue
			}
			base, r := s.seen[0], s.seen[1]
			if r.URL.Scheme != "https" {
				fmt.Printf("    { %s, %s, REDIR_SCHEME, NULL, NULL, NULL, NULL, NULL, NULL, 0, 0 },\n", cstr(b), cstr(loc))
				continue
			}
			key := authorityAddr(r.URL.Scheme, r.URL.Host)
			same := 0
			if key == authorityAddr(base.URL.Scheme, base.URL.Host) {
				same = 1
			}
			strip := 0
			if _, ok := r.Header["Cookie"]; !ok {
				strip = 1
			}
			ref, hasRef := r.Header["Referer"]
			referer := ""
			if hasRef {
				referer = ref[0]
			}
			auth, hasAuth := r.Header["Authorization"]
			authorization := ""
			if hasAuth {
				authorization = auth[0]
			}
			host := r.Host
			if host == "" {
				host = r.URL.Host
			}
			valid := true
			path := ""
			host, err = httpguts.PunycodeHostPort(host)
			if err != nil || !httpguts.ValidHostHeader(host) {
				valid = false
			} else {
				path = r.URL.RequestURI()
				if !validPseudoPath(path) {
					path = strings.TrimPrefix(path, r.URL.Scheme+"://"+host)
					valid = validPseudoPath(path)
				}
			}
			outcome := "REDIR_REQUEST"
			if !valid && same == 0 {
				outcome = "REDIR_PREFACE"
			}
			fmt.Printf("    { %s, %s, %s, %s, %s, %s, %s, %s, %s, %d, %d },\n", cstr(b), cstr(loc), outcome,
				cstr(r.URL.String()), cnull(host, valid), cnull(path, valid), cstr(key), cnull(referer, hasRef),
				cnull(authorization, hasAuth), same, strip)
		}
	}
	fmt.Println("};")
	chainVectors()
}

// Chains of redirects, each hop's answer the next Location, and whether the cookie went with each
// request: once a hop has left the first request's domain it is left behind for good, whatever the
// later hops come back to (GOROOT/src/net/http/client.go:700-706).
type chain struct {
	locs []string
	seen []*http.Request
}

func (c *chain) RoundTrip(r *http.Request) (*http.Response, error) {
	c.seen = append(c.seen, r)
	if len(c.seen) > len(c.locs) {
		return nil, errors.New("end")
	}
	h := http.Header{}
	h["Location"] = []string{c.locs[len(c.seen)-1]}
	return &http.Response{StatusCode: 302, Header: h, Body: io.NopCloser(strings.NewReader("")),
		ContentLength: 0, Request: r}, nil
}

var chains = [][]string{
	{"https://www.example.com/", "https://other.example/o", "https://sub.www.example.com/s"},
	{"https://www.example.com/", "https://other.example/o", "https://www.example.com/b"},
	{"https://www.example.com/", "https://sub.www.example.com/a", "https://www.example.com/b", "https://x.www.example.com/"},
	{"https://www.example.com/", "https://example.com/", "https://www.example.com/"},
	{"https://ww\xc3\xa9.example/", "https://sub.xn--ww-cja.example/", "https://other.example/", "https://ww\xc3\xa9.example/"},
}

func chainVectors() {
	fmt.Println("static const struct { const char *url[4]; int strip[4]; } redirchain[] = {")
	for _, ch := range chains {
		first, err := http.NewRequest("GET", ch[0], nil)
		if err != nil {
			panic(err)
		}
		first.Header["Cookie"] = []string{"padding="}
		c := &chain{locs: ch[1:]}
		(&http.Client{Transport: c}).Do(first)
		if len(c.seen) != len(ch) {
			panic(ch)
		}
		fmt.Print("    { {")
		for i := 0; i < 4; i++ {
			if i < len(ch) {
				fmt.Printf(" %s,", cstr(ch[i]))
			} else {
				fmt.Print(" NULL,")
			}
		}
		fmt.Print(" }, {")
		for i := 0; i < 4; i++ {
			strip := 0
			if i < len(c.seen) {
				if _, ok := c.seen[i].Header["Cookie"]; !ok {
					strip = 1
				}
			}
			fmt.Printf(" %d,", strip)
		}
		fmt.Println(" } },")
	}
	fmt.Println("};")
}
