// What the reference's spider puts on the wire for a harvested path, computed by the reference's
// own code: `http.NewRequest("GET", "https://" + ServerName + path, nil)`
// (vendor/Xray-core/transport/internet/reality/reality.go:231-241), sent by a real http.Client —
// whose send adds an Authorization header for a URL with userinfo
// (GOROOT/src/net/http/client.go:253-258) — to a RoundTripper that only looks at what it was
// given; then what the HTTP/2 client makes of that request: the ClientConn's key, authorityAddr
// (copied because it is unexported, with GOROOT's idna.ToASCII in it), and the checks EncodeHeaders
// makes before it writes HEADERS — httpguts.PunycodeHostPort and ValidHostHeader, and the :path
// rule.
//
// Xray v26.9.9 is built with Go 1.27, where that client is net/http's own
// (GOROOT/src/net/http/internal/http2) and its idna and httpguts are the copies Go ships in
// GOROOT/src/vendor. So this runs with Go 1.27 against those copies (tools/.goroot-x, made by the
// Makefile with $(GO127)) — see tools/redirurl.
//
// Three outcomes, which are three different things on the wire:
//
//	request   :authority, :path and Authorization as the client writes them
//	preface   the connection's opening goes out (it is dialled before the headers are encoded) and
//	          no HEADERS follow — EncodeHeaders refused the request
//	none      NewRequest failed: the reference returns before dialling anything
package main

import (
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
			fmt.Fprintf(&b, "%c%03o", 92, c) // '?' too, so that no trigraph can form
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

const serverName = "www.example.com"

// Every one of these is something the harvest can store: it matched `href="([/h].*?)"`, lost the
// prefix `https://<ServerName>` if it had it, and carries no dot. The first character after a
// trimmed prefix can be anything, which is where most of the odd ones come from.
var inputs = []string{
	"/", "", "/shop", "/deep/page", "//double", "///triple",
	"/a b", "/a\tb", "/a\rb", "/a\x7fb", "/\xd0\xbf\xd1\x80\xd0\xb8", "/a\x00b",
	"/a%20b", "/a%2Fb", "/a%2fb", "/a%41", "/a%41 b", "/a%2F b", "/a%", "/%", "/100%", "/a%zz",
	"/a%4", "/a!b", "/a'b", "/a(b)", "/a*b", "/a[b]", "/a{b}", "/a|b", "/a^b", "/a`b",
	"/a" + string(rune(92)) + "b", "/a<b>", "/a;b=c,d", "/a:b@c", "/~user", "/a+b", "/a$b&c",
	"/a%00b", "/a%0Ab", "/a%FFb", "/\xff\xfe",
	"/a?b=1", "/a?b c", "/a?", "/a??", "/?", "/a?#", "?x=1", "?", "?#", "/a?\xc3\xa9",
	"#top", "/a#b", "/a#%zz", "/a#%41", "/a#b c", "/a#\x01",
	":443/x", ":443", ":", ":/x", ":abc/x", ":443:1/x", ":0443/x",
	"help", "help/contact", "hello?x", "h", "home#frag", "http:x", "http://localhost/x",
	"hx:80/p", "hx:/p", "h[x", "[x", "h]x", "h<x", "h>x", "h x", "h{x", "h|x", "h" + string(rune(92)) + "x",
	"h%41x", "h%25x", "h%zz", "h%4", "h%", "h!$&'()*+,;=x", "h~_-x", "h\tx",
	// Userinfo: the server name becomes the user, what follows the '@' the host — and send adds
	// Authorization for it.
	"h@x", "@evil/x", "@evil", "@", "@/x", ":pw@evil/x", ":@evil/", "x:y:z@evil/", "%41@evil/",
	"%zz@evil/", "a b@evil/", "a^b@evil/", "\xc3\xa9@evil/", "@evil:8443/x", "@evil:/x", "@[::1]/x",
	"@[::1]:8443/x", "@evil@other/x", "%40@evil/", "%00@evil/", "@\xc3\xa9vil/x", "@xn--vil-bpa/x",
	// A host that is not ASCII: x/net runs it through idna.ToASCII for the key and the :authority.
	"h%C3%A9", "h\xc3\xa9", "\xc3\xa9/x", "\xc3\xa9:443/x", "\xc3\xa9:/x", "\xff/x", "%ff/x",
	"\xc3\xa9.xn--vil-bpa/x", ".xn--/x", ".xn--abc-/x", ".xn--ABC/x", ".xn--a-ecp.ru/x",
	".\xd0\xbf\xd1\x80\xd0\xb8\xd0\xbc\xd0\xb5\xd1\x80.\xd1\x80\xd1\x84/x", "\xed\xa0\x80/x",
	"\xf0\x9f\x98\x80/x", "\xe2\x80\x8d/x", ".xn--zzzzzzzzzzzzzzzzzzzzzzzz/x", ".xn--99999999999999/x",
	"\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9.x\xc3\xa9x/y", ".xn---abc/x", ".xn--ib9b/x", "\xe0\x80\x80/x",
	"\xf0\x80\x80\x80/x", "\xf4\x90\x80\x80/x", "\xc3/x", "@[::1]:/x", "@[::1]:",
}

type capture struct{ req *http.Request }

func (c *capture) RoundTrip(r *http.Request) (*http.Response, error) {
	c.req = r
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
}

func main() {
	// Long ones: nothing in this client holds a URL of fixed size any more.
	long := "/" + strings.Repeat("abcdefgh", 700)
	inputs = append(inputs, long, long+"?"+strings.Repeat("q", 3000), strings.Repeat("h", 5000)+"/x",
		"/"+strings.Repeat("%41", 2000), "/"+strings.Repeat("\xc3\xa9", 2000))

	fmt.Println("/* Generated by tools/spiderurl from the reference's own net/http, net/url and x/net. */")
	fmt.Printf("static const char *const spiderurl_host = %s;\n", cstr(serverName))
	fmt.Println("static const struct { const char *stored; size_t stored_len; int outcome; const char *authority, *path, *key, *authorization; } spiderurl[] = {")
	for _, s := range inputs {
		req, err := http.NewRequest("GET", "https://"+serverName+s, nil)
		if err != nil {
			fmt.Printf("    { %s, %d, LC_SPIDER_NONE, NULL, NULL, NULL, NULL },\n", cstr(s), len(s))
			continue
		}
		c := &capture{}
		if _, err := (&http.Client{Transport: c}).Do(req); err != nil || c.req == nil {
			panic(fmt.Sprintf("%q: %v", s, err))
		}
		r := c.req
		key := authorityAddr(r.URL.Scheme, r.URL.Host)
		auth, hasAuth := r.Header["Authorization"]
		authorization := ""
		if hasAuth {
			authorization = auth[0]
		}
		host := r.Host
		if host == "" {
			host = r.URL.Host
		}
		outcome := "LC_SPIDER_REQUEST"
		path := ""
		host, err = httpguts.PunycodeHostPort(host)
		if err != nil || !httpguts.ValidHostHeader(host) {
			outcome = "LC_SPIDER_PREFACE"
		} else {
			path = r.URL.RequestURI()
			if !validPseudoPath(path) {
				path = strings.TrimPrefix(path, r.URL.Scheme+"://"+host)
				if !validPseudoPath(path) {
					outcome = "LC_SPIDER_PREFACE"
				}
			}
		}
		ok := outcome == "LC_SPIDER_REQUEST"
		fmt.Printf("    { %s, %d, %s, %s, %s, %s, %s },\n", cstr(s), len(s), outcome, cnull(host, ok),
			cnull(path, ok), cstr(key), cnull(authorization, hasAuth))
	}
	fmt.Println("};")
}
