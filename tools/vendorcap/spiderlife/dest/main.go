// The site a REALITY node is pretending to be, for the one stand that asks how long the failed
// handshake's connection lives.
//
// It differs from the wireshape stand's target in the two ways that decide that measurement:
// keep-alives stay ON and no idle timeout is set, so this end NEVER closes a connection. Whatever
// close is then seen on the wire is the CLIENT's own decision, which is the whole question.
//
// Its certificate comes from the stand's own authority rather than being self-signed here, because
// BOTH clients verify the real certificate the ordinary way when REALITY does not authenticate the
// node — chain to a root, valid for the name asked for (reality.go:129-139 and, on this side,
// lc_chain_verify) — and a certificate that fails that check ends the handshake with
// bad_certificate before any spider runs. The stand hands both clients its CA through SSL_CERT_FILE.
//
// It serves HTTP/2 over TLS 1.3, because the spider is an http2.Transport (reality.go:210-219), and
// a page with links, because the spider harvests hrefs out of the body to pick its next path
// (reality.go:269-274).
package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"time"
)

const page = `<!doctype html><html><body>
<a href="/one">one</a> <a href="/two">two</a> <a href="/three">three</a>
</body></html>`

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "dest: CERT KEY [ADDR]")
		os.Exit(2)
	}
	addr := "127.0.0.1:18444"
	if len(os.Args) > 3 {
		addr = os.Args[3]
	}

	cert, err := tls.LoadX509KeyPair(os.Args[1], os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "dest: certificate:", err)
		os.Exit(1)
	}

	srv := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Requests are attributed to a client by TIME, not by headers: the stand drives the two
			// clients one after the other, and both send the same anchored Chrome User-Agent — which
			// is itself the point of anchoring it, so the User-Agent is logged but cannot tell them
			// apart.
			ua := r.Header.Get("User-Agent")
			if len(ua) > 44 {
				ua = ua[:44]
			}
			fmt.Fprintf(os.Stderr, "dest: %s %s %s %s ua=%q\n",
				time.Now().Format("15:04:05.000"), r.Proto, r.Method, r.URL.Path, ua)
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, page)
		}),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			NextProtos:   []string{"h2", "http/1.1"},
		},
		// No IdleTimeout, no ReadTimeout: this end never gives up on a connection, so that a close
		// in the trace can only have come from the client.
	}
	srv.SetKeepAlivesEnabled(true)
	panic(srv.ListenAndServeTLS("", ""))
}
