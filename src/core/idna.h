/* golang.org/x/net/idna, as far as the spider's hosts go through it — the copy Go 1.27 ships in
 * GOROOT/src/vendor, which is what Xray v26.9.9 is built with.
 *
 * Under Go 1.27 every call the spider makes lands in that copy. The HTTP/2 client is net/http's own
 * there, so authorityAddr and the :authority it writes go through GOROOT's idna.ToASCII
 * (GOROOT/src/net/http/internal/http2/transport.go:397,
 * GOROOT/src/net/http/internal/httpcommon/httpcommon.go:231), and so does the redirect rule for
 * the cookie, through httpguts.PunycodeHostPort (GOROOT/src/net/http/client.go:1031-1032). Its
 * idna.Lookup is reached from one place, the address net/http dials
 * (GOROOT/src/net/http/request.go:804, GOROOT/src/net/http/transport.go:3187-3201) — and
 * keys its idle list on (reality/fetch.c, get_client_conn). The idna of the x/net module the
 * reference requires is not on the path at all: its http2.Transport hands every request to net/http
 * (vendor/x-net/http2/transport_wrap.go:210-243).
 *
 * Go 1.27 has Unicode 17.0.0, which turns the copy's `unicode16` on
 * (GOROOT/src/vendor/golang.org/x/net/idna/idna.go:29): Unicode 16's revision of UTS #46, where a
 * disallowed rune is no longer refused while mapping but in each label once decoded, a U+FFFD — or
 * an invalid byte, which ranges as one — cannot be encoded, and the tables are 17's
 * (tools/unitables, run with Go 1.27). Until 2026-09-26 this was Go 1.26's: Unicode 15 and the older
 * algorithm. */
#ifndef LC_IDNA_H
#define LC_IDNA_H

#include <stddef.h>

/* idna.ToASCII — the Punycode profile — of `n` bytes, any bytes. 0 with a string of its own in
 * `*out` (NUL-terminated, `*on` long) for the caller to free; -1 where Go returns an error, which is
 * when the callers keep the name they had (authorityAddr) or fail the request (PunycodeHostPort);
 * -2 without memory. */
int lc_idna_to_ascii(const char *s, size_t n, char **out, size_t *on);

/* idna.Lookup.ToASCII: UTS #46 mapping, NFC, the label checks, the Bidi Rule, then the same
 * Punycode. Returns as above. */
int lc_idna_lookup(const char *s, size_t n, char **out, size_t *on);

#endif
