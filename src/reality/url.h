/* Go's net/url, as far as a spider following redirects needs it: Parse, ResolveReference,
 * EscapedPath, RequestURI, String, Hostname and the userinfo — transcribed from
 * GOROOT/src/net/url/url.go (go1.27.1, the toolchain the reference is built with) and held to the
 * real ones by tools/redirurl and tools/spiderurl.
 *
 * WHY A URL MODEL AT ALL: the spider's first request is `http.NewRequest("GET", "https://" +
 * ServerName + path, nil)` with a harvested path glued on (reality.go:220-241), and a redirect's
 * Location can be anything a site writes: absolute, scheme-relative, relative with dot segments,
 * opaque, another host, a userinfo. http.Client resolves it with `req.URL.Parse(loc)`
 * (GOROOT/src/net/http/client.go:655-666), which is Parse and ResolveReference in full.
 *
 * NO LIMITS BUT MEMORY. Every component is a heap string of its own length and may hold any byte —
 * a path or a password unescaped from "%00" holds a NUL — so each is a pointer AND a length. The
 * pointer is NUL-terminated as well, for what only ever holds text, and NULL for an empty one. */
#ifndef LC_URL_H
#define LC_URL_H

#include "core/gotext.h"

#include <stddef.h>

typedef struct {
    char  *p; /* NULL when empty; else n bytes and a NUL after them */
    size_t n;
} lc_str;

typedef struct {
    lc_str scheme, opaque, host, path, raw_path, raw_query, fragment, raw_fragment;
    int    user;         /* User != nil */
    lc_str username;     /* unescaped */
    lc_str password;     /* unescaped */
    int    password_set; /* UserPassword rather than User */
    int    force_query, omit_host;
} lc_url;

/* What these return: 0; LC_URL_ERR where Go returns an error; LC_URL_NOMEM when memory ran out,
 * which Go has no counterpart for and the caller treats as its own failure. */
enum { LC_URL_ERR = -1, LC_URL_NOMEM = -2 };

void lc_str_free(lc_str *s);
void lc_url_free(lc_url *u);

/* url.Parse of `n` bytes. `u` is freed first, so it holds a URL or zeros. */
int lc_url_parse(const char *s, size_t n, lc_url *u);

/* The same, and on LC_URL_ERR the error's text appended to `why`, as url.Error prints it:
 * `parse "…": ` and the cause, in Go's words — what x509 quotes of a SAN URI it cannot parse. */
int lc_url_parse_why(const char *s, size_t n, lc_url *u, lc_obuf *why);

/* A deep copy: `dst` is freed first. */
int lc_url_copy(lc_url *dst, const lc_url *src);

/* u.ResolveReference(ref), into `out`, which is freed first and may be neither of the others. */
int lc_url_resolve(const lc_url *u, const lc_url *ref, lc_url *out);

/* u.EscapedPath(), u.RequestURI(), u.String() and u.User.String() into `*out`, which is the
 * caller's to free — freed first, so it holds a string or zeros. */
int lc_url_escaped_path(const lc_url *u, lc_str *out);
int lc_url_request_uri(const lc_url *u, lc_str *out);
int lc_url_string(const lc_url *u, lc_str *out);
int lc_url_userinfo_string(const lc_url *u, lc_str *out);

/* Hostname() of a Host of `n` bytes: where it starts in `host` and how long it is — without its
 * port and brackets (splitHostPort, GOROOT/src/net/url/url.go). */
void lc_url_hostname(const char *host, size_t n, size_t *off, size_t *len);

/* Port() of the same: where the digits after the last colon start and how many there are — none
 * when that colon does not make a valid optional port (GOROOT/src/net/url/url.go:1201-1222). */
void lc_url_port(const char *host, size_t n, size_t *off, size_t *len);

#endif
