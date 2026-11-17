#include "reality/url.h"

#include "core/goquote.h"
#include "core/netip.h"
#include "tls/goerr.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* The encodings of GOROOT/src/net/url/url.go that a URL's parts are read and written in. */
enum { ENC_PATH, ENC_HOST, ENC_ZONE, ENC_USERPASS, ENC_FRAGMENT };

/* ---- strings --------------------------------------------------------------------------------- */

void lc_str_free(lc_str *s)
{
    free(s->p);
    s->p = NULL;
    s->n = 0;
}

/* `n` bytes into a string of their own. */
static int str_set(lc_str *s, const char *p, size_t n)
{
    lc_str_free(s);
    if (n == 0u)
        return 0;
    s->p = malloc(n + 1u);
    if (s->p == NULL)
        return LC_URL_NOMEM;
    memcpy(s->p, p, n);
    s->p[n] = '\0';
    s->n = n;
    return 0;
}

static int str_eq(const lc_str *s, const char *p, size_t n)
{
    return s->n == n && (n == 0u || memcmp(s->p, p, n) == 0);
}

/* A strings.Builder: appends that remember running out of memory, and one check at the end. */
typedef struct {
    char  *p;
    size_t n, cap;
    int    oom;
} buf;

static void b_add(buf *b, const char *s, size_t n)
{
    if (b->oom || n == 0u)
        return;
    if (b->n + n + 1u > b->cap) {
        size_t cap = b->cap != 0u ? b->cap : 64u;
        while (cap < b->n + n + 1u)
            cap *= 2u;
        char *p = realloc(b->p, cap);
        if (p == NULL) {
            b->oom = 1;
            return;
        }
        b->p = p;
        b->cap = cap;
    }
    memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = '\0';
}

static void b_byte(buf *b, char c)
{
    b_add(b, &c, 1u);
}

/* The builder's string into `out`: an empty one is NULL, as every empty lc_str is. */
static int b_done(buf *b, lc_str *out)
{
    lc_str_free(out);
    if (b->oom) {
        free(b->p);
        return LC_URL_NOMEM;
    }
    if (b->n == 0u) {
        free(b->p);
        return 0;
    }
    out->p = b->p;
    out->n = b->n;
    return 0;
}

/* ---- what Go says ---------------------------------------------------------------------------- */

/* The text of the error Go returns, appended to `why` when there is one. The Go format is kept as
 * it is written — LC_GO, so that check-qgo-reasons holds it to net/url — and its one verb takes
 * `n` bytes of `s`: %q quoted as strconv.Quote quotes, %s and %w as they are. Always LC_URL_ERR,
 * so that a refusal is one line. */
static int say_n(lc_obuf *why, const char *gofmt, const char *s, size_t n)
{
    if (why == NULL)
        return LC_URL_ERR;
    for (const char *f = gofmt; *f != '\0'; f++) {
        if (f[0] == '%' && (f[1] == 'q' || f[1] == 's' || f[1] == 'w')) {
            if (f[1] == 'q')
                lc_go_quote(why, (const uint8_t *)s, n);
            else
                lc_obuf_add(why, s, n);
            f++;
        } else {
            lc_obuf_byte(why, (uint8_t)*f);
        }
    }
    return LC_URL_ERR;
}

static int say(lc_obuf *why, const char *msg)
{
    return say_n(why, msg, NULL, 0);
}

/* ---- escaping -------------------------------------------------------------------------------- */

static int alnum(uint8_t c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

/* A byte of `set` — never the NUL a strchr would find at its end. */
static int in_set(uint8_t c, const char *set)
{
    return c != 0u && strchr(set, c) != NULL;
}

/* shouldEscape (GOROOT/src/net/url/gen_encoding_table.go:153-228, which generates the table
 * GOROOT/src/net/url/url.go:81-83 looks up). */
static int should_escape(uint8_t c, int mode)
{
    if (alnum(c))
        return 0;
    if ((mode == ENC_HOST || mode == ENC_ZONE) && in_set(c, "!$&'()*+,;=:[]<>\""))
        return 0;
    if (in_set(c, "-_.~"))
        return 0;
    if (in_set(c, "$&+,/:;=?@")) {
        if (mode == ENC_PATH)
            return c == '?';
        if (mode == ENC_USERPASS)
            return c == '@' || c == '/' || c == '?' || c == ':';
        if (mode == ENC_FRAGMENT)
            return 0;
    }
    if (mode == ENC_FRAGMENT && in_set(c, "!()*"))
        return 0;
    return 1;
}

static int ishex(uint8_t c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static uint8_t unhex(uint8_t c)
{
    return (uint8_t)(9u * (c >> 6) + (c & 15u));
}

/* unescape (GOROOT/src/net/url/url.go:107-183), for the encodings that have no '+' rule: the checks
 * over the whole string first, then the decoding. A refusal is EscapeError — "invalid URL escape"
 * and the escape, at most three bytes of it — or, for a byte a host may not hold, InvalidHostError
 * (:67-77). */
static int unescape(const char *s, size_t n, int mode, lc_str *out, lc_obuf *why)
{
    for (size_t i = 0; i < n;) {
        uint8_t c = (uint8_t)s[i];
        if (c == '%') {
            if (i + 2u >= n || !ishex((uint8_t)s[i + 1]) || !ishex((uint8_t)s[i + 2]))
                return say_n(why, LC_GO("invalid URL escape %q"), s + i, n - i > 3u ? 3u : n - i);
            int pct25 = s[i + 1] == '2' && s[i + 2] == '5';
            if (mode == ENC_HOST && unhex((uint8_t)s[i + 1]) < 8u && !pct25)
                return say_n(why, LC_GO("invalid URL escape %q"), s + i, 3u);
            if (mode == ENC_ZONE) {
                uint8_t v = (uint8_t)(unhex((uint8_t)s[i + 1]) << 4 | unhex((uint8_t)s[i + 2]));
                if (!pct25 && v != ' ' && should_escape(v, ENC_HOST))
                    return say_n(why, LC_GO("invalid URL escape %q"), s + i, 3u);
            }
            i += 3u;
            continue;
        }
        if ((mode == ENC_HOST || mode == ENC_ZONE) && c < 0x80u && should_escape(c, mode))
            return say_n(why, LC_GO("invalid character %q in host name"), s + i, 1u);
        i++;
    }
    buf b = { 0 };
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '%') {
            b_byte(&b, (char)(unhex((uint8_t)s[i + 1]) << 4 | unhex((uint8_t)s[i + 2])));
            i += 2u;
        } else {
            b_byte(&b, s[i]);
        }
    }
    return b_done(&b, out);
}

/* escape (GOROOT/src/net/url/url.go:197-250), for the encodings where a space is %20, appended. */
static void escape(buf *b, const char *s, size_t n, int mode)
{
    static const char hex[] = "0123456789ABCDEF";
    for (size_t i = 0; i < n; i++) {
        uint8_t c = (uint8_t)s[i];
        if (should_escape(c, mode)) {
            char e[3] = { '%', hex[c >> 4], hex[c & 15u] };
            b_add(b, e, 3u);
        } else {
            b_byte(b, (char)c);
        }
    }
}

/* validEncoded (GOROOT/src/net/url/url.go:704-725). */
static int valid_encoded(const lc_str *s, int mode)
{
    for (size_t i = 0; i < s->n; i++) {
        uint8_t c = (uint8_t)s->p[i];
        if (in_set(c, "!$&'()*+,;=:@[]%"))
            continue;
        if (should_escape(c, mode))
            return 0;
    }
    return 1;
}

/* validOptionalPort (GOROOT/src/net/url/url.go:763-776). */
static int valid_optional_port(const char *p, size_t n)
{
    if (n == 0u)
        return 1;
    if (p[0] != ':')
        return 0;
    for (size_t i = 1; i < n; i++)
        if (p[i] < '0' || p[i] > '9')
            return 0;
    return 1;
}

/* setPath and setFragment (GOROOT/src/net/url/url.go:661-674, :728-741): the part unescaped, and
 * the raw form kept only when escaping the unescaped one would not give it back. On Go's error
 * neither field is touched. */
static int set_raw(lc_str *dec, lc_str *raw, const char *p, size_t n, int mode, lc_obuf *why)
{
    lc_str d = { 0 };
    int    rc = unescape(p, n, mode, &d, why);
    if (rc != 0)
        return rc;
    buf e = { 0 };
    escape(&e, d.p, d.n, mode);
    if (e.oom) {
        free(e.p);
        lc_str_free(&d);
        return LC_URL_NOMEM;
    }
    int same = e.n == n && (n == 0u || memcmp(e.p, p, n) == 0);
    free(e.p);
    rc = same ? (lc_str_free(raw), 0) : str_set(raw, p, n);
    if (rc != 0) {
        lc_str_free(&d);
        return rc;
    }
    lc_str_free(dec);
    *dec = d;
    return 0;
}

static int set_path(lc_url *u, const char *p, size_t n, lc_obuf *why)
{
    return set_raw(&u->path, &u->raw_path, p, n, ENC_PATH, why);
}

static int set_fragment(lc_url *u, const char *f, size_t n, lc_obuf *why)
{
    return set_raw(&u->fragment, &u->raw_fragment, f, n, ENC_FRAGMENT, why);
}

/* EscapedPath and EscapedFragment (GOROOT/src/net/url/url.go:688-699, :751-759), appended. */
static int escaped(buf *b, const lc_str *dec, const lc_str *raw, int mode)
{
    if (raw->n != 0u && valid_encoded(raw, mode)) {
        lc_str d = { 0 };
        int    rc = unescape(raw->p, raw->n, mode, &d, NULL);
        if (rc == LC_URL_NOMEM)
            return rc;
        int same = rc == 0 && d.n == dec->n && (d.n == 0u || memcmp(d.p, dec->p, d.n) == 0);
        lc_str_free(&d);
        if (same) {
            b_add(b, raw->p, raw->n);
            return 0;
        }
    }
    if (mode == ENC_PATH && str_eq(dec, "*", 1u)) {
        b_byte(b, '*');
        return 0;
    }
    escape(b, dec->p, dec->n, mode);
    return 0;
}

/* ---- Parse ----------------------------------------------------------------------------------- */

static const char *last_index(const char *s, size_t n, char c)
{
    for (size_t i = n; i-- > 0;)
        if (s[i] == c)
            return s + i;
    return NULL;
}

static const char *index_of(const char *s, size_t n, const char *needle, size_t nn)
{
    for (size_t i = 0; i + nn <= n; i++)
        if (memcmp(s + i, needle, nn) == 0)
            return s + i;
    return NULL;
}

/* parseHost (GOROOT/src/net/url/url.go:550-641), in its words. The address inside brackets is
 * netip.ParseAddr's (core/netip.c): IPv6, a zone after the first '%' not empty, and not IPv4 —
 * "invalid IP-literal" (:604-606). A host holds no NUL: a raw one fails the control-byte check,
 * and "%00" fails unescape in both host modes. */
static int parse_host(const lc_url *u, const char *h, size_t n, lc_str *out, lc_obuf *why)
{
    const char *open = last_index(h, n, '[');
    if (open != NULL && open != h)
        return say(why, LC_GO("invalid IP-literal"));
    if (open == h) {
        const char *close = last_index(h, n, ']');
        if (close == NULL)
            return say(why, LC_GO("missing ']' in host"));
        const char *cp = close + 1;
        size_t      cpn = n - (size_t)(cp - h);
        if (!valid_optional_port(cp, cpn))
            return say_n(why, LC_GO("invalid port %q after host"), cp, cpn);
        lc_str port = { 0 }, part = { 0 }, zone = { 0 };
        int    rc = unescape(cp, cpn, ENC_HOST, &port, why);
        const char *name = h + 1;
        size_t      nn = (size_t)(close - name);
        const char *z = index_of(name, nn, "%25", 3u);
        if (rc == 0 && z != NULL) {
            rc = unescape(name, (size_t)(z - name), ENC_HOST, &part, why);
            if (rc == 0)
                rc = unescape(z, nn - (size_t)(z - name), ENC_ZONE, &zone, why);
        } else if (rc == 0) {
            rc = unescape(name, nn, ENC_HOST, &part, why);
        }
        buf b = { 0 };
        b_byte(&b, '[');
        b_add(&b, part.p, part.n);
        b_add(&b, zone.p, zone.n);
        size_t addr_end = b.n;
        b_byte(&b, ']');
        b_add(&b, port.p, port.n);
        lc_str_free(&port);
        lc_str_free(&part);
        lc_str_free(&zone);
        if (rc == 0 && b.oom)
            rc = LC_URL_NOMEM;
        if (rc == 0) {
            /* fmt.Errorf("invalid host: %w", err) around ParseAddr's own words, and an IPv4 address
             * in brackets refused after it. */
            lc_netip addr;
            lc_obuf  e = { 0 };
            if (lc_netip_parse(b.p + 1, addr_end - 1u, &addr, why != NULL ? &e : NULL) != 0)
                rc = say_n(why, LC_GO("invalid host: %w"), e.p, e.n);
            else if (addr.is4)
                rc = say(why, LC_GO("invalid IP-literal"));
            free(e.p);
        }
        if (rc != 0) {
            free(b.p);
            return rc;
        }
        return b_done(&b, out);
    }
    const char *colon = memchr(h, ':', n);
    if (colon != NULL) {
        const char *last = last_index(h, n, ':');
        /* urlstrictcolons, on by default: for http and https the FIRST colon starts the port. */
        if (last != colon && !str_eq(&u->scheme, "http", 4u) && !str_eq(&u->scheme, "https", 5u))
            colon = last;
        if (!valid_optional_port(colon, n - (size_t)(colon - h)))
            return say_n(why, LC_GO("invalid port %q after host"), colon, n - (size_t)(colon - h));
    }
    return unescape(h, n, ENC_HOST, out, why);
}

/* validUserinfo (GOROOT/src/net/url/url.go:1273-1304), over bytes: a byte outside ASCII is part of
 * a rune that is not in its list either, and so is a byte that is not UTF-8 at all. */
static int valid_userinfo(const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        uint8_t c = (uint8_t)s[i];
        if (!alnum(c) && !in_set(c, "-._:~!$&'()*+,;=%@"))
            return 0;
    }
    return 1;
}

/* parseAuthority (GOROOT/src/net/url/url.go:513-546): the host after the LAST '@', the userinfo
 * before it split at its FIRST ':'. */
static int parse_authority(lc_url *u, const char *a, size_t n, lc_obuf *why)
{
    const char *at = last_index(a, n, '@');
    const char *hp = at != NULL ? at + 1 : a;
    int         rc = parse_host(u, hp, n - (size_t)(hp - a), &u->host, why);
    if (rc != 0 || at == NULL)
        return rc;
    size_t ui = (size_t)(at - a);
    if (!valid_userinfo(a, ui))
        return say(why, LC_GO("net/url: invalid userinfo"));
    const char *colon = memchr(a, ':', ui);
    if (colon == NULL) {
        rc = unescape(a, ui, ENC_USERPASS, &u->username, why);
    } else {
        rc = unescape(a, (size_t)(colon - a), ENC_USERPASS, &u->username, why);
        if (rc == 0)
            rc = unescape(colon + 1, ui - (size_t)(colon + 1 - a), ENC_USERPASS, &u->password,
                          why);
        u->password_set = 1;
    }
    u->user = 1;
    return rc;
}

/* getScheme (GOROOT/src/net/url/url.go:370-392): 0 with the scheme's length in *n (0 for none), or
 * the error. */
static int get_scheme(const char *s, size_t len, size_t *n, lc_obuf *why)
{
    *n = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = (uint8_t)s[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
            continue;
        if ((c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.') {
            if (i == 0)
                return 0;
            continue;
        }
        if (c == ':') {
            if (i == 0)
                return say(why, LC_GO("missing protocol scheme"));
            *n = i;
            return 0;
        }
        return 0;
    }
    return 0;
}

/* parse(rawURL, viaRequest=false) (GOROOT/src/net/url/url.go:433-511). */
static int parse(const char *raw, size_t len, lc_url *u, lc_obuf *why)
{
    for (size_t i = 0; i < len; i++)
        if ((uint8_t)raw[i] < 0x20u || (uint8_t)raw[i] == 0x7fu)
            return say(why, LC_GO("net/url: invalid control character in URL"));
    if (len == 1u && raw[0] == '*')
        return str_set(&u->path, "*", 1u);
    size_t sn = 0;
    int    rc = get_scheme(raw, len, &sn, why);
    if (rc != 0)
        return rc;
    if ((rc = str_set(&u->scheme, raw, sn)) != 0)
        return rc;
    for (size_t i = 0; i < sn; i++)
        if (u->scheme.p[i] >= 'A' && u->scheme.p[i] <= 'Z')
            u->scheme.p[i] = (char)(u->scheme.p[i] - 'A' + 'a');
    const char *rest = sn != 0u ? raw + sn + 1u : raw;
    size_t      rn = len - (size_t)(rest - raw);

    size_t qn = 0;
    for (size_t i = 0; i < rn; i++)
        qn += rest[i] == '?';
    if (rn > 0u && rest[rn - 1u] == '?' && qn == 1u) {
        u->force_query = 1;
        rn--;
    } else {
        const char *q = memchr(rest, '?', rn);
        if (q != NULL) {
            if ((rc = str_set(&u->raw_query, q + 1, rn - (size_t)(q + 1 - rest))) != 0)
                return rc;
            rn = (size_t)(q - rest);
        }
    }

    if (rn == 0u || rest[0] != '/') {
        if (u->scheme.n != 0u)
            return str_set(&u->opaque, rest, rn);
        const char *slash = memchr(rest, '/', rn);
        size_t      seg = slash != NULL ? (size_t)(slash - rest) : rn;
        if (memchr(rest, ':', seg) != NULL)
            return say(why, LC_GO("first path segment in URL cannot contain colon"));
    }

    int triple = rn >= 3u && memcmp(rest, "///", 3) == 0;
    if ((u->scheme.n != 0u || !triple) && rn >= 2u && rest[0] == '/' && rest[1] == '/') {
        const char *a = rest + 2;
        size_t      an = rn - 2u;
        const char *slash = memchr(a, '/', an);
        size_t      auth = slash != NULL ? (size_t)(slash - a) : an;
        if ((rc = parse_authority(u, a, auth, why)) != 0)
            return rc;
        rest = a + auth;
        rn = an - auth;
    } else if (u->scheme.n != 0u && rn > 0u && rest[0] == '/') {
        u->omit_host = 1;
    }
    return set_path(u, rest, rn, why);
}

void lc_url_free(lc_url *u)
{
    lc_str_free(&u->scheme);
    lc_str_free(&u->opaque);
    lc_str_free(&u->host);
    lc_str_free(&u->path);
    lc_str_free(&u->raw_path);
    lc_str_free(&u->raw_query);
    lc_str_free(&u->fragment);
    lc_str_free(&u->raw_fragment);
    lc_str_free(&u->username);
    lc_str_free(&u->password);
    memset(u, 0, sizeof *u);
}

/* Parse (GOROOT/src/net/url/url.go:399-414): its error is url.Error — `parse "…": ` and the cause
 * (:40) — quoting the URL without its fragment when that is what failed to parse, and the whole
 * of it when the fragment is what failed. */
int lc_url_parse_why(const char *s, size_t len, lc_url *u, lc_obuf *why)
{
    lc_url_free(u);
    const char *hash = memchr(s, '#', len);
    size_t      un = hash != NULL ? (size_t)(hash - s) : len;
    lc_obuf     cause = { 0 };
    lc_obuf    *c = why != NULL ? &cause : NULL;
    size_t      quoted = un;
    int         rc = parse(s, un, u, c);
    if (rc == 0 && hash != NULL && un + 1u < len) {
        rc = set_fragment(u, hash + 1, len - un - 1u, c);
        quoted = len;
    }
    if (rc == LC_URL_ERR && why != NULL) {
        /* url.Error's "%s %q: %s" with Op "parse": the format's two verbs, one call each — "parse
         * %q" up to its eighth byte, then ": %s" */
        const char *f = LC_GO("parse %q: %s");
        say_n(why, "parse %q", s, quoted);
        say_n(why, f + 8, cause.p, cause.n);
        if (cause.oom)
            why->oom = 1;
    }
    free(cause.p);
    if (rc != 0)
        lc_url_free(u);
    return rc;
}

int lc_url_parse(const char *s, size_t len, lc_url *u)
{
    return lc_url_parse_why(s, len, u, NULL);
}

int lc_url_copy(lc_url *dst, const lc_url *src)
{
    lc_url_free(dst);
    dst->user = src->user;
    dst->password_set = src->password_set;
    dst->force_query = src->force_query;
    dst->omit_host = src->omit_host;
    const lc_str *from[] = { &src->scheme,   &src->opaque,       &src->host,     &src->path,
                             &src->raw_path, &src->raw_query,    &src->fragment, &src->raw_fragment,
                             &src->username, &src->password };
    lc_str *to[] = { &dst->scheme,   &dst->opaque,    &dst->host,     &dst->path,
                     &dst->raw_path, &dst->raw_query, &dst->fragment, &dst->raw_fragment,
                     &dst->username, &dst->password };
    for (size_t i = 0; i < sizeof to / sizeof to[0]; i++)
        if (str_set(to[i], from[i]->p, from[i]->n) != 0) {
            lc_url_free(dst);
            return LC_URL_NOMEM;
        }
    return 0;
}

/* ---- ResolveReference ------------------------------------------------------------------------ */

/* resolvePath (GOROOT/src/net/url/url.go:1046-1097) of Go 1.27, which Xray v26.9.9 is built with: a
 * `..` that pops back to the root starts over there, `first = len(dst) == 1` — base `b/b/` and
 * `/b/..//` give `/`. This code has always done that, and so it was Go 1.27's before the reference
 * was: Go 1.26 left `first` as it was and gave `//`, and the vectors of the time held no such path.
 * tools/redirurl has them now. */
static int resolve_path(const lc_str *base, const lc_str *ref, lc_str *out)
{
    buf full = { 0 };
    if (ref->n == 0u) {
        b_add(&full, base->p, base->n);
    } else if (ref->p[0] != '/') {
        const char *slash = last_index(base->p, base->n, '/');
        b_add(&full, base->p, slash != NULL ? (size_t)(slash - base->p) + 1u : 0u);
        b_add(&full, ref->p, ref->n);
    } else {
        b_add(&full, ref->p, ref->n);
    }
    if (full.oom) {
        free(full.p);
        return LC_URL_NOMEM;
    }
    lc_str_free(out);
    if (full.n == 0u)
        return 0;

    /* The result is never longer than `full` and its leading '/'. */
    char *dst = malloc(full.n + 2u);
    if (dst == NULL) {
        free(full.p);
        return LC_URL_NOMEM;
    }
    size_t      d = 0, en = 0, rem = full.n;
    const char *elem = full.p, *remaining = full.p;
    int         found = 1, first = 1;
    dst[d++] = '/';
    while (found) {
        elem = remaining;
        const char *slash = memchr(remaining, '/', rem);
        if (slash != NULL) {
            en = (size_t)(slash - remaining);
            remaining = slash + 1;
            rem -= en + 1u;
        } else {
            en = rem;
            remaining += en;
            rem = 0;
            found = 0;
        }
        if (en == 1u && elem[0] == '.') {
            first = 0;
            continue;
        }
        if (en == 2u && elem[0] == '.' && elem[1] == '.') {
            /* bytes.LastIndexByte(dst[1:], '/'), and dst cut back to that slash */
            size_t i = d;
            while (i > 1u && dst[i - 1u] != '/')
                i--;
            d = i > 1u ? i - 1u : 1u;
            first = d == 1u;
            continue;
        }
        if (!first)
            dst[d++] = '/';
        memcpy(dst + d, elem, en);
        d += en;
        first = 0;
    }
    if ((en == 1u && elem[0] == '.') || (en == 2u && elem[0] == '.' && elem[1] == '.'))
        dst[d++] = '/';
    dst[d] = '\0';
    free(full.p);
    if (d > 1u && dst[1] == '/') {
        memmove(dst, dst + 1, d);
        d--;
    }
    out->p = dst;
    out->n = d;
    return 0;
}

/* setPath(resolvePath(...)), whose error ResolveReference ignores — "we know we provided a
 * validly-escaped path" — leaving the path it had. */
static int resolve_into(lc_url *out, const lc_str *base, const lc_str *ref)
{
    lc_str full = { 0 };
    int    rc = resolve_path(base, ref, &full);
    if (rc == 0) {
        rc = set_path(out, full.p != NULL ? full.p : "", full.n, NULL);
        if (rc == LC_URL_ERR)
            rc = 0;
    }
    lc_str_free(&full);
    return rc;
}

static int escaped_path(const lc_url *u, lc_str *out)
{
    buf b = { 0 };
    int rc = escaped(&b, &u->path, &u->raw_path, ENC_PATH);
    if (rc != 0) {
        free(b.p);
        return rc;
    }
    return b_done(&b, out);
}

int lc_url_escaped_path(const lc_url *u, lc_str *out)
{
    return escaped_path(u, out);
}

/* ResolveReference (GOROOT/src/net/url/url.go:1110-1151). */
int lc_url_resolve(const lc_url *u, const lc_url *ref, lc_url *out)
{
    lc_str eb = { 0 }, er = { 0 }, none = { 0 };
    int    rc = lc_url_copy(out, ref);
    if (rc != 0)
        return rc;
    if (ref->scheme.n == 0u && (rc = str_set(&out->scheme, u->scheme.p, u->scheme.n)) != 0)
        goto fail;
    if (ref->scheme.n != 0u || ref->host.n != 0u || ref->user) {
        if ((rc = escaped_path(ref, &er)) != 0 || (rc = resolve_into(out, &er, &none)) != 0)
            goto fail;
        lc_str_free(&er);
        return 0;
    }
    if (ref->opaque.n != 0u) {
        out->user = 0;
        lc_str_free(&out->username);
        lc_str_free(&out->password);
        out->password_set = 0;
        lc_str_free(&out->host);
        lc_str_free(&out->path);
        return 0;
    }
    if (ref->path.n == 0u && !ref->force_query && ref->raw_query.n == 0u) {
        if ((rc = str_set(&out->raw_query, u->raw_query.p, u->raw_query.n)) != 0)
            goto fail;
        if (ref->fragment.n == 0u &&
            ((rc = str_set(&out->fragment, u->fragment.p, u->fragment.n)) != 0 ||
             (rc = str_set(&out->raw_fragment, u->raw_fragment.p, u->raw_fragment.n)) != 0))
            goto fail;
    }
    if (ref->path.n == 0u && u->opaque.n != 0u) {
        if ((rc = str_set(&out->opaque, u->opaque.p, u->opaque.n)) != 0)
            goto fail;
        out->user = 0;
        lc_str_free(&out->username);
        lc_str_free(&out->password);
        out->password_set = 0;
        lc_str_free(&out->host);
        lc_str_free(&out->path);
        return 0;
    }
    if ((rc = str_set(&out->host, u->host.p, u->host.n)) != 0 ||
        (rc = str_set(&out->username, u->username.p, u->username.n)) != 0 ||
        (rc = str_set(&out->password, u->password.p, u->password.n)) != 0)
        goto fail;
    out->user = u->user;
    out->password_set = u->password_set;
    if ((rc = escaped_path(u, &eb)) != 0 || (rc = escaped_path(ref, &er)) != 0 ||
        (rc = resolve_into(out, &eb, &er)) != 0)
        goto fail;
    lc_str_free(&eb);
    lc_str_free(&er);
    return 0;
fail:
    lc_str_free(&eb);
    lc_str_free(&er);
    lc_url_free(out);
    return rc;
}

/* ---- what is written out of a URL ------------------------------------------------------------ */

/* RequestURI (GOROOT/src/net/url/url.go:1161-1177). */
int lc_url_request_uri(const lc_url *u, lc_str *out)
{
    buf b = { 0 };
    if (u->opaque.n == 0u) {
        int rc = escaped(&b, &u->path, &u->raw_path, ENC_PATH);
        if (rc != 0) {
            free(b.p);
            return rc;
        }
        if (b.n == 0u)
            b_byte(&b, '/');
    } else {
        if (u->opaque.n >= 2u && u->opaque.p[0] == '/' && u->opaque.p[1] == '/') {
            b_add(&b, u->scheme.p, u->scheme.n);
            b_byte(&b, ':');
        }
        b_add(&b, u->opaque.p, u->opaque.n);
    }
    if (u->force_query || u->raw_query.n != 0u) {
        b_byte(&b, '?');
        b_add(&b, u->raw_query.p, u->raw_query.n);
    }
    return b_done(&b, out);
}

/* Userinfo.String (GOROOT/src/net/url/url.go): the username and, when set, ':' and the password,
 * both escaped for userinfo. */
static void userinfo(buf *b, const lc_url *u)
{
    escape(b, u->username.p, u->username.n, ENC_USERPASS);
    if (u->password_set) {
        b_byte(b, ':');
        escape(b, u->password.p, u->password.n, ENC_USERPASS);
    }
}

int lc_url_userinfo_string(const lc_url *u, lc_str *out)
{
    buf b = { 0 };
    if (u->user)
        userinfo(&b, u);
    return b_done(&b, out);
}

/* String (GOROOT/src/net/url/url.go:821-897). */
int lc_url_string(const lc_url *u, lc_str *out)
{
    buf b = { 0 };
    if (u->scheme.n != 0u) {
        b_add(&b, u->scheme.p, u->scheme.n);
        b_byte(&b, ':');
    }
    if (u->opaque.n != 0u) {
        b_add(&b, u->opaque.p, u->opaque.n);
    } else {
        if ((u->scheme.n != 0u || u->host.n != 0u || u->user) &&
            !(u->omit_host && u->host.n == 0u && !u->user)) {
            if (u->host.n != 0u || u->path.n != 0u || u->user)
                b_add(&b, "//", 2u);
            if (u->user) {
                userinfo(&b, u);
                b_byte(&b, '@');
            }
            escape(&b, u->host.p, u->host.n, ENC_HOST);
        }
        lc_str path = { 0 };
        int    rc = escaped_path(u, &path);
        if (rc != 0) {
            free(b.p);
            return rc;
        }
        /* Go 1.27 escapes the first '/' of a path that would re-parse as an authority. */
        size_t skip = 0;
        if (u->omit_host && u->host.n == 0u && !u->user && path.n >= 2u && path.p[0] == '/' &&
            path.p[1] == '/') {
            b_add(&b, "%2F", 3u);
            skip = 1;
        }
        if (path.n > skip && path.p[skip] != '/' && u->host.n != 0u)
            b_byte(&b, '/');
        if (b.n == 0u) {
            const char *p = path.p + skip;
            size_t      pn = path.n - skip;
            const char *slash = pn != 0u ? memchr(p, '/', pn) : NULL;
            size_t      seg = slash != NULL ? (size_t)(slash - p) : pn;
            if (seg != 0u && memchr(p, ':', seg) != NULL)
                b_add(&b, "./", 2u);
        }
        b_add(&b, path.p + skip, path.n - skip);
        lc_str_free(&path);
    }
    if (u->force_query || u->raw_query.n != 0u) {
        b_byte(&b, '?');
        b_add(&b, u->raw_query.p, u->raw_query.n);
    }
    if (u->fragment.n != 0u) {
        b_byte(&b, '#');
        int rc = escaped(&b, &u->fragment, &u->raw_fragment, ENC_FRAGMENT);
        if (rc != 0) {
            free(b.p);
            return rc;
        }
    }
    return b_done(&b, out);
}

void lc_url_hostname(const char *host, size_t n, size_t *off, size_t *len)
{
    const char *colon = last_index(host, n, ':');
    if (colon != NULL && valid_optional_port(colon, n - (size_t)(colon - host)))
        n = (size_t)(colon - host);
    *off = 0;
    if (n >= 2u && host[0] == '[' && host[n - 1u] == ']') {
        *off = 1;
        n -= 2u;
    }
    *len = n;
}

void lc_url_port(const char *host, size_t n, size_t *off, size_t *len)
{
    const char *colon = last_index(host, n, ':');
    *off = n;
    *len = 0;
    if (colon != NULL && valid_optional_port(colon, n - (size_t)(colon - host))) {
        *off = (size_t)(colon - host) + 1u;
        *len = n - *off;
    }
}
