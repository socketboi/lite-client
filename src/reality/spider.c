#include "reality/spider.h"

#include "core/idna.h"
#include "reality/paths.h"

#include "h2/frame.h"
#include "h2/xhttp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- strings --------------------------------------------------------------------------------- */

static int set(lc_str *s, const char *p, size_t n)
{
    lc_str_free(s);
    if (n == 0u)
        return 0;
    s->p = malloc(n + 1u);
    if (s->p == NULL)
        return -1;
    memcpy(s->p, p, n);
    s->p[n] = '\0';
    s->n = n;
    return 0;
}

/* The concatenation of up to four pieces, which is all anything here glues. */
static int cat(lc_str *s, const char *a, size_t an, const char *b, size_t bn, const char *c, size_t cn,
               const char *d, size_t dn)
{
    lc_str_free(s);
    size_t n = an + bn + cn + dn;
    if (n == 0u)
        return 0;
    char *p = malloc(n + 1u);
    if (p == NULL)
        return -1;
    if (an != 0u)
        memcpy(p, a, an);
    if (bn != 0u)
        memcpy(p + an, b, bn);
    if (cn != 0u)
        memcpy(p + an + bn, c, cn);
    if (dn != 0u)
        memcpy(p + an + bn + cn, d, dn);
    p[n] = '\0';
    s->p = p;
    s->n = n;
    return 0;
}

static int eq(const lc_str *a, const lc_str *b)
{
    return a->n == b->n && (a->n == 0u || memcmp(a->p, b->p, a->n) == 0);
}

static int is_ascii(const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if ((uint8_t)s[i] >= 0x80u)
            return 0;
    return 1;
}

void lc_spider_req_free(lc_spider_req *q)
{
    lc_str_free(&q->authority);
    lc_str_free(&q->path);
    lc_str_free(&q->key);
    lc_str_free(&q->pool);
    lc_str_free(&q->authorization);
    q->headers = 0;
}

void lc_redir_free(lc_redir *r)
{
    lc_str_free(&r->url);
    lc_str_free(&r->referer);
    lc_spider_req_free(&r->req);
    r->outcome = r->same = r->strip = 0;
}

/* ---- the host, as x/net sees it ----------------------------------------------------------------- */

/* net.SplitHostPort (GOROOT/src/net/ipsock.go): 0 with where the host starts and ends and the port,
 * -1 on any of its errors. */
static int split_host_port(const char *hp, size_t n, size_t *h0, size_t *h1, size_t *port)
{
    const char *last = NULL;
    for (size_t i = n; i-- > 0;)
        if (hp[i] == ':') {
            last = hp + i;
            break;
        }
    if (last == NULL)
        return -1; /* missing port */
    size_t i = (size_t)(last - hp), j = 0, k = 0;
    if (hp[0] == '[') {
        const char *close = memchr(hp, ']', n);
        if (close == NULL)
            return -1;
        size_t end = (size_t)(close - hp);
        if (end + 1u == n || end + 1u != i)
            return -1; /* missing port, or too many colons, or a ']' not followed by the last ':' */
        *h0 = 1;
        *h1 = end;
        j = 1;
        k = end + 1u;
    } else {
        if (memchr(hp, ':', i) != NULL)
            return -1; /* too many colons */
        *h0 = 0;
        *h1 = i;
    }
    if (memchr(hp + j, '[', n - j) != NULL || memchr(hp + k, ']', n - k) != NULL)
        return -1;
    *port = i + 1u;
    return 0;
}

/* host:port as net.JoinHostPort writes it: in brackets when the host has a colon. */
static int join_host_port(lc_str *out, const char *h, size_t hn, const char *p, size_t pn)
{
    if (memchr(h, ':', hn) != NULL)
        return cat(out, "[", 1u, h, hn, "]:", 2u, p, pn);
    return cat(out, h, hn, ":", 1u, p, pn, NULL, 0u);
}

/* authorityAddr("https", host) (vendor/x-net/http2/transport_common.go:307-334): the port 443 when
 * there is none, the name through idna.ToASCII when that takes it — kept as it was when it does not. */
static int authority_addr(const lc_str *host, lc_str *out)
{
    const char *hp = host->p != NULL ? host->p : "";
    size_t      h0 = 0, h1 = host->n, port = host->n;
    if (split_host_port(hp, host->n, &h0, &h1, &port) != 0) {
        h0 = 0;
        h1 = host->n;
        port = host->n;
    }
    const char *p = hp + port;
    size_t      pn = host->n - port;
    if (pn == 0u) {
        p = "443";
        pn = 3u;
    }
    char  *a = NULL;
    size_t an = 0;
    int    rc = lc_idna_to_ascii(hp + h0, h1 - h0, &a, &an);
    if (rc == -2)
        return -1;
    const char *h = rc == 0 ? a : hp + h0;
    size_t      hn = rc == 0 ? an : h1 - h0;
    if (hn >= 2u && h[0] == '[' && h[hn - 1u] == ']')
        rc = cat(out, h, hn, ":", 1u, p, pn, NULL, 0u);
    else
        rc = join_host_port(out, h, hn, p, pn);
    free(a);
    return rc;
}

/* canonicalAddr (GOROOT/src/net/http/transport.go:3187-3202): Hostname() through idnaASCII — as it
 * is when all ASCII, else idna.Lookup's, kept as it was when Lookup refuses
 * (GOROOT/src/net/http/request.go:791-805) — and Port(), or 443. What net/http dials, and the key
 * of its list of idle connections. */
static int canonical_addr(const lc_url *u, lc_str *out)
{
    const char *hp = u->host.p != NULL ? u->host.p : "";
    size_t      off, len, poff, plen;
    lc_url_hostname(hp, u->host.n, &off, &len);
    lc_url_port(hp, u->host.n, &poff, &plen);
    char  *a = NULL;
    size_t an = 0;
    int    rc = is_ascii(hp + off, len) ? -1 : lc_idna_lookup(hp + off, len, &a, &an);
    if (rc == -2)
        return -1;
    rc = join_host_port(out, rc == 0 ? a : hp + off, rc == 0 ? an : len, plen != 0u ? hp + poff : "443",
                        plen != 0u ? plen : 3u);
    free(a);
    return rc;
}

/* httpguts.PunycodeHostPort (vendor/x-net/http/httpguts/httplex.go): an ASCII Host as it is, else
 * the host part through idna.ToASCII and the port put back. 1 when that fails, which fails the
 * request after its ClientConn was made. */
static int punycode_host_port(const lc_str *v, lc_str *out)
{
    const char *hp = v->p != NULL ? v->p : "";
    if (is_ascii(hp, v->n))
        return set(out, hp, v->n);
    size_t h0 = 0, h1 = v->n, port = v->n;
    int    has_port = split_host_port(hp, v->n, &h0, &h1, &port) == 0;
    if (!has_port) {
        h0 = 0;
        h1 = v->n;
        port = v->n;
    }
    char  *a = NULL;
    size_t an = 0;
    int    rc = lc_idna_to_ascii(hp + h0, h1 - h0, &a, &an);
    if (rc == -2)
        return -1;
    if (rc == -1)
        return 1;
    if (!has_port || port == v->n)
        rc = set(out, a, an);
    else
        rc = join_host_port(out, a, an, hp + port, v->n - port);
    free(a);
    return rc;
}

/* httpguts.ValidHostHeader's bytes (vendor/x-net/http/httpguts/httplex.go:230-263). */
static int host_byte(uint8_t c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           (c != 0u && strchr("!$%&()*+,-.:;=[']_~", c) != NULL);
}

static int valid_pseudo_path(const char *p, size_t n)
{
    return (n > 0u && p[0] == '/') || (n == 1u && p[0] == '*');
}

/* base64.StdEncoding: padded, the standard alphabet. */
static int base64(lc_str *out, const char *prefix, size_t pn, const uint8_t *in, size_t n)
{
    static const char abc[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    lc_str_free(out);
    size_t len = pn + (n + 2u) / 3u * 4u;
    char  *p = malloc(len + 1u);
    if (p == NULL)
        return -1;
    memcpy(p, prefix, pn);
    size_t o = pn;
    for (size_t i = 0; i < n; i += 3u) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1u < n)
            v |= (uint32_t)in[i + 1] << 8;
        if (i + 2u < n)
            v |= in[i + 2];
        p[o++] = abc[v >> 18 & 63u];
        p[o++] = abc[v >> 12 & 63u];
        p[o++] = i + 1u < n ? abc[v >> 6 & 63u] : '=';
        p[o++] = i + 2u < n ? abc[v & 63u] : '=';
    }
    p[o] = '\0';
    out->p = p;
    out->n = o;
    return 0;
}

/* What x/net makes of a request for `u`, and what send put in front of it — see lc_spider_req. */
static int request_for(const lc_url *u, lc_spider_req *q)
{
    lc_spider_req_free(q);
    if (authority_addr(&u->host, &q->key) != 0)
        return -1;
    lc_str dial = { 0 };
    int    rc = canonical_addr(u, &dial) != 0 || authority_addr(&dial, &q->pool) != 0 ? -1 : 0;
    lc_str_free(&dial);
    if (rc != 0)
        return -1;

    /* send: `"Basic " + basicAuth(username, password)` for a URL with userinfo
     * (GOROOT/src/net/http/client.go:253-258, :429-432) — the unescaped name and password. */
    if (u->user) {
        size_t   n = u->username.n + 1u + u->password.n;
        uint8_t *raw = malloc(n);
        if (raw == NULL)
            return -1;
        if (u->username.n != 0u)
            memcpy(raw, u->username.p, u->username.n);
        raw[u->username.n] = ':';
        if (u->password.n != 0u)
            memcpy(raw + u->username.n + 1u, u->password.p, u->password.n);
        rc = base64(&q->authorization, "Basic ", 6u, raw, n);
        free(raw);
        if (rc != 0)
            return -1;
    }

    /* EncodeHeaders (vendor/x-net/internal/httpcommon/request.go:76-115): the Host through
     * PunycodeHostPort and ValidHostHeader, then the :path — RequestURI, and when that is not a
     * valid pseudo-path, the same with "scheme://host" cut off its front. */
    rc = punycode_host_port(&u->host, &q->authority);
    if (rc < 0)
        return -1;
    if (rc > 0)
        return 0;
    for (size_t i = 0; i < q->authority.n; i++)
        if (!host_byte((uint8_t)q->authority.p[i]))
            return 0;
    if (lc_url_request_uri(u, &q->path) != 0)
        return -1;
    if (!valid_pseudo_path(q->path.p, q->path.n)) {
        lc_str prefix = { 0 };
        if (cat(&prefix, u->scheme.p, u->scheme.n, "://", 3u, q->authority.p, q->authority.n, NULL,
                0u) != 0)
            return -1;
        const char *p = q->path.p;
        size_t      pn = q->path.n;
        if (pn >= prefix.n && memcmp(p, prefix.p, prefix.n) == 0) {
            p += prefix.n;
            pn -= prefix.n;
        }
        lc_str_free(&prefix);
        if (!valid_pseudo_path(p, pn))
            return 0;
        memmove(q->path.p, p, pn);
        q->path.n = pn;
        q->path.p[pn] = '\0';
    }
    q->headers = 1;
    return 0;
}

/* ---- the first request ----------------------------------------------------------------------- */

int lc_spider_target(const char *host, const char *stored, size_t sn, lc_url *url, lc_spider_req *q)
{
    lc_spider_req_free(q);
    /* `http.NewRequest("GET", "https://" + ServerName + path, nil)` (reality.go:231, :241): url.Parse
     * of the concatenation, whose failure is a spider that sends nothing. */
    lc_str raw = { 0 };
    size_t hn = strlen(host);
    if (cat(&raw, "https://", 8u, host, hn, stored, sn, NULL, 0u) != 0)
        return -1;
    int rc = lc_url_parse(raw.p, raw.n, url);
    lc_str_free(&raw);
    if (rc == LC_URL_NOMEM)
        return -1;
    if (rc != 0)
        return LC_SPIDER_NONE;

    /* NewRequest drops one trailing ':' off the Host (GOROOT/src/net/http/request.go:920-921). */
    if (url->host.n > 0u && url->host.p[url->host.n - 1u] == ':') {
        url->host.p[--url->host.n] = '\0';
        if (url->host.n == 0u)
            lc_str_free(&url->host);
    }

    if (request_for(url, q) != 0) {
        lc_spider_req_free(q);
        return -1;
    }
    return q->headers ? LC_SPIDER_REQUEST : LC_SPIDER_PREFACE;
}

/* ---- redirects ------------------------------------------------------------------------------ */

/* isDomainOrSubdomain (GOROOT/src/net/http/client.go:1045-1062). */
static int domain_or_subdomain(const char *sub, size_t sn, const char *parent, size_t pn)
{
    if (sn == pn && memcmp(sub, parent, sn) == 0)
        return 1;
    if (memchr(sub, ':', sn) != NULL || memchr(sub, '%', sn) != NULL)
        return 0;
    return sn > pn && memcmp(sub + sn - pn, parent, pn) == 0 && sub[sn - pn - 1u] == '.';
}

/* One side of shouldCopyHeaderOnRedirect: the URL's Hostname() through httpguts.PunycodeHostPort,
 * then ascii.ToLower, which refuses anything that is not printable ASCII
 * (GOROOT/src/net/http/internal/ascii/print.go:36-61). 1 with the name in `*out`, 0 when either
 * refuses, -1 without memory. That refusal is kept as Go has it, though nothing reaches it: Parse
 * turned away control bytes and DEL, and PunycodeHostPort encodes every byte from 0x80 up or fails. */
static int copy_host(const lc_url *u, lc_str *out)
{
    size_t off, len;
    lc_url_hostname(u->host.p, u->host.n, &off, &len);
    lc_str v = { .p = u->host.p != NULL ? u->host.p + off : NULL, .n = len };
    int    rc = punycode_host_port(&v, out);
    if (rc != 0)
        return rc < 0 ? -1 : 0;
    for (size_t i = 0; i < out->n; i++) {
        uint8_t c = (uint8_t)out->p[i];
        if (c < ' ' || c > '~')
            return 0;
        if (c >= 'A' && c <= 'Z')
            out->p[i] = (char)(c + ('a' - 'A'));
    }
    return 1;
}

/* shouldCopyHeaderOnRedirect (GOROOT/src/net/http/client.go:1017-1039), Go 1.27's: both hostnames
 * through copy_host, and a refusal on either side is not copying. 1 to copy, 0 not to, -1 without
 * memory. Go 1.26's took an ASCII name as it was, case and all, and a non-ASCII one through
 * idna.Lookup, kept as it was when that failed — so `Example.com` to `www.example.com` did not
 * carry the cookie there and does here. */
static int should_copy(const lc_url *initial, const lc_url *dest)
{
    lc_str ih = { 0 }, dh = { 0 };
    int    a = copy_host(initial, &ih);
    int    b = a == 1 ? copy_host(dest, &dh) : 0;
    int    rc = a < 0 || b < 0 ? -1
                : a == 1 && b == 1 ? domain_or_subdomain(dh.p != NULL ? dh.p : "", dh.n,
                                                         ih.p != NULL ? ih.p : "", ih.n)
                                   : 0;
    lc_str_free(&ih);
    lc_str_free(&dh);
    return rc;
}

int lc_redirect(const lc_url *first, int stripped, const lc_url *base, const char *location,
                size_t ln, lc_url *next, lc_redir *r)
{
    lc_redir_free(r);
    r->strip = stripped;
    lc_url ref = { 0 };
    int    rc = lc_url_parse(location, ln, &ref);
    if (rc == LC_URL_NOMEM)
        return -1;
    if (rc != 0) {
        r->outcome = LC_REDIR_NONE;
        return 0;
    }
    rc = lc_url_resolve(base, &ref, next);
    lc_url_free(&ref);
    if (rc != 0)
        return -1;
    int https = next->scheme.n == 5u && memcmp(next->scheme.p, "https", 5) == 0;
    if (!https) {
        r->outcome = LC_REDIR_SCHEME;
        return 0;
    }

    /* The cookie: `if !stripSensitiveHeaders && reqs[0].URL.Host != req.URL.Host` then
     * shouldCopyHeaderOnRedirect (GOROOT/src/net/http/client.go:698-704) — once left behind, it
     * stays behind. */
    if (!stripped && !eq(&first->host, &next->host)) {
        int copy = should_copy(first, next);
        if (copy < 0)
            return -1;
        r->strip = !copy;
    }

    /* refererForURL (GOROOT/src/net/http/client.go:149-173): none from https to http, else the last
     * request's String() with its first "userinfo@" taken out. The new one is https by now, so it
     * is the second. */
    {
        if (lc_url_string(base, &r->referer) != 0)
            return -1;
        if (base->user) {
            lc_str ui = { 0 }, auth = { 0 };
            if (lc_url_userinfo_string(base, &ui) != 0 ||
                cat(&auth, ui.p, ui.n, "@", 1u, NULL, 0u, NULL, 0u) != 0) {
                lc_str_free(&ui);
                return -1;
            }
            lc_str_free(&ui);
            for (size_t i = 0; i + auth.n <= r->referer.n; i++)
                if (memcmp(r->referer.p + i, auth.p, auth.n) == 0) {
                    memmove(r->referer.p + i, r->referer.p + i + auth.n, r->referer.n - i - auth.n);
                    r->referer.n -= auth.n;
                    r->referer.p[r->referer.n] = '\0';
                    break;
                }
            lc_str_free(&auth);
            if (r->referer.n == 0u)
                lc_str_free(&r->referer);
        }
    }

    if (lc_url_string(next, &r->url) != 0 || request_for(next, &r->req) != 0)
        return -1;
    lc_str base_key = { 0 };
    if (authority_addr(&base->host, &base_key) != 0)
        return -1;
    r->same = eq(&r->req.key, &base_key);
    lc_str_free(&base_key);
    r->outcome = r->req.headers || r->same ? LC_REDIR_REQUEST : LC_REDIR_PREFACE;
    return 0;
}
