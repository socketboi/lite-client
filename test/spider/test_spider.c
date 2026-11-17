/* The request sent when REALITY did not authenticate the node.
 *
 * What is asserted is the SHAPE, because that is what an observer sees and what the reference fixes:
 * the connection preface, our SETTINGS, the connection window, then one HEADERS that ends the
 * stream. And inside it, the field set — four pseudo-headers in the reference's order, the browser's
 * fourteen, the padding cookie with its empty value, and the accept-encoding the transport adds.
 *
 * The order of everything after the four pseudo-headers is deliberately NOT asserted. Go stores them
 * in a map and its writer walks it, so the reference emits them differently on every request; a test
 * pinning an order here would be pinning something the thing it imitates does not have. */

#include "reality/spider.c"

#include "h2/hpack.h"
#include "redirurl_vectors.h"
#include "spiderurl_vectors.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

/* An lc_str against a vector's string, NULL meaning none: an empty lc_str. */
static int str_is(const lc_str *s, const char *want)
{
    if (want == NULL)
        return s->n == 0u;
    return s->n == strlen(want) && (s->n == 0u || memcmp(s->p, want, s->n) == 0);
}

static const char *show(const lc_str *s)
{
    return s->n != 0u ? s->p : "-";
}

int main(void)
{
    printf("spider: the request\n");

    lc_browser b;
    ok(lc_browser_chrome(&b, 20800LL * 86400, 0, LC_BROWSER_NAV) == 0, "the browser identity builds");

    uint8_t out[8192u];
    size_t  opening = 0;
    long    n = lc_spider_request("www.example.com", &b, out, sizeof out, &opening);
    ok(n > 0, "and the request builds");
    if (n <= 0) {
        printf("\n%d failed\n", failures);
        return 1;
    }

    /* The preface first, verbatim: a server reading a plain HTTP request must not be able to
     * mistake this for one, which is the whole reason it exists. */
    static const char pre[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    ok((size_t)n > sizeof pre - 1 && memcmp(out, pre, sizeof pre - 1) == 0,
       "the connection preface leads");

    /* Then three frames, in order: SETTINGS, WINDOW_UPDATE on stream zero, HEADERS on stream one. */
    size_t at = sizeof pre - 1;
    lc_h2_hd hd;

    ok(lc_h2_get_header(out + at, (size_t)n - at, &hd) == 0 && hd.type == 0x04u && hd.stream == 0,
       "then SETTINGS on stream zero");
    at += LC_H2_HEADER + hd.len;

    ok(lc_h2_get_header(out + at, (size_t)n - at, &hd) == 0 && hd.type == 0x08u && hd.stream == 0,
       "then the connection window");
    at += LC_H2_HEADER + hd.len;
    ok(opening == at,
       "and the opening it reports ends there: the connection's write, before the request's");

    ok(lc_h2_get_header(out + at, (size_t)n - at, &hd) == 0 && hd.type == 0x01u && hd.stream == 1,
       "then HEADERS on stream one");
    ok((hd.flags & LC_H2_END_STREAM) != 0,
       "and it ends the stream, because a GET has no body");
    ok((hd.flags & LC_H2_END_HEADERS) != 0, "and carries the whole field section");

    size_t block_off = at + LC_H2_HEADER;
    ok(block_off + hd.len == (size_t)n, "the request ends where the field section does");

    /* And the fields themselves, read back with our own decoder. */
    lc_hpack_dec d;
    memset(&d, 0, sizeof d);
    d.in = out + block_off;
    d.len = hd.len;

    struct {
        const char *name;
        const char *value;
        int         seen;
    } want[] = {
        { ":authority", "www.example.com", 0 },
        { ":method", "GET", 0 },
        { ":path", "/", 0 },
        { ":scheme", "https", 0 },
        /* The one with an empty value, which is the detail most likely to be dropped as noise:
         * RandBetween(0,0) repeats "0" zero times and Go writes the cookie regardless. */
        { "cookie", "padding=", 0 },
        { "accept-encoding", "gzip", 0 },
        { "user-agent", b.ua, 0 },
        { "sec-ch-ua", b.chua, 0 },
        { "sec-fetch-mode", "navigate", 0 },
        { "sec-fetch-dest", "document", 0 },
        { "upgrade-insecure-requests", "1", 0 },
        { "priority", "u=0, i", 0 },
    };
    unsigned wanted = sizeof want / sizeof want[0];

    unsigned fields = 0;
    int      first_four = 1;
    static const char *const pseudo[4] = { ":authority", ":method", ":path", ":scheme" };
    while (lc_hpack_next(&d) == 1) {
        if (fields < 4u && strcmp(d.name, pseudo[fields]) != 0)
            first_four = 0;
        for (unsigned i = 0; i < wanted; i++)
            if (strcmp(d.name, want[i].name) == 0) {
                want[i].seen = strcmp(d.value, want[i].value) == 0 ? 1 : -1;
                break;
            }
        fields++;
    }

    ok(first_four, "the four pseudo-headers lead, in the reference's order");
    ok(fields == 4u + LC_BROWSER_HEADERS + 2u, "and the field count is the reference's");

    int all = 1;
    for (unsigned i = 0; i < wanted; i++) {
        if (want[i].seen == 1)
            continue;
        printf("        %s: %s\n", want[i].name, want[i].seen == 0 ? "missing" : "wrong value");
        all = 0;
    }
    ok(all, "every field checked is present with the reference's value");

    /* AND THE ORDER OF THE REST CHANGES BETWEEN REQUESTS, which nothing above would have noticed.
     *
     * Everything before this asks what the field section CONTAINS, so it passed just as happily
     * when the client emitted the same order every time — and that was the defect: Go walks
     * req.Header as a map and its iteration is deliberately randomised, so the reference varies the
     * order on every request while this client did not. One capture cannot tell the two apart; two
     * captures of the same node can, without decrypting anything.
     *
     * Eight requests, and at least two of them must differ. The chance of a false failure is the
     * chance that eight walks of eight fresh fifteen-key Go maps all come out identical, which is
     * not a number this suite will ever see; the chance of a false PASS is zero, because a client
     * with a fixed order produces one string eight times. */
    {
        char     seen[8][512];
        unsigned made = 0;
        for (unsigned t = 0; t < 8u; t++) {
            uint8_t buf2[8192u];
            size_t  op2 = 0;
            long    m = lc_spider_request("www.example.com", &b, buf2, sizeof buf2, &op2);
            if (m <= 0)
                break;
            /* The field section sits behind the preface and two frames, exactly as above. */
            size_t   off = sizeof pre - 1;
            lc_h2_hd h2;
            if (lc_h2_get_header(buf2 + off, (size_t)m - off, &h2) != 0)
                break;
            off += LC_H2_HEADER + h2.len;
            if (lc_h2_get_header(buf2 + off, (size_t)m - off, &h2) != 0)
                break;
            off += LC_H2_HEADER + h2.len;
            if (lc_h2_get_header(buf2 + off, (size_t)m - off, &h2) != 0)
                break;
            lc_hpack_dec d2;
            memset(&d2, 0, sizeof d2);
            d2.in = buf2 + off + LC_H2_HEADER;
            d2.len = h2.len;
            seen[made][0] = '\0';
            size_t at2 = 0;
            while (lc_hpack_next(&d2) == 1) {
                size_t nl = strlen(d2.name);
                if (at2 + nl + 2u >= sizeof seen[0])
                    break;
                memcpy(seen[made] + at2, d2.name, nl);
                at2 += nl;
                seen[made][at2++] = ',';
                seen[made][at2] = '\0';
            }
            made++;
        }
        int varied = 0;
        for (unsigned i = 1; i < made; i++)
            if (strcmp(seen[0], seen[i]) != 0)
                varied = 1;
        ok(made == 8u, "eight spider requests build");
        ok(varied, "and the headers after the pseudo-headers are not in the same order every time");
    }

    /* What a stored path becomes, against the reference's own net/http, net/url and x/net: every
     * vector tools/spiderurl wrote, from "/" to the ones that make no request at all. One line for
     * each that disagrees, then one verdict. */
    {
        int      bad = 0;
        unsigned count = (unsigned)(sizeof spiderurl / sizeof spiderurl[0]), auths = 0, idn = 0;
        for (unsigned i = 0; i < count; i++) {
            static lc_url url;
            lc_spider_req q = { 0 };
            int  got = lc_spider_target(spiderurl_host, spiderurl[i].stored, spiderurl[i].stored_len,
                                        &url, &q);
            int  same = got == spiderurl[i].outcome;
            if (same && got != LC_SPIDER_NONE) {
                same = str_is(&q.key, spiderurl[i].key) &&
                       str_is(&q.authorization, spiderurl[i].authorization);
                auths += spiderurl[i].authorization != NULL;
                idn += strstr(spiderurl[i].key, "xn--") != NULL;
            }
            if (same && got == LC_SPIDER_REQUEST)
                same = str_is(&q.authority, spiderurl[i].authority) &&
                       str_is(&q.path, spiderurl[i].path);
            if (!same) {
                bad++;
                printf("        [%.60s]: got %d %s %s %s %s, Go says %d %s %s %s %s\n", spiderurl[i].stored,
                       got, show(&q.authority), show(&q.path), show(&q.key), show(&q.authorization),
                       spiderurl[i].outcome, spiderurl[i].authority ? spiderurl[i].authority : "-",
                       spiderurl[i].path ? spiderurl[i].path : "-", spiderurl[i].key ? spiderurl[i].key : "-",
                       spiderurl[i].authorization ? spiderurl[i].authorization : "-");
            }
            lc_spider_req_free(&q);
            lc_url_free(&url);
        }
        char line[128];
        snprintf(line, sizeof line,
                 "all %u stored paths become what net/http, net/url and x/net make of them (%u with "
                 "userinfo, %u through IDNA)",
                 count, auths, idn);
        ok(bad == 0 && count > 130u && auths > 15u && idn > 15u, line);
    }

    /* What a redirect's Location becomes, against the reference's own http.Client and x/net: every
     * vector tools/redirurl wrote — relative, dotted, scheme-relative, opaque, other hosts and
     * ports, bad escapes, bad hosts, userinfo, hosts IDNA rewrites. One line for each that
     * disagrees, then one verdict. */
    {
        static lc_url base, next;
        lc_redir r = { 0 };
        int      bad = 0;
        unsigned count = (unsigned)(sizeof redirurl / sizeof redirurl[0]), requests = 0, auths = 0;
        for (unsigned i = 0; i < count; i++) {
            if (lc_url_parse(redirurl[i].base, strlen(redirurl[i].base), &base) != 0) {
                bad++;
                printf("        [%s]: the base does not parse\n", redirurl[i].base);
                continue;
            }
            int rc = lc_redirect(&base, 0, &base, redirurl[i].location, strlen(redirurl[i].location),
                                 &next, &r);
            int same = rc == 0 && r.outcome == redirurl[i].outcome;
            if (same && (r.outcome == LC_REDIR_REQUEST || r.outcome == LC_REDIR_PREFACE)) {
                same = str_is(&r.url, redirurl[i].url) && str_is(&r.req.key, redirurl[i].key) &&
                       str_is(&r.referer, redirurl[i].referer) &&
                       str_is(&r.req.authorization, redirurl[i].authorization) &&
                       r.same == redirurl[i].same && r.strip == redirurl[i].strip &&
                       r.req.headers == (redirurl[i].authority != NULL);
                auths += redirurl[i].authorization != NULL;
            }
            if (same && r.req.headers) {
                same = str_is(&r.req.authority, redirurl[i].authority) &&
                       str_is(&r.req.path, redirurl[i].path);
                requests++;
            }
            if (!same) {
                bad++;
                printf("        [%.80s] after [%s]: got %d %s %s %s %s ref %s auth %s same %d strip %d, "
                       "Go says %d %s %s %s %s ref %s auth %s same %d strip %d\n",
                       redirurl[i].location, redirurl[i].base, r.outcome, show(&r.url),
                       show(&r.req.authority), show(&r.req.path), show(&r.req.key), show(&r.referer),
                       show(&r.req.authorization), r.same, r.strip, redirurl[i].outcome,
                       redirurl[i].url ? redirurl[i].url : "-",
                       redirurl[i].authority ? redirurl[i].authority : "-",
                       redirurl[i].path ? redirurl[i].path : "-", redirurl[i].key ? redirurl[i].key : "-",
                       redirurl[i].referer ? redirurl[i].referer : "-",
                       redirurl[i].authorization ? redirurl[i].authorization : "-", redirurl[i].same,
                       redirurl[i].strip);
            }
        }
        lc_redir_free(&r);
        lc_url_free(&base);
        lc_url_free(&next);
        char line[140];
        snprintf(line, sizeof line,
                 "all %u redirects become what http.Client and x/net make of them (%u with HEADERS, %u "
                 "with userinfo)",
                 count, requests, auths);
        ok(bad == 0 && count > 1400u && requests > 900u && auths > 100u, line);
    }

    /* Chains of them, from the real client too: the cookie, once left behind by a hop, stays behind
     * whatever the later hops come back to. Each hop resolved against the one before. */
    {
        static lc_url first, base, next;
        lc_redir r = { 0 };
        int      bad = 0;
        unsigned count = (unsigned)(sizeof redirchain / sizeof redirchain[0]);
        for (unsigned c = 0; c < count; c++) {
            if (lc_url_parse(redirchain[c].url[0], strlen(redirchain[c].url[0]), &first) != 0 ||
                lc_url_copy(&base, &first) != 0) {
                bad++;
                continue;
            }
            int stripped = 0;
            for (unsigned h = 1; h < 4u && redirchain[c].url[h] != NULL; h++) {
                if (lc_redirect(&first, stripped, &base, redirchain[c].url[h],
                                strlen(redirchain[c].url[h]), &next, &r) != 0 ||
                    r.outcome != LC_REDIR_REQUEST || r.strip != redirchain[c].strip[h]) {
                    bad++;
                    printf("        chain %u, hop %u [%s]: strip %d, Go %d\n", c, h, redirchain[c].url[h],
                           r.strip, redirchain[c].strip[h]);
                    break;
                }
                stripped = r.strip;
                if (lc_url_copy(&base, &next) != 0) {
                    bad++;
                    break;
                }
            }
        }
        lc_redir_free(&r);
        lc_url_free(&first);
        lc_url_free(&base);
        lc_url_free(&next);
        char line[100];
        snprintf(line, sizeof line, "%u chains: the cookie stays behind once a hop leaves it", count);
        ok(bad == 0, line);
    }

    printf(failures == 0 ? "\nall good\n" : "\n%d failed\n", failures);
    return failures == 0 ? 0 : 1;
}
