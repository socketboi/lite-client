/* Go's resolver as transcribed in src/net/goresolve.c, the parts that need no network: what it reads
 * out of resolv.conf, nsswitch.conf and hosts, the names it would ask for, what it accepts as a name,
 * how it reads a message, what its query looks like, and how it orders an answer. White box —
 * goresolve.c is included — because each of these is a static function the lookup is built from.
 *
 * The lookup itself, queries and all, is held to Go's own resolver by the stand
 * tools/vendorcap/dnsstand, which needs port 53 and the machine's /etc and so is not run here. The
 * expected values below are what Go 1.27.1 does, each checked against it there or read off its
 * source (GOROOT/src/net). */
#include "net/goresolve.c"

#include <stdio.h>

static int failures, checks;

static void expect(int cond, const char *what)
{
    checks++;
    if (cond) {
        printf("  ok    %s\n", what);
    } else {
        printf("  FAIL  %s\n", what);
        failures++;
    }
}

static const char *write_tmp(const char *name, const char *text)
{
    static char path[4][64];
    static int  k;
    char       *p = path[k++ % 4];
    snprintf(p, 64, "/tmp/goresolve-%d-%s", (int)getpid(), name);
    FILE *f = fopen(p, "w");
    if (f != NULL) {
        fputs(text, f);
        fclose(f);
    }
    return p;
}

static void resolv_conf(void)
{
    printf("\nresolv.conf, as dnsReadConfig reads it\n");
    const char *p = write_tmp("r1", "# comment\n; also\nnameserver 192.0.2.1\nnameserver not-an-ip\n"
                                    "nameserver fe80::1%eth9\nnameserver 192.0.2.3\nnameserver 192.0.2.4\n"
                                    "domain first.test\nsearch a.test. b.test . \n"
                                    "options ndots:20 timeout:0 attempts:0 rotate single-request use-vc "
                                    "trust-ad no-reload edns0 made-up\n");
    dnsconf *c = dns_read_config(p);
    expect(c != NULL && c->nservers == 3u, "three name servers kept, the one that is not an address skipped");
    expect(c != NULL && strcmp(c->servers[0].text, "192.0.2.1:53") == 0 &&
               strcmp(c->servers[1].text, "[fe80::1%eth9]:53") == 0 &&
               strcmp(c->servers[2].text, "192.0.2.3:53") == 0,
           "each named as JoinHostPort names it, the zone kept");
    expect(c != NULL && c->nsearch == 2u && strcmp(c->search[0], "a.test.") == 0 &&
               strcmp(c->search[1], "b.test.") == 0,
           "search replaces domain, rooted, and the root itself dropped");
    expect(c != NULL && c->ndots == 15 && c->timeout_s == 1 && c->attempts == 1,
           "ndots capped at 15, timeout and attempts at least 1");
    expect(c != NULL && c->rotate && c->single_request && c->use_tcp && c->trust_ad && c->no_reload,
           "rotate, single-request, use-vc, trust-ad, no-reload");
    dnsconf_free(c);

    p = write_tmp("r2", "search x.test\ndomain only.test\n");
    c = dns_read_config(p);
    expect(c != NULL && c->nsearch == 1u && strcmp(c->search[0], "only.test.") == 0,
           "a later domain line replaces an earlier search");
    expect(c != NULL && c->default_ns && c->nservers == 2u &&
               strcmp(c->servers[0].text, "127.0.0.1:53") == 0 && strcmp(c->servers[1].text, "[::1]:53") == 0,
           "no name server: defaultNS");
    dnsconf_free(c);

    c = dns_read_config("/nonexistent/resolv.conf");
    expect(c != NULL && c->default_ns && c->ndots == 1 && c->timeout_s == 5 && c->attempts == 2,
           "no file: defaultNS, ndots 1, five seconds, two attempts");
    dnsconf_free(c);
}

static int list_is(const dnsconf *c, const char *name, const char *const *want, unsigned n)
{
    unsigned k;
    char   **l = name_list(c, name, &k);
    int      ok = k == n;
    for (unsigned i = 0; i < k; i++) {
        if (ok && strcmp(l[i], want[i]) != 0)
            ok = 0;
        free(l[i]);
    }
    free(l);
    return ok;
}

static void names(void)
{
    printf("\nthe names asked for, nameList\n");
    dnsconf c;
    memset(&c, 0, sizeof c);
    char *search[] = { (char *)"a.test.", (char *)"b.test." };
    c.search = search;
    c.nsearch = 2;
    c.ndots = 1;
    expect(list_is(&c, "host", (const char *const[]){ "host.a.test.", "host.b.test.", "host." }, 3),
           "fewer dots than ndots: the suffixes first, the name itself last");
    expect(list_is(&c, "x.y", (const char *const[]){ "x.y.", "x.y.a.test.", "x.y.b.test." }, 3),
           "as many dots as ndots: the name first");
    expect(list_is(&c, "rooted.name.", (const char *const[]){ "rooted.name." }, 1),
           "a rooted name alone");
    expect(list_is(&c, "secret.onion", (const char *const[]){ "secret.onion.a.test.", "secret.onion.b.test." }, 2),
           ".onion: never asked as itself, but a search suffix makes it another name, and that is asked");
    expect(list_is(&c, "secret.onion.", (const char *const[]){ "" }, 0), "a rooted .onion: nothing at all");
    c.ndots = 3;
    expect(list_is(&c, "x.y", (const char *const[]){ "x.y.a.test.", "x.y.b.test.", "x.y." }, 3),
           "ndots 3 puts a two-label name last");

    printf("\nwhat is a name, isDomainName\n");
    expect(is_domain_name("node.example") && is_domain_name("_srv.example.") && is_domain_name("."),
           "letters, underscores, a trailing dot, the root");
    expect(!is_domain_name("1.2.3") && !is_domain_name("bad..name") && !is_domain_name("-x.test") &&
               !is_domain_name("x-.test") && !is_domain_name("a b"),
           "all digits, an empty label, a dash at either end, a space: not names");
    char long_label[70];
    memset(long_label, 'a', 64);
    long_label[64] = '\0';
    expect(!is_domain_name(long_label), "a label of 64");
}

static void message(void)
{
    printf("\nthe message, as dnsmessage reads it\n");
    uint8_t name[255];
    uint8_t nlen;
    static const uint8_t loop[] = { 0xC0, 0x00 };
    expect(name_unpack(loop, sizeof loop, 0, name, &nlen) == (size_t)-1, "a pointer to itself: refused");
    static const uint8_t reserved[] = { 0x80, 0x00 };
    expect(name_unpack(reserved, sizeof reserved, 0, name, &nlen) == (size_t)-1, "a reserved label type: refused");
    static const uint8_t dotted[] = { 3, 'a', '.', 'b', 0 };
    expect(name_unpack(dotted, sizeof dotted, 0, name, &nlen) == (size_t)-1, "a dot inside a label: refused");
    static const uint8_t fine[] = { 4, 'n', 'o', 'd', 'e', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 };
    size_t off = name_unpack(fine, sizeof fine, 0, name, &nlen);
    expect(off == sizeof fine && nlen == 13u && memcmp(name, "node.example.", 13) == 0,
           "labels read into a rooted name, the offset past the end");

    /* A response: one question, an A record whose RDLENGTH says 2 — read as four bytes anyway. */
    static const uint8_t resp[] = {
        0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
        4, 'n', 'o', 'd', 'e', 0, 0, 1, 0, 1,
        0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 2, 192, 0, 2, 12,
    };
    dns_parser p;
    uint8_t    qn[255];
    uint8_t    ql;
    uint16_t   qt, qc;
    expect(p_start(&p, resp, sizeof resp) == DNS_OK && p_question(&p, qn, &ql, &qt, &qc) == DNS_OK &&
               p_skip_question(&p) == DNS_SECTION_DONE,
           "one question, and the section done after it");
    dns_rh  h;
    uint8_t a[4];
    expect(p_resource_header(&p, SEC_ANSWERS, &h) == DNS_OK && h.type == TYPE_A && h.length == 2u &&
               p_addr(&p, TYPE_A, a, 4) == DNS_OK && a[0] == 192 && a[3] == 12,
           "an A record of RDLENGTH 2 still gives four bytes, as AResource reads them");

    /* The query: RD, the question, an OPT for 1232. */
    dns_q q;
    memcpy(q.name, "node.example.", 13);
    q.nlen = 13;
    q.type = TYPE_AAAA;
    uint8_t  req[300];
    uint16_t id;
    size_t   n = new_request(&q, 1, &id, req, sizeof req);
    static const uint8_t tail[] = { 4, 'n', 'o', 'd', 'e', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0,
                                    0, 28, 0, 1, 0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0 };
    expect(n == 12u + sizeof tail && req[0] == 0 && req[1] == n && req[2] == (uint8_t)(id >> 8) &&
               req[4] == 0x01 && req[5] == 0x20 && req[7] == 1 && req[13] == 1 &&
               memcmp(req + 14, tail, sizeof tail) == 0,
           "the query: RD and AD, one question, an OPT record for 1232 bytes");
}

static void hosts(void)
{
    printf("\n/etc/hosts, as readHosts reads it\n");
    const char *p = write_tmp("h", "127.0.0.1 localhost\n"
                                   "192.0.2.22 Node.Example node # a comment\n"
                                   "2001:db8::22 node.example\n"
                                   "::ffff:192.0.2.24 mapped.test\n"
                                   "fe80::1%a%b pct.test\n"
                                   "not-an-address bad.test\n");
    lc_go_resolver_paths(path_resolv, path_nss, p);
    lc_goaddrs l = { 0 };
    lookup_files("NODE.example.", &l);
    expect(l.n == 2u && l.a[0].v4 && l.a[0].ip[15] == 22 && !l.a[1].v4,
           "a name matched without regard to case or the trailing dot, both lines' addresses");
    lc_goaddrs_free(&l);
    lookup_files("node", &l);
    expect(l.n == 1u && l.a[0].v4, "a name without a dot is its own key");
    lc_goaddrs_free(&l);
    lookup_files("mapped.test", &l);
    expect(l.n == 1u && l.a[0].v4 && l.a[0].ip[15] == 24, "a v4-mapped address is IPv4");
    lc_goaddrs_free(&l);
    lookup_files("pct.test", &l);
    expect(l.n == 0u, "a zone holding a '%': dropped, as splitHostZone and ParseIP drop it");
    lc_goaddrs_free(&l);
    lookup_files("bad.test", &l);
    expect(l.n == 0u, "a line whose first field is not an address: skipped");
    lc_goaddrs_free(&l);
    unlink(p);
}

static void order(void)
{
    printf("\nthe order, sortByRFC6724\n");
    /* Loopback beside global: ::1 and 127.0.0.2 come first (their sources match their scope),
     * and IPv4 global ahead of IPv6 global when IPv6 has no route. */
    lc_goaddrs l = { 0 };
    static const uint8_t v4g[4] = { 192, 0, 2, 30 }, v4l[4] = { 127, 0, 0, 2 };
    uint8_t v6l[16] = { 0 };
    v6l[15] = 1;
    (void)addrs_push(&l, v4g, 4, NULL, 0);
    (void)addrs_push(&l, v6l, 16, NULL, 0);
    (void)addrs_push(&l, v4l, 4, NULL, 0);
    sort_rfc6724(&l);
    expect(l.n == 3u && !l.a[0].v4 && l.a[1].v4 && l.a[1].ip[12] == 127 && l.a[2].ip[12] == 192,
           "::1, then 127.0.0.2, then 192.0.2.30 — loopback's precedence and scope first");
    lc_goaddrs_free(&l);
}

int main(void)
{
    printf("\nGo's resolver, the parts without a network (net/goresolve.c)\n");
    resolv_conf();
    names();
    message();
    hosts();
    order();
    printf("\n%s: %d checks, %d failed\n", failures ? "FAILURES" : "all ok", checks, failures);
    return failures ? 1 : 0;
}
