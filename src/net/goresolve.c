/* See net/goresolve.h. Go's pure resolver, go1.27.1, transcribed function by function; each block
 * names the Go it stands for. */
#include "net/goresolve.h"

#include "core/netip.h"
#include "core/rnd.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* if_nametoindex, as POSIX declares it in the system's net/if header — spelled out here because this
 * tree's reference check takes any "net/…" path in a source file for one of ours. */
unsigned int if_nametoindex(const char *ifname);

static const char *path_resolv = "/etc/resolv.conf";
static const char *path_nss = "/etc/nsswitch.conf";
static const char *path_hosts = "/etc/hosts";

void lc_go_resolver_paths(const char *resolv, const char *nsswitch, const char *hosts)
{
    path_resolv = resolv;
    path_nss = nsswitch;
    path_hosts = hosts;
}

static uint64_t mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* A file's modification time as Go compares it — time.Time.Equal on ModTime — and zero when the file
 * cannot be stat'ed, which is what a zero time.Time is. */
typedef struct {
    int64_t sec, nsec;
} mtime_t;

static mtime_t mtime_of(const struct stat *st)
{
    mtime_t m = { (int64_t)st->st_mtim.tv_sec, (int64_t)st->st_mtim.tv_nsec };
    return m;
}

static int mtime_eq(mtime_t a, mtime_t b)
{
    return a.sec == b.sec && a.nsec == b.nsec;
}

/* ---- reading a file as net/parse.go does ------------------------------------------------------
 *
 * A window of 64 KiB (open, GOROOT/src/net/parse.go:72-78) and lines cut at '\n' out of it
 * (getLineFromData and readLine, :25-66): a line that does not fit the window with its newline ends
 * the reading there, since readLine then answers no line at all. */
#define GOFILE_CAP (64u * 1024u)

typedef struct {
    int     fd;
    uint8_t data[GOFILE_CAP];
    size_t  len;
    int     at_eof;
    char    line[GOFILE_CAP + 1u];
} gofile;

static gofile *gofile_open(const char *path, int *err)
{
    gofile *f = malloc(sizeof *f);
    if (f == NULL) {
        *err = ENOMEM;
        return NULL;
    }
    f->fd = open(path, O_RDONLY | O_CLOEXEC);
    if (f->fd < 0) {
        *err = errno;
        free(f);
        return NULL;
    }
    f->len = 0;
    f->at_eof = 0;
    *err = 0;
    return f;
}

static void gofile_close(gofile *f)
{
    if (f != NULL) {
        close(f->fd);
        free(f);
    }
}

static int line_from_data(gofile *f, const char **s, size_t *n)
{
    for (size_t i = 0; i < f->len; i++) {
        if (f->data[i] == '\n') {
            memcpy(f->line, f->data, i);
            f->line[i] = '\0';
            *s = f->line;
            *n = i;
            memmove(f->data, f->data + i + 1u, f->len - i - 1u);
            f->len -= i + 1u;
            return 1;
        }
    }
    if (f->at_eof && f->len > 0u) {
        memcpy(f->line, f->data, f->len);
        f->line[f->len] = '\0';
        *s = f->line;
        *n = f->len;
        f->len = 0;
        return 1;
    }
    return 0;
}

static int gofile_line(gofile *f, const char **s, size_t *n)
{
    if (line_from_data(f, s, n))
        return 1;
    if (f->len < GOFILE_CAP) {
        /* io.ReadFull into the free part of the window: a short read is the end of the file. */
        while (f->len < GOFILE_CAP) {
            ssize_t got = read(f->fd, f->data + f->len, GOFILE_CAP - f->len);
            if (got < 0 && errno == EINTR)
                continue;
            if (got <= 0) {
                if (got == 0)
                    f->at_eof = 1;
                break;
            }
            f->len += (size_t)got;
        }
    }
    return line_from_data(f, s, n);
}

/* ---- the small string helpers of net/parse.go ------------------------------------------------- */

/* splitAtBytes(s, " \r\t\n") — getFields (GOROOT/src/net/parse.go:103-123): the fields, empty ones dropped, into
 * an array sized as Go sizes it, one more than the separators (countAnyByte). NULL when that cannot
 * be had; *count 0 then. */
typedef struct {
    const char *p;
    size_t      n;
} span;

static span *get_fields(const char *s, size_t n, size_t *count)
{
    size_t seps = 0;
    for (size_t i = 0; i < n; i++)
        if (s[i] == ' ' || s[i] == '\r' || s[i] == '\t' || s[i] == '\n')
            seps++;
    span  *out = malloc((seps + 1u) * sizeof *out);
    size_t k = 0, last = 0;
    *count = 0;
    if (out == NULL)
        return NULL;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (c == ' ' || c == '\r' || c == '\t' || c == '\n') {
            if (last < i)
                out[k++] = (span){ s + last, i - last };
            last = i + 1u;
        }
    }
    if (last < n)
        out[k++] = (span){ s + last, n - last };
    *count = k;
    return out;
}

static int span_is(span f, const char *lit)
{
    size_t l = strlen(lit);
    return f.n == l && memcmp(f.p, lit, l) == 0;
}

static int span_has_prefix(span f, const char *lit)
{
    size_t l = strlen(lit);
    return f.n >= l && memcmp(f.p, lit, l) == 0;
}

/* dtoi (GOROOT/src/net/parse.go:130-146): the number, and 0 when no digit leads. */
static int go_dtoi(const char *s, size_t n)
{
    const int big = 0xFFFFFF;
    int       v = 0;
    size_t    i;
    for (i = 0; i < n && s[i] >= '0' && s[i] <= '9'; i++) {
        v = v * 10 + (s[i] - '0');
        if (v >= big)
            return big;
    }
    return i == 0 ? 0 : v;
}

static char lower_ascii(char c)
{
    return c >= 'A' && c <= 'Z' ? (char)(c + ('a' - 'A')) : c;
}

static int is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

/* trimSpace (GOROOT/src/net/parse.go:211-219). */
static span trim_space(span x)
{
    while (x.n > 0u && is_space(x.p[0])) {
        x.p++;
        x.n--;
    }
    while (x.n > 0u && is_space(x.p[x.n - 1u]))
        x.n--;
    return x;
}

/* ---- resolv.conf: dnsReadConfig (GOROOT/src/net/dnsconfig_unix.go:19-145) --------------------- */

typedef struct {
    char     text[80]; /* JoinHostPort(ip, "53"), as Go names the server in its errors */
    lc_netip ip;
    char     zone[16];
} ns_t;

typedef struct {
    unsigned refs;
    ns_t     servers[3];
    unsigned nservers;
    int      default_ns; /* the servers are defaultNS (dnsconfig.go:25-31) */
    char   **search;     /* rooted suffixes */
    unsigned nsearch;
    int      ndots, timeout_s, attempts;
    int      rotate, single_request, use_tcp, trust_ad, no_reload;
    mtime_t  mtime;
    uint32_t soffset; /* serverOffset's counter; under conf_mu */
} dnsconf;

static void dnsconf_free(dnsconf *c)
{
    if (c == NULL)
        return;
    for (unsigned i = 0; i < c->nsearch; i++)
        free(c->search[i]);
    free(c->search);
    free(c);
}

/* ensureRooted (dnsconfig_unix.go:159-164). */
static char *ensure_rooted(const char *s, size_t n)
{
    int   rooted = n > 0u && s[n - 1u] == '.';
    char *r = malloc(n + 2u);
    if (r == NULL)
        return NULL;
    memcpy(r, s, n);
    if (!rooted)
        r[n++] = '.';
    r[n] = '\0';
    return r;
}

static int search_add(dnsconf *c, char *s)
{
    char **g = realloc(c->search, (c->nsearch + 1u) * sizeof *g);
    if (g == NULL) {
        free(s);
        return -1;
    }
    c->search = g;
    c->search[c->nsearch++] = s;
    return 0;
}

static void search_clear(dnsconf *c)
{
    for (unsigned i = 0; i < c->nsearch; i++)
        free(c->search[i]);
    c->nsearch = 0;
}

/* defaultNS (dnsconfig.go:25): 127.0.0.1:53 and [::1]:53. */
static void default_ns(dnsconf *c)
{
    memset(c->servers, 0, sizeof c->servers);
    static const char *const def[2] = { "127.0.0.1", "::1" };
    for (unsigned i = 0; i < 2u; i++) {
        (void)lc_netip_parse(def[i], strlen(def[i]), &c->servers[i].ip, NULL);
        snprintf(c->servers[i].text, sizeof c->servers[i].text, i == 0 ? "%s:53" : "[%s]:53",
                 def[i]);
    }
    c->nservers = 2;
    c->default_ns = 1;
}

/* dnsDefaultSearch (dnsconfig_unix.go:147-157): the domain of the host's own name, if it has one. */
static void default_search(dnsconf *c)
{
    char hn[256];
    if (gethostname(hn, sizeof hn) != 0)
        return;
    hn[sizeof hn - 1u] = '\0';
    char  *dot = strchr(hn, '.');
    size_t n = strlen(hn);
    if (dot != NULL && (size_t)(dot - hn) < n - 1u) {
        char *s = ensure_rooted(dot + 1, n - (size_t)(dot - hn) - 1u);
        if (s != NULL)
            (void)search_add(c, s);
    }
}

static dnsconf *dns_read_config(const char *path)
{
    dnsconf *c = calloc(1, sizeof *c);
    if (c == NULL)
        return NULL;
    c->refs = 1;
    c->ndots = 1;
    c->timeout_s = 5;
    c->attempts = 2;

    int     err;
    gofile *f = gofile_open(path, &err);
    struct stat st;
    if (f == NULL || fstat(f->fd, &st) != 0) {
        gofile_close(f);
        default_ns(c);
        default_search(c);
        return c;
    }
    c->mtime = mtime_of(&st);

    const char *line;
    size_t      n;
    while (gofile_line(f, &line, &n)) {
        if (n > 0u && (line[0] == ';' || line[0] == '#'))
            continue;
        size_t k;
        span  *fld = get_fields(line, n, &k);
        if (k < 1u) {
            free(fld);
            continue;
        }
        if (span_is(fld[0], "nameserver")) {
            if (k > 1u && c->nservers < 3u) {
                /* One more check: the server must be an IP address — netip.ParseAddr. */
                lc_netip ip;
                if (lc_netip_parse(fld[1].p, fld[1].n, &ip, NULL) == 0) {
                    ns_t *s = &c->servers[c->nservers];
                    memset(s, 0, sizeof *s);
                    s->ip = ip;
                    if (ip.zone_len > 0u && ip.zone_len < sizeof s->zone)
                        memcpy(s->zone, fld[1].p + ip.zone_off, ip.zone_len);
                    /* JoinHostPort: brackets when the host has a colon. */
                    int colon = memchr(fld[1].p, ':', fld[1].n) != NULL;
                    snprintf(s->text, sizeof s->text, colon ? "[%.*s]:53" : "%.*s:53",
                             (int)fld[1].n, fld[1].p);
                    c->nservers++;
                }
            }
        } else if (span_is(fld[0], "domain")) {
            if (k > 1u) {
                search_clear(c);
                char *s = ensure_rooted(fld[1].p, fld[1].n);
                if (s != NULL)
                    (void)search_add(c, s);
            }
        } else if (span_is(fld[0], "search")) {
            search_clear(c);
            for (size_t i = 1; i < k; i++) {
                char *s = ensure_rooted(fld[i].p, fld[i].n);
                if (s == NULL)
                    continue;
                if (strcmp(s, ".") == 0) {
                    free(s);
                    continue;
                }
                (void)search_add(c, s);
            }
        } else if (span_is(fld[0], "options")) {
            for (size_t i = 1; i < k; i++) {
                span s = fld[i];
                if (span_has_prefix(s, "ndots:")) {
                    int v = go_dtoi(s.p + 6, s.n - 6u);
                    c->ndots = v < 0 ? 0 : v > 15 ? 15 : v;
                } else if (span_has_prefix(s, "timeout:")) {
                    int v = go_dtoi(s.p + 8, s.n - 8u);
                    c->timeout_s = v < 1 ? 1 : v;
                } else if (span_has_prefix(s, "attempts:")) {
                    int v = go_dtoi(s.p + 9, s.n - 9u);
                    c->attempts = v < 1 ? 1 : v;
                } else if (span_is(s, "rotate")) {
                    c->rotate = 1;
                } else if (span_is(s, "single-request") || span_is(s, "single-request-reopen")) {
                    c->single_request = 1;
                } else if (span_is(s, "use-vc") || span_is(s, "usevc") || span_is(s, "tcp")) {
                    c->use_tcp = 1;
                } else if (span_is(s, "trust-ad")) {
                    c->trust_ad = 1;
                } else if (span_is(s, "no-reload")) {
                    c->no_reload = 1;
                }
                /* edns0 and anything unknown change nothing for the Go resolver: unknownOpt only
                 * sends a cgo build to libc, and the references have no cgo. */
            }
        }
        /* "lookup" is OpenBSD's; anything else is unknownOpt, which again only matters with cgo. */
        free(fld);
    }
    gofile_close(f);
    if (c->nservers == 0u)
        default_ns(c);
    if (c->nsearch == 0u)
        default_search(c);
    return c;
}

/* resolverConfig (dnsclient_unix.go:368-470): parsed once, then re-checked when a lookup asks and
 * more than five seconds have passed — or at once while the defaults stand in for servers — by one
 * lookup at a time, and re-read only when the file's modification time moved. */
static pthread_mutex_t conf_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t conf_sema = PTHREAD_MUTEX_INITIALIZER;
static dnsconf        *conf_cur;
static uint64_t        conf_checked;

static dnsconf *conf_get(void)
{
    pthread_mutex_lock(&conf_mu);
    if (conf_cur == NULL) {
        conf_cur = dns_read_config(path_resolv);
        conf_checked = mono_ms();
    }
    dnsconf *dc = conf_cur;
    pthread_mutex_unlock(&conf_mu);
    if (dc == NULL)
        return NULL;

    if (!dc->no_reload && pthread_mutex_trylock(&conf_sema) == 0) {
        uint64_t now = mono_ms();
        pthread_mutex_lock(&conf_mu);
        int expired = now > conf_checked + 5000u;
        int recheck = expired || conf_cur->default_ns;
        pthread_mutex_unlock(&conf_mu);
        if (recheck) {
            pthread_mutex_lock(&conf_mu);
            conf_checked = now;
            pthread_mutex_unlock(&conf_mu);
            struct stat st;
            mtime_t     m = { 0, 0 };
            if (stat(path_resolv, &st) == 0)
                m = mtime_of(&st);
            pthread_mutex_lock(&conf_mu);
            int same = mtime_eq(m, conf_cur->mtime);
            pthread_mutex_unlock(&conf_mu);
            if (!same) {
                dnsconf *fresh = dns_read_config(path_resolv);
                if (fresh != NULL) {
                    pthread_mutex_lock(&conf_mu);
                    dnsconf *old = conf_cur;
                    conf_cur = fresh;
                    if (--old->refs == 0u)
                        dnsconf_free(old);
                    pthread_mutex_unlock(&conf_mu);
                }
            }
        }
        pthread_mutex_unlock(&conf_sema);
    }

    pthread_mutex_lock(&conf_mu);
    dc = conf_cur;
    dc->refs++;
    pthread_mutex_unlock(&conf_mu);
    return dc;
}

static void conf_put(dnsconf *c)
{
    pthread_mutex_lock(&conf_mu);
    int last = --c->refs == 0u;
    pthread_mutex_unlock(&conf_mu);
    if (last)
        dnsconf_free(c);
}

/* serverOffset (dnsconfig.go:66-71): with rotate, a counter shared by every lookup under this
 * config; otherwise 0. */
static uint32_t server_offset(dnsconf *c)
{
    if (!c->rotate)
        return 0;
    pthread_mutex_lock(&conf_mu);
    uint32_t v = c->soffset++;
    pthread_mutex_unlock(&conf_mu);
    return v;
}

/* ---- nsswitch.conf: parseNSSConf and lookupOrder, the Go resolver's half ----------------------
 *
 * GOROOT/src/net/nss.go:149-247 and GOROOT/src/net/conf.go:241-470 with canUseCgo false, which is the references'
 * case: the criteria in brackets are parsed (a malformed one is an error) but never consulted, and a
 * source that is neither files nor dns counts as dns only when no dns source follows it. */
enum { ORDER_FILES_DNS = 1, ORDER_DNS_FILES, ORDER_FILES, ORDER_DNS };

typedef struct {
    int     err; /* 0, ENOENT, or another errno / EINVAL for a parse error */
    mtime_t mtime;
    char  **hosts; /* the sources of the "hosts" database, in order */
    unsigned nhosts;
    int      have_hosts;
} nssconf;

static void nssconf_free(nssconf *c)
{
    if (c == NULL)
        return;
    for (unsigned i = 0; i < c->nhosts; i++)
        free(c->hosts[i]);
    free(c->hosts);
    free(c);
}

/* parseCriteria (nss.go:222-247): each field "[!]status=action", at least three bytes, with '='. */
static int criteria_ok(span x)
{
    x = trim_space(x);
    while (x.n > 0u) {
        const char *sp = memchr(x.p, ' ', x.n);
        span        field = sp == NULL ? x : trim_space((span){ x.p, (size_t)(sp - x.p) });
        if (field.n > 0u) {
            if (field.p[0] == '!') {
                field.p++;
                field.n--;
            }
            if (field.n < 3u || memchr(field.p, '=', field.n) == NULL)
                return 0;
        }
        if (sp == NULL)
            break;
        x = trim_space((span){ sp + 1, x.n - (size_t)(sp - x.p) - 1u });
    }
    return 1;
}

static nssconf *nss_parse(const char *path)
{
    nssconf *c = calloc(1, sizeof *c);
    if (c == NULL)
        return NULL;
    int     err;
    gofile *f = gofile_open(path, &err);
    if (f == NULL) {
        c->err = err;
        return c;
    }
    struct stat st;
    if (fstat(f->fd, &st) != 0) {
        c->err = errno;
        gofile_close(f);
        return c;
    }
    c->mtime = mtime_of(&st);

    const char *line;
    size_t      n;
    while (gofile_line(f, &line, &n)) {
        /* removeComment, trimSpace */
        const char *hash = memchr(line, '#', n);
        span        l = trim_space((span){ line, hash != NULL ? (size_t)(hash - line) : n });
        if (l.n == 0u)
            continue;
        const char *colon = memchr(l.p, ':', l.n);
        if (colon == NULL) {
            c->err = EINVAL; /* "no colon on line" */
            break;
        }
        span db = trim_space((span){ l.p, (size_t)(colon - l.p) });
        int  is_hosts = db.n == 5u && memcmp(db.p, "hosts", 5) == 0;
        span srcs = { colon + 1, l.n - (size_t)(colon - l.p) - 1u };
        for (;;) {
            srcs = trim_space(srcs);
            if (srcs.n == 0u)
                break;
            const char *sp = memchr(srcs.p, ' ', srcs.n);
            span        src;
            if (sp == NULL) {
                src = srcs;
                srcs.n = 0;
            } else {
                src = (span){ srcs.p, (size_t)(sp - srcs.p) };
                srcs = trim_space((span){ sp + 1, srcs.n - (size_t)(sp - srcs.p) - 1u });
            }
            if (srcs.n > 0u && srcs.p[0] == '[') {
                const char *close_b = memchr(srcs.p, ']', srcs.n);
                if (close_b == NULL) {
                    c->err = EINVAL; /* "unclosed criterion bracket" */
                    goto done;
                }
                if (!criteria_ok((span){ srcs.p + 1, (size_t)(close_b - srcs.p) - 1u })) {
                    c->err = EINVAL; /* "invalid criteria: ..." */
                    goto done;
                }
                srcs = (span){ close_b + 1, srcs.n - (size_t)(close_b - srcs.p) - 1u };
            }
            if (is_hosts) {
                char **g = realloc(c->hosts, (c->nhosts + 1u) * sizeof *g);
                char  *s = malloc(src.n + 1u);
                if (g == NULL || s == NULL) {
                    free(s);
                    if (g != NULL)
                        c->hosts = g;
                    c->err = ENOMEM;
                    goto done;
                }
                memcpy(s, src.p, src.n);
                s[src.n] = '\0';
                c->hosts = g;
                c->hosts[c->nhosts++] = s;
                c->have_hosts = 1;
            }
        }
    }
done:
    gofile_close(f);
    return c;
}

/* nsswitchConfig.tryUpdate (nss.go:49-76): at most every five seconds, and re-parsed only when the
 * modification time moved. */
static pthread_mutex_t nss_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t nss_sema = PTHREAD_MUTEX_INITIALIZER;
static nssconf        *nss_cur;
static uint64_t        nss_checked;

static int lookup_order(void)
{
    pthread_mutex_lock(&nss_mu);
    if (nss_cur == NULL) {
        nss_cur = nss_parse(path_nss);
        nss_checked = mono_ms();
    }
    pthread_mutex_unlock(&nss_mu);
    if (pthread_mutex_trylock(&nss_sema) == 0) {
        uint64_t now = mono_ms();
        if (!(nss_checked + 5000u > now)) {
            nss_checked = now;
            struct stat st;
            mtime_t     m = { 0, 0 };
            if (stat(path_nss, &st) == 0)
                m = mtime_of(&st);
            pthread_mutex_lock(&nss_mu);
            int same = nss_cur != NULL && mtime_eq(m, nss_cur->mtime);
            pthread_mutex_unlock(&nss_mu);
            if (!same) {
                nssconf *fresh = nss_parse(path_nss);
                if (fresh != NULL) {
                    pthread_mutex_lock(&nss_mu);
                    nssconf_free(nss_cur);
                    nss_cur = fresh;
                    pthread_mutex_unlock(&nss_mu);
                }
            }
        }
        pthread_mutex_unlock(&nss_sema);
    }

    pthread_mutex_lock(&nss_mu);
    nssconf *nss = nss_cur;
    int      order = ORDER_FILES_DNS;
    if (nss == NULL || nss->err == ENOENT || (nss->err == 0 && nss->nhosts == 0u)) {
        order = ORDER_FILES_DNS;
    } else if (nss->err != 0) {
        order = ORDER_FILES_DNS; /* fallbackOrder */
    } else {
        int         has_dns = 0, has_dns_checked = 0, files = 0, dns = 0;
        const char *first = NULL;
        for (unsigned i = 0; i < nss->nhosts; i++) {
            const char *s = nss->hosts[i];
            if (strcmp(s, "files") == 0 || strcmp(s, "dns") == 0) {
                if (strcmp(s, "files") == 0) {
                    files = 1;
                } else {
                    has_dns = 1;
                    has_dns_checked = 1;
                    dns = 1;
                }
                if (first == NULL)
                    first = s;
                continue;
            }
            if (!has_dns_checked) {
                has_dns_checked = 1;
                for (unsigned j = i + 1u; j < nss->nhosts; j++) {
                    if (strcmp(nss->hosts[j], "dns") == 0) {
                        has_dns = 1;
                        break;
                    }
                }
            }
            if (!has_dns) {
                dns = 1;
                if (first == NULL)
                    first = "dns";
            }
        }
        if (files && dns)
            order = strcmp(first, "files") == 0 ? ORDER_FILES_DNS : ORDER_DNS_FILES;
        else if (files)
            order = ORDER_FILES;
        else if (dns)
            order = ORDER_DNS;
        else
            order = ORDER_FILES_DNS;
    }
    pthread_mutex_unlock(&nss_mu);
    return order;
}

/* ---- /etc/hosts: readHosts and lookupStaticHost (GOROOT/src/net/hosts.go:52-147) ---------------
 *
 * Kept five seconds (cacheMaxAge, :16), and past that re-read only when the size or the modification
 * time moved. A file that cannot be opened for any reason but "not there" or "not allowed" leaves the
 * old entries in place. Keys are the names lowercased and made absolute (absDomainName: a trailing dot
 * for any name with a dot in it); each key keeps the addresses of every line naming it, in order, and
 * the canonical name of the first such line. */
/* The addresses are kept as parsed. Go keeps ip.String() and parses it again with splitHostZone and
 * ParseIP in goLookupIPFiles (dnsclient_unix.go:618-631), which gives back the same bytes — except
 * for a zone that itself holds a '%': splitHostZone cuts at the LAST one (GOROOT/src/net/
 * ipsock.go:220-230), the host part then fails ParseIP and the address is dropped. Such an address
 * is dropped here, where it is read. */
typedef struct {
    char     *key;
    char     *canonical;
    lc_goip  *addrs;
    unsigned  naddrs;
} host_ent;

static pthread_mutex_t hosts_mu = PTHREAD_MUTEX_INITIALIZER;
static host_ent       *hosts_ents;
static unsigned        hosts_n;
static uint64_t        hosts_expire; /* monotonic ms; 0 before the first read */
static const char     *hosts_path;
static mtime_t         hosts_mtime;
static int64_t         hosts_size;

static void hosts_free(host_ent *e, unsigned n)
{
    for (unsigned i = 0; i < n; i++) {
        free(e[i].key);
        free(e[i].canonical);
        free(e[i].addrs);
    }
    free(e);
}

/* absDomainName (GOROOT/src/net/dnsclient.go:156-161), into a fresh string. */
static char *abs_domain_name(const char *s, size_t n)
{
    int   dot = memchr(s, '.', n) != NULL && s[n - 1u] != '.';
    char *r = malloc(n + 2u);
    if (r == NULL)
        return NULL;
    memcpy(r, s, n);
    if (dot)
        r[n++] = '.';
    r[n] = '\0';
    return r;
}

static host_ent *hosts_find(host_ent *e, unsigned n, const char *key)
{
    for (unsigned i = 0; i < n; i++)
        if (strcmp(e[i].key, key) == 0)
            return &e[i];
    return NULL;
}

static int ip_append(lc_goip **list, unsigned *n, const lc_goip *ip)
{
    lc_goip *g = realloc(*list, (*n + 1u) * sizeof *g);
    if (g == NULL)
        return -1;
    *list = g;
    g[(*n)++] = *ip;
    return 0;
}

static void read_hosts(void)
{
    uint64_t now = mono_ms();
    const char *hp = path_hosts;
    if (hosts_expire != 0u && now < hosts_expire && hosts_path == hp && hosts_n > 0u)
        return;
    struct stat st;
    int         st_ok = stat(hp, &st) == 0;
    mtime_t     m = { 0, 0 };
    int64_t     size = 0;
    if (st_ok) {
        m = mtime_of(&st);
        size = (int64_t)st.st_size;
    }
    if (st_ok && hosts_path == hp && mtime_eq(hosts_mtime, m) && hosts_size == size) {
        hosts_expire = now + 5000u;
        return;
    }

    host_ent *hs = NULL;
    unsigned  hn = 0;
    int       err;
    gofile   *f = gofile_open(hp, &err);
    if (f == NULL && err != ENOENT && err != EACCES && err != EPERM)
        return;
    if (f != NULL) {
        const char *line;
        size_t      n;
        while (gofile_line(f, &line, &n)) {
            const char *hash = memchr(line, '#', n);
            if (hash != NULL)
                n = (size_t)(hash - line);
            size_t k;
            span  *fl = get_fields(line, n, &k);
            if (k < 2u) {
                free(fl);
                continue;
            }
            lc_netip ip;
            if (lc_netip_parse(fl[0].p, fl[0].n, &ip, NULL) != 0) {
                free(fl);
                continue;
            }
            static const uint8_t mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
            lc_goip addr;
            memset(&addr, 0, sizeof addr);
            memcpy(addr.ip, ip.ip, 16);
            addr.v4 = ip.is4 || memcmp(ip.ip, mapped, 12) == 0;
            if (ip.zone_len > 0u && ip.zone_len < sizeof addr.zone)
                memcpy(addr.zone, fl[0].p + ip.zone_off, ip.zone_len);
            int dropped = ip.zone_len > 0u && (memchr(fl[0].p + ip.zone_off, '%', ip.zone_len) != NULL ||
                                               ip.zone_len >= sizeof addr.zone);
            char *canonical = NULL;
            for (size_t i = 1; i < k; i++) {
                char lowered[GOFILE_CAP];
                for (size_t j = 0; j < fl[i].n; j++)
                    lowered[j] = lower_ascii(fl[i].p[j]);
                char *key = abs_domain_name(lowered, fl[i].n);
                if (key == NULL)
                    continue;
                if (i == 1u) {
                    free(canonical);
                    canonical = strdup(key);
                }
                host_ent *e = hosts_find(hs, hn, key);
                if (e != NULL) {
                    if (!dropped)
                        (void)ip_append(&e->addrs, &e->naddrs, &addr);
                    free(key);
                    continue;
                }
                host_ent *g = realloc(hs, (hn + 1u) * sizeof *g);
                if (g == NULL) {
                    free(key);
                    continue;
                }
                hs = g;
                memset(&hs[hn], 0, sizeof hs[hn]);
                hs[hn].key = key;
                hs[hn].canonical = canonical != NULL ? strdup(canonical) : NULL;
                if (!dropped)
                    (void)ip_append(&hs[hn].addrs, &hs[hn].naddrs, &addr);
                hn++;
            }
            free(canonical);
            free(fl);
        }
        gofile_close(f);
    }
    hosts_free(hosts_ents, hosts_n);
    hosts_ents = hs;
    hosts_n = hn;
    hosts_expire = now + 5000u;
    hosts_path = hp;
    hosts_mtime = m;
    hosts_size = size;
}

/* ---- the answer's addresses -------------------------------------------------------------------- */

static int addrs_push(lc_goaddrs *l, const uint8_t *ip, size_t len, const char *zone, size_t zlen)
{
    lc_goip *g = realloc(l->a, (l->n + 1u) * sizeof *g);
    if (g == NULL)
        return -1;
    l->a = g;
    lc_goip *a = &l->a[l->n++];
    memset(a, 0, sizeof *a);
    static const uint8_t mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
    if (len == 4u) {
        memcpy(a->ip, mapped, 12);
        memcpy(a->ip + 12, ip, 4);
        a->v4 = 1;
    } else {
        memcpy(a->ip, ip, 16);
        /* net.IP.To4: a v4-mapped sixteen-byte address is IPv4 to everything that dials it. */
        a->v4 = memcmp(ip, mapped, 12) == 0;
    }
    if (zlen > 0u && zlen < sizeof a->zone)
        memcpy(a->zone, zone, zlen);
    return 0;
}

void lc_goaddrs_free(lc_goaddrs *l)
{
    free(l->a);
    l->a = NULL;
    l->n = 0;
}

/* ---- RFC 6724: sortByRFC6724 (GOROOT/src/net/addrselect.go:14-376) ------------------------------ */

typedef struct {
    int     valid;
    uint8_t ip[16]; /* v4 as v4-mapped */
    int     v4;     /* Is4 or Is4In6: everything in this file treats the two alike, as netip does */
    int     v6pure; /* Is6 and not Is4In6 */
} naddr;

typedef struct {
    uint8_t scope, precedence, label;
} ipattr;

typedef struct {
    lc_goip addr;
    ipattr  addr_attr;
    naddr   src;
    ipattr  src_attr;
} rinfo;

static naddr naddr_of(const lc_goip *a)
{
    naddr n;
    n.valid = 1;
    memcpy(n.ip, a->ip, 16);
    n.v4 = a->v4;
    n.v6pure = !a->v4;
    return n;
}

/* The policy table of RFC 6724 section 2.1, longest prefix first (addrselect.go:218-280). */
static const struct {
    uint8_t prefix[16];
    int     bits;
    uint8_t precedence, label;
} policy[] = {
    { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 128, 50, 0 },
    { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff }, 96, 35, 4 },
    { { 0 }, 96, 1, 3 },
    { { 0x20, 0x01 }, 32, 5, 5 },
    { { 0x20, 0x02 }, 16, 30, 2 },
    { { 0x3f, 0xfe }, 16, 1, 12 },
    { { 0xfe, 0xc0 }, 10, 1, 11 },
    { { 0xfc }, 7, 3, 13 },
    { { 0 }, 0, 40, 1 },
};

static int prefix_contains(const uint8_t *p, int bits, const uint8_t *ip)
{
    int full = bits / 8, rest = bits % 8;
    if (memcmp(p, ip, (size_t)full) != 0)
        return 0;
    if (rest == 0)
        return 1;
    uint8_t mask = (uint8_t)(0xffu << (8 - rest));
    return (p[full] & mask) == (ip[full] & mask);
}

/* classifyScope (addrselect.go:308-326). */
static uint8_t classify_scope(const naddr *a)
{
    const uint8_t *b = a->ip;
    int            loop = a->v4 ? b[12] == 127 : memcmp(b, (const uint8_t[16]){ [15] = 1 }, 16) == 0;
    int            link = a->v4 ? (b[12] == 169 && b[13] == 254) : (b[0] == 0xfe && (b[1] & 0xc0) == 0x80);
    if (loop || link)
        return 0x2;
    if (a->v6pure && b[0] == 0xff)
        return (uint8_t)(b[1] & 0xf);
    if (a->v6pure && b[0] == 0xfe && (b[1] & 0xc0) == 0xc0)
        return 0x5;
    return 0xe;
}

/* ipAttrOf (addrselect.go:67-77). */
static ipattr ip_attr_of(const naddr *a)
{
    ipattr r = { 0, 0, 0 };
    if (!a->valid)
        return r;
    for (size_t i = 0; i < sizeof policy / sizeof policy[0]; i++) {
        if (prefix_contains(policy[i].prefix, policy[i].bits, a->ip)) {
            r.precedence = policy[i].precedence;
            r.label = policy[i].label;
            break;
        }
    }
    r.scope = classify_scope(a);
    return r;
}

/* commonPrefixLen (addrselect.go:335-376): IPv4 against IPv4, else the first 64 bits of IPv6. */
static int common_prefix_len(const naddr *a, const lc_goip *b)
{
    const uint8_t *x, *y;
    size_t         n;
    if (a->v4 != b->v4)
        return 0;
    if (a->v4) {
        x = a->ip + 12;
        y = b->ip + 12;
        n = 4;
    } else {
        x = a->ip;
        y = b->ip;
        n = 8;
    }
    int cpl = 0;
    for (size_t i = 0; i < n; i++) {
        if (x[i] == y[i]) {
            cpl += 8;
            continue;
        }
        int     bits = 8;
        uint8_t ab = x[i], bb = y[i];
        for (;;) {
            ab >>= 1;
            bb >>= 1;
            bits--;
            if (ab == bb)
                return cpl + bits;
        }
    }
    return cpl;
}

/* compareByRFC6724 (addrselect.go:90-208): -1 prefers a, 1 prefers b. */
static int compare_rfc6724(const rinfo *a, const rinfo *b)
{
    if (!a->src.valid && !b->src.valid)
        return 0;
    if (!b->src.valid)
        return -1;
    if (!a->src.valid)
        return 1;
    /* Rule 2: matching scope. */
    if (a->addr_attr.scope == a->src_attr.scope && b->addr_attr.scope != b->src_attr.scope)
        return -1;
    if (a->addr_attr.scope != a->src_attr.scope && b->addr_attr.scope == b->src_attr.scope)
        return 1;
    /* Rule 5: matching label. */
    if (a->src_attr.label == a->addr_attr.label && b->src_attr.label != b->addr_attr.label)
        return -1;
    if (a->src_attr.label != a->addr_attr.label && b->src_attr.label == b->addr_attr.label)
        return 1;
    /* Rule 6: higher precedence. */
    if (a->addr_attr.precedence > b->addr_attr.precedence)
        return -1;
    if (a->addr_attr.precedence < b->addr_attr.precedence)
        return 1;
    /* Rule 8: smaller scope. */
    if (a->addr_attr.scope < b->addr_attr.scope)
        return -1;
    if (a->addr_attr.scope > b->addr_attr.scope)
        return 1;
    /* Rule 9: longest matching prefix, IPv6 only. */
    if (!a->addr.v4 && !b->addr.v4) {
        int ca = common_prefix_len(&a->src, &a->addr);
        int cb = common_prefix_len(&b->src, &b->addr);
        if (ca > cb)
            return -1;
        if (ca < cb)
            return 1;
    }
    return 0;
}

/* slices.SortStableFunc: stableCmpFunc and what it calls (GOROOT/src/slices/zsortanyfunc.go:10-16,
 * :329-487) — insertion sort in blocks of twenty, then symMerge. The comparison above is not a
 * strict weak order, so only this algorithm gives Go's order. */
static void rswap(rinfo *d, int i, int j)
{
    rinfo t = d[i];
    d[i] = d[j];
    d[j] = t;
}

static void insertion_sort(rinfo *d, int a, int b)
{
    for (int i = a + 1; i < b; i++)
        for (int j = i; j > a && compare_rfc6724(&d[j], &d[j - 1]) < 0; j--)
            rswap(d, j, j - 1);
}

static void swap_range(rinfo *d, int a, int b, int n)
{
    for (int i = 0; i < n; i++)
        rswap(d, a + i, b + i);
}

static void rotate(rinfo *d, int a, int m, int b)
{
    int i = m - a, j = b - m;
    while (i != j) {
        if (i > j) {
            swap_range(d, m - i, m, j);
            i -= j;
        } else {
            swap_range(d, m - i, m + j - i, i);
            j -= i;
        }
    }
    swap_range(d, m - i, m, i);
}

static void sym_merge(rinfo *d, int a, int m, int b)
{
    if (m - a == 1) {
        int i = m, j = b;
        while (i < j) {
            int h = (int)((unsigned)(i + j) >> 1);
            if (compare_rfc6724(&d[h], &d[a]) < 0)
                i = h + 1;
            else
                j = h;
        }
        for (int k = a; k < i - 1; k++)
            rswap(d, k, k + 1);
        return;
    }
    if (b - m == 1) {
        int i = a, j = m;
        while (i < j) {
            int h = (int)((unsigned)(i + j) >> 1);
            if (!(compare_rfc6724(&d[m], &d[h]) < 0))
                i = h + 1;
            else
                j = h;
        }
        for (int k = m; k > i; k--)
            rswap(d, k, k - 1);
        return;
    }
    int mid = (int)((unsigned)(a + b) >> 1);
    int n = mid + m;
    int start, r;
    if (m > mid) {
        start = n - b;
        r = mid;
    } else {
        start = a;
        r = m;
    }
    int p = n - 1;
    while (start < r) {
        int c = (int)((unsigned)(start + r) >> 1);
        if (!(compare_rfc6724(&d[p - c], &d[c]) < 0))
            start = c + 1;
        else
            r = c;
    }
    int end = n - start;
    if (start < m && m < end)
        rotate(d, start, m, end);
    if (a < start && start < mid)
        sym_merge(d, a, start, mid);
    if (mid < end && end < b)
        sym_merge(d, mid, end, b);
}

static void stable_sort(rinfo *d, int n)
{
    int block = 20;
    int a = 0, b = block;
    while (b <= n) {
        insertion_sort(d, a, b);
        a = b;
        b += block;
    }
    insertion_sort(d, a, n);
    while (block < n) {
        a = 0;
        b = 2 * block;
        while (b <= n) {
            sym_merge(d, a, a + block, b);
            a = b;
            b += 2 * block;
        }
        int m = a + block;
        if (m < n)
            sym_merge(d, a, m, n);
        block *= 2;
    }
}

/* srcAddrs (addrselect.go:44-59): a UDP socket connected to each address on port 53 — which sends
 * nothing — and the local address the kernel chose for it. */
static naddr src_addr(const lc_goip *a)
{
    naddr none = { 0 };
    int   fd;
    int   rc;
    if (a->v4) {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof sin);
        sin.sin_family = AF_INET;
        sin.sin_port = htons(53);
        memcpy(&sin.sin_addr, a->ip + 12, 4);
        fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (fd < 0)
            return none;
        rc = connect(fd, (struct sockaddr *)&sin, sizeof sin);
    } else {
        struct sockaddr_in6 sin6;
        memset(&sin6, 0, sizeof sin6);
        sin6.sin6_family = AF_INET6;
        sin6.sin6_port = htons(53);
        memcpy(&sin6.sin6_addr, a->ip, 16);
        if (a->zone[0] != '\0') {
            unsigned idx = if_nametoindex(a->zone);
            if (idx == 0u) {
                char *end;
                unsigned long v = strtoul(a->zone, &end, 10);
                idx = *end == '\0' ? (unsigned)v : 0u;
            }
            sin6.sin6_scope_id = idx;
        }
        fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (fd < 0)
            return none;
        rc = connect(fd, (struct sockaddr *)&sin6, sizeof sin6);
    }
    naddr src = none;
    if (rc == 0) {
        struct sockaddr_storage ss;
        socklen_t               len = sizeof ss;
        if (getsockname(fd, (struct sockaddr *)&ss, &len) == 0) {
            lc_goip g;
            memset(&g, 0, sizeof g);
            if (ss.ss_family == AF_INET) {
                static const uint8_t mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
                memcpy(g.ip, mapped, 12);
                memcpy(g.ip + 12, &((struct sockaddr_in *)&ss)->sin_addr, 4);
                g.v4 = 1;
            } else {
                memcpy(g.ip, &((struct sockaddr_in6 *)&ss)->sin6_addr, 16);
                g.v4 = 0;
            }
            src = naddr_of(&g);
            /* A sixteen-byte source that is v4-mapped is Is4In6 to netip, and treated as IPv4
             * wherever this file looks. */
            static const uint8_t mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
            if (!g.v4 && memcmp(g.ip, mapped, 12) == 0) {
                src.v4 = 1;
                src.v6pure = 0;
            }
        }
    }
    close(fd);
    return src;
}

static void sort_rfc6724(lc_goaddrs *l)
{
    if (l->n < 2u)
        return;
    rinfo *inf = malloc(l->n * sizeof *inf);
    if (inf == NULL)
        return;
    for (unsigned i = 0; i < l->n; i++) {
        inf[i].addr = l->a[i];
        naddr d = naddr_of(&l->a[i]);
        inf[i].addr_attr = ip_attr_of(&d);
        inf[i].src = src_addr(&l->a[i]);
        inf[i].src_attr = ip_attr_of(&inf[i].src);
    }
    stable_sort(inf, (int)l->n);
    for (unsigned i = 0; i < l->n; i++)
        l->a[i] = inf[i].addr;
    free(inf);
}

/* ---- the message: golang.org/x/net/dns/dnsmessage, the parts the lookup touches -----------------
 *
 * Transcribed from GOROOT/src/vendor/golang.org/x/net/dns/dnsmessage/message.go (go1.27.1). What a
 * response is accepted as — which records count, which malformation ends the reading and where — is
 * the parser's, so the parser is Go's, including the one habit a rewrite would lose: a header read
 * by AnswerHeader is read AGAIN by the next AnswerHeader unless its body was taken or skipped
 * (resHeaderValid, :617-637), which is how the answer that skipToAnswer stopped at is the first one
 * goLookupIPCNAMEOrder reads. */
enum { DNS_OK = 0, DNS_SECTION_DONE, DNS_NOT_STARTED, DNS_BAD };

enum { SEC_NOT_STARTED = 0, SEC_HEADER, SEC_QUESTIONS, SEC_ANSWERS, SEC_AUTHORITIES, SEC_ADDITIONALS, SEC_DONE };

#define TYPE_A     1u
#define TYPE_CNAME 5u
#define TYPE_AAAA  28u
#define TYPE_OPT   41u
#define CLASS_INET 1u

typedef struct {
    uint16_t id, bits;
    uint16_t count[4]; /* questions, answers, authorities, additionals */
} dns_hdr;

typedef struct {
    uint8_t  name[255];
    uint8_t  len;
    uint16_t type, klass;
    uint32_t ttl;
    uint16_t length;
} dns_rh;

typedef struct {
    const uint8_t *msg;
    size_t         mlen;
    dns_hdr        hdr;
    int            section;
    size_t         off;
    unsigned       index;
    int            rh_valid;
    size_t         rh_off;
    uint16_t       rh_type, rh_length;
} dns_parser;

static int u16_at(const uint8_t *m, size_t mlen, size_t off, uint16_t *v)
{
    if (off + 2u > mlen)
        return -1;
    *v = (uint16_t)(m[off] << 8 | m[off + 1u]);
    return 0;
}

/* Name.unpack (message.go:2048-2123): labels and pointers, at most ten pointers, no '.' inside a
 * label, and a name of 254 bytes or more refused while it is read. Returns the offset after the name
 * in the message, or (size_t)-1. */
static size_t name_unpack(const uint8_t *msg, size_t mlen, size_t off, uint8_t *name, uint8_t *nlen)
{
    size_t cur = off, next = off;
    int    ptr = 0;
    size_t len = 0;
    for (;;) {
        if (cur >= mlen)
            return (size_t)-1; /* errBaseLen */
        unsigned c = msg[cur++];
        switch (c & 0xC0u) {
        case 0x00:
            if (c == 0u)
                goto end;
            if (cur + c > mlen)
                return (size_t)-1; /* errCalcLen */
            for (size_t i = cur; i < cur + c; i++)
                if (msg[i] == '.')
                    return (size_t)-1; /* errInvalidName */
            if (len + c >= 254u)
                return (size_t)-1; /* errNameTooLong */
            if (name != NULL) {
                memcpy(name + len, msg + cur, c);
                name[len + c] = '.';
            }
            len += c + 1u;
            cur += c;
            break;
        case 0xC0:
            if (cur >= mlen)
                return (size_t)-1; /* errInvalidPtr */
            {
                unsigned c1 = msg[cur++];
                if (ptr == 0)
                    next = cur;
                if (++ptr > 10)
                    return (size_t)-1; /* errTooManyPtr */
                cur = (c ^ 0xC0u) << 8 | c1;
            }
            break;
        default:
            return (size_t)-1; /* errReserved */
        }
    }
end:
    if (len == 0u) {
        if (name != NULL)
            name[0] = '.';
        len = 1;
    }
    if (nlen != NULL)
        *nlen = (uint8_t)len;
    if (ptr == 0)
        next = cur;
    return next;
}

/* skipName (message.go:2125-2160). */
static size_t name_skip(const uint8_t *msg, size_t mlen, size_t off)
{
    size_t n = off;
    for (;;) {
        if (n >= mlen)
            return (size_t)-1;
        unsigned c = msg[n++];
        switch (c & 0xC0u) {
        case 0x00:
            if (c == 0u)
                return n;
            n += c;
            if (n > mlen)
                return (size_t)-1;
            break;
        case 0xC0:
            return n + 1u;
        default:
            return (size_t)-1;
        }
    }
}

/* Parser.Start (message.go:573-584). */
static int p_start(dns_parser *p, const uint8_t *msg, size_t mlen)
{
    memset(p, 0, sizeof *p);
    p->msg = msg;
    p->mlen = mlen;
    uint16_t v[6];
    for (int i = 0; i < 6; i++)
        if (u16_at(msg, mlen, (size_t)i * 2u, &v[i]) != 0)
            return DNS_BAD;
    p->hdr.id = v[0];
    p->hdr.bits = v[1];
    for (int i = 0; i < 4; i++)
        p->hdr.count[i] = v[2 + i];
    p->off = 12;
    p->section = SEC_QUESTIONS;
    return DNS_OK;
}

/* checkAdvance (message.go:586-600). */
static int p_advance(dns_parser *p, int sec)
{
    if (p->section < sec)
        return DNS_NOT_STARTED;
    if (p->section > sec)
        return DNS_SECTION_DONE;
    p->rh_valid = 0;
    if (p->index == p->hdr.count[sec - SEC_QUESTIONS]) {
        p->index = 0;
        p->section++;
        return DNS_SECTION_DONE;
    }
    return DNS_OK;
}

/* Parser.Question (message.go:663-684). */
static int p_question(dns_parser *p, uint8_t *name, uint8_t *nlen, uint16_t *type, uint16_t *klass)
{
    int rc = p_advance(p, SEC_QUESTIONS);
    if (rc != DNS_OK)
        return rc;
    size_t off = name_unpack(p->msg, p->mlen, p->off, name, nlen);
    if (off == (size_t)-1 || u16_at(p->msg, p->mlen, off, type) != 0 ||
        u16_at(p->msg, p->mlen, off + 2u, klass) != 0)
        return DNS_BAD;
    p->off = off + 4u;
    p->index++;
    return DNS_OK;
}

/* Parser.SkipQuestion (message.go:707-725). */
static int p_skip_question(dns_parser *p)
{
    int rc = p_advance(p, SEC_QUESTIONS);
    if (rc != DNS_OK)
        return rc;
    size_t off = name_skip(p->msg, p->mlen, p->off);
    if (off == (size_t)-1 || off + 4u > p->mlen)
        return DNS_BAD;
    p->off = off + 4u;
    p->index++;
    return DNS_OK;
}

/* Parser.resourceHeader (message.go:618-637) with ResourceHeader.unpack (:1716-1735). */
static int p_resource_header(dns_parser *p, int sec, dns_rh *h)
{
    if (p->rh_valid)
        p->off = p->rh_off;
    int rc = p_advance(p, sec);
    if (rc != DNS_OK)
        return rc;
    size_t off = name_unpack(p->msg, p->mlen, p->off, h->name, &h->len);
    uint16_t t16a, t16b;
    if (off == (size_t)-1 || u16_at(p->msg, p->mlen, off, &h->type) != 0 ||
        u16_at(p->msg, p->mlen, off + 2u, &h->klass) != 0 || u16_at(p->msg, p->mlen, off + 4u, &t16a) != 0 ||
        u16_at(p->msg, p->mlen, off + 6u, &t16b) != 0 || u16_at(p->msg, p->mlen, off + 8u, &h->length) != 0)
        return DNS_BAD;
    h->ttl = (uint32_t)t16a << 16 | t16b;
    p->rh_valid = 1;
    p->rh_off = p->off;
    p->rh_type = h->type;
    p->rh_length = h->length;
    p->off = off + 10u;
    return DNS_OK;
}

/* Parser.skipResource (message.go:639-661) with skipResource (:1794-1821). */
static int p_skip_resource(dns_parser *p, int sec)
{
    if (p->rh_valid && p->section == sec) {
        size_t n = p->off + p->rh_length;
        if (n > p->mlen)
            return DNS_BAD; /* errResourceLen */
        p->off = n;
        p->rh_valid = 0;
        p->index++;
        return DNS_OK;
    }
    int rc = p_advance(p, sec);
    if (rc != DNS_OK)
        return rc;
    size_t off = name_skip(p->msg, p->mlen, p->off);
    uint16_t length;
    if (off == (size_t)-1 || off + 8u > p->mlen || u16_at(p->msg, p->mlen, off + 8u, &length) != 0)
        return DNS_BAD;
    off += 10u + length;
    if (off > p->mlen)
        return DNS_BAD;
    p->off = off;
    p->index++;
    return DNS_OK;
}

static void p_skip_all(dns_parser *p, int sec)
{
    for (;;)
        if (p_skip_resource(p, sec) != DNS_OK)
            return;
}

/* AResource, AAAAResource (message.go:1026-1060): the body read at the offset whatever the header's
 * length says, and the offset then moved by that length. */
static int p_addr(dns_parser *p, uint16_t type, uint8_t *out, size_t n)
{
    if (!p->rh_valid || p->rh_type != type)
        return DNS_NOT_STARTED;
    if (p->off + n > p->mlen)
        return DNS_BAD; /* errBaseLen */
    memcpy(out, p->msg + p->off, n);
    p->off += p->rh_length;
    p->rh_valid = 0;
    p->index++;
    return DNS_OK;
}

/* CNAMEResource (message.go:900-916). */
static int p_cname(dns_parser *p)
{
    if (!p->rh_valid || p->rh_type != TYPE_CNAME)
        return DNS_NOT_STARTED;
    if (name_unpack(p->msg, p->mlen, p->off, NULL, NULL) == (size_t)-1)
        return DNS_BAD;
    p->off += p->rh_length;
    p->rh_valid = 0;
    p->index++;
    return DNS_OK;
}

/* ---- the exchange: newRequest, the round trips, exchange (dnsclient_unix.go:59-220) ------------ */

#define MAX_DNS_PACKET 1232u /* maxDNSPacketSize (dnsclient_unix.go:39) */

/* Error words, as net's errors print them — for the log line only; nothing here goes on the wire. */
#define E_NOSUCHHOST   "no such host"
#define E_UNMARSHAL    "cannot unmarshal DNS message"
#define E_MARSHAL      "cannot marshal DNS message"
#define E_LAME         "lame referral"
#define E_MISBEHAVING  "server misbehaving"
#define E_NOANSWER     "no answer from DNS server"
#define E_INVALID      "invalid DNS response"
#define E_TIMEOUT      "i/o timeout"
#define E_CANCELLED    "operation was canceled"

typedef struct {
    uint8_t  name[255]; /* rooted, as text */
    uint8_t  nlen;
    uint16_t type;
} dns_q;

/* newRequest (dnsclient_unix.go:59-94): a header with a random ID and RD, AD when trust-ad; the one
 * question; and an OPT record for 1232 bytes with nothing in it. The two-byte length TCP wants in
 * front. Returns the length after the prefix, or 0 when the name does not pack. */
static size_t new_request(const dns_q *q, int ad, uint16_t *id, uint8_t *tcp, size_t cap)
{
    uint8_t r[2];
    if (lc_rnd(r, sizeof r) != 0)
        return 0;
    /* randInt() >> 1 truncated to uint16: the low sixteen bits of a random word. */
    *id = (uint16_t)(r[0] << 8 | r[1]);
    size_t w = 2;
    uint16_t bits = 0x0100u | (ad ? 0x0020u : 0u);
    uint16_t hv[6] = { *id, bits, 1, 0, 0, 1 };
    for (int i = 0; i < 6; i++) {
        tcp[w++] = (uint8_t)(hv[i] >> 8);
        tcp[w++] = (uint8_t)hv[i];
    }
    /* Name.pack without compression (message.go:1976-2046). */
    if (q->nlen == 0u || q->nlen > 254u || q->name[q->nlen - 1u] != '.')
        return 0;
    if (q->nlen == 1u && q->name[0] == '.') {
        tcp[w++] = 0;
    } else {
        size_t begin = 0;
        for (size_t i = 0; i < q->nlen; i++) {
            if (q->name[i] != '.')
                continue;
            size_t seg = i - begin;
            if (seg >= 64u || seg == 0u)
                return 0;
            if (w + 1u + seg + 16u > cap)
                return 0;
            tcp[w++] = (uint8_t)seg;
            memcpy(tcp + w, q->name + begin, seg);
            w += seg;
            begin = i + 1u;
        }
        tcp[w++] = 0;
    }
    tcp[w++] = (uint8_t)(q->type >> 8);
    tcp[w++] = (uint8_t)q->type;
    tcp[w++] = 0;
    tcp[w++] = (uint8_t)CLASS_INET;
    /* The OPT record: root name, type 41, class = the UDP payload size, TTL 0, no data. */
    tcp[w++] = 0;
    tcp[w++] = 0;
    tcp[w++] = (uint8_t)TYPE_OPT;
    tcp[w++] = (uint8_t)(MAX_DNS_PACKET >> 8);
    tcp[w++] = (uint8_t)MAX_DNS_PACKET;
    for (int i = 0; i < 4; i++)
        tcp[w++] = 0;
    tcp[w++] = 0;
    tcp[w++] = 0;
    size_t l = w - 2u;
    tcp[0] = (uint8_t)(l >> 8);
    tcp[1] = (uint8_t)l;
    return l;
}

static int ascii_name_eq(const uint8_t *a, size_t an, const uint8_t *b, size_t bn)
{
    if (an != bn)
        return 0;
    for (size_t i = 0; i < an; i++) {
        uint8_t x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z')
            x += 0x20;
        if (y >= 'A' && y <= 'Z')
            y += 0x20;
        if (x != y)
            return 0;
    }
    return 1;
}

/* checkResponse (dnsclient_unix.go:96-107). */
static int check_response(uint16_t id, const dns_q *q, const dns_parser *p, const uint8_t *rname,
                          uint8_t rlen, uint16_t rtype, uint16_t rclass)
{
    if ((p->hdr.bits & 0x8000u) == 0u)
        return 0;
    if (p->hdr.id != id)
        return 0;
    if (q->type != rtype || rclass != CLASS_INET || !ascii_name_eq(q->name, q->nlen, rname, rlen))
        return 0;
    return 1;
}

/* One exchange's socket and the wait on it: until readable, the deadline, or the cancel descriptor.
 * 1 readable (or writable), 0 timed out, -1 cancelled. */
static int wait_fd(int fd, short ev, uint64_t deadline, int cancel)
{
    for (;;) {
        uint64_t now = mono_ms();
        if (now >= deadline)
            return 0;
        struct pollfd p[2];
        nfds_t        np = 0;
        p[np].fd = fd;
        p[np].events = ev;
        p[np++].revents = 0;
        if (cancel >= 0) {
            p[np].fd = cancel;
            p[np].events = POLLIN;
            p[np++].revents = 0;
        }
        uint64_t left = deadline - now;
        int      rc = poll(p, np, left > 60000u ? 60000 : (int)left);
        if (rc < 0 && errno == EINTR)
            continue;
        if (rc < 0)
            return 0;
        if (np > 1u && p[1].revents != 0)
            return -1;
        if (p[0].revents != 0)
            return 1;
    }
}

typedef struct {
    uint8_t   *buf; /* the response, the parser reads it */
    size_t     len;
    dns_parser p;
} response;

/* The server's socket address. */
static socklen_t server_sa(const ns_t *s, struct sockaddr_storage *ss)
{
    memset(ss, 0, sizeof *ss);
    if (s->ip.is4) {
        struct sockaddr_in *in = (struct sockaddr_in *)ss;
        in->sin_family = AF_INET;
        in->sin_port = htons(53);
        memcpy(&in->sin_addr, s->ip.ip + 12, 4);
        return sizeof *in;
    }
    struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)ss;
    in6->sin6_family = AF_INET6;
    in6->sin6_port = htons(53);
    memcpy(&in6->sin6_addr, s->ip.ip, 16);
    if (s->zone[0] != '\0') {
        unsigned idx = if_nametoindex(s->zone);
        if (idx == 0u) {
            char         *end;
            unsigned long v = strtoul(s->zone, &end, 10);
            idx = *end == '\0' ? (unsigned)v : 0u;
        }
        in6->sin6_scope_id = idx;
    }
    return sizeof *in6;
}

/* exchange (dnsclient_unix.go:169-220): UDP, and TCP when the answer came truncated — or TCP alone
 * with use-vc — each with a deadline of its own, `timeout` from when it starts. Returns 0 with the
 * response, or -1 with `err` set. */
static int exchange(const ns_t *server, const dns_q *q, int timeout_s, int use_tcp, int ad, int cancel,
                    response *out, const char **err)
{
    uint8_t  req[2u + 12u + 256u + 4u + 11u];
    uint16_t id;
    size_t   qlen = new_request(q, ad, &id, req, sizeof req);
    if (qlen == 0u) {
        *err = E_MARSHAL;
        return -1;
    }
    struct sockaddr_storage ss;
    socklen_t               sl = server_sa(server, &ss);

    for (int tcp = use_tcp; tcp <= 1; tcp++) {
        uint64_t deadline = mono_ms() + (uint64_t)timeout_s * 1000u;
        int fd = socket(ss.ss_family, (tcp ? SOCK_STREAM : SOCK_DGRAM) | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (fd < 0) {
            *err = strerror(errno);
            return -1;
        }
        int rc = connect(fd, (struct sockaddr *)&ss, sl);
        if (rc != 0 && errno == EINPROGRESS) {
            int w = wait_fd(fd, POLLOUT, deadline, cancel);
            if (w <= 0) {
                close(fd);
                *err = w < 0 ? E_CANCELLED : E_TIMEOUT;
                return -1;
            }
            int       soerr = 0;
            socklen_t sol = sizeof soerr;
            (void)getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sol);
            rc = soerr == 0 ? 0 : -1;
            errno = soerr;
        }
        if (rc != 0) {
            *err = strerror(errno);
            close(fd);
            return -1;
        }

        uint8_t *buf = NULL;
        size_t   blen = 0;
        dns_parser p;
        int      got = 0;
        if (!tcp) {
            /* dnsPacketRoundTrip (:109-134): anything that does not parse, or answers another
             * question, is ignored and the wait goes on. */
            if (send(fd, req + 2, qlen, MSG_NOSIGNAL) < 0) {
                *err = strerror(errno);
                close(fd);
                return -1;
            }
            buf = malloc(MAX_DNS_PACKET);
            if (buf == NULL) {
                close(fd);
                *err = strerror(ENOMEM);
                return -1;
            }
            for (;;) {
                int w = wait_fd(fd, POLLIN, deadline, cancel);
                if (w <= 0) {
                    *err = w < 0 ? E_CANCELLED : E_TIMEOUT;
                    break;
                }
                ssize_t n = recv(fd, buf, MAX_DNS_PACKET, 0);
                if (n < 0) {
                    if (errno == EAGAIN || errno == EINTR)
                        continue;
                    *err = strerror(errno);
                    break;
                }
                uint8_t  rname[255];
                uint8_t  rlen;
                uint16_t rtype, rclass;
                if (p_start(&p, buf, (size_t)n) != DNS_OK)
                    continue;
                if (p_question(&p, rname, &rlen, &rtype, &rclass) != DNS_OK ||
                    !check_response(id, q, &p, rname, rlen, rtype, rclass))
                    continue;
                blen = (size_t)n;
                got = 1;
                break;
            }
        } else {
            /* dnsStreamRoundTrip (:136-167). */
            size_t sent = 0, total = qlen + 2u;
            while (sent < total) {
                ssize_t n = send(fd, req + sent, total - sent, MSG_NOSIGNAL);
                if (n < 0 && errno == EAGAIN) {
                    int w = wait_fd(fd, POLLOUT, deadline, cancel);
                    if (w <= 0) {
                        *err = w < 0 ? E_CANCELLED : E_TIMEOUT;
                        break;
                    }
                    continue;
                }
                if (n < 0) {
                    *err = strerror(errno);
                    break;
                }
                sent += (size_t)n;
            }
            uint8_t lenb[2];
            size_t  have = 0, want = 2;
            uint8_t *dst = lenb;
            int      ok = sent == total;
            while (ok) {
                if (have == want) {
                    if (dst == lenb) {
                        want = (size_t)(lenb[0] << 8 | lenb[1]);
                        buf = malloc(want > 0u ? want : 1u);
                        if (buf == NULL) {
                            *err = strerror(ENOMEM);
                            ok = 0;
                            break;
                        }
                        dst = buf;
                        have = 0;
                        if (want > 0u)
                            continue;
                    }
                    break;
                }
                int w = wait_fd(fd, POLLIN, deadline, cancel);
                if (w <= 0) {
                    *err = w < 0 ? E_CANCELLED : E_TIMEOUT;
                    ok = 0;
                    break;
                }
                ssize_t n = recv(fd, dst + have, want - have, 0);
                if (n < 0 && (errno == EAGAIN || errno == EINTR))
                    continue;
                if (n <= 0) {
                    *err = n == 0 ? "EOF" : strerror(errno);
                    ok = 0;
                    break;
                }
                have += (size_t)n;
            }
            if (ok) {
                uint8_t  rname[255];
                uint8_t  rlen;
                uint16_t rtype, rclass;
                if (p_start(&p, buf, want) != DNS_OK ||
                    p_question(&p, rname, &rlen, &rtype, &rclass) != DNS_OK) {
                    *err = E_UNMARSHAL;
                } else if (!check_response(id, q, &p, rname, rlen, rtype, rclass)) {
                    *err = E_INVALID;
                } else {
                    blen = want;
                    got = 1;
                }
            }
        }
        close(fd);
        if (!got) {
            free(buf);
            return -1;
        }
        /* One question and no more: SkipQuestion must find the section done. */
        if (p_skip_question(&p) != DNS_SECTION_DONE) {
            free(buf);
            *err = E_INVALID;
            return -1;
        }
        /* A truncated UDP answer is asked again over TCP; a truncated TCP one is taken as it is. */
        if (!tcp && (p.hdr.bits & 0x0200u) != 0u) {
            free(buf);
            continue;
        }
        out->buf = buf;
        out->len = blen;
        out->p = p;
        out->p.msg = buf;
        return 0;
    }
    *err = E_NOANSWER;
    return -1;
}

/* extractExtendedRCode (dnsclient_unix.go:276-295), on a copy of the parser. */
static unsigned extended_rcode(dns_parser p, int *has_add)
{
    unsigned rcode = p.hdr.bits & 0xFu;
    p_skip_all(&p, SEC_ANSWERS);
    p_skip_all(&p, SEC_AUTHORITIES);
    *has_add = 0;
    for (;;) {
        dns_rh h;
        if (p_resource_header(&p, SEC_ADDITIONALS, &h) != DNS_OK)
            return rcode;
        *has_add = 1;
        if (h.type == TYPE_OPT) {
            if ((h.ttl & 0x00ff0000u) == 0u)
                return (h.ttl >> 24 << 4) | rcode;
            return rcode;
        }
        if (p_skip_resource(&p, SEC_ADDITIONALS) != DNS_OK)
            return rcode;
    }
}

/* checkHeader (dnsclient_unix.go:222-253). NULL when the header is fine. */
static const char *check_header(dns_parser *p)
{
    int      has_add;
    unsigned rcode = extended_rcode(*p, &has_add);
    if (rcode == 3u)
        return E_NOSUCHHOST;
    dns_rh h;
    int    rc = p_resource_header(p, SEC_ANSWERS, &h);
    if (rc != DNS_OK && rc != DNS_SECTION_DONE)
        return E_UNMARSHAL;
    int aa = (p->hdr.bits & 0x0400u) != 0u, ra = (p->hdr.bits & 0x0080u) != 0u;
    if (rcode == 0u && !aa && !ra && rc == DNS_SECTION_DONE && !has_add)
        return E_LAME;
    if (rcode != 0u && rcode != 3u)
        return E_MISBEHAVING; /* errServerTemporarilyMisbehaving for SERVFAIL, same words */
    return NULL;
}

/* skipToAnswer (dnsclient_unix.go:255-274). */
static const char *skip_to_answer(dns_parser *p, uint16_t qtype)
{
    for (;;) {
        dns_rh h;
        int    rc = p_resource_header(p, SEC_ANSWERS, &h);
        if (rc == DNS_SECTION_DONE)
            return E_NOSUCHHOST;
        if (rc != DNS_OK)
            return E_UNMARSHAL;
        if (h.type == qtype)
            return NULL;
        if (p_skip_resource(p, SEC_ANSWERS) != DNS_OK)
            return E_UNMARSHAL;
    }
}

typedef struct {
    int      ok;         /* a response to read answers from */
    int      nosuchhost; /* the name does not exist: no other server is asked */
    response r;
    char     err[200];
} one_name;

/* tryOneName (dnsclient_unix.go:297-366), with the serverOffset it takes first handed in by the
 * caller, which decides the order the two queries of a name take theirs in — see the lookup. `shown`
 * is the name the error speaks of: goLookupIPCNAMEOrder puts the original one back (:825-830). */
static void try_one_name(dnsconf *cfg, const char *name, uint16_t qtype, int cancel, uint32_t off,
                         const char *shown, one_name *res)
{
    memset(res, 0, sizeof *res);
    dns_q q;
    size_t nl = strlen(name);
    if (nl > 255u) {
        snprintf(res->err, sizeof res->err, "lookup %s: %s", shown, E_MARSHAL);
        return;
    }
    memcpy(q.name, name, nl);
    q.nlen = (uint8_t)nl;
    q.type = qtype;

    uint32_t sl = cfg->nservers;
    for (int i = 0; i < cfg->attempts; i++) {
        for (uint32_t j = 0; j < sl; j++) {
            const ns_t *server = &cfg->servers[(off + j) % sl];
            const char *err = NULL;
            response    r;
            if (exchange(server, &q, cfg->timeout_s, cfg->use_tcp, cfg->trust_ad, cancel, &r, &err) != 0) {
                snprintf(res->err, sizeof res->err, "lookup %s on %s: %s", shown, server->text, err);
                if (strcmp(err, E_CANCELLED) == 0)
                    return;
                continue;
            }
            const char *bad = check_header(&r.p);
            if (bad == NULL)
                bad = skip_to_answer(&r.p, qtype);
            if (bad != NULL) {
                snprintf(res->err, sizeof res->err, "lookup %s on %s: %s", shown, server->text, bad);
                if (strcmp(bad, E_NOSUCHHOST) == 0) {
                    /* The name does not exist, so trying another server won't help. */
                    free(r.buf);
                    res->nosuchhost = 1;
                    return;
                }
                free(r.buf);
                continue;
            }
            res->ok = 1;
            res->r = r;
            return;
        }
    }
}

/* ---- the lookup: goLookupIPCNAMEOrder (dnsclient_unix.go:638-848) ------------------------------ */

/* nameList (dnsclient_unix.go:527-576), with avoidDNS (:518-525). */
static int avoid_dns(const char *name)
{
    size_t n = strlen(name);
    if (n == 0u)
        return 1;
    if (name[n - 1u] == '.')
        n--;
    static const char onion[] = ".onion";
    if (n < sizeof onion - 1u)
        return 0;
    for (size_t i = 0; i < sizeof onion - 1u; i++)
        if (lower_ascii(name[n - (sizeof onion - 1u) + i]) != onion[i])
            return 0;
    return 1;
}

static char **name_list(const dnsconf *conf, const char *name, unsigned *count)
{
    *count = 0;
    size_t n = strlen(name);
    int    rooted = n > 0u && name[n - 1u] == '.';
    if (n > 254u || (n == 254u && !rooted))
        return NULL;
    char **out = calloc(conf->nsearch + 2u, sizeof *out);
    if (out == NULL)
        return NULL;
    if (rooted) {
        if (!avoid_dns(name))
            out[(*count)++] = strdup(name);
        return out;
    }
    int dots = 0;
    for (size_t i = 0; i < n; i++)
        dots += name[i] == '.';
    int   has_ndots = dots >= conf->ndots;
    char *base = malloc(n + 2u);
    if (base == NULL)
        return out;
    memcpy(base, name, n);
    base[n] = '.';
    base[n + 1u] = '\0';
    if (has_ndots && !avoid_dns(base))
        out[(*count)++] = strdup(base);
    for (unsigned i = 0; i < conf->nsearch; i++) {
        size_t sl = strlen(conf->search[i]);
        char  *fqdn = malloc(n + 1u + sl + 1u);
        if (fqdn == NULL)
            continue;
        memcpy(fqdn, base, n + 1u);
        memcpy(fqdn + n + 1u, conf->search[i], sl + 1u);
        if (!avoid_dns(fqdn) && strlen(fqdn) <= 254u)
            out[(*count)++] = fqdn;
        else
            free(fqdn);
    }
    if (!has_ndots && !avoid_dns(base))
        out[(*count)++] = strdup(base);
    free(base);
    return out;
}

/* isDomainName (GOROOT/src/net/dnsclient.go:89-150). */
static int is_domain_name(const char *s)
{
    if (strcmp(s, ".") == 0)
        return 1;
    size_t l = strlen(s);
    if (l == 0u || l > 254u || (l == 254u && s[l - 1u] != '.'))
        return 0;
    char last = '.';
    int  non_numeric = 0, partlen = 0;
    for (size_t i = 0; i < l; i++) {
        char c = s[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') {
            non_numeric = 1;
            partlen++;
        } else if (c >= '0' && c <= '9') {
            partlen++;
        } else if (c == '-') {
            if (last == '.')
                return 0;
            partlen++;
            non_numeric = 1;
        } else if (c == '.') {
            if (last == '.' || last == '-')
                return 0;
            if (partlen > 63 || partlen == 0)
                return 0;
            partlen = 0;
        } else {
            return 0;
        }
        last = c;
    }
    if (last == '-' || partlen > 63)
        return 0;
    return non_numeric;
}

/* lookupStaticHost + goLookupIPFiles (GOROOT/src/net/hosts.go:129-147, dnsclient_unix.go:618-631). */
static void lookup_files(const char *name, lc_goaddrs *out)
{
    size_t n = strlen(name);
    char  *lowered = malloc(n + 1u);
    if (lowered == NULL)
        return;
    for (size_t i = 0; i <= n; i++)
        lowered[i] = lower_ascii(name[i]);
    char *key = abs_domain_name(lowered, n);
    free(lowered);
    if (key == NULL)
        return;
    pthread_mutex_lock(&hosts_mu);
    read_hosts();
    host_ent *e = hosts_n != 0u ? hosts_find(hosts_ents, hosts_n, key) : NULL;
    if (e != NULL)
        for (unsigned i = 0; i < e->naddrs; i++)
            (void)addrs_push(out, e->addrs[i].ip, 16, e->addrs[i].zone, strlen(e->addrs[i].zone));
    pthread_mutex_unlock(&hosts_mu);
    free(key);
    sort_rfc6724(out);
}

/* The two queries of a name, run at once as Go runs them — a goroutine each — and handed over in
 * the order they finish, which is the order their addresses are appended in (`lane`). */
typedef struct {
    dnsconf        *cfg;
    const char     *fqdn;
    uint16_t        qtype;
    int             cancel;
    one_name        res;
    pthread_mutex_t *mu;
    pthread_cond_t  *cv;
    int             *order;
    int              seq;
    int              done;
    uint32_t         off;
    const char      *shown;
} query_job;

static void *query_main(void *arg)
{
    query_job *j = arg;
    try_one_name(j->cfg, j->fqdn, j->qtype, j->cancel, j->off, j->shown, &j->res);
    pthread_mutex_lock(j->mu);
    j->seq = (*j->order)++;
    j->done = 1;
    pthread_cond_broadcast(j->cv);
    pthread_mutex_unlock(j->mu);
    return NULL;
}

/* The answers of one response, as the loop at dnsclient_unix.go:718-800 reads them: A and AAAA
 * appended, CNAME and anything else stepped over, and a record that does not unmarshal ends the
 * reading of this response with an error. */
static void read_answers(one_name *r, lc_goaddrs *out, char *last_err, size_t cap, const char *name)
{
    dns_parser *p = &r->r.p;
    for (;;) {
        dns_rh h;
        int    rc = p_resource_header(p, SEC_ANSWERS, &h);
        if (rc != DNS_OK && rc != DNS_SECTION_DONE)
            snprintf(last_err, cap, "lookup %s: %s", name, E_UNMARSHAL);
        if (rc != DNS_OK)
            break;
        if (h.type == TYPE_A) {
            uint8_t a[4];
            if (p_addr(p, TYPE_A, a, 4) != DNS_OK) {
                snprintf(last_err, cap, "lookup %s: %s", name, E_UNMARSHAL);
                break;
            }
            (void)addrs_push(out, a, 4, NULL, 0);
        } else if (h.type == TYPE_AAAA) {
            uint8_t a[16];
            if (p_addr(p, TYPE_AAAA, a, 16) != DNS_OK) {
                snprintf(last_err, cap, "lookup %s: %s", name, E_UNMARSHAL);
                break;
            }
            (void)addrs_push(out, a, 16, NULL, 0);
        } else if (h.type == TYPE_CNAME) {
            if (p_cname(p) != DNS_OK) {
                snprintf(last_err, cap, "lookup %s: %s", name, E_UNMARSHAL);
                break;
            }
        } else if (p_skip_resource(p, SEC_ANSWERS) != DNS_OK) {
            snprintf(last_err, cap, "lookup %s: %s", name, E_UNMARSHAL);
            break;
        }
    }
}

static int cancelled(int cancel)
{
    if (cancel < 0)
        return 0;
    struct pollfd p = { cancel, POLLIN, 0 };
    return poll(&p, 1, 0) > 0;
}

int lc_go_lookup_ip(const char *name, int cancel, lc_goaddrs *out, char *why, size_t why_cap)
{
    out->a = NULL;
    out->n = 0;
    why[0] = '\0';

    int      order = lookup_order();
    dnsconf *conf = conf_get();
    if (conf == NULL) {
        snprintf(why, why_cap, "lookup %s: %s", name, strerror(ENOMEM));
        return -1;
    }

    if (order == ORDER_FILES_DNS || order == ORDER_FILES) {
        lookup_files(name, out);
        if (out->n > 0u) {
            conf_put(conf);
            return 0;
        }
        if (order == ORDER_FILES) {
            conf_put(conf);
            snprintf(why, why_cap, "lookup %s: %s", name, E_NOSUCHHOST);
            return -1;
        }
    }
    if (!is_domain_name(name)) {
        conf_put(conf);
        snprintf(why, why_cap, "lookup %s: %s", name, E_NOSUCHHOST);
        return -1;
    }

    char     last_err[200] = "";
    unsigned nn;
    char   **names = name_list(conf, name, &nn);
    size_t   namelen = strlen(name);
    for (unsigned k = 0; k < nn; k++) {
        const char *fqdn = names[k];
        if (cancelled(cancel)) {
            snprintf(last_err, sizeof last_err, "lookup %s: %s", name, E_CANCELLED);
            break;
        }
        static const uint16_t qtypes[2] = { TYPE_A, TYPE_AAAA };
        query_job       jobs[2];
        pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
        pthread_cond_t  cv = PTHREAD_COND_INITIALIZER;
        int             seq = 0;
        int             order_of[2] = { 0, 1 };
        for (int t = 0; t < 2; t++) {
            memset(&jobs[t], 0, sizeof jobs[t]);
            jobs[t].cfg = conf;
            jobs[t].fqdn = fqdn;
            jobs[t].qtype = qtypes[t];
            jobs[t].cancel = cancel;
            jobs[t].mu = &mu;
            jobs[t].cv = &cv;
            jobs[t].order = &seq;
            jobs[t].shown = name;
        }
        if (conf->single_request) {
            /* Sequential, A then AAAA, each taking its server offset as it starts (responseFn,
             * :688-696). */
            for (int t = 0; t < 2; t++) {
                jobs[t].off = server_offset(conf);
                query_main(&jobs[t]);
            }
        } else {
            /* THE AAAA QUERY FIRST. queryFn starts a goroutine for A and then one for AAAA, and Go's
             * scheduler runs the newest first: it goes into the P's runnext, pushing the A goroutine
             * back into the queue behind it. So the AAAA lookup takes the first server offset — with
             * `rotate` it goes to the first server and A to the second, eight runs of eight on the
             * stand (tools/vendorcap/dnsstand, `rotate`) — and its query usually leaves first. The
             * offsets are handed out here in that order, and the AAAA thread is started first. */
            jobs[1].off = server_offset(conf);
            jobs[0].off = server_offset(conf);
            pthread_t th[2];
            int       started[2] = { 0, 0 };
            started[1] = pthread_create(&th[1], NULL, query_main, &jobs[1]) == 0;
            started[0] = pthread_create(&th[0], NULL, query_main, &jobs[0]) == 0;
            for (int t = 0; t < 2; t++) {
                if (started[t])
                    pthread_join(th[t], NULL);
                else
                    query_main(&jobs[t]);
            }
            if (jobs[1].seq < jobs[0].seq) {
                order_of[0] = 1;
                order_of[1] = 0;
            }
        }
        pthread_cond_destroy(&cv);
        pthread_mutex_destroy(&mu);

        for (int t = 0; t < 2; t++) {
            one_name *r = &jobs[order_of[t]].res;
            if (!r->ok) {
                /* Prefer the error for the original name (:708-712). */
                int original = strlen(fqdn) == namelen + 1u && strncmp(fqdn, name, namelen) == 0 &&
                               fqdn[namelen] == '.';
                if (last_err[0] == '\0' || original)
                    snprintf(last_err, sizeof last_err, "%s", r->err);
                continue;
            }
            read_answers(r, out, last_err, sizeof last_err, name);
        }
        for (int t = 0; t < 2; t++)
            free(jobs[t].res.r.buf);
        if (out->n > 0u)
            break;
    }
    for (unsigned k = 0; k < nn; k++)
        free(names[k]);
    free(names);
    conf_put(conf);

    sort_rfc6724(out);
    if (out->n == 0u) {
        if (order == ORDER_DNS_FILES) {
            lookup_files(name, out);
            if (out->n > 0u)
                return 0;
        }
        if (last_err[0] != '\0') {
            snprintf(why, why_cap, "%s", last_err);
            return -1;
        }
        /* No name to ask at all — .onion, or every suffix too long — and no error: Go answers an
         * empty list, and the dial is what fails, with errNoSuitableAddress. */
    }
    return 0;
}

socklen_t lc_goip_sockaddr(const lc_goip *a, uint16_t port, struct sockaddr_storage *ss)
{
    memset(ss, 0, sizeof *ss);
    if (a->v4) {
        struct sockaddr_in *in = (struct sockaddr_in *)ss;
        in->sin_family = AF_INET;
        in->sin_port = htons(port);
        memcpy(&in->sin_addr, a->ip + 12, 4);
        return sizeof *in;
    }
    struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)ss;
    in6->sin6_family = AF_INET6;
    in6->sin6_port = htons(port);
    memcpy(&in6->sin6_addr, a->ip, 16);
    if (a->zone[0] != '\0') {
        /* A zone is an interface name, or failing that a number (zoneCache.index, GOROOT/src/net/
         * interface.go). */
        unsigned idx = if_nametoindex(a->zone);
        if (idx == 0u) {
            char         *end;
            unsigned long v = strtoul(a->zone, &end, 10);
            idx = *end == '\0' ? (unsigned)v : 0u;
        }
        in6->sin6_scope_id = idx;
    }
    return sizeof *in6;
}

int lc_goip_literal(const char *s, lc_goip *out)
{
    lc_netip ip;
    size_t   n = strlen(s);
    if (n == 0u || lc_netip_parse(s, n, &ip, NULL) != 0)
        return -1;
    static const uint8_t mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
    memset(out, 0, sizeof *out);
    memcpy(out->ip, ip.ip, 16);
    out->v4 = ip.is4 || memcmp(ip.ip, mapped, 12) == 0;
    if (ip.zone_len > 0u) {
        if (ip.zone_len >= sizeof out->zone)
            return -1;
        memcpy(out->zone, s + ip.zone_off, ip.zone_len);
    }
    return 0;
}
