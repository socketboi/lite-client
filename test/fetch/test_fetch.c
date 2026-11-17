/* The spider's fetch against a site that answers the way tools/vendorcap/spiderredir's did.
 *
 * A scripted site — its own HPACK encoder, so the fetch's decoder has a dynamic table to follow —
 * answers the first request; what the fetch writes back is parsed frame by frame and its HEADERS
 * decoded with a decoder per connection, as the site's own would. What is asserted is what the
 * reference wrote on the stand, 24 September: another HEADERS on stream 3 with the referer and the
 * first request's headers, ten requests and no eleventh, the window for an unread body before the
 * next request, a second preface for another host with the cookie left behind — and nothing where
 * it wrote nothing. The order of the walked headers is a draw and is not asserted; the SET is. */
#include "reality/paths.h"
#include "reality/spider.h"

#include "h2/frame.h"
#include "h2/hpack.h"

#include "core/gozip.h"
#include "spiderflow_vectors.h"
#include "spiderpool_vectors.h"
#include "header_budget_reference.h"

#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <zlib.h>

static int failures;

static uint64_t monotonic_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        abort();
    return (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
}

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

#define HOST "stand.example"

/* One draw from the name's set: whether it is `want`. */
static int drawn_is(const char *host, const char *want)
{
    char  *p = NULL;
    size_t n = 0;
    int    is = lc_spider_path(host, &p, &n) == 0 && n == strlen(want) && memcmp(p, want, n) == 0;
    free(p);
    return is;
}

/* ---- the site -------------------------------------------------------------------------------- */

typedef struct {
    lc_hpack_enc enc;
    uint8_t      buf[1u << 17];
    size_t       len;
} site;

static void frame(site *s, uint8_t type, uint8_t flags, uint32_t stream, const void *p, size_t n)
{
    s->len += lc_h2_put_header(s->buf + s->len, sizeof s->buf - s->len, (uint32_t)n, type, flags,
                               stream);
    if (n > 0u)
        memcpy(s->buf + s->len, p, n);
    s->len += n;
}

static void settings(site *s, uint16_t id, uint32_t v)
{
    uint8_t p[6] = { (uint8_t)(id >> 8), (uint8_t)id, (uint8_t)(v >> 24), (uint8_t)(v >> 16),
                     (uint8_t)(v >> 8), (uint8_t)v };
    frame(s, LC_H2_SETTINGS, 0, 0, p, id == 0u ? 0u : sizeof p);
}

static void answer(site *s, uint32_t stream, int end, const char *status, const char *location,
                   const char *length, const char *encoding)
{
    lc_hpack_field fs[6];
    unsigned       n = 0;
    fs[n++] = (lc_hpack_field){ ":status", status };
    fs[n++] = (lc_hpack_field){ "server", "stand" };
    if (location != NULL)
        fs[n++] = (lc_hpack_field){ "location", location };
    if (length != NULL)
        fs[n++] = (lc_hpack_field){ "content-length", length };
    if (encoding != NULL)
        fs[n++] = (lc_hpack_field){ "content-encoding", encoding };
    uint8_t block[4096];
    long    bl = lc_hpack_enc_block(&s->enc, fs, n, block, sizeof block);
    frame(s, LC_H2_HEADERS, (uint8_t)(LC_H2_END_HEADERS | (end ? LC_H2_END_STREAM : 0u)), stream,
          block, (size_t)bl);
}

static void body(site *s, uint32_t stream, const uint8_t *p, size_t n, int end)
{
    while (n > 0u || end) {
        size_t chunk = n < 16384u ? n : 16384u;
        int    last = chunk == n;
        frame(s, LC_H2_DATA, (uint8_t)(last && end ? LC_H2_END_STREAM : 0u), stream, p, chunk);
        p += chunk;
        n -= chunk;
        if (last)
            break;
    }
}

static void filler(site *s, uint32_t stream, size_t n, int end)
{
    static uint8_t x[1u << 16];
    memset(x, 'x', sizeof x);
    body(s, stream, x, n, end);
}

/* Everything the site wrote, in pieces of `piece` bytes — a frame lands across records as often as
 * not — and then the settle a read of the socket ends with. */
static int deliver(lc_spider_fetch *f, site *s, size_t piece)
{
    int rc = 0;
    for (size_t at = 0; at < s->len && rc == 0;) {
        size_t n = piece == 0u || s->len - at < piece ? s->len - at : piece;
        /* Each piece in a buffer of its own with poison after it, as a record's plaintext is: a
         * reader that ran past the end of what it was given would read the poison, not the next
         * piece that happens to lie there in the site's buffer. */
        static uint8_t one[sizeof s->buf + 64u];
        memcpy(one, s->buf + at, n);
        memset(one + n, 0xa5, 64u);
        rc = lc_spider_fetch_feed(f, one, n);
        at += n;
    }
    s->len = 0;
    if (lc_spider_fetch_settle(f, 0) != 0)
        rc = -1;
    return rc;
}

/* Unlike deliver's third argument (fragment size), this helper supplies the consumer clock. */
static int deliver_at(lc_spider_fetch *f, site *s, uint64_t now)
{
    int rc = lc_spider_fetch_feed(f, s->buf, s->len);
    s->len = 0;
    int settled = lc_spider_fetch_settle(f, now);
    return rc != 0 ? rc : settled;
}

/* ---- what the fetch wrote -------------------------------------------------------------------- */

#define PREFACE_TYPE 0xffu

typedef struct {
    uint8_t  type, flags;
    uint32_t stream, len;
    unsigned write;
    size_t   off; /* of the payload in `bytes` */
} wframe;

typedef struct {
    unsigned writes;
    wframe   fr[512];
    unsigned n;
    uint8_t  bytes[1u << 17];
    size_t   len;
} wire;

static void collect(lc_spider_fetch *f, wire *w)
{
    memset(w, 0, sizeof *w);
    uint8_t *one;
    long           got;
    while ((got = lc_spider_fetch_take(f, &one)) > 0) {
        size_t at = 0;
        if ((size_t)got >= 24u && memcmp(one, "PRI * HTTP/2.0", 14) == 0) {
            w->fr[w->n++] = (wframe){ PREFACE_TYPE, 0, 0, 24, w->writes, 0 };
            at = 24;
        }
        while (at + LC_H2_HEADER <= (size_t)got && w->n < 512u) {
            lc_h2_hd hd;
            if (lc_h2_get_header(one + at, (size_t)got - at, &hd) != 0)
                break;
            memcpy(w->bytes + w->len, one + at + LC_H2_HEADER, hd.len);
            w->fr[w->n++] = (wframe){ hd.type, hd.flags, hd.stream, hd.len, w->writes, w->len };
            w->len += hd.len;
            at += LC_H2_HEADER + hd.len;
        }
        w->writes++;
        free(one);
    }
}

static unsigned count(const wire *w, uint8_t type)
{
    unsigned c = 0;
    for (unsigned i = 0; i < w->n; i++)
        c += w->fr[i].type == type;
    return c;
}

static const wframe *find(const wire *w, uint8_t type, unsigned nth)
{
    for (unsigned i = 0; i < w->n; i++)
        if (w->fr[i].type == type && nth-- == 0u)
            return &w->fr[i];
    return NULL;
}

/* One request as the site would read it: pseudo-headers in order, the rest as a set. */
typedef struct {
    char     pseudo[4][2048];
    char     name[32][64];
    char     value[32][8192];
    unsigned n;
    size_t   block;
} request;

static int read_request(const wire *w, const wframe *h, lc_hpack_dec *d, request *r)
{
    memset(r, 0, sizeof *r);
    if (h == NULL)
        return -1;
    d->in = w->bytes + h->off;
    d->len = h->len;
    d->off = 0;
    r->block = h->len;
    unsigned p = 0;
    int      rc;
    while ((rc = lc_hpack_next(d)) == 1) {
        if (d->name[0] == ':' && p < 4u) {
            snprintf(r->pseudo[p++], sizeof r->pseudo[0], "%.60s=%.1900s", d->name, d->value);
        } else if (r->n < 32u) {
            snprintf(r->name[r->n], sizeof r->name[0], "%.63s", d->name);
            snprintf(r->value[r->n], sizeof r->value[0], "%s", d->value);
            r->n++;
        }
    }
    return rc == 0 ? 0 : -1;
}

static const char *get(const request *r, const char *name)
{
    for (unsigned i = 0; i < r->n; i++)
        if (strcmp(r->name[i], name) == 0)
            return r->value[i];
    return NULL;
}

/* The later request carries every field of the first, value for value, and `extra` besides. */
static int same_set_plus(const request *first, const request *later, const char *extra,
                         const char *without)
{
    unsigned want = first->n + (extra != NULL) - (without != NULL);
    if (later->n != want)
        return 0;
    for (unsigned i = 0; i < first->n; i++) {
        if (without != NULL && strcmp(first->name[i], without) == 0) {
            if (get(later, without) != NULL)
                return 0;
            continue;
        }
        const char *v = get(later, first->name[i]);
        if (v == NULL || strcmp(v, first->value[i]) != 0)
            return 0;
    }
    return extra == NULL || get(later, extra) != NULL;
}

/* ---- a fetch from the start ------------------------------------------------------------------ */

typedef struct {
    lc_spider_fetch *f;
    site             s;
    wire             w;
    lc_hpack_dec     d; /* the site's decoder for the first connection */
    request          first;
} run;

static int start_on(run *r, const char *host)
{
    lc_browser b;
    lc_hpack_dec_free(&r->d);
    memset(&r->d, 0, sizeof r->d);
    lc_hpack_enc_init(&r->s.enc);
    r->s.len = 0;
    if (lc_browser_chrome_anchored(&b, LC_BROWSER_NAV) != 0)
        return -1;
    r->f = lc_spider_fetch_new(host, &b);
    if (r->f != NULL)
        lc_spider_fetch_settle(r->f, 0); /* the first request goes out: nothing had arrived */
    if (r->f == NULL)
        return -1;
    collect(r->f, &r->w);
    if (r->w.writes != 2u || read_request(&r->w, find(&r->w, LC_H2_HEADERS, 0), &r->d, &r->first) != 0)
        return -1;
    settings(&r->s, 0, 0); /* the site's first frame, an empty SETTINGS */
    return 0;
}

static int start(run *r)
{
    return start_on(r, HOST);
}

/* ---- what Go's gzip reader makes of a slurp -------------------------------------------------- */

/* The body whole, as the fetch has it when Do gets to the slurp — every frame in, the stream ended —
 * read by io.CopyN(io.Discard, body, 2048) through core/gozip, and the window those reads and then
 * Close hand back, by inflow.add over the windows the frames left (vendor/x-net/http2/flow.go). */
typedef struct {
    const uint8_t *p;
    size_t         len, at;
    int64_t        s_avail, s_unsent, c_avail, c_unsent;
    uint32_t       stream, conn, consumed;
} oracle;

static void oracle_add(int64_t *avail, int64_t *unsent, uint64_t n, uint32_t *sent)
{
    *unsent += (int64_t)n;
    if (*unsent < 4096 && *unsent < *avail)
        return;
    *sent += (uint32_t)*unsent;
    *avail += *unsent;
    *unsent = 0;
}

static int oracle_src(void *ctx, size_t cap, const uint8_t **p, size_t *n, int *err)
{
    oracle *o = ctx;
    size_t  k = o->len - o->at < cap ? o->len - o->at : cap;
    *p = o->p + o->at;
    *n = k;
    *err = k == 0u ? LC_GZ_EOF : LC_GZ_NONE;
    o->at += k;
    o->consumed += (uint32_t)k;
    if (k > 0u) {
        oracle_add(&o->c_avail, &o->c_unsent, k, &o->conn);
        oracle_add(&o->s_avail, &o->s_unsent, k, &o->stream);
    }
    return 0;
}

static void slurp_oracle(const uint8_t *gz, size_t len, oracle *o)
{
    memset(o, 0, sizeof *o);
    o->p = gz;
    o->len = len;
    o->c_avail = (int64_t)(1u << 30) + 65535 - (int64_t)len;
    o->s_avail = (int64_t)(4u << 20) - (int64_t)len;
    lc_gozip *z = lc_gozip_new(oracle_src, o);
    int64_t   limit = 2048;
    while (z != NULL && limit > 0) {
        const uint8_t *out;
        size_t         n;
        int            err;
        if (lc_gozip_read(z, limit < 8192 ? (size_t)limit : 8192u, &out, &n, &err) != 0)
            break;
        limit -= (int64_t)n;
        if (err != LC_GZ_NONE)
            break;
    }
    lc_gozip_free(z);
    if (o->len > o->at)
        oracle_add(&o->c_avail, &o->c_unsent, o->len - o->at, &o->conn);
}

/* ---- which connection a hop goes out on ------------------------------------------------------ */

static void event(char *ev, size_t cap, const char *e)
{
    size_t n = strlen(ev);
    snprintf(ev + n, cap - n, "%s%s", n != 0u ? "|" : "", e);
}

/* One chain of tools/spiderpool, told as the site there tells it: R and the :authority for a request
 * on the ClientConns there are, P for a second opening and then H for a request after it or C for
 * the connection closed, D when Do has returned with the connection open. The site answers every
 * request with the next Location, a 200 once they run out, and acknowledges every SETTINGS. */
static void pool_events(const char *host, const char *const *locs, char *ev, size_t cap)
{
    static site    s;
    static wire    w;
    static request q;
    lc_hpack_dec   d;
    lc_browser     b;
    ev[0] = '\0';
    memset(&d, 0, sizeof d);
    lc_hpack_enc_init(&s.enc);
    s.len = 0;
    if (lc_browser_chrome_anchored(&b, LC_BROWSER_NAV) != 0) {
        event(ev, cap, "no browser");
        return;
    }
    lc_spider_fetch *f = lc_spider_fetch_new(host, &b);
    if (f == NULL) {
        event(ev, cap, "no fetch");
        return;
    }
    int      rc = lc_spider_fetch_settle(f, 0), opened = 0, after_p = 0;
    unsigned next = 0;
    settings(&s, 0, 0);
    for (int round = 0; round < 32; round++) {
        collect(f, &w);
        for (unsigned i = 0; i < w.n; i++) {
            const wframe *fr = &w.fr[i];
            if (fr->type == PREFACE_TYPE) {
                if (opened++ != 0) {
                    event(ev, cap, "P");
                    after_p = 1;
                }
            } else if (fr->type == LC_H2_HEADERS && after_p) {
                event(ev, cap, "H");
                goto out;
            } else if (fr->type == LC_H2_HEADERS) {
                if (read_request(&w, fr, &d, &q) != 0 || strncmp(q.pseudo[0], ":authority=", 11) != 0) {
                    event(ev, cap, "unreadable");
                    goto out;
                }
                char r[2100];
                snprintf(r, sizeof r, "R%.2000s", q.pseudo[0] + 11);
                event(ev, cap, r);
                const char *loc = locs[next] != NULL ? locs[next++] : NULL;
                answer(&s, fr->stream, 1, loc != NULL ? "302" : "200", loc, "0", NULL);
            } else if (fr->type == LC_H2_SETTINGS && !(fr->flags & 0x1u)) {
                frame(&s, LC_H2_SETTINGS, 0x1u, 0, NULL, 0);
            }
        }
        if (rc != 0) {
            event(ev, cap, "C");
            goto out;
        }
        if (after_p) {
            event(ev, cap, "nothing after P");
            goto out;
        }
        if (lc_spider_fetch_done(f)) {
            event(ev, cap, "D");
            goto out;
        }
        rc = deliver(f, &s, 0);
    }
    event(ev, cap, "no end");
out:
    lc_hpack_dec_free(&d);
    lc_spider_fetch_free(f);
}


typedef struct {
    lc_spider_fetch *f;
    int failed;
    unsigned pings;
} concurrent_fetch;

static void *feed_pings(void *ctx)
{
    concurrent_fetch *c = ctx;
    uint8_t ping[LC_H2_HEADER + 8u] = { 0 };
    (void)lc_h2_put_header(ping, sizeof ping, 8, LC_H2_PING, 0, 0);
    for (unsigned i = 0; i < 64u; i++) {
        ping[sizeof ping - 1u] = (uint8_t)i;
        if (lc_spider_fetch_feed(c->f, ping, sizeof ping) != 0)
            c->failed = 1;
    }
    return NULL;
}

static void *settle_fetch(void *ctx)
{
    concurrent_fetch *c = ctx;
    for (unsigned i = 0; i < 64u; i++) {
        if (lc_spider_fetch_settle(c->f, 0) != 0)
            c->failed = 1;
        (void)lc_spider_fetch_deadline(c->f);
        (void)lc_spider_fetch_done(c->f);
        (void)lc_spider_fetch_reads(c->f);
    }
    return NULL;
}

static void *wait_stopped(void *ctx)
{
    concurrent_fetch *c = ctx;
    uint64_t generation = 0;
    int rc = lc_spider_fetch_wait(c->f, &generation);
    if (rc == 1)
        rc = lc_spider_fetch_wait(c->f, &generation);
    if (rc != 0)
        c->failed = 1;
    return NULL;
}

static void *wait_completion(void *ctx)
{
    concurrent_fetch *c = ctx;
    uint64_t generation = 0;
    if (lc_spider_fetch_wait(c->f, &generation) != 1)
        c->failed = 1;
    return NULL;
}

typedef struct {
    lc_spider_fetch *f;
    pthread_mutex_t lock;
    pthread_cond_t changed;
    unsigned turns;
    int failed, exited;
} body_worker;

static void *consume_body(void *ctx)
{
    body_worker *w = ctx;
    uint64_t generation = 0;
    int rc;
    while ((rc = lc_spider_fetch_wait(w->f, &generation)) == 1) {
        int stepped;
        do {
            stepped = lc_spider_fetch_step(w->f, monotonic_ms());
            pthread_mutex_lock(&w->lock);
            w->turns++;
            if (stepped < 0)
                w->failed = 1;
            pthread_cond_broadcast(&w->changed);
            pthread_mutex_unlock(&w->lock);
        } while (stepped == 1); /* Yielded continuation is ready without another DATA wake. */
        if (stepped < 0)
            break;
    }
    pthread_mutex_lock(&w->lock);
    if (rc < 0)
        w->failed = 1;
    w->exited = 1;
    pthread_cond_broadcast(&w->changed);
    pthread_mutex_unlock(&w->lock);
    return NULL;
}

/* A bounded test watchdog, not a protocol delay. The predicate, not elapsed time, drives progress. */
static int await_turn(body_worker *w, unsigned turn)
{
    struct timespec limit;
    if (clock_gettime(CLOCK_REALTIME, &limit) != 0)
        return 0;
    limit.tv_sec += 10;
    pthread_mutex_lock(&w->lock);
    int rc = 0;
    while (w->turns < turn && !w->exited && rc == 0)
        rc = pthread_cond_timedwait(&w->changed, &w->lock, &limit);
    int ready = w->turns >= turn && !w->failed;
    pthread_mutex_unlock(&w->lock);
    return ready;
}

/* take also notifies the consumer, so a turn count is not a body-completion predicate. */
static int await_body_done(body_worker *w)
{
    struct timespec limit;
    if (clock_gettime(CLOCK_REALTIME, &limit) != 0)
        return 0;
    limit.tv_sec += 10;
    pthread_mutex_lock(&w->lock);
    int rc = 0;
    while (!lc_spider_fetch_done(w->f) && !w->exited && !w->failed && rc == 0)
        rc = pthread_cond_timedwait(&w->changed, &w->lock, &limit);
    int done = lc_spider_fetch_done(w->f) && !w->failed;
    pthread_mutex_unlock(&w->lock);
    return done;
}

static void *take_fetch(void *ctx)
{
    concurrent_fetch *c = ctx;
    for (unsigned i = 0; i < 256u; i++) {
        uint8_t *out = NULL;
        long n = lc_spider_fetch_take(c->f, &out);
        if (n < 0)
            c->failed = 1;
        if (n > 0) {
            lc_h2_hd hd;
            if (lc_h2_get_header(out, (size_t)n, &hd) != 0 || hd.type != LC_H2_PING ||
                hd.flags != LC_H2_ACK || hd.len != 8u || n != 17)
                c->failed = 1;
            else
                c->pings++;
        }
        free(out);
    }
    return NULL;
}

static void test_bounded_request(void)
{
    lc_browser b;
    size_t value_len = 96u * 1024u, cap = 128u * 1024u;
    char *value = malloc(value_len + 1u);
    uint8_t *sent = malloc(cap), *block = malloc(cap);
    site *peer = calloc(1, sizeof *peer);
    ok(value != NULL && sent != NULL && block != NULL && peer != NULL &&
           lc_browser_chrome_anchored(&b, LC_BROWSER_NAV) == 0,
       "large request continuation fixture");
    if (value == NULL || sent == NULL || block == NULL || peer == NULL)
        exit(1);
    memset(value, 'x', value_len);
    value[value_len] = '\0';
    const char *large_name = b.header[0].name;
    b.header[0].value = value;
    lc_spider_fetch *f = lc_spider_fetch_new("bounded-request.example", &b);
    ok(f != NULL && lc_spider_fetch_write_barrier(f) == 0,
       "large request enables socket completion ownership");
    if (f == NULL)
        exit(1);
    uint8_t *one = NULL;
    ok(lc_spider_fetch_take(f, &one) > 0 && lc_spider_fetch_write_complete(f, 1) == 0,
       "large request opening completes first");
    free(one);
    settings(peer, 0, 0);
    one = NULL;
    ok(lc_spider_fetch_feed(f, peer->buf, peer->len) == 0 &&
           lc_spider_fetch_take(f, &one) > 0 && lc_spider_fetch_write_complete(f, 1) == 0,
       "large request accepts initial server SETTINGS before header production");
    free(one);
    peer->len = 0;
    size_t used = 0;
    int injected = 0, ended = 0, exhausted = 0;
    unsigned header_frames = 0;
    for (unsigned turn = 0; turn < 128u; turn++) {
        int rc = lc_spider_fetch_step(f, 0);
        ok(rc >= 0, "large request continuation remains live");
        long n;
        unsigned batch = 0;
        while ((n = lc_spider_fetch_take(f, &one)) > 0) {
            ok((size_t)n <= cap - used, "large request capture fits");
            if ((size_t)n > cap - used)
                exit(1);
            memcpy(sent + used, one, (size_t)n);
            used += (size_t)n;
            batch++;
            if (!ended) {
                lc_h2_hd hd;
                ok(lc_h2_get_header(one, (size_t)n, &hd) == 0 &&
                       (hd.type == LC_H2_HEADERS || hd.type == 0x9u) && hd.stream == 1u &&
                       hd.len + LC_H2_HEADER == (size_t)n,
                   "each request batch preserves a whole Framer Write");
                ended = (hd.flags & LC_H2_END_HEADERS) != 0u;
                header_frames++;
            }
            if (!injected) {
                uint8_t settings_ack[LC_H2_HEADER];
                (void)lc_h2_put_header(settings_ack, sizeof settings_ack, 0, LC_H2_SETTINGS,
                                       LC_H2_ACK, 0);
                ok(lc_spider_fetch_feed(f, settings_ack, sizeof settings_ack) == 0 &&
                       !lc_spider_fetch_read_ready(f),
                   "SETTINGS ACK waits while the request owns cc.wmu, as processSettings does");
                settings(peer, 0, 0);
                uint8_t ping[8] = {1, 2, 3, 4, 5, 6, 7, 8};
                frame(peer, LC_H2_PING, 0, 0, ping, sizeof ping);
                uint8_t ignored[8192] = {0};
                frame(peer, 0xfu, 0, 0, ignored, sizeof ignored);
                ok(lc_spider_fetch_feed(f, peer->buf, peer->len) == 0 &&
                       !lc_spider_fetch_read_ready(f),
                   "SETTINGS/PING and a feed tail wait behind the header writer");
                injected = 1;
            }
            ok(lc_spider_fetch_step(f, 0) == 2,
               "taking a request Write does not advance its continuation");
            ok(lc_spider_fetch_write_complete(f, 1) == 0, "request Write completes once");
            free(one);
            one = NULL;
        }
        if (!ended)
            ok(batch <= 1u, "one natural frame batch is produced before the next completion turn");
        if (rc == 0 && batch == 0u) {
            exhausted = 1;
            break;
        }
    }
    size_t off = 0, block_len = 0;
    unsigned acks = 0;
    int end_headers = 0;
    while (off < used) {
        lc_h2_hd hd;
        if (lc_h2_get_header(sent + off, used - off, &hd) != 0)
            break;
        if (hd.type == LC_H2_HEADERS || hd.type == 0x9u) {
            ok(!end_headers && hd.len <= cap - block_len,
               "HEADERS/CONTINUATION stay contiguous and ordered");
            memcpy(block + block_len, sent + off + LC_H2_HEADER, hd.len);
            block_len += hd.len;
            end_headers = (hd.flags & LC_H2_END_HEADERS) != 0u;
        } else {
            ok(end_headers && (hd.flags & LC_H2_ACK) != 0u &&
                   (hd.type == LC_H2_SETTINGS || hd.type == LC_H2_PING),
               "protocol ACKs follow END_HEADERS, never interrupt the request");
            acks++;
        }
        off += LC_H2_HEADER + hd.len;
    }
    lc_hpack_dec dec = {0};
    dec.in = block;
    dec.len = block_len;
    int found = 0, decoded;
    while ((decoded = lc_hpack_next(&dec)) == 1)
        if (strcmp(dec.name, large_name) == 0)
            found = dec.value_len == value_len && memcmp(dec.value, value, value_len) == 0;
    ok(exhausted && off == used && header_frames > 2u && end_headers && acks == 2u &&
           found && decoded == 0 && lc_spider_fetch_read_ready(f),
       "whole large header survives bounded production and deferred feed resumes exactly once");
    lc_hpack_dec_free(&dec);
    lc_spider_fetch_stop(f);
    lc_spider_fetch_free(f);
    for (unsigned mode = 0; mode < 2u; mode++) {
        f = lc_spider_fetch_new("bounded-teardown.example", &b);
        ok(f != NULL && lc_spider_fetch_write_barrier(f) == 0,
           "large request teardown continuation fixture");
        if (f == NULL)
            exit(1);
        one = NULL;
        ok(lc_spider_fetch_take(f, &one) > 0 && lc_spider_fetch_write_complete(f, 1) == 0,
           "large request teardown opening completes");
        free(one);
        one = NULL;
        ok(lc_spider_fetch_step(f, 0) == 1 && lc_spider_fetch_take(f, &one) > 0 &&
               lc_spider_fetch_feed(f, peer->buf, peer->len) == 0 &&
               !lc_spider_fetch_read_ready(f),
           "large request teardown holds encoded block, frame and unread feed tail");
        if (mode == 0u) {
            lc_spider_fetch_stop(f);
            ok(lc_spider_fetch_step(f, 0) == 0, "stop does not resume a pending header writer");
        } else {
            ok(lc_spider_fetch_write_complete(f, 0) == 0 && lc_spider_fetch_step(f, 0) == -1,
               "failed socket completion terminates pending header production");
        }
        lc_spider_fetch_free(f);
        free(one);
    }
    free(peer);
    free(block);
    free(sent);
    free(value);
}

static void test_reader_write_identity(void)
{
    run *r = calloc(1, sizeof *r);
    ok(r != NULL && start_on(r, "reader-write-identity.example") == 0,
       "readLoop completion ownership fixture");
    if (r == NULL || r->f == NULL)
        exit(1);
    for (unsigned i = 0; i < 64u; i++) {
        uint8_t ping[8] = {0};
        ping[7] = (uint8_t)i;
        frame(&r->s, LC_H2_PING, 0, 0, ping, sizeof ping);
    }
    ok(lc_spider_fetch_write_barrier(r->f) == 0 &&
           lc_spider_fetch_feed(r->f, r->s.buf, r->s.len) == 0,
       "one feed accepts SETTINGS followed by 64 PINGs");
    for (unsigned i = 0; i <= 64u; i++) {
        uint8_t *one = NULL, *next = NULL;
        long n = lc_spider_fetch_take(r->f, &one);
        lc_h2_hd hd;
        ok(n > 0 && lc_h2_get_header(one, (size_t)n, &hd) == 0 &&
               hd.type == (i == 0u ? LC_H2_SETTINGS : LC_H2_PING) &&
               (hd.flags & LC_H2_ACK) != 0u &&
               (i == 0u || (n == 17 && one[16] == (uint8_t)(i - 1u))),
           "readLoop ACK identity and order are preserved");
        ok(!lc_spider_fetch_read_ready(r->f) && lc_spider_fetch_step(r->f, 0) == 2 &&
               lc_spider_fetch_take(r->f, &next) == 0 && next == NULL,
           "one pending protocol Write blocks its readLoop and cannot grow the output queue");
        ok(lc_spider_fetch_write_complete(r->f, 1) == 0 &&
               lc_spider_fetch_write_complete(r->f, 1) == -1 &&
               lc_spider_fetch_take(r->f, &next) == 0,
           "completion releases only that Write, without materializing later ACKs");
        free(one);
        int rc = lc_spider_fetch_step(r->f, 0);
        ok(i < 64u ? rc == 1 : rc == 0,
           "saved readLoop resumes at its next protocol operation without new input");
    }
    ok(lc_spider_fetch_read_ready(r->f), "readLoop regains TLS read readiness after its last ACK");
    lc_spider_fetch_stop(r->f);
    lc_spider_fetch_free(r->f);
    lc_hpack_dec_free(&r->d);
    free(r);
}

static void test_foreign_reader_body(void)
{
    for (unsigned scenario = 0; scenario < 14u; scenario++) {
        unsigned mode = scenario % 4u, teardown = scenario / 4u;
        int large = mode >= 2u, gzip = (mode & 1u) != 0u;
        char host[64];
        snprintf(host, sizeof host, "foreign-body-%u.example", scenario);
        run *r = calloc(1, sizeof *r);
        ok(r != NULL && start_on(r, host) == 0 && deliver(r->f, &r->s, 0) == 0,
           "foreign readLoop Write body fixture");
        if (r == NULL || r->f == NULL)
            exit(1);
        collect(r->f, &r->w);
        uint8_t page[8192], encoded[16384];
        const char link[] = "<a href=\"/during-ack\">link</a>";
        size_t page_len = large ? sizeof page : sizeof link - 1u;
        uint32_t random = 123456789u;
        for (size_t i = 0; i < page_len; i++) {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            page[i] = (uint8_t)(32u + random % 95u);
        }
        memcpy(page + page_len - (sizeof link - 1u), link, sizeof link - 1u);
        const uint8_t *payload = page;
        size_t payload_len = page_len;
        if (gzip) {
            z_stream z = {0};
            int init = deflateInit2(&z, 6, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
            ok(init == Z_OK, "foreign Write gzip encoder");
            if (init != Z_OK)
                exit(1);
            z.next_in = page;
            z.avail_in = (uInt)page_len;
            z.next_out = encoded;
            z.avail_out = sizeof encoded;
            ok(deflate(&z, Z_FINISH) == Z_STREAM_END, "foreign Write complete gzip page");
            payload_len = z.total_out;
            deflateEnd(&z);
            payload = encoded;
        }
        ok(!large || payload_len > 4096u, "large source needs a flow-credit Write");
        ok(lc_spider_fetch_write_barrier(r->f) == 0, "foreign Write completion contract");
        answer(&r->s, 1, 0, "200", NULL, NULL, gzip ? "gzip" : NULL);
        body(&r->s, 1, payload, payload_len, 1);
        if (teardown == 3u) {
            uint8_t goaway[8] = {0, 0, 0, 1, 0, 0, 0, 0};
            frame(&r->s, LC_H2_GOAWAY, 0, 0, goaway, sizeof goaway);
        }
        uint8_t ping[8] = {0};
        ping[7] = 1u;
        frame(&r->s, LC_H2_PING, 0, 0, ping, sizeof ping);
        ping[7] = 2u;
        frame(&r->s, LC_H2_PING, 0, 0, ping, sizeof ping);
        ok(lc_spider_fetch_feed(r->f, r->s.buf, r->s.len) == 0,
           "body and END_STREAM arrive before a readLoop ACK blocks later input");
        r->s.len = 0;
        uint8_t *ack = NULL, *next = NULL;
        long ack_len = lc_spider_fetch_take(r->f, &ack);
        ok(ack_len == 17 && ack[3] == LC_H2_PING && ack[4] == LC_H2_ACK && ack[16] == 1u,
           "the first readLoop ACK remains in flight");
        uint64_t generation = 0;
        ok(lc_spider_fetch_wait(r->f, &generation) == 1,
           "Do readiness is not suppressed by a foreign readLoop Write");
        int rc = 1;
        for (unsigned i = 0; i < 128u && rc == 1; i++)
            rc = lc_spider_fetch_step(r->f, 0);
        int found = 0;
        for (unsigned i = 0; i < 200u && !found; i++)
            found = drawn_is(host, "/during-ack");
        ok((teardown == 3u ? rc < 0 : (rc == 0 || rc == 2)) &&
               !lc_spider_fetch_done(r->f) && found == (!large && teardown != 3u),
           large ? "plain/gzip source retains its accounted Read pending flow-credit Write"
                 : "plain/gzip ReadAll harvests behind the foreign ACK, but Close still waits for cleanup");
        ok(!lc_spider_fetch_read_ready(r->f) && lc_spider_fetch_take(r->f, &next) == 0 &&
               next == NULL && ack_len == 17 && ack[16] == 1u,
           "independent Do neither completes the ACK nor resumes that readLoop");
        if (teardown == 1u || teardown == 2u) {
            if (teardown == 1u) {
                lc_spider_fetch_stop(r->f);
                ok(lc_spider_fetch_step(r->f, 0) == 0 &&
                       lc_spider_fetch_wait(r->f, &generation) == 0,
                   "stop interrupts foreign/owned source waits without advancing them");
            } else {
                ok(lc_spider_fetch_write_complete(r->f, 0) == 0 &&
                       lc_spider_fetch_step(r->f, 0) < 0,
                   "foreign Write failure closes a pending plain/gzip Read");
            }
            lc_spider_fetch_free(r->f);
            ok(ack_len == 17 && ack[16] == 1u,
               "foreign ACK ownership outlives stop/error and saved source destruction");
            free(ack);
            lc_hpack_dec_free(&r->d);
            free(r);
            continue;
        }
        ok(lc_spider_fetch_write_complete(r->f, 1) == 0 &&
               lc_spider_fetch_write_complete(r->f, 1) == -1,
           "foreign ACK completion identity survives independent body progress");
        free(ack);
        if (teardown == 3u) {
            ok(lc_spider_fetch_take(r->f, &next) == 0 && next == NULL,
               "GOAWAY cleanup forgets the stream behind the foreign ACK without later dispatch");
            lc_spider_fetch_free(r->f);
            lc_hpack_dec_free(&r->d);
            free(r);
            continue;
        }
        rc = 1;
        for (unsigned i = 0; i < 128u && rc == 1; i++)
            rc = lc_spider_fetch_step(r->f, 0);
        ack_len = lc_spider_fetch_take(r->f, &ack);
        ok((rc == 1 || rc == 2) && ack_len == 17 && ack[3] == LC_H2_PING && ack[16] == 2u,
           "only completion resumes the saved second PING, before any body WINDOW_UPDATE");
        ok(lc_spider_fetch_write_complete(r->f, 1) == 0, "second foreign ACK completes");
        free(ack);
        ok(lc_spider_fetch_step(r->f, 0) >= 0 && lc_spider_fetch_read_ready(r->f),
           "readLoop resumes after its ACK even when independent Do already ended");
        unsigned updates = 0;
        int writes_ok = 1, injected = 0;
        for (unsigned i = 0; i < 256u && !lc_spider_fetch_done(r->f); i++) {
            rc = lc_spider_fetch_step(r->f, 0);
            if (rc < 0) {
                writes_ok = 0;
                break;
            }
            while ((ack_len = lc_spider_fetch_take(r->f, &ack)) > 0) {
                for (size_t off = 0; off < (size_t)ack_len; off += 13u) {
                    lc_h2_hd hd;
                    if ((size_t)ack_len - off < 13u ||
                        lc_h2_get_header(ack + off, (size_t)ack_len - off, &hd) != 0 ||
                        hd.type != LC_H2_WINDOW_UPDATE || hd.len != 4u)
                        writes_ok = 0;
                    updates++;
                }
                int inject = large && !injected;
                if (inject) {
                    ping[7] = 3u;
                    frame(&r->s, LC_H2_PING, 0, 0, ping, sizeof ping);
                    ok(lc_spider_fetch_feed(r->f, r->s.buf, r->s.len) == 0 &&
                           lc_spider_fetch_step(r->f, 0) == 2 &&
                           !lc_spider_fetch_read_ready(r->f),
                       "PING dispatch waits on body cc.wmu and suspends the next TLS Read");
                    r->s.len = 0;
                }
                if (lc_spider_fetch_write_complete(r->f, 1) != 0)
                    writes_ok = 0;
                free(ack);
                if (inject) {
                    injected = 1;
                    uint8_t *premature = NULL;
                    ok(lc_spider_fetch_take(r->f, &premature) == 0 && premature == NULL,
                       "body Flush completion releases cc.wmu; ACK has not been produced behind that lock");
                    ok(lc_spider_fetch_step(r->f, 0) == 1,
                       "readLoop resumes saved PING dispatch after body Flush releases cc.wmu");
                    ack_len = lc_spider_fetch_take(r->f, &ack);
                    ok(ack_len == 17 && ack[3] == LC_H2_PING && ack[16] == 3u,
                       "later foreign ACK retains its exact identity after the body Write");
                    rc = 1;
                    for (unsigned j = 0; j < 128u && rc == 1; j++)
                        rc = lc_spider_fetch_step(r->f, 0);
                    ok(rc == 2 && lc_spider_fetch_write_complete(r->f, 1) == 0,
                       "later ACK completes only after independent plain/gzip continuation");
                    free(ack);
                    ok(lc_spider_fetch_step(r->f, 0) >= 0 && lc_spider_fetch_read_ready(r->f),
                       "later ACK completion releases the TLS/readLoop boundary");
                }
            }
        }
        found = 0;
        for (unsigned i = 0; i < 200u && !found; i++)
            found = drawn_is(host, "/during-ack");
        ok(writes_ok && lc_spider_fetch_done(r->f) && found && (large ? updates > 0u : updates == 0u),
           "completion resumes the exact source/gzip continuation and finishes without duplicate ACK/CANCEL");
        lc_spider_fetch_stop(r->f);
        lc_spider_fetch_free(r->f);
        lc_hpack_dec_free(&r->d);
        free(r);
    }
}

static void test_pending_source_reallocation(void)
{
    for (unsigned mode = 0; mode < 6u; mode++) {
        unsigned gzip = mode % 2u, teardown = mode / 2u;
        const char *host = gzip ? "saved-gzip-source.example" : "saved-plain-source.example";
        run *r = calloc(1, sizeof *r);
        ok(r != NULL && start_on(r, host) == 0 && deliver(r->f, &r->s, 0) == 0,
           "saved source Read reallocation fixture");
        if (r == NULL || r->f == NULL)
            exit(1);
        collect(r->f, &r->w);
        uint8_t page[16384], zipped[32768];
        uint32_t random = 987654321u;
        for (size_t i = 0; i < sizeof page; i++) {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            page[i] = (uint8_t)(32u + random % 95u);
        }
        const char link[] = "<a href=\"/saved-source\">link</a>";
        memcpy(page + (gzip ? 2000u : 4500u), link, sizeof link - 1u);
        const uint8_t *payload = page;
        size_t payload_len = sizeof page;
        if (gzip) {
            z_stream z = {0};
            ok(deflateInit2(&z, 6, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) == Z_OK,
               "saved source gzip encoder");
            z.next_in = page;
            z.avail_in = sizeof page;
            z.next_out = zipped;
            z.avail_out = sizeof zipped;
            ok(deflate(&z, Z_FINISH) == Z_STREAM_END, "saved source gzip page");
            payload_len = z.total_out;
            deflateEnd(&z);
            payload = zipped;
        }
        ok(payload_len > 8192u && lc_spider_fetch_write_barrier(r->f) == 0,
           "saved source spans two DATA feeds");
        answer(&r->s, 1, 0, "200", NULL, NULL, gzip ? "gzip" : NULL);
        body(&r->s, 1, payload, 8192u, 0);
        ok(lc_spider_fetch_feed(r->f, r->s.buf, r->s.len) == 0,
           "the first pipe buffer arrives without END_STREAM");
        int rc = 1;
        for (unsigned i = 0; i < 128u && rc == 1; i++)
            rc = lc_spider_fetch_step(r->f, 0);
        uint8_t *write = NULL;
        long wn = lc_spider_fetch_take(r->f, &write);
        ok(rc == 2 && wn > 0 && write[3] == LC_H2_WINDOW_UPDATE,
           "body source owns a Read pending its flow-credit Flush");
        r->s.len = 0;
        body(&r->s, 1, payload + 8192u, payload_len - 8192u, 1);
        if (teardown != 0u) {
            uint8_t nonce[8] = {0};
            nonce[7] = 0x76;
            frame(&r->s, LC_H2_PING, 0, 0, nonce, sizeof nonce);
        }
        ok(lc_spider_fetch_feed(r->f, r->s.buf, r->s.len) == 0 &&
               lc_spider_fetch_step(r->f, 0) == 1 && lc_spider_fetch_step(r->f, 0) == 2,
           "feed grows the pipe; non-writing cleanup forgets once then waits behind the source Write");
        if (teardown != 0u) {
            ok(!lc_spider_fetch_read_ready(r->f),
               "plain/gzip teardown retains PING behind its body writer owner");
            if (teardown == 1u) {
                lc_spider_fetch_stop(r->f);
                uint64_t generation = 0;
                ok(lc_spider_fetch_step(r->f, 0) == 0 &&
                       lc_spider_fetch_wait(r->f, &generation) == 0,
                   "stop interrupts the retained source and writer-lock wait without dispatching PING");
            } else {
                ok(lc_spider_fetch_write_complete(r->f, 0) == 0 &&
                       lc_spider_fetch_step(r->f, 0) < 0,
                   "failed body Flush closes plain/gzip while readLoop waits on its cc.wmu");
            }
            lc_spider_fetch_free(r->f);
            ok(write[3] == LC_H2_WINDOW_UPDATE,
               "retained whole body Write remains caller-owned after stop/error destruction");
            free(write);
            lc_hpack_dec_free(&r->d);
            free(r);
            continue;
        }
        ok(lc_spider_fetch_write_complete(r->f, 1) == 0,
           "actual completion releases the saved Read result");
        free(write);
        int writes_ok = 1;
        for (unsigned i = 0; i < 256u && !lc_spider_fetch_done(r->f); i++) {
            if (lc_spider_fetch_step(r->f, 0) < 0) {
                writes_ok = 0;
                break;
            }
            while ((wn = lc_spider_fetch_take(r->f, &write)) > 0) {
                if (write[3] != LC_H2_WINDOW_UPDATE || lc_spider_fetch_write_complete(r->f, 1) != 0)
                    writes_ok = 0;
                free(write);
            }
        }
        int found = 0;
        for (unsigned i = 0; i < 200u && !found; i++)
            found = drawn_is(host, "/saved-source");
        ok(writes_ok && lc_spider_fetch_done(r->f) && found,
           gzip ? "gzip continuation preserves the copied source through pipe reallocation and checked EOF"
                : "plain Read preserves the copied source through pipe compaction and EOF");
        lc_spider_fetch_stop(r->f);
        lc_spider_fetch_free(r->f);
        lc_hpack_dec_free(&r->d);
        free(r);
    }
}

static void test_single_request_owner(void)
{
    for (unsigned teardown = 0; teardown < 3u; teardown++) {
        lc_browser b;
        ok(lc_browser_chrome_anchored(&b, LC_BROWSER_NAV) == 0,
           "single-frame writer browser");
        lc_spider_fetch *f = lc_spider_fetch_new("single-owner.example", &b);
        ok(f != NULL && lc_spider_fetch_write_barrier(f) == 0,
           "single-frame request completion fixture");
        if (f == NULL)
            exit(1);
        uint8_t *write = NULL;
        ok(lc_spider_fetch_take(f, &write) > 0 && lc_spider_fetch_write_complete(f, 1) == 0,
           "single-frame fixture completes its opening");
        free(write);
        ok(lc_spider_fetch_step(f, 0) == 1,
           "single-frame request is produced independently of readLoop");
        long wn = lc_spider_fetch_take(f, &write);
        ok(wn > 9 && write[3] == LC_H2_HEADERS && (write[4] & LC_H2_END_HEADERS) != 0u,
           "request Flush contains a single complete HEADERS frame");
        uint8_t input[LC_H2_HEADER * 2u + 8u] = {0};
        (void)lc_h2_put_header(input, sizeof input, 0, LC_H2_SETTINGS, LC_H2_ACK, 0);
        ok(lc_spider_fetch_feed(f, input, LC_H2_HEADER) == 0 && !lc_spider_fetch_read_ready(f),
           "SETTINGS ACK waits while single-frame request owns cc.wmu");
        (void)lc_h2_put_header(input, sizeof input, 8u, LC_H2_PING, 0, 0);
        memset(input + LC_H2_HEADER, 0x77, 8u);
        (void)lc_h2_put_header(input + LC_H2_HEADER + 8u, LC_H2_HEADER, 0, 0xfu, 0, 0);
        ok(lc_spider_fetch_feed(f, input, sizeof input) == 0 &&
               !lc_spider_fetch_read_ready(f) && lc_spider_fetch_step(f, 0) == 2,
           "PING and the following frame wait on single-frame request Flush");
        if (teardown == 1u) {
            lc_spider_fetch_stop(f);
            uint64_t generation = 0;
            ok(lc_spider_fetch_step(f, 0) == 0 && lc_spider_fetch_wait(f, &generation) == 0,
               "stop interrupts single-frame request/PING writer wait");
        } else if (teardown == 2u) {
            ok(lc_spider_fetch_write_complete(f, 0) == 0 && lc_spider_fetch_step(f, 0) < 0,
               "failed single-frame request Flush closes its waiting readLoop");
        } else {
            ok(lc_spider_fetch_write_complete(f, 1) == 0,
               "own final request Write releases cc.wmu");
            uint8_t *ack = NULL;
            ok(lc_spider_fetch_take(f, &ack) == 0 && ack == NULL,
               "ACK is not constructed before request owner release and saved-frame dispatch");
            ok(lc_spider_fetch_step(f, 0) == 1,
               "saved PING dispatch resumes after single-frame Flush");
            long an = lc_spider_fetch_take(f, &ack);
            ok(an == 17 && ack[3] == LC_H2_PING && ack[4] == LC_H2_ACK && ack[16] == 0x77,
               "saved single-frame PING retains its exact ACK identity");
            ok(lc_spider_fetch_write_complete(f, 1) == 0 &&
                   lc_spider_fetch_step(f, 0) >= 0 && lc_spider_fetch_read_ready(f),
               "ACK completion resumes the following frame without another HEADERS Write");
            free(ack);
        }
        lc_spider_fetch_free(f);
        ok(write[3] == LC_H2_HEADERS, "whole request stays caller-owned through teardown");
        free(write);
    }
}

int main(void)
{
    test_bounded_request();
    test_reader_write_identity();
    test_foreign_reader_body();
    test_pending_source_reallocation();
    test_single_request_owner();
    static run r;
    static request next;

    printf("the fetch: its first request\n");
    {
        ok(start(&r) == 0, "the fetch starts with two writes, the opening and the request");
        ok(r.w.fr[0].type == PREFACE_TYPE && r.w.fr[1].type == LC_H2_SETTINGS &&
               r.w.fr[2].type == LC_H2_WINDOW_UPDATE && r.w.fr[2].write == 0u,
           "the opening: preface, SETTINGS and the connection window in one write");
        const wframe *h = find(&r.w, LC_H2_HEADERS, 0);
        ok(h != NULL && h->write == 1u && h->stream == 1u &&
               h->flags == (LC_H2_END_STREAM | LC_H2_END_HEADERS),
           "then HEADERS on stream 1, ending it, in a write of its own");
        ok(strcmp(r.first.pseudo[0], ":authority=" HOST) == 0 &&
               strcmp(r.first.pseudo[2], ":path=/") == 0 && get(&r.first, "cookie") != NULL &&
               get(&r.first, "referer") == NULL,
           "for / on the host, with the padding cookie and no referer");
        lc_spider_fetch_free(r.f);
    }

    printf("\na redirect on the same host (rel)\n");
    {
        start(&r);
        answer(&r.s, 1, 1, "302", "/a", "0", NULL);
        ok(deliver(r.f, &r.s, 0) == 0, "the site's SETTINGS and a 302 to /a are read");
        collect(r.f, &r.w);
        ok(r.w.writes == 2u && r.w.fr[0].type == LC_H2_SETTINGS && r.w.fr[0].flags == LC_H2_ACK,
           "the SETTINGS is acknowledged, in a write of its own");
        const wframe *h = find(&r.w, LC_H2_HEADERS, 0);
        ok(h != NULL && h->stream == 3u && h->flags == (LC_H2_END_STREAM | LC_H2_END_HEADERS),
           "and the redirect goes out as HEADERS on stream 3");
        ok(read_request(&r.w, h, &r.d, &next) == 0 && strcmp(next.pseudo[2], ":path=/a") == 0 &&
               strcmp(next.pseudo[0], ":authority=" HOST) == 0,
           "for /a on the same authority");
        const char *ref = get(&next, "referer");
        ok(ref != NULL && strcmp(ref, "https://" HOST "/") == 0,
           "with the first request's URL as its referer");
        ok(same_set_plus(&r.first, &next, "referer", NULL),
           "and every header of the first request, value for value — the referer the one more");
        char line[96];
        snprintf(line, sizeof line, "its block refers back to the first: %zu bytes against %zu",
                 next.block, r.first.block);
        ok(next.block < 100u && r.first.block > 300u, line);
        lc_spider_fetch_free(r.f);
    }

    printf("\nthe same, the site's bytes in pieces of 1, 7, 20, 33 and 1000\n");
    {
        size_t pieces[] = { 1, 7, 20, 33, 1000 }; /* 20 and 33 cut a frame after its header */
        int    all = 1;
        for (unsigned i = 0; i < 5u; i++) {
            start(&r);
            answer(&r.s, 1, 1, "302", "/a", "0", NULL);
            all &= deliver(r.f, &r.s, pieces[i]) == 0;
            collect(r.f, &r.w);
            const wframe *h = find(&r.w, LC_H2_HEADERS, 0);
            all &= h != NULL && h->stream == 3u && read_request(&r.w, h, &r.d, &next) == 0 &&
                   strcmp(next.pseudo[2], ":path=/a") == 0;
            lc_spider_fetch_free(r.f);
        }
        ok(all, "a frame split across reads is put back together: the same redirect every time");
    }

    printf("\nten requests and no eleventh (chain)\n");
    {
        start(&r);
        unsigned requests = 1, last_stream = 1;
        for (unsigned i = 1; i <= 12u; i++) {
            char loc[16];
            snprintf(loc, sizeof loc, "/c%u", i);
            answer(&r.s, last_stream, 1, "302", loc, "0", NULL);
            deliver(r.f, &r.s, 0);
            collect(r.f, &r.w);
            const wframe *h = find(&r.w, LC_H2_HEADERS, 0);
            if (h == NULL)
                break;
            requests++;
            last_stream = h->stream;
        }
        char line[96];
        snprintf(line, sizeof line, "%u requests, the last on stream %u", requests, last_stream);
        ok(requests == 10u && last_stream == 19u, line);
        lc_spider_fetch_free(r.f);
    }

    printf("\na redirect's body: read, or its window handed back\n");
    {
        start(&r);
        answer(&r.s, 1, 0, "302", "/a", "1000", NULL);
        filler(&r.s, 1, 1000, 1);
        deliver(r.f, &r.s, 0);
        collect(r.f, &r.w);
        ok(count(&r.w, LC_H2_WINDOW_UPDATE) == 0u && count(&r.w, LC_H2_RST_STREAM) == 0u &&
               find(&r.w, LC_H2_HEADERS, 0) != NULL,
           "smallbody: 1000 bytes slurped, nothing handed back, stream 3 follows");
        lc_spider_fetch_free(r.f);

        start(&r);
        answer(&r.s, 1, 0, "302", "/a", "5000", NULL);
        filler(&r.s, 1, 5000, 1);
        deliver(r.f, &r.s, 0);
        collect(r.f, &r.w);
        const wframe *wu = find(&r.w, LC_H2_WINDOW_UPDATE, 0);
        const wframe *h = find(&r.w, LC_H2_HEADERS, 0);
        uint32_t      inc = 0;
        if (wu != NULL)
            inc = (uint32_t)r.w.bytes[wu->off] << 24 | (uint32_t)r.w.bytes[wu->off + 1] << 16 |
                  (uint32_t)r.w.bytes[wu->off + 2] << 8 | r.w.bytes[wu->off + 3];
        ok(wu != NULL && wu->stream == 0u && inc == 5000u && h != NULL && wu->write < h->write &&
               count(&r.w, LC_H2_RST_STREAM) == 0u,
           "bigbody: the connection's window for 5000 unread bytes, then stream 3, no RST_STREAM");
        lc_spider_fetch_free(r.f);

        /* The body not yet there when Do closes it: the stream is cancelled, and the window for
         * what arrives after goes back as it arrives. */
        start(&r);
        answer(&r.s, 1, 0, "302", "/a", "5000", NULL);
        deliver(r.f, &r.s, 0);
        collect(r.f, &r.w);
        const wframe *rst = find(&r.w, LC_H2_RST_STREAM, 0);
        ok(rst != NULL && rst->stream == 1u && r.w.bytes[rst->off + 3] == 0x8u &&
               find(&r.w, LC_H2_HEADERS, 0) != NULL && rst->write < find(&r.w, LC_H2_HEADERS, 0)->write,
           "a body still to come: RST_STREAM(CANCEL) on stream 1, then stream 3");
        filler(&r.s, 1, 5000, 1);
        deliver(r.f, &r.s, 0);
        collect(r.f, &r.w);
        wu = find(&r.w, LC_H2_WINDOW_UPDATE, 0);
        ok(wu != NULL && wu->stream == 0u && r.w.n == 1u,
           "and the 5000 that came after it are handed back on the connection");
        lc_spider_fetch_free(r.f);

        /* A small body that comes a read later is waited for — the slurp reads it — where a large
         * one is not. */
        start(&r);
        answer(&r.s, 1, 0, "302", "/a", "1000", NULL);
        deliver(r.f, &r.s, 0);
        collect(r.f, &r.w);
        ok(r.w.writes == 1u && find(&r.w, LC_H2_HEADERS, 0) == NULL,
           "a small body still to come is waited for: nothing but the ACK yet");
        filler(&r.s, 1, 1000, 1);
        deliver(r.f, &r.s, 0);
        collect(r.f, &r.w);
        ok(find(&r.w, LC_H2_RST_STREAM, 0) == NULL && find(&r.w, LC_H2_HEADERS, 0) != NULL,
           "and once it is read, stream 3 — no RST_STREAM");
        lc_spider_fetch_free(r.f);
    }

    printf("\na gzip body, as gzip.Reader reads it\n");
    {
        /* Where the slurp stops reading a gzip body is Go's gzip reader's to say, and core/gozip is
         * that reader, held to Go by test/gozip — so it is the oracle here: over the whole body, as
         * the fetch has it when Do gets to the slurp, what does it read, and what window do those
         * reads and the Close hand back. What is asserted is that the fetch puts exactly that on the
         * wire, and then the next request. */
        static uint8_t plain[60000], gz[64000];
        uint32_t       x = 2463534242u; /* hex from a xorshift, which compresses to about half */
        for (size_t i = 0; i < sizeof plain; i++) {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            plain[i] = (uint8_t)"0123456789abcdef"[x & 15u];
        }
        const size_t sizes[] = { 300, 20000, sizeof plain };
        const char  *what[] = { "a small one is read to its end: nothing handed back",
                                "less than 32 KB of output: read to the end of the final block",
                                "past 32 KB: read to the fill that filled flate's window, the rest "
                                "handed back by Close" };
        for (unsigned c = 0; c < 3u; c++) {
            z_stream z;
            memset(&z, 0, sizeof z);
            deflateInit2(&z, 6, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
            z.next_in = plain;
            z.avail_in = (uInt)sizes[c];
            z.next_out = gz;
            z.avail_out = sizeof gz;
            deflate(&z, Z_FINISH);
            size_t len = sizeof gz - z.avail_out;
            deflateEnd(&z);

            oracle o;
            slurp_oracle(gz, len, &o);

            start(&r);
            answer(&r.s, 1, 0, "301", "/a", NULL, "gzip");
            body(&r.s, 1, gz, len, 1);
            deliver(r.f, &r.s, 0);
            collect(r.f, &r.w);
            uint32_t conn = 0, strm = 0;
            for (unsigned i = 0; i < r.w.n; i++) {
                const wframe *wf = &r.w.fr[i];
                if (wf->type != LC_H2_WINDOW_UPDATE)
                    continue;
                uint32_t inc = (uint32_t)r.w.bytes[wf->off] << 24 |
                               (uint32_t)r.w.bytes[wf->off + 1] << 16 |
                               (uint32_t)r.w.bytes[wf->off + 2] << 8 | r.w.bytes[wf->off + 3];
                if (wf->stream == 1u)
                    strm += inc;
                else
                    conn += inc;
            }
            char line[200];
            snprintf(line, sizeof line, "%s: %zu bytes, %u read, windows %u and %u", what[c], len,
                     o.consumed, conn, strm);
            ok(strm == o.stream && conn == o.conn && find(&r.w, LC_H2_HEADERS, 0) != NULL &&
                   count(&r.w, LC_H2_RST_STREAM) == 0u && (c < 2u || o.consumed < len),
               line);
            lc_spider_fetch_free(r.f);
        }
    }

    printf("\nanother host, a subdomain, http, no Location, nothing that parses\n");
    {
        start(&r);
        answer(&r.s, 1, 1, "302", "https://other.example/o", "0", NULL);
        deliver(r.f, &r.s, 0);
        collect(r.f, &r.w);
        const wframe *pre = find(&r.w, PREFACE_TYPE, 0);
        const wframe *h = find(&r.w, LC_H2_HEADERS, 0);
        lc_hpack_dec fresh;
        memset(&fresh, 0, sizeof fresh);
        ok(pre != NULL && h != NULL && h->stream == 1u && pre->write < h->write,
           "cross: a second preface mid-stream, then HEADERS on stream 1 again");
        ok(read_request(&r.w, h, &fresh, &next) == 0 &&
               strcmp(next.pseudo[0], ":authority=other.example") == 0 &&
               same_set_plus(&r.first, &next, "referer", "cookie"),
           "from a fresh encoder, for the other host, without the cookie");
        lc_hpack_dec_free(&fresh);
        lc_spider_fetch_free(r.f);

        start(&r);
        answer(&r.s, 1, 1, "302", "https://sub." HOST "/u", "0", NULL);
        deliver(r.f, &r.s, 0);
        collect(r.f, &r.w);
        h = find(&r.w, LC_H2_HEADERS, 0);
        memset(&fresh, 0, sizeof fresh);
        ok(find(&r.w, PREFACE_TYPE, 0) != NULL && read_request(&r.w, h, &fresh, &next) == 0 &&
               same_set_plus(&r.first, &next, "referer", NULL),
           "sub: a new connection too, and the cookie kept — a subdomain of the first host");
        lc_hpack_dec_free(&fresh);
        lc_spider_fetch_free(r.f);

        const char *none[] = { "http://" HOST "/h", NULL, "https://w{b}.example/" };
        const char *what[] = { "http: x/net refuses the scheme — nothing",
                               "noloc: a 302 without a Location is the page — nothing",
                               "a Location that does not parse — nothing" };
        for (unsigned i = 0; i < 3u; i++) {
            start(&r);
            answer(&r.s, 1, 1, "302", none[i], "0", NULL);
            deliver(r.f, &r.s, 0);
            collect(r.f, &r.w);
            ok(r.w.writes == 1u && r.w.fr[0].type == LC_H2_SETTINGS, what[i]);
            lc_spider_fetch_free(r.f);
        }

        /* Userinfo: send clones the header map and sets Authorization on the clone, for every
         * request whose URL has it — and a relative Location inherits it — while the referer is the
         * last URL with its "userinfo@" taken out (GOROOT/src/net/http/client.go:149-173, :253-258). */
        start(&r);
        answer(&r.s, 1, 1, "302", "https://u:p@" HOST "/x", "0", NULL);
        deliver(r.f, &r.s, 0);
        collect(r.f, &r.w);
        const wframe *hu = find(&r.w, LC_H2_HEADERS, 0);
        const char   *au = NULL, *ru = NULL;
        ok(hu != NULL && hu->stream == 3u && find(&r.w, PREFACE_TYPE, 0) == NULL &&
               read_request(&r.w, hu, &r.d, &next) == 0 &&
               (au = get(&next, "authorization")) != NULL && strcmp(au, "Basic dTpw") == 0 &&
               (ru = get(&next, "referer")) != NULL && strcmp(ru, "https://" HOST "/") == 0 &&
               next.n == r.first.n + 2u,
           "userinfo: the same connection, and Authorization besides the referer");
        r.s.len = 0;
        answer(&r.s, 3, 1, "302", "/y", "0", NULL);
        deliver(r.f, &r.s, 0);
        collect(r.f, &r.w);
        hu = find(&r.w, LC_H2_HEADERS, 0);
        ok(hu != NULL && hu->stream == 5u && read_request(&r.w, hu, &r.d, &next) == 0 &&
               (au = get(&next, "authorization")) != NULL && strcmp(au, "Basic dTpw") == 0 &&
               (ru = get(&next, "referer")) != NULL && strcmp(ru, "https://" HOST "/x") == 0,
           "and a relative hop keeps it, its referer without the \"u:p@\"");
        lc_spider_fetch_free(r.f);

        /* And a first request with userinfo, which a harvested link glued to the server name makes:
         * "https://user.example@evil/x" loses its prefix and becomes "@evil/x" — the server name the
         * user, evil the host. */
        {
            lc_browser b;
            site       s;
            lc_hpack_enc_init(&s.enc);
            s.len = 0;
            lc_browser_chrome_anchored(&b, LC_BROWSER_NAV);
            lc_spider_fetch *f = lc_spider_fetch_new("user.example", &b);
            lc_spider_fetch_settle(f, 0);
            collect(f, &r.w);
            settings(&s, 0, 0);
            const char page[] = "<a href=\"https://user.example@evil/x\">x</a>";
            answer(&s, 1, 0, "200", NULL, NULL, NULL);
            body(&s, 1, (const uint8_t *)page, sizeof page - 1u, 1);
            deliver(f, &s, 0);
            lc_spider_fetch_free(f);
            int seen = 0;
            for (unsigned k = 0; k < 200u && !seen; k++) {
                f = lc_spider_fetch_new("user.example", &b);
                lc_spider_fetch_settle(f, 0);
                collect(f, &r.w);
                lc_hpack_dec d1;
                memset(&d1, 0, sizeof d1);
                if (read_request(&r.w, find(&r.w, LC_H2_HEADERS, 0), &d1, &next) == 0 &&
                    strcmp(next.pseudo[0], ":authority=evil") == 0)
                    seen = (au = get(&next, "authorization")) != NULL &&
                                   strcmp(au, "Basic dXNlci5leGFtcGxlOg==") == 0 &&
                                   strcmp(next.pseudo[2], ":path=/x") == 0 &&
                                   next.n == r.first.n + 1u
                               ? 1
                               : -1;
                lc_hpack_dec_free(&d1);
                lc_spider_fetch_free(f);
            }
            ok(seen == 1, "a first request with userinfo: the host after the '@', and Authorization");
        }
    }

    printf("\nwhat the connection says on the way\n");
    {
        /* The site's table size: the next block opens with the update x/net's encoder owes. */
        start(&r);
        r.s.len = 0;
        settings(&r.s, 0x1u, 4096u);
        answer(&r.s, 1, 1, "302", "/a", "0", NULL);
        deliver(r.f, &r.s, 0);
        collect(r.f, &r.w);
        const wframe *h = find(&r.w, LC_H2_HEADERS, 0);
        ok(h != NULL && r.w.bytes[h->off] == 0x3fu && r.w.bytes[h->off + 1] == 0xe1u &&
               r.w.bytes[h->off + 2] == 0x1fu,
           "SETTINGS_HEADER_TABLE_SIZE: the redirect's block opens with a size update");
        lc_spider_fetch_free(r.f);

        /* GOAWAY that takes stream 1: the connection is dead to the pool and closes as soon as
         * stream 1 is done with (forgetStreamID's closeOnIdle) — and the redirect's dial, which hands
         * back the same TLS connection, fails on it: nothing more is written. */
        start(&r);
        uint8_t ga[8] = { 0, 0, 0, 1, 0, 0, 0, 0 };
        frame(&r.s, LC_H2_GOAWAY, 0, 0, ga, sizeof ga);
        answer(&r.s, 1, 1, "302", "/a", "0", NULL);
        ok(deliver(r.f, &r.s, 0) != 0, "GOAWAY: the connection closes once stream 1 is done");
        collect(r.f, &r.w);
        ok(r.w.n == 1u && r.w.fr[0].type == LC_H2_SETTINGS && r.w.fr[0].flags == LC_H2_ACK,
           "and the redirect is never sent: no preface, no HEADERS");
        lc_spider_fetch_free(r.f);

        /* GOAWAY that does not take stream 1: it is aborted, retryable — doRequest cancels it and
         * the idle connection closes; the retry's dial fails on it. */
        start(&r);
        uint8_t ga0[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
        frame(&r.s, LC_H2_GOAWAY, 0, 0, ga0, sizeof ga0);
        ok(deliver(r.f, &r.s, 0) != 0, "GOAWAY before stream 1: the connection closes");
        collect(r.f, &r.w);
        const wframe *rst0 = find(&r.w, LC_H2_RST_STREAM, 0);
        ok(rst0 != NULL && rst0->stream == 1u && r.w.bytes[rst0->off + 3] == 0x8u &&
               count(&r.w, LC_H2_PING) == 0u && find(&r.w, PREFACE_TYPE, 0) == NULL,
           "after RST_STREAM(CANCEL) on stream 1 and no PING — it is closing anyway");
        lc_spider_fetch_free(r.f);

        /* PING: answered with its eight bytes. An interim answer is waited past. */
        start(&r);
        uint8_t pg[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
        frame(&r.s, LC_H2_PING, 0, 0, pg, sizeof pg);
        answer(&r.s, 1, 0, "103", NULL, NULL, NULL);
        answer(&r.s, 1, 1, "307", "/b", "0", NULL);
        deliver(r.f, &r.s, 0);
        collect(r.f, &r.w);
        const wframe *pong = find(&r.w, LC_H2_PING, 0);
        h = find(&r.w, LC_H2_HEADERS, 0);
        ok(pong != NULL && pong->flags == LC_H2_ACK && memcmp(r.w.bytes + pong->off, pg, 8) == 0,
           "a PING comes back with ACK and its eight bytes");
        ok(h != NULL && read_request(&r.w, h, &r.d, &next) == 0 &&
               strcmp(next.pseudo[2], ":path=/b") == 0,
           "a 103 is waited past, and the 307 after it followed");
        lc_spider_fetch_free(r.f);

        /* The site resets the stream and then answers it: RoundTrip takes the answer when both are
         * there (golang.org/issue/49645, vendor/x-net/http2/transport.go:1061-1075), the stream was
         * closed cleanly on both sides so nothing is reset back, and the redirect is followed on
         * stream 3. */
        start(&r);
        uint8_t code[4] = { 0, 0, 0, 2 };
        frame(&r.s, LC_H2_RST_STREAM, 0, 1, code, sizeof code);
        answer(&r.s, 1, 1, "302", "/a", "0", NULL);
        deliver(r.f, &r.s, 0);
        collect(r.f, &r.w);
        h = find(&r.w, LC_H2_HEADERS, 0);
        ok(h != NULL && h->stream == 3u && find(&r.w, LC_H2_RST_STREAM, 0) == NULL,
           "RST_STREAM then the answer: the answer wins, stream 3 follows, nothing reset back");
        lc_spider_fetch_free(r.f);

        /* Reset alone: RoundTrip's error, not one it retries — and nothing more. */
        start(&r);
        frame(&r.s, LC_H2_RST_STREAM, 0, 1, code, sizeof code);
        deliver(r.f, &r.s, 0);
        collect(r.f, &r.w);
        ok(find(&r.w, LC_H2_HEADERS, 0) == NULL && find(&r.w, LC_H2_RST_STREAM, 0) == NULL &&
               lc_spider_fetch_done(r.f),
           "RST_STREAM(INTERNAL_ERROR) and no answer: Do fails, nothing reset back");
        lc_spider_fetch_free(r.f);

        /* REFUSED_STREAM is retried at once, on the same connection. */
        start(&r);
        uint8_t refused[4] = { 0, 0, 0, 7 };
        frame(&r.s, LC_H2_RST_STREAM, 0, 1, refused, sizeof refused);
        deliver(r.f, &r.s, 0);
        collect(r.f, &r.w);
        h = find(&r.w, LC_H2_HEADERS, 0);
        ok(h != NULL && h->stream == 3u && read_request(&r.w, h, &r.d, &next) == 0 &&
               strcmp(next.pseudo[2], ":path=/") == 0 && get(&next, "referer") == NULL,
           "RST_STREAM(REFUSED_STREAM): the same request again at once, on stream 3");
        /* And again after a second, then two. */
        frame(&r.s, LC_H2_RST_STREAM, 0, 3, refused, sizeof refused);
        deliver(r.f, &r.s, 0);
        collect(r.f, &r.w);
        uint64_t due = lc_spider_fetch_deadline(r.f);
        ok(r.w.n == 0u && due == 1000u, "the second refusal waits a second — no more, no less");
        lc_spider_fetch_settle(r.f, 999);
        collect(r.f, &r.w);
        ok(r.w.n == 0u, "nothing before it");
        lc_spider_fetch_settle(r.f, 1000);
        collect(r.f, &r.w);
        h = find(&r.w, LC_H2_HEADERS, 0);
        ok(h != NULL && h->stream == 5u, "and then stream 5");
        frame(&r.s, LC_H2_RST_STREAM, 0, 5, refused, sizeof refused);
        deliver(r.f, &r.s, 0);
        ok(lc_spider_fetch_deadline(r.f) == 2000u, "the third waits two");
        lc_spider_fetch_free(r.f);

        /* PROTOCOL_ERROR from the peer: the connection is not reused — closed once stream 1 is
         * done — and the redirect's dial fails on it. */
        start(&r);
        uint8_t proto[4] = { 0, 0, 0, 1 };
        answer(&r.s, 1, 0, "302", "/a", NULL, NULL);
        frame(&r.s, LC_H2_RST_STREAM, 0, 1, proto, sizeof proto);
        ok(deliver(r.f, &r.s, 0) != 0 && (collect(r.f, &r.w), find(&r.w, LC_H2_HEADERS, 0) == NULL),
           "RST_STREAM(PROTOCOL_ERROR) after the answer: not reused, closed, no redirect");
        lc_spider_fetch_free(r.f);

        /* A response header x/net's framer refuses: the stream is reset, PROTOCOL_ERROR. */
        start(&r);
        lc_hpack_field bad[] = { { ":status", "302" }, { "location", "/a\x7f" } };
        uint8_t        blk[256];
        long           bl = lc_hpack_enc_block(&r.s.enc, bad, 2, blk, sizeof blk);
        frame(&r.s, LC_H2_HEADERS, LC_H2_END_HEADERS | LC_H2_END_STREAM, 1, blk, (size_t)bl);
        deliver(r.f, &r.s, 0);
        collect(r.f, &r.w);
        const wframe *rst = find(&r.w, LC_H2_RST_STREAM, 0);
        ok(rst != NULL && rst->stream == 1u && r.w.bytes[rst->off + 3] == 0x1u &&
               find(&r.w, LC_H2_HEADERS, 0) == NULL,
           "a header value with a control byte: RST_STREAM(PROTOCOL_ERROR), and no redirect");
        lc_spider_fetch_free(r.f);
    }

    printf("\nthe edges x/net draws\n");
    {
        /* Padding is handed back as its frame arrives — both windows, never read (processData,
         * vendor/x-net/http2/transport.go:2383-2424) — on the same inflow the reads refill: sixteen
         * frames of one byte and 256 of padding cross its 4096 on the sixteenth. */
        start(&r);
        answer(&r.s, 1, 0, "200", NULL, NULL, NULL);
        deliver(r.f, &r.s, 0);
        collect(r.f, &r.w);
        uint8_t padded[257];
        memset(padded, 0, sizeof padded);
        padded[0] = 255;
        padded[1] = 'x';
        unsigned wus = 0, at16 = 0;
        for (unsigned i = 0; i < 16u; i++) {
            frame(&r.s, LC_H2_DATA, LC_H2_PADDED, 1, padded, sizeof padded);
            deliver(r.f, &r.s, 0);
            collect(r.f, &r.w);
            wus += count(&r.w, LC_H2_WINDOW_UPDATE);
            if (i == 15u && r.w.writes == 1u && count(&r.w, LC_H2_WINDOW_UPDATE) == 2u)
                at16 = (uint32_t)r.w.bytes[r.w.fr[0].off + 2] << 8 | r.w.bytes[r.w.fr[0].off + 3];
        }
        ok(wus == 2u && at16 == 4111u,
           "padded DATA: its padding, pad-length byte and all, back as it arrives — 16 frames of 1 "
           "and 256 make 4111, at the sixteenth");
        lc_spider_fetch_free(r.f);

        /* The slurp is two kilobytes of what gzip.Reader hands out, not of what it reads: a stream
         * whose sync flush gives exactly 2048 is done there, one fill in. */
        {
            static uint8_t hex[40000], gz[50000];
            uint32_t       x = 88172645u;
            for (size_t i = 0; i < sizeof hex; i++) {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                hex[i] = (uint8_t)"0123456789abcdef"[x & 15u];
            }
            z_stream z;
            memset(&z, 0, sizeof z);
            deflateInit2(&z, 6, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
            z.next_out = gz;
            z.avail_out = sizeof gz;
            z.next_in = hex;
            z.avail_in = 2048;
            deflate(&z, Z_SYNC_FLUSH);
            z.avail_in = sizeof hex - 2048u;
            deflate(&z, Z_FINISH);
            size_t len = sizeof gz - z.avail_out;
            deflateEnd(&z);
            oracle o;
            slurp_oracle(gz, len, &o);
            start(&r);
            answer(&r.s, 1, 0, "302", "/a", NULL, "gzip");
            body(&r.s, 1, gz, len, 1);
            deliver(r.f, &r.s, 0);
            collect(r.f, &r.w);
            uint32_t strm = 0;
            for (unsigned i = 0; i < r.w.n; i++)
                if (r.w.fr[i].type == LC_H2_WINDOW_UPDATE && r.w.fr[i].stream == 1u)
                    strm += (uint32_t)r.w.bytes[r.w.fr[i].off + 2] << 8 | r.w.bytes[r.w.fr[i].off + 3];
            ok(o.consumed == 4096u && strm == 4096u && find(&r.w, LC_H2_HEADERS, 0) != NULL,
               "a sync flush of exactly 2048: the slurp stops after one fill");
            lc_spider_fetch_free(r.f);
        }

        /* Close hands back exactly 4096 — inflow.add's threshold, met. */
        start(&r);
        answer(&r.s, 1, 0, "302", "/a", "4096", NULL);
        filler(&r.s, 1, 4096, 1);
        deliver(r.f, &r.s, 0);
        collect(r.f, &r.w);
        const wframe *wu = find(&r.w, LC_H2_WINDOW_UPDATE, 0);
        ok(wu != NULL && wu->stream == 0u && r.w.bytes[wu->off + 2] == 0x10u &&
               r.w.bytes[wu->off + 3] == 0u,
           "an unread body of 4096: +4096 on the connection at Close");
        lc_spider_fetch_free(r.f);

        /* A page longer than its Content-Length, ended in the same frame: the read that finds it
         * aborts the stream, but the peer had closed it too — so cleanupWriteRequest sees a stream
         * closed on both sides and resets nothing (vendor/x-net/http2/transport.go:1335-1344). */
        start_on(&r, "long.example");
        answer(&r.s, 1, 0, "200", NULL, "10", NULL);
        deliver(r.f, &r.s, 0);
        collect(r.f, &r.w);
        body(&r.s, 1, (const uint8_t *)"0123456789abcdefghij", 20, 1);
        deliver(r.f, &r.s, 0);
        collect(r.f, &r.w);
        ok(count(&r.w, LC_H2_RST_STREAM) == 0u && lc_spider_fetch_done(r.f),
           "a body past its Content-Length with END_STREAM: an error to the reader, no RST_STREAM");
        lc_spider_fetch_free(r.f);

        /* A CONTINUATION for another stream than the HEADERS it follows: the connection. */
        start(&r);
        lc_hpack_field st[] = { { ":status", "302" } };
        uint8_t        blk[64];
        long           bl = lc_hpack_enc_block(&r.s.enc, st, 1, blk, sizeof blk);
        frame(&r.s, LC_H2_HEADERS, 0, 1, blk, (size_t)bl);
        frame(&r.s, 0x9u, LC_H2_END_HEADERS, 3, NULL, 0);
        ok(deliver(r.f, &r.s, 0) != 0, "a CONTINUATION on another stream ends the connection");
        lc_spider_fetch_free(r.f);

        /* A SETTINGS acknowledgement nobody asked for. */
        start(&r);
        frame(&r.s, LC_H2_SETTINGS, LC_H2_ACK, 0, NULL, 0);
        frame(&r.s, LC_H2_SETTINGS, LC_H2_ACK, 0, NULL, 0);
        ok(deliver(r.f, &r.s, 0) != 0, "a second SETTINGS ACK ends the connection");
        lc_spider_fetch_free(r.f);

        /* A header list past MAX_HEADER_LIST_SIZE: the block goes on being decoded without its
         * fields — Truncated — until a fragment comes in larger than twice what is left, which is any
         * at all once nothing is: the connection (readMetaFrame,
         * vendor/x-net/http2/frame.go:1776-1806). */
        start(&r);
        deliver(r.f, &r.s, 0);
        collect(r.f, &r.w);
        static uint8_t big[16006];
        big[0] = 0x00;
        big[1] = 0x01;
        big[2] = 'x';
        big[3] = 0x7f;
        big[4] = 0x81;
        big[5] = 0x7c;
        memset(big + 6, 'a', 16000);
        frame(&r.s, LC_H2_HEADERS, 0, 1, blk, (size_t)bl);
        int rc = lc_spider_fetch_feed(r.f, r.s.buf, r.s.len);
        unsigned sent = 0;
        for (; rc == 0 && sent < 700u; sent++) {
            r.s.len = 0;
            frame(&r.s, 0x9u, sent == 699u ? LC_H2_END_HEADERS : 0u, 1, big, sizeof big);
            rc = lc_spider_fetch_feed(r.f, r.s.buf, r.s.len);
        }
        r.s.len = 0;
        char line[120];
        snprintf(line, sizeof line,
                 "a header list past ten megabytes: the connection, at CONTINUATION %u", sent);
        ok(rc != 0 && sent == reference_header_continuation_cutoff, line);
        collect(r.f, &r.w);
        ok(count(&r.w, LC_H2_RST_STREAM) == 0u, "and no stream reset over it");
        lc_spider_fetch_free(r.f);
    }

    printf("\nwhat Go 1.27's client does, which Xray v26.9.9 is built with\n");
    {
        /* Setting.Valid, asked of every setting as it is read (vendor/x-net/http2/transport.go:
         * 2548-2551, vendor/x-net/http2/http2.go:141-160): out of range ends the connection before
         * the ACK. This checked MAX_FRAME_SIZE 0 as "taken" — an endless run of empty CONTINUATIONs
         * behind a stuck writer — which no reference, x/net's or net/http's, ever did. */
        static const struct {
            uint16_t    id;
            uint32_t    v;
            int         ends;
            const char *what;
        } sv[] = {
            { 0x5u, 0u, 1, "SETTINGS_MAX_FRAME_SIZE 0 ends the connection, unacknowledged" },
            { 0x5u, 16383u, 1, "so does 16383" },
            { 0x5u, 16777216u, 1, "and 2^24" },
            { 0x2u, 2u, 1, "SETTINGS_ENABLE_PUSH 2 ends it too" },
            { 0x8u, 2u, 1, "and SETTINGS_ENABLE_CONNECT_PROTOCOL 2" },
            { 0x5u, 16384u, 0, "MAX_FRAME_SIZE 16384 is taken and acknowledged" },
            { 0x5u, 16777215u, 0, "and 2^24-1" },
        };
        for (size_t i = 0; i < sizeof sv / sizeof sv[0]; i++) {
            start(&r);
            r.s.len = 0;
            settings(&r.s, sv[i].id, sv[i].v);
            int rc = deliver(r.f, &r.s, 0);
            collect(r.f, &r.w);
            const wframe *ack = find(&r.w, LC_H2_SETTINGS, 0);
            int acked = ack != NULL && ack->flags == LC_H2_ACK;
            ok(sv[i].ends ? rc != 0 && !acked : rc == 0 && acked, sv[i].what);
            lc_spider_fetch_free(r.f);
        }

        /* Go 1.27.3 detects an initial-window overflow lazily on a later query. */
        start(&r);
        uint8_t wu[4] = { 0x7f, 0xff, 0x00, 0x00 }; /* 2^31-1 - 65535, onto 65535 */
        frame(&r.s, LC_H2_WINDOW_UPDATE, 0, 1, wu, sizeof wu);
        settings(&r.s, 0x4u, 65536u);
        ok(deliver(r.f, &r.s, 0) == 0,
           "INITIAL_WINDOW_SIZE acknowledges a temporarily overflowing stream window");
        collect(r.f, &r.w);
        unsigned flow_acks = count(&r.w, LC_H2_SETTINGS);
        printf("FLOW_ORACLE {\"case\":\"settings_only\",\"settings_ack\":%u,\"conn_closed\":false,\"stream_flow\":%u}\n",
               flow_acks, count(&r.w, LC_H2_RST_STREAM));
        r.s.len = 0;
        uint8_t one[4] = {0, 0, 0, 1};
        frame(&r.s, LC_H2_WINDOW_UPDATE, 0, 1, one, sizeof one);
        int flow_rc = deliver(r.f, &r.s, 0);
        ok(flow_rc != 0, "a later WINDOW_UPDATE detects a connection flow error");
        collect(r.f, &r.w);
        printf("FLOW_ORACLE {\"case\":\"window_detects\",\"settings_ack\":%u,\"conn_closed\":%s,\"stream_flow\":%u}\n",
               flow_acks + count(&r.w, LC_H2_SETTINGS), flow_rc != 0 ? "true" : "false",
               count(&r.w, LC_H2_RST_STREAM));
        lc_spider_fetch_free(r.f);
        start(&r);
        frame(&r.s, LC_H2_WINDOW_UPDATE, 0, 1, wu, sizeof wu);
        settings(&r.s, 0x4u, 65536u);
        settings(&r.s, 0x4u, 65534u);
        frame(&r.s, LC_H2_WINDOW_UPDATE, 0, 1, one, sizeof one);
        flow_rc = deliver(r.f, &r.s, 0);
        collect(r.f, &r.w);
        ok(flow_rc == 0 && find(&r.w, LC_H2_RST_STREAM, 0) == NULL,
           "a later SETTINGS can restore the window before any overflow query");
        printf("FLOW_ORACLE {\"case\":\"settings_restore\",\"settings_ack\":%u,\"conn_closed\":%s,\"stream_flow\":%u}\n",
               count(&r.w, LC_H2_SETTINGS), flow_rc != 0 ? "true" : "false",
               count(&r.w, LC_H2_RST_STREAM));
        lc_spider_fetch_free(r.f);
        start(&r);
        frame(&r.s, LC_H2_WINDOW_UPDATE, 0, 1, wu, sizeof wu);
        settings(&r.s, 0x4u, 65535u);
        ok(deliver(r.f, &r.s, 0) == 0, "and one it can take does not");
        lc_spider_fetch_free(r.f);

        /* GOAWAY on a connection with nothing open: the readLoop ends and the connection closes
         * (processGoAway, GOROOT/src/net/http/internal/http2/transport.go:2641-2644); x/net kept it
         * open until the server closed it. */
        start(&r);
        const char page[] = "<html></html>";
        answer(&r.s, 1, 0, "200", NULL, NULL, NULL);
        body(&r.s, 1, (const uint8_t *)page, sizeof page - 1u, 1);
        ok(deliver(r.f, &r.s, 0) == 0, "a page read whole leaves the connection open");
        uint8_t idle[8] = { 0, 0, 0, 1, 0, 0, 0, 0 };
        frame(&r.s, LC_H2_GOAWAY, 0, 0, idle, sizeof idle);
        ok(deliver(r.f, &r.s, 0) != 0, "and a GOAWAY after it, with nothing open, closes it");
        lc_spider_fetch_free(r.f);

        /* Trailers past MAX_HEADER_LIST_SIZE — Truncated, and not so far past it that the framer
         * ends the connection — reset the stream, PROTOCOL_ERROR (processTrailers,
         * GOROOT/src/net/http/internal/http2/transport.go:2322-2329); x/net kept what it had. 654
         * fields of 16033 leave 178 of the ten megabytes, and a field of 233 in a fragment of 205
         * is past that without being past twice it (vendor/x-net/http2/frame.go:1776-1796). */
        start(&r);
        answer(&r.s, 1, 0, "200", NULL, NULL, NULL);
        deliver(r.f, &r.s, 0);
        static uint8_t tbig[16006];
        tbig[0] = 0x00;
        tbig[1] = 0x01;
        tbig[2] = 'x';
        tbig[3] = 0x7f;
        tbig[4] = 0x81;
        tbig[5] = 0x7c;
        memset(tbig + 6, 'a', 16000);
        int rc = 0;
        for (unsigned k = 0; k < 654u && rc == 0; k++) {
            r.s.len = 0;
            frame(&r.s, k == 0u ? LC_H2_HEADERS : 0x9u, k == 0u ? LC_H2_END_STREAM : 0u, 1, tbig,
                  sizeof tbig);
            rc = lc_spider_fetch_feed(r.f, r.s.buf, r.s.len);
        }
        static uint8_t tlast[205];
        tlast[0] = 0x00;
        tlast[1] = 0x01;
        tlast[2] = 'y';
        tlast[3] = 0x7f;
        tlast[4] = 0x49; /* 127 + 73 = 200 */
        memset(tlast + 5, 'b', 200);
        r.s.len = 0;
        frame(&r.s, 0x9u, LC_H2_END_HEADERS, 1, tlast, sizeof tlast);
        if (rc == 0)
            rc = deliver(r.f, &r.s, 0);
        collect(r.f, &r.w);
        const wframe *tr = find(&r.w, LC_H2_RST_STREAM, 0);
        ok(rc == 0 && tr != NULL && tr->stream == 1u && r.w.bytes[tr->off + 3] == 0x1u,
           "trailers just past ten megabytes: the stream reset, PROTOCOL_ERROR, the connection kept");
        lc_spider_fetch_free(r.f);
    }

    printf("\nthe page: harvested only when it is read whole\n");
    {
        /* Each on a name of its own: what a page harvests is what later first requests to the name
         * draw from, and the rest of this file asks for "/" on HOST. */
        const char *hosts[] = { "whole.example", "short.example", "reset.example" };
        const char *what[] = { "a page read to its end is harvested",
                               "one shorter than its Content-Length is not",
                               "one the site resets half-way is not" };
        const char  page[] = "<a href=\"/found\">x</a>";
        for (unsigned i = 0; i < 3u; i++) {
            lc_browser b;
            site       s;
            lc_hpack_enc_init(&s.enc);
            s.len = 0;
            lc_browser_chrome_anchored(&b, LC_BROWSER_NAV);
            lc_spider_fetch *f = lc_spider_fetch_new(hosts[i], &b);
            lc_spider_fetch_settle(f, 0);
            collect(f, &r.w);
            settings(&s, 0, 0);
            answer(&s, 1, 0, "200", NULL, i == 1u ? "100" : i == 2u ? NULL : "22", NULL);
            if (i == 2u) {
                body(&s, 1, (const uint8_t *)page, sizeof page - 1u, 0); /* the whole link, no end */
                uint8_t code[4] = { 0, 0, 0, 2 };
                frame(&s, LC_H2_RST_STREAM, 0, 1, code, sizeof code);
            } else {
                body(&s, 1, (const uint8_t *)page, sizeof page - 1u, 1);
            }
            deliver(f, &s, 0);
            lc_spider_fetch_free(f);
            int found = 0;
            for (unsigned k = 0; k < 200u && !found; k++) {
                found = drawn_is(hosts[i], "/found");
            }
            ok(found == (i == 0u), what[i]);
        }

        /* The site ends the page and closes the connection in the same read: what was fed is
         * settled before the loss, so the finished page is harvested; a page it had not finished is
         * aborted with the connection, and nothing acts after it. */
        const char *lost_hosts[] = { "lostwhole.example", "losthalf.example" };
        for (unsigned i = 0; i < 2u; i++) {
            lc_browser b;
            site       s;
            lc_hpack_enc_init(&s.enc);
            s.len = 0;
            lc_browser_chrome_anchored(&b, LC_BROWSER_NAV);
            lc_spider_fetch *f = lc_spider_fetch_new(lost_hosts[i], &b);
            lc_spider_fetch_settle(f, 0);
            collect(f, &r.w);
            settings(&s, 0, 0);
            answer(&s, 1, 0, "200", NULL, NULL, NULL);
            body(&s, 1, (const uint8_t *)page, sizeof page - 1u, i == 0u);
            int fed = lc_spider_fetch_feed(f, s.buf, s.len);
            int settled = lc_spider_fetch_settle(f, 0);
            lc_spider_fetch_lost(f);
            int after = lc_spider_fetch_settle(f, 0);
            lc_spider_fetch_free(f);
            int found = 0;
            for (unsigned k = 0; k < 200u && !found; k++) {
                found = drawn_is(lost_hosts[i], "/found");
            }
            ok(fed == 0 && settled == 0 && after == -1 && found == (i == 0u),
               i == 0u ? "a page the site finished before closing is harvested"
                       : "one it closed half-way is not, and the fetch is over");
        }

        /* A gzip page: its text harvested through Go's reader — when it inflates to the end, and
         * not at all when it breaks, even after links it had already passed. */
        const char *gz_hosts[] = { "zipped.example", "broken.example" };
        for (unsigned i = 0; i < 2u; i++) {
            const char   *text = "<html><a href=\"/zipped\">x</a><a href=\"/also\">y</a></html>";
            unsigned char gz[512];
            z_stream      z;
            memset(&z, 0, sizeof z);
            deflateInit2(&z, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
            z.next_in = (Bytef *)(uintptr_t)text;
            z.avail_in = (uInt)strlen(text);
            z.next_out = gz;
            z.avail_out = sizeof gz;
            deflate(&z, i == 0u ? Z_FINISH : Z_FULL_FLUSH);
            size_t gz_len = sizeof gz - z.avail_out;
            deflateEnd(&z);
            if (i == 1u) {
                memset(gz + gz_len, 0xff, 16u); /* a block type that does not exist */
                gz_len += 16u;
            }
            lc_browser b;
            site       s;
            lc_hpack_enc_init(&s.enc);
            s.len = 0;
            lc_browser_chrome_anchored(&b, LC_BROWSER_NAV);
            lc_spider_fetch *f = lc_spider_fetch_new(gz_hosts[i], &b);
            lc_spider_fetch_settle(f, 0);
            collect(f, &r.w);
            settings(&s, 0, 0);
            answer(&s, 1, 0, "200", NULL, NULL, "gzip");
            deliver(f, &s, 0);
            body(&s, 1, gz, 1u, 0); /* the magic's first byte alone */
            deliver(f, &s, 0);
            body(&s, 1, gz + 1, gz_len - 1u, 1);
            deliver(f, &s, 0);
            lc_spider_fetch_free(f);
            int found = 0;
            for (unsigned k = 0; k < 200u && !found; k++) {
                found = drawn_is(gz_hosts[i], "/zipped");
            }
            ok(found == (i == 0u), i == 0u ? "a gzip page is inflated and harvested, split one byte in"
                                           : "a gzip page that breaks harvests nothing, not even "
                                             "what came first");
        }
    }

    printf("\nwhat ends the connection\n");
    {
        start(&r);
        r.s.len = 0;
        answer(&r.s, 1, 1, "302", "/a", "0", NULL);
        ok(deliver(r.f, &r.s, 0) != 0, "a first frame that is not SETTINGS");
        lc_spider_fetch_free(r.f);

        start(&r);
        r.s.len = 0;
        uint8_t early[8] = { 0 };
        frame(&r.s, LC_H2_PING, 0, 0, early, sizeof early);
        ok(deliver(r.f, &r.s, 0) != 0, "nor a PING before it");
        collect(r.f, &r.w);
        ok(r.w.n == 0u, "and it is not answered");
        lc_spider_fetch_free(r.f);

        start(&r);
        filler(&r.s, 3, 10, 1);
        ok(deliver(r.f, &r.s, 0) != 0, "DATA on a stream never opened — the next one it would have");
        lc_spider_fetch_free(r.f);

        start(&r);
        uint8_t junk[3] = { 0xff, 0xff, 0xff };
        frame(&r.s, LC_H2_HEADERS, LC_H2_END_HEADERS, 1, junk, sizeof junk);
        ok(deliver(r.f, &r.s, 0) != 0, "a header block the decoder cannot read: COMPRESSION_ERROR");
        lc_spider_fetch_free(r.f);
    }

    printf("\nthe window handed back while the page is read, against Go's own readers\n");
    {
        /* For each page of tools/spiderflow: its answer, then its frames one at a time — the reader
         * drains each before the next lands — and every write the fetch makes compared with the
         * WINDOW_UPDATEs io.ReadAll over x/net's body made in Go, through gzip.Reader when the page
         * is gzip. Last because the pages' links go into the name's set. */
        for (unsigned c = 0; c < (unsigned)(sizeof spiderflow / sizeof spiderflow[0]); c++) {
            start(&r);
            answer(&r.s, 1, 0, "200", NULL, NULL, spiderflow[c].gzip ? "gzip" : NULL);
            deliver(r.f, &r.s, 0);
            collect(r.f, &r.w);
            unsigned got = 0, bad = 0;
            size_t   at = 0;
            for (unsigned i = 0; i < spiderflow[c].nframes; i++) {
                size_t n = spiderflow[c].frames[i];
                frame(&r.s, LC_H2_DATA,
                      (uint8_t)(i + 1u == spiderflow[c].nframes ? LC_H2_END_STREAM : 0u), 1,
                      spiderflow[c].body + at, n);
                at += n;
                deliver(r.f, &r.s, 0);
                collect(r.f, &r.w);
                for (unsigned wr = 0; wr < r.w.writes; wr++) {
                    uint32_t cn = 0, st = 0;
                    for (unsigned k = 0; k < r.w.n; k++) {
                        const wframe *wf = &r.w.fr[k];
                        if (wf->write != wr || wf->type != LC_H2_WINDOW_UPDATE)
                            continue;
                        uint32_t inc = (uint32_t)r.w.bytes[wf->off] << 24 |
                                       (uint32_t)r.w.bytes[wf->off + 1] << 16 |
                                       (uint32_t)r.w.bytes[wf->off + 2] << 8 |
                                       r.w.bytes[wf->off + 3];
                        if (wf->stream == 0u)
                            cn = inc;
                        else
                            st = inc;
                    }
                    if (got >= spiderflow[c].nupdates || cn != spiderflow[c].updates[got][0] ||
                        st != spiderflow[c].updates[got][1])
                        bad++;
                    got++;
                }
            }
            char line[160];
            snprintf(line, sizeof line, "%s: %u window updates, as Go's readers make them",
                     spiderflow[c].name, spiderflow[c].nupdates);
            ok(bad == 0 && got == spiderflow[c].nupdates && at == spiderflow[c].body_len &&
                   lc_spider_fetch_done(r.f),
               line);
            lc_spider_fetch_free(r.f);
        }
    }

    /* Where each hop of a redirect chain goes out — the ClientConn it has, a second opening, or
     * none, the connection closed — as the reference's net/http of Go 1.27 does it
     * (tools/spiderpool, which runs it). */
    printf("\nspider: the connection each hop goes out on, against Go 1.27's own client\n");
    {
        unsigned bad = 0, n = sizeof spiderpool / sizeof spiderpool[0];
        for (unsigned c = 0; c < n; c++) {
            char ev[4096];
            pool_events(spiderpool[c].host, spiderpool[c].locs, ev, sizeof ev);
            if (strcmp(ev, spiderpool[c].events) != 0 && bad++ < 8u)
                printf("        %s > %s: %s, Go %s\n", spiderpool[c].host,
                       spiderpool[c].locs[0], ev, spiderpool[c].events);
        }
        char line[160];
        snprintf(line, sizeof line, "all %u chains go out as Go's client sends them", n);
        ok(bad == 0, line);
    }


    /* A dequeued write belongs to its consumer, not to the fetch's reallocatable output queue. */
    {
        lc_browser b;
        int made = lc_browser_chrome_anchored(&b, LC_BROWSER_NAV) == 0;
        lc_spider_fetch *f = made ? lc_spider_fetch_new("ownership.example", &b) : NULL;
        uint8_t *opening = NULL, *request_bytes = NULL;
        long n = lc_spider_fetch_take(f, &opening);
        ok(n >= 24 && opening != NULL, "take transfers a complete opening write");
        if (f != NULL) {
            ok(lc_spider_fetch_step(f, 0) == 1,
               "the first Do transition commits and yields while its opening is held");
            ok(lc_spider_fetch_step(f, 0) == 0 && !lc_spider_fetch_done(f),
               "the resumed request waits for response input instead of yielding forever");
            long request_len = lc_spider_fetch_take(f, &request_bytes);
            ok(request_len > 0 && request_bytes != NULL, "the next write has independent ownership");
        }
        lc_spider_fetch_free(f);
        ok(n >= 24 && opening != NULL && memcmp(opening, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0,
           "a transferred write survives queue mutation and fetch destruction");
        free(opening);
        free(request_bytes);
        uint8_t *empty = (uint8_t *)(void *)&b;
        ok(lc_spider_fetch_take(NULL, &empty) == 0 && empty == NULL,
           "an empty take clears its output pointer");
    }

    {
        int started = start_on(&r, "body-owner.example") == 0;
        ok(started, "a fetch with an independent body-consumer turn");
        if (started) {
            answer(&r.s, 1, 0, "200", NULL, NULL, NULL);
            ok(deliver(r.f, &r.s, 0) == 0, "Do starts reading the response body");
            collect(r.f, &r.w);
            uint8_t data[8192];
            memset(data, 'x', sizeof data);
            body(&r.s, 1, data, sizeof data, 1);
            ok(lc_spider_fetch_feed(r.f, r.s.buf, r.s.len) == 0,
               "the readLoop delivers DATA and END_STREAM without running Do");
            r.s.len = 0;
            collect(r.f, &r.w);
            ok(!lc_spider_fetch_done(r.f) && count(&r.w, LC_H2_WINDOW_UPDATE) == 0u,
               "feed alone neither consumes body bytes nor returns their window");
            ok(lc_spider_fetch_step(r.f, 0) == 1 && !lc_spider_fetch_done(r.f),
               "the body consumer yields after accounting one complete Read");
            /* Mutate the pipe between consumer calls. No returned source pointer may survive the
             * step boundary; an END_STREAM is already present so a PING only advances readLoop. */
            uint8_t ping[LC_H2_HEADER + 8u] = { 0 };
            (void)lc_h2_put_header(ping, sizeof ping, 8, LC_H2_PING, 0, 0);
            ok(lc_spider_fetch_feed(r.f, ping, sizeof ping) == 0,
               "readLoop progresses between body consumer steps");
            int rc = 1;
            unsigned steps = 0;
            while (rc == 1 && steps++ < 128u)
                rc = lc_spider_fetch_step(r.f, 0);
            ok(rc == 0 && lc_spider_fetch_done(r.f),
               "body continuation reaches EOF without a new DATA notification");
            collect(r.f, &r.w);
            ok(count(&r.w, LC_H2_WINDOW_UPDATE) > 0u,
               "body consumption returns the window on the Do turn");
            lc_spider_fetch_free(r.f);
        }
    }
    {
        int started = start_on(&r, "step-redirect.example") == 0;
        ok(started, "a redirect with separate close and next-request continuations");
        if (started) {
            ok(deliver(r.f, &r.s, 0) == 0, "the redirect connection accepts SETTINGS");
            collect(r.f, &r.w);
            answer(&r.s, 1, 0, "302", "/next", "5000", NULL);
            ok(lc_spider_fetch_feed(r.f, r.s.buf, r.s.len) == 0,
               "the response arrives with its large body still pending");
            r.s.len = 0;
            ok(lc_spider_fetch_step(r.f, 0) == 1,
               "response handling yields before body Close");
            collect(r.f, &r.w);
            ok(count(&r.w, LC_H2_RST_STREAM) == 0u && count(&r.w, LC_H2_HEADERS) == 0u,
               "response handling publishes neither cancellation nor next request");
            ok(lc_spider_fetch_write_barrier(r.f) == 0,
               "redirect cancellation uses completion-aware handoff");
            ok(lc_spider_fetch_step(r.f, 0) == 1,
               "Close signals independent cleanup and yields before its reset decision");
            ok(lc_spider_fetch_step(r.f, 0) == 1,
               "Close waits for cleanup Write completion before the next request");
            uint8_t *cancel_write = NULL;
            long cancel_len = lc_spider_fetch_take(r.f, &cancel_write);
            ok(cancel_len > 0 && lc_spider_fetch_step(r.f, 0) == 2,
               "taking CANCEL cannot advance redirect before socket completion");
            lc_h2_hd cancel_header;
            ok(cancel_len >= (long)LC_H2_HEADER &&
                   lc_h2_get_header(cancel_write, (size_t)cancel_len, &cancel_header) == 0 &&
                   cancel_header.type == LC_H2_RST_STREAM && cancel_header.stream == 1u,
               "the in-flight write starts with the previous stream cancellation");
            uint8_t ping[LC_H2_HEADER + 8u] = {0};
            (void)lc_h2_put_header(ping, sizeof ping, 8u, LC_H2_PING, 0, 0);
            memset(ping + LC_H2_HEADER, 0x78, 8u);
            ok(lc_spider_fetch_feed(r.f, ping, sizeof ping) == 0 &&
                   !lc_spider_fetch_read_ready(r.f),
               "PING waits on the cleanup reset Flush owner");
            ok(lc_spider_fetch_write_complete(r.f, 1) == 0,
               "the TLS owner confirms cancellation completion");
            free(cancel_write);
            uint8_t *cleanup_ack = NULL;
            ok(lc_spider_fetch_take(r.f, &cleanup_ack) == 0 && cleanup_ack == NULL,
               "cleanup completion leaves the separate donec check without preconstructing the waiting ACK");
            ok(lc_spider_fetch_step(r.f, 0) == 1,
               "readLoop dispatch resumes after cleanup owner releases cc.wmu");
            long cleanup_ack_len = lc_spider_fetch_take(r.f, &cleanup_ack);
            ok(cleanup_ack_len == 17 && cleanup_ack[3] == LC_H2_PING && cleanup_ack[16] == 0x78 &&
                   lc_spider_fetch_write_complete(r.f, 1) == 0,
               "cleanup's saved PING ACK completes without duplicate reset or redirect HEADERS");
            free(cleanup_ack);
            collect(r.f, &r.w);
            ok(count(&r.w, LC_H2_RST_STREAM) == 0u && count(&r.w, LC_H2_HEADERS) == 0u,
               "cancellation completion does not repeat CANCEL or generate HEADERS itself");
            const wframe *next_headers = NULL;
            int duplicate_cancel = 0;
            for (unsigned turn = 0; turn < 8u && next_headers == NULL; turn++) {
                int rc = lc_spider_fetch_step(r.f, 0);
                collect(r.f, &r.w);
                duplicate_cancel |= count(&r.w, LC_H2_RST_STREAM) != 0u;
                next_headers = find(&r.w, LC_H2_HEADERS, 0);
                if (rc != 1)
                    break;
            }
            ok(next_headers != NULL && next_headers->stream == 3u &&
                   !duplicate_cancel,
               "stream 3 HEADERS follow Close without repeating CANCEL");
            ok(lc_spider_fetch_write_complete(r.f, 1) == 0,
               "redirect request completion releases the consumer barrier");
            ok(lc_spider_fetch_step(r.f, 0) == 0,
               "the redirect attempt waits for new response input");
            lc_spider_fetch_free(r.f);
        }
    }
    {
        lc_browser b;
        int made = lc_browser_chrome_anchored(&b, LC_BROWSER_NAV) == 0;
        lc_spider_fetch *f = made ? lc_spider_fetch_new("write-barrier.example", &b) : NULL;
        ok(f != NULL && lc_spider_fetch_write_barrier(f) == 0,
           "a fetch with explicit write-completion ownership");
        if (f != NULL) {
            uint8_t *bytes = NULL, *other = NULL;
            ok(lc_spider_fetch_settle(f, 0) == -1,
               "the legacy settle driver cannot bypass write-completion ownership");
            ok(lc_spider_fetch_step(f, 0) == 2,
               "queued opening prevents consumer progress");
            ok(!lc_spider_fetch_read_ready(f),
               "readLoop is not started before opening Flush completion");
            long n = lc_spider_fetch_take(f, &bytes);
            ok(n > 0 && lc_spider_fetch_step(f, 0) == 2,
               "taking the opening does not complete its socket Write");
            ok(!lc_spider_fetch_read_ready(f),
               "taking opening bytes does not start readLoop");
            ok(lc_spider_fetch_take(f, &other) == 0 && other == NULL,
               "only one write can be in flight");
            ok(lc_spider_fetch_write_complete(f, 1) == 0 &&
                   lc_spider_fetch_step(f, 0) == 1,
               "confirmed opening completion permits request generation");
            ok(lc_spider_fetch_read_ready(f),
               "opening completion starts readLoop despite pending request Write");
            free(bytes);
            bytes = NULL;
            ok(lc_spider_fetch_write_complete(f, 1) == -1,
               "duplicate completion is refused");
            n = lc_spider_fetch_take(f, &bytes);
            ok(n > 0 && lc_spider_fetch_write_complete(f, 0) == 0 &&
                   lc_spider_fetch_step(f, 0) == -1,
               "a failed socket Write terminates consumer progress");
            free(bytes);
            lc_spider_fetch_stop(f);
            lc_spider_fetch_free(f);
        }
    }
    {
        lc_browser b;
        int made = lc_browser_chrome_anchored(&b, LC_BROWSER_NAV) == 0;
        lc_spider_fetch *f = made ? lc_spider_fetch_new("completion-wait.example", &b) : NULL;
        ok(f != NULL && lc_spider_fetch_write_barrier(f) == 0,
           "a completion waiter with an outstanding opening write");
        if (f != NULL) {
            uint8_t *bytes = NULL;
            long n = lc_spider_fetch_take(f, &bytes);
            concurrent_fetch waiter = { f, 0, 0 };
            pthread_t thread;
            int created = pthread_create(&thread, NULL, wait_completion, &waiter);
            uint8_t settings_frame[LC_H2_HEADER] = { 0 };
            (void)lc_h2_put_header(settings_frame, sizeof settings_frame, 0, LC_H2_SETTINGS, 0, 0);
            ok(n > 0 && lc_spider_fetch_feed(f, settings_frame, sizeof settings_frame) == 0 &&
                   lc_spider_fetch_step(f, 0) == 2,
               "input while a Write is outstanding leaves consumer blocked");
            ok(lc_spider_fetch_write_complete(f, 1) == 0,
               "opening completion releases the saved peer input, not an ACK");
            free(bytes);
            bytes = NULL;
            ok(lc_spider_fetch_step(f, 0) == 1 && !lc_spider_fetch_read_ready(f),
               "saved SETTINGS dispatches only after opening completion and blocks on its ACK");
            n = lc_spider_fetch_take(f, &bytes);
            ok(n > 0 && lc_spider_fetch_step(f, 0) == 2 &&
                   lc_spider_fetch_write_complete(f, 1) == 0,
               "completion of every queued write releases the barrier");
            free(bytes);
            if (created == 0)
                pthread_join(thread, NULL);
            ok(created == 0 && !waiter.failed,
               "the completion waiter returns after barrier release, regardless of startup order");
            lc_spider_fetch_stop(f);
            lc_spider_fetch_free(f);
        }
    }
    {
        lc_browser b;
        int made = lc_browser_chrome_anchored(&b, LC_BROWSER_NAV) == 0;
        lc_spider_fetch *f = made ? lc_spider_fetch_new("stop-write.example", &b) : NULL;
        ok(f != NULL && lc_spider_fetch_write_barrier(f) == 0,
           "a stopped consumer with a Write still outstanding");
        if (f != NULL) {
            uint8_t *bytes = NULL;
            long n = lc_spider_fetch_take(f, &bytes);
            concurrent_fetch waiter = { f, 0, 0 };
            pthread_t thread;
            int created = pthread_create(&thread, NULL, wait_stopped, &waiter);
            lc_spider_fetch_stop(f);
            if (created == 0)
                pthread_join(thread, NULL);
            ok(n > 0 && created == 0 && !waiter.failed && lc_spider_fetch_step(f, 0) == 0,
               "stop releases a completion waiter without acknowledging the outstanding Write");
            lc_spider_fetch_free(f);
            ok(n >= 24 && bytes != NULL && memcmp(bytes, "PRI * HTTP/2.0", 14) == 0,
               "the abandoned in-flight bytes remain owned by the TLS caller after destruction");
            free(bytes);
        }
    }
    {
        int started = start_on(&r, "step-cleanup.example") == 0;
        ok(started, "a finished stream for cleanup continuation");
        if (started) {
            ok(deliver(r.f, &r.s, 0) == 0, "the cleanup connection accepts SETTINGS");
            collect(r.f, &r.w);
            answer(&r.s, 1, 1, "200", NULL, "0", NULL);
            ok(lc_spider_fetch_feed(r.f, r.s.buf, r.s.len) == 0,
               "the response closes its stream before Do runs");
            r.s.len = 0;
            ok(lc_spider_fetch_step(r.f, 0) == 1 && !lc_spider_fetch_done(r.f),
               "stream cleanup yields before the response transition");
            collect(r.f, &r.w);
            ok(count(&r.w, LC_H2_RST_STREAM) == 0u,
               "a completed stream cleanup emits no cancellation");
            int rc = 1;
            unsigned steps = 0;
            while (rc == 1 && steps++ < 16u)
                rc = lc_spider_fetch_step(r.f, 0);
            ok(rc == 0 && lc_spider_fetch_done(r.f),
               "resumption skips completed cleanup and finishes Do");
            collect(r.f, &r.w);
            ok(count(&r.w, LC_H2_RST_STREAM) == 0u && count(&r.w, LC_H2_HEADERS) == 0u,
               "resumed cleanup produces neither duplicate cancellation nor request");
            lc_spider_fetch_free(r.f);
        }
    }
    {
        int started = start_on(&r, "body-yield-cleanup.example") == 0;
        ok(started, "a body yield with peer-closed cleanup pending");
        if (started) {
            answer(&r.s, 1, 0, "200", NULL, NULL, NULL);
            ok(deliver(r.f, &r.s, 0) == 0, "the body reader waits before peer close");
            collect(r.f, &r.w);
            body(&r.s, 1, (const uint8_t *)"x", 1, 1);
            ok(lc_spider_fetch_feed(r.f, r.s.buf, r.s.len) == 0,
               "one body byte and END_STREAM make both reader and cleanup ready");
            r.s.len = 0;
            ok(lc_spider_fetch_step(r.f, 0) == 1 && !lc_spider_fetch_done(r.f),
               "the byte Read yields without processing peer-close cleanup");
            ok(lc_spider_fetch_step(r.f, 0) == 1 && !lc_spider_fetch_done(r.f),
               "the next step reaches body EOF and yields for pending cleanup, not Do completion");
            int rc = 1;
            for (unsigned i = 0; i < 8u && rc == 1; i++)
                rc = lc_spider_fetch_step(r.f, 0);
            ok(rc == 0 && lc_spider_fetch_done(r.f),
               "harvest and deferred Close finish after cleanup without a new DATA wake");
            lc_spider_fetch_free(r.f);
        }
    }
    {
        /* Loss must wait for every saved Read/cleanup continuation, including Writes those Reads
         * publish. A prefix of an unfinished page must never enter the next connection's path set. */
        for (unsigned finished = 0; finished < 2u; finished++) {
            const char *host = finished ? "deferred-whole.example" : "deferred-half.example";
            int started = start_on(&r, host) == 0;
            ok(started, "a page for DATA/END_STREAM/EOF handoff");
            if (!started)
                continue;
            ok(deliver(r.f, &r.s, 0) == 0, "the EOF fixture accepts SETTINGS");
            collect(r.f, &r.w);
            answer(&r.s, 1, 0, "200", NULL, NULL, NULL);
            ok(deliver(r.f, &r.s, 0) == 0, "the page reader is waiting before EOF");
            collect(r.f, &r.w);
            ok(lc_spider_fetch_write_barrier(r.f) == 0,
               "the EOF consumer observes actual Write completion");
            uint8_t page[24576];
            memset(page, ' ', sizeof page);
            const char link[] = "<a href=\"/after-eof\">saved</a>";
            memcpy(page + sizeof page - sizeof link, link, sizeof link - 1u);
            body(&r.s, 1, page, sizeof page, (int)finished);
            ok(lc_spider_fetch_feed(r.f, r.s.buf, r.s.len) == 0,
               "multiple body Reads arrive before the loss handoff");
            r.s.len = 0;
            lc_spider_fetch_loss_pending(r.f);
            int rc = 1;
            unsigned steps = 0, completions = 0;
            while (rc >= 0 && steps++ < 128u) {
                rc = lc_spider_fetch_step(r.f, 0);
                uint8_t *write_bytes = NULL;
                long n;
                while ((n = lc_spider_fetch_take(r.f, &write_bytes)) > 0) {
                    free(write_bytes);
                    completions++;
                    if (lc_spider_fetch_write_complete(r.f, 1) != 0) {
                        rc = -2;
                        break;
                    }
                }
            }
            int found = 0;
            for (unsigned draw = 0; draw < 200u && !found; draw++)
                found = drawn_is(host, "/after-eof");
            ok(rc == -1 && steps > 2u && steps < 128u && completions > 0u,
               "deferred loss drains body continuations and completion barriers without stalling");
            ok(found == (int)finished,
               finished ? "END_STREAM before EOF preserves the link from the final body Read"
                        : "EOF without END_STREAM never harvests the partial page");
            lc_spider_fetch_stop(r.f);
            lc_spider_fetch_free(r.f);
        }
    }
    {
        int started = start_on(&r, "step-gzip.example") == 0;
        ok(started, "a gzip page for resumable consumer reads");
        if (started) {
            uint8_t plain[8192], gz[9000];
            memset(plain, 'x', sizeof plain);
            z_stream z;
            memset(&z, 0, sizeof z);
            int init = deflateInit2(&z, 6, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
            int encoded = 0;
            size_t gz_len = 0;
            if (init == Z_OK) {
                z.next_in = plain;
                z.avail_in = sizeof plain;
                z.next_out = gz;
                z.avail_out = sizeof gz;
                encoded = deflate(&z, Z_FINISH) == Z_STREAM_END;
                gz_len = sizeof gz - z.avail_out;
                deflateEnd(&z);
            }
            ok(encoded, "the gzip continuation fixture is complete");
            if (encoded) {
                answer(&r.s, 1, 0, "200", NULL, NULL, "gzip");
                body(&r.s, 1, gz, gz_len, 1);
                ok(lc_spider_fetch_feed(r.f, r.s.buf, r.s.len) == 0,
                   "gzip bytes and EOF arrive before consumer steps");
                r.s.len = 0;
                int rc = 1;
                unsigned steps = 0;
                while (rc == 1 && steps++ < 128u)
                    rc = lc_spider_fetch_step(r.f, 0);
                ok(rc == 0 && steps > 1u && lc_spider_fetch_done(r.f),
                   "gzip resumes across Read boundaries and reaches checked EOF");
            }
            lc_spider_fetch_free(r.f);
        }
    }
    {
        int started = start_on(&r, "worker-body.example") == 0;
        ok(started, "a fetch driven by an independent notified consumer thread");
        if (started) {
            body_worker worker = { .f = r.f, .lock = PTHREAD_MUTEX_INITIALIZER,
                                   .changed = PTHREAD_COND_INITIALIZER };
            pthread_t thread;
            int created = pthread_create(&thread, NULL, consume_body, &worker);
            ok(created == 0, "the body consumer thread starts");
            if (created == 0) {
                ok(await_turn(&worker, 1), "the worker handles the initial turn without polling");
                collect(r.f, &r.w);
                answer(&r.s, 1, 0, "200", NULL, NULL, NULL);
                ok(lc_spider_fetch_feed(r.f, r.s.buf, r.s.len) == 0,
                   "the owner feeds response headers without settling");
                r.s.len = 0;
                /* take wakes the worker too: turn 2 need not have processed these HEADERS. Feed
                 * DATA without claiming that scheduling order; await_body_done is the predicate. */
                collect(r.f, &r.w);
                uint8_t data[8192];
                memset(data, 'x', sizeof data);
                body(&r.s, 1, data, sizeof data, 1);
                ok(lc_spider_fetch_feed(r.f, r.s.buf, r.s.len) == 0,
                   "the owner feeds DATA and EOF without settling");
                r.s.len = 0;
                ok(await_body_done(&worker),
                   "the worker alone consumes body and completes Do");
                collect(r.f, &r.w);
                ok(count(&r.w, LC_H2_WINDOW_UPDATE) > 0u,
                   "the owner takes window writes produced by the worker");
                lc_spider_fetch_stop(r.f);
                pthread_join(thread, NULL);
                ok(worker.exited && !worker.failed,
                   "the worker exits on stop and is joined before fetch destruction");
            }
            lc_spider_fetch_free(r.f);
            pthread_cond_destroy(&worker.changed);
            pthread_mutex_destroy(&worker.lock);
        }
    }
    {
        int started = start_on(&r, "retry-wake.example") == 0;
        ok(started, "a fetch for the real consumer retry deadline");
        if (started) {
            uint64_t generation = 0;
            ok(lc_spider_fetch_wait(r.f, &generation) == 1 &&
                   deliver_at(r.f, &r.s, monotonic_ms()) == 0,
               "the first request starts on the monotonic clock");
            collect(r.f, &r.w);
            uint8_t refused[4] = { 0, 0, 0, 7 };
            frame(&r.s, LC_H2_RST_STREAM, 0, 1, refused, sizeof refused);
            ok(deliver_at(r.f, &r.s, monotonic_ms()) == 0,
               "the first refusal retries immediately");
            collect(r.f, &r.w);
            const wframe *retry = find(&r.w, LC_H2_HEADERS, 0);
            ok(retry != NULL && retry->stream == 3u,
               "the immediate retry uses stream 3 on the same connection");
            frame(&r.s, LC_H2_RST_STREAM, 0, 3, refused, sizeof refused);
            uint64_t before = monotonic_ms();
            ok(deliver_at(r.f, &r.s, before) == 0,
               "the second refusal enters the protocol backoff");
            collect(r.f, &r.w);
            uint64_t deadline = lc_spider_fetch_deadline(r.f);
            ok(deadline == before + 1000u && count(&r.w, LC_H2_HEADERS) == 0u,
               "backoff queues no request before its real one-second deadline");
            ok(lc_spider_fetch_wait(r.f, &generation) == 1,
               "the refusals retain their input notification");
            if (deadline != 0u) {
                ok(lc_spider_fetch_wait(r.f, &generation) == 1 &&
                       monotonic_ms() >= deadline,
                   "consumer wait wakes at retry expiry without new input");
                ok(lc_spider_fetch_settle(r.f, monotonic_ms()) == 0,
                   "the consumer advances the expired retry");
                collect(r.f, &r.w);
                retry = find(&r.w, LC_H2_HEADERS, 0);
                ok(retry != NULL && retry->stream == 5u &&
                       lc_spider_fetch_deadline(r.f) == 0u,
                   "expiry sends stream 5 and clears the retry deadline");
            }
            lc_spider_fetch_stop(r.f);
            lc_spider_fetch_free(r.f);
        }
    }
    {
        int started = start_on(&r, "pending-eof.example") == 0;
        ok(started, "a response completed immediately before transport EOF");
        if (started) {
            answer(&r.s, 1, 0, "200", NULL, NULL, NULL);
            body(&r.s, 1, (const uint8_t *)"x", 1, 1);
            ok(lc_spider_fetch_feed(r.f, r.s.buf, r.s.len) == 0,
               "HEADERS and DATA END_STREAM are fed without a consumer turn");
            r.s.len = 0;
            lc_spider_fetch_loss_pending(r.f);
            int rc = 1;
            unsigned steps = 0;
            while (rc == 1 && steps++ < 32u) {
                rc = lc_spider_fetch_step(r.f, monotonic_ms());
                collect(r.f, &r.w);
            }
            ok(rc == -1 && lc_spider_fetch_done(r.f),
               "pending transport EOF closes only after the completed body finishes Do");
            lc_spider_fetch_stop(r.f);
            lc_spider_fetch_free(r.f);
        }
    }
    {
        int started = start_on(&r, "wake.example") == 0;
        ok(started, "a fetch for consumer notifications");
        if (started) {
            uint64_t generation = 0;
            ok(lc_spider_fetch_wait(r.f, &generation) == 1,
               "the initial consumer turn is ready without a timer");
            ok(deliver(r.f, &r.s, 0) == 0 &&
                   lc_spider_fetch_wait(r.f, &generation) == 1,
               "input delivered before wait cannot lose its notification");
            uint8_t ping[LC_H2_HEADER + 8u] = { 0 };
            (void)lc_h2_put_header(ping, sizeof ping, 8, LC_H2_PING, 0, 0);
            ok(lc_spider_fetch_feed(r.f, ping, sizeof ping) == 0 &&
                   lc_spider_fetch_settle(r.f, 0) == 0 &&
                   lc_spider_fetch_wait(r.f, &generation) == 1,
               "the consumer waits after producing a complete response write");
            uint8_t *write = NULL;
            long write_len = lc_spider_fetch_take(r.f, &write);
            ok(write_len > 0 && lc_spider_fetch_wait(r.f, &generation) == 1,
               "taking one complete write wakes the consumer to resume");
            free(write);
            concurrent_fetch consumer = { r.f, 0, 0 };
            pthread_t thread;
            int created = pthread_create(&thread, NULL, wait_stopped, &consumer);
            if (created == 0) {
                lc_spider_fetch_stop(r.f);
                pthread_join(thread, NULL);
            }
            ok(created == 0 && !consumer.failed,
               "stop interrupts the consumer before or during wait, joined before destruction");
            ok(lc_spider_fetch_wait(r.f, &generation) == 0,
               "stop is persistent for a later wait");
            ok(lc_spider_fetch_step(r.f, monotonic_ms()) == 0,
               "a stopped consumer does not resume a step");
            lc_spider_fetch_free(r.f);
        }
    }
    {
        int started = start_on(&r, "concurrent.example") == 0;
        ok(started, "a fetch for concurrent feed and Do operations");
        if (started) {
            ok(deliver(r.f, &r.s, 0) == 0, "the concurrent fetch accepts SETTINGS");
            collect(r.f, &r.w);
            concurrent_fetch feed = { r.f, 0, 0 }, settle = { r.f, 0, 0 },
                             take = { r.f, 0, 0 };
            pthread_t reader, doer, writer;
            int rd = pthread_create(&reader, NULL, feed_pings, &feed);
            int dw = pthread_create(&doer, NULL, settle_fetch, &settle);
            int wr = pthread_create(&writer, NULL, take_fetch, &take);
            if (rd == 0)
                pthread_join(reader, NULL);
            if (dw == 0)
                pthread_join(doer, NULL);
            if (wr == 0)
                pthread_join(writer, NULL);
            collect(r.f, &r.w);
            ok(rd == 0 && dw == 0 && wr == 0 && !feed.failed && !settle.failed && !take.failed &&
                   count(&r.w, LC_H2_PING) + take.pings == 64u,
               "concurrent feed/settle/take preserves all 64 complete PING responses");
            lc_spider_fetch_free(r.f);
        }
    }
    lc_hpack_dec_free(&r.d);
    printf(failures == 0 ? "\nall good\n" : "\n%d failed\n", failures);
    return failures == 0 ? 0 : 1;
}
