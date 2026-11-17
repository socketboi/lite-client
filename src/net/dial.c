#include "net/dial.h"

#include "net/goresolve.h"
#include "net/loop.h"
#include "net/sock.h"

#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

/* ── The lookup, shared by every dial of one name while it is in flight ──
 *
 * Go's singleflight group, keyed as Go keys it — "ip\0" and the name, no port (GOROOT/src/net/
 * lookup.go:332-336) — so dials of one name to two ports share a lookup. A lookup is in the group
 * from the moment the first dial asks until it finishes — then it leaves the group, so the next dial
 * asks again (singleflight deletes the key when the call returns) — or until the only dial waiting on
 * it gives up, which is ForgetUnshared (lookup.go:343-357). Go then cancels the lookup, and so does
 * this: `cancel` is written, and the resolver sends nothing more. The resolver is Go's own, the
 * references' — see net/goresolve.h. Until 2026-09-30 it was getaddrinfo, which could not be
 * cancelled and asked and ordered in libc's way.
 *
 * The references are counted under one mutex: the thread holds one, each waiting dial one, and the
 * last to let go frees it. The eventfd is written once, when the answer is in, and never read: a
 * waiting dial has it in its own epoll set, and level-triggered it stays readable for every waiter
 * until each has taken the answer and removed it. */
typedef struct flight {
    struct flight *next;
    char           host[256];
    int            ev;
    int            cancel; /* eventfd, written when nobody waits any more */
    unsigned       refs;
    int            in_group;
    int            done;
    int            failed;
    char           why[200]; /* Go's error text when failed */
    lc_goaddrs     res;
} flight;

static pthread_mutex_t group_mu = PTHREAD_MUTEX_INITIALIZER;
static flight         *group;

static void group_unlink(flight *f)
{
    for (flight **p = &group; *p != NULL; p = &(*p)->next) {
        if (*p == f) {
            *p = f->next;
            break;
        }
    }
    f->in_group = 0;
}

static void flight_free(flight *f)
{
    close(f->ev);
    if (f->cancel >= 0)
        close(f->cancel);
    lc_goaddrs_free(&f->res);
    free(f);
}

/* Settles the lookup and wakes whoever waits. Called with group_mu held. */
static void flight_settle(flight *f)
{
    f->done = 1;
    if (f->in_group)
        group_unlink(f);
    /* An eventfd counter this far from its limit takes the write; nothing else can refuse it. */
    uint64_t one = 1;
    if (write(f->ev, &one, sizeof one) < 0) {
    }
}

static void *flight_main(void *arg)
{
    flight *f = arg;
    /* Written outside the lock and read only once `done` is seen under it. */
    int rc = lc_go_lookup_ip(f->host, f->cancel, &f->res, f->why, sizeof f->why);

    pthread_mutex_lock(&group_mu);
    f->failed = rc != 0;
    flight_settle(f);
    int last = --f->refs == 0u;
    pthread_mutex_unlock(&group_mu);
    if (last)
        flight_free(f);
    return NULL;
}

/* The lookup of host in flight, joined, or a new one started. NULL with errno when a new one could
 * not even be set up. */
static flight *flight_join(const char *host)
{
    pthread_mutex_lock(&group_mu);
    for (flight *f = group; f != NULL; f = f->next) {
        if (strcmp(f->host, host) == 0) {
            f->refs++;
            pthread_mutex_unlock(&group_mu);
            return f;
        }
    }

    flight *f = calloc(1, sizeof *f);
    if (f == NULL) {
        pthread_mutex_unlock(&group_mu);
        errno = ENOMEM;
        return NULL;
    }
    f->ev = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    f->cancel = f->ev >= 0 ? eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK) : -1;
    if (f->ev < 0 || f->cancel < 0) {
        int e = errno;
        if (f->ev >= 0)
            close(f->ev);
        free(f);
        pthread_mutex_unlock(&group_mu);
        errno = e;
        return NULL;
    }
    snprintf(f->host, sizeof f->host, "%s", host);
    f->refs = 2u; /* the thread's and this dial's */
    f->in_group = 1;
    f->next = group;
    group = f;

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    (void)pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_t t;
    int       rv = pthread_create(&t, &attr, flight_main, f);
    pthread_attr_destroy(&attr);
    if (rv != 0) {
        /* No thread, so no lookup: an answer at once, the failure to start one — which to the dial
         * is a failed lookup like any other. */
        f->refs = 1u;
        f->failed = 1;
        snprintf(f->why, sizeof f->why, "lookup %s: %s", host, strerror(rv));
        flight_settle(f);
    }
    pthread_mutex_unlock(&group_mu);
    return f;
}

/* A dial lets go of its lookup: when it has the answer, or when it gives up on it. */
static void flight_leave(flight *f)
{
    pthread_mutex_lock(&group_mu);
    /* ForgetUnshared: nobody but this dial and the thread — the next dial starts afresh, and this
     * lookup is cancelled (lookupGroupCancel). */
    if (!f->done && f->in_group && f->refs == 2u) {
        group_unlink(f);
        uint64_t one = 1;
        if (write(f->cancel, &one, sizeof one) < 0) {
        }
    }
    int last = --f->refs == 0u;
    pthread_mutex_unlock(&group_mu);
    if (last)
        flight_free(f);
}

/* ── The dial ── */

/* What the epoll set's entries say they are. */
#define TAG_PRIMARY  0u
#define TAG_FALLBACK 1u
#define TAG_LOOKUP   2u

/* One of dialParallel's two racers: dialSerial over its list. */
typedef struct {
    unsigned *idx; /* into lc_dial.addrs, in the lookup's order */
    unsigned  n;
    unsigned next;    /* the address being tried, or the next to try */
    int      fd;      /* its connect in flight, -1 between two */
    uint64_t until;   /* that connect's partialDeadline */
    int      started;
    int      done;
    int      err;     /* firstErr, or what ended the list */
} racer;

struct lc_dial {
    int         ep;
    uint64_t    deadline;
    uint16_t    port;
    flight     *fl;        /* while the lookup is awaited */
    lc_goaddrs  addrs;      /* the answer, copied */
    racer       r[2];      /* primary, fallback */
    uint64_t    fallback_at;
    int         timed_out;
    char        why[200];
};

/* partialDeadline (GOROOT/src/net/dial.go:273-293): an equal share of what is left, but no less
 * than two seconds unless less than that is left. */
#define SANE_MINIMUM_MS 2000u
/* fallbackDelay's default (GOROOT/src/net/dial.go:295-301). */
#define FALLBACK_DELAY_MS 300u

static void racer_close(lc_dial *d, racer *r)
{
    if (r->fd >= 0) {
        (void)epoll_ctl(d->ep, EPOLL_CTL_DEL, r->fd, NULL);
        close(r->fd);
        r->fd = -1;
    }
}

/* dialSerial from the address at r->next on (GOROOT/src/net/dial.go:733-773). Returns a socket
 * already connected — a connect() can finish at once — or -1: a connect is in flight, or the list
 * is done. */
static int racer_run(lc_dial *d, unsigned k, uint64_t now)
{
    racer *r = &d->r[k];
    while (r->fd < 0 && !r->done) {
        if (r->next >= r->n) {
            r->done = 1;
            if (r->err == 0)
                r->err = EADDRNOTAVAIL; /* errMissingAddress, which an empty list cannot reach */
            break;
        }
        /* ctx.Done at the top of the loop: the dial's own time is up, and that is the answer,
         * whatever the earlier addresses said. */
        if (now >= d->deadline) {
            r->done = 1;
            r->err = ETIMEDOUT;
            break;
        }
        uint64_t left = d->deadline - now;
        uint64_t share = left / (uint64_t)(r->n - r->next);
        if (share < SANE_MINIMUM_MS)
            share = left < SANE_MINIMUM_MS ? left : SANE_MINIMUM_MS;
        r->until = now + share;

        unsigned                i = r->idx[r->next];
        struct sockaddr_storage ss;
        socklen_t               sl = lc_goip_sockaddr(&d->addrs.a[i], d->port, &ss);
        int                     fd = socket(ss.ss_family, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
        int                     err = 0;
        if (fd < 0) {
            err = errno;
        } else if (lc_set_nonblocking(fd) != 0) {
            err = errno;
        } else {
            lc_tcp_outbound(fd);
            if (connect(fd, (const struct sockaddr *)&ss, sl) == 0)
                return fd;
            if (errno == EINPROGRESS) {
                struct epoll_event ev = { .events = EPOLLOUT, .data.u32 = k };
                if (epoll_ctl(d->ep, EPOLL_CTL_ADD, fd, &ev) == 0) {
                    r->fd = fd;
                    break;
                }
            }
            err = errno;
        }
        if (fd >= 0)
            close(fd);
        if (r->err == 0)
            r->err = err;
        r->next++;
    }
    return -1;
}

/* The connect in flight has failed with err: the next address. */
static int racer_next(lc_dial *d, unsigned k, int err, uint64_t now)
{
    racer *r = &d->r[k];
    racer_close(d, r);
    if (r->err == 0)
        r->err = err;
    r->next++;
    return racer_run(d, k, now);
}

/* A racer has won: its socket leaves the set, the other racer is stopped — Go closes a connection
 * the loser makes after this, and cancels its dial. */
static int racer_won(lc_dial *d, unsigned k, int fd)
{
    racer *r = &d->r[k];
    if (r->fd == fd) {
        (void)epoll_ctl(d->ep, EPOLL_CTL_DEL, fd, NULL);
        r->fd = -1;
    }
    racer_close(d, &d->r[k ^ 1u]);
    return fd;
}

static int dial_fail(lc_dial *d, int err, uint64_t now)
{
    d->timed_out = now >= d->deadline;
    snprintf(d->why, sizeof d->why, "%s", d->timed_out ? "i/o timeout" : strerror(err));
    return -1;
}

/* The answer is in: the lists, and the primary racer away (DialContext,
 * GOROOT/src/net/dial.go:553-560). */
static int lookup_done(lc_dial *d, uint64_t now)
{
    flight *f = d->fl;
    pthread_mutex_lock(&group_mu);
    int failed = f->failed;
    int nomem = 0;
    if (!failed) {
        /* lookupIPReturn copies a shared answer; so does this, since the flight goes with its last
         * holder. */
        d->addrs.a = malloc(f->res.n * sizeof *d->addrs.a);
        if (d->addrs.a != NULL) {
            memcpy(d->addrs.a, f->res.a, f->res.n * sizeof *d->addrs.a);
            d->addrs.n = f->res.n;
        } else {
            nomem = 1;
        }
    } else {
        snprintf(d->why, sizeof d->why, "%s", f->why);
    }
    pthread_mutex_unlock(&group_mu);
    (void)epoll_ctl(d->ep, EPOLL_CTL_DEL, f->ev, NULL);
    flight_leave(f);
    d->fl = NULL;

    if (failed || nomem) {
        if (nomem)
            snprintf(d->why, sizeof d->why, "%s", strerror(ENOMEM));
        d->timed_out = 0;
        return -1;
    }
    if (d->addrs.n == 0u) {
        /* filterAddrList's errNoSuitableAddress (GOROOT/src/net/ipsock.go:59-78). */
        snprintf(d->why, sizeof d->why, "no suitable address found");
        d->timed_out = 0;
        return -1;
    }
    d->r[0].idx = malloc(d->addrs.n * sizeof *d->r[0].idx);
    d->r[1].idx = malloc(d->addrs.n * sizeof *d->r[1].idx);
    if (d->r[0].idx == NULL || d->r[1].idx == NULL) {
        snprintf(d->why, sizeof d->why, "%s", strerror(ENOMEM));
        d->timed_out = 0;
        return -1;
    }

    /* partition(isIPv4) (GOROOT/src/net/ipsock.go:115-127): the addresses of the first one's kind
     * are the primary list — IPv4 as net.IP.To4 has it, so a v4-mapped one is IPv4. */
    for (unsigned i = 0; i < d->addrs.n; i++) {
        racer *r = &d->r[d->addrs.a[i].v4 == d->addrs.a[0].v4 ? 0 : 1];
        r->idx[r->n++] = i;
    }
    d->r[0].started = 1;
    if (d->r[1].n > 0u)
        d->fallback_at = now + FALLBACK_DELAY_MS;
    int fd = racer_run(d, TAG_PRIMARY, now);
    return fd >= 0 ? racer_won(d, TAG_PRIMARY, fd) : LC_DIAL_PENDING;
}

lc_dial *lc_dial_start(const char *host, uint16_t port, uint64_t now_ms, uint32_t timeout_ms)
{
    lc_dial *d = calloc(1, sizeof *d);
    if (d == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    d->r[0].fd = d->r[1].fd = -1;
    d->deadline = now_ms + timeout_ms;
    d->port = port;
    d->ep = epoll_create1(EPOLL_CLOEXEC);
    if (d->ep < 0) {
        int e = errno;
        free(d);
        errno = e;
        return NULL;
    }
    d->fl = flight_join(host);
    struct epoll_event ev = { .events = EPOLLIN, .data.u32 = TAG_LOOKUP };
    if (d->fl == NULL || epoll_ctl(d->ep, EPOLL_CTL_ADD, d->fl->ev, &ev) != 0) {
        int e = errno;
        lc_dial_free(d);
        errno = e;
        return NULL;
    }
    return d;
}

int lc_dial_fd(const lc_dial *d)
{
    return d->ep;
}

uint64_t lc_dial_wake(const lc_dial *d)
{
    uint64_t at = d->deadline;
    for (unsigned k = 0; k < 2u; k++)
        if (d->r[k].fd >= 0 && d->r[k].until < at)
            at = d->r[k].until;
    if (d->fl == NULL && !d->r[1].started && d->r[1].n > 0u && d->fallback_at < at)
        at = d->fallback_at;
    return at;
}

int lc_dial_step(lc_dial *d, uint64_t now)
{
    struct epoll_event evs[4];
    int                n = epoll_wait(d->ep, evs, 4, 0);

    if (d->fl != NULL) {
        pthread_mutex_lock(&group_mu);
        int done = d->fl->done;
        pthread_mutex_unlock(&group_mu);
        if (!done) {
            /* The lookup's context is the dial's: its time running out is the dial failing. */
            if (now >= d->deadline) {
                flight_leave(d->fl);
                d->fl = NULL;
                return dial_fail(d, ETIMEDOUT, now);
            }
            return LC_DIAL_PENDING;
        }
        int fd = lookup_done(d, now);
        if (fd != LC_DIAL_PENDING)
            return fd;
        n = 0; /* anything read above belonged to the lookup */
    }

    /* A connect has finished, one way or the other. */
    for (int i = 0; i < n; i++) {
        unsigned k = evs[i].data.u32;
        if (k > TAG_FALLBACK || d->r[k].fd < 0)
            continue;
        int err = lc_socket_error(d->r[k].fd);
        if (err == 0)
            return racer_won(d, k, d->r[k].fd);
        int fd = racer_next(d, k, err, now);
        if (fd >= 0)
            return racer_won(d, k, fd);
    }

    /* A connect whose share of the time is spent: the next address, as a context deadline
     * ending dialSingle. */
    for (unsigned k = 0; k < 2u; k++) {
        racer *r = &d->r[k];
        if (r->fd >= 0 && now >= r->until) {
            int fd = racer_next(d, k, ETIMEDOUT, now);
            if (fd >= 0)
                return racer_won(d, k, fd);
        }
    }

    /* The fallback racer: when its timer fires, or at once when the primary has failed first —
     * `fallbackTimer.Reset(0)` (GOROOT/src/net/dial.go:720-726). */
    racer *fb = &d->r[1];
    if (!fb->started && fb->n > 0u && (now >= d->fallback_at || d->r[0].done)) {
        fb->started = 1;
        int fd = racer_run(d, TAG_FALLBACK, now);
        if (fd >= 0)
            return racer_won(d, TAG_FALLBACK, fd);
    }

    /* Both done, or the primary done with no fallback: the primary's error
     * (GOROOT/src/net/dial.go:717-719). */
    if (d->r[0].done && (fb->n == 0u || fb->done))
        return dial_fail(d, d->r[0].err, now);
    return LC_DIAL_PENDING;
}

const char *lc_dial_why(const lc_dial *d)
{
    return d->why;
}

int lc_dial_timed_out(const lc_dial *d)
{
    return d->timed_out;
}

void lc_dial_free(lc_dial *d)
{
    if (d == NULL)
        return;
    racer_close(d, &d->r[0]);
    racer_close(d, &d->r[1]);
    if (d->fl != NULL)
        flight_leave(d->fl);
    if (d->ep >= 0)
        close(d->ep);
    free(d->r[0].idx);
    free(d->r[1].idx);
    lc_goaddrs_free(&d->addrs);
    free(d);
}

int lc_resolve_literal(const char *host, uint16_t port, lc_resolved *out)
{
    lc_goip ip;
    out->n = 0;
    if (lc_goip_literal(host, &ip) != 0)
        return EAI_NONAME;
    out->len[0] = lc_goip_sockaddr(&ip, port, &out->addr[0]);
    out->family[0] = out->addr[0].ss_family;
    out->socktype[0] = SOCK_STREAM;
    out->protocol[0] = IPPROTO_TCP;
    out->n = 1;
    return 0;
}
