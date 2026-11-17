#include "reality/paths.h"

#include "core/gomap.h"
#include "core/rnd.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

/* ---- the sets the whole process shares ----------------------------------------------------------
 *
 * The paths themselves, and beside them the hashes of the Go map they are keys of — kept for as long
 * as the set is, because the reference's map is (reality.go:308-310) and the layout a walk reads is
 * the one the keys were inserted into: from the ninth path on, where each key sits comes from its
 * hash under the map's own seed, drawn once. core/gomap builds that layout from the hashes when a
 * draw walks it.
 *
 * WHOSE SETS THEY ARE. The reference has one map of them per process, and its process is every
 * connection Xray makes. Ours is split into a worker per CPU on the REALITY plane (lc-tunnel,
 * supervise), and a set each would be a divergence on the wire: the second worker to meet a
 * stranger node would ask for SpiderX where the reference asks for a path the first one harvested.
 * So lc-tunnel moves them into shared memory before it forks (lc_spider_paths_share), and the lock
 * is process-shared — the reference's `maps.Lock()`, across processes. Until then, and in every
 * program that never forks, they are this process's own.
 *
 * THE ARENA they live in is one mapping, reserved large and paid for as it is touched, and
 * addressed by offsets, never pointers, so that it reads the same in every process that maps it.
 * Nothing in it is ever freed — the reference's map never shrinks either — and an array that grows
 * is copied into new room and the old left behind. Its end is the process's memory running out,
 * which is where the reference's map ends too. */
#define ARENA_RESERVE ((size_t)(sizeof(void *) >= 8u ? (size_t)1 << 30 : (size_t)256 << 20))

typedef struct {
    pthread_mutex_t lock;
    size_t          size, top;
    size_t          sets; /* the first name's set, 0 for none */
} arena;

/* One ServerName's set: its keys in the order they came, each key's hash beside it, and a table to
 * find a key by its bytes — the map's own lookup, which the reference's `paths[k] = struct{}{}`
 * makes before it inserts anything. */
typedef struct {
    size_t   next;
    size_t   name;        /* NUL-terminated */
    uint32_t count, cap;
    size_t   hash;        /* uint64_t[cap] */
    size_t   key;         /* size_t[cap]: each key, its length and then its bytes and a NUL */
    uint32_t tcap;        /* a power of two */
    size_t   table;       /* uint32_t[tcap]: a key's index + 1, 0 for none */
} name_set;

static arena *A;
static int    A_shared;

#define AT(off, type) ((type *)(void *)((uint8_t *)A + (off)))

/* Room in the arena, aligned for anything it holds: its offset, 0 when there is none. */
static size_t room(size_t n)
{
    size_t off = (A->top + 7u) & ~(size_t)7u;
    if (off > A->size || n > A->size - off)
        return 0;
    A->top = off + n;
    return off;
}

static arena *map_arena(int shared)
{
    void *p = mmap(NULL, ARENA_RESERVE, PROT_READ | PROT_WRITE,
                   (shared ? MAP_SHARED : MAP_PRIVATE) | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (p == MAP_FAILED)
        return NULL;
    arena *a = p;
    a->size = ARENA_RESERVE;
    a->top = sizeof *a;
    a->sets = 0;
    return a;
}

/* The lock around every touch of the sets, as the reference takes `maps.Lock()` around its draw
 * and its harvest (reality.go:221-231, :268-281). The arena is made at the first use of it.
 *
 * A worker can die between table/mask publication or after writing a lookup slot
 * but before publishing its key count. Rebuild derived lookup tables from the
 * committed keys before making an abandoned mutex consistent. No path or hash is
 * redrawn, and incomplete insertions are not promoted into the committed set. */
static void restore_tables(void);

static int store_lock(void)
{
    if (A == NULL) {
        arena *a = map_arena(0);
        if (a == NULL)
            return -1;
        if (pthread_mutex_init(&a->lock, NULL) != 0) {
            (void)munmap(a, ARENA_RESERVE);
            return -1;
        }
        A = a;
    }
    int rc = pthread_mutex_lock(&A->lock);
    if (rc == EOWNERDEAD) {
        restore_tables();
        rc = pthread_mutex_consistent(&A->lock);
        if (rc != 0)
            (void)pthread_mutex_unlock(&A->lock);
    }
    if (rc != 0) {
        errno = rc;
        return -1;
    }
    return 0;
}

static void store_unlock(void)
{
    (void)pthread_mutex_unlock(&A->lock);
}

int lc_spider_paths_share(void)
{
    if (A_shared)
        return 0;
    arena *shared = map_arena(1);
    if (shared == NULL)
        return -1;
    pthread_mutexattr_t attr;
    int                 rc = pthread_mutexattr_init(&attr);
    if (rc == 0) {
        rc = pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
        if (rc == 0)
            rc = pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST);
        if (rc == 0)
            rc = pthread_mutex_init(&shared->lock, &attr);
        (void)pthread_mutexattr_destroy(&attr);
    }
    if (rc != 0) {
        (void)munmap(shared, ARENA_RESERVE);
        errno = rc;
        return -1;
    }
    /* What this process already holds goes with it — nothing, from the one caller, which shares
     * before the first connection; but it is not this function's to assume. Offsets mean the same
     * in the copy. */
    if (A != NULL) {
        if (store_lock() != 0) {
            (void)pthread_mutex_destroy(&shared->lock);
            (void)munmap(shared, ARENA_RESERVE);
            return -1;
        }
        memcpy((uint8_t *)shared + sizeof *shared, (uint8_t *)A + sizeof *A, A->top - sizeof *A);
        shared->top = A->top;
        shared->sets = A->sets;
        store_unlock();
        arena *old = A;
        A = shared;
        (void)pthread_mutex_destroy(&old->lock);
        (void)munmap(old, ARENA_RESERVE);
    } else {
        A = shared;
    }
    A_shared = 1;
    return 0;
}

/* ---- a set's keys ---------------------------------------------------------------------------------- */

static uint64_t fnv(const uint8_t *p, size_t n)
{
    uint64_t h = 0xcbf29ce484222325ull;
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 0x100000001b3ull;
    }
    return h;
}

static const uint8_t *key_bytes(const name_set *s, uint32_t i, size_t *n)
{
    size_t off = AT(s->key, size_t)[i];
    *n = *AT(off, size_t);
    return AT(off + sizeof(size_t), uint8_t);
}

/* The key's index, or -1. Entries past the count are what an insert that died left: not keys. */
static long find(const name_set *s, const uint8_t *p, size_t n)
{
    uint32_t mask = s->tcap - 1u;
    for (uint32_t at = (uint32_t)fnv(p, n) & mask;; at = (at + 1u) & mask) {
        uint32_t e = AT(s->table, uint32_t)[at];
        if (e == 0u)
            return -1;
        if (e - 1u < s->count) {
            size_t         kn;
            const uint8_t *k = key_bytes(s, e - 1u, &kn);
            if (kn == n && memcmp(k, p, n) == 0)
                return (long)(e - 1u);
        }
    }
}

static void table_put(name_set *s, uint32_t i)
{
    size_t         n;
    const uint8_t *p = key_bytes(s, i, &n);
    uint32_t       mask = s->tcap - 1u;
    uint32_t       at = (uint32_t)fnv(p, n) & mask;
    while (AT(s->table, uint32_t)[at] != 0u)
        at = (at + 1u) & mask;
    AT(s->table, uint32_t)[at] = i + 1u;
}

/* Growth publishes the allocation before its larger mask. Either visible mask
 * therefore fits the allocation and has room for every committed key. Recovery
 * itself may be interrupted: the next owner rebuilds from the same key count. */
static void restore_tables(void)
{
    for (size_t off = A->sets; off != 0u; off = AT(off, name_set)->next) {
        name_set *s = AT(off, name_set);
        memset(AT(s->table, uint32_t), 0, (size_t)s->tcap * sizeof(uint32_t));
        for (uint32_t i = 0; i < s->count; i++)
            table_put(s, i);
    }
}

/* Room for one more key: the arrays and the table grown, copied, and put in place — each a single
 * store of an offset, so that a set is never half moved. -1 when the arena has no more room. */
static int grow_for_one(name_set *s)
{
    if (s->count == s->cap) {
        uint32_t cap = s->cap * 2u;
        size_t   h = room((size_t)cap * sizeof(uint64_t)), k = room((size_t)cap * sizeof(size_t));
        if (h == 0u || k == 0u)
            return -1;
        memcpy(AT(h, uint64_t), AT(s->hash, uint64_t), (size_t)s->count * sizeof(uint64_t));
        memcpy(AT(k, size_t), AT(s->key, size_t), (size_t)s->count * sizeof(size_t));
        __atomic_store_n(&s->hash, h, __ATOMIC_RELEASE);
        __atomic_store_n(&s->key, k, __ATOMIC_RELEASE);
        __atomic_store_n(&s->cap, cap, __ATOMIC_RELEASE);
    }
    if (2u * (s->count + 1u) > s->tcap) {
        uint32_t tcap = s->tcap * 2u;
        size_t   t = room((size_t)tcap * sizeof(uint32_t));
        if (t == 0u)
            return -1;
        memset(AT(t, uint32_t), 0, (size_t)tcap * sizeof(uint32_t));
        name_set next = *s;
        next.table = t;
        next.tcap = tcap;
        for (uint32_t i = 0; i < s->count; i++)
            table_put(&next, i);
        /* Publish initialized storage and its arena allocation before its offset,
         * and the offset before the larger mask, including on 32-bit MIPS. */
        __atomic_store_n(&s->table, t, __ATOMIC_RELEASE);
        __atomic_store_n(&s->tcap, tcap, __ATOMIC_RELEASE);
    }
    return 0;
}

/* `paths[k] = struct{}{}`: nothing when the key is there, else the key at the end with a hash of
 * its own, drawn now and kept. -1 when there was no room or no hash could be had — the key is then
 * not a key, and the set is as it was. */
static int add(name_set *s, const uint8_t *p, size_t n)
{
    if (find(s, p, n) >= 0)
        return 0;
    uint64_t h;
    if (grow_for_one(s) != 0 || lc_rnd((uint8_t *)&h, sizeof h) != 0)
        return -1;
    size_t off = room(sizeof(size_t) + n + 1u);
    if (off == 0u)
        return -1;
    *AT(off, size_t) = n;
    if (n > 0u)
        memcpy(AT(off + sizeof(size_t), uint8_t), p, n);
    AT(off + sizeof(size_t), uint8_t)[n] = '\0';
    AT(s->hash, uint64_t)[s->count] = h;
    AT(s->key, size_t)[s->count] = off;
    table_put(s, s->count);
    __atomic_store_n(&s->count, s->count + 1u, __ATOMIC_RELEASE);
    return 0;
}

/* The set for this name, made the way the reference makes it: with SpiderX already in it
 * (reality.go:224-230), so the first request asks for SpiderX and every later one draws from what
 * the pages carried. SpiderX is "/" here and nothing in this client's configuration changes it. The
 * lock is held. NULL when it could not be made — no room, or no randomness for the first key's
 * hash; the next caller then tries again rather than drawing from a map that does not hold what the
 * set does. */
static name_set *set_for(const char *host)
{
    for (size_t off = A->sets; off != 0u; off = AT(off, name_set)->next)
        if (strcmp(AT(AT(off, name_set)->name, char), host) == 0)
            return AT(off, name_set);
    size_t hn = strlen(host);
    size_t so = room(sizeof(name_set)), no = room(hn + 1u);
    size_t h = room(8u * sizeof(uint64_t)), k = room(8u * sizeof(size_t));
    size_t t = room(16u * sizeof(uint32_t));
    if (so == 0u || no == 0u || h == 0u || k == 0u || t == 0u)
        return NULL;
    memcpy(AT(no, char), host, hn + 1u);
    name_set *s = AT(so, name_set);
    *s = (name_set){ .name = no, .cap = 8u, .hash = h, .key = k, .tcap = 16u, .table = t };
    memset(AT(t, uint32_t), 0, 16u * sizeof(uint32_t));
    if (add(s, (const uint8_t *)"/", 1u) != 0)
        return NULL;
    s->next = A->sets;
    __atomic_store_n(&A->sets, so, __ATOMIC_RELEASE); /* made, and only now found */
    return s;
}

/* `stopAt := int(crypto.RandBetween(0, int64(len(paths)-1)))`, then `for s := range paths` until
 * the walk reaches stopAt (reality.go:312-322). Two things in that are easy to read past, and both
 * are on the wire:
 *
 *   - RandBetween's upper bound is EXCLUDED: it returns `from + rand.Int(rand.Reader, to-from)`
 *     (vendor/Xray-core/common/crypto/crypto.go:12-21), and rand.Int is uniform in [0, max). So
 *     stopAt is never len-1 — the key a walk reaches LAST is never the one asked for — and with one
 *     or two paths the call returns `from` without drawing at all (two since v26.9.9; the draw it
 *     made before, rand.Int of 1, was always 0);
 *   - the index is a position in a WALK, not in the insertion order, and a Go walk is not uniform
 *     over rotations: up to eight keys sit in one group of eight slots and the walk starts at any of
 *     the eight, so with k keys the insertion order comes out (9-k)/8 of the time (see
 *     core/gomap). With "/" and one harvested path stopAt is always 0, and the reference asks for
 *     "/" seven times in eight.
 *
 * The lock is held. */
static int draw(const name_set *s, char **out, size_t *len)
{
    uint32_t key = 0;
    if (s->count > 1u) {
        size_t   stop = 0;
        uint64_t off[2];
        unsigned chosen = 0;
        /* DIVERGES: O9. Stop the same map walk at its selected rank without a
         * full order array. Hashes, rank bounds and entropy draws stay intact. */
        int rc = lc_rnd_below(s->count - 1u, &stop) != 0 ||
                 lc_rnd((uint8_t *)off, sizeof off) != 0 ||
                 lc_gomap_at(AT(s->hash, uint64_t), s->count, 0, off[0], off[1],
                             (unsigned)stop, &chosen) != 0;
        if (!rc)
            key = chosen;
        if (rc)
            return -1;
    }
    size_t         n;
    const uint8_t *p = key_bytes(s, key, &n);
    char          *copy = malloc(n + 1u);
    if (copy == NULL)
        return -1;
    memcpy(copy, p, n + 1u);
    *out = copy;
    *len = n;
    return 0;
}

int lc_spider_path(const char *host, char **out, size_t *len)
{
    if (host == NULL || host[0] == '\0' || store_lock() != 0)
        return -1;
    name_set *s = set_for(host);
    int       rc = s != NULL ? draw(s, out, len) : -1;
    store_unlock();
    return rc;
}

/* ---- the body of one answer ---------------------------------------------------------------------- */

struct lc_spider_sink {
    char    *host;
    /* What is in hand and not yet decided — from a tag whose closing quote has not come, or the few
     * bytes that could be the front of one — and how far past that tag has been looked at already. */
    uint8_t *buf;
    size_t   len, cap, looked;
    /* What the page links to, every match in the order the page has it, kept until the page is known
     * to have been read whole — see lc_spider_sink_commit. */
    struct {
        uint8_t *p;
        size_t   n;
    }       *pending;
    size_t   npending, cpending;
    int      oom;
};

/* ---- what a page is read for ---------------------------------------------------------------------- */

/* `href="([/h].*?)"` — the reference's regexp (reality.go:304), and every piece of it matters:
 *
 *   - the first character of the match must be `/` or `h`, which is how a link to somewhere else on
 *     the same site or an absolute one is taken and `#anchor`, `?query` and `javascript:` are not;
 *   - `.` in Go does not match a newline and `*?` is not greedy, so the match ends at the first
 *     quote ON THAT LINE. An href with no closing quote before the line ends is not a match;
 *   - what is stored is the match with the prefix `https://<ServerName>` removed and only if it
 *     carries no dot (reality.go:269-274) — which is how a link to another host is dropped, since
 *     its trimmed form still holds the dot of its domain.
 */
static void take(lc_spider_sink *sink, const uint8_t *value, size_t len)
{
    size_t hn = strlen(sink->host);
    if (len >= 8u + hn && memcmp(value, "https://", 8) == 0 && memcmp(value + 8, sink->host, hn) == 0) {
        value += 8u + hn;
        len -= 8u + hn;
    }
    if (memchr(value, '.', len) != NULL)
        return;
    if (sink->npending == sink->cpending) {
        size_t cap = sink->cpending == 0u ? 16u : 2u * sink->cpending;
        void  *p = realloc(sink->pending, cap * sizeof *sink->pending);
        if (p == NULL) {
            sink->oom = 1;
            return;
        }
        sink->pending = p;
        sink->cpending = cap;
    }
    uint8_t *copy = malloc(len + 1u);
    if (copy == NULL) {
        sink->oom = 1;
        return;
    }
    if (len > 0u)
        memcpy(copy, value, len);
    sink->pending[sink->npending].p = copy;
    sink->pending[sink->npending].n = len;
    sink->npending++;
}

/* The harvest, into the set every later connection to the name draws from — once the page has been
 * read to its end, because that is when the reference harvests: `io.ReadAll(resp.Body)` and only
 * then `href.FindAllSubmatch(body, -1)`, with a read that failed ending the pass before it
 * (reality.go:263-275). A page the site cut short, one whose length was not what it said, one that
 * did not inflate: the reference learns nothing from any of them.
 *
 * The set for this name is made here as well as at the draw, because the harvest can be the first
 * thing that touches it: the reference makes the map when a connection for the name starts and both
 * halves work on that one map (reality.go:222-230). A set that cannot be made harvests nothing, as a
 * failed draw asks for nothing. A page whose matches could not all be held is not harvested: the
 * reference holds them all or the process ends. */
void lc_spider_sink_commit(lc_spider_sink *sink)
{
    if (sink == NULL || sink->oom || store_lock() != 0)
        return;
    name_set *s = set_for(sink->host);
    for (size_t i = 0; s != NULL && i < sink->npending; i++)
        if (add(s, sink->pending[i].p, sink->pending[i].n) != 0)
            break;
    store_unlock();
}

/* Scans what is in hand and says where the next scan must start.
 *
 * Everything before the returned index is decided; from it onwards the buffer may hold the front of
 * a match whose closing quote has not arrived yet, and the caller carries those bytes into the next
 * chunk. A page arrives as a dozen DATA frames and a link lands across the seam of two of them
 * often enough that not doing this would lose links at random. A match is as long as the page
 * makes it; what was carried is not looked at twice (`looked`). */
static size_t scan(lc_spider_sink *sink, const uint8_t *b, size_t n)
{
    static const char tag[] = "href=\"";
    const size_t      tag_len = sizeof tag - 1u;

    size_t i = 0;
    while (i < n) {
        size_t h = n;
        for (size_t k = i; k + tag_len <= n; k++)
            if (b[k] == 'h' && memcmp(b + k, tag, tag_len) == 0) {
                h = k;
                break;
            }
        if (h == n) { /* no tag in hand: keep only what could be the front of one */
            sink->looked = 0;
            return n >= tag_len - 1u ? n - (tag_len - 1u) : 0u;
        }

        size_t v = h + tag_len;
        size_t j = h == 0u && sink->looked > v ? sink->looked : v;
        while (j < n && b[j] != '"' && b[j] != '\n')
            j++;
        if (j == n) {
            sink->looked = n - h; /* undecided — the quote, or the newline that rules it out */
            return h;
        }
        sink->looked = 0;
        if (b[j] == '"' && j > v && (b[v] == '/' || b[v] == 'h')) {
            take(sink, b + v, j - v);
            i = j + 1u; /* FindAll goes on after the match */
        } else {
            i = h + 1u; /* no match here: the next start is the next byte, and a tag can begin
                         * before the quote this one was cut at */
        }
    }
    sink->looked = 0;
    return n;
}

lc_spider_sink *lc_spider_sink_new(const char *host)
{
    if (host == NULL || host[0] == '\0')
        return NULL;
    lc_spider_sink *sink = calloc(1, sizeof *sink);
    if (sink == NULL || (sink->host = strdup(host)) == NULL) {
        free(sink);
        return NULL;
    }
    return sink;
}

void lc_spider_sink_data(lc_spider_sink *sink, const uint8_t *data, size_t len)
{
    if (sink == NULL || data == NULL || len == 0u || sink->oom)
        return;
    if (sink->len + len > sink->cap) {
        size_t cap = sink->cap == 0u ? 4096u : sink->cap;
        while (cap < sink->len + len)
            cap *= 2u;
        uint8_t *b = realloc(sink->buf, cap);
        if (b == NULL) {
            sink->oom = 1;
            return;
        }
        sink->buf = b;
        sink->cap = cap;
    }
    memcpy(sink->buf + sink->len, data, len);
    sink->len += len;
    size_t done = scan(sink, sink->buf, sink->len);
    memmove(sink->buf, sink->buf + done, sink->len - done);
    sink->len -= done;
}

void lc_spider_sink_free(lc_spider_sink *sink)
{
    if (sink == NULL)
        return;
    for (size_t i = 0; i < sink->npending; i++)
        free(sink->pending[i].p);
    free(sink->pending);
    free(sink->buf);
    free(sink->host);
    free(sink);
}
