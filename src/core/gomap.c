#include "core/gomap.h"
#include "core/rnd.h"

#include <stdlib.h>
#include <string.h>

#define GROUP     8u    /* abi.MapGroupSlots */
#define MAX_TABLE 1024u /* maxTableCapacity */

/* A table: its slots, each the key in it or -1. */
typedef struct {
    unsigned cap, growth_left, local_depth;
    int      index;
    int32_t *slot;
} table;

/* The map being built from its hashes: a small group until the ninth key, then a directory of
 * tables. */
typedef struct {
    const uint64_t *hash;
    int             small;
    int32_t         group[GROUP];
    unsigned        used;
    unsigned        depth; /* globalDepth */
    table         **dir;   /* 1 << depth entries */
    table         **all;   /* every table made, for the free */
    unsigned        nall, call;
} gmap;

/* maxGrowthLeft (GOROOT/src/internal/runtime/maps/table.go:115-136). */
static unsigned max_growth(unsigned cap)
{
    return cap <= GROUP ? cap - 1u : cap * 7u / GROUP;
}

/* newTable (GOROOT/src/internal/runtime/maps/table.go:73-99): the capacity at least a group and a
 * power of two. */
static table *new_table(gmap *m, uint64_t capacity, int index, unsigned depth)
{
    if (capacity < GROUP)
        capacity = GROUP;
    uint64_t cap = 1;
    while (cap < capacity)
        cap <<= 1;
    if (m->nall == m->call) {
        unsigned n = m->call == 0u ? 8u : m->call * 2u;
        table  **a = realloc(m->all, n * sizeof *a);
        if (a == NULL)
            return NULL;
        m->all = a;
        m->call = n;
    }
    table   *t = calloc(1, sizeof *t);
    int32_t *s = t != NULL ? malloc((size_t)cap * sizeof *s) : NULL;
    if (s == NULL) {
        free(t);
        return NULL;
    }
    for (uint64_t i = 0; i < cap; i++)
        s[i] = -1;
    t->cap = (unsigned)cap;
    t->growth_left = max_growth(t->cap);
    t->local_depth = depth;
    t->index = index;
    t->slot = s;
    m->all[m->nall++] = t;
    return t;
}

/* uncheckedPutSlot, and the placing half of PutSlot: the probe sequence over groups from
 * h1(hash) = hash >> 7, masked, stepping 1, 2, 3 (makeProbeSeq and next,
 * GOROOT/src/internal/runtime/maps/table.go:1274-1292), and the first empty slot of the first group
 * with one. */
static void place(table *t, int32_t key, uint64_t hash)
{
    uint64_t mask = t->cap / GROUP - 1u;
    uint64_t off = (hash >> 7) & mask;
    for (uint64_t step = 0;;) {
        for (unsigned s = 0; s < GROUP; s++) {
            int32_t *p = &t->slot[off * GROUP + s];
            if (*p < 0) {
                *p = key;
                t->growth_left--;
                return;
            }
        }
        step++;
        off = (off + step) & mask;
    }
}

/* replaceTable (GOROOT/src/internal/runtime/maps/map.go:353-361). */
static void replace_table(gmap *m, table *t)
{
    unsigned entries = 1u << (m->depth - t->local_depth);
    for (unsigned i = 0; i < entries; i++)
        m->dir[(unsigned)t->index + i] = t;
}

/* grow (GOROOT/src/internal/runtime/maps/table.go:1227-1272): a table of twice the slots in its
 * place, every key re-placed in the old slot order. */
static int grow(gmap *m, table *t, unsigned cap)
{
    table *nt = new_table(m, cap, t->index, t->local_depth);
    if (nt == NULL)
        return -1;
    for (unsigned i = 0; i < t->cap; i++)
        if (t->slot[i] >= 0)
            place(nt, t->slot[i], m->hash[t->slot[i]]);
    replace_table(m, nt);
    t->index = -1;
    return 0;
}

/* split and installTableSplit (GOROOT/src/internal/runtime/maps/table.go:1179-1225,
 * GOROOT/src/internal/runtime/maps/map.go:363-395): two tables of 1024 one level deeper, a key
 * going left or right by the hash bit that level adds, in the old slot order; and the directory
 * doubled first when the table was as deep as it. */
static int split(gmap *m, table *t)
{
    unsigned depth = t->local_depth + 1u;
    table   *left = new_table(m, MAX_TABLE, -1, depth);
    table   *right = left != NULL ? new_table(m, MAX_TABLE, -1, depth) : NULL;
    if (right == NULL)
        return -1;
    uint64_t mask = (uint64_t)1 << (64u - depth);
    for (unsigned i = 0; i < t->cap; i++) {
        int32_t k = t->slot[i];
        if (k >= 0)
            place((m->hash[k] & mask) == 0u ? left : right, k, m->hash[k]);
    }
    if (t->local_depth == m->depth) {
        unsigned n = 1u << m->depth;
        table  **nd = malloc(2u * n * sizeof *nd);
        if (nd == NULL)
            return -1;
        for (unsigned i = 0; i < n; i++) {
            table *d = m->dir[i];
            nd[2u * i] = d;
            nd[2u * i + 1u] = d;
            if (d->index == (int)i)
                d->index = (int)(2u * i);
        }
        free(m->dir);
        m->dir = nd;
        m->depth++;
    }
    left->index = t->index;
    replace_table(m, left);
    right->index = left->index + (int)(1u << (m->depth - left->local_depth));
    replace_table(m, right);
    t->index = -1;
    return 0;
}

/* NewMap with a hint (GOROOT/src/internal/runtime/maps/map.go:264-323): past a group's worth,
 * tables of hint*8/7 between them, as many as a table of 1024 each needs, a power of two of them. */
/* Keep construction and cleanup in each public walk as in the original
 * single-caller build; out-of-line calls penalize tiny header maps on MIPS. */
static inline __attribute__((always_inline)) int make_map(gmap *m, unsigned hint)
{
    m->small = 1;
    if (hint <= GROUP)
        return 0;
    uint64_t target = (uint64_t)hint * GROUP / 7u;
    uint64_t size = (target + MAX_TABLE - 1u) / MAX_TABLE, dir_size = 1;
    while (dir_size < size)
        dir_size <<= 1;
    unsigned depth = 0;
    while ((1ull << depth) < dir_size)
        depth++;
    m->dir = malloc((size_t)dir_size * sizeof *m->dir);
    if (m->dir == NULL)
        return -1;
    m->depth = depth;
    m->small = 0;
    for (uint64_t i = 0; i < dir_size; i++)
        if ((m->dir[i] = new_table(m, target / dir_size, (int)i, depth)) == NULL)
            return -1;
    return 0;
}

/* PutSlot (GOROOT/src/internal/runtime/maps/map.go:486-596,
 * GOROOT/src/internal/runtime/maps/table.go:266-380): the small group's first empty slot while it
 * has one; then the table the directory gives the hash — grown, or split, when its budget is spent,
 * and the insert tried again. */
static inline __attribute__((always_inline)) int put(gmap *m, int32_t key)
{
    uint64_t h = m->hash[key];
    if (m->small) {
        if (m->used < GROUP) {
            unsigned s = 0;
            while (m->group[s] >= 0)
                s++;
            m->group[s] = key;
            m->used++;
            return 0;
        }
        /* growToTable (GOROOT/src/internal/runtime/maps/map.go:608-645). */
        m->dir = malloc(sizeof *m->dir);
        table *t = m->dir != NULL ? new_table(m, 2u * GROUP, 0, 0) : NULL;
        if (t == NULL)
            return -1;
        for (unsigned i = 0; i < GROUP; i++)
            if (m->group[i] >= 0)
                place(t, m->group[i], m->hash[m->group[i]]);
        m->dir[0] = t;
        m->depth = 0;
        m->small = 0;
    }
    for (;;) {
        unsigned idx = m->depth == 0u ? 0u : (unsigned)(h >> (64u - m->depth));
        table   *t = m->dir[idx];
        if (t->growth_left == 0u) {
            if ((2u * t->cap <= MAX_TABLE ? grow(m, t, 2u * t->cap) : split(m, t)) != 0)
                return -1;
            continue;
        }
        place(t, key, h);
        m->used++;
        return 0;
    }
}

/* Iter.Next (GOROOT/src/internal/runtime/maps/table.go:810-1082): the small group from the entry
 * offset; or every table, from the one the directory offset lands in — moved back to the table's
 * first entry — in directory order, each from the entry offset. */
static unsigned walk(const gmap *m, uint64_t eo, uint64_t doff, unsigned *order)
{
    unsigned k = 0;
    if (m->used == 0u)
        return 0;
    if (m->small) {
        for (unsigned i = 0; i < GROUP; i++) {
            int32_t key = m->group[(unsigned)((i + eo) % GROUP)];
            if (key >= 0)
                order[k++] = (unsigned)key;
        }
        return k;
    }
    uint64_t len = 1ull << m->depth;
    for (uint64_t di = 0; di < len;) {
        uint64_t d = (di + doff) & (len - 1u);
        table   *t = m->dir[d];
        if ((uint64_t)t->index != d)
            doff -= d - (uint64_t)t->index;
        uint64_t mask = t->cap - 1u;
        for (uint64_t e = 0; e <= mask; e++) {
            int32_t key = t->slot[(e + eo) & mask];
            if (key >= 0)
                order[k++] = (unsigned)key;
        }
        di += 1ull << (m->depth - t->local_depth);
    }
    return k;
}

static inline __attribute__((always_inline)) void unmake(gmap *m)
{
    for (unsigned i = 0; i < m->nall; i++) {
        free(m->all[i]->slot);
        free(m->all[i]);
    }
    free(m->all);
    free(m->dir);
}

int lc_gomap_order(const uint64_t *hash, unsigned n, unsigned hint, uint64_t entry_off,
                   uint64_t dir_off, unsigned *order)
{
    gmap m;
    memset(&m, 0, sizeof m);
    for (unsigned i = 0; i < GROUP; i++)
        m.group[i] = -1;
    m.hash = hash;
    int rc = make_map(&m, hint);
    for (unsigned k = 0; k < n && rc == 0; k++)
        rc = put(&m, (int32_t)k);
    if (rc == 0)
        (void)walk(&m, entry_off, dir_off, order);
    unmake(&m);
    return rc;
}

/* The same iterator position without materializing a whole order. Tables have
 * no deletions, so their live count is exactly the spent growth budget. Skip
 * earlier tables by that count, then scan only the selected table's slots. */
static int select_key(const gmap *m, uint64_t eo, uint64_t doff, unsigned rank, unsigned *key)
{
    if (m->small) {
        for (unsigned i = 0; i < GROUP; i++) {
            int32_t candidate = m->group[(unsigned)((i + eo) % GROUP)];
            if (candidate >= 0 && rank-- == 0u) {
                *key = (unsigned)candidate;
                return 0;
            }
        }
        return -1;
    }
    uint64_t len = 1ull << m->depth;
    for (uint64_t di = 0; di < len;) {
        uint64_t d = (di + doff) & (len - 1u);
        table *t = m->dir[d];
        if ((uint64_t)t->index != d)
            doff -= d - (uint64_t)t->index;
        unsigned used = max_growth(t->cap) - t->growth_left;
        if (rank < used) {
            uint64_t mask = t->cap - 1u;
            for (uint64_t e = 0; e <= mask; e++) {
                int32_t candidate = t->slot[(e + eo) & mask];
                if (candidate >= 0 && rank-- == 0u) {
                    *key = (unsigned)candidate;
                    return 0;
                }
            }
            return -1;
        }
        rank -= used;
        di += 1ull << (m->depth - t->local_depth);
    }
    return -1;
}

int lc_gomap_at(const uint64_t *hash, unsigned n, unsigned hint, uint64_t entry_off,
                uint64_t dir_off, unsigned rank, unsigned *key)
{
    if (rank >= n || key == NULL)
        return -1;
    gmap m;
    memset(&m, 0, sizeof m);
    for (unsigned i = 0; i < GROUP; i++)
        m.group[i] = -1;
    m.hash = hash;
    int rc = make_map(&m, hint);
    for (unsigned k = 0; k < n && rc == 0; k++)
        rc = put(&m, (int32_t)k);
    if (rc == 0)
        rc = select_key(&m, entry_off, dir_off, rank, key);
    unmake(&m);
    return rc;
}

void lc_gomap_init(lc_gomap *m)
{
    memset(m, 0, sizeof *m);
}

void lc_gomap_init_hint(lc_gomap *m, unsigned hint)
{
    lc_gomap_init(m);
    m->hint = hint;
}

int lc_gomap_insert(lc_gomap *m)
{
    if (m->n >= LC_GOMAP_KEYS || lc_rnd((uint8_t *)&m->hash[m->n], sizeof m->hash[0]) != 0)
        return -1;
    m->n++;
    return 0;
}

int lc_gomap_walk(const lc_gomap *m, unsigned *order)
{
    uint64_t off[2];
    if (lc_rnd((uint8_t *)off, sizeof off) != 0)
        return -1;
    return lc_gomap_order(m->hash, m->n, m->hint, off[0], off[1], order);
}

int lc_gomap_fresh_walk(unsigned n, unsigned *order)
{
    /* Every hash and both offsets in ONE draw: a request's headers are built once per connection on
     * a router, and a read from the system per header is fifteen syscalls where one does. */
    uint64_t r[LC_GOMAP_KEYS + 2u];
    if (n > LC_GOMAP_KEYS || lc_rnd((uint8_t *)r, (n + 2u) * sizeof r[0]) != 0)
        return -1;
    return lc_gomap_order(r, n, 0, r[n], r[n + 1u], order);
}

int lc_gomap_copy(const lc_gomap *from, lc_gomap *to, unsigned skip, unsigned *to_from)
{
    unsigned order[LC_GOMAP_KEYS];
    if (lc_gomap_walk(from, order) != 0)
        return -1;
    int copied = 0;
    for (unsigned i = 0; i < from->n; i++) {
        if (order[i] == skip)
            continue;
        if (lc_gomap_insert(to) != 0)
            return -1;
        to_from[to->n - 1u] = order[i];
        copied++;
    }
    return copied;
}
