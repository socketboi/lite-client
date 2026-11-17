#include "quic/udptab.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

lc_qudp *lc_qudptab_find(lc_qudptab *t, uint32_t id)
{
    unsigned lo = 0, hi = t->n;
    while (lo < hi) {
        unsigned mid = lo + (hi - lo) / 2u;
        if (t->v[mid].id < id)
            lo = mid + 1u;
        else
            hi = mid;
    }
    return lo < t->n && t->v[lo].id == id ? &t->v[lo] : NULL;
}

lc_qudp *lc_qudptab_open(lc_qudptab *t)
{
    if (t->last_id >= (uint32_t)INT_MAX)
        return NULL;
    if (t->n == t->cap) {
        unsigned cap = t->cap > 0u ? t->cap * 2u : 8u;
        lc_qudp *grown = realloc(t->v, (size_t)cap * sizeof *grown);
        if (grown == NULL)
            return NULL;
        t->v = grown;
        t->cap = cap;
    }
    /* On the end, where the largest id so far belongs. Zero is never an id, so an uninitialised
     * field is never a session — upstream's client starts at one too
     * (vendor/hysteria/core/client/udp.go:99, :153-154). */
    lc_qudp *u = &t->v[t->n++];
    memset(u, 0, sizeof *u);
    u->id = ++t->last_id;
    return u;
}

static void held_free(lc_qudp *u)
{
    for (unsigned i = 0; i < u->hq_n; i++)
        free(u->hq[(u->hq_head + i) % LC_QUDP_CHAN]);
    free(u->hq);
    free(u->hq_len);
}

void lc_qudptab_close(lc_qudptab *t, uint32_t id)
{
    lc_qudp *u = lc_qudptab_find(t, id);
    if (u == NULL)
        return;
    free(u->r.buf);
    held_free(u);
    size_t at = (size_t)(u - t->v);
    memmove(u, u + 1, (t->n - at - 1u) * sizeof *u);
    t->n--;
}

void lc_qudptab_free(lc_qudptab *t)
{
    for (unsigned i = 0; i < t->n; i++) {
        free(t->v[i].r.buf);
        held_free(&t->v[i]);
    }
    free(t->v);
    memset(t, 0, sizeof *t);
}
