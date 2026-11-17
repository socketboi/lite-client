/* uTLS's rawInput (tls/rawin.c) against Go's own: every case tools/rawin ran through a real
 * bytes.Buffer and uTLS's readFromUntil is run here through the model, the stream arriving in the
 * same chunks, and every size a read asked for must be the one Go's asked for, and the buffer's
 * shape at the end Go's. Then the allocator's rounding, length by length. */

#include "tls/rawin.h"

#include <stdio.h>
#include <string.h>

#include "reference.h"

static int failures;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

/* The socket as tools/rawin's feed is: a read gets what is left of the current chunk or what it
 * asked for, whichever is less. */
typedef struct {
    const int32_t *chunks;
    uint32_t       n, i;
    size_t         left;
} feed;

static size_t feed_read(feed *f, size_t asked)
{
    if (f->left == 0u) {
        if (f->i == f->n)
            return 0;
        f->left = (size_t)f->chunks[f->i++];
    }
    size_t got = asked < f->left ? asked : f->left;
    f->left -= got;
    return got;
}

/* readFromUntil(n) through the model, each size asked checked against Go's next. */
static int until(lc_rawin *r, feed *f, size_t n, const int32_t *asked, uint32_t nasked,
                 uint32_t *k)
{
    size_t want;
    while ((want = lc_rawin_ask(r, n)) > 0u) {
        if (*k >= nasked || (size_t)asked[*k] != want)
            return 0;
        (*k)++;
        size_t got = feed_read(f, want);
        if (got == 0u)
            return 0;
        lc_rawin_got(r, got);
    }
    return 1;
}

static int one_case(const struct rw_case *c)
{
    lc_rawin r;
    memset(&r, 0, sizeof r);
    feed     f = { rw_chunks + c->chunks, c->nchunks, 0, 0 };
    uint32_t k = 0;
    for (uint32_t i = 0; i < c->nrecs; i++) {
        int32_t body = rw_recs[c->recs + i];
        if (!until(&r, &f, 5, rw_asked + c->asked, c->nasked, &k))
            return 0;
        if (body < 0)
            break;
        if (!until(&r, &f, 5u + (size_t)body, rw_asked + c->asked, c->nasked, &k))
            return 0;
        lc_rawin_next(&r, 5u + (size_t)body);
    }
    return k == c->nasked && r.off == c->off && r.len == c->len && r.cap == c->cap;
}

int main(void)
{
    printf("the node's socket asked for what uTLS's rawInput asks for, read by read\n");
    char     what[160];
    unsigned n = sizeof rw_cases / sizeof rw_cases[0], good = 0, reads = 0;
    for (unsigned i = 0; i < n; i++) {
        good += (unsigned)one_case(&rw_cases[i]);
        reads += rw_cases[i].nasked;
    }
    snprintf(what, sizeof what, "%u streams, %u reads: every size asked and every buffer's shape "
                                "at the end is Go's (%u agree)", n, reads, good);
    ok(good == n, what);

    /* The first case is the stand's `huge` on a fresh connection: one read of 576 bytes, and the
     * rest of the record left in the socket. */
    ok(rw_cases[0].nasked == 1u && rw_asked[rw_cases[0].asked] == 576,
       "a refused header on a fresh connection: the reference asks for 576 bytes, and no more");

    /* rw_roundup: pairs of (length, capacity from there on), from 65 to 70 000. */
    unsigned steps = sizeof rw_roundup / sizeof rw_roundup[0] / 2u, bad = 0, checked = 0;
    for (unsigned s = 0; s < steps; s++) {
        size_t from = (size_t)rw_roundup[2u * s], to = s + 1u < steps ? (size_t)rw_roundup[2u * s + 2u]
                                                                      : 70001u;
        for (size_t c = from; c < to; c++, checked++)
            if (lc_rawin_roundup(c) != (size_t)rw_roundup[2u * s + 1u])
                bad++;
    }
    snprintf(what, sizeof what, "the allocator's rounding for every length from 65 to 70 000 is "
                                "the runtime's (%u lengths, %u differ)", checked, bad);
    ok(checked == 70000u - 64u && bad == 0u, what);

    if (failures) {
        printf("%d FAILED\n", failures);
        return 1;
    }
    printf("all good\n");
    return 0;
}
