/* The UDP sessions of one Hysteria2 connection: how they are numbered, found and forgotten.
 *
 * What matters is what the reference's map gives for free and a sorted array has to earn: every id
 * handed out once, from one upwards (vendor/hysteria/core/client/udp.go:99, :153-154); a lookup
 * that finds exactly the session with that id, whatever has been closed around it; no ceiling but
 * memory — the thirty-two this used to stop at is crossed many times over here; and a reassembly
 * buffer that goes with the session that took it. */

#include "quic/udptab.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

static int failures;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

/* Whether the table holds exactly the ids `want` says it does, each found at its own entry. */
static int holds(lc_qudptab *t, const unsigned char *want, unsigned upto)
{
    unsigned n = 0;
    for (unsigned id = 1; id <= upto; id++) {
        lc_qudp *u = lc_qudptab_find(t, id);
        if ((u != NULL) != (want[id] != 0))
            return 0;
        if (u != NULL && u->id != id)
            return 0;
        n += want[id] != 0;
    }
    return n == t->n;
}

static void test_numbering(void)
{
    lc_qudptab t = { 0 };
    lc_qudp   *a = lc_qudptab_open(&t);
    ok(a != NULL && a->id == 1u, "the first session is number one, as upstream's first is");
    lc_qudp *b = lc_qudptab_open(&t);
    ok(b != NULL && b->id == 2u, "the next is two");
    lc_qudptab_close(&t, 1u);
    lc_qudp *c = lc_qudptab_open(&t);
    ok(c != NULL && c->id == 3u, "a closed number is not handed out again: nextID only grows");
    ok(lc_qudptab_find(&t, 0u) == NULL, "zero is never a session");
    ok(lc_qudptab_find(&t, 1u) == NULL, "a closed session is not found");
    ok(lc_qudptab_find(&t, 4u) == NULL, "nor one never opened");
    lc_qudptab_free(&t);
    ok(t.n == 0u && t.v == NULL && t.last_id == 0u, "freed, the table is empty and starts at one again");
}

/* A thousand sessions — thirty-one times the old ceiling — then two thirds of them closed in an
 * order that is neither first-to-last nor last-to-first, with every survivor checked after each
 * round. */
static void test_many(void)
{
    enum { N = 1000 };
    static unsigned char want[N + 1];
    lc_qudptab           t = { 0 };
    int                  opened = 1;
    for (unsigned i = 1; i <= N; i++) {
        lc_qudp *u = lc_qudptab_open(&t);
        opened = opened && u != NULL && u->id == i;
        want[i] = 1;
    }
    ok(opened && t.n == N, "a thousand sessions open, each with the next number");
    ok(holds(&t, want, N), "and each is found as itself");

    /* Every id divisible by three, last to first; then every id one short of that, first to last.
     * What is left is 1, 4, 7 … 1000 — 334 of them. */
    int      kept = 1;
    unsigned left = N;
    for (unsigned id = N - N % 3u; id >= 3u; id -= 3u) {
        lc_qudptab_close(&t, id);
        want[id] = 0;
        left--;
    }
    kept = kept && holds(&t, want, N);
    for (unsigned id = 2; id <= N; id += 3u) {
        lc_qudptab_close(&t, id);
        want[id] = 0;
        left--;
    }
    kept = kept && holds(&t, want, N);
    ok(kept && t.n == left && left == 334u,
       "two thirds closed in two orders, the third that is left is found, each as itself");

    lc_qudp *u = lc_qudptab_open(&t);
    ok(u != NULL && u->id == N + 1u && lc_qudptab_find(&t, N + 1u) == u,
       "and a new one after all that takes the next number and is found");
    lc_qudptab_close(&t, 5000u);
    ok(t.n == left + 1u, "closing a number that is not there changes nothing");
    lc_qudptab_free(&t);
}

/* The buffer a session takes for its first fragment is the session's, and goes with it — and only
 * with it: closing one session must not take its neighbour's. */
static void test_buffers(void)
{
    lc_qudptab t = { 0 };
    lc_qudp   *a = lc_qudptab_open(&t);
    lc_qudp   *b = lc_qudptab_open(&t);
    lc_qudp   *c = lc_qudptab_open(&t);
    ok(a != NULL && b != NULL && c != NULL && a->r.buf == NULL && b->r.buf == NULL,
       "a session opens holding no reassembly buffer");
    uint8_t *bb = malloc(64), *cb = malloc(64);
    lc_qudptab_find(&t, 2u)->r.buf = bb;
    lc_qudptab_find(&t, 3u)->r.buf = cb;
    lc_qudptab_close(&t, 2u);
    lc_qudp *c2 = lc_qudptab_find(&t, 3u);
    ok(c2 != NULL && c2->r.buf == cb, "closing one leaves the next one its own buffer");
    lc_qudptab_free(&t); /* cb goes here; bb went with session 2 */
}

/* Ids stop at INT_MAX, because lc_qconn hands them out as ints and a negative one reads as failure. */
static void test_exhaustion(void)
{
    lc_qudptab t = { 0 };
    t.last_id = (uint32_t)INT_MAX - 1u;
    lc_qudp *u = lc_qudptab_open(&t);
    ok(u != NULL && u->id == (uint32_t)INT_MAX, "the last id an int can hold is still handed out");
    ok(lc_qudptab_open(&t) == NULL, "and after it no more: refused, not wrapped to a negative handle");
    ok(t.n == 1u, "and the refusal added nothing");
    lc_qudptab_free(&t);
}

int main(void)
{
    printf("the UDP sessions of a Hysteria2 connection\n");

    test_numbering();
    test_many();
    test_buffers();
    test_exhaustion();

    printf("\n%s\n", failures == 0 ? "sessions are numbered, found and forgotten as upstream's map does"
                                   : "the session table has CHANGED");
    return failures == 0 ? 0 : 1;
}
