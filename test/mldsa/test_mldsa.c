/* cert/mldsa.c against Go 1.27.1's own crypto/mldsa: every key, message and signature
 * tools/mldsavec wrote down, NewPublicKey's answer and Verify's, verdict and words. */
#include "cert/mldsa.h"

#include "reference.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int      failures;
static unsigned shown;

static int same(const char *what, const char *call, int rc, const lc_obuf *err, const char *want)
{
    const char *got = rc == 0 ? "" : (err->p != NULL ? err->p : "(no words)");
    if ((rc == 0) != (want[0] == '\0') || strcmp(got, want) != 0) {
        if (shown++ < 25)
            printf("  FAIL  %s: %s\n        Go:   \"%s\"\n        this: \"%s\"\n", what, call, want, got);
        return 0;
    }
    return 1;
}

/* A byte string that grows, for the cases that append. */
typedef struct {
    uint8_t *p;
    size_t   n;
} bytes;

static void build(bytes *b, const uint8_t *src, size_t n, size_t cap)
{
    b->p = malloc(cap > 0u ? cap : 1u);
    if (b->p == NULL) {
        printf("  FAIL  out of memory\n");
        exit(1);
    }
    if (n != 0u)
        memcpy(b->p, src, n);
    b->n = n;
}

static void apply(bytes *b, const struct mv_case *m)
{
    switch (m->op) {
    case 1: b->p[m->pos] ^= m->val; break;
    case 2: b->p[m->pos] = m->val; break;
    case 3: b->n = m->pos; break;
    case 4: memset(b->p + b->n, m->val, m->pos); b->n += m->pos; break;
    default: break;
    }
}

/* The signature of base i, rebuilt from its pool bytes or from the base it was edited from. */
static void base_sig(size_t i, uint8_t *out)
{
    const struct mv_base *b = &mv_bases[i];
    if (b->from < 0) {
        memcpy(out, mv_pool + b->sig, b->sig_len);
        return;
    }
    const struct mv_base *f = &mv_bases[b->from];
    memcpy(out, mv_pool + f->sig, f->sig_len);
    for (unsigned e = b->edit; e < (unsigned)b->edit + b->nedit; e++)
        out[mv_edits[e].pos] = mv_edits[e].val;
}

int main(void)
{
    printf("crypto/mldsa of go1.27.1: NewPublicKey and Verify(pub, msg, sig, nil)\n");

    size_t   nc = sizeof mv_cases / sizeof mv_cases[0];
    size_t   accepted = 0, refused_pk = 0;
    int      before = failures;
    for (size_t i = 0; i < nc; i++) {
        const struct mv_case *m = &mv_cases[i];
        const struct mv_base *b = &mv_bases[m->base];
        uint8_t               sig0[LC_MLDSA87_SIG];
        base_sig(m->base, sig0);

        size_t extra = m->op == 4 ? m->pos : 0u;
        bytes  pk, msg, sig;
        build(&pk, mv_pool + b->pk, b->pk_len, b->pk_len + extra);
        build(&msg, mv_pool + b->msg, b->msg_len, b->msg_len + extra);
        build(&sig, sig0, b->sig_len, b->sig_len + extra);
        if (m->target == 1)
            apply(&pk, m);
        else if (m->target == 2)
            apply(&msg, m);
        else if (m->target == 3)
            apply(&sig, m);

        char what[200];
        snprintf(what, sizeof what, "%s (target %u, op %u, pos %u, val %#x, params %u)", b->what, m->target,
                 m->op, m->pos, m->val, m->params);

        lc_obuf e1 = { 0 }, e2 = { 0 };
        int     rc1 = lc_mldsa_public_key_ok(m->params, pk.p, pk.n, &e1);
        int     rc2 = lc_mldsa_verify(m->params, pk.p, pk.n, msg.p, msg.n, sig.p, sig.n, &e2);
        int     ok = same(what, "NewPublicKey", rc1, &e1, mv_texts[m->t_pk]);
        ok = same(what, "Verify", rc2, &e2, mv_texts[m->t_ver]) && ok;
        /* And with no place for the words: the verdict alone. */
        ok = ok && (lc_mldsa_verify(m->params, pk.p, pk.n, msg.p, msg.n, sig.p, sig.n, NULL) == 0) ==
                       (mv_texts[m->t_ver][0] == '\0');
        if (!ok)
            failures++;
        accepted += rc2 == 0;
        refused_pk += rc1 != 0;
        free(e1.p);
        free(e2.p);
        free(pk.p);
        free(msg.p);
        free(sig.p);
    }
    printf("  %-4s  %zu cases over %zu keys, messages and signatures: every answer Go's (%zu valid, %zu keys "
           "refused, %d differ)\n",
           failures == before ? "ok" : "FAIL", nc, sizeof mv_bases / sizeof mv_bases[0], accepted, refused_pk,
           failures - before);

    /* Every distinct text Go gave appears among the answers this checked — a header that lost a
     * refusal path would otherwise pass with it untested. */
    size_t nt = sizeof mv_texts / sizeof mv_texts[0];
    int    all = 1;
    for (size_t t = 0; t < nt; t++) {
        int seen = 0;
        for (size_t i = 0; i < nc && !seen; i++)
            seen = mv_cases[i].t_ver == t || mv_cases[i].t_pk == t;
        all = all && seen;
    }
    printf("  %-4s  %zu distinct answers of Go's, each reached\n", all && nt >= 6u ? "ok" : "FAIL", nt);
    if (!(all && nt >= 6u))
        failures++;

    if (failures) {
        printf("%d FAILED\n", failures);
        return 1;
    }
    printf("all good\n");
    return 0;
}
