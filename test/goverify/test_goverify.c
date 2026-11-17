/* cert/goverify.c held to go1.27.1's own Certificate.Verify, call for call.
 *
 * test/goverify/run.sh runs crypto/x509's tests with every Verify and policiesValid call recorded
 * (tools/x509verify/zz_record.go) and hands the record to this program, which makes each call again
 * from the same bytes: every certificate parsed by lc_x509_go127_parse (Go parsed it, so must we),
 * the pools rebuilt in Go's order, the same instant, name, key usages and policy options — and the
 * answer compared: the error's text, or the chains, certificate for certificate and in Go's
 * order. White box — goverify.c is included — because policiesValid is a static function.
 *
 *   test_goverify RECORD...   (each record numbers its certificates afresh) */
#include "cert/goverify.c"

#include <stdio.h>

static int hexval(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1;
}

/* hex into a fresh buffer */
static uint8_t *unhex(const char *s, size_t n, size_t *out_n)
{
    uint8_t *b = malloc(n / 2u + 1u);
    if (b == NULL)
        return NULL;
    for (size_t i = 0; i + 1u < n; i += 2u)
        b[i / 2u] = (uint8_t)(hexval(s[i]) << 4 | hexval(s[i + 1u]));
    *out_n = n / 2u;
    return b;
}

typedef struct {
    lc_gocert c;
    int       ok;
} entry;

static entry  *certs;
static size_t  ncerts;
static size_t  parse_fail, total_certs;

/* split `s` on `sep` into at most `max` fields, in place */
static size_t split(char *s, char sep, char **f, size_t max)
{
    size_t n = 0;
    f[n++] = s;
    for (char *p = s; *p != '\0' && n < max; p++) {
        if (*p == sep) {
            *p = '\0';
            f[n++] = p + 1;
        }
    }
    return n;
}

static int index_of(const lc_gocert *c)
{
    for (size_t i = 0; i < ncerts; i++)
        if (&certs[i].c == c)
            return (int)i;
    return -1;
}

/* a list of certificate numbers, "3,5,9" or "3-5-9", into pointers; 0 when one is unusable */
static int numbers(char *s, char sep, const lc_gocert ***out, size_t *n)
{
    *out = NULL;
    *n = 0;
    if (*s == '\0')
        return 1;
    size_t k = 1;
    for (char *p = s; *p != '\0'; p++)
        k += *p == sep;
    *out = malloc(k * sizeof **out);
    char *save = s;
    for (size_t i = 0; i < k; i++) {
        long v = strtol(save, &save, 10);
        if (v < 0 || (size_t)v >= ncerts || !certs[v].ok)
            return 0;
        (*out)[(*n)++] = &certs[v].c;
        if (*save == sep)
            save++;
    }
    return 1;
}

static void options(char *ekus, char *pols, const char *flags, lc_goverify_opts *o, int **eku_buf,
                    lc_gobytes **pol_buf, uint8_t ***pol_mem)
{
    *eku_buf = NULL;
    *pol_buf = NULL;
    *pol_mem = NULL;
    size_t ne = 0, np = 0;
    if (*ekus != '\0') {
        size_t k = 1;
        for (char *p = ekus; *p; p++)
            k += *p == ',';
        *eku_buf = malloc(k * sizeof **eku_buf);
        char *s = ekus;
        for (size_t i = 0; i < k; i++) {
            (*eku_buf)[ne++] = (int)strtol(s, &s, 10);
            if (*s == ',')
                s++;
        }
    }
    if (*pols != '\0') {
        size_t k = 1;
        for (char *p = pols; *p; p++)
            k += *p == ',';
        *pol_buf = malloc(k * sizeof **pol_buf);
        *pol_mem = calloc(k + 1u, sizeof **pol_mem);
        char *s = pols;
        for (size_t i = 0; i < k; i++) {
            char  *e = strchr(s, ',');
            size_t len = e != NULL ? (size_t)(e - s) : strlen(s);
            size_t bn;
            uint8_t *b = unhex(s, len, &bn);
            (*pol_mem)[i] = b;
            (*pol_buf)[np++] = (lc_gobytes){ b, bn };
            s += len + (e != NULL);
        }
    }
    o->key_usages = *eku_buf;
    o->key_usages_n = ne;
    o->policies = *pol_buf;
    o->policies_n = np;
    o->inhibit_policy_mapping = flags[0] == '1';
    o->require_explicit_policy = flags[1] == '1';
    o->inhibit_any_policy = flags[2] == '1';
}

static void free_options(int *eku, lc_gobytes *pol, uint8_t **mem, size_t np)
{
    free(eku);
    free(pol);
    if (mem != NULL)
        for (size_t i = 0; i < np; i++)
            free(mem[i]);
    free(mem);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: test_goverify RECORD...\n");
        return 2;
    }
    size_t  cap = 0, v_total = 0, v_bad = 0, p_total = 0, p_bad = 0, v_ok_chains = 0, v_err = 0,
           skipped = 0, shown = 0;
    char   *line = NULL;
    ssize_t len;
    for (int arg = 1; arg < argc; arg++) {
    FILE *f = fopen(argv[arg], "r");
    if (f == NULL) {
        perror(argv[arg]);
        return 2;
    }
    while ((len = getline(&line, &cap, f)) > 0) {
        if (line[len - 1] == '\n')
            line[--len] = '\0';
        char  *fld[12];
        size_t nf;
        if (line[0] == 'C') {
            nf = split(line, '|', fld, 3);
            size_t idx = (size_t)strtoul(fld[1], NULL, 10);
            if (idx != ncerts) {
                fprintf(stderr, "record out of order at certificate %zu\n", idx);
                return 2;
            }
            certs = realloc(certs, (ncerts + 1u) * sizeof *certs);
            size_t   dn;
            uint8_t *der = unhex(fld[2], strlen(fld[2]), &dn);
            lc_obuf  why = { 0 };
            certs[ncerts].ok = lc_x509_go127_parse(der, dn, &certs[ncerts].c, NULL, &why) == 0;
            if (!certs[ncerts].ok) {
                parse_fail++;
                if (shown++ < 10)
                    printf("  FAIL  certificate %zu parses in Go, not here: %s\n", ncerts,
                           why.p != NULL ? why.p : "");
            }
            free(why.p);
            free(der);
            ncerts++;
            total_certs++;
        } else if (line[0] == 'V') {
            /* V|leaf|roots|inters|unix|nsec|dns|ekus|pols|flags|result */
            nf = split(line, '|', fld, 11);
            if (nf != 11u)
                continue;
            v_total++;
            const lc_gocert **leaf, **roots, **inters;
            size_t            nl, nr, ni;
            if (!numbers(fld[1], ',', &leaf, &nl) || nl != 1u || !numbers(fld[2], ',', &roots, &nr) ||
                !numbers(fld[3], ',', &inters, &ni)) {
                skipped++;
                continue;
            }
            lc_gopool *rp = lc_gopool_new(), *ip = lc_gopool_new();
            for (size_t i = 0; i < nr; i++)
                pool_add_borrowed(rp, roots[i]);
            for (size_t i = 0; i < ni; i++)
                pool_add_borrowed(ip, inters[i]);
            size_t dn;
            char  *dns = (char *)unhex(fld[6], strlen(fld[6]), &dn);
            lc_goverify_opts o;
            memset(&o, 0, sizeof o);
            o.roots = rp;
            o.intermediates = ip;
            o.have_time = 1;
            o.now_sec = strtoll(fld[4], NULL, 10);
            o.now_nsec = (int32_t)strtol(fld[5], NULL, 10);
            o.dns_name = dns;
            o.dns_name_n = dn;
            int        *eku;
            lc_gobytes *pol;
            uint8_t   **mem;
            options(fld[7], fld[8], fld[9], &o, &eku, &pol, &mem);

            lc_gochains ch = { 0 };
            lc_obuf     err = { 0 };
            int         rc = lc_go_verify(leaf[0], &o, &ch, &err);
            lc_obuf     got = { 0 };
            if (rc == 0) {
                put(&got, "C:");
                for (size_t i = 0; i < ch.n; i++) {
                    if (i > 0u)
                        put(&got, ";");
                    for (size_t k = 0; k < ch.a[i].n; k++) {
                        if (k > 0u)
                            put(&got, "-");
                        put_int(&got, index_of(ch.a[i].certs[k]));
                    }
                }
            } else {
                put(&got, "E:");
                static const char hx[] = "0123456789abcdef";
                for (size_t i = 0; i < err.n; i++) {
                    lc_obuf_byte(&got, (uint8_t)hx[(uint8_t)err.p[i] >> 4]);
                    lc_obuf_byte(&got, (uint8_t)hx[(uint8_t)err.p[i] & 15u]);
                }
            }
            const char *want = fld[10];
            int         same = got.p != NULL && strcmp(got.p, want) == 0;
            if (want[0] == 'C')
                v_ok_chains++;
            else
                v_err++;
            if (!same) {
                v_bad++;
                if (shown++ < 25) {
                    printf("  FAIL  Verify of certificate %s (dns %.*s):\n", fld[1], (int)dn, dns);
                    if (want[0] == 'E') {
                        size_t wn;
                        char  *w = (char *)unhex(want + 2, strlen(want + 2), &wn);
                        printf("          Go:   %.*s\n", (int)wn, w);
                        free(w);
                    } else {
                        printf("          Go:   %s\n", want);
                    }
                    if (rc == 0)
                        printf("          here: %s\n", got.p);
                    else
                        printf("          here: %.*s\n", (int)err.n, err.p != NULL ? err.p : "");
                }
            }
            free(got.p);
            free(err.p);
            lc_gochains_free(&ch);
            free_options(eku, pol, mem, o.policies_n);
            free(dns);
            lc_gopool_free(rp);
            lc_gopool_free(ip);
            free(leaf);
            free(roots);
            free(inters);
        } else if (line[0] == 'P') {
            /* P|chain|ekus|pols|flags|result */
            nf = split(line, '|', fld, 6);
            if (nf != 6u)
                continue;
            p_total++;
            const lc_gocert **chain;
            size_t            n;
            if (!numbers(fld[1], '-', &chain, &n)) {
                skipped++;
                continue;
            }
            lc_goverify_opts o;
            memset(&o, 0, sizeof o);
            int        *eku;
            lc_gobytes *pol;
            uint8_t   **mem;
            options(fld[2], fld[3], fld[4], &o, &eku, &pol, &mem);
            int oom = 0;
            int got = policies_valid((chainv){ chain, n }, &o, &oom);
            if (got != atoi(fld[5]) || oom) {
                p_bad++;
                if (shown++ < 25)
                    printf("  FAIL  policiesValid of chain %s (options %s|%s|%s): Go %s, here %d\n",
                           fld[1], fld[2], fld[3], fld[4], fld[5], got);
            }
            free_options(eku, pol, mem, o.policies_n);
            free(chain);
        }
    }
    fclose(f);
    for (size_t i = 0; i < ncerts; i++)
        if (certs[i].ok)
            lc_gocert_free(&certs[i].c);
    free(certs);
    certs = NULL;
    ncerts = 0;
    }
    free(line);

    int fails = 0;
    printf("  %s  %zu certificates Go parsed, %zu refused here\n", parse_fail ? "FAIL" : "ok  ", total_certs,
           parse_fail);
    fails += parse_fail != 0u;
    printf("  %s  %zu Verify calls (%zu with chains, %zu with errors): %zu answered otherwise\n",
           v_bad ? "FAIL" : "ok  ", v_total, v_ok_chains, v_err, v_bad);
    fails += v_bad != 0u;
    printf("  %s  %zu policiesValid calls: %zu answered otherwise\n", p_bad ? "FAIL" : "ok  ", p_total, p_bad);
    fails += p_bad != 0u;
    if (skipped)
        printf("  FAIL  %zu calls name a certificate that did not parse here\n", skipped);
    fails += skipped != 0u;
    if (v_total < 1000u || p_total < 100u) {
        printf("  FAIL  too few calls recorded: the record is not Go's whole test suite\n");
        fails++;
    }
    return fails ? 1 : 0;
}
