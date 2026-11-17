/* cert/x509go.c against Go's own x509.ParseCertificate: every certificate tools/x509read wrote
 * down, the verdict and the words — go1.26.6's for lc_x509_go_parse (the QUIC plane) and
 * go1.27.1's for lc_x509_go127_parse (the REALITY plane), the latter asked twice, for the verdict
 * alone and with the certificate filled in, which must not change the answer. The reference's
 * answer is taken for the machine this runs on — the 64-bit one where Go's int is 64 bits wide and
 * P-256 is assembly (x86_64, aarch64), the 32-bit one where it is neither (mipsel) — as
 * cert/x509go.c answers for the machine it is compiled for. */
#include "cert/x509go.h"

#include "reference.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WIDE (UINTPTR_MAX > 0xffffffffu)

static int      failures;
static unsigned shown;

static void compare(const char *toolchain, const char *what, const char *want, int rc, lc_obuf *err)
{
    const char *got = rc == 0 ? "" : (err->p != NULL ? err->p : "(no words)");
    if ((rc == 0) != (want[0] == '\0') || strcmp(got, want) != 0) {
        if (shown++ < 25)
            printf("  FAIL  %s, %s\n        Go:   \"%s\"\n        this: \"%s\"\n", toolchain, what, want, got);
        failures++;
    }
    free(err->p);
}

static void check(const char *what, const uint8_t *der, size_t len, uint16_t t64, uint16_t t32, uint16_t u64,
                  uint16_t u32)
{
    lc_obuf err = { 0 };
    size_t  bits = 0;
    compare("go1.26.6", what, xg_texts[WIDE ? t64 : t32], lc_x509_go_parse(der, len, &bits, &err), &err);
    err = (lc_obuf){ 0 };
    compare("go1.27.1", what, xg_texts[WIDE ? u64 : u32], lc_x509_go127_parse(der, len, NULL, &bits, &err),
            &err);
    lc_gocert c;
    err = (lc_obuf){ 0 };
    int rc = lc_x509_go127_parse(der, len, &c, &bits, &err);
    compare("go1.27.1 with the fields", what, xg_texts[WIDE ? u64 : u32], rc, &err);
    if (rc == 0)
        lc_gocert_free(&c);
}

int main(void)
{
    printf("x509.ParseCertificate, go1.26.6 and go1.27.1, as the %s reference answers it\n",
           WIDE ? "64-bit" : "32-bit");

    size_t         nm = sizeof xg_mutations / sizeof xg_mutations[0];
    static uint8_t buf[1u << 16];
    int            before = failures;
    for (size_t i = 0; i < nm; i++) {
        const uint8_t *base = xg_pool + xg_bases[xg_mutations[i].base].off;
        size_t         len = xg_bases[xg_mutations[i].base].len;
        memcpy(buf, base, len);
        switch (xg_mutations[i].op) {
        case 1: buf[xg_mutations[i].pos] ^= xg_mutations[i].val; break;
        case 2: buf[xg_mutations[i].pos] = xg_mutations[i].val; break;
        case 3: len = xg_mutations[i].pos; break;
        default: break;
        }
        char what[96];
        snprintf(what, sizeof what, "base %u, byte %u, op %u, value %#x", xg_mutations[i].base,
                 xg_mutations[i].pos, xg_mutations[i].op, xg_mutations[i].val);
        check(what, buf, len, xg_mutations[i].t64, xg_mutations[i].t32, xg_mutations[i].u64,
              xg_mutations[i].u32);
    }
    printf("  %-4s  %zu mutations of %zu certificates: every answer Go's (%d differ)\n",
           failures == before ? "ok" : "FAIL", nm, sizeof xg_bases / sizeof xg_bases[0], failures - before);

    size_t ne = sizeof xg_edges / sizeof xg_edges[0];
    before = failures;
    for (size_t i = 0; i < ne; i++)
        check(xg_edges[i].what, xg_pool + xg_edges[i].off, xg_edges[i].len, xg_edges[i].t64,
              xg_edges[i].t32, xg_edges[i].u64, xg_edges[i].u32);
    printf("  %-4s  %zu edges written out one by one: every answer Go's (%d differ)\n",
           failures == before ? "ok" : "FAIL", ne, failures - before);

    /* And the key size the TLS layer weighs, which only a parsed RSA key has: the rich base is
     * RSA with a 512-bit modulus, the second is P-256 — for both toolchains. */
    size_t bits = 1;
    int    ok = lc_x509_go_parse(xg_pool + xg_bases[0].off, xg_bases[0].len, &bits, NULL) == 0 &&
             bits == 512u;
    ok = ok && lc_x509_go_parse(xg_pool + xg_bases[1].off, xg_bases[1].len, &bits, NULL) == 0 &&
         bits == 0u;
    ok = ok && lc_x509_go127_parse(xg_pool + xg_bases[0].off, xg_bases[0].len, NULL, &bits, NULL) == 0 &&
         bits == 512u;
    ok = ok && lc_x509_go127_parse(xg_pool + xg_bases[1].off, xg_bases[1].len, NULL, &bits, NULL) == 0 &&
         bits == 0u;
    printf("  %-4s  N.BitLen() of an RSA key, and none for any other\n", ok ? "ok" : "FAIL");
    if (!ok)
        failures++;

    if (failures) {
        printf("%d FAILED\n", failures);
        return 1;
    }
    printf("all good\n");
    return 0;
}
