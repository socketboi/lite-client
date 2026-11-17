/* cert/goverify.c's lc_go_load_roots, printed the way tools/x509roots prints go1.27.1's
 * SystemCertPool: one line per certificate, its subject in hex, in the pool's order — or "error: "
 * and the error. test/goroots/run.sh compares the two, scenario by scenario. */
#include "cert/goverify.h"

#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    lc_gopool *p = NULL;
    lc_obuf    err = { 0 };
    int        rc = lc_go_load_roots(getenv("SSL_CERT_FILE"), getenv("SSL_CERT_DIR"), &p, &err);
    if (rc == -2) {
        fprintf(stderr, "out of memory\n");
        return 2;
    }
    if (rc != 0) {
        printf("error: %.*s\n", (int)err.n, err.p != NULL ? err.p : "");
        free(err.p);
        return 0;
    }
    for (size_t i = 0; i < lc_gopool_len(p); i++) {
        const lc_gocert *c = lc_gopool_cert(p, i);
        for (size_t k = 0; k < c->raw_subject.n; k++)
            printf("%02x", c->raw_subject.p[k]);
        printf("\n");
    }
    lc_gopool_free(p);
    return 0;
}
