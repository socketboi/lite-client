#include "cert/chain.h"

#include "cert/cert.h"
#include "cert/goverify.h"
#include "cert/x509go.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The certificates of a TLS 1.3 Certificate message body, each read by go1.27.1's
 * x509.ParseCertificate as uTLS reads them before anything else looks
 * (vendor/utls/handshake_client.go:1143-1154): 0 with them, -1 with the words. */
static int parse_all(const uint8_t *body, size_t len, lc_gocert **out, size_t *n, char *err,
                     size_t err_cap)
{
    *out = NULL;
    *n = 0;
    size_t         off = 0;
    const uint8_t *der = NULL;
    size_t         der_len = 0;
    int            step;
    while ((step = lc_cert_next_from_message(body, len, &off, &der, &der_len)) == 0) {
        lc_gocert *v = realloc(*out, (*n + 1u) * sizeof *v);
        if (v == NULL) {
            snprintf(err, err_cap, "out of memory reading the certificates");
            return -1;
        }
        *out = v;
        lc_obuf why = { 0 };
        if (lc_x509_go127_parse(der, der_len, &(*out)[*n], NULL, &why) != 0) {
            snprintf(err, err_cap, "tls: failed to parse certificate from server: %s",
                     why.p != NULL ? why.p : "");
            free(why.p);
            return -1;
        }
        free(why.p);
        (*n)++;
    }
    if (step < 0) {
        snprintf(err, err_cap, "the certificate list is malformed");
        return -1;
    }
    if (*n == 0u) {
        snprintf(err, err_cap, "the peer sent an empty certificate list");
        return -1;
    }
    return 0;
}

int lc_chain_verify(const uint8_t *body, size_t len, const char *hostname, char *err, size_t err_cap)
{
    lc_gocert *certs;
    size_t     n;
    int        rc = parse_all(body, len, &certs, &n, err, err_cap);
    if (rc == 0) {
        lc_obuf why = { 0 };
        rc = lc_go_verify_peer(certs, n, hostname, &why);
        if (rc != 0)
            snprintf(err, err_cap, "%s", why.oom ? "out of memory verifying the chain"
                                     : why.p != NULL ? why.p
                                                     : "");
        free(why.p);
        rc = rc == 0 ? 0 : -1;
    }
    for (size_t i = 0; i < n; i++)
        lc_gocert_free(&certs[i]);
    free(certs);
    return rc;
}

int lc_x509_parses(const uint8_t *der, size_t len, size_t *rsa_bits)
{
    return lc_x509_go127_parse(der, len, NULL, rsa_bits, NULL) == 0;
}

void lc_chain_forget_roots(void)
{
    lc_go_system_roots_reset(NULL, NULL);
}
