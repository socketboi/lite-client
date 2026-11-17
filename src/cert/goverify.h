/* x509.Certificate.Verify of go1.27.1, as the REALITY plane's reference runs it.
 *
 * When a REALITY node does not recognise this client it relays a real site, and the site's chain is
 * verified as an ordinary web certificate:
 *
 *     opts := x509.VerifyOptions{ DNSName: c.ServerName, Intermediates: x509.NewCertPool() }
 *     for _, cert := range certs[1:] { opts.Intermediates.AddCert(cert) }
 *     if _, err := certs[0].Verify(opts); err != nil { return err }
 *                    (vendor/Xray-core/transport/internet/reality/reality.go:128-139)
 *
 * with Roots nil, which on Linux is the pool loadSystemRoots builds from the files Go knows
 * (GOROOT/src/crypto/x509/root.go, root_linux.go), and a failure there is answered by uTLS with
 * alertBadCertificate. Which chains pass is therefore the reference's decision, and this is its
 * code: buildChains with its candidate order and its signature-check budget, isValid,
 * VerifyHostname (no Common Name), the nested EKU check, RFC 9618's policy graph and the name
 * constraints of constraints.go — each function below names the one it transcribes
 * (GOROOT/src/crypto/x509/verify.go unless it says otherwise). The words of the error are Go's
 * too, for the log.
 *
 * Until 2026-09-30 mbedTLS decided this (DIVERGENCES.md G4): a Common Name was matched when there
 * was no SAN, name constraints, policies and the EKU nesting were its own, and so was the store. */
#ifndef LC_GOVERIFY_H
#define LC_GOVERIFY_H

#include "cert/gocert.h"
#include "core/gotext.h"

#include <stddef.h>
#include <stdint.h>

/* x509.CertPool: certificates in the order they were added, each once (by its bytes). */
typedef struct lc_gopool lc_gopool;

lc_gopool *lc_gopool_new(void);
void       lc_gopool_free(lc_gopool *p);

/* AddCert: the pool takes `c` — its contents, which the caller must not free — unless an identical
 * certificate is already there, in which case `c` is released. 0, or -2 when memory ran out. */
int lc_gopool_add(lc_gopool *p, lc_gocert *c);

/* AppendCertsFromPEM (cert_pool.go): every CERTIFICATE block without headers that pem.Decode finds
 * and go1.27.1's ParseCertificate reads. 1 when one was added, 0 when none, -2 out of memory. */
int lc_gopool_append_pem(lc_gopool *p, const uint8_t *pem, size_t n);

size_t           lc_gopool_len(const lc_gopool *p);
const lc_gocert *lc_gopool_cert(const lc_gopool *p, size_t i);

/* systemRootsPool on Linux: loaded once per process, as sync.Once loads it. NULL with the text of
 * SystemRootsError's cause in `err` when loadSystemRoots failed. */
const lc_gopool *lc_go_system_roots(lc_obuf *err);

/* The files loadSystemRoots reads, for test/goverify: SSL_CERT_FILE and SSL_CERT_DIR are read from
 * the environment as Go reads them; these replace the built-in lists. NULL restores them. Not
 * thread-safe, and it forgets the loaded pool. */
void lc_go_system_roots_reset(const char *const *files, const char *const *dirs);

/* loadOnDiskRoots itself, into a fresh pool: 0, or -1 with the error, or -2. */
int lc_go_load_roots(const char *cert_file, const char *cert_dir, lc_gopool **out, lc_obuf *err);

typedef struct {
    const char     *dns_name; /* DNSName; NULL or "" for none */
    size_t          dns_name_n;
    const lc_gopool *intermediates; /* NULL: none */
    const lc_gopool *roots;         /* NULL: the system's */
    int             have_time;      /* CurrentTime set; otherwise time.Now() */
    int64_t         now_sec;
    int32_t         now_nsec;
    const int      *key_usages; /* ExtKeyUsage values; none means serverAuth */
    size_t          key_usages_n;
    /* CertificatePolicies (each OID's DER contents; none means any) and the three unexported
     * policy options Go's own tests set — nothing else does, Xray included */
    const lc_gobytes *policies;
    size_t            policies_n;
    int               inhibit_policy_mapping, require_explicit_policy, inhibit_any_policy;
} lc_goverify_opts;

typedef struct {
    const lc_gocert **certs; /* leaf first; pointers into the pools and the leaf */
    size_t            n;
} lc_gochain;

typedef struct {
    lc_gochain *a;
    size_t      n;
} lc_gochains;

void lc_gochains_free(lc_gochains *c);

/* Certificate.Verify: 0 with the chains (when `chains` is not NULL), -1 with Go's error text in
 * `err`, -2 when memory ran out. */
int lc_go_verify(const lc_gocert *leaf, const lc_goverify_opts *opts, lc_gochains *chains,
                 lc_obuf *err);

/* What REALITY's VerifyPeerCertificate does after its HMAC check fails: `certs` are the peer's
 * certificates in order, already parsed; the name is the ServerName. 0 or -1 with the words. */
int lc_go_verify_peer(const lc_gocert *certs, size_t n, const char *server_name, lc_obuf *err);

#endif
