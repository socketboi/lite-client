/* A certificate as Go 1.27's x509.ParseCertificate leaves it: the fields of x509.Certificate that
 * Certificate.Verify reads (GOROOT/src/crypto/x509/verify.go), and nothing else.
 *
 * The REALITY plane's reference is Xray-core built with go1.27.1, and when a node does not know
 * this client it relays a real site's certificates, which uTLS parses (x509.ParseCertificate) and
 * REALITY's VerifyPeerCertificate then verifies as an ordinary web chain
 * (vendor/Xray-core/transport/internet/reality/reality.go:128-139). cert/x509go.c reads a
 * certificate by parser.go's rules — go1.26.6's for the QUIC plane, go1.27.1's here — and fills
 * this in when asked; cert/goverify.h is what reads it.
 *
 * Every byte view points into `raw`, the certificate's own copy of its DER, so a certificate is
 * one allocation of DER plus the lists below, and lives as long as the caller keeps it. */
#ifndef LC_GOCERT_H
#define LC_GOCERT_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    const uint8_t *p;
    size_t         n;
} lc_gobytes;

typedef struct {
    lc_gobytes *a;
    size_t      n, cap;
} lc_gobytes_list;

/* x509.PublicKeyAlgorithm (GOROOT/src/crypto/x509/x509.go:277-284). */
enum {
    LC_GO_PK_UNKNOWN = 0,
    LC_GO_PK_RSA,
    LC_GO_PK_DSA,
    LC_GO_PK_ECDSA,
    LC_GO_PK_ED25519,
    LC_GO_PK_MLDSA,
};

/* The curves namedCurveFromOID knows, and the ML-DSA parameter sets. */
enum { LC_GO_P224 = 1, LC_GO_P256, LC_GO_P384, LC_GO_P521 };
enum { LC_GO_MLDSA44 = 1, LC_GO_MLDSA65, LC_GO_MLDSA87 };

/* x509.ExtKeyUsage values, Go's numbering (x509.go:704-719). */
enum { LC_GO_EKU_ANY = 0, LC_GO_EKU_SERVER_AUTH = 1 };

/* An IP range of a name constraint: net.IPNet, 4 or 16 bytes of each. */
typedef struct {
    uint8_t ip[16], mask[16];
    size_t  len;
} lc_goipnet;

/* A URI of the SAN extension: *url.URL, as much of it as the constraint check reads — the Host,
 * and String() for the words. */
typedef struct {
    char  *host;
    size_t host_n;
    char  *string;
    size_t string_n;
} lc_gouri;

/* A PolicyMapping: two OIDs, each the DER contents of the OBJECT IDENTIFIER. */
typedef struct {
    lc_gobytes issuer, subject;
} lc_gopolicymap;

typedef struct lc_gocert_s {
    uint8_t *raw;
    size_t   raw_n;

    lc_gobytes tbs, raw_issuer, raw_subject, raw_spki;
    int64_t    version;
    lc_gobytes serial; /* the INTEGER's content octets; ParseCertificate refuses a negative one */

    int        sig_alg;   /* x509.SignatureAlgorithm, Go's numbering (cert/gosig.h) */
    uint8_t   *signature; /* BitString.RightAlign(), a copy */
    size_t     signature_n;

    int pk_alg;     /* PublicKeyAlgorithm */
    int pk_present; /* PublicKey != nil: the algorithm is known and parsePublicKey returned one */
    /* The key, as parsePublicKey read it: the right-aligned subjectPublicKey (`key`, a copy), and
     * for RSA the modulus's content octets and the exponent as a Go int; for ECDSA the curve and
     * the uncompressed point (= key); for Ed25519 and ML-DSA the key bytes (= key). */
    uint8_t   *key;
    size_t     key_n;
    lc_gobytes rsa_n;
    int64_t    rsa_e;
    int        curve, mldsa;

    /* NotBefore and NotAfter: the instant in Unix seconds, and the zone they were written in
     * (seconds east of UTC, `utc` for "Z"), which Format(time.RFC3339) prints. */
    int64_t not_before, not_after;
    int32_t not_before_off, not_after_off;
    int     not_before_utc, not_after_utc;

    /* Subject.CommonName and Subject.Organization[0], for UnknownAuthorityError's words: Go
     * strings, so a T61String is Latin-1 turned UTF-8 and a BMPString UCS-2 turned UTF-8 (copies,
     * NULL when there is none). */
    char  *subject_cn, *subject_o;
    size_t subject_cn_n, subject_o_n;

    int        has_san, has_name_constraints; /* the extension is there at all */
    lc_gobytes san_value;                     /* its value, which alreadyInChain compares */

    int      key_usage;
    int      basic_constraints_valid, is_ca;
    int64_t  max_path_len;
    int      max_path_len_zero;
    lc_gobytes subject_key_id, authority_key_id;

    int   *ext_key_usage;
    size_t ext_key_usage_n;
    size_t unknown_ext_key_usage_n;

    lc_gobytes_list dns_names, email_addresses, ip_addresses;
    lc_gouri       *uris;
    size_t          uris_n;

    lc_gobytes_list permitted_dns, excluded_dns, permitted_email, excluded_email, permitted_uri,
        excluded_uri;
    lc_goipnet *permitted_ip, *excluded_ip;
    size_t      permitted_ip_n, excluded_ip_n;

    lc_gobytes_list policies;
    lc_gopolicymap *policy_mappings;
    size_t          policy_mappings_n;
    int64_t         require_explicit_policy, inhibit_policy_mapping, inhibit_any_policy;
    int             require_explicit_policy_zero, inhibit_policy_mapping_zero, inhibit_any_policy_zero;

    size_t unhandled_critical;
} lc_gocert;

void lc_gocert_free(lc_gocert *c);

#endif
