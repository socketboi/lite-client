/* Handshake message parsing and Finished, replayed from the RFC 8448 flight.
 *
 * This is the last part of the handshake that can be checked without a server, and it is the part a
 * server rejects first when it is wrong: an unreadable ServerHello or a Finished that does not
 * verify both end the connection with nothing useful in the log.
 *
 * The server flight is walked exactly as it arrives — one buffer holding four messages back to
 * back — because that framing is the thing implementations get wrong. Records do not delimit
 * messages, message headers do. */

#include "tls/msg.h"
#include "tls/alert.h"
#include "tls/transcript.h"
#include "test_vectors.h"

#include <stdio.h>
#include <string.h>

#define SZ(a) (sizeof(a) / sizeof((a)[0]))

static int failures;

static void ok(const char *what) { printf("  ok    %s\n", what); }

static void fail(const char *what)
{
    printf("  FAIL  %s\n", what);
    failures++;
}

static void check_bytes(const char *what, const uint8_t *got, const uint8_t *want, size_t len)
{
    if (memcmp(got, want, len) == 0) {
        printf("  ok    %s (%zu bytes)\n", what, len);
        return;
    }
    printf("  FAIL  %s\n        want:", what);
    for (size_t i = 0; i < len; i++)
        printf(" %02x", want[i]);
    printf("\n        got: ");
    for (size_t i = 0; i < len; i++)
        printf(" %02x", got[i]);
    printf("\n");
    failures++;
}

/* The hello every ServerHello below answers: the session id they echo (0x40..0x5f), the suites
 * 0x1301 and 0x1302, the version range a browser parrot offers — 1.3 down to 1.2 — and one x25519
 * share. What the TLS plane's lc_sh_expect_from_hello reads out of a real hello, written down. */
static lc_sh_expect test_expect(void)
{
    static uint8_t        sid[32];
    static const uint8_t  suites[] = { 0x13u, 0x01u, 0x13u, 0x02u };
    lc_sh_expect          ex;
    memset(&ex, 0, sizeof ex);
    for (unsigned i = 0; i < 32u; i++)
        sid[i] = (uint8_t)(0x40u + i);
    ex.session_id = sid;
    ex.session_id_len = sizeof sid;
    ex.suites = suites;
    ex.suites_len = sizeof suites;
    ex.min_version = 0x0303u;
    ex.shares[0] = 0x001du;
    ex.share_count = 1u;
    return ex;
}

/* What a caller does with a ServerHello: parse, then judge. -1 either way it is refused. */
static int judge(const uint8_t *body, size_t len, lc_server_hello *sh)
{
    lc_sh_expect ex = test_expect();
    return lc_parse_server_hello(body, len, sh) != 0 ? -1 : lc_check_server_hello(sh, &ex);
}

/* ---- the verdict's order, one pair at a time ---------------------------------------------------
 *
 * Every case is a ServerHello with a fault, or two, and the alert the reference sends for it. The
 * pairs are the point: two faults whose checks send DIFFERENT alerts, so that the answer says which
 * check came first. A client with the right checks in the wrong order passes every single-fault
 * case and fails these. */
static const uint8_t v_hrr_random[32] = {
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
};
static const uint8_t X_SV13[] = { 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04 };
static const uint8_t X_SV12[] = { 0x00, 0x2b, 0x00, 0x02, 0x03, 0x03 };
static const uint8_t X_SV11[] = { 0x00, 0x2b, 0x00, 0x02, 0x03, 0x02 };
static const uint8_t X_SV15[] = { 0x00, 0x2b, 0x00, 0x02, 0x03, 0x05 };
static const uint8_t X_SV3B[] = { 0x00, 0x2b, 0x00, 0x03, 0x03, 0x04, 0x00 };
static const uint8_t X_KS[]   = { 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20,
                                  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                                  17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
static const uint8_t X_KSX[]  = { 0x00, 0x33, 0x00, 0x02, 0x00, 0x1d }; /* bare, a shared group */
static const uint8_t X_KSP[]  = { 0x00, 0x33, 0x00, 0x02, 0x00, 0x17 }; /* bare, not shared */
static const uint8_t X_KS17[] = { 0x00, 0x33, 0x00, 0x08, 0x00, 0x17, 0x00, 0x04, 1, 2, 3, 4 }; /* a share, not ours */
static const uint8_t X_PSK[]  = { 0x00, 0x29, 0x00, 0x02, 0x00, 0x00 };
static const uint8_t X_PSK3[] = { 0x00, 0x29, 0x00, 0x03, 0x00, 0x00, 0x00 };
static const uint8_t X_CK[]   = { 0x00, 0x2c, 0x00, 0x03, 0x00, 0x01, 0xaa };
static const uint8_t X_PF0[]  = { 0x00, 0x0b, 0x00, 0x01, 0x00 };       /* ec_point_formats, empty */
static const uint8_t X_PF[]   = { 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00 }; /* ec_point_formats: null */
static const uint8_t X_ECH[]  = { 0xfe, 0x0d, 0x00, 0x00 };
static const uint8_t X_EMS[]  = { 0x00, 0x17, 0x00, 0x00 };
static const uint8_t X_BAD[]  = { 0x00, 0x00, 0x00, 0x01, 0x41 };       /* server_name with a body */

typedef struct { const uint8_t *p; size_t n; } v_snip;
#define V(a) { a, sizeof a }

enum { R_ZERO, R_DG12, R_DG11, R_HRR };

typedef struct {
    const char *what;
    uint16_t    legacy;
    unsigned    random;
    int         sid_bad;
    uint16_t    suite;
    uint8_t     comp;
    v_snip      e[4];
    int         no_block;
    int         retried;
    uint16_t    min_version;
    uint8_t     want; /* 0: accepted */
} v_case;

/* What v_judge answers for a hello accepted as TLS 1.2 — the handshake goes on as hs12 does (T3) — as
 * against 0 for one accepted as TLS 1.3. No alert has this number. */
#define V_TLS12 12u

static const v_case vcases[] = {
    { "no supported_versions and 1.2 in the legacy field: TLS 1.2, and the handshake goes on as hs12 (70 until T3)",
      0x0303, R_ZERO, 0, 0x1301, 0, { V(X_KS) }, 0, 0, 0x0303, V_TLS12 },
    { "the same with the TLS 1.2 downgrade canary: illegal_parameter (47)",
      0x0303, R_DG12, 0, 0x1301, 0, { V(X_KS) }, 0, 0, 0x0303, 47 },
    { "the same with the TLS 1.1 canary: 47 as well",
      0x0303, R_DG11, 0, 0x1301, 0, { V(X_KS) }, 0, 0, 0x0303, 47 },
    { "supported_versions saying 1.2 on a first hello: TLS 1.2 (70 until T3, 47 before that)",
      0x0303, R_ZERO, 0, 0x1301, 0, { V(X_SV12), V(X_KS) }, 0, 0, 0x0303, V_TLS12 },
    { "and 1.2 with the canary: 47",
      0x0303, R_DG12, 0, 0x1301, 0, { V(X_SV12), V(X_KS) }, 0, 0, 0x0303, 47 },
    { "1.1 with the canary: 70, outside the range, so the canary is never read",
      0x0303, R_DG11, 0, 0x1301, 0, { V(X_SV11), V(X_KS) }, 0, 0, 0x0303, 70 },
    { "a version above 1.3: 70",
      0x0303, R_ZERO, 0, 0x1301, 0, { V(X_SV15), V(X_KS) }, 0, 0, 0x0303, 70 },
    { "supported_versions three bytes long does not unmarshal: 10, not the 47 it got",
      0x0303, R_ZERO, 0, 0x1301, 0, { V(X_SV3B), V(X_KS) }, 0, 0, 0x0303, 10 },
    { "0x0304 in the legacy field and no supported_versions: missing_extension (109) on a FIRST hello",
      0x0304, R_ZERO, 0, 0x1301, 0, { V(X_KS) }, 0, 0, 0x0303, 109 },
    { "no supported_versions after a retry: 109",
      0x0303, R_ZERO, 0, 0x1301, 0, { V(X_KS) }, 0, 1, 0x0303, 109 },
    { "1.2 in supported_versions after a retry: 47",
      0x0303, R_ZERO, 0, 0x1301, 0, { V(X_SV12), V(X_KS) }, 0, 1, 0x0303, 47 },
    { "on a plane pinned to 1.3, no supported_versions: 70",
      0x0303, R_ZERO, 0, 0x1301, 0, { V(X_KS) }, 0, 0, 0x0304, 70 },
    { "on a plane pinned to 1.3, 1.2 with the canary: 70, the canary out of reach",
      0x0303, R_DG12, 0, 0x1301, 0, { V(X_SV12), V(X_KS) }, 0, 0, 0x0304, 70 },
    { "a wrong legacy version AND a malformed extension after it: 10, the whole message first",
      0x0301, R_ZERO, 0, 0x1301, 0, { V(X_SV13), V(X_KS), V(X_BAD) }, 0, 0, 0x0303, 10 },
    { "a compression method AND a malformed extension after it: 10",
      0x0303, R_ZERO, 0, 0x1301, 1, { V(X_SV13), V(X_KS), V(X_BAD) }, 0, 0, 0x0303, 10 },
    { "a wrong legacy version alone: 47",
      0x0301, R_ZERO, 0, 0x1301, 0, { V(X_SV13), V(X_KS) }, 0, 0, 0x0303, 47 },
    { "a forbidden extension AND a session id that does not match: 110, the forbidden check first",
      0x0303, R_ZERO, 1, 0x1301, 0, { V(X_SV13), V(X_KS), V(X_EMS) }, 0, 0, 0x0303, 110 },
    { "pre_shared_key selected: 47",
      0x0303, R_ZERO, 0, 0x1301, 0, { V(X_SV13), V(X_KS), V(X_PSK) }, 0, 0, 0x0303, 47 },
    { "pre_shared_key of three bytes does not unmarshal: 10",
      0x0303, R_ZERO, 0, 0x1301, 0, { V(X_SV13), V(X_KS), V(X_PSK3) }, 0, 0, 0x0303, 10 },
    { "pre_shared_key AND a cookie: 110, the cookie refused first",
      0x0303, R_ZERO, 0, 0x1301, 0, { V(X_SV13), V(X_KS), V(X_PSK), V(X_CK) }, 0, 0, 0x0303, 110 },
    { "a bare group in a ServerHello: decode_error (50)",
      0x0303, R_ZERO, 0, 0x1301, 0, { V(X_SV13), V(X_KSX) }, 0, 0, 0x0303, 50 },
    { "a bare group AND a session id that does not match: 47, the session id first",
      0x0303, R_ZERO, 1, 0x1301, 0, { V(X_SV13), V(X_KSX) }, 0, 0, 0x0303, 47 },
    { "a cookie in a ServerHello: 110",
      0x0303, R_ZERO, 0, 0x1301, 0, { V(X_SV13), V(X_KS), V(X_CK) }, 0, 0, 0x0303, 110 },
    { "a cookie AND a suite not offered: 47, the suite first",
      0x0303, R_ZERO, 0, 0x1303, 0, { V(X_SV13), V(X_KS), V(X_CK) }, 0, 0, 0x0303, 47 },
    { "a cookie AND no key share: 110, the cookie first",
      0x0303, R_ZERO, 0, 0x1301, 0, { V(X_SV13), V(X_CK) }, 0, 0, 0x0303, 110 },
    { "a share for a group this hello sent none for: 47",
      0x0303, R_ZERO, 0, 0x1301, 0, { V(X_SV13), V(X_KS17) }, 0, 0, 0x0303, 47 },
    { "no key share alone: 47",
      0x0303, R_ZERO, 0, 0x1301, 0, { V(X_SV13) }, 0, 0, 0x0303, 47 },
    { "no extensions block at all: the message PARSES, and is TLS 1.2 (70 until T3)",
      0x0303, R_ZERO, 0, 0x1301, 0, { { NULL, 0 } }, 1, 0, 0x0303, V_TLS12 },
    { "ec_point_formats with an empty list does not unmarshal: 10",
      0x0303, R_ZERO, 0, 0x1301, 0, { V(X_SV13), V(X_KS), V(X_PF0) }, 0, 0, 0x0303, 10 },
    { "ec_point_formats that parses is accepted, as the reference accepts it",
      0x0303, R_ZERO, 0, 0x1301, 0, { V(X_SV13), V(X_KS), V(X_PF) }, 0, 0, 0x0303, 0 },
    { "encrypted_client_hello in an ordinary ServerHello is accepted",
      0x0303, R_ZERO, 0, 0x1301, 0, { V(X_SV13), V(X_KS), V(X_ECH) }, 0, 0, 0x0303, 0 },
    { "encrypted_client_hello in a retry: unsupported_extension (110)",
      0x0303, R_HRR, 0, 0x1301, 0, { V(X_SV13), V(X_KSP), V(X_ECH) }, 0, 0, 0x0303, 110 },
    { "a retry with a share and no cookie: 47, the changes-nothing check before the share's 50",
      0x0303, R_HRR, 0, 0x1301, 0, { V(X_SV13), V(X_KS) }, 0, 0, 0x0303, 47 },
    { "a retry with a share and a cookie: 50",
      0x0303, R_HRR, 0, 0x1301, 0, { V(X_SV13), V(X_KS), V(X_CK) }, 0, 0, 0x0303, 50 },
    { "a retry for a group already shared: 47",
      0x0303, R_HRR, 0, 0x1301, 0, { V(X_SV13), V(X_KSX) }, 0, 0, 0x0303, 47 },
    { "a retry for a group not yet shared passes the verdict",
      0x0303, R_HRR, 0, 0x1301, 0, { V(X_SV13), V(X_KSP) }, 0, 0, 0x0303, 0 },
    { "a second retry: unexpected_message (10)",
      0x0303, R_HRR, 0, 0x1301, 0, { V(X_SV13), V(X_KSP) }, 0, 1, 0x0303, 10 },
    { "a second retry with a session id that does not match: 47, checkServerHelloOrHRR first",
      0x0303, R_HRR, 1, 0x1301, 0, { V(X_SV13), V(X_KSP) }, 0, 1, 0x0303, 47 },
    { "after a retry, a suite other than the retry's: 47",
      0x0303, R_ZERO, 0, 0x1302, 0, { V(X_SV13), V(X_KS) }, 0, 1, 0x0303, 47 },
    { "a well-formed ServerHello passes",
      0x0303, R_ZERO, 0, 0x1301, 0, { V(X_SV13), V(X_KS) }, 0, 0, 0x0303, 0 },
};

static size_t v_build(const v_case *v, uint8_t *body)
{
    size_t n = 0;
    body[n++] = (uint8_t)(v->legacy >> 8);
    body[n++] = (uint8_t)v->legacy;
    if (v->random == R_HRR)
        memcpy(body + n, v_hrr_random, 32);
    else
        memset(body + n, 0x11, 32);
    if (v->random == R_DG12)
        memcpy(body + n + 24, "DOWNGRD\x01", 8);
    if (v->random == R_DG11)
        memcpy(body + n + 24, "DOWNGRD\x00", 8);
    n += 32;
    body[n++] = 32u;
    for (unsigned i = 0; i < 32u; i++)
        body[n++] = (uint8_t)(0x40u + i + (v->sid_bad && i == 31u ? 1u : 0u));
    body[n++] = (uint8_t)(v->suite >> 8);
    body[n++] = (uint8_t)v->suite;
    body[n++] = v->comp;
    if (!v->no_block) {
        size_t at = n;
        n += 2u;
        for (unsigned k = 0; k < 4u && v->e[k].p != NULL; k++) {
            memcpy(body + n, v->e[k].p, v->e[k].n);
            n += v->e[k].n;
        }
        body[at] = (uint8_t)((n - at - 2u) >> 8);
        body[at + 1u] = (uint8_t)(n - at - 2u);
    }
    return n;
}

static uint8_t v_judge(const v_case *v, int stdlib)
{
    uint8_t      body[512];
    size_t       n = v_build(v, body);
    lc_sh_expect ex = test_expect();
    ex.min_version = v->min_version;
    ex.retried = v->retried;
    ex.retry_suite = 0x1301u;
    ex.stdlib = stdlib;
    lc_server_hello sh;
    int rc = lc_parse_server_hello(body, n, &sh);
    if (rc == 0)
        rc = lc_check_server_hello(&sh, &ex);
    return rc == 0 ? (sh.tls12 ? V_TLS12 : 0u) : sh.alert;
}

static void verdict_order(void)
{
    printf("\nthe verdict, in the reference's order\n");
    for (size_t c = 0; c < SZ(vcases); c++) {
        uint8_t got = v_judge(&vcases[c], 0);
        if (got == vcases[c].want) {
            printf("  ok    %s\n", vcases[c].what);
        } else {
            printf("  FAIL  %s: got %u\n", vcases[c].what, (unsigned)got);
            failures++;
        }
    }

    /* THE ONE NUMBER THE TWO PLANES DO NOT SHARE IN HERE. uTLS answers a compression method with
     * illegal_parameter; the standard library the QUIC plane's reference is built with answers
     * decode_error (GOROOT/src/crypto/tls/handshake_client_tls13.go:199-201, go1.25.14). The same
     * message, both ways. */
    static const v_case comp = { "a compression method", 0x0303, R_ZERO, 0, 0x1301, 1,
                                 { V(X_SV13), V(X_KS) }, 0, 0, 0x0303, 0 };
    if (v_judge(&comp, 0) == LC_ALERT_ILLEGAL_PARAMETER && v_judge(&comp, 1) == LC_ALERT_DECODE_ERROR)
        ok("a compression method is illegal_parameter under uTLS and decode_error under the "
           "standard library");
    else
        fail("a compression method does not get each library's own alert");
}

/* certificateRequestMsgTLS13.unmarshal, one rule at a time — the same in uTLS and the standard
 * library, so both planes ask lc_cert_request_parses and answer with their own number. */
static void cert_request_shape(void)
{
    printf("\nthe CertificateRequest a server may send\n");
    static const struct { uint8_t b[24]; size_t n; int parses; const char *what; } c[] = {
        { { 0x00, 0x00, 0x08, 0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x08, 0x07 }, 11, 1,
          "an empty context and one signature algorithm parse" },
        { { 0x01, 0x05, 0x00, 0x00 }, 4, 0, "a non-empty request context does not" },
        { { 0x00, 0x00, 0x09, 0x00, 0x0d, 0x00, 0x05, 0x00, 0x03, 0x08, 0x07, 0x04 }, 12, 0,
          "an algorithm list of odd length does not" },
        { { 0x00, 0x00, 0x06, 0x00, 0x0d, 0x00, 0x02, 0x00, 0x00 }, 9, 0, "nor an empty one" },
        { { 0x00, 0x00, 0x04, 0x00, 0x05, 0x00, 0x00 }, 7, 1, "status_request with no body parses" },
        { { 0x00, 0x00, 0x05, 0x00, 0x05, 0x00, 0x01, 0x00 }, 8, 0, "and with a body does not" },
        { { 0x00, 0x00, 0x06, 0x00, 0x2f, 0x00, 0x02, 0x00, 0x00 }, 9, 0,
          "an empty certificate_authorities list does not" },
        { { 0x00, 0x00, 0x09, 0x00, 0x2f, 0x00, 0x05, 0x00, 0x03, 0x00, 0x01, 0x41 }, 12, 1,
          "one with a name in it does" },
        { { 0x00, 0x00, 0x00, 0x00 }, 4, 0, "bytes after the extension block do not" },
        { { 0x00, 0x00, 0x05, 0x7a, 0x7a, 0x00, 0x01, 0x00 }, 8, 1, "an unknown extension is stepped over" },
    };
    for (size_t i = 0; i < SZ(c); i++) {
        if (lc_cert_request_parses(c[i].b, c[i].n) == c[i].parses)
            ok(c[i].what);
        else
            fail(c[i].what);
    }
}

int main(void)
{
    printf("RFC 8448 handshake messages\n");

    /* ---- ServerHello ---- */
    {
        lc_msg_reader r;
        lc_msg_reader_init(&r, srv_record_1_payload, SZ(srv_record_1_payload));

        uint8_t        type = 0;
        const uint8_t *body = NULL, *whole = NULL;
        size_t         body_len = 0, whole_len = 0;

        if (lc_msg_next(&r, &type, &body, &body_len, &whole, &whole_len) != 1 ||
            type != LC_HS_SERVER_HELLO) {
            fail("ServerHello does not parse as a handshake message");
            return 1;
        }
        ok("ServerHello framed correctly");

        lc_server_hello sh;
        if (lc_parse_server_hello(body, body_len, &sh) != 0) {
            fail("ServerHello body does not parse");
        } else {
            if (sh.is_hello_retry)
                fail("ServerHello mistaken for a HelloRetryRequest");
            else
                ok("not a HelloRetryRequest");

            if (sh.cipher_suite != 0x1301u)
                fail("cipher suite is not TLS_AES_128_GCM_SHA256");
            else
                ok("cipher suite TLS_AES_128_GCM_SHA256");

            if (sh.group != 0x001du)
                fail("selected group is not x25519");
            else
                ok("selected group x25519");

            if (sh.key_share_len != SZ(srv_x25519_public_key))
                fail("key share has the wrong length");
            else
                check_bytes("server key share", sh.key_share,
                            srv_x25519_public_key, SZ(srv_x25519_public_key));
        }

        if (lc_msg_next(&r, &type, &body, &body_len, &whole, &whole_len) != 0)
            fail("something follows ServerHello in its record");
        else
            ok("ServerHello is the only message in its record");
    }

    /* ---- the encrypted flight: four messages in one buffer ---- */
    {
        static const uint8_t expect[] = {
            LC_HS_ENCRYPTED_EXT, LC_HS_CERTIFICATE, LC_HS_CERTIFICATE_VERIFY, LC_HS_FINISHED
        };
        lc_msg_reader r;
        lc_msg_reader_init(&r, srv_record_2_payload, SZ(srv_record_2_payload));

        size_t         seen = 0;
        uint8_t        type = 0;
        const uint8_t *body = NULL, *whole = NULL;
        size_t         body_len = 0, whole_len = 0;
        const uint8_t *finished_body = NULL;
        size_t         finished_len = 0;

        /* The transcript stops just before Finished: verify_data authenticates everything up to
         * but not including the message carrying it. Getting that boundary wrong is the classic
         * way to produce a Finished that never verifies. */
        lc_transcript t;
        if (lc_transcript_init(&t, LC_SHA256) != 0) {
            fail("cannot start a transcript");
            return 1;
        }
        lc_transcript_add(&t, cli_record_1_payload, SZ(cli_record_1_payload));
        lc_transcript_add(&t, srv_record_1_payload, SZ(srv_record_1_payload));

        uint8_t transcript_before_finished[LC_HASH_MAX];
        int     have_boundary = 0;

        int rc;
        while ((rc = lc_msg_next(&r, &type, &body, &body_len, &whole, &whole_len)) == 1) {
            if (seen < SZ(expect) && type != expect[seen]) {
                printf("  FAIL  message %zu is type %02x, expected %02x\n", seen, type, expect[seen]);
                failures++;
            }
            if (type == LC_HS_FINISHED) {
                lc_transcript_snapshot(&t, transcript_before_finished);
                have_boundary = 1;
                finished_body = body;
                finished_len = body_len;
            }
            lc_transcript_add(&t, whole, whole_len);
            seen++;
        }
        if (rc != 0)
            fail("the flight does not walk cleanly to its end");
        else if (seen != SZ(expect)) {
            /* Through fail(), so that it is counted: a FAIL printed beside the tally is one the
             * summary line and the exit code never hear of. */
            char line[80];
            snprintf(line, sizeof line, "%zu messages in the flight, expected %zu", seen, SZ(expect));
            fail(line);
        } else
            ok("four messages walked in order: EncryptedExtensions, Certificate, CertificateVerify, Finished");

        /* ---- Finished ---- */
        if (have_boundary && finished_body != NULL) {
            uint8_t vd[LC_HASH_MAX];
            if (lc_finished_verify_data(LC_SHA256, srv_derive_s_hs_traffic_expanded,
                                        transcript_before_finished, vd) != 0) {
                fail("computing verify_data returned an error");
            } else {
                check_bytes("server verify_data", vd,
                            srv_finished_finished, SZ(srv_finished_finished));
                check_bytes("verify_data equals the Finished body", finished_body,
                            srv_finished_finished, SZ(srv_finished_finished));
            }

            if (lc_finished_check(LC_SHA256, srv_derive_s_hs_traffic_expanded,
                                  transcript_before_finished, finished_body, finished_len) != 0)
                fail("the server Finished does not verify");
            else
                ok("server Finished verifies");

            /* A tampered Finished must not verify. Without this the check could be returning
             * success unconditionally and everything above would still pass. */
            uint8_t bad[LC_HASH_MAX];
            memcpy(bad, finished_body, finished_len);
            bad[0] ^= 0x01u;
            if (lc_finished_check(LC_SHA256, srv_derive_s_hs_traffic_expanded,
                                  transcript_before_finished, bad, finished_len) == 0)
                fail("a tampered Finished still verified");
            else
                ok("tampered Finished rejected");
        }
        lc_transcript_free(&t);
    }

    /* ---- the client's own Finished ---- */
    {
        lc_transcript t;
        if (lc_transcript_init(&t, LC_SHA256) == 0) {
            lc_transcript_add(&t, cli_record_1_payload, SZ(cli_record_1_payload));
            lc_transcript_add(&t, srv_record_1_payload, SZ(srv_record_1_payload));
            lc_transcript_add(&t, srv_record_2_payload, SZ(srv_record_2_payload));

            uint8_t th[LC_HASH_MAX], vd[LC_HASH_MAX];
            lc_transcript_snapshot(&t, th);
            if (lc_finished_verify_data(LC_SHA256, srv_derive_c_hs_traffic_expanded, th, vd) != 0)
                fail("computing the client verify_data returned an error");
            else
                check_bytes("client verify_data", vd, cli_finished_finished, SZ(cli_finished_finished));
            lc_transcript_free(&t);
        }
    }

    /* ---- malformed input must not be accepted ---- */
    {
        static const uint8_t truncated[] = { 0x02, 0x00, 0x00, 0x56, 0x03 };
        lc_msg_reader        r;
        uint8_t              type = 0;
        const uint8_t       *body = NULL, *whole = NULL;
        size_t               body_len = 0, whole_len = 0;

        lc_msg_reader_init(&r, truncated, sizeof truncated);
        if (lc_msg_next(&r, &type, &body, &body_len, &whole, &whole_len) != -1)
            fail("a message shorter than its own length was accepted");
        else
            ok("truncated message rejected");

        lc_server_hello sh;
        if (lc_parse_server_hello(srv_record_1_payload + 4u, 8u, &sh) == 0)
            fail("a truncated ServerHello was accepted");
        else
            ok("truncated ServerHello rejected");
    }

    /* ---- what the reference refuses in a ServerHello, and this parser stepped over ----
     *
     * Every case below is one line of checkServerHelloOrHRR
     * (vendor/utls/handshake_client_tls13.go:185-232) or of serverHelloMsg.unmarshal
     * (vendor/utls/handshake_messages.go:931-943). They are here because the parser used to accept
     * all of them, and because accepting them is not a strength question — it is this client
     * tolerating messages a Go peer has already answered with an alert, which is a way to tell the
     * two apart by sending one.
     *
     * The hello is built rather than mutated from the RFC vector, so that each case differs from a
     * message that PARSES in exactly the one way it is about. */
    {
        printf("\nServerHello fields the reference refuses\n");

        /* Big enough for the unbounded-repeat case below, which needs sixty-five distinct
         * extensions before it can say anything about the sixty-fifth. */
        static uint8_t body[1024];
        static uint8_t ext[768];

        size_t ext_len = 0;
        /* supported_versions = 0x0304 */
        ext[ext_len++] = 0x00u; ext[ext_len++] = 0x2bu;
        ext[ext_len++] = 0x00u; ext[ext_len++] = 0x02u;
        ext[ext_len++] = 0x03u; ext[ext_len++] = 0x04u;
        /* key_share: x25519 with a 32-byte share */
        ext[ext_len++] = 0x00u; ext[ext_len++] = 0x33u;
        ext[ext_len++] = 0x00u; ext[ext_len++] = 0x24u;
        ext[ext_len++] = 0x00u; ext[ext_len++] = 0x1du;
        ext[ext_len++] = 0x00u; ext[ext_len++] = 0x20u;
        for (unsigned i = 0; i < 32u; i++)
            ext[ext_len++] = (uint8_t)(0xa0u + i);
        size_t base_ext_len = ext_len;

        size_t len = 0;
        /* Assembles body[] from the current ext[0..el). */
        size_t el = base_ext_len;
        #define BUILD_BODY()                                                                       \
            do {                                                                                   \
                len = 0;                                                                           \
                body[len++] = 0x03u; body[len++] = 0x03u;                                          \
                for (unsigned i_ = 0; i_ < 32u; i_++) body[len++] = (uint8_t)i_;                   \
                body[len++] = 0x20u;                                                               \
                for (unsigned i_ = 0; i_ < 32u; i_++) body[len++] = (uint8_t)(0x40u + i_);         \
                body[len++] = 0x13u; body[len++] = 0x01u;                                          \
                body[len++] = 0x00u;                                                               \
                body[len++] = (uint8_t)(el >> 8); body[len++] = (uint8_t)(el & 0xffu);             \
                memcpy(body + len, ext, el); len += el;                                            \
            } while (0)

        lc_server_hello sh;

        BUILD_BODY();
        if (judge(body, len, &sh) != 0)
            fail("the built ServerHello does not parse, so nothing below proves anything");
        else if (sh.session_id_len != 32u || sh.session_id[0] != 0x40u)
            fail("the session id is not handed back to the caller");
        else
            ok("a well-formed ServerHello parses and yields its session id");

        /* `if hs.serverHello.vers != VersionTLS12` (:197-200). */
        BUILD_BODY();
        body[1] = 0x04u;
        if (judge(body, len, &sh) == 0)
            fail("a legacy_version other than 0x0303 was accepted");
        else
            ok("legacy_version must be 0x0303, as the reference requires");

        /* `if hs.serverHello.compressionMethod != compressionNone` (:215-218). */
        BUILD_BODY();
        body[2u + 32u + 1u + 32u + 2u] = 0x01u;
        if (judge(body, len, &sh) == 0)
            fail("a non-null legacy_compression_method was accepted");
        else
            ok("legacy_compression_method must be null");

        /* `if seenExts[extension] { return false }` (utls/handshake_messages.go:940-943). The repeat is
         * a second supported_versions, which on the old parser simply won. */
        el = base_ext_len;
        ext[el++] = 0x00u; ext[el++] = 0x2bu;
        ext[el++] = 0x00u; ext[el++] = 0x02u;
        ext[el++] = 0x03u; ext[el++] = 0x04u;
        BUILD_BODY();
        if (judge(body, len, &sh) == 0)
            fail("a repeated extension was accepted, last one winning");
        else
            ok("a repeated extension refuses the whole message");

        /* ⚠️ AND THE REFUSAL HAS NO CEILING, which is the half a bounded table cannot assert.
         *
         * The reference keeps a map — `if seenExts[extension] { return false }`
         * (vendor/utls/handshake_messages.go:931-943) — so a repeat is refused wherever it sits in
         * the list. This parser used to keep sixty-four entries and stop recording past that, which
         * refuses a repeat among the first sixty-four and ACCEPTS one past it: bounded, then
         * lenient, on the first message a server sends.
         *
         * So the repeat here is deliberately out of that reach. Sixty-three padded identifiers plus
         * the two the base set carries make the last padded one the SIXTY-FIFTH distinct — one past
         * the old table, where nothing was recorded and the second copy therefore won. The case
         * above cannot catch this: its repeat is the third extension. */
        el = base_ext_len;
        for (unsigned i = 0; i < 63u; i++) {
            uint16_t id = (uint16_t)(0x8000u + i); /* private use: neither read here nor forbidden */
            ext[el++] = (uint8_t)(id >> 8);
            ext[el++] = (uint8_t)(id & 0xffu);
            ext[el++] = 0x00u;
            ext[el++] = 0x00u;
        }
        ext[el++] = 0x80u; /* 0x803e again — the sixty-fifth distinct, repeated */
        ext[el++] = 0x3eu;
        ext[el++] = 0x00u;
        ext[el++] = 0x00u;
        BUILD_BODY();
        if (judge(body, len, &sh) == 0)
            fail("a repeat past the sixty-fourth distinct extension was accepted");
        else
            ok("a repeated extension is refused however far down the list it sits");

        /* The six forbidden in a TLS 1.3 ServerHello (:201-211), each on its own so that a parser
         * naming five of them fails here rather than in the field. */
        static const struct { uint16_t id; const char *name; } forbidden[] = {
            { 0x0005u, "status_request" }, { 0x0010u, "application_layer_protocol_negotiation" },
            { 0x0012u, "signed_certificate_timestamp" }, { 0x0017u, "extended_master_secret" },
            { 0x0023u, "session_ticket" }, { 0xff01u, "renegotiation_info" },
        };
        for (unsigned f = 0; f < sizeof forbidden / sizeof forbidden[0]; f++) {
            el = base_ext_len;
            ext[el++] = (uint8_t)(forbidden[f].id >> 8);
            ext[el++] = (uint8_t)(forbidden[f].id & 0xffu);
            ext[el++] = 0x00u; ext[el++] = 0x00u;
            BUILD_BODY();
            if (judge(body, len, &sh) == 0) {
                printf("  FAIL  %s is forbidden in a TLS 1.3 ServerHello and was accepted\n",
                       forbidden[f].name);
                failures++;
            } else {
                printf("  ok    %s refuses the message, as it does the reference's\n",
                       forbidden[f].name);
            }
        }
        #undef BUILD_BODY
    }

    verdict_order();
    cert_request_shape();

    printf("\n%s\n", failures == 0 ? "handshake messages match RFC 8448" : "HANDSHAKE PARSING IS WRONG");
    return failures == 0 ? 0 : 1;
}
