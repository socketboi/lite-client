/* Who the Hysteria2 node is.
 *
 * Two halves, and each is worthless alone. The pin is SHA-256 over the leaf certificate as it
 * arrived, compared with a value the operator supplied out of band — it says WHICH key the peer must
 * hold. CertificateVerify is a signature over the transcript with that certificate's private key —
 * it says the peer HAS it. There is no chain to validate here and deliberately so: this client
 * already knows the key it expects, which is a different question from which authority vouches for a
 * name. Until both existed, a completed handshake proved only that the peer could perform an X25519
 * exchange — something any party carrying the packets can do — and the client would then send the
 * node's password to whoever that was.
 *
 * What is pinned here is the decision, not the digest: that a match is accepted, that a single wrong
 * bit is refused, and above all that a flight with no certificate in it is refused rather than
 * treated as unpinned. That last one matters most, because it is the check handed back to the party
 * it is aimed at — a peer that simply omits the message must not thereby escape it.
 *
 * SHA-256 itself is not re-proved here; the key-schedule tests already pin mbedTLS's digest against
 * the RFC vectors. This test computes the expected value with the same function the check uses, so
 * it deliberately says nothing about the hash and everything about the branch.
 *
 * White box, like test/hsframe: the check is internal to the module that must not complete a
 * handshake without it. */

#include "quic/qtls.c"

#include "test_vectors.h"
#include "reference_misplaced.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <mbedtls/rsa.h>

static int failures;

static void expect(int cond, const char *what)
{
    if (cond) {
        printf("  ok    %s\n", what);
        return;
    }
    printf("  FAIL  %s\n", what);
    failures++;
}

/* A stand-in for the certificate the node presented. Its contents are irrelevant to the check — only
 * that the digest is taken over exactly these bytes.
 *
 * `cert_verified` is set because these cases are about the comparison. The check that the signature
 * was verified at all is its own case below: a pin over a certificate nobody proved they hold
 * compares public bytes, which anyone who has spoken to the node once can replay. */
static void put_cert(lc_qtls *q, size_t len)
{
    memset(q, 0, sizeof *q);
    /* On the heap, as the client keeps it: the field is a pointer sized to the leaf. */
    q->cert_der = malloc(len ? len : 1u);
    if (q->cert_der == NULL)
        return;
    for (size_t i = 0; i < len; i++)
        q->cert_der[i] = (uint8_t)(i * 7u + 1u);
    q->cert_der_len = len;
    q->cert_seen = 1;
    q->cert_verified = 1;
}

/* The private key of the certificate in the trace. RFC 8448 section 2 prints it precisely so that
 * implementations can produce signatures the document does not contain, and two of the cases below
 * need exactly that: a signature that is genuine, that mbedTLS accepts, and that TLS 1.3 still
 * forbids. Two primes and the public exponent are enough for mbedTLS to rebuild the rest, and the
 * case that follows proves the rebuild is the certificate's own key rather than trusting these
 * bytes to have been copied correctly. */
static const uint8_t rfc8448_prime1[] = {
    0xe4, 0x35, 0xfb, 0x7c, 0xc8, 0x37, 0x37, 0x75, 0x6d, 0xac, 0xea, 0x96, 0xab, 0x7f, 0x59, 0xa2,
    0xcc, 0x10, 0x69, 0xdb, 0x7d, 0xeb, 0x19, 0x0e, 0x17, 0xe3, 0x3a, 0x53, 0x2b, 0x27, 0x3f, 0x30,
    0xa3, 0x27, 0xaa, 0x0a, 0xaa, 0xbc, 0x58, 0xcd, 0x67, 0x46, 0x6a, 0xf9, 0x84, 0x5f, 0xad, 0xc6,
    0x75, 0xfe, 0x09, 0x4a, 0xf9, 0x2c, 0x4b, 0xd1, 0xf2, 0xc1, 0xbc, 0x33, 0xdd, 0x2e, 0x05, 0x15
};
static const uint8_t rfc8448_prime2[] = {
    0xca, 0xbd, 0x3b, 0xc0, 0xe0, 0x43, 0x86, 0x64, 0xc8, 0xd4, 0xcc, 0x9f, 0x99, 0x97, 0x7a, 0x94,
    0xd9, 0xbb, 0xfe, 0xad, 0x8e, 0x43, 0x87, 0x0a, 0xba, 0xe3, 0xf7, 0xeb, 0x8b, 0x4e, 0x0e, 0xee,
    0x8a, 0xf1, 0xd9, 0xb4, 0x71, 0x9b, 0xa6, 0x19, 0x6c, 0xf2, 0xcb, 0xba, 0xee, 0xeb, 0xf8, 0xb3,
    0x49, 0x0a, 0xfe, 0x9e, 0x9f, 0xfa, 0x74, 0xa8, 0x8a, 0xa5, 0x1f, 0xc6, 0x45, 0x62, 0x93, 0x03
};
static const uint8_t rfc8448_e[] = { 0x01, 0x00, 0x01 };

/* Its modulus is a thousand and twenty-four bits, so every signature it makes is this long. */
#define RFC8448_SIG 128u

static int rng(void *ctx, unsigned char *out, size_t len)
{
    (void)ctx;
    return lc_rnd(out, len) == 0 ? 0 : -1;
}

/* What RFC 8446 4.4.3 says is signed: sixty-four spaces, the context string, the zero byte that is
 * a separator and not a C terminator, then the transcript hash. Rebuilt here because these cases
 * sign it themselves — if it disagreed with the construction inside check_cert_verify by one byte,
 * the two refusals below would happen for that reason instead of the one they claim, which is why
 * a signature made this way and salted correctly is checked to be ACCEPTED first. */
static int signed_digest(const uint8_t *th, size_t th_len, uint8_t *out)
{
    static const char ctx_str[] = "TLS 1.3, server CertificateVerify";
    uint8_t           content[64u + sizeof ctx_str + LC_HASH_MAX];
    memset(content, 0x20, 64u);
    memcpy(content + 64u, ctx_str, sizeof ctx_str);
    memcpy(content + 64u + sizeof ctx_str, th, th_len);
    return mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), content,
                      64u + sizeof ctx_str + th_len, out);
}

/* A CertificateVerify body: the scheme, the length, the signature. */
static size_t put_cv(uint8_t *out, uint16_t scheme, const uint8_t *sig, size_t sig_len)
{
    out[0] = (uint8_t)(scheme >> 8);
    out[1] = (uint8_t)scheme;
    out[2] = (uint8_t)(sig_len >> 8);
    out[3] = (uint8_t)sig_len;
    memcpy(out + 4, sig, sig_len);
    return 4u + sig_len;
}

/* A sink for the one case that starts a real handshake. What it emits is test/hello's subject; what
 * is wanted here is the state lc_qtls_start leaves behind — and, since the list of suites offered is
 * decided nowhere else and read by nothing else, the bytes themselves. */
static uint8_t sink_hello[4096];
static size_t  sink_hello_len;

static int sink_send(void *ctx, lc_qtls_level level, const uint8_t *data, size_t len)
{
    (void)ctx;
    if (level == LC_QTLS_INITIAL && len <= sizeof sink_hello) {
        memcpy(sink_hello, data, len);
        sink_hello_len = len;
    }
    return level == LC_QTLS_INITIAL && len > 4u ? 0 : -1;
}

/* Every message handed to the sink, in order, for the case that asks what finish() sends. */
static uint8_t       sent_msg[4][64];
static size_t        sent_len[4];
static lc_qtls_level sent_level[4];
static unsigned      sent_count;

static int sent_capture(void *ctx, lc_qtls_level level, const uint8_t *data, size_t len)
{
    (void)ctx;
    if (sent_count < 4u) {
        size_t n = len < sizeof sent_msg[0] ? len : sizeof sent_msg[0];
        memcpy(sent_msg[sent_count], data, n);
        sent_len[sent_count] = len;
        sent_level[sent_count] = level;
        sent_count++;
    }
    return 0;
}

/* Where the cipher-suite list starts in a ClientHello, and how long it is. Walks the message rather
 * than assuming an offset, because the field before it is variable: handshake header 4, legacy
 * version 2, random 32, then a one-byte session_id length. Returns 0 if the message is too short to
 * hold what it claims, so a malformed hello reads as "no suites" instead of running off the end. */
static size_t suites_at(const uint8_t *hello, size_t len, size_t *count)
{
    size_t at = 4u + 2u + 32u;
    *count    = 0;
    if (len < at + 1u)
        return 0;
    at += 1u + hello[at];
    if (len < at + 2u)
        return 0;
    size_t bytes = ((size_t)hello[at] << 8) | hello[at + 1u];
    if (bytes % 2u != 0u || len < at + 2u + bytes)
        return 0;
    *count = bytes / 2u;
    return at + 2u;
}

static int sink_secret(void *ctx, lc_qtls_level level, const uint8_t *secret, size_t len)
{
    (void)ctx;
    (void)level;
    (void)secret;
    (void)len;
    return 0;
}

/* How many bytes the greased transport parameter occupies at the head of `mem`, or 0 if what stands
 * there is not one.
 *
 * The identifier is `27 + 31k` for some byte k — the whole of what quic-go can emit
 * (vendor/quic-go/internal/wire/transport_parameters.go:372-378) — and the body is at most fifteen
 * bytes, because the length there is a random byte modulo sixteen. Both are checked, so that every
 * case using this proves the entry is present AND well formed rather than merely stepping over
 * whatever happens to be first. */
static size_t grease_len(const uint8_t *mem, size_t len)
{
    if (len < 2u)
        return 0;

    const uint8_t *p = mem;
    uint64_t       id;
    /* One or two bytes of varint, which is all an identifier below 7933 can need. */
    if ((p[0] & 0xc0u) == 0) {
        id = p[0];
        p += 1;
    } else {
        if (len < 3u)
            return 0;
        id = ((uint64_t)(p[0] & 0x3fu) << 8) | p[1];
        p += 2;
    }
    uint64_t blen = *p++;

    if (id < 27u || (id - 27u) % 31u != 0u || (id - 27u) / 31u > 255u || blen > 15u)
        return 0;
    size_t n = (size_t)(p - mem) + (size_t)blen;
    return n <= len ? n : 0;
}

/* A HelloRetryRequest, or a ServerHello answering a retried hello, as a server writes one: legacy
 * version 0x0303, the random (the retry's fixed one when `retry`), an empty session id — this
 * plane's hello sends none — the suite, no compression, supported_versions 1.3, then key_share: a
 * bare group when `share` is NULL and `group` is set, the full form otherwise; a cookie when one is
 * given; and encrypted_client_hello when `ech`. */
static const uint8_t hrr_random[32] = { 0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
                                        0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
                                        0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
                                        0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c };

static size_t put_sh(uint8_t *out, int retry, uint16_t suite, uint16_t group, const uint8_t *share,
                     size_t share_len, const uint8_t *cookie, size_t cookie_len, int ech)
{
    size_t i = 4;
    out[0] = LC_HS_SERVER_HELLO;
    out[i++] = 0x03;
    out[i++] = 0x03;
    for (size_t k = 0; k < 32u; k++)
        out[i++] = retry ? hrr_random[k] : (uint8_t)(0x40u + k);
    out[i++] = 0x00; /* legacy_session_id_echo */
    out[i++] = (uint8_t)(suite >> 8);
    out[i++] = (uint8_t)suite;
    out[i++] = 0x00; /* legacy_compression_method */
    size_t exts = i;
    i += 2u;
    out[i++] = 0x00, out[i++] = 0x2b, out[i++] = 0x00, out[i++] = 0x02, out[i++] = 0x03,
    out[i++] = 0x04;
    if (group != 0u) {
        out[i++] = 0x00;
        out[i++] = 0x33;
        if (share == NULL) {
            out[i++] = 0x00, out[i++] = 0x02;
            out[i++] = (uint8_t)(group >> 8), out[i++] = (uint8_t)group;
        } else {
            out[i++] = (uint8_t)((share_len + 4u) >> 8), out[i++] = (uint8_t)(share_len + 4u);
            out[i++] = (uint8_t)(group >> 8), out[i++] = (uint8_t)group;
            out[i++] = (uint8_t)(share_len >> 8), out[i++] = (uint8_t)share_len;
            memcpy(out + i, share, share_len);
            i += share_len;
        }
    }
    if (cookie != NULL) {
        out[i++] = 0x00, out[i++] = 0x2c;
        out[i++] = (uint8_t)((cookie_len + 2u) >> 8), out[i++] = (uint8_t)(cookie_len + 2u);
        out[i++] = (uint8_t)(cookie_len >> 8), out[i++] = (uint8_t)cookie_len;
        memcpy(out + i, cookie, cookie_len);
        i += cookie_len;
    }
    if (ech) {
        out[i++] = 0xfe, out[i++] = 0x0d, out[i++] = 0x00, out[i++] = 0x08;
        memset(out + i, 0x5a, 8);
        i += 8u;
    }
    out[exts] = (uint8_t)((i - exts - 2u) >> 8);
    out[exts + 1u] = (uint8_t)(i - exts - 2u);
    out[1] = (uint8_t)((i - 4u) >> 16);
    out[2] = (uint8_t)((i - 4u) >> 8);
    out[3] = (uint8_t)(i - 4u);
    return i;
}

/* Where extension `type` starts in a ClientHello (at its type bytes), and 0 when it is absent. */
static size_t ch_ext(const uint8_t *h, size_t len, uint16_t type, size_t *exts_at)
{
    size_t at = 4u + 2u + 32u;
    at += 1u + h[at];
    at += 2u + ((size_t)h[at] << 8 | h[at + 1u]);
    at += 1u + h[at];
    *exts_at = at;
    at += 2u;
    while (at + 4u <= len) {
        uint16_t t = (uint16_t)(h[at] << 8 | h[at + 1u]);
        size_t   l = (size_t)h[at + 2u] << 8 | h[at + 3u];
        if (t == type)
            return at;
        at += 4u + l;
    }
    return 0;
}

int main(void)
{
    printf("\nthe node against its pin\n\n");

    static lc_qtls q;
    uint8_t        digest[LC_HASH_MAX];

    /* The hash the client will actually use, asked of the same table lc_qtls_start asks. Every case
     * driving the state machine below used to name LC_SHA256 outright, and that is not a failure
     * this test would report — it is one it would stop looking for: change LC_QTLS_SUITE to 0x1302
     * and the client moves to SHA-384 as one piece while these cases keep proving a configuration
     * that no longer exists, green throughout. */
    lc_hash hash = LC_SHA256;
    expect(lc_tls_suite_params(LC_QTLS_SUITE, NULL, &hash, NULL) == 0,
           "the one suite this client offers resolves in the suite table");

    /* The pin itself is SHA-256 whatever the suite is: it is a digest of the leaf, defined by
     * Hysteria2's pinSHA256 and by what `openssl x509 -outform der | sha256sum` prints, and has
     * nothing to do with the key schedule. So this one is named, not looked up. */
    put_cert(&q, 900u);
    if (lc_hash_digest(LC_SHA256, q.cert_der, q.cert_der_len, digest) != 0) {
        printf("  FAIL  cannot digest the certificate\n");
        return 1;
    }

    memcpy(q.pin, digest, LC_QTLS_PIN);
    q.have_pin = 1;
    expect(check_pin(&q) == 0, "the certificate the node presented matches its pin");
    expect(q.peer_pinned == 1, "and the connection is marked as one that proved who it reached");

    /* One bit, in the last byte — the place a comparison that stops early is least likely to look
     * at, and the reason the comparison folds every byte before it branches. */
    put_cert(&q, 900u);
    memcpy(q.pin, digest, LC_QTLS_PIN);
    q.have_pin = 1;
    q.pin[LC_QTLS_PIN - 1u] ^= 0x01u;
    expect(check_pin(&q) != 0, "a pin differing in a single bit of its last byte is refused");
    expect(q.peer_pinned == 0, "and nothing marks that connection as authenticated");

    /* The same certificate, one byte longer. A digest taken over the wrong length would still be a
     * digest, and would still match nothing — but this is the case where a length kept separately
     * from the bytes goes wrong quietly. */
    put_cert(&q, 901u);
    memcpy(q.pin, digest, LC_QTLS_PIN);
    q.have_pin = 1;
    expect(check_pin(&q) != 0, "a certificate one byte longer than the pinned one is refused");

    /* The attack the check exists to stop: answer the flight without a Certificate at all and hope
     * the client treats "nothing to compare" as "nothing to object to". */
    memset(&q, 0, sizeof q);
    memcpy(q.pin, digest, LC_QTLS_PIN);
    q.have_pin = 1;
    expect(check_pin(&q) != 0, "a flight carrying no certificate is refused, not waved through");

    put_cert(&q, 0u);
    q.cert_seen = 1;
    memcpy(q.pin, digest, LC_QTLS_PIN);
    q.have_pin = 1;
    expect(check_pin(&q) != 0, "and neither is an empty one");

    /* The case the pin was worth nothing without. A certificate is public: whoever has connected to
     * the node once holds a copy and can present it verbatim. Only CertificateVerify — a signature
     * over the transcript with that certificate's private key — ties it to this session, so a
     * matching digest without one must not pass. */
    put_cert(&q, 900u);
    memcpy(q.pin, digest, LC_QTLS_PIN);
    q.have_pin = 1;
    q.cert_verified = 0;
    expect(check_pin(&q) != 0,
           "a matching certificate whose signature was never verified is refused");
    expect(q.peer_pinned == 0, "and a replayed certificate cannot mark a connection authenticated");

    /* And the signature itself, against RFC 8448 section 3 — a real server flight this repository
     * did not produce: its certificate, its CertificateVerify, and every message the signed
     * transcript is made of.
     *
     * This is the case that had to come from outside. The construction being checked is sixty-four
     * spaces, a context string, ONE ZERO BYTE, and the transcript hash, and the zero is the byte
     * that looks like a C string terminator and is not. Written without it, the check refused every
     * genuine server on earth — and a test that signed its own fixture with the same code would
     * have agreed with it, twice, and said nothing. */
    {
        static lc_qtls v;
        memset(&v, 0, sizeof v);
        v.hash = LC_SHA256;

        const uint8_t *der = NULL;
        size_t         der_len = 0;
        int            got_cert = lc_cert_first_from_message(srv_msg_certificate + 4,
                                                             sizeof srv_msg_certificate - 4u,
                                                             &der, &der_len) == 0;
        expect(got_cert, "the leaf comes out of the trace's Certificate message");
        if (got_cert) {
            v.cert_der = malloc(der_len ? der_len : 1u);
            if (v.cert_der != NULL) {
                memcpy(v.cert_der, der, der_len);
                v.cert_der_len = der_len;
                v.cert_seen = 1;
            }
        }

        /* Everything the server hashed before it signed: its own flight up to but not including
         * CertificateVerify, on top of the ClientHello. */
        lc_transcript tr;
        uint8_t       th[LC_HASH_MAX];
        int           built = lc_transcript_init(&tr, LC_SHA256) == 0 &&
                    lc_transcript_add(&tr, cli_msg_clienthello, sizeof cli_msg_clienthello) == 0 &&
                    lc_transcript_add(&tr, srv_msg_serverhello, sizeof srv_msg_serverhello) == 0 &&
                    lc_transcript_add(&tr, srv_msg_encryptedextensions,
                                      sizeof srv_msg_encryptedextensions) == 0 &&
                    lc_transcript_add(&tr, srv_msg_certificate, sizeof srv_msg_certificate) == 0 &&
                    lc_transcript_snapshot(&tr, th) == 0;
        expect(built, "and the transcript it signed is rebuilt from the messages before it");

        const uint8_t *cv = srv_msg_certificateverify + 4;
        size_t         cv_len = sizeof srv_msg_certificateverify - 4u;

        expect(check_cert_verify(&v, cv, cv_len, th) == 0,
               "a real server's CertificateVerify verifies against its certificate");
        expect(v.cert_verified == 1, "and only that marks the certificate as one the peer holds");

        /* Each of the three things the check is made of, broken one at a time. */
        uint8_t bad[sizeof srv_msg_certificateverify];
        memcpy(bad, srv_msg_certificateverify, sizeof bad);
        bad[sizeof bad - 1u] ^= 0x01u;
        v.cert_verified = 0;
        expect(check_cert_verify(&v, bad + 4, cv_len, th) != 0,
               "a signature differing in one bit is refused");

        uint8_t th_bad[LC_HASH_MAX];
        memcpy(th_bad, th, sizeof th_bad);
        th_bad[0] ^= 0x01u;
        expect(check_cert_verify(&v, cv, cv_len, th_bad) != 0,
               "so is the same signature over a transcript one bit different");

        /* The scheme is the first two bytes of the body, which are bad[4] and bad[5]: writing only
         * the first left 0x0404, a code that exists in no registry, and the case proved that an
         * unknown scheme is refused while its name said PKCS#1. rsa_pkcs1_sha256 is 0x0401. */
        memcpy(bad, srv_msg_certificateverify, sizeof bad);
        bad[4] = 0x04u;
        bad[5] = 0x01u;
        expect(check_cert_verify(&v, bad + 4, cv_len, th) != 0,
               "and a PKCS#1 v1.5 scheme is refused however well it verifies");
        expect(v.cert_verified == 0, "none of which ever set the flag the pin depends on");

        /* THE TWO THINGS A SIGNATURE THAT REALLY VERIFIES CAN STILL BE WRONG ABOUT.
         *
         * Every case above breaks the signature, the transcript or the scheme code, so it would be
         * refused by a check that never looked at the key type or the salt length. These two would
         * not: the signatures are made with the certificate's own private key and mbedTLS accepts
         * both of them. What refuses them is the binding of the scheme to the key type, and TLS
         * 1.3's fixed salt length, and nothing else in this file. */
        mbedtls_pk_context priv;
        mbedtls_pk_init(&priv);
        int have_key =
            mbedtls_pk_setup(&priv, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) == 0 &&
            mbedtls_rsa_import_raw(mbedtls_pk_rsa(priv), NULL, 0,
                                   rfc8448_prime1, sizeof rfc8448_prime1,
                                   rfc8448_prime2, sizeof rfc8448_prime2, NULL, 0,
                                   rfc8448_e, sizeof rfc8448_e) == 0 &&
            mbedtls_rsa_complete(mbedtls_pk_rsa(priv)) == 0;
        expect(have_key, "the trace's own RSA key is rebuilt from the primes RFC 8448 prints");

        mbedtls_pk_context pub;
        mbedtls_pk_init(&pub);
        const uint8_t *spki = NULL;
        size_t         spki_len = 0;
        int            have_pub = lc_cert_spki(v.cert_der, v.cert_der_len, &spki, &spki_len) == 0;
        if (have_pub) {
            unsigned char *p = (unsigned char *)(uintptr_t)spki;
            have_pub = mbedtls_pk_parse_subpubkey(&p, spki + spki_len, &pub) == 0;
        }
        expect(have_pub && have_key && mbedtls_pk_check_pair(&pub, &priv, rng, NULL) == 0,
               "and it is the key that certificate carries, not a mistyped copy of one");

        uint8_t cvd[LC_HASH_MAX];
        expect(signed_digest(th, lc_hash_len(LC_SHA256), cvd) == 0,
               "the bytes RFC 8446 says are signed are rebuilt to sign them");

        uint8_t sig[RFC8448_SIG];
        uint8_t fake[4u + RFC8448_SIG];
        size_t  fake_len;

        /* A signature this test made itself, salted the way TLS 1.3 requires, must be ACCEPTED —
         * otherwise the two refusals below could be refusals of a malformed fixture, and would say
         * nothing about the checks they are aimed at. */
        v.cert_verified = 0;
        /* mbedTLS signs PSS only through a context whose padding says so — a parsed or imported key
         * starts at PKCS#1 v1.5, and rsassa_pss_sign_ext returns BAD_INPUT_DATA rather than a
         * signature. The verifying side takes the padding from the call, not from the key. */
        if (have_key)
            mbedtls_rsa_set_padding(mbedtls_pk_rsa(priv), MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
        int salted_right = have_key &&
                           mbedtls_rsa_rsassa_pss_sign_ext(mbedtls_pk_rsa(priv), rng, NULL,
                                                           MBEDTLS_MD_SHA256,
                                                           (unsigned)lc_hash_len(LC_SHA256), cvd,
                                                           (int)lc_hash_len(LC_SHA256), sig) == 0;
        fake_len = put_cv(fake, 0x0804u, sig, sizeof sig);
        expect(salted_right && check_cert_verify(&v, fake, fake_len, th) == 0,
               "a PSS signature made here, salted to the digest's length, is accepted");

        /* The salt length. RFC 8446 4.2.3 fixes it at the digest length; twenty bytes is a salt
         * every RSA-PSS implementation will produce on request and TLS 1.3 forbids. Both halves are
         * asserted, because "mbedTLS accepts it" is what makes the refusal a decision of ours:
         * SALT_LEN_ANY, which stood in qtls.c, is precisely the first line passing.
         *
         * This case is a statement about the build it runs in. mbedtls_pk_verify_ext has a PSA path
         * that verifies as PSA_ALG_RSA_PSS_ANY_SALT and ignores the length; the container this test
         * runs in has MBEDTLS_USE_PSA_CRYPTO off, so the length is enforced and this passes. See the
         * note beside expected_salt_len in qtls.c for what that means on the router. */
        v.cert_verified = 0;
        int salted_short = have_key &&
                           mbedtls_rsa_rsassa_pss_sign_ext(mbedtls_pk_rsa(priv), rng, NULL,
                                                           MBEDTLS_MD_SHA256,
                                                           (unsigned)lc_hash_len(LC_SHA256), cvd,
                                                           20, sig) == 0;
        fake_len = put_cv(fake, 0x0804u, sig, sizeof sig);
        mbedtls_pk_rsassa_pss_options any;
        any.mgf1_hash_id = MBEDTLS_MD_SHA256;
        any.expected_salt_len = MBEDTLS_RSA_SALT_LEN_ANY;
        expect(salted_short && have_pub &&
                   mbedtls_pk_verify_ext(MBEDTLS_PK_RSASSA_PSS, &any, &pub, MBEDTLS_MD_SHA256, cvd,
                                         lc_hash_len(LC_SHA256), sig, sizeof sig) == 0,
               "a PSS signature salted with twenty bytes is one SALT_LEN_ANY accepts");
        expect(check_cert_verify(&v, fake, fake_len, th) != 0,
               "and this client does not: TLS 1.3 fixes the salt at the digest's length");

        /* The key type. An ECDSA scheme over an RSA certificate is not a mismatch mbedTLS reports:
         * mbedtls_pk_verify dispatches to rsa_verify_wrap, which for a parsed public key performs
         * PKCS#1 v1.5 — the padding the scheme table refuses by name, reached by lying about the key
         * instead. So the signature below is a real PKCS#1 v1.5 signature by the pinned key, offered
         * under ecdsa_secp256r1_sha256, and it verifies. */
        v.cert_verified = 0;
        if (have_key)
            mbedtls_rsa_set_padding(mbedtls_pk_rsa(priv), MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
        int signed_v15 = have_key &&
                         mbedtls_rsa_pkcs1_sign(mbedtls_pk_rsa(priv), rng, NULL, MBEDTLS_MD_SHA256,
                                                (unsigned)lc_hash_len(LC_SHA256), cvd, sig) == 0;
        fake_len = put_cv(fake, 0x0403u, sig, sizeof sig);
        expect(signed_v15 && have_pub &&
                   mbedtls_pk_verify(&pub, MBEDTLS_MD_SHA256, cvd, lc_hash_len(LC_SHA256), sig,
                                     sizeof sig) == 0,
               "a PKCS#1 v1.5 signature by that same key is one mbedTLS verifies without complaint");
        expect(check_cert_verify(&v, fake, fake_len, th) != 0,
               "and an ECDSA scheme naming an RSA certificate's key is refused before it can");
        expect(v.cert_verified == 0, "neither of which set the flag the pin depends on");

        mbedtls_pk_free(&priv);
        mbedtls_pk_free(&pub);
        lc_transcript_free(&tr);
    }

    /* THE ATTACK THE CASES ABOVE COULD NOT SEE.
     *
     * Everything before this point calls check_cert_verify and check_pin directly, which is why the
     * pin was defeatable while every one of those cases passed: the two functions were each correct
     * and the state between them was not. cert_verified is a flag, so it cannot say WHICH bytes were
     * in cert_der when it was set — and nothing stopped a second Certificate from replacing them.
     *
     * So this case drives lc_qtls_recv, the state machine, with a flight assembled the way an
     * impersonator would: its own leaf, a signature it can honestly produce over that leaf, and then
     * the real node's leaf replayed. It needs no key of ours. What it wanted was for check_pin to
     * hash the second certificate while trusting a signature over the first.
     *
     * The messages are fed at LC_QTLS_HANDSHAKE because that is where the level table puts them;
     * keys_installed is set by hand because ServerHello and its key exchange are not what is under
     * test here. */
    {
        static lc_qtls v;
        /* lc_qtls_free between the sub-cases, not memset. The transcript is an mbedTLS context with
         * an allocation behind it (mbedtls_md_setup), and zeroing the structure on top of a ready
         * one dropped the only pointer to it: three leaks per run, which no assertion here could
         * ever have noticed. */
        memset(&v, 0, sizeof v);
        v.hash = hash;
        v.keys_installed = 1;
        v.read_level = LC_QTLS_HANDSHAKE;
        v.expect = LC_QX_CERTIFICATE;
        if (lc_transcript_init(&v.tr, hash) != 0) {
            printf("  FAIL  cannot start a transcript\n");
            return 1;
        }
        v.tr_ready = 1;

        expect(lc_qtls_recv(&v, LC_QTLS_HANDSHAKE, srv_msg_certificate,
                            sizeof srv_msg_certificate) == 0,
               "the flight's first Certificate is accepted");

        /* The second one — the replay. Anything at all, as long as it parses: the point is that the
         * bytes the pin will hash are not the bytes the signature covered. */
        expect(lc_qtls_recv(&v, LC_QTLS_HANDSHAKE, srv_msg_certificate,
                            sizeof srv_msg_certificate) != 0,
               "a SECOND Certificate is refused — the pin cannot be pointed at other bytes");

        /* And the same rule for the message carrying QUIC's transport parameters, for the same
         * reason: a repeat would overwrite what the connection is about to be configured from. */
        lc_qtls_free(&v);
        v.hash = hash;
        v.keys_installed = 1;
        v.read_level = LC_QTLS_HANDSHAKE;
        v.expect = LC_QX_ENCRYPTED_EXT;
        if (lc_transcript_init(&v.tr, hash) != 0) {
            printf("  FAIL  cannot start a transcript\n");
            return 1;
        }
        v.tr_ready = 1;
        /* A QUIC EncryptedExtensions, built here rather than taken from srv_msg_encryptedextensions.
         *
         * That vector is RFC 8448's, which is TLS over TCP and therefore carries no ALPN at all —
         * and on QUIC a server that selects no protocol is one the reference refuses outright
         * (checkALPN, vendor/utls/handshake_client.go:1001-1007, citing RFC 9001 §8.1). Feeding a TCP
         * vector into the QUIC path made this case assert that a node which answered nothing was
         * acceptable, which is the opposite of the rule. What a real node sends is this: the
         * protocol it picked, and the transport parameters.
         *
         *   08 00 00 11            EncryptedExtensions, 17 bytes
         *     00 0f                  extensions, 15 bytes
         *     00 10 00 05            ALPN, 5 bytes
         *       00 03 02 68 33         one name, two characters, "h3"
         *     00 39 00 02            quic_transport_parameters, 2 bytes
         *       40 01                  enough to be copied out and no more */
        static const uint8_t ee_quic[] = { 0x08, 0x00, 0x00, 0x11, 0x00, 0x0f, 0x00, 0x10,
                                           0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x33, 0x00,
                                           0x39, 0x00, 0x02, 0x40, 0x01 };
        expect(lc_qtls_recv(&v, LC_QTLS_HANDSHAKE, ee_quic, sizeof ee_quic) == 0,
               "EncryptedExtensions is accepted once");
        expect(lc_qtls_recv(&v, LC_QTLS_HANDSHAKE, ee_quic, sizeof ee_quic) != 0,
               "and refused twice");

        /* And the rule that vector could not express: no protocol selected is not acceptable on
         * QUIC. Same message with the ALPN extension taken out. */
        lc_qtls_free(&v);
        v.hash = hash;
        v.keys_installed = 1;
        v.read_level = LC_QTLS_HANDSHAKE;
        v.expect = LC_QX_ENCRYPTED_EXT;
        if (lc_transcript_init(&v.tr, hash) != 0) {
            printf("  FAIL  cannot start a transcript\n");
            return 1;
        }
        v.tr_ready = 1;
        static const uint8_t ee_no_alpn[] = { 0x08, 0x00, 0x00, 0x08, 0x00, 0x06,
                                              0x00, 0x39, 0x00, 0x02, 0x40, 0x01 };
        expect(lc_qtls_recv(&v, LC_QTLS_HANDSHAKE, ee_no_alpn, sizeof ee_no_alpn) != 0,
               "a node that selects no ALPN is refused, as RFC 9001 8.1 requires");

        /* A leaf this client cannot read — here a certificate_list whose declared length does not
         * describe what follows it. It used to be stepped over, cert_seen left clear, and the
         * connection failed several messages later at the pin, reported as "the node's certificate
         * does not match" when the truth was that the node sent something unparseable. */
        lc_qtls_free(&v);
        v.hash = hash;
        v.keys_installed = 1;
        v.read_level = LC_QTLS_HANDSHAKE;
        v.expect = LC_QX_CERTIFICATE;
        if (lc_transcript_init(&v.tr, hash) != 0) {
            printf("  FAIL  cannot start a transcript\n");
            return 1;
        }
        v.tr_ready = 1;
        static const uint8_t unreadable[] = { LC_HS_CERTIFICATE, 0x00u, 0x00u, 0x04u,
                                              0x00u, 0x00u, 0x00u, 0x05u };
        expect(lc_qtls_recv(&v, LC_QTLS_HANDSHAKE, unreadable, sizeof unreadable) != 0,
               "a Certificate this client cannot read is refused where it arrives, not at the pin");
        expect(v.cert_seen == 0, "and leaves nothing behind that says a certificate was seen");

        /* A header declaring more than the reassembly window holds is refused on sight rather than
         * waited for — otherwise four bytes cost the caller its whole handshake deadline, and the
         * tool reports "no answer" for what is really a malformed peer. */
        lc_qtls_free(&v);
        v.hash = hash;
        v.keys_installed = 1;
        v.read_level = LC_QTLS_HANDSHAKE;
        v.expect = LC_QX_CERTIFICATE;
        if (lc_transcript_init(&v.tr, hash) != 0) {
            printf("  FAIL  cannot start a transcript\n");
            return 1;
        }
        v.tr_ready = 1;
        uint8_t huge[4] = { LC_HS_CERTIFICATE, 0xffu, 0xffu, 0xffu };
        expect(lc_qtls_recv(&v, LC_QTLS_HANDSHAKE, huge, sizeof huge) != 0,
               "a message declared larger than the window is refused, not awaited");

        /* AFTER THE HANDSHAKE, WHICH IS WHERE THE ESTABLISHED CONNECTIONS DIED.
         *
         * A node sends session tickets unprompted once the handshake is done, and this client does
         * not resume, so they are read off the front of the buffer and dropped. They used to be
         * copied in and left there: the guard that refused to look at anything post-handshake
         * returned before the message was consumed, so `partial` only ever grew, and at sixteen
         * kilobytes the window check tore down a connection that was working.
         *
         * ⚠️ AND NOT WITHOUT END, which is where this case used to go wrong in the other
         * direction: it fed sixty-four and asserted the connection stood. The reference parses each
         * ticket, counts every post-handshake message against maxUselessRecords — sixteen in the
         * standard library, and on QUIC never reset — and refuses the seventeenth
         * (GOROOT/src/crypto/tls/conn.go:1309-1322, GOROOT/src/crypto/tls/common.go:71,
         * go1.25.14). So sixteen well-formed tickets of a kilobyte are consumed, the seventeenth is
         * unexpected_message, and one that does not parse is decode_error. */
        static uint8_t ticket[1024];
        memset(ticket, 0x5a, sizeof ticket);
        ticket[0] = LC_HS_NEW_SESSION_TICKET;
        ticket[1] = 0x00u;
        ticket[2] = 0x03u;
        ticket[3] = 0xfcu; /* a body of 1020, so the message is exactly this buffer */
        ticket[12] = 0x00u; /* no nonce */
        ticket[13] = 0x03u; /* a label of 1007 bytes */
        ticket[14] = 0xefu;
        ticket[1022] = 0x00u; /* and no extensions */
        ticket[1023] = 0x00u;

        lc_qtls_free(&v);
        v.hash = hash;
        v.done = 1;
        v.read_level = LC_QTLS_APPLICATION;
        v.expect = LC_QX_DONE;
        int drained = 1;
        for (int i = 0; i < 16; i++)
            if (lc_qtls_recv(&v, LC_QTLS_APPLICATION, ticket, sizeof ticket) != 0 ||
                v.partial_len != 0u)
                drained = 0;
        expect(drained && v.done == 1,
               "sixteen session tickets after the handshake are consumed and dropped, not hoarded");
        expect(lc_qtls_recv(&v, LC_QTLS_APPLICATION, ticket, sizeof ticket) != 0 &&
                   lc_qtls_alert(&v) == LC_ALERT_UNEXPECTED_MESSAGE,
               "and the seventeenth is unexpected_message, as the reference counts them");

        lc_qtls_free(&v);
        v.hash = hash;
        v.done = 1;
        v.read_level = LC_QTLS_APPLICATION;
        v.expect = LC_QX_DONE;
        ticket[1023] = 0x01u; /* an extensions block that says one byte and has none */
        expect(lc_qtls_recv(&v, LC_QTLS_APPLICATION, ticket, sizeof ticket) != 0 &&
                   lc_qtls_alert(&v) == LC_ALERT_DECODE_ERROR,
               "a ticket that does not parse is decode_error");
        ticket[1023] = 0x00u;

        /* Everything else after done is refused. A second Finished is the one that matters: it
         * would install the application keys twice, and ngtcp2 aborts the process on that rather
         * than returning an error. And handshake data at the Handshake level once the read level
         * has moved to application is refused before it is even parsed — internal_error, the
         * reference's answer to data at a level it is not reading
         * (GOROOT/src/crypto/tls/quic.go:257-261). */
        lc_qtls_free(&v);
        v.hash = hash;
        v.done = 1;
        v.read_level = LC_QTLS_APPLICATION;
        v.expect = LC_QX_DONE;
        expect(lc_qtls_recv(&v, LC_QTLS_HANDSHAKE, srv_msg_encryptedextensions,
                            sizeof srv_msg_encryptedextensions) != 0 &&
                   lc_qtls_alert(&v) == LC_ALERT_INTERNAL_ERROR,
               "a handshake message arriving after the handshake is refused, at the wrong level");
        lc_qtls_free(&v);
    }

    /* And what a handshake this client starts is configured with. Nothing above calls
     * lc_qtls_start — every case sets the fields it needs by hand — so the one line that decides
     * the hash for the whole key schedule had no case at all. */
    {
        static lc_qtls       s;
        lc_qtls_sink         sink = { NULL, sink_send, sink_secret, sink_secret };
        /* Stands in for what ngtcp2 encodes, and so it has to BE that shape: one well-formed entry,
         * initial_source_connection_id with a two-byte value. It used to be `00 04 00 00`, which
         * declares four bytes of body and supplies two — unparseable, and it passed only because
         * the writer had a retreat that copied an unparseable blob through whole. That retreat was
         * this tree's invention and is gone, so the fixture has to be honest. */
        static const uint8_t params[] = { 0x0fu, 0x02u, 0xaau, 0xbbu };
        expect(lc_qtls_start(&s, &sink, "node.example", params, sizeof params, NULL, 0) == 0,
               "a handshake starts and its ClientHello leaves at the initial level");
        expect(s.suite == LC_QTLS_SUITE && s.hash == hash,
               "with the hash the suite table gives, not one asserted beside the suite");
        expect(s.have_pin == 0 && s.peer_pinned == 0,
               "and started without a pin it says so rather than claiming an identity");

        /* AND THE TRANSCRIPT DOES NOT EXIST YET, which is the whole of the fix below it.
         *
         * A transcript hashes with one algorithm from the moment it is created, and which one is
         * not known until a ServerHello names a suite. While a single suite was offered, starting
         * it here was harmless. Three are offered now, one of them TLS_AES_256_GCM_SHA384: pick
         * that and the transcript is SHA-256 while every secret derived from it is sized SHA-384,
         * so a 32-byte snapshot is read as 48 and the last sixteen are whatever the stack held.
         * Nothing asserts, nothing decrypts, and the node reads as unreachable. */
        expect(s.tr_ready == 0 && s.ch_len > 4u,
               "and the ClientHello is kept rather than hashed, the suite being unknown so far");

        /* AND IT OFFERS THREE SUITES, WHICH NOTHING ELSE IN THIS TREE LOOKS AT.
         *
         * The list is a fingerprint and a twelvefold difference in speed on the target, and it is
         * decided in one statement that no test read and no generated vector covers. It was reverted
         * to a single suite by a commit whose subject was the mini-app's help text, and every gate
         * stayed green: the compiler does not mind, and the SHA-384 case below hands the client a
         * captured ServerHello rather than one the node could only have chosen from what we sent.
         *
         * So this reads the bytes that left. */
        size_t count = 0;
        size_t at    = suites_at(sink_hello, sink_hello_len, &count);
        expect(at != 0 && count == 3u, "the ClientHello offers three suites, as every Go client does");

        uint16_t offered[3] = { 0, 0, 0 };
        for (size_t i = 0; i < count && i < 3u; i++)
            offered[i] = (uint16_t)(((uint16_t)sink_hello[at + i * 2u] << 8) |
                                    sink_hello[at + i * 2u + 1u]);
        expect(at != 0 && ((offered[0] == 0x1301u && offered[1] == 0x1302u && offered[2] == 0x1303u) ||
                           (offered[0] == 0x1303u && offered[1] == 0x1301u && offered[2] == 0x1302u)),
               "and they are Go's two orderings, whole and in order, not a set in any arrangement");

        /* Go chooses at runtime. A VM can hide AES instructions even on x86_64, so the wire
         * assertion must follow the same detected capability rather than the build architecture. */
        if (lc_qtls_aesgcm_hardware())
            expect(offered[0] == 0x1301u, "AES first when this CPU supports GCM");
        else
            expect(offered[0] == 0x1303u, "ChaCha20 first when this CPU lacks GCM");
        lc_qtls_free(&s);
    }

    /* Then a server that chooses the SHA-384 suite. The ClientHello offers it, so this is a
     * handshake that can really happen — and before the ClientHello was kept back, this case
     * derived its keys from uninitialised memory. */
    {
        static lc_qtls s;
        lc_qtls_sink   sink = { NULL, sink_send, sink_secret, sink_secret };
        /* Stands in for what ngtcp2 encodes, and so it has to BE that shape: one well-formed entry,
         * initial_source_connection_id with a two-byte value. It used to be `00 04 00 00`, which
         * declares four bytes of body and supplies two — unparseable, and it passed only because
         * the writer had a retreat that copied an unparseable blob through whole. That retreat was
         * this tree's invention and is gone, so the fixture has to be honest. */
        static const uint8_t params[] = { 0x0fu, 0x02u, 0xaau, 0xbbu };
        expect(lc_qtls_start(&s, &sink, "node.example", params, sizeof params, NULL, 0) == 0,
               "a handshake starts, offering three suites");

        /* The same captured ServerHello with one field changed: session_id length sits at offset
         * 38, and the suite is the two bytes after that variable-length field. */
        static uint8_t sh[sizeof srv_msg_serverhello];
        memcpy(sh, srv_msg_serverhello, sizeof sh);
        size_t at = 4u + 2u + 32u;
        size_t suite_at = at + 1u + sh[at];
        expect(suite_at + 1u < sizeof sh && sh[suite_at] == 0x13u,
               "the captured ServerHello names its suite where TLS says it does");
        sh[suite_at + 1u] = 0x02u; /* TLS_AES_256_GCM_SHA384 */

        expect(lc_qtls_recv(&s, LC_QTLS_INITIAL, sh, sizeof sh) == 0,
               "a ServerHello choosing AES-256-GCM is accepted");
        expect(s.suite == 0x1302u && s.hash == LC_SHA384,
               "and the key schedule moves to SHA-384 with it, rather than staying where it began");
        /* AND THE TRANSCRIPT HASHES WITH SHA-384 TOO, which is the assertion that discriminates.
         * `tr_ready` and `s.hash` both read correctly even with the bug — the first was set at
         * start, the second is assigned from the suite table either way — so a case built on those
         * two passes a revert and proves nothing. What was actually wrong is the algorithm the
         * running context was created with, and only this line looks at it. */
        expect(s.tr_ready == 1 && s.tr.hash == LC_SHA384 && s.ch_len == 0,
               "the transcript starts here, over the ClientHello, with the hash the suite implies");
        lc_qtls_free(&s);
    }

    /* THE QUIC PLANE'S REFUSALS OF A ServerHello CARRY THE STANDARD LIBRARY'S NUMBERS.
     *
     * The same verdict as the TLS plane, but this plane's reference is Go's crypto/tls as built into
     * hysteria, which answers a message that does not unmarshal and a compression method with
     * decode_error (GOROOT/src/crypto/tls/conn.go:1185-1186,
     * GOROOT/src/crypto/tls/handshake_client_tls13.go:199-201,
     * go1.25.14) — where uTLS says 10 and 47. These used to leave as a bare -1 with no alert at all,
     * which ngtcp2 closed as an application error. */
    {
        static const struct { size_t cut; int comp; uint8_t want; const char *what; } cases[] = {
            { 60u, 0, LC_ALERT_DECODE_ERROR,
              "a ServerHello cut short is decode_error on the QUIC plane" },
            { 0u, 1, LC_ALERT_DECODE_ERROR,
              "and a compression method is decode_error too, not uTLS's illegal_parameter" },
        };
        for (size_t c = 0; c < sizeof cases / sizeof cases[0]; c++) {
            static lc_qtls       s;
            lc_qtls_sink         sink = { NULL, sink_send, sink_secret, sink_secret };
            static const uint8_t params[] = { 0x0fu, 0x02u, 0xaau, 0xbbu };
            if (lc_qtls_start(&s, &sink, "node.example", params, sizeof params, NULL, 0) != 0) {
                expect(0, "a handshake starts");
                continue;
            }
            static uint8_t sh[sizeof srv_msg_serverhello];
            memcpy(sh, srv_msg_serverhello, sizeof sh);
            size_t len = sizeof sh;
            if (cases[c].cut != 0u) {
                len = cases[c].cut;
                sh[1] = 0u;
                sh[2] = 0u;
                sh[3] = (uint8_t)(len - 4u);
            }
            if (cases[c].comp) {
                size_t at = 4u + 2u + 32u;
                sh[at + 1u + sh[at] + 2u] = 0x01u; /* legacy_compression_method */
            }
            expect(lc_qtls_recv(&s, LC_QTLS_INITIAL, sh, len) != 0 &&
                       lc_qtls_alert(&s) == cases[c].want,
                   cases[c].what);
            lc_qtls_free(&s);
        }
    }

    /* THE ONE READ LEVEL AND THE ORDER OF THE FLIGHT, driven through lc_qtls_recv from a real start.
     *
     * The reference reads handshake data at one level at a time and refuses any other before a
     * byte is parsed (GOROOT/src/crypto/tls/quic.go:257-261, internal_error); it will not change
     * its read keys over bytes still buffered (:384-392, unexpected_message); and it reads the
     * flight as a sequence of type assertions
     * (GOROOT/src/crypto/tls/handshake_client_tls13.go:547-757). Each case is one of those, on the
     * captured ServerHello this file already uses. */
    {
        static const uint8_t params[] = { 0x0fu, 0x02u, 0xaau, 0xbbu };
        static const uint8_t ee_quic[] = { 0x08, 0x00, 0x00, 0x11, 0x00, 0x0f, 0x00, 0x10,
                                           0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x33, 0x00,
                                           0x39, 0x00, 0x02, 0x40, 0x01 };
        static const uint8_t fin[] = { LC_HS_FINISHED, 0x00, 0x00, 0x20,
                                       1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                                       17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
        static lc_qtls s;
        lc_qtls_sink   sink = { NULL, sink_send, sink_secret, sink_secret };
        static uint8_t two[2 * sizeof srv_msg_serverhello];

#define QSTART() (lc_qtls_start(&s, &sink, "node.example", params, sizeof params, NULL, 0) == 0)
        if (QSTART()) {
            expect(lc_qtls_recv(&s, LC_QTLS_HANDSHAKE, ee_quic, sizeof ee_quic) != 0 &&
                       lc_qtls_alert(&s) == LC_ALERT_INTERNAL_ERROR,
                   "Handshake data before the ServerHello is refused at the level, internal_error");
            expect(!lc_qtls_own(&s) && lc_qtls_go_error(&s)[0] != '\0',
                   "and that refusal is the reference's, with its words, not a failure of ours");
            lc_qtls_free(&s);
        }
        /* A FAILURE OF OUR OWN IS MARKED AS ONE, and the transport then closes without a word, as
         * the reference's process does at such a point (own_fail in quic/qtls.c, lc_qconn_close).
         * Our own hello made unreadable stands in for the rest — memory, a key that will not derive —
         * none of which a test can bring about from outside. */
        if (QSTART()) {
            s.ch_len = 3u;
            expect(lc_qtls_recv(&s, LC_QTLS_INITIAL, srv_msg_serverhello,
                                sizeof srv_msg_serverhello) != 0 &&
                       lc_qtls_own(&s) && lc_qtls_go_error(&s)[0] == '\0',
                   "a failure of our own is marked as ours and carries no words of the reference's");
            lc_qtls_free(&s);
        }
        if (QSTART()) {
            memcpy(two, srv_msg_serverhello, sizeof srv_msg_serverhello);
            memcpy(two + sizeof srv_msg_serverhello, fin, 4u);
            expect(lc_qtls_recv(&s, LC_QTLS_INITIAL, two, sizeof srv_msg_serverhello + 4u) != 0 &&
                       lc_qtls_alert(&s) == LC_ALERT_UNEXPECTED_MESSAGE,
                   "bytes after the ServerHello in the same Initial data are unexpected_message "
                   "when the read keys change");
            lc_qtls_free(&s);
        }
        if (QSTART()) {
            expect(lc_qtls_recv(&s, LC_QTLS_INITIAL, srv_msg_serverhello,
                                sizeof srv_msg_serverhello) == 0 &&
                       s.read_level == LC_QTLS_HANDSHAKE,
                   "the captured ServerHello moves the read level to Handshake");
            expect(lc_qtls_recv(&s, LC_QTLS_INITIAL, srv_msg_serverhello,
                                sizeof srv_msg_serverhello) != 0 &&
                       lc_qtls_alert(&s) == LC_ALERT_INTERNAL_ERROR,
                   "and a second one at Initial is refused at the level, not read as a repeat");
            lc_qtls_free(&s);
        }
        if (QSTART()) {
            (void)lc_qtls_recv(&s, LC_QTLS_INITIAL, srv_msg_serverhello, sizeof srv_msg_serverhello);
            expect(lc_qtls_recv(&s, LC_QTLS_HANDSHAKE, srv_msg_certificate,
                                sizeof srv_msg_certificate) != 0 &&
                       lc_qtls_alert(&s) == LC_ALERT_UNEXPECTED_MESSAGE,
                   "a Certificate before EncryptedExtensions is unexpected_message");
            lc_qtls_free(&s);
        }
        if (QSTART()) {
            (void)lc_qtls_recv(&s, LC_QTLS_INITIAL, srv_msg_serverhello, sizeof srv_msg_serverhello);
            expect(lc_qtls_recv(&s, LC_QTLS_HANDSHAKE, ee_quic, sizeof ee_quic) == 0,
                   "EncryptedExtensions is taken where the flight expects it");
            expect(lc_qtls_recv(&s, LC_QTLS_HANDSHAKE, fin, sizeof fin) != 0 &&
                       lc_qtls_alert(&s) == LC_ALERT_UNEXPECTED_MESSAGE && s.done == 0,
                   "and a Finished straight after it — no Certificate, no CertificateVerify — is "
                   "unexpected_message, where it used to complete an unpinned handshake");
            lc_qtls_free(&s);
        }
        if (QSTART()) {
            static uint8_t low[sizeof srv_msg_serverhello];
            memcpy(low, srv_msg_serverhello, sizeof low);
            int zeroed = 0;
            for (size_t i = 0; i + 4u + 32u <= sizeof low; i++)
                if (low[i] == 0x00u && low[i + 1u] == 0x1du && low[i + 2u] == 0x00u &&
                    low[i + 3u] == 0x20u) {
                    memset(low + i + 4u, 0, 32);
                    zeroed = 1;
                    break;
                }
            expect(zeroed && lc_qtls_recv(&s, LC_QTLS_INITIAL, low, sizeof low) != 0 &&
                       lc_qtls_alert(&s) == LC_ALERT_ILLEGAL_PARAMETER,
                   "an X25519 share that yields no secret is illegal_parameter, not a bare refusal");
            lc_qtls_free(&s);
        }
#undef QSTART

        /* And a Finished that does not verify: decrypt_error, where it was a bare -1. The state is
         * set by hand to the point just before it, the key being whatever lc_qtls_start left. */
        static lc_qtls f;
        memset(&f, 0, sizeof f);
        f.hash = hash;
        f.keys_installed = 1;
        f.read_level = LC_QTLS_HANDSHAKE;
        f.expect = LC_QX_FINISHED;
        if (lc_transcript_init(&f.tr, hash) == 0) {
            f.tr_ready = 1;
            expect(lc_qtls_recv(&f, LC_QTLS_HANDSHAKE, fin, sizeof fin) != 0 &&
                       lc_qtls_alert(&f) == LC_ALERT_DECRYPT_ERROR,
                   "a Finished that does not verify is decrypt_error");
        }
        lc_qtls_free(&f);
    }

    /* ENCRYPTED EXTENSIONS, WHOLE MESSAGE FIRST. The reference unmarshals the message and answers
     * decode_error for any fault of shape — a repeated extension, a server_name or early_data with
     * a body, bytes after the block (GOROOT/src/crypto/tls/handshake_messages.go:1056-1121) — and
     * only then judges the protocol (120), the transport parameters (missing, 109) and early_data
     * (110), in that order (GOROOT/src/crypto/tls/handshake_client_tls13.go:561-588). */
    {
        static const uint8_t ALPN_H3[] = { 0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x33 };
        static const uint8_t ALPN_H2[] = { 0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x32 };
        static const uint8_t TP[]      = { 0x00, 0x39, 0x00, 0x02, 0x40, 0x01 };
        static const uint8_t SNI_BODY[] = { 0x00, 0x00, 0x00, 0x01, 0x41 };
        static const uint8_t EARLY[]   = { 0x00, 0x2a, 0x00, 0x00 };
        static const uint8_t EARLY4[]  = { 0x00, 0x2a, 0x00, 0x04, 0, 0, 0, 1 };
        static const uint8_t BAD_LEN[] = { 0x7a, 0x7a, 0x00, 0x09, 0x00 };
        static const struct {
            const uint8_t *e[3];
            size_t         n[3];
            int            trailing;
            uint8_t        want; /* 0: accepted */
            const char    *what;
        } cases[] = {
            { { ALPN_H3, TP, NULL }, { sizeof ALPN_H3, sizeof TP, 0 }, 0, 0,
              "a well-formed EncryptedExtensions is accepted" },
            { { ALPN_H3, TP, NULL }, { sizeof ALPN_H3, sizeof TP, 0 }, 1, LC_ALERT_DECODE_ERROR,
              "bytes after the extension block are decode_error" },
            { { ALPN_H3, TP, TP }, { sizeof ALPN_H3, sizeof TP, sizeof TP }, 0, LC_ALERT_DECODE_ERROR,
              "a repeated extension is decode_error, where it was accepted" },
            { { ALPN_H3, TP, SNI_BODY }, { sizeof ALPN_H3, sizeof TP, sizeof SNI_BODY }, 0,
              LC_ALERT_DECODE_ERROR, "a server_name with a body is decode_error" },
            { { ALPN_H2, TP, BAD_LEN }, { sizeof ALPN_H2, sizeof TP, sizeof BAD_LEN }, 0,
              LC_ALERT_DECODE_ERROR,
              "the wrong protocol AND a malformed extension after it: decode_error, the whole "
              "message is read before the protocol is judged" },
            { { ALPN_H2, TP, NULL }, { sizeof ALPN_H2, sizeof TP, 0 }, 0,
              LC_ALERT_NO_APPLICATION_PROTOCOL, "a protocol that is not h3 is no_application_protocol" },
            { { ALPN_H3, NULL, NULL }, { sizeof ALPN_H3, 0, 0 }, 0, LC_ALERT_MISSING_EXTENSION,
              "no transport parameters is missing_extension, not a failure after our Finished" },
            { { ALPN_H3, TP, EARLY }, { sizeof ALPN_H3, sizeof TP, sizeof EARLY }, 0,
              LC_ALERT_UNSUPPORTED_EXTENSION, "early_data never offered is unsupported_extension" },
            { { ALPN_H3, TP, EARLY4 }, { sizeof ALPN_H3, sizeof TP, sizeof EARLY4 }, 0,
              LC_ALERT_DECODE_ERROR, "and an early_data with a body is decode_error" },
        };
        for (size_t c = 0; c < sizeof cases / sizeof cases[0]; c++) {
            static uint8_t msg[256];
            size_t         n = 6u;
            for (unsigned k = 0; k < 3u; k++)
                if (cases[c].e[k] != NULL) {
                    memcpy(msg + n, cases[c].e[k], cases[c].n[k]);
                    n += cases[c].n[k];
                }
            size_t block = n - 6u;
            if (cases[c].trailing)
                msg[n++] = 0x00u;
            msg[0] = LC_HS_ENCRYPTED_EXT;
            msg[1] = 0x00u;
            msg[2] = (uint8_t)((n - 4u) >> 8);
            msg[3] = (uint8_t)(n - 4u);
            msg[4] = (uint8_t)(block >> 8);
            msg[5] = (uint8_t)block;

            static lc_qtls v;
            memset(&v, 0, sizeof v);
            v.hash = hash;
            v.keys_installed = 1;
            v.read_level = LC_QTLS_HANDSHAKE;
            v.expect = LC_QX_ENCRYPTED_EXT;
            if (lc_transcript_init(&v.tr, hash) != 0)
                continue;
            v.tr_ready = 1;
            int     rc = lc_qtls_recv(&v, LC_QTLS_HANDSHAKE, msg, n);
            uint8_t got = rc == 0 ? 0u : lc_qtls_alert(&v);
            expect(got == cases[c].want, cases[c].what);
            lc_qtls_free(&v);
        }

        /* And a parameter block over a kilobyte, which the reference takes and this used to drop
         * without a word — failing the handshake later, as though the node had sent none. */
        static uint8_t big[2100];
        size_t         n = 6u;
        memcpy(big + n, ALPN_H3, sizeof ALPN_H3);
        n += sizeof ALPN_H3;
        big[n++] = 0x00; big[n++] = 0x39; big[n++] = 0x07; big[n++] = 0xd0; /* 2000 bytes */
        memset(big + n, 0x40, 2000);
        n += 2000u;
        big[0] = LC_HS_ENCRYPTED_EXT;
        big[1] = 0x00u;
        big[2] = (uint8_t)((n - 4u) >> 8);
        big[3] = (uint8_t)(n - 4u);
        big[4] = (uint8_t)((n - 6u) >> 8);
        big[5] = (uint8_t)(n - 6u);
        static lc_qtls v;
        memset(&v, 0, sizeof v);
        v.hash = hash;
        v.keys_installed = 1;
        v.read_level = LC_QTLS_HANDSHAKE;
        v.expect = LC_QX_ENCRYPTED_EXT;
        if (lc_transcript_init(&v.tr, hash) == 0) {
            v.tr_ready = 1;
            expect(lc_qtls_recv(&v, LC_QTLS_HANDSHAKE, big, n) == 0 && v.peer_params_len == 2000u &&
                       v.params_fresh == 1,
                   "a transport parameter block of two kilobytes is kept whole, for the shim");
        }
        lc_qtls_free(&v);
    }

    /* THE CERTIFICATE, AS THE STANDARD LIBRARY READS IT: the whole message, every certificate in
     * it as X.509, an RSA key over 8192 bits, the leaf's key type, then the pin — all before
     * CertificateVerify (GOROOT/src/crypto/tls/handshake_client.go:1135-1222). Each case wraps
     * certificates in a Certificate message of its own. */
    {
        const uint8_t *leaf = NULL;
        size_t         leaf_len = 0;
        (void)lc_cert_first_from_message(srv_msg_certificate + 4, sizeof srv_msg_certificate - 4u,
                                         &leaf, &leaf_len);
        static const uint8_t junk[] = { 0x30, 0x03, 0x02, 0x01, 0x00 };

        /* An RSA key of 8208 bits in a certificate x509.ParseCertificate reads — a signature
         * algorithm inside and out, empty Names, a validity, no extensions: the reference parses
         * it and refuses the SIZE, with bad_certificate. */
        static uint8_t big[1300];
        size_t         bn = 0;
        {
            static uint8_t mod[1027];
            mod[0] = 0x00;
            memset(mod + 1, 0xc3, sizeof mod - 1u);
            static uint8_t rsapub[1100], spki[1150], tbs[1180];
            size_t         r = 0, s = 0, t = 0;
            rsapub[r++] = 0x30; rsapub[r++] = 0x82; rsapub[r++] = 0; rsapub[r++] = 0;
            rsapub[r++] = 0x02; rsapub[r++] = 0x82;
            rsapub[r++] = (uint8_t)(sizeof mod >> 8); rsapub[r++] = (uint8_t)sizeof mod;
            memcpy(rsapub + r, mod, sizeof mod); r += sizeof mod;
            rsapub[r++] = 0x02; rsapub[r++] = 0x03; rsapub[r++] = 0x01; rsapub[r++] = 0x00;
            rsapub[r++] = 0x01;
            rsapub[2] = (uint8_t)((r - 4u) >> 8); rsapub[3] = (uint8_t)(r - 4u);
            static const uint8_t alg[] = { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
                                           0x0d, 0x01, 0x01, 0x01, 0x05, 0x00 };
            spki[s++] = 0x30; spki[s++] = 0x82; spki[s++] = 0; spki[s++] = 0;
            memcpy(spki + s, alg, sizeof alg); s += sizeof alg;
            spki[s++] = 0x03; spki[s++] = 0x82;
            spki[s++] = (uint8_t)((r + 1u) >> 8); spki[s++] = (uint8_t)(r + 1u);
            spki[s++] = 0x00;
            memcpy(spki + s, rsapub, r); s += r;
            spki[2] = (uint8_t)((s - 4u) >> 8); spki[3] = (uint8_t)(s - 4u);
            static const uint8_t sig_ai[] = { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
                                              0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00 };
            static const uint8_t validity[] = { 0x30, 0x1e, 0x17, 0x0d, '2', '5', '0', '1', '0', '1',
                                                '0', '0', '0', '0', '0', '0', 'Z', 0x17, 0x0d, '3',
                                                '5', '1', '2', '3', '1', '2', '3', '5', '9', '5', '9',
                                                'Z' };
            static const uint8_t version_serial[] = { 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01 };
            static const uint8_t empty_name[] = { 0x30, 0x00 };
            static const uint8_t signature[] = { 0x03, 0x02, 0x00, 0x00 };
            tbs[t++] = 0x30; tbs[t++] = 0x82; tbs[t++] = 0; tbs[t++] = 0;
            memcpy(tbs + t, version_serial, sizeof version_serial); t += sizeof version_serial;
            memcpy(tbs + t, sig_ai, sizeof sig_ai); t += sizeof sig_ai;
            memcpy(tbs + t, empty_name, sizeof empty_name); t += sizeof empty_name;
            memcpy(tbs + t, validity, sizeof validity); t += sizeof validity;
            memcpy(tbs + t, empty_name, sizeof empty_name); t += sizeof empty_name;
            memcpy(tbs + t, spki, s); t += s;
            tbs[2] = (uint8_t)((t - 4u) >> 8); tbs[3] = (uint8_t)(t - 4u);
            size_t body = t + sizeof sig_ai + sizeof signature;
            big[bn++] = 0x30; big[bn++] = 0x82;
            big[bn++] = (uint8_t)(body >> 8); big[bn++] = (uint8_t)body;
            memcpy(big + bn, tbs, t); bn += t;
            memcpy(big + bn, sig_ai, sizeof sig_ai); bn += sizeof sig_ai;
            memcpy(big + bn, signature, sizeof signature); bn += sizeof signature;
        }
        expect(lc_cert_rsa_bits(big, bn) == 8208u, "the built certificate carries an 8208-bit RSA key");

        static const struct { int kind; uint8_t want; const char *what; } cases[] = {
            { 0, 0, "the trace's certificate alone is accepted" },
            { 1, LC_ALERT_DECODE_ERROR,
              "a leaf followed by an intermediate that is not X.509 is decode_error, where only the "
              "leaf used to be read" },
            { 2, LC_ALERT_DECODE_ERROR, "a leaf that is not X.509 is decode_error at the Certificate" },
            { 3, LC_ALERT_BAD_CERTIFICATE,
              "an RSA key over 8192 bits is bad_certificate, the reference's size check" },
            { 4, LC_ALERT_BAD_CERTIFICATE,
              "a certificate that does not match the pin is bad_certificate AT the Certificate, "
              "before any CertificateVerify is read" },
            { 5, 0, "one that matches is accepted, and the peer is not yet called pinned" },
        };
        for (size_t c = 0; c < sizeof cases / sizeof cases[0]; c++) {
            static uint8_t msg[4096];
            size_t         n = 8u;
            const uint8_t *certs[2] = { leaf, NULL };
            size_t         lens[2] = { leaf_len, 0 };
            if (cases[c].kind == 1) { certs[1] = junk; lens[1] = sizeof junk; }
            if (cases[c].kind == 2) { certs[0] = junk; lens[0] = sizeof junk; }
            if (cases[c].kind == 3) { certs[0] = big; lens[0] = bn; }
            for (unsigned k = 0; k < 2u && certs[k] != NULL; k++) {
                msg[n++] = (uint8_t)(lens[k] >> 16); msg[n++] = (uint8_t)(lens[k] >> 8);
                msg[n++] = (uint8_t)lens[k];
                memcpy(msg + n, certs[k], lens[k]); n += lens[k];
                msg[n++] = 0x00; msg[n++] = 0x00;
            }
            size_t list = n - 8u;
            msg[0] = LC_HS_CERTIFICATE;
            msg[1] = (uint8_t)((n - 4u) >> 16); msg[2] = (uint8_t)((n - 4u) >> 8);
            msg[3] = (uint8_t)(n - 4u);
            msg[4] = 0x00; /* empty request context */
            msg[5] = (uint8_t)(list >> 16); msg[6] = (uint8_t)(list >> 8); msg[7] = (uint8_t)list;

            static lc_qtls v;
            memset(&v, 0, sizeof v);
            v.hash = hash;
            v.keys_installed = 1;
            v.read_level = LC_QTLS_HANDSHAKE;
            v.expect = LC_QX_CERTIFICATE;
            if (cases[c].kind == 4 || cases[c].kind == 5) {
                v.have_pin = 1;
                if (lc_hash_digest(LC_SHA256, leaf, leaf_len, v.pin) != 0)
                    continue;
                if (cases[c].kind == 4)
                    v.pin[0] ^= 0x01u;
            }
            if (lc_transcript_init(&v.tr, hash) != 0)
                continue;
            v.tr_ready = 1;
            int     rc = lc_qtls_recv(&v, LC_QTLS_HANDSHAKE, msg, n);
            uint8_t got = rc == 0 ? 0u : lc_qtls_alert(&v);
            expect(got == cases[c].want && (cases[c].kind != 5 || v.peer_pinned == 0), cases[c].what);

            /* And under the parrot, the words the close carries (quic/conn.c): uTLS's own, which
             * quic-go sends as INTERNAL_ERROR's reason (tls/goerr.h) — x509's exact place for the
             * SEQUENCE { INTEGER 0 } that stands in for a certificate, since cert/x509go.c
             * (test/x509go holds that parser to Go's on every other shape). */
            static const char *const words[] = {
                "", "tls: failed to parse certificate from server: x509: malformed tbs certificate",
                "tls: failed to parse certificate from server: x509: malformed tbs certificate",
                "tls: server sent certificate containing RSA key larger than 8192 bits",
                "no certificate matches the pinned hash", "",
            };
            uint8_t pin[LC_QTLS_PIN];
            int     have_pin = v.have_pin;
            memcpy(pin, v.pin, sizeof pin);
            lc_qtls_free(&v);
            memset(&v, 0, sizeof v);
            v.hash = hash;
            v.chrome = 1;
            v.keys_installed = 1;
            v.read_level = LC_QTLS_HANDSHAKE;
            v.expect = LC_QX_CERTIFICATE;
            v.have_pin = have_pin;
            memcpy(v.pin, pin, sizeof pin);
            if (lc_transcript_init(&v.tr, hash) != 0)
                continue;
            v.tr_ready = 1;
            (void)lc_qtls_recv(&v, LC_QTLS_HANDSHAKE, msg, n);
            {
                char what[640];
                snprintf(what, sizeof what, "under the parrot: \"%s\" (got \"%s\")",
                         words[cases[c].kind], lc_qtls_go_error(&v));
                expect(strcmp(lc_qtls_go_error(&v), words[cases[c].kind]) == 0, what);
            }
            lc_qtls_free(&v);
        }
    }

    /* A CERTIFICATEREQUEST ON THE QUIC PLANE, which the reference answers rather than refuses:
     * it is taken once where a Certificate is expected, parsed (decode_error when it does not), and
     * owed an empty Certificate ahead of our Finished
     * (GOROOT/src/crypto/tls/handshake_client_tls13.go:637-645, :759-795). */
    {
        static const uint8_t cr[] = { LC_HS_CERTIFICATE_REQUEST, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x08,
                                      0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x08, 0x07 };
        static const uint8_t cr_bad[] = { LC_HS_CERTIFICATE_REQUEST, 0x00, 0x00, 0x0c, 0x00, 0x00,
                                          0x09, 0x00, 0x0d, 0x00, 0x05, 0x00, 0x03, 0x08, 0x07,
                                          0x04 };
        static lc_qtls v;
        for (int k = 0; k < 2; k++) {
            memset(&v, 0, sizeof v);
            v.hash = hash;
            v.keys_installed = 1;
            v.read_level = LC_QTLS_HANDSHAKE;
            v.expect = LC_QX_CERTIFICATE;
            if (lc_transcript_init(&v.tr, hash) != 0)
                continue;
            v.tr_ready = 1;
            if (k == 0) {
                expect(lc_qtls_recv(&v, LC_QTLS_HANDSHAKE, cr, sizeof cr) == 0 && v.cert_requested == 1 &&
                           v.expect == LC_QX_CERTIFICATE,
                       "a CertificateRequest is taken where the Certificate is expected");
                expect(lc_qtls_recv(&v, LC_QTLS_HANDSHAKE, cr, sizeof cr) != 0 &&
                           lc_qtls_alert(&v) == LC_ALERT_UNEXPECTED_MESSAGE,
                       "and a second one is unexpected_message");
            } else {
                expect(lc_qtls_recv(&v, LC_QTLS_HANDSHAKE, cr_bad, sizeof cr_bad) != 0 &&
                           lc_qtls_alert(&v) == LC_ALERT_DECODE_ERROR,
                       "a CertificateRequest whose algorithm list is an odd length is decode_error");
            }
            lc_qtls_free(&v);
        }

        /* And what finish() puts on the wire for it: the empty Certificate, then our Finished, both
         * at the Handshake level. */
        memset(&v, 0, sizeof v);
        v.hash = hash;
        v.cert_requested = 1;
        v.sink.send = sent_capture;
        v.sink.rx_secret = sink_secret;
        v.sink.tx_secret = sink_secret;
        sent_count = 0;
        uint8_t th[LC_HASH_MAX];
        memset(th, 0x42, sizeof th);
        if (lc_transcript_init(&v.tr, hash) == 0) {
            v.tr_ready = 1;
            expect(finish(&v, th) == 0 && sent_count == 2 && sent_len[0] == sizeof lc_empty_certificate &&
                       memcmp(sent_msg[0], lc_empty_certificate, sizeof lc_empty_certificate) == 0 &&
                       sent_level[0] == LC_QTLS_HANDSHAKE && sent_msg[1][0] == LC_HS_FINISHED &&
                       sent_level[1] == LC_QTLS_HANDSHAKE,
                   "a requested certificate is answered with the empty Certificate, then our Finished");
        }
        lc_qtls_free(&v);
    }

    /* The one edit this file makes to what ngtcp2 says: max_datagram_frame_size is taken back out of
     * the ClientHello, because announcing a limit nobody else announces is itself a name. It runs on
     * every handshake and had no case at all — while being the only parser here fed something it did
     * not encode. */
    {
        uint8_t  mem[64];
        lc_buf   b;

        /* THE GREASED PARAMETER COMES FIRST NOW, and these cases are about what follows it.
         *
         * skip_grease steps over one entry and asserts its shape on the way: the identifier is
         * `27 + 31k` for some byte k, which is the whole of what quic-go can emit
         * (vendor/quic-go/internal/wire/transport_parameters.go:372-378), and the body is at most
         * fifteen bytes because the length is a random byte modulo sixteen. Checking the shape here
         * rather than in a case of its own is deliberate: every one of these four calls then proves
         * the entry is present and well formed, and a version that emitted it only sometimes would
         * fail three of them. */

        /* AND `08 01 00` NOW APPEARS IN EVERY ONE OF THESE, which is the second thing this encoder
         * does and the reason these expectations gained three bytes.
         *
         * initial_max_streams_bidi is zero for this client (the derivation is in src/quic/params.c:
         * http3.Transport forces MaxIncomingStreams to -1 and populateConfig folds it to 0, so no
         * hysteria client ever advertises the 100 that quic-go's bare default would give). ngtcp2
         * will not encode a zero (vendor/ngtcp2/lib/ngtcp2_transport_params.c:330-333) while
         * quic-go writes the identifier unconditionally
         * (vendor/quic-go/internal/wire/transport_parameters.go:384-385), so the entry is
         * synthesised here, in its place in the order — after 0x04 and before 0x09 — rather than
         * appended. These cases feed blobs with no 0x08 in them, which is exactly the shape ngtcp2
         * hands over, so each of them proves the synthesis as well as what it was written for. */
        static const uint8_t bidi0[] = { 0x08u, 0x01u, 0x00u };

        /* Three parameters, ours in the middle: idle_timeout(0x01), datagram_size(0x20),
         * max_udp_payload(0x03). */
        static const uint8_t three[] = { 0x01u, 0x04u, 0x00u, 0x00u, 0x75u, 0x30u,
                                         0x20u, 0x02u, 0x44u, 0xb0u,
                                         0x03u, 0x02u, 0x44u, 0xb0u };
        static const uint8_t without[] = { 0x01u, 0x04u, 0x00u, 0x00u, 0x75u, 0x30u,
                                           0x03u, 0x02u, 0x44u, 0xb0u };

        lc_buf_init(&b, mem, sizeof mem);
        write_params_without_datagram_size(&b, three, sizeof three);
        size_t g = grease_len(mem, b.len);
        expect(g > 0 && b.len - g == sizeof bidi0 + sizeof without &&
                   memcmp(mem + g, bidi0, sizeof bidi0) == 0 &&
                   memcmp(mem + g + sizeof bidi0, without, sizeof without) == 0,
               "the datagram size is dropped and its neighbours pass through untouched");

        /* The same identifier written as a two-byte varint, which QUIC permits and a peer may
         * choose. Comparing bytes rather than the decoded value would let this one through. */
        static const uint8_t wide[] = { 0x40u, 0x20u, 0x02u, 0x44u, 0xb0u,
                                        0x03u, 0x02u, 0x44u, 0xb0u };
        lc_buf_init(&b, mem, sizeof mem);
        write_params_without_datagram_size(&b, wide, sizeof wide);
        g = grease_len(mem, b.len);
        expect(g > 0 && b.len - g == sizeof bidi0 + 4 &&
                   memcmp(mem + g, bidi0, sizeof bidi0) == 0 &&
                   memcmp(mem + g + sizeof bidi0, wide + 5, 4) == 0,
               "and dropped however the identifier is encoded, not only in its shortest form");

        /* Nothing of ours in it: out comes exactly what went in, plus the synthesised entry. */
        lc_buf_init(&b, mem, sizeof mem);
        write_params_without_datagram_size(&b, without, sizeof without);
        g = grease_len(mem, b.len);
        expect(g > 0 && b.len - g == sizeof bidi0 + sizeof without &&
                   memcmp(mem + g, bidi0, sizeof bidi0) == 0 &&
                   memcmp(mem + g + sizeof bidi0, without, sizeof without) == 0,
               "parameters with nothing to drop are copied unchanged");

        /* The entry lands in the ORDER's place for 0x08, not at either end. 0x04 precedes it and
         * 0x09 follows it in quic-go's Marshal, and a blob carrying both proves the position rather
         * than merely the presence — appending would satisfy the three cases above. */
        static const uint8_t around[] = { 0x09u, 0x02u, 0x40u, 0x64u,
                                          0x04u, 0x04u, 0x81u, 0x40u, 0x00u, 0x00u };
        static const uint8_t ordered[] = { 0x04u, 0x04u, 0x81u, 0x40u, 0x00u, 0x00u,
                                           0x08u, 0x01u, 0x00u,
                                           0x09u, 0x02u, 0x40u, 0x64u };
        lc_buf_init(&b, mem, sizeof mem);
        write_params_without_datagram_size(&b, around, sizeof around);
        g = grease_len(mem, b.len);
        expect(g > 0 && b.len - g == sizeof ordered &&
                   memcmp(mem + g, ordered, sizeof ordered) == 0,
               "and it is written between initial_max_data and the uni stream limit, as Marshal has it");

        /* And it is SYNTHESISED, not added: a blob that already carries 0x08 is copied through once
         * and keeps its own value. Nothing in this client produces such a blob today — ngtcp2 emits
         * the entry only for a non-zero limit — but the encoder should not start duplicating
         * entries the day one does. */
        static const uint8_t has_bidi[] = { 0x08u, 0x02u, 0x40u, 0x64u,
                                            0x03u, 0x02u, 0x44u, 0xb0u };
        lc_buf_init(&b, mem, sizeof mem);
        write_params_without_datagram_size(&b, has_bidi, sizeof has_bidi);
        g = grease_len(mem, b.len);
        expect(g > 0 && b.len - g == sizeof has_bidi &&
                   memcmp(mem + g, has_bidi, sizeof has_bidi) == 0,
               "a limit ngtcp2 did encode is passed through, not written twice");

        /* A blob that parses for one entry and then does not — the last length claims two bytes with
         * one left. It is REFUSED, and that is the change this case now records.
         *
         * It used to be copied through whole, on the argument that sending something ngtcp2 produced
         * beats sending nothing. That was this tree's invention: quic-go's Marshal has no such path
         * because it never receives a blob — it writes the list it holds. And the argument was weak
         * on its own terms, since a blob that does not parse means this code is wrong about output
         * it produced a moment earlier, and the answer to being wrong is to stop rather than to put
         * a guess on the wire. */
        static const uint8_t cut[] = { 0x01u, 0x04u, 0x00u, 0x00u, 0x75u, 0x30u,
                                       0x03u, 0x02u, 0x44u };
        lc_buf_init(&b, mem, sizeof mem);
        expect(write_params_without_datagram_size(&b, cut, sizeof cut) != 0,
               "and a blob that stops parsing halfway is refused, not guessed at");
    }

    /* A HelloRetryRequest IS ANSWERED, as the reference answers it (processHelloRetryRequest,
     * GOROOT/src/crypto/tls/handshake_client_tls13.go:235-412, go1.25.14). Until 2026-09-24 this
     * plane stopped where the reference sends a second hello — on a first flight whose keys come
     * from a connection id in the clear, so anyone on the path could make it stop.
     *
     * The second hello is the first one re-marshalled: every byte the same up to key_share, the
     * cookie echoed just ahead of it, and the share replaced by one for the group named. What the
     * reference's own second hello looks like on the wire is tools/vendorcap/qstand's to show. */
    {
        static const uint8_t params[] = { 0x0fu, 0x02u, 0xaau, 0xbbu };
        static lc_qtls       s;
        lc_qtls_sink         sink = { NULL, sink_send, sink_secret, sink_secret };
        static uint8_t       ch1[4096], msg[70000];
        size_t               ch1_len = 0, n, exts1 = 0, exts2 = 0;
        static const uint8_t cookie[] = { 0xc0, 0x0c, 0x1e, 0x55, 0x01, 0x02, 0x03 };

#define HRR_START()                                                                             \
    (lc_qtls_start(&s, &sink, "node.example", params, sizeof params, NULL, 0) == 0 &&            \
     (memcpy(ch1, sink_hello, sink_hello_len), ch1_len = sink_hello_len, 1))

        if (HRR_START()) {
            n = put_sh(msg, 1, 0x1301u, LC_GROUP_SECP256R1, NULL, 0, cookie, sizeof cookie, 0);
            expect(lc_qtls_recv(&s, LC_QTLS_INITIAL, msg, n) == 0 && s.retried == 1 &&
                       s.expect == LC_QX_SERVER_HELLO && s.read_level == LC_QTLS_INITIAL,
                   "a retry naming secp256r1 with a cookie is answered, and a ServerHello is "
                   "expected again at the same level");
            size_t ks1 = ch_ext(ch1, ch1_len, 0x0033u, &exts1);
            size_t ck2 = ch_ext(sink_hello, sink_hello_len, 0x002cu, &exts2);
            size_t ks2 = ch_ext(sink_hello, sink_hello_len, 0x0033u, &exts2);
            expect(ks1 != 0u && ks1 == ck2 && exts1 == exts2 &&
                       memcmp(ch1 + 4, sink_hello + 4, exts1 - 4u) == 0 &&
                       memcmp(ch1 + exts1 + 2u, sink_hello + exts2 + 2u, ks1 - exts1 - 2u) == 0,
                   "the second hello is the first up to key_share, the random included");
            expect(ck2 != 0u && sink_hello[ck2 + 3u] == sizeof cookie + 2u &&
                       memcmp(sink_hello + ck2 + 6u, cookie, sizeof cookie) == 0 &&
                       ks2 == ck2 + 6u + sizeof cookie,
                   "the cookie comes back verbatim, directly ahead of key_share");
            expect(ks2 != 0u && sink_hello[ks2 + 6u] == 0x00 && sink_hello[ks2 + 7u] == 0x17 &&
                       sink_hello[ks2 + 9u] == LC_P256_POINT &&
                       sink_hello[ks2 + 10u] == 0x04 &&
                       ks2 + 10u + LC_P256_POINT == sink_hello_len,
                   "and key_share is one uncompressed secp256r1 point, the hello's last bytes");
            size_t body = (size_t)sink_hello[1] << 16 | (size_t)sink_hello[2] << 8 | sink_hello[3];
            size_t exts = (size_t)sink_hello[exts2] << 8 | sink_hello[exts2 + 1u];
            expect(body == sink_hello_len - 4u && exts == sink_hello_len - exts2 - 2u,
                   "with both lengths rewritten to what the second hello holds");

            /* The answering ServerHello, with a real secp256r1 point: the key the retry made is the
             * key the schedule then uses. */
            uint8_t spriv[LC_P256_KEY], spub[LC_P256_POINT];
            (void)lc_p256_keygen(spriv, spub);
            n = put_sh(msg, 0, 0x1301u, LC_GROUP_SECP256R1, spub, sizeof spub, NULL, 0, 0);
            expect(lc_qtls_recv(&s, LC_QTLS_INITIAL, msg, n) == 0 && s.keys_installed == 1 &&
                       s.read_level == LC_QTLS_HANDSHAKE,
                   "a ServerHello with the secp256r1 share installs the handshake keys");
        } else {
            expect(0, "a handshake starts");
        }
        lc_qtls_free(&s);

        /* A retry that only asks for a cookie keeps the first hello's key shares exactly. */
        if (HRR_START()) {
            n = put_sh(msg, 1, 0x1301u, 0u, NULL, 0, cookie, sizeof cookie, 0);
            size_t ks1 = ch_ext(ch1, ch1_len, 0x0033u, &exts1);
            expect(lc_qtls_recv(&s, LC_QTLS_INITIAL, msg, n) == 0 &&
                       sink_hello_len == ch1_len + 6u + sizeof cookie &&
                       memcmp(sink_hello + ks1 + 6u + sizeof cookie, ch1 + ks1, ch1_len - ks1) == 0,
                   "a cookie-only retry re-sends both key shares as they were, the cookie ahead");
        }
        lc_qtls_free(&s);

        /* What the reference refuses, each with its number. */
        static const struct {
            uint16_t    group;
            int         full, with_cookie, ech;
            uint8_t     want;
            const char *what;
        } refused[] = {
            { LC_GROUP_X25519, 0, 0, 0, LC_ALERT_ILLEGAL_PARAMETER,
              "a retry for x25519, which the hello already shared, is illegal_parameter" },
            { LC_GROUP_X25519MLKEM768, 0, 0, 0, LC_ALERT_ILLEGAL_PARAMETER,
              "and one for X25519MLKEM768 likewise" },
            { 0x0099u, 0, 0, 0, LC_ALERT_ILLEGAL_PARAMETER,
              "a retry for a group the hello never offered is illegal_parameter" },
            { 0u, 0, 0, 0, LC_ALERT_ILLEGAL_PARAMETER,
              "a retry that changes nothing is illegal_parameter" },
            /* With a cookie: without one, the full form leaves selectedGroup empty and the retry
             * "changes nothing" - 47, one check ahead of this one. */
            { LC_GROUP_SECP256R1, 1, 1, 0, LC_ALERT_DECODE_ERROR,
              "a retry carrying a full key share is decode_error" },
            { LC_GROUP_SECP256R1, 0, 0, 1, LC_ALERT_UNSUPPORTED_EXTENSION,
              "a retry carrying encrypted_client_hello is unsupported_extension" },
        };
        for (size_t c = 0; c < sizeof refused / sizeof refused[0]; c++) {
            if (!HRR_START()) {
                expect(0, "a handshake starts");
                continue;
            }
            static const uint8_t pt[LC_P256_POINT] = { 0x04 };
            n = put_sh(msg, 1, 0x1301u, refused[c].group, refused[c].full ? pt : NULL,
                       refused[c].full ? sizeof pt : 0, refused[c].with_cookie ? cookie : NULL,
                       refused[c].with_cookie ? sizeof cookie : 0, refused[c].ech);
            expect(lc_qtls_recv(&s, LC_QTLS_INITIAL, msg, n) != 0 &&
                       lc_qtls_alert(&s) == refused[c].want,
                   refused[c].what);
            lc_qtls_free(&s);
        }

        /* And after the retry, the ServerHello the reference would refuse. */
        static const struct {
            int         retry;
            uint16_t    suite, group;
            size_t      share_len;
            int         bad_point;
            uint8_t     want;
            const char *what;
        } after[] = {
            { 1, 0x1301u, LC_GROUP_SECP256R1, 0u, 0, LC_ALERT_UNEXPECTED_MESSAGE,
              "a second retry is unexpected_message" },
            { 0, 0x1302u, LC_GROUP_SECP256R1, LC_P256_POINT, 0, LC_ALERT_ILLEGAL_PARAMETER,
              "a ServerHello that changes the suite the retry chose is illegal_parameter" },
            { 0, 0x1301u, LC_GROUP_X25519, LC_X25519_KEY, 0, LC_ALERT_ILLEGAL_PARAMETER,
              "an x25519 answer to a hello that now shares only secp256r1 is illegal_parameter" },
            { 0, 0x1301u, LC_GROUP_SECP256R1, LC_P256_POINT - 1u, 0, LC_ALERT_ILLEGAL_PARAMETER,
              "a secp256r1 share one byte short is illegal_parameter" },
            { 0, 0x1301u, LC_GROUP_SECP256R1, LC_P256_POINT, 1, LC_ALERT_ILLEGAL_PARAMETER,
              "and a point that is not on the curve is illegal_parameter too" },
        };
        for (size_t c = 0; c < sizeof after / sizeof after[0]; c++) {
            if (!HRR_START()) {
                expect(0, "a handshake starts");
                continue;
            }
            n = put_sh(msg, 1, 0x1301u, LC_GROUP_SECP256R1, NULL, 0, NULL, 0, 0);
            if (lc_qtls_recv(&s, LC_QTLS_INITIAL, msg, n) != 0) {
                expect(0, "the retry is answered");
                lc_qtls_free(&s);
                continue;
            }
            uint8_t share[LC_P256_POINT], priv[LC_P256_KEY];
            (void)lc_p256_keygen(priv, share);
            if (after[c].bad_point)
                share[LC_P256_POINT - 1u] ^= 0x01u;
            n = put_sh(msg, after[c].retry, after[c].suite, after[c].group,
                       after[c].retry ? NULL : share, after[c].share_len, NULL, 0, 0);
            expect(lc_qtls_recv(&s, LC_QTLS_INITIAL, msg, n) != 0 &&
                       lc_qtls_alert(&s) == after[c].want,
                   after[c].what);
            lc_qtls_free(&s);
        }

        /* A cookie that the second hello's extensions cannot hold: Go's marshal fails, and the
         * handshake ends on that error, with no alert of its own — internal_error on the wire, as
         * quicError gives any error that carries none (GOROOT/src/crypto/tls/quic.go:358-373). */
        if (HRR_START()) {
            static uint8_t big[64500];
            memset(big, 0x33, sizeof big);
            n = put_sh(msg, 1, 0x1301u, 0u, NULL, 0, big, sizeof big, 0);
            expect(lc_qtls_recv(&s, LC_QTLS_INITIAL, msg, n) != 0 && lc_qtls_alert(&s) == 0u,
                   "a cookie too large for the second hello ends it without an alert of our own");
        }
        lc_qtls_free(&s);
#undef HRR_START
    }

    /* WHILE PARROTING CHROME THE HANDSHAKE IS READ AS uTLS READS IT, and each case below is one
     * place where that gives a different answer from the standard library, or a message the
     * standard library never meets. The references are cited where qtls.c decides each. */
    {
        static const uint8_t params[] = { 0x0fu, 0x00u, 0x01u, 0x04u, 0x80u, 0x00u, 0x75u, 0x30u,
                                          0x03u, 0x02u, 0x45u, 0xc0u, 0x04u, 0x04u, 0x80u, 0xf0u,
                                          0x00u, 0x00u, 0x05u, 0x04u, 0x80u, 0x60u, 0x00u, 0x00u,
                                          0x06u, 0x04u, 0x80u, 0x60u, 0x00u, 0x00u, 0x07u, 0x04u,
                                          0x80u, 0x60u, 0x00u, 0x00u, 0x08u, 0x02u, 0x40u, 0x64u,
                                          0x09u, 0x02u, 0x40u, 0x67u, 0x20u, 0x04u, 0x80u, 0x01u,
                                          0x00u, 0x00u };
        static lc_qtls s;
        lc_qtls_sink   sink = { NULL, sink_send, sink_secret, sink_secret };
        static uint8_t ch1[4096], msg[4096];
        size_t         ch1_len = 0, n;

#define CSTART()                                                                                  \
    (lc_qtls_start(&s, &sink, "node.example", params, sizeof params, NULL, LC_QTLS_CHROME) == 0 &&  \
     (memcpy(ch1, sink_hello, sink_hello_len), ch1_len = sink_hello_len, 1))

        /* EncryptedExtensions carrying ALPN h3 and the parameters, then what is varied. */
        static const uint8_t ee_ok[] = { 0x08, 0x00, 0x00, 0x11, 0x00, 0x0f, 0x00, 0x10,
                                         0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x33, 0x00,
                                         0x39, 0x00, 0x02, 0x40, 0x01 };
        static const uint8_t ee_bad[] = { 0x08, 0x00, 0x00, 0x06, 0x00, 0x04, 0x00, 0x10,
                                          0x00, 0x09 };
        static const uint8_t ee_no_params[] = { 0x08, 0x00, 0x00, 0x0b, 0x00, 0x09, 0x00, 0x10,
                                                0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x33 };
        static const uint8_t ee_no_alpn[] = { 0x08, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00, 0x39,
                                              0x00, 0x02, 0x40, 0x01 };
        static const uint8_t ee_alps[] = { 0x08, 0x00, 0x00, 0x15, 0x00, 0x13, 0x00, 0x10,
                                           0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x33, 0x00,
                                           0x39, 0x00, 0x02, 0x40, 0x01, 0x44, 0xcd, 0x00,
                                           0x00 };

        if (CSTART()) {
            expect(lc_qtls_recv(&s, LC_QTLS_INITIAL, srv_msg_serverhello,
                                sizeof srv_msg_serverhello) == 0 &&
                       s.read_level == LC_QTLS_HANDSHAKE,
               "Chrome: the captured ServerHello answers the Chrome hello, x25519 on its own key");
            expect(lc_qtls_recv(&s, LC_QTLS_HANDSHAKE, ee_bad, sizeof ee_bad) != 0 &&
                       lc_qtls_alert(&s) == LC_ALERT_UNEXPECTED_MESSAGE,
                   "Chrome: an EncryptedExtensions that does not parse is 10, where stdlib says 50");
        }
        lc_qtls_free(&s);

        static const struct {
            const uint8_t *ee;
            size_t         len;
            uint8_t        want;
            const char    *what;
        } ees[] = {
            { ee_no_params, sizeof ee_no_params, LC_ALERT_MISSING_EXTENSION,
              "Chrome: EncryptedExtensions without the transport parameters is 109" },
            { ee_no_alpn, sizeof ee_no_alpn, LC_ALERT_NO_APPLICATION_PROTOCOL,
              "Chrome: and without a protocol chosen, over QUIC, 120" },
            { ee_ok, sizeof ee_ok, 0u, "Chrome: ALPN h3 and the parameters are taken" },
        };
        for (size_t c = 0; c < sizeof ees / sizeof ees[0]; c++) {
            if (!CSTART())
                continue;
            (void)lc_qtls_recv(&s, LC_QTLS_INITIAL, srv_msg_serverhello,
                               sizeof srv_msg_serverhello);
            int rc = lc_qtls_recv(&s, LC_QTLS_HANDSHAKE, ees[c].ee, ees[c].len);
            expect(ees[c].want == 0u ? rc == 0 && s.params_fresh == 1 && s.alps_answer_len == 0u
                                     : rc != 0 && lc_qtls_alert(&s) == ees[c].want,
                   ees[c].what);
            lc_qtls_free(&s);
        }

        if (CSTART()) {
            (void)lc_qtls_recv(&s, LC_QTLS_INITIAL, srv_msg_serverhello,
                               sizeof srv_msg_serverhello);
            expect(lc_qtls_recv(&s, LC_QTLS_HANDSHAKE, ee_alps, sizeof ee_alps) == 0 &&
                       s.alps_answer_len == LC_ALPS_ANSWER_LEN && s.alps_answer[0] == 0x08 &&
                       s.alps_answer[6] == 0x44 && s.alps_answer[7] == 0xcd,
                   "Chrome: a server's ALPS is taken, and an EncryptedExtensions of ours is owed for "
                   "it at the new codepoint");
        }
        lc_qtls_free(&s);

        /* Bytes after the ServerHello are read on under the parrot, not refused. */
        if (CSTART()) {
            static uint8_t two[sizeof srv_msg_serverhello + sizeof ee_ok];
            memcpy(two, srv_msg_serverhello, sizeof srv_msg_serverhello);
            memcpy(two + sizeof srv_msg_serverhello, ee_ok, sizeof ee_ok);
            expect(lc_qtls_recv(&s, LC_QTLS_INITIAL, two, sizeof two) == 0 &&
                       s.read_level == LC_QTLS_HANDSHAKE && s.expect == LC_QX_CERTIFICATE,
                   "Chrome: an EncryptedExtensions after the ServerHello in the same Initial data is "
                   "read as the next message, as uTLS reads its buffer");
        }
        lc_qtls_free(&s);

        /* A compressed certificate in an algorithm the Chrome hello did not offer: 42. */
        if (CSTART()) {
            (void)lc_qtls_recv(&s, LC_QTLS_INITIAL, srv_msg_serverhello,
                               sizeof srv_msg_serverhello);
            (void)lc_qtls_recv(&s, LC_QTLS_HANDSHAKE, ee_ok, sizeof ee_ok);
            static const uint8_t zlib_cc[] = { LC_HS_COMPRESSED_CERTIFICATE, 0x00, 0x00, 0x0a,
                                               0x00, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x02,
                                               0x78, 0x9c };
            expect(lc_qtls_recv(&s, LC_QTLS_HANDSHAKE, zlib_cc, sizeof zlib_cc) != 0 &&
                       lc_qtls_alert(&s) == LC_ALERT_BAD_CERTIFICATE,
                   "Chrome: a certificate compressed with zlib, which the hello did not offer, is 42");
        }
        lc_qtls_free(&s);

        /* The retry, as uTLS answers it: the key share replaced where it stands, the cookie at a
         * drawn index, everything else — the permuted order, the random — carried over; and P-521,
         * which the Chrome hello does not offer, refused. */
        static const uint8_t cookie[] = { 0xc0, 0x0c, 0x1e, 0x55, 0x01, 0x02, 0x03 };
        unsigned at_seen = 0;
        unsigned extension_count = 0;
        int      shape_ok = 1;
        for (int k = 0; k < 40 && shape_ok; k++) {
            if (!CSTART()) {
                shape_ok = 0;
                break;
            }
            n = put_sh(msg, 1, 0x1301u, LC_GROUP_SECP256R1, NULL, 0, cookie, sizeof cookie, 0);
            if (lc_qtls_recv(&s, LC_QTLS_INITIAL, msg, n) != 0 || s.retried != 1) {
                shape_ok = 0;
                break;
            }
            size_t exts1 = 0, exts2 = 0;
            size_t ck = ch_ext(sink_hello, sink_hello_len, 0x002cu, &exts2);
            size_t ks = ch_ext(sink_hello, sink_hello_len, 0x0033u, &exts2);
            (void)ch_ext(ch1, ch1_len, 0x0033u, &exts1);
            extension_count = 0;
            for (size_t at = exts1 + 2u; at + 4u <= ch1_len; extension_count++)
                at += 4u + ((size_t)ch1[at + 2u] << 8 | ch1[at + 3u]);
            /* Random and session id carried over; the cookie verbatim; the share one P-256 point. */
            shape_ok = ck != 0u && ks != 0u && memcmp(ch1 + 6, sink_hello + 6, 32) == 0 &&
                       memcmp(sink_hello + ck + 6u, cookie, sizeof cookie) == 0 &&
                       sink_hello[ks + 6u] == 0x00 && sink_hello[ks + 7u] == 0x17 &&
                       sink_hello[ks + 3u] == 6u + LC_P256_POINT;
            /* Which extension the cookie went in front of: its index among the others. */
            unsigned idx = 0;
            for (size_t at = exts2 + 2u; at < ck; idx++)
                at += 4u + ((size_t)sink_hello[at + 2u] << 8 | sink_hello[at + 3u]);
            at_seen |= 1u << idx;
            lc_qtls_free(&s);
        }
        lc_qtls_free(&s);
        expect(shape_ok, "Chrome: a retry for P-256 keeps the random, echoes the cookie, and "
                         "carries one P-256 share");
        /* uTLS draws over [0, len(Extensions)-2). The 2.13.0 hello adds trust_anchors;
         * derive the bound from the actual first hello instead of the old eleven-field profile. */
        unsigned allowed = extension_count > 2u && extension_count <= 32u
                               ? (1u << (extension_count - 2u)) - 1u : 0u;
        expect(allowed != 0u && (at_seen & ~allowed) == 0u && __builtin_popcount(at_seen) >= 5,
               "Chrome: the cookie lands at a drawn index, never among the last two");

        if (CSTART()) {
            n = put_sh(msg, 1, 0x1301u, LC_GROUP_SECP521R1, NULL, 0, NULL, 0, 0);
            expect(lc_qtls_recv(&s, LC_QTLS_INITIAL, msg, n) != 0 &&
                       lc_qtls_alert(&s) == LC_ALERT_ILLEGAL_PARAMETER,
                   "Chrome: a retry for P-521, which the Chrome hello does not offer, is 47");
        }
        lc_qtls_free(&s);

        /* After the handshake: thirty-two tickets are dropped, the thirty-third is 10, and so is a
         * KeyUpdate and anything else — uTLS's count and its one answer. */
        {
            static lc_qtls p;
            static const uint8_t nst[] = { LC_HS_NEW_SESSION_TICKET, 0x00, 0x00, 0x0e,
                                           0x00, 0x00, 0x0e, 0x10, 0x01, 0x02, 0x03, 0x04,
                                           0x00, 0x00, 0x01, 0xaa, 0x00, 0x00 };
            static const uint8_t ku[] = { LC_HS_KEY_UPDATE, 0x00, 0x00, 0x01, 0x00 };
            memset(&p, 0, sizeof p);
            p.chrome = 1;
            p.done = 1;
            p.read_level = LC_QTLS_APPLICATION;
            p.partial = p.partial_inline;
            p.partial_cap = sizeof p.partial_inline;
            int all = 1;
            for (int k = 0; k < 32; k++)
                all = all && lc_qtls_recv(&p, LC_QTLS_APPLICATION, nst, sizeof nst) == 0;
            expect(all && lc_qtls_recv(&p, LC_QTLS_APPLICATION, nst, sizeof nst) != 0 &&
                       lc_qtls_alert(&p) == LC_ALERT_UNEXPECTED_MESSAGE,
                   "Chrome: thirty-two tickets are dropped and the thirty-third is 10");
            lc_qtls_free(&p);
            memset(&p, 0, sizeof p);
            p.chrome = 1;
            p.done = 1;
            p.read_level = LC_QTLS_APPLICATION;
            p.partial = p.partial_inline;
            p.partial_cap = sizeof p.partial_inline;
            expect(lc_qtls_recv(&p, LC_QTLS_APPLICATION, ku, sizeof ku) != 0 &&
                       lc_qtls_alert(&p) == LC_ALERT_UNEXPECTED_MESSAGE,
                   "Chrome: a KeyUpdate after the handshake is 10, as on QUIC it has no place");
            lc_qtls_free(&p);
        }

        /* READ, THEN COUNTED, THEN JUDGED — uTLS's readHandshake before the count and the type
         * (vendor/utls/u_conn.go:957-984): a known message that does not unmarshal is sendAlert's
         * error, "local error: tls: unexpected message", even past the thirty-second message; one
         * that does is "received unexpected handshake message of type %T". The reader is uTLS's:
         * EncryptedExtensions with an extension twice reads there and not in the standard library,
         * and CompressedCertificate is its own. Until 2026-09-29 a known type that did not read was
         * judged as one that did (Q7). */
        {
            static lc_qtls p;
            static const uint8_t nst[] = { LC_HS_NEW_SESSION_TICKET, 0x00, 0x00, 0x0e,
                                           0x00, 0x00, 0x0e, 0x10, 0x01, 0x02, 0x03, 0x04,
                                           0x00, 0x00, 0x01, 0xaa, 0x00, 0x00 };
            static const uint8_t cr_ok[] = { LC_HS_CERTIFICATE_REQUEST, 0, 0, 3, 0, 0, 0 };
            static const uint8_t cr_bad[] = { LC_HS_CERTIFICATE_REQUEST, 0, 0, 2, 0, 0 };
            static const uint8_t ee_twice[] = { LC_HS_ENCRYPTED_EXT, 0, 0, 10, 0, 8,
                                                0xfe, 0x01, 0, 0, 0xfe, 0x01, 0, 0 };
            static const uint8_t cc_ok[] = { LC_HS_COMPRESSED_CERTIFICATE, 0, 0, 8, 0, 2, 0, 0, 16,
                                             0, 0, 0 };
            static const uint8_t cc_bad[] = { LC_HS_COMPRESSED_CERTIFICATE, 0, 0, 8, 0, 2, 0, 0, 16,
                                              0, 0, 1 };
            static const struct {
                const uint8_t *m;
                size_t         len;
                int            tickets;
                const char    *go, *what;
            } pc[] = {
                { cr_bad, sizeof cr_bad, 0, "local error: tls: unexpected message",
                  "Chrome: a CertificateRequest that does not read, in uTLS's words for it" },
                { cr_bad, sizeof cr_bad, 32, "local error: tls: unexpected message",
                  "Chrome: and after thirty-two tickets too, since it is read before it is counted" },
                { cr_ok, sizeof cr_ok, 0,
                  "tls: received unexpected handshake message of type *tls.certificateRequestMsgTLS13",
                  "Chrome: a CertificateRequest that reads is named by its type" },
                { ee_twice, sizeof ee_twice, 0,
                  "tls: received unexpected handshake message of type *tls.encryptedExtensionsMsg",
                  "Chrome: EncryptedExtensions with an extension twice reads, as uTLS reads it" },
                { cc_ok, sizeof cc_ok, 0,
                  "tls: received unexpected handshake message of type *tls.utlsCompressedCertificateMsg",
                  "Chrome: a CompressedCertificate that reads is named by its type" },
                { cc_bad, sizeof cc_bad, 0, "local error: tls: unexpected message",
                  "Chrome: one whose block runs past the message does not read" },
            };
            for (size_t i = 0; i < sizeof pc / sizeof pc[0]; i++) {
                memset(&p, 0, sizeof p);
                p.chrome = 1;
                p.done = 1;
                p.read_level = LC_QTLS_APPLICATION;
                p.partial = p.partial_inline;
                p.partial_cap = sizeof p.partial_inline;
                int all = 1;
                for (int k = 0; k < pc[i].tickets; k++)
                    all = all && lc_qtls_recv(&p, LC_QTLS_APPLICATION, nst, sizeof nst) == 0;
                expect(all && lc_qtls_recv(&p, LC_QTLS_APPLICATION, pc[i].m, pc[i].len) != 0 &&
                           lc_qtls_alert(&p) == LC_ALERT_UNEXPECTED_MESSAGE &&
                           strcmp(lc_qtls_go_error(&p), pc[i].go) == 0,
                       pc[i].what);
                lc_qtls_free(&p);
            }

            /* Without the parrot the reader is the standard library's, and its answer to a known
             * message that does not unmarshal is decode_error, before the count as well
             * (GOROOT/src/crypto/tls/conn.go:1185-1187, :1314-1322, go1.25.14). */
            for (int tickets = 0; tickets <= 16; tickets += 16) {
                memset(&p, 0, sizeof p);
                p.done = 1;
                p.read_level = LC_QTLS_APPLICATION;
                p.partial = p.partial_inline;
                p.partial_cap = sizeof p.partial_inline;
                int all = 1;
                for (int k = 0; k < tickets; k++)
                    all = all && lc_qtls_recv(&p, LC_QTLS_APPLICATION, nst, sizeof nst) == 0;
                expect(all && lc_qtls_recv(&p, LC_QTLS_APPLICATION, cr_bad, sizeof cr_bad) != 0 &&
                           lc_qtls_alert(&p) == LC_ALERT_DECODE_ERROR,
                       tickets ? "a CertificateRequest that does not parse after sixteen tickets: "
                                 "still decode_error"
                               : "a CertificateRequest after the handshake that does not parse is "
                                 "decode_error");
                lc_qtls_free(&p);
            }
            memset(&p, 0, sizeof p);
            p.done = 1;
            p.read_level = LC_QTLS_APPLICATION;
            p.partial = p.partial_inline;
            p.partial_cap = sizeof p.partial_inline;
            expect(lc_qtls_recv(&p, LC_QTLS_APPLICATION, cr_ok, sizeof cr_ok) != 0 &&
                       lc_qtls_alert(&p) == LC_ALERT_UNEXPECTED_MESSAGE,
                   "and one that parses is unexpected_message");
            lc_qtls_free(&p);
        }
#undef CSTART
    }

    /* A MESSAGE THE FLIGHT DID NOT EXPECT IS UNMARSHALLED BEFORE IT IS REFUSED, and the number
     * depends on how that went: the reference hands every message to unmarshalHandshakeMessage
     * before the handshake asserts its type, so a type it has no message for is 10, one that does
     * not unmarshal is 50, and one that does is 10 again at the assertion
     * (GOROOT/src/crypto/tls/conn.go:1127-1193, go1.25.14). Until 2026-09-24 every one of them was
     * 10 here. test/qpin/reference_misplaced.h is the reference's own answer for each message, at
     * both versions the reader can be at — tools/misplaced ran it. */
    {
        unsigned bad = 0;
        size_t   n = sizeof mp_cases / sizeof mp_cases[0];
        for (size_t i = 0; i < n; i++) {
            uint8_t got = lc_std_misplaced_alert(mp_pool + mp_cases[i].off, mp_cases[i].len,
                                                 mp_cases[i].tls13);
            if ((int)got != mp_cases[i].alert) {
                if (bad < 8)
                    printf("  FAIL  type %u, %u bytes, %s: the reference answers %d, this %u\n",
                           (unsigned)mp_pool[mp_cases[i].off], (unsigned)mp_cases[i].len,
                           mp_cases[i].tls13 ? "TLS 1.3" : "before the ServerHello",
                           mp_cases[i].alert, (unsigned)got);
                bad++;
            }
        }
        char what[128];
        snprintf(what, sizeof what, "%u misplaced messages: every answer the reference's",
                 (unsigned)n);
        expect(bad == 0, what);

        /* And through the state machine, where it is decided: a Certificate at the Initial level,
         * where a ServerHello is expected, before the version is known. */
        static const uint8_t params[] = { 0x0fu, 0x02u, 0xaau, 0xbbu };
        static lc_qtls       s;
        lc_qtls_sink         sink = { NULL, sink_send, sink_secret, sink_secret };
        static const uint8_t cert_ok[] = { LC_HS_CERTIFICATE, 0, 0, 3, 0, 0, 0 };
        static const uint8_t cert_bad[] = { LC_HS_CERTIFICATE, 0, 0, 2, 0, 0 };
        if (lc_qtls_start(&s, &sink, "node.example", params, sizeof params, NULL, 0) == 0) {
            expect(lc_qtls_recv(&s, LC_QTLS_INITIAL, cert_ok, sizeof cert_ok) != 0 &&
                       lc_qtls_alert(&s) == LC_ALERT_UNEXPECTED_MESSAGE,
                   "a well-formed Certificate where the ServerHello belongs is unexpected_message");
        }
        lc_qtls_free(&s);
        if (lc_qtls_start(&s, &sink, "node.example", params, sizeof params, NULL, 0) == 0) {
            expect(lc_qtls_recv(&s, LC_QTLS_INITIAL, cert_bad, sizeof cert_bad) != 0 &&
                       lc_qtls_alert(&s) == LC_ALERT_DECODE_ERROR,
                   "and one that does not unmarshal is decode_error, as the reference answers it");
        }
        lc_qtls_free(&s);
    }

    printf("\n%s\n",
           failures == 0 ? "the pin decides, and decides before anything is sent"
                         : "the pin does not decide");
    return failures == 0 ? 0 : 1;
}
