/* CertificateVerify: the one message that proves the peer holds the key in the certificate it sent.
 *
 * ⚠️ THIS CHECK HAS BEEN ABSENT BEFORE. src/tls/certverify.h says so at the top: the REALITY plane
 * folded the message into the transcript and did nothing else, so an active prober could answer our
 * hello with any certificate and a signature of pure noise, and this client carried on where an Xray
 * one has already sent decrypt_error and stopped. The check exists now. Nothing held it.
 *
 * The positive cases are the point. A verifier that always refuses passes every negative case in
 * this file, and "always refuses" is not a quiet failure — handshakes stop, someone loosens the
 * check, and the loosening is what nobody tests. So the signatures below are real, made by Go over
 * the exact bytes RFC 8446 4.4.3 names, and this client has to accept them.
 *
 * Signed by Go rather than by this tree, which is what makes them evidence: a vector produced with
 * the code under test would agree with itself whatever that code did. tools/certverify. */

#include "cert/cert.h"
#include "tls/certverify.h"
#include "tls/hkdf.h"

#include "certverify_vectors.h"
#include "mldsacv_vectors.h"

#include <stdio.h>
#include <string.h>

static int fails;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        fails++;
}

static char    err[256];
static uint8_t alert;
/* uTLS's words for the refusal: what the QUIC plane closes with under the Chrome parrot. */
static char    gotext[256];

/* Which reference a case is asked under: 0 for uTLS, the REALITY plane's; 1 for the standard
 * library, the QUIC plane's. */
static int plane_stdlib;

static int verify(const unsigned char *cert, unsigned cert_len, const unsigned char *body,
                  unsigned body_len)
{
    err[0] = '\0';
    alert = 0xffu;
    return lc_cert_verify(cert, cert_len, LC_SHA256, cv_transcript, body, body_len, plane_stdlib, !plane_stdlib,
                          err, sizeof err, &alert, gotext, sizeof gotext);
}

int main(void)
{
    printf("the peer's proof that it holds the key it showed\n");

    /* ---- the signatures that must be accepted ---- */
    ok(verify(cv_ed_cert, cv_ed_cert_len, cv_ed_body, cv_ed_body_len) == 0,
       "an ed25519 signature Go made over the right content verifies");
    ok(verify(cv_ec_cert, cv_ec_cert_len, cv_ec_body, cv_ec_body_len) == 0,
       "and so does an ECDSA P-256 one, which signs a digest rather than the content");
    ok(verify(cv_rsa_cert, cv_rsa_cert_len, cv_rsa_body, cv_rsa_body_len) == 0,
       "and so does an RSA-PSS one of a 2048-bit key");

    /* ---- the floor under an RSA key: Go's since 1.24, in both references ---- */
    for (plane_stdlib = 0; plane_stdlib <= 1; plane_stdlib++) {
        ok(verify(cv_rsa768_cert, cv_rsa768_cert_len, cv_rsa768_body, cv_rsa768_body_len) != 0 &&
               alert == LC_ALERT_DECRYPT_ERROR,
           plane_stdlib ? "a good signature by a 768-bit RSA key is decrypt_error, for the standard library"
                        : "a good signature by a 768-bit RSA key is decrypt_error, for uTLS: "
                          "rsa.VerifyPSS refuses the key before the signature");
        ok(strcmp(gotext, "tls: invalid signature by the server certificate: crypto/rsa: 768-bit keys "
                          "are insecure (see https://go.dev/pkg/crypto/rsa#hdr-Minimum_key_size)") == 0,
           "in Go's words");
    }
    plane_stdlib = 0;

    /* ---- a genuine ECDSA signature, re-encoded: DER as cryptobyte reads it ----
     *
     * ecdsa.VerifyASN1 parses the signature with cryptobyte — minimal lengths, minimal INTEGERs,
     * nothing after the SEQUENCE — and answers false to anything else, so each of these is
     * decrypt_error in the reference though the numbers inside are the right ones. mbedTLS, which
     * judged this until 2026-09-30, took the first two: anybody holding a genuine signature could
     * re-encode it into one this client accepted and the reference refused. */
    {
        const uint8_t *der = cv_ec_body + 4;
        size_t         dn = cv_ec_body_len - 4u;
        /* 30 L 02 Lr r 02 Ls s, short-form lengths: the vector's own shape */
        int shaped = dn >= 8u && der[0] == 0x30u && der[1] == dn - 2u && der[2] == 0x02u;
        ok(shaped, "the vector's signature is a short-form SEQUENCE of two INTEGERs");
        if (shaped) {
            size_t  rl = der[3];
            uint8_t body[200];
            size_t  n;
            for (plane_stdlib = 0; plane_stdlib <= 1; plane_stdlib++) {
                /* r with a zero in front of it: not minimal */
                n = 0;
                body[n++] = cv_ec_body[0];
                body[n++] = cv_ec_body[1];
                body[n++] = 0;
                body[n++] = (uint8_t)(dn + 1u);
                body[n++] = 0x30u;
                body[n++] = (uint8_t)(der[1] + 1u);
                body[n++] = 0x02u;
                body[n++] = (uint8_t)(rl + 1u);
                body[n++] = 0x00u;
                memcpy(body + n, der + 4, dn - 4u);
                n += dn - 4u;
                ok(verify(cv_ec_cert, cv_ec_cert_len, body, (unsigned)n) != 0 && alert == LC_ALERT_DECRYPT_ERROR,
                   "an INTEGER with a needless leading zero is decrypt_error");
                /* the SEQUENCE's length in long form */
                n = 0;
                body[n++] = cv_ec_body[0];
                body[n++] = cv_ec_body[1];
                body[n++] = 0;
                body[n++] = (uint8_t)(dn + 1u);
                body[n++] = 0x30u;
                body[n++] = 0x81u;
                memcpy(body + n, der + 1, dn - 1u);
                n += dn - 1u;
                ok(verify(cv_ec_cert, cv_ec_cert_len, body, (unsigned)n) != 0 && alert == LC_ALERT_DECRYPT_ERROR,
                   "a length in long form under 128 is decrypt_error");
                /* a byte after the SEQUENCE */
                n = 0;
                body[n++] = cv_ec_body[0];
                body[n++] = cv_ec_body[1];
                body[n++] = 0;
                body[n++] = (uint8_t)(dn + 1u);
                memcpy(body + n, der, dn);
                n += dn;
                body[n++] = 0x00u;
                ok(verify(cv_ec_cert, cv_ec_cert_len, body, (unsigned)n) != 0 && alert == LC_ALERT_DECRYPT_ERROR,
                   "a byte after the SEQUENCE is decrypt_error");
                ok(strcmp(gotext, "tls: invalid signature by the server certificate: ECDSA verification failure") == 0,
                   "in Go's words");
            }
            plane_stdlib = 0;
        }
    }

    /* ---- and the ones that must not ---- */

    /* THE CASE THE MESSAGE EXISTS FOR: everything parses, the certificate is real, the signature is
     * a real signature — of a key the certificate does not name. */
    ok(verify(cv_ed_cert, cv_ed_cert_len, cv_ed_body_wrongkey, cv_ed_body_wrongkey_len) != 0,
       "a signature by a key the certificate does not name is refused");
    ok(alert == LC_ALERT_DECRYPT_ERROR,
       "and it leaves as decrypt_error, which is what the reference sends there");

    /* ⚠️ A GENUINE SIGNATURE OVER THE WRONG CONTENT. This is what a verifier that drops the zero
     * byte after the context string, or the sixty-four spaces before it, accepts — and it would
     * reject the real one above, so the two cases together pin the signing input exactly. */
    ok(verify(cv_ed_cert, cv_ed_cert_len, cv_ed_body_otherhash, cv_ed_body_otherhash_len) != 0,
       "a genuine signature over a different transcript is refused");

    /* A scheme this build cannot check must be named as such rather than waved through. */
    {
        unsigned char b[128];
        memcpy(b, cv_ed_body, cv_ed_body_len < sizeof b ? cv_ed_body_len : sizeof b);
        b[0] = 0x02;
        b[1] = 0x01; /* rsa_pkcs1_sha1, which TLS 1.3 does not allow at all */
        ok(verify(cv_ed_cert, cv_ed_cert_len, b, cv_ed_body_len) != 0,
           "a signature scheme this build does not verify is refused");
        ok(alert == LC_ALERT_ILLEGAL_PARAMETER,
           "as illegal_parameter, the alert Go sends for an unsupported scheme");
    }

    /* The length inside the message has to agree with the message. A body that says one thing and
     * carries another does not unmarshal — and each reference has its own number for that:
     * unexpected_message in uTLS (vendor/utls/conn.go:1185-1186), decode_error in the standard
     * library (GOROOT/src/crypto/tls/conn.go:1185-1186). This said decode_error for both, which was
     * the QUIC plane's answer given to the REALITY plane as well. */
    {
        unsigned char b[128];
        memcpy(b, cv_ed_body, cv_ed_body_len < sizeof b ? cv_ed_body_len : sizeof b);
        b[3] = (unsigned char)(b[3] - 1u);
        ok(verify(cv_ed_cert, cv_ed_cert_len, b, cv_ed_body_len) != 0 &&
               alert == LC_ALERT_UNEXPECTED_MESSAGE,
           "a stated signature length that does not match the body is unexpected_message under uTLS");
        plane_stdlib = 1;
        ok(verify(cv_ed_cert, cv_ed_cert_len, b, cv_ed_body_len) != 0 && alert == LC_ALERT_DECODE_ERROR,
           "and decode_error under the standard library");
        ok(verify(cv_ed_cert, cv_ed_cert_len, cv_ed_body, 3u) != 0 && alert == LC_ALERT_DECODE_ERROR,
           "as is a body of three bytes there");
        plane_stdlib = 0;
    }

    /* Truncated to less than the four fixed bytes: unexpected_message under uTLS, the same answer
     * as any message that does not unmarshal. */
    ok(verify(cv_ed_cert, cv_ed_cert_len, cv_ed_body, 3u) != 0, "a body of three bytes is refused");
    ok(alert == LC_ALERT_UNEXPECTED_MESSAGE, "as unexpected_message");

    /* A SCHEME THE KEY CANNOT SIGN WITH — here RSA-PSS over an Ed25519 certificate. uTLS tries to
     * verify and fails, decrypt_error; the standard library refuses the pairing first,
     * illegal_parameter (GOROOT/src/crypto/tls/handshake_client_tls13.go:681-685). And an Ed25519
     * signature one byte short is decrypt_error on both — ed25519.Verify says no — where this said
     * decode_error. */
    {
        unsigned char b[128];
        memcpy(b, cv_ed_body, cv_ed_body_len < sizeof b ? cv_ed_body_len : sizeof b);
        b[0] = 0x08u;
        b[1] = 0x04u; /* rsa_pss_rsae_sha256 */
        ok(verify(cv_ed_cert, cv_ed_cert_len, b, cv_ed_body_len) != 0 && alert == LC_ALERT_DECRYPT_ERROR,
           "RSA-PSS over an Ed25519 certificate is decrypt_error under uTLS");
        plane_stdlib = 1;
        ok(verify(cv_ed_cert, cv_ed_cert_len, b, cv_ed_body_len) != 0 &&
               alert == LC_ALERT_ILLEGAL_PARAMETER,
           "and illegal_parameter under the standard library, which checks the pairing first");
        plane_stdlib = 0;

        memcpy(b, cv_ed_body, cv_ed_body_len < sizeof b ? cv_ed_body_len : sizeof b);
        b[3] = (unsigned char)(b[3] - 1u);
        ok(verify(cv_ed_cert, cv_ed_cert_len, b, cv_ed_body_len - 1u) != 0 &&
               alert == LC_ALERT_DECRYPT_ERROR,
           "an Ed25519 signature one byte short is decrypt_error, not decode_error");
    }
    ok(verify(NULL, 0u, cv_ed_body, cv_ed_body_len) != 0,
       "and so is a signature with no certificate to check it against");

    /* Every refusal has to say something: outside the process they all look identical, and the
     * sentence is the only thing that tells them apart. */
    ok(err[0] != '\0', "and a refusal always leaves a reason behind");

    /* ---- the key-type switch the reference runs before any of the above ----
     *
     * verifyServerCertificate admits RSA, ECDSA and Ed25519 and answers anything else with
     * alertUnsupportedCertificate, before verification and regardless of InsecureSkipVerify
     * (vendor/utls/handshake_client.go:1239-1249). lc_cert_key_supported is that switch; both
     * planes call it on the leaf they just received. The alien here is Ed448 — one byte of OID
     * away from Ed25519 (1.3.101.113 against .112), which is exactly the distance at which a
     * lookalike check waves the wrong key through. */
    ok(lc_cert_key_supported(cv_ed_cert, cv_ed_cert_len) == 1, "an Ed25519 leaf is a supported kind");
    ok(lc_cert_key_supported(cv_ec_cert, cv_ec_cert_len) == 1, "and so is ECDSA");
    ok(lc_cert_key_supported(cv_rsa_cert, cv_rsa_cert_len) == 1, "and so is RSA");
    {
        static unsigned char ed448[4096];
        unsigned n = cv_ed_cert_len < sizeof ed448 ? cv_ed_cert_len : (unsigned)sizeof ed448;
        memcpy(ed448, cv_ed_cert, n);
        /* Flip every 2b 65 70 to 2b 65 71: the OID appears in the SPKI and again in the signature
         * AlgorithmIdentifiers, and patching only one of them would leave a certificate no encoder
         * produces. The walk only reads the SPKI's, but the patch keeps the document coherent. */
        int patched = 0;
        for (unsigned i = 0; i + 2 < n; i++)
            if (ed448[i] == 0x2b && ed448[i + 1] == 0x65 && ed448[i + 2] == 0x70) {
                ed448[i + 2] = 0x71;
                patched++;
            }
        ok(patched > 0, "the Ed25519 OID was found to patch at all");
        ok(lc_cert_key_supported(ed448, n) == 0,
           "an Ed448 leaf - one OID byte away - is the alien the reference answers with 43");
    }
    ok(lc_cert_key_supported(cv_ed_cert, 20u) == -1,
       "a certificate cut too short to hold an SPKI is the parse failure, not the alien");

    for (unsigned i = 0; i < sizeof mcv_cases / sizeof mcv_cases[0]; i++) {
        const struct mcv_case *c = &mcv_cases[i];
        plane_stdlib = 0;
        int result = verify(c->cert, c->cert_len, c->body, c->body_len);
        ok(c->error[0] == '\0' ? result == 0 : result != 0 && alert == LC_ALERT_DECRYPT_ERROR &&
                                                  strcmp(gotext, c->error) == 0,
           "ML-DSA CertificateVerify matches Go for the key, scheme, signature and error text");
        ok(lc_cert_key_supported(c->cert, c->cert_len) == 2,
           "an ML-DSA leaf is distinguished from classical and unsupported keys");
        for (int stdlib = 0; stdlib <= 1; stdlib++) {
            result = lc_cert_verify(c->cert, c->cert_len, LC_SHA256, cv_transcript,
                                    c->body, c->body_len, stdlib, 0,
                                    err, sizeof err, &alert, gotext, sizeof gotext);
            ok(result != 0 && alert == LC_ALERT_ILLEGAL_PARAMETER,
               "both pinned Hysteria profiles keep refusing ML-DSA schemes");
        }
    }

    printf("\n%s\n", fails == 0 ? "the peer has to prove it holds the key"
                                : "the proof is NOT being checked as it was");
    return fails == 0 ? 0 : 1;
}
