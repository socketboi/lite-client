/* The certificate walk, against certificates Go produced.
 *
 * Two of them. The first is an ordinary self-signed ed25519 certificate, and the values to match
 * are what Go's own x509 parser read out of it — so agreement is with a real parser, not with our
 * own idea of the format.
 *
 * The second is what a REALITY server actually sends: identical structure, but the signature field
 * holds an HMAC over the public key instead of a signature. It is included because a parser that
 * validates what it reads would reject exactly the certificates this client exists to read, and
 * that failure would only appear against a live server.
 *
 * The malformed cases matter as much as the good ones: this data arrives from the network before
 * anything has been authenticated. */

#include "cert/cert.h"
#include "cert_vectors.h"
#include "remarshal_vectors.h"
#include "test_vectors.h"
#include "tls/msg.h"

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

static void check_bytes(const char *what, const uint8_t *got, size_t got_len,
                        const uint8_t *want, size_t want_len)
{
    if (got_len == want_len && memcmp(got, want, want_len) == 0) {
        printf("  ok    %s (%zu bytes)\n", what, want_len);
        return;
    }
    printf("  FAIL  %s: %zu bytes against %zu expected\n", what, got_len, want_len);
    failures++;
}

/* Rejecting a mutated certificate. The byte to change is chosen by the caller so each case says
 * what it is really testing. */
static void must_reject(const char *what, size_t at, uint8_t xor_with)
{
    static uint8_t bad[SZ(cert_der)];
    memcpy(bad, cert_der, sizeof bad);
    bad[at] ^= xor_with;

    lc_cert c;
    if (lc_cert_parse(bad, sizeof bad, &c) == 0)
        fail(what);
    else
        ok(what);
}

int main(void)
{
    printf("certificate parsing, against Go crypto/x509\n");

    /* ---- an ordinary certificate ---- */
    {
        lc_cert c;
        if (lc_cert_parse(cert_der, SZ(cert_der), &c) != 0) {
            fail("a valid ed25519 certificate does not parse");
        } else {
            check_bytes("public key", c.public_key, c.public_key_len,
                        cert_public_key, SZ(cert_public_key));
            check_bytes("signature", c.signature, c.signature_len,
                        cert_signature, SZ(cert_signature));
        }
    }

    /* ---- what a REALITY server sends ---- */
    {
        lc_cert c;
        if (lc_cert_parse(reality_cert_der, SZ(reality_cert_der), &c) != 0) {
            fail("a REALITY certificate does not parse");
        } else {
            ok("REALITY certificate parses despite carrying an HMAC where a signature belongs");
            check_bytes("REALITY signature field", c.signature, c.signature_len,
                        reality_cert_signature, SZ(reality_cert_signature));
            check_bytes("REALITY public key", c.public_key, c.public_key_len,
                        cert_public_key, SZ(cert_public_key));
        }
    }

    /* ---- the Certificate message from the RFC 8448 flight ---- */
    {
        lc_msg_reader r;
        lc_msg_reader_init(&r, srv_record_2_payload, SZ(srv_record_2_payload));

        uint8_t        type = 0;
        const uint8_t *body = NULL, *whole = NULL;
        size_t         body_len = 0, whole_len = 0;
        int            found = 0;

        while (lc_msg_next(&r, &type, &body, &body_len, &whole, &whole_len) == 1) {
            if (type != LC_HS_CERTIFICATE)
                continue;
            found = 1;
            const uint8_t *der = NULL;
            size_t         der_len = 0;
            if (lc_cert_first_from_message(body, body_len, &der, &der_len) != 0) {
                fail("the leading certificate cannot be taken out of the message");
            } else {
                printf("  ok    leading certificate extracted from the message (%zu bytes)\n", der_len);
                /* That certificate is RSA, so the walk must refuse it rather than misread it —
                 * REALITY is ed25519 only, and a client that guessed at another key type would be
                 * authenticating against something the protocol never defined. */
                lc_cert c;
                if (lc_cert_parse(der, der_len, &c) == 0)
                    fail("an RSA certificate was accepted as ed25519");
                else
                    ok("RSA certificate refused: this client is ed25519 only");
            }
            break;
        }
        if (!found)
            fail("no Certificate message in the flight");
    }

    /* ---- malformed input ---- */
    {
        lc_cert c;
        if (lc_cert_parse(cert_der, 4u, &c) == 0)
            fail("a truncated certificate was accepted");
        else
            ok("truncated certificate rejected");

        if (lc_cert_parse(cert_der, 0u, &c) == 0)
            fail("an empty buffer was accepted");
        else
            ok("empty buffer rejected");

        must_reject("outer SEQUENCE tag corrupted", 0u, 0xffu);
        must_reject("outer length corrupted", 2u, 0x40u);
    }

    /* ---- malformed Certificate messages ---- */
    {
        static const uint8_t empty_list[] = { 0x00, 0x00, 0x00, 0x00 };
        const uint8_t       *der = NULL;
        size_t               der_len = 0;
        if (lc_cert_first_from_message(empty_list, sizeof empty_list, &der, &der_len) == 0)
            fail("an empty certificate list was accepted");
        else
            ok("empty certificate list rejected");

        static const uint8_t lying_length[] = { 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x05 };
        if (lc_cert_first_from_message(lying_length, sizeof lying_length, &der, &der_len) == 0)
            fail("a certificate list longer than its message was accepted");
        else
            ok("overlong certificate list rejected");
    }

    /* ---- THE LEAF'S OWN EXTENSIONS, WHICH THE WALK USED TO STEP OVER UNREAD ----
     *
     * The reference parses the two it knows and refuses the whole message when either is malformed
     * (vendor/utls/handshake_messages.go:1611-1653). Every case below is a message a Go client
     * stops on, and each is one edit away from the case above it, so a check that answers only the
     * easy half fails here rather than on a node.
     *
     * The certificate itself is one byte: nothing here reaches the DER parser, and a real chain
     * would only make the offsets harder to read. */
    {
        const uint8_t *der = NULL;
        size_t         der_len = 0;

        /* ctx, u24 list length, u24 cert length, one byte of cert, u16 extensions length, then the
         * extension block the case is about. */
        struct {
            const char *what;
            int         accept;
            size_t      ext_len;
            uint8_t     ext[24];
        } cases[] = {
            { "no extensions at all is the ordinary chain", 1, 0, { 0 } },
            { "an unknown extension is skipped whole, empty body and all", 1, 4,
              { 0xffu, 0xa5u, 0x00u, 0x00u } },
            { "a status_request with no body at all", 0, 4, { 0x00u, 0x05u, 0x00u, 0x00u } },
            { "a status_request whose status type is not OCSP", 0, 9,
              { 0x00u, 0x05u, 0x00u, 0x05u, 0x02u, 0x00u, 0x00u, 0x01u, 0xaau } },
            { "a status_request with an EMPTY staple", 0, 8,
              { 0x00u, 0x05u, 0x00u, 0x04u, 0x01u, 0x00u, 0x00u, 0x00u } },
            { "a status_request with bytes after its staple", 0, 10,
              { 0x00u, 0x05u, 0x00u, 0x06u, 0x01u, 0x00u, 0x00u, 0x01u, 0xaau, 0xbbu } },
            { "a well-formed OCSP staple", 1, 9,
              { 0x00u, 0x05u, 0x00u, 0x05u, 0x01u, 0x00u, 0x00u, 0x01u, 0xaau } },
            { "an SCT extension with an empty list", 0, 6,
              { 0x00u, 0x12u, 0x00u, 0x02u, 0x00u, 0x00u } },
            { "an SCT list holding a zero-length timestamp", 0, 10,
              { 0x00u, 0x12u, 0x00u, 0x06u, 0x00u, 0x04u, 0x00u, 0x01u, 0xaau, 0x00u } },
            { "an SCT whose length runs past the list", 0, 9,
              { 0x00u, 0x12u, 0x00u, 0x05u, 0x00u, 0x03u, 0x00u, 0x05u, 0xaau } },
            { "a well-formed SCT list of one", 1, 9,
              { 0x00u, 0x12u, 0x00u, 0x05u, 0x00u, 0x03u, 0x00u, 0x01u, 0xaau } },
            { "an extension record cut off inside its own header", 0, 3,
              { 0x00u, 0x12u, 0x00u } },
            { "an extension whose body runs past the block", 0, 4,
              { 0x00u, 0x12u, 0x00u, 0x09u } },
        };

        for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
            uint8_t msg[64];
            size_t  n = 0;
            size_t  list = 3u + 1u + 2u + cases[i].ext_len;
            msg[n++] = 0x00u; /* certificate_request_context */
            msg[n++] = (uint8_t)(list >> 16);
            msg[n++] = (uint8_t)(list >> 8);
            msg[n++] = (uint8_t)list;
            msg[n++] = 0x00u;
            msg[n++] = 0x00u;
            msg[n++] = 0x01u; /* one byte of certificate */
            msg[n++] = 0x30u;
            msg[n++] = (uint8_t)(cases[i].ext_len >> 8);
            msg[n++] = (uint8_t)cases[i].ext_len;
            memcpy(msg + n, cases[i].ext, cases[i].ext_len);
            n += cases[i].ext_len;

            int got = lc_cert_first_from_message(msg, n, &der, &der_len) == 0;
            if (got == cases[i].accept)
                ok(cases[i].what);
            else
                fail(cases[i].what);
        }

        /* And the same malformed extension on an entry that is NOT the leaf, which the reference
         * skips without looking: `if len(certificate.Certificate) > 1 { continue }`
         * (utls/handshake_messages.go:1619-1622). Only the frame is checked there. */
        {
            static const uint8_t two[] = {
                0x00u,                      /* context */
                0x00u, 0x00u, 0x10u,        /* list length */
                0x00u, 0x00u, 0x01u, 0x30u, /* leaf, one byte */
                0x00u, 0x00u,               /* leaf extensions: none */
                0x00u, 0x00u, 0x01u, 0x31u, /* second entry */
                0x00u, 0x04u,               /* its extensions: an EMPTY status_request */
                0x00u, 0x05u, 0x00u, 0x00u,
            };
            size_t off = 0;
            int    a = lc_cert_next_from_message(two, sizeof two, &off, &der, &der_len);
            int    b = lc_cert_next_from_message(two, sizeof two, &off, &der, &der_len);
            if (a == 0 && b == 0)
                ok("a malformed status_request on an intermediate is skipped, as it is in Go");
            else
                fail("an intermediate's extensions were parsed as though it were the leaf");
        }
    }

    /* ---- the message as the reference hashes it: certificateMsgTLS13 marshalled again ---- */
    printf("\nthe Certificate re-marshalled, against uTLS's own (tools/certremarshal)\n");
    for (size_t i = 0; i < sizeof remarshal_vectors / sizeof remarshal_vectors[0]; i++) {
        static uint8_t got[4096];
        size_t         off = 0, der_len = 0, n = 0;
        const uint8_t *der = NULL;
        int            step;
        while ((step = lc_cert_next_from_message(remarshal_vectors[i].in, remarshal_vectors[i].in_len,
                                                 &off, &der, &der_len)) == 0) {
        }
        if (step == 1)
            n = lc_cert13_remarshal(remarshal_vectors[i].in, remarshal_vectors[i].in_len, got,
                                    sizeof got);
        check_bytes(remarshal_vectors[i].name, got, n, remarshal_vectors[i].out,
                    remarshal_vectors[i].out_len);
    }

    printf("\n%s\n", failures == 0 ? "certificate parsing agrees with Go" : "CERTIFICATE PARSING IS WRONG");
    return failures == 0 ? 0 : 1;
}
