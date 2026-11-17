/* RFC 8879, the half of it a client has to do — now all three algorithms the hello promises.
 *
 * THE THREE VECTORS ARE NOT EQUALLY STRONG, AND THE DIFFERENCE IS THE POINT OF THIS PARAGRAPH.
 *
 * zlib is checked against an INDEPENDENT implementation: the stream is written by Go's
 * compress/zlib and opened by libz, so what passes is agreement about the format rather than
 * agreement with ourselves. brotli and zstd are written by the encoders in the same vendored trees
 * whose decoders we link (tools/certcomp/gen.c, because Go's standard library has neither and the
 * gate runs with --network none). That still catches a wrong call, a wrong bound and a wrong length
 * check — encoder and decoder are different code — but it would not catch upstream misreading its
 * own specification.
 *
 * What closes the gap unevenly: test/certcomp/live.sh runs a real OpenSSL server, and the image's
 * OpenSSL is built with zlib and zstd — so those two are also proved against a foreign
 * implementation on a real handshake. NOTHING IN THIS IMAGE SPEAKS BROTLI, so brotli's only check
 * is the round trip here. That is the weakest link in this file and it is named rather than papered
 * over; what would close it is an OpenSSL built with brotli, or a capture from a Cloudflare-fronted
 * site, which is where brotli actually comes from in the field.
 *
 * The refusals matter as much: this is attacker-controlled input arriving before anything in the
 * handshake has been authenticated, and every field in the header is a number the peer chose. */

#include "tls/alert.h"
#include "tls/certcomp.h"
#include "certcomp_vectors.h"
#include "chain_vectors.h"
#include "reference_open.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(const char *what) { printf("  ok    %s\n", what); }

static void fail(const char *what, const char *why)
{
    printf("  FAIL  %s%s%s\n", what, why != NULL ? ": " : "", why != NULL ? why : "");
    failures++;
}

/* What the Firefox table offers, which is every algorithm this client opens — the list each case is
 * judged against unless it says otherwise. */
static const uint8_t offered_all[] = LC_CERTCOMP_EXT_BODY;

static uint8_t out[16384];
static uint8_t msg[16384];

/* Every refusal takes the good message and changes exactly one thing, so that what is being tested
 * is that field and not the shape of the message. */
static void must_refuse(const char *what)
{
    size_t n = 0;
    char   why[192] = { 0 };
    if (lc_certcomp_open(msg, sizeof certcomp_message, offered_all, sizeof offered_all, out,
                         sizeof out, &n, why, sizeof why, NULL, 0) != 0)
        printf("  ok    %s (%s)\n", what, why);
    else
        fail(what, "it was accepted");
}

static void reset(void) { memcpy(msg, certcomp_message, sizeof certcomp_message); }

/* The exact answer, for the cases where the reference's number is known: `len` is how much of `msg`
 * the call is handed, which lets a case add a byte to the end of the message. */
static void must_answer(const char *what, size_t len, int want)
{
    size_t n = 0;
    char   why[192] = { 0 };
    int    got = lc_certcomp_open(msg, len, offered_all, sizeof offered_all, out, sizeof out, &n,
                                  why, sizeof why, NULL, 0);
    if (got == want) {
        printf("  ok    %s: %d%s%s\n", what, got, why[0] ? " — " : "", why);
    } else {
        char b[64];
        snprintf(b, sizeof b, "answered %d where the reference answers %d", got, want);
        fail(what, b);
    }
}

/* THE OPENER AGAINST THE REFERENCE'S OWN, RUN. test/certcomp/reference_open.h holds what
 * vendor/utls's decompressCert answered — with the brotli and zstd readers its go.mod pins — for
 * streams its own Go encoders wrote, each mutated the ways a peer can; tools/certcompread made it.
 * The answer is compared as the handshake would see it: 42 from the opener, or an opened body that
 * is the first `declared` bytes of what was compressed (10 there is the Certificate parse after,
 * which test/alert holds). The buffer is what the handshake hands over: the declared length, as the
 * reference allocates it — no cap since 2026-09-25 (see the call in tls/client.c). OPENED_MAX is only
 * this file's room for the largest length the cases declare. */
#define OPENED_MAX (512u * 1024u)

static void cert_body(uint8_t *b, size_t n, uint32_t seed)
{
    uint8_t  period[97];
    uint32_t x = seed;
    for (size_t i = 0; i < sizeof period; i++) {
        x = x * 1103515245u + 12345u;
        period[i] = (uint8_t)(x >> 24);
    }
    size_t list = n - 4u, cert = n - 9u;
    memset(b, 0, n);
    b[1] = (uint8_t)(list >> 16), b[2] = (uint8_t)(list >> 8), b[3] = (uint8_t)list;
    b[4] = (uint8_t)(cert >> 16), b[5] = (uint8_t)(cert >> 8), b[6] = (uint8_t)cert;
    for (size_t i = 0; i < cert; i++)
        b[7u + i] = period[i % 97u];
}

static void test_against_the_reference(void)
{
    printf("\nstreams opened by the reference's own decompressCert\n");

    static uint8_t plain[300000];
    static uint8_t opened[OPENED_MAX];
    static uint8_t wire[70000];
    unsigned       bad = 0, long_ones = 0, racy = 0, words = 0, wrong_words = 0;
    const size_t   n_cases = sizeof co_cases / sizeof co_cases[0];

    for (size_t i = 0; i < n_cases; i++) {
        unsigned base = co_cases[i].base;
        size_t   run = co_bases[base].len - (size_t)co_cases[i].cut;
        size_t   declared = (size_t)co_cases[i].declared;
        memcpy(wire + 8, co_pool + co_bases[base].off, run);
        if (co_cases[i].flip >= 0 && (size_t)co_cases[i].flip < run)
            wire[8 + co_cases[i].flip] ^= 0xffu;
        memset(wire + 8 + run, 0xa5, (size_t)co_cases[i].extra);
        run += (size_t)co_cases[i].extra;
        wire[0] = 0, wire[1] = (uint8_t)co_bases[base].alg;
        wire[2] = (uint8_t)(declared >> 16), wire[3] = (uint8_t)(declared >> 8);
        wire[4] = (uint8_t)declared;
        wire[5] = (uint8_t)(run >> 16), wire[6] = (uint8_t)(run >> 8), wire[7] = (uint8_t)run;

        racy += co_cases[i].racy != 0;
        long_ones += declared > 262144u;
        if (declared > OPENED_MAX) {
            fail("a case declares more than this file's buffer", NULL);
            continue;
        }
        size_t n = 0;
        char   why[192] = { 0 }, go[192] = { 0 };
        int    got = lc_certcomp_open(wire, 8 + run, offered_all, sizeof offered_all, opened,
                                      declared, &n, why, sizeof why, go, sizeof go);

        int ok_here;
        if (co_cases[i].alert == LC_ALERT_BAD_CERTIFICATE) {
            ok_here = got == LC_ALERT_BAD_CERTIFICATE;
        } else {
            ok_here = got == 0 && n == declared;
            if (ok_here && co_cases[i].flip < 0) {
                cert_body(plain, co_bases[base].plain_len, co_bases[base].seed);
                ok_here = memcmp(opened, plain, declared) == 0;
            }
        }
        /* And for brotli, what the Chrome parrot offers, the words: a stream the reference refused
         * with 42, in what decompressCert returned, wrapped as utlsReadServerCertificate wraps it
         * (vendor/utls-hy/u_handshake_client.go:35-38); none for anything else. A 10 comes from
         * the Certificate that did not read, which is the caller's to name. */
        if (co_bases[base].alg == 2u && co_cases[i].alert != LC_ALERT_UNEXPECTED_MESSAGE) {
            char want[256] = { 0 };
            if (co_cases[i].alert == LC_ALERT_BAD_CERTIFICATE)
                snprintf(want, sizeof want, "tls: failed to decompress certificate message: %s",
                         co_cases[i].why);
            words++;
            if (strcmp(go, want) != 0) {
                if (wrong_words < 12)
                    printf("  FAIL  brotli, %u bytes, stream %u, declared %d, cut %d, flip %d, "
                           "extra %d: the reference says \"%s\", this \"%s\"\n",
                           co_bases[base].plain_len, base, co_cases[i].declared, co_cases[i].cut,
                           co_cases[i].flip, co_cases[i].extra, want, go);
                wrong_words++;
            }
        }
        if (!ok_here) {
            if (bad < 12)
                printf("  FAIL  alg %u, %u bytes, stream %u, declared %d, cut %d, flip %d, extra %d: "
                       "the reference answers %d, this %d (%u bytes%s%s)\n",
                       co_bases[base].alg, co_bases[base].plain_len, base, co_cases[i].declared,
                       co_cases[i].cut, co_cases[i].flip, co_cases[i].extra, co_cases[i].alert, got,
                       (unsigned)n, why[0] ? ": " : "", why);
            bad++;
        }
    }
    char what[160];
    snprintf(what, sizeof what, "%u streams, %u cases: every answer the reference's (%u differ)",
             (unsigned)(sizeof co_bases / sizeof co_bases[0]), (unsigned)n_cases, bad);
    if (bad == 0)
        ok(what);
    else
        fail(what, NULL);
    snprintf(what, sizeof what, "%u brotli cases: each in the reference's words (%u differ)", words,
             wrong_words);
    if (wrong_words == 0 && words > 0)
        ok(what);
    else
        fail(what, NULL);
    printf("  ----  %u of them declare more than the Certificate message's 262144, and open as the\n"
           "        reference opens them (they were refused here until 2026-09-25)\n",
           long_ones);
    printf("  ----  %u of them are zstd whose answer there depends on a block being decoded in time;\n"
           "        held to the answer with it ready, as tls/certcomp.c models (one core refuses)\n",
           racy);
}

int main(void)
{
    printf("compressed certificates, the three algorithms this client offers\n\n");

    /* ---- the one that must work ---- */
    {
        size_t n = 0;
        char   why[192] = { 0 };
        if (lc_certcomp_open(certcomp_message, sizeof certcomp_message, offered_all,
                             sizeof offered_all, out, sizeof out, &n, why, sizeof why, NULL, 0) != 0) {
            fail("a zlib stream from Go opens", why);
        } else if (n != sizeof certcomp_plain || memcmp(out, certcomp_plain, n) != 0) {
            fail("a zlib stream from Go opens to the certificate message", "the bytes differ");
        } else {
            printf("  ok    a zlib stream from Go opens to the certificate message (%u bytes from "
                   "%u)\n",
                   (unsigned)n, (unsigned)sizeof certcomp_message);
        }
    }

    /* ---- and the other two the hello promises ---- */
    {
        size_t n = 0;
        char   why[192] = { 0 };
        if (lc_certcomp_open(certcomp_message_brotli, sizeof certcomp_message_brotli, offered_all,
                             sizeof offered_all, out, sizeof out, &n, why, sizeof why, NULL, 0) != 0) {
            fail("a brotli stream opens", why);
        } else if (n != sizeof certcomp_plain || memcmp(out, certcomp_plain, n) != 0) {
            fail("a brotli stream opens to the certificate message", "the bytes differ");
        } else {
            printf("  ok    a brotli stream opens to the certificate message (%u bytes from %u)\n",
                   (unsigned)n, (unsigned)sizeof certcomp_message_brotli);
        }
    }
    {
        size_t n = 0;
        char   why[192] = { 0 };
        if (lc_certcomp_open(certcomp_message_zstd, sizeof certcomp_message_zstd, offered_all,
                             sizeof offered_all, out, sizeof out, &n, why, sizeof why, NULL, 0) != 0) {
            fail("a zstd stream opens", why);
        } else if (n != sizeof certcomp_plain || memcmp(out, certcomp_plain, n) != 0) {
            fail("a zstd stream opens to the certificate message", "the bytes differ");
        } else {
            printf("  ok    a zstd stream opens to the certificate message (%u bytes from %u)\n",
                   (unsigned)n, (unsigned)sizeof certcomp_message_zstd);
        }
    }

    /* ---- and the ways it must not ---- */
    {
        /* 0 and 4 rather than 2: since the client gained brotli and zstd, every algorithm RFC 8879
         * defines is one it offers, so "not advertised" has to be spelled with an identifier the
         * registry does not use. Both edges of the offered range, because a bounds error in the
         * loop over the extension body would show on one and not the other. */
        reset();
        msg[1] = 0x00u; /* below zlib(1) */
        must_refuse("an identifier below the three offered");

        reset();
        msg[1] = 0x04u; /* above zstd(3) */
        must_refuse("an identifier above the three offered");

        /* WHAT OUR HELLO OFFERED, NOT WHAT THIS BUILD OPENS. A Chrome hello offers brotli alone, so
         * the zlib message these cases are built on is one the reference refuses with 42 — the
         * list it checks is the one it sent (vendor/utls/u_handshake_client.go:59-69). And a hello
         * that offered nothing never reads the message as compressed at all: 10. */
        {
            static const uint8_t brotli_only[] = { 0x02u, 0x00u, 0x02u };
            size_t               n = 0;
            char                 why[192] = { 0 };
            reset();
            int got = lc_certcomp_open(msg, sizeof certcomp_message, brotli_only,
                                       sizeof brotli_only, out, sizeof out, &n, why, sizeof why, NULL, 0);
            if (got == LC_ALERT_BAD_CERTIFICATE)
                ok("zlib, against a hello that offered brotli alone, is 42");
            else
                fail("zlib, against a hello that offered brotli alone, is 42", why);
            got = lc_certcomp_open(msg, sizeof certcomp_message, NULL, 0, out, sizeof out, &n, why,
                                   sizeof why, NULL, 0);
            if (got == LC_ALERT_UNEXPECTED_MESSAGE)
                ok("a compressed certificate our hello never asked for is 10");
            else
                fail("a compressed certificate our hello never asked for is 10", why);
        }

        reset();
        msg[2] = 0xffu; /* a declared size far past what a handshake message can be */
        must_refuse("a declared size larger than a handshake message");

        reset();
        msg[3] = 0x00u;
        msg[4] = 0x00u; /* declares zero */
        /* One Read into nothing: flate had output to hand over, so it returns 0 bytes and no error,
         * and the reference takes it — then the empty Certificate does not parse, which is 10 and
         * test/alert's. This refused it here as 42 until 2026-09-24. */
        must_answer("a declared size of zero opens to nothing", sizeof certcomp_message, 0);

        /* THE HEADER IS unmarshal's (vendor/utls/u_handshake_messages.go:43-54): a run that claims
         * more than the message carries does not read, and that is 10 — readHandshake's answer to
         * any message that does not unmarshal — not 42. And the header does not ask the message to
         * end after the run, so a byte past it is not refused at all. Both answered 42 until
         * 2026-09-24. */
        reset();
        msg[7] = (uint8_t)(msg[7] + 1u);
        must_answer("a run that claims more than the message carries", sizeof certcomp_message,
                    LC_ALERT_UNEXPECTED_MESSAGE);

        reset();
        msg[sizeof certcomp_message] = 0xaau;
        must_answer("a byte after the run, which the header never looks at",
                    sizeof certcomp_message + 1u, 0);

        reset();
        must_answer("a message too short for its header", 7u, LC_ALERT_UNEXPECTED_MESSAGE);

        reset();
        msg[7] = (uint8_t)(msg[7] - 1u); /* the run now stops one byte short of the stream */
        must_refuse("a run one byte shorter than its stream, which then does not inflate");

        reset();
        msg[sizeof certcomp_message - 1u] ^= 0xffu;
        must_refuse("a stream whose last byte was altered");

        reset();
        msg[12] ^= 0xffu; /* inside the deflate data, past the zlib header */
        must_refuse("a stream whose middle was altered");

        /* The reference sizes its buffer to the declared length, so a stream that opens to MORE
         * than declared fills it and is taken, the rest never read (see the one-Read models in
         * tls/certcomp.c). This refused it until 2026-09-24. */
        reset();
        msg[4] = (uint8_t)(msg[4] - 1u);
        must_answer("a stream that opens to more than it declared", sizeof certcomp_message, 0);

        /* A caller with less room than the message needs is refused rather than served a truncated
         * certificate list, which would parse and be wrong. */
        reset();
        {
            size_t n = 0;
            char   why[192] = { 0 };
            if (lc_certcomp_open(msg, sizeof certcomp_message, offered_all, sizeof offered_all, out,
                                 sizeof certcomp_plain - 1u, &n, why, sizeof why, NULL, 0) != 0)
                ok("a buffer smaller than the declared size");
            else
                fail("a buffer smaller than the declared size", "it was accepted");
        }
    }

    test_against_the_reference();

    printf("\n%s\n", failures == 0 ? "all three algorithms open, and every malformed header is refused"
                                   : "THE COMPRESSED CERTIFICATE PATH IS WRONG");
    return failures == 0 ? 0 : 1;
}
