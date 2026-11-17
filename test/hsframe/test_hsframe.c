/* Handshake message framing across record boundaries.
 *
 * A record boundary and a message boundary have nothing to do with each other. One record may carry
 * several messages, and one message may be spread over several records — legal TLS 1.3, and what
 * actually happens when a REALITY server decides the client is a stranger and proxies the donor
 * site, whose certificate chain does not fit one record. Code that reads messages out of a single
 * record works against most servers and fails against some, which is the worst distribution of
 * outcomes there is: it looks correct everywhere anyone tests it.
 *
 * The property under test is the one the transcript depends on. Whatever the peer's record layer
 * does with the bytes, the messages that come out must be the same messages, and the bytes handed to
 * the transcript must be the message as sent, header included. If splitting a flight changed what
 * the transcript hashed, the server's Finished would stop verifying — and on this client that is
 * reported as "REALITY not authenticated", which points the blame at the stamp rather than at the
 * framing and costs an afternoon.
 *
 * White box on purpose: the reassembler is internal to client.c, and the alternative — driving the
 * whole state machine — needs a live server and proves less. */

#include "tls/client.c"

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(const char *what)
{
    printf("  ok    %s\n", what);
}

static void fail(const char *what)
{
    printf("  FAIL  %s\n", what);
    failures++;
}

static void expect(int cond, const char *what)
{
    if (cond)
        ok(what);
    else
        fail(what);
}

/* One message: a four-byte header — type and a 24-bit length — and a body whose bytes are a
 * function of the type, so a message that came back wrong is recognisable rather than merely
 * unequal. */
static size_t put_msg(uint8_t *out, uint8_t type, size_t body_len)
{
    out[0] = type;
    out[1] = (uint8_t)(body_len >> 16);
    out[2] = (uint8_t)(body_len >> 8);
    out[3] = (uint8_t)body_len;
    for (size_t i = 0; i < body_len; i++)
        out[4 + i] = (uint8_t)(type + i);
    return body_len + 4u;
}

/* What one delivery of a flight produced: the messages, in order, and a hash over the exact bytes
 * each one contributed to a transcript. */
#define MAX_MSGS 8

typedef struct {
    unsigned count;
    uint8_t  type[MAX_MSGS];
    size_t   body_len[MAX_MSGS];
    uint8_t  digest[LC_HASH_MAX];
    int      error;
} outcome;

/* Feeds a flight in chunks of `chunk` bytes (0 meaning "all at once") and records what came out.
 * This is what the phases do: append whatever the record layer produced, then drain every message
 * that is now complete, leaving any partial one for the next arrival. */
static void deliver(outcome *o, const uint8_t *flight, size_t len, size_t chunk)
{
    memset(o, 0, sizeof *o);
    lc_client_config cfg = {0};
    lc_client_hs *hs = lc_client_hs_new(&cfg);
    if (hs == NULL) {
        o->error = 1;
        return;
    }
    /* The encrypted flight, where these messages arrive: the version is settled by then, which is
     * what lets a Certificate use the larger ceiling (see hs_msg_ceiling). */
    hs->have_vers = 1;

    lc_transcript tr;
    if (lc_transcript_init(&tr, LC_SHA256) != 0) {
        o->error = 1;
        lc_client_hs_free(hs);
        return;
    }

    size_t off = 0;
    while (off < len) {
        size_t n = chunk == 0u ? len : chunk;
        if (n > len - off)
            n = len - off;
        if (hs_msg_add(hs, flight + off, n) != 0) {
            o->error = 1;
            break;
        }
        off += n;

        uint8_t        type = 0;
        const uint8_t *body = NULL, *whole = NULL;
        size_t         body_len = 0, whole_len = 0;
        int            rc;
        while ((rc = hs_msg_take(hs, &type, &body, &body_len, &whole, &whole_len)) == 1) {
            if (o->count < MAX_MSGS) {
                o->type[o->count] = type;
                o->body_len[o->count] = body_len;
                /* The body is checked here rather than kept: it is generated from the type, so a
                 * byte out of place means the reassembly spliced two arrivals wrongly. */
                for (size_t i = 0; i < body_len; i++) {
                    if (body[i] != (uint8_t)(type + i)) {
                        o->error = 1;
                        break;
                    }
                }
                o->count++;
            }
            lc_transcript_add(&tr, whole, whole_len);
            hs_msg_drop(hs, whole_len);
        }
        if (rc < 0) {
            o->error = 1;
            break;
        }
    }

    lc_transcript_snapshot(&tr, o->digest);
    lc_transcript_free(&tr);
    lc_client_hs_free(hs);
}

static int same(const outcome *a, const outcome *b)
{
    if (a->error || b->error || a->count != b->count)
        return 0;
    for (unsigned i = 0; i < a->count; i++) {
        if (a->type[i] != b->type[i] || a->body_len[i] != b->body_len[i])
            return 0;
    }
    return memcmp(a->digest, b->digest, LC_HASH_MAX) == 0;
}

int main(void)
{
    printf("\nhandshake messages across record boundaries\n\n");

    /* A server flight of the shape that provokes this: EncryptedExtensions, a certificate far larger
     * than one record's worth of the buffer this used to read from, CertificateVerify, Finished. */
    static uint8_t flight[24000];
    size_t         len = 0;
    len += put_msg(flight + len, LC_HS_ENCRYPTED_EXT, 20u);
    len += put_msg(flight + len, LC_HS_CERTIFICATE, 9000u);
    len += put_msg(flight + len, LC_HS_CERTIFICATE_VERIFY, 260u);
    len += put_msg(flight + len, LC_HS_FINISHED, 32u);

    outcome whole_at_once;
    deliver(&whole_at_once, flight, len, 0);
    expect(!whole_at_once.error, "a flight delivered in one piece reads without error");
    expect(whole_at_once.count == 4, "and yields exactly the four messages it holds");
    expect(whole_at_once.type[1] == LC_HS_CERTIFICATE && whole_at_once.body_len[1] == 9000u,
           "including a certificate too large to have arrived in one record");

    /* The property, checked at every boundary rather than at a chosen one: an arrival can land
     * anywhere, including inside a length field. */
    int all_equal = 1;
    for (size_t k = 1; k < len; k++) {
        outcome split;
        deliver(&split, flight, len, k);
        if (!same(&whole_at_once, &split)) {
            all_equal = 0;
            printf("        first difference at a chunk size of %zu bytes\n", k);
            break;
        }
    }
    expect(all_equal, "every chunk size produces the same messages and the same transcript");

    outcome byte_at_a_time;
    deliver(&byte_at_a_time, flight, len, 1u);
    expect(same(&whole_at_once, &byte_at_a_time),
           "and so does a peer that delivers one byte at a time");

    /* Nothing may leave the window early. A message is either all here or it is not a message: a
     * parser handed three quarters of a certificate cannot tell that from a malformed one. */
    {
        static lc_client_hs hs;
        memset(&hs, 0, sizeof hs);
        hs.plain = hs.plain_inline;
        hs.plain_cap = sizeof hs.plain_inline;
        uint8_t        type = 0;
        const uint8_t *body = NULL, *whole = NULL;
        size_t         body_len = 0, whole_len = 0;

        expect(hs_msg_add(&hs, flight, 3u) == 0 &&
                   hs_msg_take(&hs, &type, &body, &body_len, &whole, &whole_len) == 0,
               "a header that has not finished arriving yields nothing");

        memset(&hs, 0, sizeof hs);
        hs.plain = hs.plain_inline;
        hs.plain_cap = sizeof hs.plain_inline;
        expect(hs_msg_add(&hs, flight, 4u + 19u) == 0 &&
                   hs_msg_take(&hs, &type, &body, &body_len, &whole, &whole_len) == 0,
               "nor does a body one byte short of complete");

        expect(hs_msg_add(&hs, flight + 23u, 1u) == 0 &&
                   hs_msg_take(&hs, &type, &body, &body_len, &whole, &whole_len) == 1 &&
                   whole_len == 24u,
               "and the byte that completes it releases the whole message, header included");
    }

    /* The bound that keeps the window from overflowing: the residue left behind is always shorter
     * than one message, so a whole record can always be appended to it. */
    {
        static lc_client_hs hs;
        memset(&hs, 0, sizeof hs);
        hs.plain = hs.plain_inline;
        hs.plain_cap = sizeof hs.plain_inline;
        uint8_t        header[4] = { LC_HS_CERTIFICATE, 0xff, 0xff, 0xff };
        uint8_t        type = 0;
        const uint8_t *body = NULL, *whole = NULL;
        size_t         body_len = 0, whole_len = 0;

        expect(hs_msg_add(&hs, header, sizeof header) == 0 &&
                   hs_msg_take(&hs, &type, &body, &body_len, &whole, &whole_len) < 0,
               "a message declared larger than the window is refused, not waited for");
    }

    /* THE TWO BOUNDS, WHICH ARE THE REFERENCE'S AND NOT THE BUFFER'S.
     *
     * Go reads a handshake message up to maxHandshake, and a Certificate up to
     * maxHandshakeCertificateMsg — "since certificate messages are likely to be the only messages
     * that can be larger than maxHandshake" (vendor/utls/conn.go:1102-1117, utls/common.go:71-72). This
     * client had one number, sixteen kilobytes, because that was the size of its window; the window
     * now grows for the message that does not fit it, so the number a peer meets is Go's.
     *
     * Off by one here and either the largest legal message is refused in the field, or the residue
     * can grow past what a record can be appended to — and the second of those is a buffer overrun
     * rather than a refusal, so both edges are pinned rather than trusted to the arithmetic.
     * Delivered in record-sized pieces, which is the shape that exercises the growth. */
    {
        static uint8_t big[LC_HS_MAX_CERTIFICATE + LC_REC_MAX_PLAINTEXT];

        size_t  fits = put_msg(big, LC_HS_CERTIFICATE, LC_HS_MAX_CERTIFICATE);
        outcome largest;
        deliver(&largest, big, fits, LC_REC_MAX_PLAINTEXT);
        expect(!largest.error && largest.count == 1 && largest.body_len[0] == LC_HS_MAX_CERTIFICATE,
               "a Certificate of the reference's 262144 bytes survives arriving in record-sized "
               "pieces");

        size_t  over = put_msg(big, LC_HS_CERTIFICATE, LC_HS_MAX_CERTIFICATE + 1u);
        outcome too_big;
        deliver(&too_big, big, over, LC_REC_MAX_PLAINTEXT);
        expect(too_big.error && too_big.count == 0,
               "and one byte more than that is refused rather than half-assembled");

        /* Anything that is not a Certificate stops four times earlier. */
        size_t  other_fits = put_msg(big, LC_HS_ENCRYPTED_EXT, LC_HS_MAX_MESSAGE);
        outcome other;
        deliver(&other, big, other_fits, LC_REC_MAX_PLAINTEXT);
        expect(!other.error && other.count == 1 && other.body_len[0] == LC_HS_MAX_MESSAGE,
               "an EncryptedExtensions of the reference's 65536 bytes is read");

        size_t  other_over = put_msg(big, LC_HS_ENCRYPTED_EXT, LC_HS_MAX_MESSAGE + 1u);
        outcome other_too_big;
        deliver(&other_too_big, big, other_over, LC_REC_MAX_PLAINTEXT);
        expect(other_too_big.error && other_too_big.count == 0,
               "and one byte more than THAT is refused, because only a Certificate may be larger");
    }

    /* ---- the classical key share is the hybrid's, not a second one ----
     *
     * uTLS wraps the two entries in ReuseHybridAndClassicalKeyShares (vendor/utls/u_parrots.go:1611,
     * consumed at :3270 and :3292-3295), so in every reference Firefox hello the last 32 bytes of
     * the X25519MLKEM768 share are byte-identical to the standalone X25519 share. This client
     * generated two independent pairs, and the equality therefore never held.
     *
     * It is checked HERE, on the real shipped table and through the real filler, because nothing
     * else can see it: `fp diff` reduces key_share to groups and lengths (tools/fp/diff.go:128-140),
     * which were right the whole time, and no handshake fails when it is wrong — the REALITY server
     * prefers the standalone entry and authenticates us as usual. A gate that cannot fail on a
     * defect is not covering it. */
    {
        printf("\nthe key shares, against what uTLS reuses\n");

        FILE *tf = fopen("package/files/fingerprint.fpt", "rb");
        if (tf == NULL) {
            expect(0, "package/files/fingerprint.fpt opens");
        } else {
            static uint8_t table[8192];
            size_t         table_len = fread(table, 1, sizeof table, tf);
            fclose(tf);

            static uint8_t hello_a[4096], hello_b[4096];
            lc_hello_out   info_a, info_b;
            client_keys    keys_a, keys_b;
            memset(&keys_a, 0, sizeof keys_a);
            memset(&keys_b, 0, sizeof keys_b);
            char err[256];

            int built = lc_hello_build(table, table_len, "example.com", hello_a, sizeof hello_a,
                                       &info_a) == LC_HELLO_OK &&
                        lc_hello_build(table, table_len, "example.com", hello_b, sizeof hello_b,
                                       &info_b) == LC_HELLO_OK &&
                        fill_key_shares(hello_a, &info_a, &keys_a, err, sizeof err) == 0 &&
                        fill_key_shares(hello_b, &info_b, &keys_b, err, sizeof err) == 0;
            expect(built, "two hellos build from the shipped table and their key shares fill");

            const lc_hello_key_slot *hyb = NULL, *cls = NULL;
            for (unsigned i = 0; built && i < info_a.slot_count; i++) {
                if (info_a.slots[i].group == LC_GROUP_X25519MLKEM768)
                    hyb = &info_a.slots[i];
                if (info_a.slots[i].group == LC_GROUP_X25519)
                    cls = &info_a.slots[i];
            }
            expect(hyb != NULL && cls != NULL,
                   "the shipped fingerprint offers both X25519MLKEM768 and standalone x25519");

            if (built && hyb != NULL && cls != NULL) {
                const uint8_t *tail_a = hello_a + hyb->off + LC_MLKEM_EK;
                const uint8_t *std_a = hello_a + cls->off;
                expect(memcmp(tail_a, std_a, LC_X25519_KEY) == 0,
                       "the standalone x25519 share IS the hybrid's classical half, as it is in uTLS");

                /* Not zero, or the comparison above would hold for a filler that wrote nothing. */
                uint8_t acc = 0;
                for (size_t i = 0; i < LC_X25519_KEY; i++)
                    acc = (uint8_t)(acc | std_a[i]);
                expect(acc != 0, "and it is a key rather than an unfilled slot");

                /* And still fresh per connection: reuse is within one hello, not across them. */
                const uint8_t *std_b = hello_b + cls->off;
                expect(memcmp(std_a, std_b, LC_X25519_KEY) != 0,
                       "while two hellos still carry two different keys");

                /* The private kept for the standalone group must be the hybrid's, or the REALITY
                 * stamp signs with a key the server will not find. */
                expect(keys_a.have_x25519 &&
                           memcmp(keys_a.x25519_priv, keys_a.hybrid.x25519_priv, LC_X25519_KEY) == 0,
                       "and the private half kept for x25519 is the hybrid's own");
            }

            keys_free(&keys_a);
            keys_free(&keys_b);
        }
    }

    printf("\n%s\n", failures == 0 ? "a message is what it is, however it arrives"
                                   : "the framing does not hold");
    return failures == 0 ? 0 : 1;
}
