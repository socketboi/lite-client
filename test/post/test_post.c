/* What this client makes of the server's records once the handshake is over — src/tls/post.c.
 *
 * Every case below is one of tools/vendorcap/nodealert's scenarios, where a stock REALITY node
 * misbehaved in front of Xray's own client and of lc-tunnel, and the alert each sent back was read
 * with the client's key. The expectations are what the REFERENCE did there, not a reading of its
 * source — the run is recorded in that stand's header. What a stand cannot reach cheaply is added
 * by hand and says so: the boundaries of a count, a message cut at every byte. */

#include "tls/post.h"

#include "tls/alert.h"
#include "tls/msg.h"
#include "tls/record.h"

#include <stdio.h>
#include <string.h>

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

/* The node's NewSessionTicket: lifetime 7200, age_add, a one-byte nonce, a four-byte ticket, no
 * extensions — tools/vendorcap/nodealert/node/main.go's `nst`. */
static const uint8_t nst[] = { 0x04, 0x00, 0x00, 0x12, 0x00, 0x00, 0x1c, 0x20, 0x01, 0x02, 0x03,
                               0x04, 0x01, 0x00, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00 };

/* One record through a fresh state, or through `p` when given. */
static int rec(lc_post *p, uint8_t inner, const uint8_t *b, size_t n, uint8_t *alert)
{
    const char *why = NULL;
    *alert = 0xffu;
    return lc_post_record(p, b, n, inner, alert, &why);
}

static int refused_with(int v, const uint8_t *alert, uint8_t want)
{
    return v == LC_POST_REFUSED && *alert == want;
}

static void headers(void)
{
    printf("record headers\n");
    uint8_t     a = 0;
    const char *why = NULL;
    const uint8_t ok[5] = { 0x17, 0x03, 0x03, 0x41, 0x00 };  /* 2^14 + 256, the most there is */
    const uint8_t vers[5] = { 0x17, 0x03, 0x01, 0x00, 0x20 };
    const uint8_t v13[5] = { 0x17, 0x03, 0x04, 0x00, 0x20 };
    const uint8_t huge[5] = { 0x17, 0x03, 0x03, 0x41, 0x01 };
    const lc_post p13 = { 0 };
    expect(lc_post_header(&p13, ok, &a, &why) == LC_POST_TAKEN, "a length of 2^14 + 256 is read");
    expect(refused_with(lc_post_header(&p13, vers, &a, &why), &a, LC_ALERT_PROTOCOL_VERSION),
           "vers: 0x0301 is protocol_version");
    expect(refused_with(lc_post_header(&p13, v13, &a, &why), &a, LC_ALERT_PROTOCOL_VERSION),
           "0x0304 is protocol_version too — 1.3 records say 0x0303");
    expect(refused_with(lc_post_header(&p13, huge, &a, &why), &a, LC_ALERT_RECORD_OVERFLOW),
           "huge: one over is record_overflow");
}

/* TLS 1.2 after the handshake (T3): a record may be up to 2^14 + 2048 (vendor/utls/conn.go:675-679),
 * a warning alert is dropped and counted, a fatal one ends it, any other level is 10 (:738-746); a
 * handshake message is a renegotiation — a HelloRequest refused with no_renegotiation, anything else
 * 10, a type uTLS does not know 10 twice (vendor/utls/conn.go:1270-1312). */
static void tls12(void)
{
    printf("TLS 1.2\n");
    lc_post       p = { 0 };
    uint8_t       a = 0;
    const char   *why = NULL;
    p.tls12 = 1;
    const uint8_t most[5] = { 0x17, 0x03, 0x03, 0x48, 0x00 }; /* 2^14 + 2048 */
    const uint8_t over[5] = { 0x17, 0x03, 0x03, 0x48, 0x01 };
    expect(lc_post_header(&p, most, &a, &why) == LC_POST_TAKEN, "a length of 2^14 + 2048 is read on TLS 1.2");
    expect(refused_with(lc_post_header(&p, over, &a, &why), &a, LC_ALERT_RECORD_OVERFLOW),
           "one over that is record_overflow");

    const uint8_t warn[2] = { 1u, 90u }, fatal[2] = { 2u, 40u }, odd[2] = { 3u, 40u }, close[2] = { 1u, 0u };
    expect(rec(&p, LC_REC_ALERT, warn, 2u, &a) == LC_POST_TAKEN, "a warning alert is dropped");
    expect(rec(&p, LC_REC_ALERT, fatal, 2u, &a) == LC_POST_ENDED && a == 40u, "a fatal one ends it");
    expect(refused_with(rec(&p, LC_REC_ALERT, odd, 2u, &a), &a, LC_ALERT_UNEXPECTED_MESSAGE),
           "a level that is neither is unexpected_message");
    expect(rec(&p, LC_REC_ALERT, close, 2u, &a) == LC_POST_CLOSED, "close_notify is the end of the stream");
    lc_post q = { 0 };
    q.tls12 = 1;
    int v = LC_POST_TAKEN;
    for (unsigned i = 0; i < 33u && v == LC_POST_TAKEN; i++)
        v = rec(&q, LC_REC_ALERT, warn, 2u, &a);
    expect(refused_with(v, &a, LC_ALERT_UNEXPECTED_MESSAGE), "the thirty-third warning in a row is 10");

    const uint8_t hello_req[4] = { 0x00, 0x00, 0x00, 0x00 }, hello_req_body[5] = { 0x00, 0x00, 0x00, 0x01, 0x00 };
    lc_post r = { 0 };
    r.tls12 = 1;
    expect(refused_with(rec(&r, LC_REC_HANDSHAKE, hello_req, 4u, &a), &a, LC_ALERT_NO_RENEGOTIATION),
           "a HelloRequest is no_renegotiation");
    lc_post_free(&r);
    expect(refused_with(rec(&r, LC_REC_HANDSHAKE, hello_req_body, 5u, &a), &a, LC_ALERT_UNEXPECTED_MESSAGE),
           "one with a body does not unmarshal: 10");
    lc_post_free(&r);
    expect(refused_with(rec(&r, LC_REC_HANDSHAKE, nst, sizeof nst, &a), &a, LC_ALERT_UNEXPECTED_MESSAGE),
           "a NewSessionTicket is not a HelloRequest: 10");
    lc_post_free(&r);
    const uint8_t unknown[4] = { 0x63, 0x00, 0x00, 0x00 };
    expect(rec(&r, LC_REC_HANDSHAKE, unknown, 4u, &a) == LC_POST_TWICE && a == LC_ALERT_UNEXPECTED_MESSAGE,
           "a type uTLS does not know is 10, twice");
    lc_post_free(&r);
}

static void ccs(void)
{
    printf("ChangeCipherSpec\n");
    lc_post       p = { 0 };
    uint8_t       a = 0;
    const char   *why = NULL;
    static uint8_t big[16385];
    const uint8_t one = 1u, two = 2u;
    memset(big, 1, sizeof big);
    expect(refused_with(lc_post_ccs(&p, &one, 1u, &a, &why), &a, LC_ALERT_UNEXPECTED_MESSAGE),
           "ccs: the right one is unexpected_message");
    expect(refused_with(lc_post_ccs(&p, &two, 1u, &a, &why), &a, LC_ALERT_DECODE_ERROR),
           "ccs2: a wrong byte is decode_error");
    expect(refused_with(lc_post_ccs(&p, NULL, 0u, &a, &why), &a, LC_ALERT_DECODE_ERROR),
           "ccs0: an empty one is decode_error");
    expect(refused_with(lc_post_ccs(&p, big, sizeof big, &a, &why), &a, LC_ALERT_RECORD_OVERFLOW),
           "ccsbig: over 2^14 is record_overflow, before anything is looked at");
    expect(refused_with(lc_post_ccs(&p, big, 16384u, &a, &why), &a, LC_ALERT_DECODE_ERROR),
           "2^14 of them is decode_error — the ceiling is inclusive");

    expect(rec(&p, LC_REC_HANDSHAKE, nst, 3u, &a) == LC_POST_TAKEN, "half a ticket waits");
    expect(refused_with(lc_post_ccs(&p, &two, 1u, &a, &why), &a, LC_ALERT_UNEXPECTED_MESSAGE),
           "partccs: a ChangeCipherSpec across a half-arrived message is 10, even a wrong one");
    lc_post_free(&p);
}

static void tickets(void)
{
    printf("NewSessionTicket\n");
    lc_post p = { 0 };
    uint8_t a = 0;
    expect(rec(&p, LC_REC_HANDSHAKE, nst, sizeof nst, &a) == LC_POST_TAKEN, "nst: read and ignored");
    expect(p.hand == NULL && p.hand_len == 0u, "and nothing is kept");

    /* Cut at every byte: the same ticket in two records. */
    int all = 1;
    for (size_t cut = 1; cut < sizeof nst; cut++) {
        lc_post q = { 0 };
        all &= rec(&q, LC_REC_HANDSHAKE, nst, cut, &a) == LC_POST_TAKEN;
        all &= q.hand_len == cut;
        all &= rec(&q, LC_REC_HANDSHAKE, nst + cut, sizeof nst - cut, &a) == LC_POST_TAKEN;
        all &= q.hand == NULL && q.hand_len == 0u;
        lc_post_free(&q);
    }
    expect(all, "nstsplit: a ticket cut at any byte is put back together and read");

    /* A ticket and a half, then the rest: the whole one is read, the half kept. */
    uint8_t two[2 * sizeof nst];
    memcpy(two, nst, sizeof nst);
    memcpy(two + sizeof nst, nst, sizeof nst);
    expect(rec(&p, LC_REC_HANDSHAKE, two, sizeof nst + 5u, &a) == LC_POST_TAKEN &&
               p.hand_len == 5u,
           "a whole ticket and five bytes of the next: the five are kept");
    expect(rec(&p, LC_REC_APPLICATION_DATA, (const uint8_t *)"x", 1u, &a) == LC_POST_REFUSED &&
               a == LC_ALERT_UNEXPECTED_MESSAGE,
           "and application data across them is 10");
    lc_post_free(&p);

    /* Half a ticket, then a record that finishes it and starts something else, then the rest of
     * that: what is kept after the first message has to be the START of the second — which a
     * second ticket, byte for byte the first, would not show. */
    uint8_t mid[sizeof nst - 3u + 2u];
    memcpy(mid, nst + 3, sizeof nst - 3u);
    mid[sizeof nst - 3u] = 0x63u;
    mid[sizeof nst - 2u] = 0x00u;
    const uint8_t tail[2] = { 0x00, 0x00 };
    expect(rec(&p, LC_REC_HANDSHAKE, nst, 3u, &a) == LC_POST_TAKEN &&
               rec(&p, LC_REC_HANDSHAKE, mid, sizeof mid, &a) == LC_POST_TAKEN &&
               p.hand_len == 2u && rec(&p, LC_REC_HANDSHAKE, tail, sizeof tail, &a) == LC_POST_TWICE,
           "a ticket finished by the record that starts the next message, and that message read");
    lc_post_free(&p);

    const uint8_t bad[] = { 0x04, 0x00, 0x00, 0x05, 0, 0, 0, 0, 0 };
    expect(refused_with(rec(&p, LC_REC_HANDSHAKE, bad, sizeof bad, &a), &a,
                        LC_ALERT_UNEXPECTED_MESSAGE),
           "nstbad: one that does not unmarshal is 10");
    lc_post_free(&p);
}

static void counts(void)
{
    printf("records that carry nothing\n");
    static uint8_t many[33 * sizeof nst];
    for (size_t i = 0; i < 33u; i++)
        memcpy(many + i * sizeof nst, nst, sizeof nst);
    uint8_t a = 0;
    lc_post p = { 0 };
    expect(rec(&p, LC_REC_HANDSHAKE, many, 32u * sizeof nst, &a) == LC_POST_TAKEN,
           "nst32: thirty-two tickets in one record are read");
    lc_post_free(&p);
    p.useless = 0;
    expect(refused_with(rec(&p, LC_REC_HANDSHAKE, many, sizeof many, &a), &a,
                        LC_ALERT_UNEXPECTED_MESSAGE),
           "nst33: the thirty-third is 10");
    lc_post_free(&p);

    /* The record that brings tickets starts the count again, so tickets one to a record never add
     * up — the count is per record for them, and across records for empty ones. */
    lc_post q = { 0 };
    int     ok = 1;
    for (int i = 0; i < 100; i++)
        ok &= rec(&q, LC_REC_HANDSHAKE, nst, sizeof nst, &a) == LC_POST_TAKEN;
    expect(ok, "a hundred tickets one to a record are all read");

    lc_post e = { 0 };
    ok = 1;
    for (int i = 0; i < 32; i++)
        ok &= rec(&e, LC_REC_APPLICATION_DATA, NULL, 0u, &a) == LC_POST_TAKEN;
    expect(ok, "thirty-two empty records are read");
    expect(refused_with(rec(&e, LC_REC_APPLICATION_DATA, NULL, 0u, &a), &a,
                        LC_ALERT_UNEXPECTED_MESSAGE),
           "the thirty-third is 10");

    lc_post r = { 0 };
    ok = 1;
    for (int i = 0; i < 32; i++)
        ok &= rec(&r, LC_REC_APPLICATION_DATA, NULL, 0u, &a) == LC_POST_TAKEN;
    ok &= rec(&r, LC_REC_APPLICATION_DATA, (const uint8_t *)"x", 1u, &a) == LC_POST_DATA;
    for (int i = 0; i < 32; i++)
        ok &= rec(&r, LC_REC_APPLICATION_DATA, NULL, 0u, &a) == LC_POST_TAKEN;
    expect(ok, "a record with bytes in it starts the count again");

    lc_post t = { 0 };
    ok = 1;
    for (int i = 0; i < 31; i++)
        ok &= rec(&t, LC_REC_APPLICATION_DATA, NULL, 0u, &a) == LC_POST_TAKEN;
    ok &= rec(&t, LC_REC_HANDSHAKE, nst, sizeof nst, &a) == LC_POST_TAKEN;
    expect(ok && t.useless == 1u,
           "a ticket's record starts it again too, and then counts its ticket — one");

    lc_post w = { 0 };
    const uint8_t cn[2] = { 1, 0 };
    ok = 1;
    for (int i = 0; i < 32; i++)
        ok &= rec(&w, LC_REC_APPLICATION_DATA, NULL, 0u, &a) == LC_POST_TAKEN;
    expect(ok && rec(&w, LC_REC_ALERT, cn, 2u, &a) == LC_POST_CLOSED,
           "close_notify after thirty-two empty records is the end of the stream, not the thirty-third");
}

static void handshake_records(void)
{
    printf("other handshake messages\n");
    uint8_t a = 0;
    lc_post p = { 0 };
    const uint8_t unknown[] = { 0x63, 0, 0, 0 };
    const uint8_t fin[] = { 0x14, 0, 0, 0 };
    const uint8_t big[] = { 0x04, 0x01, 0x00, 0x01 };
    const uint8_t cert[] = { 0x0b, 0x04, 0x00, 0x01 };
    const uint8_t certok[] = { 0x0b, 0x04, 0x00, 0x00 };
    const uint8_t max[] = { 0x04, 0x01, 0x00, 0x00 };
    const uint8_t kubad[] = { 0x18, 0, 0, 1, 2 };

    expect(refused_with(rec(&p, LC_REC_HANDSHAKE, NULL, 0u, &a), &a, LC_ALERT_UNEXPECTED_MESSAGE),
           "hs0: an empty handshake record is 10");
    expect(rec(&p, LC_REC_HANDSHAKE, unknown, sizeof unknown, &a) == LC_POST_TWICE &&
               a == LC_ALERT_UNEXPECTED_MESSAGE,
           "hsunknown: a type uTLS does not know is 10, twice");
    const uint8_t ee[] = { 0x08, 0, 0, 0 }, cc[] = { 0x19, 0, 0, 0 }, three[] = { 0x03, 0, 0, 0 };
    expect(refused_with(rec(&p, LC_REC_HANDSHAKE, ee, sizeof ee, &a), &a,
                        LC_ALERT_UNEXPECTED_MESSAGE) &&
               refused_with(rec(&p, LC_REC_HANDSHAKE, cc, sizeof cc, &a), &a,
                            LC_ALERT_UNEXPECTED_MESSAGE),
           "EncryptedExtensions and CompressedCertificate, which uTLS adds, are 10 once");
    expect(rec(&p, LC_REC_HANDSHAKE, three, sizeof three, &a) == LC_POST_TWICE,
           "type 3, which nothing has, twice");
    const uint8_t unknown_big[] = { 0x63, 0x01, 0x00, 0x01 };
    expect(refused_with(rec(&p, LC_REC_HANDSHAKE, unknown_big, sizeof unknown_big, &a), &a,
                        LC_ALERT_INTERNAL_ERROR),
           "an unknown type declared over 64 KiB is internal_error — the length is read first");
    const uint8_t unknown_long[] = { 0x63, 0, 0, 2, 0 };
    expect(rec(&p, LC_REC_HANDSHAKE, unknown_long, sizeof unknown_long, &a) == LC_POST_TAKEN,
           "and one whose body has not all arrived is not refused yet");
    expect(rec(&p, LC_REC_HANDSHAKE, unknown_long + 4, 1u, &a) == LC_POST_TWICE,
           "until it has");
    lc_post_free(&p);
    expect(refused_with(rec(&p, LC_REC_HANDSHAKE, fin, sizeof fin, &a), &a,
                        LC_ALERT_UNEXPECTED_MESSAGE),
           "hsfin: a Finished is 10");
    expect(refused_with(rec(&p, LC_REC_HANDSHAKE, big, sizeof big, &a), &a, LC_ALERT_INTERNAL_ERROR),
           "hsbig: a ticket declared over 64 KiB is internal_error, on the four bytes alone");
    expect(rec(&p, LC_REC_HANDSHAKE, max, sizeof max, &a) == LC_POST_TAKEN && p.hand_len == 4u,
           "one declared at exactly 64 KiB waits for its body");
    lc_post_free(&p);
    expect(refused_with(rec(&p, LC_REC_HANDSHAKE, cert, sizeof cert, &a), &a,
                        LC_ALERT_INTERNAL_ERROR),
           "hscert: a Certificate declared over 256 KiB is internal_error");
    expect(rec(&p, LC_REC_HANDSHAKE, certok, sizeof certok, &a) == LC_POST_TAKEN,
           "hscertok: one at 256 KiB waits for its body");
    expect(refused_with(rec(&p, LC_REC_APPLICATION_DATA, (const uint8_t *)"x", 1u, &a), &a,
                        LC_ALERT_UNEXPECTED_MESSAGE),
           "and the reply that interrupts it is 10");
    lc_post_free(&p);

    expect(rec(&p, LC_REC_HANDSHAKE, big, 3u, &a) == LC_POST_TAKEN &&
               p.hand_len == 3u,
           "three bytes of a header are not yet a length, so nothing is refused");
    expect(refused_with(rec(&p, LC_REC_HANDSHAKE, big + 3, 1u, &a), &a, LC_ALERT_INTERNAL_ERROR),
           "the fourth makes it one, and the refusal comes then");
    lc_post_free(&p);

    expect(refused_with(rec(&p, LC_REC_HANDSHAKE, kubad, sizeof kubad, &a), &a,
                        LC_ALERT_UNEXPECTED_MESSAGE),
           "a KeyUpdate that does not unmarshal is 10");
    lc_post_free(&p);
}


/* What handleKeyUpdate is handed, in order: the caller's `key_update`, recorded. */
static int ku_calls, ku_requested[64], ku_fail_at = -1;

static int ku_record(void *ctx, int requested)
{
    (void)ctx;
    if (ku_calls < 64)
        ku_requested[ku_calls] = requested;
    return ku_calls++ == ku_fail_at ? -1 : 0;
}

static void key_updates(void)
{
    printf("KeyUpdate\n");
    uint8_t       a = 0;
    lc_post       p = { 0 };
    const uint8_t ku0[] = { 0x18, 0, 0, 1, 0 }, ku1[] = { 0x18, 0, 0, 1, 1 };

    expect(rec(&p, LC_REC_HANDSHAKE, ku0, sizeof ku0, &a) == LC_POST_ENDED && a == 0u,
           "with nobody to act on it, a KeyUpdate ends the connection and owes no alert");

    p.key_update = ku_record;
    ku_calls = 0;
    expect(rec(&p, LC_REC_HANDSHAKE, ku0, sizeof ku0, &a) == LC_POST_TAKEN && ku_calls == 1 &&
               ku_requested[0] == 0,
           "update_not_requested is handed on as 0");
    expect(rec(&p, LC_REC_HANDSHAKE, ku1, sizeof ku1, &a) == LC_POST_TAKEN && ku_calls == 2 &&
               ku_requested[1] == 1,
           "update_requested as 1");

    /* A ticket, a KeyUpdate asking for one back, a ticket: all in one record, the call in its place
     * and the ticket after it read as it came. */
    uint8_t mix[sizeof nst + sizeof ku1 + sizeof nst];
    memcpy(mix, nst, sizeof nst);
    memcpy(mix + sizeof nst, ku1, sizeof ku1);
    memcpy(mix + sizeof nst + sizeof ku1, nst, sizeof nst);
    ku_calls = 0;
    expect(rec(&p, LC_REC_HANDSHAKE, mix, sizeof mix, &a) == LC_POST_TAKEN && ku_calls == 1 &&
               p.useless == 3u,
           "a KeyUpdate between two tickets in one record: one call, three messages counted");

    ku_calls = 0;
    expect(rec(&p, LC_REC_HANDSHAKE, ku1, 2u, &a) == LC_POST_TAKEN && ku_calls == 0 &&
               rec(&p, LC_REC_HANDSHAKE, ku1 + 2, sizeof ku1 - 2u, &a) == LC_POST_TAKEN &&
               ku_calls == 1,
           "one cut across two records is acted on once it is whole, and not before");

    ku_calls = 0;
    ku_fail_at = 0;
    expect(rec(&p, LC_REC_HANDSHAKE, ku1, sizeof ku1, &a) == LC_POST_ENDED && a == 0u,
           "a KeyUpdate the caller cannot carry out ends the connection, with no alert");
    ku_fail_at = -1;
    lc_post_free(&p);

    /* The count comes first (vendor/utls/conn.go:1325-1329): thirty-three in one record are
     * refused at the thirty-third, and only thirty-two were acted on. */
    static uint8_t many[33 * sizeof ku0];
    for (size_t i = 0; i < 33u; i++)
        memcpy(many + i * sizeof ku0, ku0, sizeof ku0);
    lc_post q = { 0 };
    q.key_update = ku_record;
    ku_calls = 0;
    expect(refused_with(rec(&q, LC_REC_HANDSHAKE, many, sizeof many, &a), &a,
                        LC_ALERT_UNEXPECTED_MESSAGE) && ku_calls == 32,
           "thirty-three in one record: thirty-two acted on, the thirty-third is 10");
    lc_post_free(&q);
}

static void alerts_and_types(void)
{
    printf("alerts and types\n");
    uint8_t       a = 0;
    lc_post       p = { 0 };
    const uint8_t three[3] = { 2, 40, 0 };
    const uint8_t fatal[2] = { 2, 80 };
    const uint8_t warn[2] = { 1, 90 };
    const uint8_t cn[2] = { 1, 0 };
    const uint8_t cn_fatal[2] = { 2, 0 };
    expect(refused_with(rec(&p, LC_REC_ALERT, three, sizeof three, &a), &a,
                        LC_ALERT_UNEXPECTED_MESSAGE),
           "alertbad: an alert of three bytes is 10");
    expect(refused_with(rec(&p, LC_REC_ALERT, three, 1u, &a), &a, LC_ALERT_UNEXPECTED_MESSAGE),
           "and one of a single byte");
    expect(rec(&p, LC_REC_ALERT, fatal, sizeof fatal, &a) == LC_POST_ENDED,
           "alert: the server's fatal alert ends it, and nothing is sent back");
    expect(rec(&p, LC_REC_ALERT, warn, sizeof warn, &a) == LC_POST_ENDED,
           "alertwarn: so does a warning — TLS 1.3 has no warnings but close_notify");
    expect(rec(&p, LC_REC_ALERT, cn, sizeof cn, &a) == LC_POST_CLOSED,
           "close: close_notify is the end of the server's stream");
    expect(rec(&p, LC_REC_ALERT, cn_fatal, sizeof cn_fatal, &a) == LC_POST_CLOSED,
           "whatever level it comes at");
    expect(refused_with(rec(&p, 24u, cn, sizeof cn, &a), &a, LC_ALERT_UNEXPECTED_MESSAGE),
           "type24: a type TLS does not have is 10");
    expect(rec(&p, LC_REC_APPLICATION_DATA, (const uint8_t *)"x", 1u, &a) == LC_POST_DATA,
           "application data with bytes in it is the caller's");

    expect(rec(&p, LC_REC_HANDSHAKE, nst, 2u, &a) == LC_POST_TAKEN, "half a ticket waits");
    expect(refused_with(rec(&p, LC_REC_ALERT, cn, sizeof cn, &a), &a, LC_ALERT_UNEXPECTED_MESSAGE),
           "and even close_notify across it is 10");
    lc_post_free(&p);
}

int main(void)
{
    headers();
    tls12();
    ccs();
    tickets();
    counts();
    handshake_records();
    alerts_and_types();
    key_updates();
    if (failures) {
        printf("%d FAILED\n", failures);
        return 1;
    }
    printf("all passed\n");
    return 0;
}
