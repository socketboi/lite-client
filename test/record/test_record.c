/* The record layer against the RFC 8448 trace.
 *
 * The document prints, for every record sent, both the plaintext the handshake produced and the
 * bytes that went on the wire. For protected records the second is the first sealed under the
 * traffic keys it also prints — which makes the trace a complete AEAD test, sequence numbers
 * included.
 *
 * Sequence numbers are the point of testing it this way. They are never transmitted: both ends
 * count independently, and a single miscount produces an authentication failure several records
 * later, far from the cause. Replaying the whole conversation in order is the only way to catch
 * that before a live server does. */

#include "tls/record.h"
#include "tls/alert.h"
#include "test_vectors.h"

#include <stdio.h>
#include <string.h>

#define SZ(a) (sizeof(a) / sizeof((a)[0]))

static int failures;

static void report(const char *what, const uint8_t *got, size_t got_len,
                   const uint8_t *want, size_t want_len)
{
    if (got_len == want_len && memcmp(got, want, want_len) == 0) {
        printf("  ok    %s (%zu bytes)\n", what, want_len);
        return;
    }
    printf("  FAIL  %s: %zu bytes against %zu expected\n", what, got_len, want_len);
    size_t n = got_len < want_len ? got_len : want_len;
    for (size_t i = 0; i < n; i++) {
        if (got[i] != want[i]) {
            printf("        first difference at byte %zu: %02x against %02x\n", i, got[i], want[i]);
            break;
        }
    }
    failures++;
}

/* One record from the trace: open it, then seal the plaintext back and check the wire bytes match.
 * Opening proves the nonce and the AAD; sealing proves nothing was reconstructed by accident. */
static void replay(lc_record_key *k, const char *what,
                   const uint8_t *record, size_t record_len,
                   const uint8_t *payload, size_t payload_len,
                   uint8_t want_type)
{
    uint8_t open_buf[LC_REC_MAX_PLAINTEXT];
    size_t  open_len = 0;
    uint8_t type = 0;

    uint64_t seq_before = k->seq;
    if (lc_record_unprotect(k, record, record_len, open_buf, sizeof open_buf, &open_len, &type) != 0) {
        printf("  FAIL  %s: does not authenticate at sequence %llu\n",
               what, (unsigned long long)seq_before);
        failures++;
        return;
    }
    char name[96];
    snprintf(name, sizeof name, "%s — plaintext", what);
    report(name, open_buf, open_len, payload, payload_len);

    if (type != want_type) {
        printf("  FAIL  %s: inner content type %02x against %02x expected\n", what, type, want_type);
        failures++;
    }

    /* Seal it again at the sequence number it was sent with, and the wire bytes must come back
     * identical: the record layer has no randomness of its own. */
    lc_record_key echo = *k;
    echo.seq = seq_before;
    uint8_t seal_buf[LC_REC_MAX_PLAINTEXT + LC_REC_HEADER + LC_AEAD_TAG];
    size_t  seal_len = 0;
    if (lc_record_protect(&echo, want_type, payload, payload_len, 0,
                          seal_buf, sizeof seal_buf, &seal_len) != 0) {
        printf("  FAIL  %s: cannot re-seal\n", what);
        failures++;
        return;
    }
    snprintf(name, sizeof name, "%s — wire bytes", what);
    report(name, seal_buf, seal_len, record, record_len);
}

int main(void)
{
    printf("RFC 8448 record layer, TLS_AES_128_GCM_SHA256\n");

    /* Server handshake keys protect exactly one record: everything from EncryptedExtensions to
     * the server Finished. */
    lc_record_key srv_hs;
    if (lc_record_key_init(&srv_hs, LC_AEAD_AES_128_GCM,
                           srv_wkeys_handshake_data_key_expanded,
                           srv_wkeys_handshake_data_iv_expanded) != 0) {
        printf("  FAIL  cannot bind server handshake keys\n");
        return 1;
    }
    replay(&srv_hs, "server handshake flight",
           srv_record_2_complete_record, SZ(srv_record_2_complete_record),
           srv_record_2_payload, SZ(srv_record_2_payload), LC_REC_HANDSHAKE);
    lc_record_key_free(&srv_hs);

    /* The server's READ keys for handshake data are the client's write keys — the trace prints
     * them from the server's side, which is the only place they appear. */
    lc_record_key cli_hs;
    if (lc_record_key_init(&cli_hs, LC_AEAD_AES_128_GCM,
                           srv_rkeys_handshake_data_key_expanded,
                           srv_rkeys_handshake_data_iv_expanded) != 0) {
        printf("  FAIL  cannot bind client handshake keys\n");
        return 1;
    }
    replay(&cli_hs, "client Finished",
           cli_record_2_complete_record, SZ(cli_record_2_complete_record),
           cli_record_2_payload, SZ(cli_record_2_payload), LC_REC_HANDSHAKE);
    lc_record_key_free(&cli_hs);

    /* Application keys carry three server records in a row. They are replayed on one key on
     * purpose: sequence numbers 0, 1 and 2 in order, which is where a miscount would show. */
    lc_record_key srv_app;
    if (lc_record_key_init(&srv_app, LC_AEAD_AES_128_GCM,
                           srv_wkeys_application_data_key_expanded,
                           srv_wkeys_application_data_iv_expanded) != 0) {
        printf("  FAIL  cannot bind server application keys\n");
        return 1;
    }
    replay(&srv_app, "server NewSessionTicket (seq 0)",
           srv_record_3_complete_record, SZ(srv_record_3_complete_record),
           srv_record_3_payload, SZ(srv_record_3_payload), LC_REC_HANDSHAKE);
    replay(&srv_app, "server application data (seq 1)",
           srv_record_4_complete_record, SZ(srv_record_4_complete_record),
           srv_record_4_payload, SZ(srv_record_4_payload), LC_REC_APPLICATION_DATA);
    replay(&srv_app, "server close_notify (seq 2)",
           srv_record_5_complete_record, SZ(srv_record_5_complete_record),
           srv_record_5_payload, SZ(srv_record_5_payload), LC_REC_ALERT);
    lc_record_key_free(&srv_app);

    lc_record_key cli_app;
    if (lc_record_key_init(&cli_app, LC_AEAD_AES_128_GCM,
                           cli_wkeys_application_data_key_expanded,
                           cli_wkeys_application_data_iv_expanded) != 0) {
        printf("  FAIL  cannot bind client application keys\n");
        return 1;
    }
    replay(&cli_app, "client application data (seq 0)",
           cli_record_3_complete_record, SZ(cli_record_3_complete_record),
           cli_record_3_payload, SZ(cli_record_3_payload), LC_REC_APPLICATION_DATA);
    replay(&cli_app, "client close_notify (seq 1)",
           cli_record_4_complete_record, SZ(cli_record_4_complete_record),
           cli_record_4_payload, SZ(cli_record_4_payload), LC_REC_ALERT);
    lc_record_key_free(&cli_app);

    /* A record that has been tampered with must not open. Without this the whole file would pass
     * on an implementation that ignored the tag entirely. */
    lc_record_key tamper;
    if (lc_record_key_init(&tamper, LC_AEAD_AES_128_GCM,
                           srv_wkeys_handshake_data_key_expanded,
                           srv_wkeys_handshake_data_iv_expanded) == 0) {
        static uint8_t bad[SZ(srv_record_2_complete_record)];
        memcpy(bad, srv_record_2_complete_record, sizeof bad);
        bad[LC_REC_HEADER + 10u] ^= 0x01u;

        uint8_t out[LC_REC_MAX_PLAINTEXT];
        size_t  out_len = 0;
        uint8_t type = 0;
        int rc = lc_record_unprotect(&tamper, bad, sizeof bad, out, sizeof out, &out_len, &type);
        if (rc != -(int)LC_ALERT_BAD_RECORD_MAC) {
            printf("  FAIL  a flipped bit gave %d, where the reference answers bad_record_mac\n", rc);
            failures++;
        } else {
            printf("  ok    flipped bit rejected, with bad_record_mac as the reference sends\n");
        }
        lc_record_key_free(&tamper);
    }

    /* AND A RECORD LABELLED AS ANYTHING BUT application_data ON THE OUTSIDE MUST NOT OPEN EITHER —
     * with bad_record_mac, which is where the reference's answer turned out to be.
     *
     * TLS 1.3 puts 0x17 on every protected record whatever is really inside; the true type is the
     * last non-zero plaintext byte. The reference writes that rule down — `if typ !=
     * recordTypeApplicationData { return nil, 0, alertUnexpectedMessage }` (vendor/utls/conn.go:
     * 411-414) — but after the tag, and the tag covers the header (:372-373), so a relabelled
     * record fails the tag first and 20 is what goes back. This case expected nothing but a refusal
     * and so could not see that the number the handshake sent for it was 51.
     *
     * One byte of a record known to open is changed, so a refusal can only be about the outer type;
     * the untouched value is in the same loop, and asserts that it still opens. */
    {
        static uint8_t mislabelled[SZ(srv_record_2_complete_record)];
        uint8_t        out[LC_REC_MAX_PLAINTEXT];
        size_t         out_len = 0;
        uint8_t        type = 0;

        static const uint8_t outer[] = { LC_REC_APPLICATION_DATA, LC_REC_HANDSHAKE,
                                         LC_REC_ALERT, LC_REC_CHANGE_CIPHER_SPEC };
        for (unsigned i = 0; i < sizeof outer / sizeof outer[0]; i++) {
            lc_record_key k2;
            if (lc_record_key_init(&k2, LC_AEAD_AES_128_GCM,
                                   srv_wkeys_handshake_data_key_expanded,
                                   srv_wkeys_handshake_data_iv_expanded) != 0)
                continue;
            memcpy(mislabelled, srv_record_2_complete_record, sizeof mislabelled);
            mislabelled[0] = outer[i];
            out_len = 0;
            int rc = lc_record_unprotect(&k2, mislabelled, sizeof mislabelled, out, sizeof out,
                                         &out_len, &type);
            int want = outer[i] == LC_REC_APPLICATION_DATA ? 0 : -(int)LC_ALERT_BAD_RECORD_MAC;
            if (rc != want) {
                printf("  FAIL  outer type 0x%02x: %d, wanted %d\n", outer[i], rc, want);
                failures++;
            } else {
                printf(want == 0 ? "  ok    outer type 0x%02x opens, so the rest is about one byte\n"
                                 : "  ok    outer type 0x%02x is refused with bad_record_mac\n",
                       outer[i]);
            }
            lc_record_key_free(&k2);
        }
    }


    /* ⚠️ WHAT ONLY A PEER HOLDING THE KEY CAN SEND, and what the reference makes of it once the tag
     * has verified (vendor/utls/conn.go:411-427): a header other than application_data is
     * unexpected_message, an inner plaintext over 2^14 + 1 is record_overflow, a body of nothing but
     * a tag is an empty application-data record. This refused all three before opening, with
     * bad_record_mac. The records are sealed here by hand — header, inner plaintext exactly as
     * given, sequence number zero — because lc_record_protect writes none of them; the tools/
     * vendorcap/nodealert stand sends the same three from a REALITY node to Xray's own client. */
    {
        static uint8_t inner[LC_REC_MAX_PLAINTEXT + 2u], sealed[LC_REC_MAX_WIRE],
            out[LC_REC_MAX_OPEN];
        memset(inner, 'a', sizeof inner);
        inner[LC_REC_MAX_PLAINTEXT] = LC_REC_APPLICATION_DATA;
        inner[LC_REC_MAX_PLAINTEXT + 1u] = LC_REC_APPLICATION_DATA;

        struct {
            uint8_t     outer;
            size_t      inner_len;
            size_t      out_cap;
            int         want;
            size_t      want_len;
            const char *what;
        } cases[] = {
            { LC_REC_APPLICATION_DATA, 0u, sizeof out, 0, 0u,
              "a body of nothing but a tag opens, to an empty application-data record" },
            { LC_REC_APPLICATION_DATA, LC_REC_MAX_PLAINTEXT + 1u, sizeof out, 0, LC_REC_MAX_PLAINTEXT,
              "an inner plaintext of 2^14 + 1 opens: 2^14 bytes and the type" },
            { LC_REC_APPLICATION_DATA, LC_REC_MAX_PLAINTEXT + 1u, LC_REC_MAX_INNER, 0,
              LC_REC_MAX_PLAINTEXT, "and into a buffer of exactly LC_REC_MAX_INNER" },
            { LC_REC_APPLICATION_DATA, LC_REC_MAX_PLAINTEXT + 2u, sizeof out,
              -(int)LC_ALERT_RECORD_OVERFLOW, 0u, "one byte more is record_overflow" },
            { LC_REC_APPLICATION_DATA, LC_REC_MAX_PLAINTEXT + 2u, LC_REC_MAX_INNER,
              -(int)LC_ALERT_BAD_RECORD_MAC, 0u,
              "and bad_record_mac where there is no room to open it — the limit, named" },
            { LC_REC_HANDSHAKE, 1u, sizeof out, -(int)LC_ALERT_UNEXPECTED_MESSAGE, 0u,
              "sealed under a handshake header, unexpected_message" },
            { LC_REC_ALERT, 1u, sizeof out, -(int)LC_ALERT_UNEXPECTED_MESSAGE, 0u,
              "sealed under an alert header, the same" },
        };
        for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
            lc_aead a;
            lc_record_key r;
            if (lc_aead_init(&a, LC_AEAD_AES_128_GCM, srv_wkeys_handshake_data_key_expanded) != 0 ||
                lc_record_key_init(&r, LC_AEAD_AES_128_GCM, srv_wkeys_handshake_data_key_expanded,
                                   srv_wkeys_handshake_data_iv_expanded) != 0) {
                printf("  FAIL  keys for case %u\n", i);
                failures++;
                continue;
            }
            size_t body = cases[i].inner_len + LC_AEAD_TAG, n = 0;
            sealed[0] = cases[i].outer;
            sealed[1] = 0x03u;
            sealed[2] = 0x03u;
            sealed[3] = (uint8_t)(body >> 8);
            sealed[4] = (uint8_t)body;
            /* Sequence number zero: the nonce is the iv. */
            int rc = lc_aead_seal(&a, srv_wkeys_handshake_data_iv_expanded, sealed, LC_REC_HEADER,
                                  inner + sizeof inner - cases[i].inner_len, cases[i].inner_len,
                                  sealed + LC_REC_HEADER, sizeof sealed - LC_REC_HEADER, &n);
            size_t  out_len = 0xffffu;
            uint8_t type = 0;
            if (rc == 0)
                rc = lc_record_unprotect(&r, sealed, LC_REC_HEADER + n, out, cases[i].out_cap,
                                         &out_len, &type);
            int ok = rc == cases[i].want &&
                     (rc != 0 || (out_len == cases[i].want_len && type == LC_REC_APPLICATION_DATA));
            printf(ok ? "  ok    %s\n" : "  FAIL  %s (%d)\n", cases[i].what, rc);
            failures += !ok;
            lc_aead_free(&a);
            lc_record_key_free(&r);
        }
    }

    /* A PLAINTEXT THAT IS ALL PADDING has no content type, and the reference says so with
     * unexpected_message (vendor/utls/conn.go:418-427) — the one failure after the tag that a peer
     * holding the key can produce, and a different number from every failure before it. */
    {
        lc_record_key w, r;
        if (lc_record_key_init(&w, LC_AEAD_AES_128_GCM, srv_wkeys_handshake_data_key_expanded,
                               srv_wkeys_handshake_data_iv_expanded) == 0 &&
            lc_record_key_init(&r, LC_AEAD_AES_128_GCM, srv_wkeys_handshake_data_key_expanded,
                               srv_wkeys_handshake_data_iv_expanded) == 0) {
            uint8_t sealed[64], out[64];
            size_t  n = 0, out_len = 0;
            uint8_t type = 0xffu;
            int     rc = lc_record_protect(&w, 0x00u, NULL, 0, 3, sealed, sizeof sealed, &n);
            if (rc == 0)
                rc = lc_record_unprotect(&r, sealed, n, out, sizeof out, &out_len, &type);
            if (rc != -(int)LC_ALERT_UNEXPECTED_MESSAGE) {
                printf("  FAIL  a record of nothing but padding gave %d, not unexpected_message\n", rc);
                failures++;
            } else {
                printf("  ok    a record of nothing but padding is unexpected_message, as the "
                       "reference answers it\n");
            }
            lc_record_key_free(&w);
            lc_record_key_free(&r);
        }
    }


    {
        lc_record_key w, r;
        uint8_t key[16] = {0}, iv[LC_AEAD_NONCE] = {0};
        static uint8_t payload[LC_REC_MAX_PLAINTEXT], sealed[LC_REC_MAX_WIRE],
                       opened[LC_REC_MAX_INNER];
        memset(payload, 0x5a, sizeof payload);
        if (lc_record_key_init(&w, LC_AEAD_AES_128_GCM, key, iv) != 0 ||
            lc_record_key_init(&r, LC_AEAD_AES_128_GCM, key, iv) != 0)
            return 1;
        size_t n = 0, opened_len = 0;
        uint8_t type = 0;
        int rc = lc_record_protect(&w, LC_REC_APPLICATION_DATA, payload, sizeof payload,
                                   0, sealed, sizeof sealed, &n);
        if (rc == 0)
            rc = lc_record_unprotect(&r, sealed, n, opened, sizeof opened, &opened_len, &type);
        if (rc != 0 || opened_len != sizeof payload || type != LC_REC_APPLICATION_DATA ||
            memcmp(payload, opened, sizeof payload) != 0) {
            printf("  FAIL  full 16384-byte outgoing TLS payload roundtrip\n");
            failures++;
        } else {
            printf("  ok    full 16384-byte outgoing TLS payload roundtrip\n");
        }
        uint64_t seq = w.seq;
        if (lc_record_protect(&w, LC_REC_APPLICATION_DATA, payload, sizeof payload, 1,
                              sealed, sizeof sealed, &n) == 0 || w.seq != seq ||
            lc_record_protect(&w, LC_REC_APPLICATION_DATA, payload, sizeof payload + 1u, 0,
                              sealed, sizeof sealed, &n) == 0 || w.seq != seq ||
            lc_record_protect(&w, LC_REC_APPLICATION_DATA, payload, 1, SIZE_MAX,
                              sealed, sizeof sealed, &n) == 0 || w.seq != seq) {
            printf("  FAIL  oversized outgoing TLS plaintext rejected before sealing\n");
            failures++;
        } else {
            printf("  ok    oversized outgoing TLS plaintext rejected before sealing\n");
        }
        lc_record_key_free(&w);
        lc_record_key_free(&r);
    }

    /* Empty slices are valid for halfConn.encrypt, including CBC's copy(dst, payload).
     * Exercise the NULL/zero C representation in every TLS 1.2 record mode as well. */
    {
        static const uint16_t ids[] = {0xc013u, 0xc02fu, 0xcca8u};
        const uint8_t key[32] = {0}, iv[16] = {0}, mac[32] = {0};
        for (size_t i = 0; i < SZ(ids); i++) {
            const lc_tls12_suite *suite = lc_tls12_suite_by_id(ids[i]);
            lc_record_key w = {0}, r = {0};
            uint8_t sealed[128], plain[128], type = 0;
            size_t n = 0, len = 1;
            int rc = suite == NULL ? -1 : lc_record_key_init12(&w, suite, key, iv, mac, 0);
            if (rc == 0)
                rc = lc_record_key_init12(&r, suite, key, iv, mac, 1);
            if (rc == 0)
                rc = lc_record_protect(&w, LC_REC_APPLICATION_DATA, NULL, 0, 0,
                                       sealed, sizeof sealed, &n);
            if (rc == 0)
                rc = lc_record_unprotect(&r, sealed, n, plain, sizeof plain, &len, &type);
            if (rc != 0 || len != 0u || type != LC_REC_APPLICATION_DATA || w.seq != 1u || r.seq != 1u) {
                printf("  FAIL  empty TLS 1.2 payload in suite %04x\n", (unsigned)ids[i]);
                failures++;
            } else {
                printf("  ok    empty TLS 1.2 payload in suite %04x\n", (unsigned)ids[i]);
            }
            lc_record_key_free(&w);
            lc_record_key_free(&r);
        }
    }

    printf("\n%s\n", failures == 0 ? "record layer matches RFC 8448" : "RECORD LAYER IS WRONG");
    return failures == 0 ? 0 : 1;
}
