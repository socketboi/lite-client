#include "tls/post.h"

#include "tls/alert.h"
#include "tls/msg.h"
#include "tls/record.h"
#include "tls/stdmsg.h"

#include <stdlib.h>
#include <string.h>

/* `maxUselessRecords` (vendor/utls/common.go:73). */
#define MAX_USELESS 32u
/* readHandshake's ceilings (vendor/utls/common.go:71-72): `maxHandshake`, and
 * `maxHandshakeCertificateMsg` for a Certificate once the version is known. */
#define MAX_HANDSHAKE      65536u
#define MAX_HANDSHAKE_CERT 262144u

static int refuse(uint8_t *alert, const char **why, uint8_t a, const char *w)
{
    *alert = a;
    *why = w;
    return LC_POST_REFUSED;
}

int lc_post_header(const lc_post *p, const uint8_t hdr[5], uint8_t *alert, const char **why)
{
    /* `c.haveVers && vers != expectedVers`, where a TLS 1.3 connection expects 0x0303
     * (vendor/utls/conn.go:653-665). */
    if (hdr[1] != 0x03u || hdr[2] != 0x03u)
        return refuse(alert, why, LC_ALERT_PROTOCOL_VERSION, "a record with the wrong version");
    /* `n > maxCiphertextTLS13` (:676-680) — or maxCiphertext, 2^14 + 2048, on TLS 1.2. */
    size_t n = (size_t)hdr[3] << 8 | hdr[4];
    if (n > LC_REC_MAX_PLAINTEXT + (p->tls12 ? 2048u : 256u))
        return refuse(alert, why, LC_ALERT_RECORD_OVERFLOW, "an oversized record");
    return LC_POST_TAKEN;
}

int lc_post_ccs(const lc_post *p, const uint8_t *body, size_t n, uint8_t *alert, const char **why)
{
    /* Over 2^14 (:694-696); with a handshake message half-arrived (:708-711); not the one byte 1
     * (:740-743); and otherwise not expected once the handshake is done (:756-758). */
    if (n > LC_REC_MAX_PLAINTEXT)
        return refuse(alert, why, LC_ALERT_RECORD_OVERFLOW, "an oversized record");
    if (p->hand_len > 0u)
        return refuse(alert, why, LC_ALERT_UNEXPECTED_MESSAGE,
                      "a ChangeCipherSpec across a handshake message");
    if (n != 1u || body[0] != 1u)
        return refuse(alert, why, LC_ALERT_DECODE_ERROR, "a malformed ChangeCipherSpec");
    return refuse(alert, why, LC_ALERT_UNEXPECTED_MESSAGE, "a ChangeCipherSpec after the handshake");
}

/* A handshake record: its bytes join c.hand, and every whole message in it goes through UConn's
 * handlePostHandshakeMessage (vendor/utls/u_conn.go:957-984). readHandshake first: its ceiling,
 * refused with internal_error as soon as the four bytes that declare the length are in
 * (vendor/utls/conn.go:1096-1120), then the whole message unmarshalled — a type uTLS does not know
 * is 10 twice, one that does not unmarshal 10 (:1169-1186). Then the count of useless records,
 * then the message. A NewSessionTicket is read and ignored: Xray's REALITY client runs with
 * SessionTicketsDisabled, and handleNewSessionTicket returns before looking further
 * (vendor/utls/handshake_client_tls13.go:975-983). Anything else that unmarshals is 10 as well.
 * What has not all arrived waits for the next record. */
static int handshake(lc_post *p, const uint8_t *data, size_t len, uint8_t *alert, const char **why)
{
    const uint8_t *buf = data;
    size_t         have = len;
    if (p->hand_len > 0u) {
        uint8_t *grown = realloc(p->hand, p->hand_len + len);
        if (grown == NULL)
            return LC_POST_NOMEM;
        memcpy(grown + p->hand_len, data, len);
        p->hand = grown;
        p->hand_len += len;
        buf = p->hand;
        have = p->hand_len;
    }

    size_t off = 0;
    while (have - off >= 4u) {
        const uint8_t *m = buf + off;
        size_t         n = (size_t)m[1] << 16 | (size_t)m[2] << 8 | m[3];
        if (n > (m[0] == LC_HS_CERTIFICATE ? MAX_HANDSHAKE_CERT : MAX_HANDSHAKE))
            return refuse(alert, why, LC_ALERT_INTERNAL_ERROR,
                          "a post-handshake message longer than the reference reads");
        if (have - off < 4u + n)
            break;
        /* A type uTLS has no message for is refused as soon as the whole of it is in, and twice
         * (vendor/utls/u_conn.go:836-837, vendor/utls/conn.go:1184) — see lc_hs_utls_knows. */
        if (!lc_hs_utls_knows(m[0])) {
            *alert = LC_ALERT_UNEXPECTED_MESSAGE;
            *why = "a handshake message of a type uTLS does not know";
            return LC_POST_TWICE;
        }
        /* TLS 1.2: handleRenegotiation, not handlePostHandshakeMessage (vendor/utls/u_conn.go:957-960,
         * vendor/utls/conn.go:1270-1312). A HelloRequest that unmarshals — nothing after its header —
         * is refused with no_renegotiation, Xray's config leaving Renegotiation at RenegotiateNever;
         * any other message is unexpected_message, and none of it counts as a useless record. */
        if (p->tls12) {
            if (m[0] == 0u && n == 0u)
                return refuse(alert, why, LC_ALERT_NO_RENEGOTIATION, "a request to renegotiate");
            return refuse(alert, why, LC_ALERT_UNEXPECTED_MESSAGE,
                          "a handshake message after the TLS 1.2 handshake that is not a HelloRequest");
        }
        int ok = 0, requested = 0;
        if (m[0] == LC_HS_NEW_SESSION_TICKET)
            ok = lc_std_ticket13_reads(m, 4u + n);
        else if (m[0] == LC_HS_KEY_UPDATE)
            ok = lc_std_key_update_reads(m, 4u + n, &requested);
        if (!ok)
            return refuse(alert, why, LC_ALERT_UNEXPECTED_MESSAGE,
                          "a post-handshake message a client does not take");
        if (++p->useless > MAX_USELESS)
            return refuse(alert, why, LC_ALERT_UNEXPECTED_MESSAGE,
                          "more records that carry nothing than the reference takes");
        /* handleKeyUpdate (vendor/utls/conn.go:1345-1382) is the caller's: the keys are its. A Go
         * node never sends one of its own accord — `keyUpdateMsg{}` is built in one place in the
         * reference, the answer — but a peer may, and a client that ignored it could open nothing
         * after it. */
        if (m[0] == LC_HS_KEY_UPDATE &&
            (p->key_update == NULL || p->key_update(p->ctx, requested) != 0)) {
            *alert = 0;
            *why = "a KeyUpdate that could not be acted on";
            return LC_POST_ENDED;
        }
        off += 4u + n;
    }

    size_t rest = have - off;
    if (rest == 0u) {
        lc_post_free(p);
        return LC_POST_TAKEN;
    }
    if (buf == p->hand) {
        memmove(p->hand, p->hand + off, rest);
    } else {
        uint8_t *kept = malloc(rest);
        if (kept == NULL)
            return LC_POST_NOMEM;
        memcpy(kept, buf + off, rest);
        free(p->hand);
        p->hand = kept;
    }
    p->hand_len = rest;
    return LC_POST_TAKEN;
}

int lc_post_record(lc_post *p, const uint8_t *plain, size_t len, uint8_t inner, uint8_t *alert,
                   const char **why)
{
    /* A record that moved something starts the count again (:703-706). */
    if (inner != LC_REC_ALERT && len > 0u)
        p->useless = 0;
    /* Anything but a handshake record, with a handshake message half-arrived (:708-711). */
    if (inner != LC_REC_HANDSHAKE && p->hand_len > 0u)
        return refuse(alert, why, LC_ALERT_UNEXPECTED_MESSAGE,
                      "another record across a handshake message");
    switch (inner) {
    case LC_REC_ALERT:
        /* The server's alert ends its stream: close_notify as the end of it, anything else as an
         * error with nothing sent back — TLS 1.3 makes every other alert fatal whatever its level
         * (:717-729). One that is not two bytes is 10. */
        if (len != 2u)
            return refuse(alert, why, LC_ALERT_UNEXPECTED_MESSAGE, "a malformed alert");
        if (plain[1] == LC_ALERT_CLOSE_NOTIFY)
            return LC_POST_CLOSED;
        /* TLS 1.2 keeps the levels: a warning is dropped and reading goes on, up to the count; a fatal
         * one ends it; any other level is 10 (:730-738). */
        if (p->tls12 && plain[0] == 1u) {
            if (++p->useless > MAX_USELESS)
                return refuse(alert, why, LC_ALERT_UNEXPECTED_MESSAGE,
                              "more records that carry nothing than the reference takes");
            return LC_POST_TAKEN;
        }
        if (p->tls12 && plain[0] != 2u)
            return refuse(alert, why, LC_ALERT_UNEXPECTED_MESSAGE, "an alert of an unknown level");
        *alert = plain[1];
        *why = "an alert";
        return LC_POST_ENDED;
    case LC_REC_HANDSHAKE:
        if (len == 0u)
            return refuse(alert, why, LC_ALERT_UNEXPECTED_MESSAGE, "an empty handshake record");
        return handshake(p, plain, len, alert, why);
    case LC_REC_APPLICATION_DATA:
        /* An empty one means nothing — TLS 1.3 allows them, and a REALITY node sends them in its
         * target's post-handshake lengths (vendor/REALITY/tls.go:419-435) — up to the count
         * (:781-785, retryReadRecord at :802-809). */
        if (len > 0u)
            return LC_POST_DATA;
        if (++p->useless > MAX_USELESS)
            return refuse(alert, why, LC_ALERT_UNEXPECTED_MESSAGE,
                          "more records that carry nothing than the reference takes");
        return LC_POST_TAKEN;
    default:
        return refuse(alert, why, LC_ALERT_UNEXPECTED_MESSAGE, "a record of a type TLS does not have");
    }
}

void lc_post_free(lc_post *p)
{
    free(p->hand);
    p->hand = NULL;
    p->hand_len = 0;
}
