#include "tls/client.h"
#include "tls/prf12.h"
#include "tls/suite.h"

#include <mbedtls/pk.h>

#include "cert/cert.h"
#include "cert/chain.h"
#include "core/rnd.h"
#include "fp/hello.h"
#include "net/sock.h"
#include "tls/certcomp.h"
#include "tls/certverify.h"
#include "tls/hybrid.h"
#include "tls/kex.h"
#include "tls/msg.h"
#include "tls/suite.h"
#include "tls/transcript.h"
#include "core/wipe.h"

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define MAX_HELLO 16384u
#define MAX_FLIGHT 65536u

/* The groups the client can produce a key for (LC_GROUP_*) live in tls/kex.h — a fingerprint asking
 * for anything else is a table this build cannot honour, since a key share that is not a valid point
 * is detectable. */

/* Private material for every slot in the hello, kept until the server names the one it chose. */
typedef struct {
    lc_hybrid_key hybrid;
    int           have_hybrid;
    uint8_t       x25519_priv[LC_X25519_KEY];
    int           have_x25519;
    uint8_t       p256_priv[LC_P256_KEY];
    int           have_p256;
    uint8_t       p384_priv[LC_P384_KEY];
    int           have_p384;
    uint8_t       p521_priv[LC_P521_KEY];
    int           have_p521;
    /* The group of the first classical share in the hello, whose key is the one the reference
     * keeps — see shared_for — and the GREASE group, if a share carries one. */
    uint16_t      ecdhe_group;
    uint16_t      grease_group;
} client_keys;

static void keys_free(client_keys *k)
{
    if (k->have_hybrid)
        lc_hybrid_key_free(&k->hybrid);
    lc_wipe(k->x25519_priv, sizeof k->x25519_priv);
    lc_wipe(k->p256_priv, sizeof k->p256_priv);
    lc_wipe(k->p384_priv, sizeof k->p384_priv);
    lc_wipe(k->p521_priv, sizeof k->p521_priv);
    lc_wipe(k, sizeof *k);
}

static void say(char *err, size_t cap, const char *fmt, ...)
{
    if (err == NULL || cap == 0)
        return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, cap, fmt, ap);
    va_end(ap);
}

/* Fills the key_share slots the fingerprint asked for. A GREASE slot stays zero, which is what
 * Chrome puts there — the group does not exist, so nothing can be computed from it.
 *
 * TWO PASSES, AND THE SECOND ONE IS THE POINT: THE CLASSICAL SHARE IS THE HYBRID'S, NOT A SECOND KEY.
 *
 * A Firefox hello offers X25519MLKEM768 and X25519 both, and the X25519 it offers is not an
 * independent key pair — it is the same public key that sits in the last 32 bytes of the 1216-byte
 * hybrid share. uTLS says so structurally rather than in passing: the profile wraps the two entries
 * in a marker,
 *
 *     &KeyShareExtension{KeyShares: append(
 *         ReuseHybridAndClassicalKeyShares(
 *             KeyShare{Group: X25519MLKEM768},
 *             KeyShare{Group: X25519},
 *         ), KeyShare{Group: CurveP256})}     (vendor/utls/u_parrots.go:1611-1624, case at :1547)
 *
 * and ApplyPreset consumes it: the hybrid entry is built as
 * `append(mlkemKey.EncapsulationKey().Bytes(), ecdheKey.PublicKey().Bytes()...)` (:3270), that very
 * ecdheKey is stashed (:3274-3279), and the marked classical entry is then filled from it —
 * `reusedKey := keysForCurve[0]` / `ext.KeyShares[i].Data = reusedKey.PublicKey().Bytes()`
 * (vendor/utls/u_parrots.go:3292-3295). The markers themselves are
 * vendor/utls/u_public.go:649-662. Xray pins this exact revision (vendor/Xray-core/go.mod:18).
 *
 * So in EVERY reference Firefox hello, hybrid[1184:1216] equals the standalone X25519 entry byte for
 * byte. This client generated two independent pairs, so that equality never held — a test of two
 * 32-byte ranges at fixed offsets in the first TCP packet of every REALITY connection, needing no
 * state and no heuristics, and nothing fails while it is wrong: the REALITY server prefers the
 * standalone entry (vendor/REALITY/tls.go:215-239) and authenticates us normally. The pinned REALITY
 * loop also REQUIRES one X25519MLKEM768 share, placed before the standalone X25519 —
 * a hello without it is not a client and gets the real site — which the Firefox table meets.
 *
 * The acceptance gate cannot see it either — tools/fp/diff.go:128-140 reduces key_share to groups
 * and lengths, both of which were already right. That is why this survived a byte-for-byte
 * comparison that was doing its job as specified.
 *
 * The passes exist so that the reuse does not depend on the hybrid slot preceding the classical one
 * in the table.
 *
 * ⚠️ AND ONLY WHERE THE PROFILE CARRIES THE MARKER — which this copied for every profile, and was
 * wrong for the one the routers run. Chrome 133 lists the two entries bare, `{Group: X25519MLKEM768},
 * {Group: X25519}` (vendor/utls/u_parrots.go:946-950), and an entry without the marker gets a key of
 * its own: `ecdheKey, err := generateECDHEKey(uconn.config.rand(), curveID)` (:3304). The marker has
 * one user, Firefox 148 (:1613). So the same fixed-offset test flagged every Chrome hello of this
 * client the other way round — equal where the reference's never are. Whether to reuse now comes from
 * the table (info->key_share_reuse), which tools/fp reads off the capture: the two keys are equal
 * exactly when the parrot reused them. */
static int fill_key_share_slot(uint8_t *hello, const lc_hello_key_slot *s, client_keys *keys,
                               char *err, size_t err_cap);

static int fill_key_shares(uint8_t *hello, const lc_hello_out *info, client_keys *keys,
                           char *err, size_t err_cap)
{
    /* THE ONE KEY THE REFERENCE KEEPS: uTLS generates a key for every classical share and keeps
     * the first non-GREASE one as `KeyShareKeys.Ecdhe` (vendor/utls/u_parrots.go:3296-3314); the
     * hybrid's classical half is kept apart (:3272-3273). A retry replaces them all with the one
     * key it asked for (vendor/utls/handshake_client_tls13.go:348-354), which is this function
     * running again on the second hello. */
    keys->ecdhe_group = 0;
    keys->grease_group = 0;
    for (unsigned i = 0; i < info->slot_count; i++) {
        uint16_t g = info->slots[i].group;
        if (keys->ecdhe_group == 0u &&
            (g == LC_GROUP_X25519 || g == LC_GROUP_SECP256R1 || g == LC_GROUP_SECP384R1 ||
             g == LC_GROUP_SECP521R1))
            keys->ecdhe_group = g;
        if ((g & 0x0f0fu) == 0x0a0au && (g >> 8) == (g & 0xffu))
            keys->grease_group = g;
    }

    /* Everything except the standalone X25519 entry, so that the hybrid exists before it is asked for. */
    for (unsigned i = 0; i < info->slot_count; i++) {
        if (info->slots[i].group == LC_GROUP_X25519)
            continue;
        if (fill_key_share_slot(hello, &info->slots[i], keys, err, err_cap) != 0)
            return -1;
    }

    for (unsigned i = 0; i < info->slot_count; i++) {
        const lc_hello_key_slot *s = &info->slots[i];
        if (s->group != LC_GROUP_X25519)
            continue;
        if (s->len != LC_X25519_KEY) {
            say(err, err_cap, "fingerprint asks for %zu bytes of x25519", s->len);
            return -1;
        }
        if (keys->have_hybrid && info->key_share_reuse) {
            /* The hybrid share is ek || x25519_pub, so its classical public half is the last 32
             * bytes of what was written into that slot; the private half is already in the hybrid
             * key. Copied into x25519_priv as well as reused publicly, so that everything reading
             * the standalone key — shared_for when the server selects x25519, and the REALITY stamp
             * — keeps working on one key rather than learning about the reuse. */
            const lc_hello_key_slot *h = NULL;
            for (unsigned j = 0; j < info->slot_count; j++)
                if (info->slots[j].group == LC_GROUP_X25519MLKEM768)
                    h = &info->slots[j];
            if (h == NULL) {
                say(err, err_cap, "a hybrid key exists with no slot to have come from");
                return -1;
            }
            memcpy(hello + s->off, hello + h->off + LC_MLKEM_EK, LC_X25519_KEY);
            memcpy(keys->x25519_priv, keys->hybrid.x25519_priv, LC_X25519_KEY);
            keys->have_x25519 = 1;
            continue;
        }
        if (fill_key_share_slot(hello, s, keys, err, err_cap) != 0)
            return -1;
    }
    return 0;
}

static int fill_key_share_slot(uint8_t *hello, const lc_hello_key_slot *s, client_keys *keys,
                               char *err, size_t err_cap)
{
    {
        uint8_t *at = hello + s->off;

        switch (s->group) {
        case LC_GROUP_X25519MLKEM768: {
            if (s->len != LC_HYBRID_SHARE) {
                say(err, err_cap, "fingerprint asks for %zu bytes of X25519MLKEM768, protocol says %u",
                    s->len, (unsigned)LC_HYBRID_SHARE);
                return -1;
            }
            uint8_t share[LC_HYBRID_SHARE];
            if (lc_hybrid_keygen(&keys->hybrid, share) != 0) {
                say(err, err_cap, "cannot generate a hybrid key pair");
                return -1;
            }
            keys->have_hybrid = 1;
            memcpy(at, share, sizeof share);
            break;
        }
        case LC_GROUP_X25519: {
            if (s->len != LC_X25519_KEY) {
                say(err, err_cap, "fingerprint asks for %zu bytes of x25519", s->len);
                return -1;
            }
            uint8_t pub[LC_X25519_KEY];
            if (lc_x25519_keygen(keys->x25519_priv, pub) != 0) {
                say(err, err_cap, "cannot generate an x25519 key pair");
                return -1;
            }
            keys->have_x25519 = 1;
            memcpy(at, pub, sizeof pub);
            break;
        }
        case LC_GROUP_SECP256R1: {
            if (s->len != LC_P256_POINT) {
                say(err, err_cap, "fingerprint asks for %zu bytes of secp256r1", s->len);
                return -1;
            }
            uint8_t point[LC_P256_POINT];
            if (lc_p256_keygen(keys->p256_priv, point) != 0) {
                say(err, err_cap, "cannot generate a secp256r1 key pair");
                return -1;
            }
            keys->have_p256 = 1;
            memcpy(at, point, sizeof point);
            break;
        }
        case LC_GROUP_SECP384R1: {
            if (s->len != LC_P384_POINT) {
                say(err, err_cap, "fingerprint asks for %zu bytes of secp384r1", s->len);
                return -1;
            }
            uint8_t point[LC_P384_POINT];
            if (lc_p384_keygen(keys->p384_priv, point) != 0) {
                say(err, err_cap, "cannot generate a secp384r1 key pair");
                return -1;
            }
            keys->have_p384 = 1;
            memcpy(at, point, sizeof point);
            break;
        }
        case LC_GROUP_SECP521R1: {
            if (s->len != LC_P521_POINT) {
                say(err, err_cap, "fingerprint asks for %zu bytes of secp521r1", s->len);
                return -1;
            }
            uint8_t point[LC_P521_POINT];
            if (lc_p521_keygen(keys->p521_priv, point) != 0) {
                say(err, err_cap, "cannot generate a secp521r1 key pair");
                return -1;
            }
            keys->have_p521 = 1;
            memcpy(at, point, sizeof point);
            break;
        }
        default:
            /* A GREASE slot, or a group this build does not implement. The length tells them
             * apart: a GREASE key share is one or two bytes, a real one is dozens.
             *
             * Its contents are ZERO, not random. Chrome sends a single zero byte, and some servers
             * check — filling it with randomness produced illegal_parameter from several sites while
             * Cloudflare and Google accepted it happily. The builder already zeroed the slot, so
             * there is nothing to write here. */
            if (s->len > 8u) {
                say(err, err_cap, "fingerprint asks for group 0x%04x, which this build cannot produce",
                    s->group);
                return -1;
            }
            (void)at;
            break;
        }
    }
    return 0;
}

/* The shared secret for whichever group the server chose. */
static int shared_for(const client_keys *keys, const lc_server_hello *sh,
                      uint8_t *out, size_t *out_len, char *err, size_t err_cap)
{
    /* WITH THE REFERENCE'S KEY, WHATEVER GROUP THE SERVER NAMED. uTLS checks that the group
     * is among the hello's key shares (vendor/utls/handshake_client_tls13.go:536-541) and then
     * agrees with `keyShareKeys.ecdhe` — the first classical share's key — on the server's bytes
     * (vendor/utls/key_schedule.go:186-209). So a server choosing secp256r1 from a hello whose first
     * classical share is X25519 gets illegal_parameter. The new key-exchange helper parses
     * the peer key on the declared curve before ECDH, so a 32-byte cross-curve share
     * is refused too; the older helper accepted it as X25519. A server
     * choosing an offered GREASE group now gets internal_error: no key exchange exists for it
     * (vendor/utls/handshake_client_tls13.go:576-580). Only the hybrid has a key of its own
     * (vendor/utls/key_schedule.go:296-335).
     *
     * ⚠️ UNTIL 2026-09-27 each group used its own key, and a server choosing secp256r1 completed a
     * handshake the reference refuses. */
    uint16_t g = sh->group;
    if (g != LC_GROUP_X25519MLKEM768) {
        int offered = (g == LC_GROUP_X25519 && keys->have_x25519) ||
                      (g == LC_GROUP_SECP256R1 && keys->have_p256) ||
                      (g == LC_GROUP_SECP384R1 && keys->have_p384) ||
                      (g == LC_GROUP_SECP521R1 && keys->have_p521) ||
                      (keys->grease_group != 0u && g == keys->grease_group);
        if (!offered) {
            say(err, err_cap, "server chose group 0x%04x, which was not offered", g);
            return -1;
        }
        if (g == keys->grease_group && g != 0u) {
            say(err, err_cap, "server chose an offered group with no key exchange");
            return -2;
        }
        if (g != keys->ecdhe_group) {
            say(err, err_cap, "server chose a curve different from the retained ECDHE key");
            return -1;
        }
    }
    switch (g) {
    case LC_GROUP_X25519MLKEM768:
        if (!keys->have_hybrid || sh->key_share_len != LC_HYBRID_CT) {
            say(err, err_cap, "server chose X25519MLKEM768 with a %zu-byte share", sh->key_share_len);
            return -1;
        }
        if (lc_hybrid_shared(&keys->hybrid, sh->key_share, out) != 0) {
            say(err, err_cap, "hybrid key agreement failed");
            return -1;
        }
        *out_len = LC_HYBRID_SECRET;
        return 0;

    case LC_GROUP_X25519:
        if (!keys->have_x25519 || sh->key_share_len != LC_X25519_KEY) {
            say(err, err_cap, "the server's share, %zu bytes, is no key for our x25519", sh->key_share_len);
            return -1;
        }
        if (lc_x25519(keys->x25519_priv, sh->key_share, out) != 0) {
            say(err, err_cap, "x25519 agreement failed (low-order peer key?)");
            return -1;
        }
        *out_len = LC_X25519_SHARED;
        return 0;

    case LC_GROUP_SECP256R1:
        if (!keys->have_p256 || sh->key_share_len != LC_P256_POINT) {
            say(err, err_cap, "the server's share, %zu bytes, is no key for our secp256r1", sh->key_share_len);
            return -1;
        }
        if (lc_p256_shared(keys->p256_priv, sh->key_share, out) != 0) {
            say(err, err_cap, "secp256r1 agreement failed (point not on the curve?)");
            return -1;
        }
        *out_len = LC_P256_SHARED;
        return 0;

    case LC_GROUP_SECP384R1:
        if (!keys->have_p384 || sh->key_share_len != LC_P384_POINT) {
            say(err, err_cap, "the server's share, %zu bytes, is no key for our secp384r1", sh->key_share_len);
            return -1;
        }
        if (lc_p384_shared(keys->p384_priv, sh->key_share, out) != 0) {
            say(err, err_cap, "secp384r1 agreement failed (point not on the curve?)");
            return -1;
        }
        *out_len = LC_P384_SHARED;
        return 0;

    case LC_GROUP_SECP521R1:
        if (!keys->have_p521 || sh->key_share_len != LC_P521_POINT) {
            say(err, err_cap, "the server's share, %zu bytes, is no key for our secp521r1", sh->key_share_len);
            return -1;
        }
        if (lc_p521_shared(keys->p521_priv, sh->key_share, out) != 0) {
            say(err, err_cap, "secp521r1 agreement failed (point not on the curve?)");
            return -1;
        }
        *out_len = LC_P521_SHARED;
        return 0;

    default:
        say(err, err_cap, "server chose group 0x%04x, which was not offered", sh->group);
        return -1;
    }
}

/* An alert is the only thing a server ever tells us about why it refused, and there is exactly one
 * chance to read it. Turning the two bytes into words is the difference between a day of guessing
 * and knowing which field was wrong. */
static const char *alert_text(uint8_t desc)
{
    switch (desc) {
    case 0:   return "close_notify";
    case 10:  return "unexpected_message";
    case 20:  return "bad_record_mac";
    case 22:  return "record_overflow — a record larger than the ciphertext limit";
    case 40:  return "handshake_failure — no shared cipher suite, group or version";
    case 42:  return "bad_certificate";
    case 43:  return "unsupported_certificate";
    case 47:  return "illegal_parameter — a field is malformed or not allowed here";
    case 50:  return "decode_error — the hello does not parse";
    case 51:  return "decrypt_error";
    case 70:  return "protocol_version — TLS 1.3 was not offered acceptably";
    case 80:  return "internal_error";
    case 109: return "missing_extension";
    case 110: return "unsupported_extension";
    case 112: return "unrecognized_name — the server has no site for this SNI";
    case 120: return "no_application_protocol — the ALPN list was not acceptable";
    default:  return "unknown alert";
    }
}
/* ---- the resumable handshake ------------------------------------------------ */

/* A TLS 1.3 record is at most the plaintext limit plus the expansion the AEAD is allowed. Sizing
 * the buffer by the protocol rather than by what servers happen to send is the difference between
 * a client that works and one that works until it meets a large certificate chain. */
/* And before the version is settled a record may be longer than that, up to maxCiphertext, and the
 * reference reads all of it before it refuses one over the plaintext limit — see the record header.
 * So the buffer holds that much: 2 KB more per handshake, for the reference's order of events. */
#define MAX_RECORD (LC_REC_HEADER + LC_REC_MAX_PLAINTEXT + 2048u)

/* The reference's pre-TLS-1.3 ceiling, 16384 + 2048 (vendor/utls/common.go:68), used to stand here
 * as MAX_CIPHERTEXT_PRE_TLS13 and was read by nothing at all — `grep -rn` across src/ and test/
 * matched only its own definition. Its comment claimed "the record header check needs it", which was
 * the part worth removing: a constant that names a rule nobody applies reads as coverage.
 *
 * The behaviour it described is real and lives elsewhere — the record path bounds a ciphertext by the
 * buffer it must land in, and test/alert pins both edges (16641 before the version is settled is
 * refused WITH the alert; the same record after it is refused for the 1.3 ceiling). Removed rather
 * than wired up: wiring it would add a second spelling of a bound that is already structural. Found
 * by the sieve's acceptance pass, 2026-09-09. */

/* Our own ClientHello, which is not the protocol maximum: the largest this build produces carries a
 * 1216-byte X25519MLKEM768 share and lands near 1700 bytes. Four kilobytes leaves room for a table
 * that asks for more, and refuses rather than overflows if one ever asks for far more. */
#define MAX_HELLO_OUT 4096u

/* A dummy ChangeCipherSpec on the wire: the five-byte record header and the single byte 0x01. It is
 * a constant because it is written in two places — ahead of the second ClientHello on the retry
 * path, and bundled with the client's Finished on the ordinary one — and because the retry buffer
 * has to be sized for it. */
#define LC_CCS_RECORD 6u

/* THE LARGEST HANDSHAKE MESSAGE THIS CLIENT WILL READ, WHICH IS THE REFERENCE'S TWO NUMBERS.
 *
 * Messages are delimited by their own four-byte header and not by the record layer, so one of them
 * may arrive spread over several records — legal TLS 1.3, and the thing that actually happens when a
 * REALITY server decides we are a stranger and proxies the donor site, whose full RSA chain does not
 * fit one record.
 *
 * This used to be one number, sixteen kilobytes, chosen because it is what a record holds and
 * because the reassembly window was a fixed array twice that size. Go draws the line in two places
 * instead: maxHandshake for any message and maxHandshakeCertificateMsg for a Certificate, "since
 * certificate messages are likely to be the only messages that can be larger than maxHandshake"
 * (vendor/utls/common.go:71-72, vendor/utls/conn.go:1102-1117). And what a peer gets for crossing
 * the line is alert 80, `c.sendAlertLocked(alertInternalError)`, not the decode_error this used to
 * send.
 *
 * Both halves were measurable from outside: a server sending a twenty-kilobyte flight — a chain a
 * few real sites do have — was refused by this client and read by every other, and the alert that
 * came back named a different fault than Go's does. The window now grows on the heap for the
 * message that does not fit the inline one, which is what lets the numbers be the reference's
 * rather than the buffer's. */
#define LC_HS_MAX_MESSAGE     65536u  /* maxHandshake */
#define LC_HS_MAX_CERTIFICATE 262144u /* maxHandshakeCertificateMsg */

typedef enum {
    PH_HELLO = 0,   /* build, stamp, and hand over the ClientHello */
    PH_SERVER_HELLO,
    PH_FLIGHT,
    PH_FLIGHT12,    /* TLS 1.2: see the section of that name */
    PH_FINISHED,    /* our Finished is in the out buffer and has not been taken yet */
    PH_DONE,
    PH_FAILED,
} phase;

/* Which message the TLS 1.2 flight reads next — see phase_flight12. */
#define ST12_CERT     0u /* the Certificate */
#define ST12_STATUS   1u /* a CertificateStatus, or the message after the Certificate */
#define ST12_KX       2u /* the certificate is verified; a ServerKeyExchange, a request or the done */
#define ST12_REQ      3u /* after the ServerKeyExchange: a request or the done */
#define ST12_DONE     4u /* after the request: the done */
#define ST12_TICKET   5u /* our flight is out; the NewSessionTicket the ServerHello promised */
#define ST12_CCS      6u /* the server's ChangeCipherSpec */
#define ST12_FINISHED 7u /* the server's Finished, under its keys */


struct lc_client_hs {
    lc_client_config cfg;
    phase            ph;
    char             err[192];
    char             stage[64];

    client_keys   keys;
    lc_transcript tr;
    int           tr_ready;

    uint8_t      hello[MAX_HELLO_OUT];
    lc_hello_out info;
    /* A HelloRetryRequest has been answered; a second one is a protocol error. */
    int          retried;
    uint16_t     retry_suite; /* the suite it chose, which the ServerHello must not change */

    /* Settled by the ServerHello and used by every step after it. */
    lc_hash     hash;
    lc_aead_alg alg;
    size_t      key_len;
    size_t      hlen;

    uint8_t empty_hash[LC_HASH_MAX];
    uint8_t hs_secret[LC_HASH_MAX];
    uint8_t c_hs[LC_HASH_MAX];
    uint8_t s_hs[LC_HASH_MAX];

    lc_record_key s_keys, c_keys;
    int           hs_keys_ready;

    /* One record being assembled, and the handshake bytes it yields. Two buffers rather than one:
     * the AEAD would decrypt in place, but a subtle overlap bug here corrupts traffic rather than
     * failing, and 16 KB of transient memory is the cheaper side of that trade.
     *
     * `plain` is also the reassembly window, which is why it is twice a record: it holds however
     * much of a handshake message has arrived so far plus the record being appended to it. A message
     * is never handed to the transcript or a parser until all of it is here, because a parser that
     * sees three quarters of a Certificate cannot tell that from a malformed one. */
    uint8_t rx[MAX_RECORD];
    size_t  rx_len;
    size_t  rx_want; /* bytes still needed to complete the record */
    /* The reassembly window: the inline one is twice a record, which holds the residue of an
     * incomplete message plus the whole record being appended to it, and is what every ordinary
     * handshake uses. A message larger than that — up to the reference's own ceilings, see
     * LC_HS_MAX_MESSAGE — grows `plain` onto the heap for the life of the handshake, so that the
     * limit a peer meets is Go's number rather than this buffer's. */
    uint8_t  plain_inline[LC_REC_MAX_PLAINTEXT * 2u];
    uint8_t *plain;
    size_t   plain_cap;
    size_t   plain_len; /* handshake bytes held, waiting for a message to complete */

    /* The largest thing this ever holds is the retry path's pair: the six-byte dummy
     * ChangeCipherSpec record followed by the whole second ClientHello. Sized for exactly that and
     * not for the hello alone — the CCS was added later, and a buffer that fits the common case by
     * six bytes is the kind that holds until the day a hello is at its maximum. */
    uint8_t tx[LC_CCS_RECORD + LC_REC_HEADER + MAX_HELLO_OUT];
    size_t  tx_len;
    size_t  tx_off;
    /* Where one write of `tx` ends and the next begins, 0 when it all goes in one: see
     * lc_client_hs_out and the retry in phase_server_hello. */
    size_t  tx_cut;

    /* THE LEAF CERTIFICATE, kept because CertificateVerify arrives after it and has to be checked
     * against it. Copied rather than pointed at: `body` points into the reassembly window, which is
     * consumed the moment the message is handed over.
     *
     * On the heap and sized to the leaf, because the ceiling this used to be sized to is now the
     * reference's 256 KB and a fixed field of that size would be paid by every handshake for a
     * certificate that is two kilobytes in practice. Allocated when the Certificate arrives and
     * freed with the handshake. */
    uint8_t *cert_der;
    size_t   cert_der_len;
    int      cert_verified;

    /* Where a CompressedCertificate is opened, when one arrives. NULL until then, and sized to the
     * length the message declares — see the arm in phase_flight that allocates it. */
    uint8_t *opened;
    size_t   opened_cap;

    /* Where the encrypted flight has got to, and whether the peer asked for a certificate of ours.
     * See flight_next and the answer built in phase_finish. */
    uint8_t flight;
    int     cert_requested;

    /* Our answer to the server's application settings, when it sent any: see lc_utls_alps_answer.
     * Sent after the server's Finished, before the Certificate a CertificateRequest earns. */
    uint8_t alps_answer[LC_ALPS_ANSWER_LEN];
    size_t  alps_answer_len;

    /* An alert owed to the peer: see hs_alert. */
    int     alert_pending;
    uint8_t alert_desc;
    /* The refusal is a failure of this client's own, owed no alert at all: see hs_own. */
    int own;

    /* The reference's `c.haveVers`: false until the ServerHello names a version we accept, and the
     * gate on checking the version byte of every record after it. See the record header. */
    int     have_vers;
    /* The dummy ChangeCipherSpec, owed from the reference's sendDummyChangeCipherSpec until our
     * Finished or an alert carries it; see where it is set in phase_server_hello. */
    int      ccs_owed;
    /* The alert goes out twice; see hs_alert_type. */
    int      alert_twice;
    /* ...and in two writes rather than one; see hs_alert_type. */
    int      alert_split;
    /* Records ignored in a row — retryCount in the reference; see hs_ignore. */
    unsigned useless;

    /* TLS 1.2, when the server chose it (T3) — see the section of that name below. `c_keys` and
     * `hs_keys_ready` then hold our write key from our ChangeCipherSpec on, which is what an alert is
     * sealed under; `rd12` is the server's, from its ChangeCipherSpec on. */
    int                   tls12;
    const lc_tls12_suite *s12;
    uint8_t               st12;
    int                   ocsp12, ticket12, ems12, cert_req12, cert_checked12, peer_ccs12, ccs_taken12;
    uint8_t              *chain13; /* the server's certificates in the TLS 1.3 message form */
    size_t                chain13_len;
    uint8_t               server_random12[32];
    uint8_t               pms12[LC_KEX_SHARED_MAX];
    size_t                pms12_len;
    uint8_t               ckx12[2u + 1024u]; /* the ClientKeyExchange body: RSA up to 8192 bits */
    size_t                ckx12_len;
    uint8_t               master12[LC_TLS12_MASTER_LEN];
    lc_record_key         rd12;
    int                   rd12_ready;
};

/* The alert codes are in tls/certverify.h, beside the verifier that decides most of them. They were
 * defined here as well, with the same values — two copies of one table, which agree until the day
 * somebody changes the copy the other file does not include. */

/* Records that an alert is owed, so that whoever holds the socket can put it on the wire.
 *
 * Deferred rather than written here because the failures happen inside parsers that have no
 * descriptor, and threading one into them would put a write in the middle of a parse. The run loop
 * flushes it — see hs_flush_alert.
 *
 * The LEVEL is not a parameter: the reference derives it, warning for close_notify and
 * no_renegotiation and fatal for everything else (vendor/utls/conn.go:849-855), and a caller that
 * could choose would eventually choose differently from the reference for one code.
 *
 * ⚠️ THE RULE THIS FILE NOW KEEPS, because for most of its life it kept the opposite by accident:
 * every hs_fail reached after the hello has gone out owes an alert, and twenty-six of them owed one
 * and sent nothing — the socket simply died. That is not a smaller version of the same refusal, it
 * is a different observable event, and the argument for why it matters was already written against
 * ONE branch of phase_server_hello (the ServerHello parse, alert 47) while its neighbours above and
 * below were left silent: a prober that answers our hello with an anomalous flight learns which
 * client it is talking to from whether seven bytes come back.
 *
 * Failures that are this client's own — memory, a hash that will not compute, a buffer of ours the
 * reference does not have — are the exception, and owe nothing: see hs_own. The reference has no
 * counterpart to them; where they happen its process has ended. The internal_error that remains
 * here is the reference's own, each with its citation.
 *
 * THREE PLACES STAY SILENT ON PURPOSE, each documented where it stands, and none of them is an
 * oversight to be tidied up later:
 *
 *   - phase_hello's four refusals. Nothing has been written yet; there is no handshake to abort,
 *     and the reference fails inside makeClientHello before its first byte too.
 *   - a received alert that is well formed. The peer has said why it is going; the reference does
 *     not answer. One that is not two bytes long, or has a level that is neither warning nor
 *     fatal, is answered — see hs_record_kind.
 *   - a first record that is not a handshake record. The reference refuses it with a header error
 *     and no alert precisely because whatever is on the other end may not speak TLS
 *     (vendor/utls/conn.go:666-673). */
static void hs_alert(lc_client_hs *hs, uint8_t desc)
{
    /* The first one wins. A failure that cascades into a second failure is still one refusal, and
     * the reference sends one alert for it — twice over in the one case hs_alert_type names. */
    if (!hs->alert_pending) {
        hs->alert_pending = 1;
        hs->alert_desc = desc;
    }
}

/* A FAILURE OF THIS CLIENT'S OWN IS OWED NOTHING — memory that could not be had, a hash or a key
 * that would not compute, a buffer of ours, a state that cannot be reached. The reference has no
 * counterpart to any of them: Go ends the process where memory runs out and its hashes do not fail,
 * so the server hears no alert, only the connection ending as the kernel ends a dead process's —
 * which is what closing the socket here produces. It takes the alert's place, first come first
 * served, so nothing cascading from it is sent either. Until 2026-09-30 these took internal_error,
 * "what the reference sends when it cannot proceed for its own reasons" — but those reasons are
 * the ones below that carry a citation, and none of these is among them. */
static void hs_own(lc_client_hs *hs)
{
    if (!hs->alert_pending) {
        hs->alert_pending = 1;
        hs->own = 1;
    }
}

/* unexpected_message for a handshake message that is not the one expected — ONCE for a type the
 * reference knows, and TWICE for one it does not; see lc_hs_utls_knows. This client used to send
 * one either way. */
static void hs_alert_type(lc_client_hs *hs, uint8_t type)
{
    if (hs->alert_pending)
        return;
    hs_alert(hs, LC_ALERT_UNEXPECTED_MESSAGE);
    hs->alert_twice = !lc_hs_utls_knows(type);
    /* And in two writes where the reference is not buffering: each sendAlert is its own Write
     * until `c.buffering` goes on, which is after the ServerHello has been read and checked
     * (vendor/utls/handshake_client_tls13.go:136) — so in this phase; Conn.write sends at once
     * unless it is set (vendor/utls/conn.go:951-959). Past it both copies leave in the flush the error path makes (vendor/utls/u_conn.go:
     * 371-375), one write. */
    hs->alert_split = hs->alert_twice && hs->ph == PH_SERVER_HELLO;
}

static void hs_fail(lc_client_hs *hs, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(hs->err, sizeof hs->err, fmt, ap);
    va_end(ap);
    hs->ph = PH_FAILED;
}

static void hs_stage(lc_client_hs *hs, const char *what)
{
    snprintf(hs->stage, sizeof hs->stage, "%s", what);
}

lc_client_hs *lc_client_hs_new(const lc_client_config *cfg)
{
    lc_client_hs *hs = calloc(1, sizeof *hs);
    if (hs == NULL)
        return NULL;
    hs->cfg = *cfg;
    hs->hash = LC_SHA256;
    hs->plain = hs->plain_inline;
    hs->plain_cap = sizeof hs->plain_inline;
    hs->rx_want = LC_REC_HEADER;
    hs_stage(hs, "starting");
    return hs;
}

void lc_client_hs_free(lc_client_hs *hs)
{
    if (hs == NULL)
        return;
    if (hs->hs_keys_ready) {
        lc_record_key_free(&hs->s_keys);
        lc_record_key_free(&hs->c_keys);
    }
    if (hs->tr_ready)
        lc_transcript_free(&hs->tr);
    if (hs->plain != hs->plain_inline) {
        /* Wiped for the same reason the state below is: it has held the plaintext of the
         * certificate flight. */
        lc_wipe(hs->plain, hs->plain_cap);
        free(hs->plain);
    }
    free(hs->cert_der);
    free(hs->opened);
    free(hs->chain13);
    if (hs->rd12_ready)
        lc_record_key_free(&hs->rd12);
    keys_free(&hs->keys);
    /* Wiped whole rather than merely freed: it has held handshake secrets and the plaintext of the
     * server's certificate flight. */
    lc_wipe(hs, sizeof *hs);
    free(hs);
}

const char *lc_client_hs_error(const lc_client_hs *hs)
{
    return hs->err;
}

const uint8_t *lc_client_hs_hello(const lc_client_hs *hs, size_t *len)
{
    *len = hs->info.len;
    return hs->hello;
}

const uint8_t *lc_client_hs_stamp_key(const lc_client_hs *hs)
{
    /* The same choice the stamp made, restated rather than stored: keeping a second copy of a
     * private key so that a diagnostic can read it is how one ends up in a core dump. */
    return hs->keys.have_x25519 ? hs->keys.x25519_priv : hs->keys.hybrid.x25519_priv;
}

size_t lc_client_hs_want(const lc_client_hs *hs)
{
    return hs->tx_len > hs->tx_off ? 0u : hs->rx_want;
}

size_t lc_client_hs_feed(lc_client_hs *hs, const uint8_t *data, size_t len)
{
    size_t take = len < hs->rx_want ? len : hs->rx_want;
    if (take == 0u)
        return 0u;
    memcpy(hs->rx + hs->rx_len, data, take);
    hs->rx_len += take;
    hs->rx_want -= take;

    /* The header names the body length, so the moment it is complete the machine knows exactly how
     * much more to ask for — and can refuse a record that could not fit before reading it. */
    if (hs->rx_want == 0u && hs->rx_len == LC_REC_HEADER) {
        /* THE HEADER IS JUDGED BEFORE THE BODY IS READ, AND IN THE REFERENCE'S ORDER: the SSLv2
         * byte, then the version, then — on a first record only — the "be extra suspicious" rule,
         * and only then the length (vendor/utls/conn.go:644-678). The last two used to be the other
         * way round, the type and version checked in phase_server_hello once the body had arrived
         * and the length checked here, so a first record like `17 03 03 50 00` got record_overflow
         * back where every Go client closes without a word.
         *
         * ⚠️ 0x80 FIRST, the one byte on which the reference speaks before it has any reason to:
         *
         *     // No valid TLS record has a type of 0x80, however SSLv2 handshakes
         *     // start with a uint16 length where the MSB is set ...
         *     if !handshakeComplete && typ == 0x80 {
         *         c.sendAlert(alertProtocolVersion)
         *         return c.in.setErrorLocked(c.newRecordHeaderError(nil, "unsupported SSLv2 handshake received"))
         *     }                                                    (vendor/utls/conn.go:644-651)
         *
         * A plaintext protocol_version alert, on any record of the handshake — `!handshakeComplete`,
         * not only the first. We were silent on it until the reverse sieve named it "below threshold —
         * both reject": both did reject, and not the same way, which is what this client is judged
         * by. One byte to trigger, one record to observe, no key needed by either side. */
        if (hs->rx[0] == 0x80u) {
            hs_alert(hs, LC_ALERT_PROTOCOL_VERSION);
            hs_fail(hs, "unsupported SSLv2 handshake received");
            return take;
        }
        /* THE VERSION IN THE HEADER, WHICH THIS CLIENT DID NOT LOOK AT ONCE.
         *
         * RFC 8446 5.1 says legacy_record_version "MUST be ignored for all purposes", and the
         * reference ignores that instruction — it checks, and refuses:
         *
         *     if c.haveVers && vers != expectedVers {
         *         c.sendAlert(alertProtocolVersion)
         *         ...received record with version %x when expecting version %x
         *     }                                            (vendor/utls/conn.go:661-664)
         *
         * with expectedVers folded to 0x0303 for TLS 1.3 — "All TLS 1.3 records are expected to
         * have 0x0303 (1.2) after the initial hello" (:654-659).
         *
         * ⚠️ THE RFC AND THE REFERENCE DISAGREE HERE, AND THE REFERENCE WINS, because what this
         * client owes is not conformance but sameness: a prober that answers with one record
         * carrying 0x0304 gets alert 70 from every Go client on the web and, until this, a silent
         * acceptance from this one. Following the RFC would have been the defensible choice for a
         * general TLS stack and the wrong one here. The risk of being stricter than the RFC is
         * bounded by the same observation from the other side: Go enforces this against the whole
         * internet, so no peer worth reaching sends anything else.
         *
         * `have_vers` is latched where the reference latches it — when the ServerHello's version is
         * accepted (vendor/utls/handshake_client.go:558) — so the FIRST record is not checked, which is the
         * reference's behaviour and not an omission. */
        if (hs->have_vers && (hs->rx[1] != 0x03u || hs->rx[2] != 0x03u)) {
            hs_alert(hs, LC_ALERT_PROTOCOL_VERSION); /* vendor/utls/conn.go:662 */
            hs_fail(hs, "record carries version 0x%02x%02x when 0x0303 was expected",
                    hs->rx[1], hs->rx[2]);
            return take;
        }
        /* A FIRST RECORD THAT DOES NOT LOOK LIKE TLS is refused in SILENCE:
         *
         *     if !c.haveVers {
         *         // First message, be extra suspicious: this might not be a TLS client.
         *         if (typ != recordTypeAlert && typ != recordTypeHandshake) || vers >= 0x1000 {
         *             return c.in.setErrorLocked(c.newRecordHeaderError(c.conn, ...))
         *         }
         *     }                                                (vendor/utls/conn.go:666-673)
         *
         * — newRecordHeaderError, not sendAlert. Whatever is on the other end may not be speaking TLS
         * at all, and answering it with a TLS alert tells it more than it told us. Both halves of the
         * condition matter: the version half was missing until the sieve of 2026-08-29 found it, the
         * one true divergence in 505 pairs — `16 FF FF 00 05 ...` closed a stock client with a bare
         * FIN and was parsed here as a ServerHello. "First" means until the version is settled,
         * which is when have_vers is latched, so after a HelloRetryRequest the rule no longer
         * applies and a ChangeCipherSpec may arrive. */
        if (!hs->have_vers &&
            ((hs->rx[0] != LC_REC_ALERT && hs->rx[0] != LC_REC_HANDSHAKE) ||
             ((unsigned)hs->rx[1] << 8 | hs->rx[2]) >= 0x1000u)) {
            hs_fail(hs, "first record (type 0x%02x, version 0x%02x%02x) does not look like TLS",
                    hs->rx[0], hs->rx[1], hs->rx[2]);
            return take;
        }
        size_t body = (size_t)hs->rx[3] << 8 | hs->rx[4];
        /* THE REFERENCE'S TWO CEILINGS, AND WHEN EACH IS READ.
         *
         *     if c.vers == VersionTLS13 && n > maxCiphertextTLS13 || n > maxCiphertext {
         *         c.sendAlert(alertRecordOverflow)
         *     }                                        (vendor/utls/conn.go:675-679)
         *
         * on the header — `(vers == TLS13 && n > 16640) || n > 18432`, maxCiphertextTLS13 and
         * maxCiphertext being 16384+256 and 16384+2048 (vendor/utls/common.go:67-69) — and then, on
         * the WHOLE record once it has been read and opened,
         *
         *     if len(data) > maxPlaintext {
         *         return c.in.setErrorLocked(c.sendAlert(alertRecordOverflow))
         *     }                                        (vendor/utls/conn.go:693-695)
         *
         * which hs_record_kind asks of every record that is not opened: before keys the body IS the
         * data, and so is a ChangeCipherSpec in TLS 1.3, passed through unopened
         * (vendor/utls/conn.go:346-351). An opened one is bounded by lc_record_unprotect.
         *
         * ⚠️ UNTIL 2026-09-27 the header refused anything over 16384 before a version was settled,
         * at once. The reference refuses 16385..18432 there only once it has READ the body: a peer
         * that declares 17000 bytes and sends five gets record_overflow from us at the header and
         * silence from uTLS, which is still waiting for the rest. The buffer holds maxCiphertext
         * now, which is what makes waiting possible. */
        size_t max_body = hs->have_vers && !hs->tls12 ? LC_REC_MAX_PLAINTEXT + 256u
                                                   : LC_REC_MAX_PLAINTEXT + 2048u;
        if (body > max_body) {
            hs_alert(hs, LC_ALERT_RECORD_OVERFLOW); /* vendor/utls/conn.go:676 */
            hs_fail(hs, "record of %zu bytes does not fit", body);
            return take;
        }
        hs->rx_want = body;
    }
    return take;
}

/* True when a whole record is in hand. */
static int record_ready(const lc_client_hs *hs)
{
    return hs->rx_len >= LC_REC_HEADER && hs->rx_want == 0u;
}

static void record_drop(lc_client_hs *hs)
{
    hs->rx_len = 0;
    hs->rx_want = LC_REC_HEADER;
}

/* ---- handshake message reassembly -------------------------------------------
 *
 * A record boundary and a message boundary have nothing to do with each other: one record may carry
 * several messages, and one message may be spread over several records. Reading messages straight
 * out of a single record works against most servers and fails against some — the worst possible
 * distribution of outcomes, because it looks correct everywhere it is tested.
 *
 * Only complete messages leave this window, and they leave it as the exact bytes the server sent,
 * header included. That last part is not a detail: the transcript hashes messages as sent, and a
 * transcript fed the payload of a record instead would produce a Finished that fails to verify —
 * which on this client reads as "REALITY not authenticated", pointing the blame at the stamp rather
 * than at the framing. */

/* The ceiling for the message at the front of the window, which is the reference's two numbers: a
 * Certificate may be four times what anything else may be (vendor/utls/conn.go:1102-1117) — but
 * only once the version is settled:
 *
 *     // hasVers indicates we're past the first message, forcing someone trying to
 *     // make us just allocate a large buffer to at least do the initial part of
 *     // the handshake first.
 *     if c.haveVers && data[0] == typeCertificate {
 *         maxHandshakeSize = maxHandshakeCertificateMsg
 *     }
 *
 * This read the type alone, so a first message typed as a Certificate and declaring 200 KB was
 * waited for here where every Go client refuses it at 64 KiB with internal_error. */
static size_t hs_msg_ceiling(const lc_client_hs *hs, uint8_t type)
{
    return hs->have_vers && type == LC_HS_CERTIFICATE ? LC_HS_MAX_CERTIFICATE : LC_HS_MAX_MESSAGE;
}

/* Makes room for |n| more bytes in the window, growing it onto the heap if the inline one cannot
 * hold what is already there plus that much. The window never has to hold more than one message
 * and one record, so the ceiling it grows to is the largest message plus a record.
 *
 * Reserving is separate from appending because the record layer decrypts STRAIGHT INTO the window —
 * two buffers rather than three, see the arm that calls lc_record_unprotect — and that path needs
 * the room before it has the bytes. */
static int hs_msg_reserve(lc_client_hs *hs, size_t n)
{
    if (n <= hs->plain_cap - hs->plain_len)
        return 0;

    size_t   want = hs->plain_len + n;
    size_t   cap = LC_HS_MAX_CERTIFICATE + 4u + LC_REC_MAX_PLAINTEXT;
    uint8_t *grown;

    if (want > cap)
        return -1;

    grown = malloc(cap);
    if (grown == NULL)
        return -1;

    memcpy(grown, hs->plain, hs->plain_len);
    if (hs->plain != hs->plain_inline) {
        lc_wipe(hs->plain, hs->plain_cap);
        free(hs->plain);
    }
    hs->plain = grown;
    hs->plain_cap = cap;
    return 0;
}

/* Appends a run of handshake bytes to the window. */
static int hs_msg_add(lc_client_hs *hs, const uint8_t *p, size_t n)
{
    if (hs_msg_reserve(hs, n) != 0)
        return -1;

    memcpy(hs->plain + hs->plain_len, p, n);
    hs->plain_len += n;
    return 0;
}

/* Yields the message at the front of the window. Returns 1 with the message set, 0 when more records
 * are needed to complete it, and -1 when the peer declares one larger than the reference reads.
 *
 * The residue left behind is always shorter than one message, which is what keeps the window from
 * overflowing: a full record can always be appended to it. */
static int hs_msg_take(lc_client_hs *hs, uint8_t *type, const uint8_t **body, size_t *body_len,
                       const uint8_t **whole, size_t *whole_len)
{
    if (hs->plain_len < 4u)
        return 0;

    const uint8_t *m = hs->plain;
    size_t         n = (size_t)m[1] << 16 | (size_t)m[2] << 8 | m[3];
    if (n > hs_msg_ceiling(hs, m[0]))
        return -1;
    if (hs->plain_len < n + 4u)
        return 0;

    *type = m[0];
    *body = m + 4;
    *body_len = n;
    *whole = m;
    *whole_len = n + 4u;
    return 1;
}

/* A whole handshake message already in the window, or the header of one larger than the reference
 * reads: either way the next phase has something to act on without another record, as readHandshake
 * has when c.hand already holds it (vendor/utls/conn.go:1082-1090, :1100-1117). What a ServerHello
 * or a retry carried behind it in its record is the case — see phase_server_hello. */
static int msg_waiting(const lc_client_hs *hs)
{
    if (hs->plain_len < 4u)
        return 0;
    const uint8_t *m = hs->plain;
    size_t         n = (size_t)m[1] << 16 | (size_t)m[2] << 8 | m[3];
    return n > hs_msg_ceiling(hs, m[0]) || hs->plain_len >= n + 4u;
}

/* Discards the message just taken, keeping whatever followed it. Invalidates the pointers that
 * hs_msg_take handed out, so the caller hashes and parses before calling this. */
static void hs_msg_drop(lc_client_hs *hs, size_t whole_len)
{
    hs->plain_len -= whole_len;
    memmove(hs->plain, hs->plain + whole_len, hs->plain_len);
}

const uint8_t *lc_client_hs_out(const lc_client_hs *hs, size_t *len)
{
    /* Up to the cut first, then the rest: two calls, as the reference makes two Writes where it is
     * not buffering. */
    size_t end = hs->tx_cut > hs->tx_off ? hs->tx_cut : hs->tx_len;
    *len = end - hs->tx_off;
    return hs->tx + hs->tx_off;
}

void lc_client_hs_out_taken(lc_client_hs *hs, size_t n)
{
    hs->tx_off += n;
    if (hs->tx_off >= hs->tx_len)
        hs->tx_off = hs->tx_len = hs->tx_cut = 0;
}


/* How many bytes a key share for this group takes, for the caller that has to splice one in. Zero
 * for a group this build cannot key, which is how the retry path refuses without a second list. */
static size_t key_share_len_for(uint16_t group)
{
    switch (group) {
    case LC_GROUP_X25519MLKEM768: return LC_HYBRID_SHARE;
    case LC_GROUP_X25519:         return LC_X25519_KEY;
    case LC_GROUP_SECP256R1:      return LC_P256_POINT;
    case LC_GROUP_SECP384R1:      return LC_P384_POINT;
    case LC_GROUP_SECP521R1:      return LC_P521_POINT;
    default:                      return 0;
    }
}

/* ---- phase one: the ClientHello --------------------------------------------- */

static void phase_hello(lc_client_hs *hs, lc_client *cl)
{
    hs_stage(hs, "building ClientHello");

    /* NONE OF THIS PHASE'S REFUSALS SENDS AN ALERT, and that is not the omission it looks like next
     * to the rest of the file — see hs_alert for the rule and the other two exceptions. Not one
     * byte has gone out yet: there is no handshake to abort, and an alert would be this client
     * introducing itself to a peer it has not spoken to. The reference is in the same position and
     * does the same, failing inside makeClientHello with an error and no write. */
    lc_hello_err herr = lc_hello_build(hs->cfg.table, hs->cfg.table_len, hs->cfg.sni,
                                       hs->hello, sizeof hs->hello, &hs->info);
    if (herr != LC_HELLO_OK) {
        /* Which of the four, because this line is the whole of what a person gets. It used to say
         * "the fingerprint table does not build a hello" for all of them, and for an empty server
         * name that sentence sends the reader to a file that is perfectly fine. */
        hs_fail(hs, "%s", lc_hello_why(herr));
        return;
    }
    if (fill_key_shares(hs->hello, &hs->info, &hs->keys, hs->err, sizeof hs->err) != 0) {
        hs->ph = PH_FAILED;
        return;
    }

    if (hs->cfg.use_reality) {
        hs_stage(hs, "stamping REALITY");
        if (!hs->keys.have_hybrid && !hs->keys.have_x25519) {
            hs_fail(hs, "REALITY needs an x25519 key share and the fingerprint offers none");
            return;
        }
        /* REALITY structurally requires a 32-byte session_id: the stamp writes exactly that many
         * bytes at sid_off. A fingerprint declaring any other width would leave the stamp
         * overwriting the ClientHello bytes that follow — still in-bounds, but a malformed hello the
         * server cannot authenticate, and the only symptom is a silent fall-back to the donor site.
         * Refuse such a table here rather than send a hello that cannot work. */
        if (hs->info.sid_len != LC_REALITY_SESSION_ID) {
            hs_fail(hs, "REALITY needs a 32-byte session_id and the fingerprint declares another");
            return;
        }
        /* The stamp reuses an ephemeral X25519 key already in key_share, and WHICH one matters.
         *
         * The server walks the key shares looking for the standalone X25519 group first, and only
         * falls back to the classical half inside the hybrid when there is no standalone entry.
         * Xray's client picks in the same order. Signing with the hybrid's half while the server
         * verifies against the standalone one produces a handshake that completes perfectly and
         * authenticates nothing — the server treats the client as a stranger and serves the real
         * site. Which is exactly what the first live run against the node did. */
        const uint8_t *x_priv = hs->keys.have_x25519 ? hs->keys.x25519_priv
                                                     : hs->keys.hybrid.x25519_priv;
        if (lc_reality_stamp(hs->hello, hs->info.len, hs->info.sid_off, hs->cfg.reality,
                             x_priv, hs->cfg.unix_time, cl->reality_auth_key) != 0) {
            hs_fail(hs, "stamping failed");
            return;
        }
    }

    /* The transcript cannot start here, however natural that would look: its hash is decided by the
     * cipher suite, and the cipher suite is not known until the ServerHello arrives. Starting it on
     * SHA-256 and switching later silently produced a transcript over the wrong hash, and the only
     * symptom was that every server record failed to authenticate — several layers away from the
     * cause. The hello is kept and hashed once the suite is known. */

    /* Out as a plaintext handshake record. Its legacy version is 0x0301 — what a browser sends, and
     * what the fingerprint therefore requires. */
    hs_stage(hs, "sending ClientHello");
    hs->tx[0] = LC_REC_HANDSHAKE;
    hs->tx[1] = 0x03;
    hs->tx[2] = 0x01;
    hs->tx[3] = (uint8_t)(hs->info.len >> 8);
    hs->tx[4] = (uint8_t)hs->info.len;
    memcpy(hs->tx + LC_REC_HEADER, hs->hello, hs->info.len);
    hs->tx_len = LC_REC_HEADER + hs->info.len;
    hs->tx_off = 0;
    hs->ph = PH_SERVER_HELLO;
}

/* Named the moment the hello has gone out rather than when the reply starts arriving: a peer that
 * closes without answering is the commonest failure here, and reporting it as "sending ClientHello"
 * sends whoever reads the message looking at the wrong end of the exchange. */
/* ---- records that are not handshake bytes ------------------------------------
 *
 * What the reference's readRecordOrCCS does with a record once it is open — or, before any key
 * exists, as it came (vendor/utls/conn.go:697-790). Both phases call it with the content type and
 * the body as the reference would see them after its decrypt, and it answers:
 *
 *    0  handshake bytes, which the caller appends;
 *    1  a record the reference ignores — the machine waits for the next one;
 *   -1  the handshake is over, with an alert raised exactly where the reference raises one.
 *
 * ⚠️ ONE PLACE FOR ALL OF IT, because two phases each had a piece and neither had it all. Before a
 * key existed, any alert record ended the handshake in silence and a ChangeCipherSpec was refused
 * as "not a handshake record" — which broke the one legal sequence a Go server produces after a
 * HelloRetryRequest, where the dummy ChangeCipherSpec follows the retry
 * (vendor/utls/handshake_server_tls13.go, doHelloRetryRequest). Once keys existed, every alert
 * the server sent was answered with unexpected_message, where the reference answers none. */
#define LC_MAX_USELESS_RECORDS 32u /* maxUselessRecords, vendor/utls/common.go:73 */

static int hs_ignore(lc_client_hs *hs)
{
    /* retryReadRecord: "drop a non-advancing record, like a warning alert, empty application_data,
     * or a change_cipher_spec in TLS 1.3" — and give up with unexpected_message after thirty-two in
     * a row (vendor/utls/conn.go:797-804). Without the count a peer could hold the machine forever
     * on records that each cost it five bytes. */
    if (++hs->useless > LC_MAX_USELESS_RECORDS) {
        hs_alert(hs, LC_ALERT_UNEXPECTED_MESSAGE);
        hs_fail(hs, "too many ignored records");
        return -1;
    }
    return 1;
}

static int hs_record_kind(lc_client_hs *hs, uint8_t type, const uint8_t *data, size_t n)
{
    /* `len(data) > maxPlaintext` (vendor/utls/conn.go:693-695), before anything else is asked of
     * the record: here for the ones that were not opened — any record before keys, and a
     * ChangeCipherSpec after them — since lc_record_unprotect refuses an opened one first. */
    if (n > LC_REC_MAX_PLAINTEXT) {
        hs_alert(hs, LC_ALERT_RECORD_OVERFLOW);
        hs_fail(hs, "a record of %zu bytes, over the plaintext limit", n);
        return -1;
    }
    /* "Application Data messages are always protected" (:699-701) — reachable only once the
     * version is settled, since before it the header's first-record rule has already refused the
     * type in silence. */
    if (type == LC_REC_APPLICATION_DATA && !hs->hs_keys_ready) {
        hs_alert(hs, LC_ALERT_UNEXPECTED_MESSAGE);
        hs_fail(hs, "application data before any key exists");
        return -1;
    }
    /* "This is a state-advancing message: reset the retry count" (:703-706). */
    if (type != LC_REC_ALERT && type != LC_REC_CHANGE_CIPHER_SPEC && n > 0u)
        hs->useless = 0;
    /* "Handshake messages MUST NOT be interleaved with other record types in TLS 1.3" (:708-711):
     * `c.vers == VersionTLS13` is have_vers here, this client settling on nothing else. */
    if (hs->have_vers && !hs->tls12 && type != LC_REC_HANDSHAKE && hs->plain_len > 0u) {
        hs_alert(hs, LC_ALERT_UNEXPECTED_MESSAGE);
        hs_fail(hs, "a record of type 0x%02x in the middle of a handshake message", type);
        return -1;
    }

    switch (type) {
    case LC_REC_ALERT:
        /* An alert is not answered with an alert — except when it is not one: a body that is not
         * two bytes is unexpected_message (:721-723). close_notify is an orderly end of stream
         * (:724-726); in TLS 1.3 any other alert ends the connection as the peer's error, with
         * nothing written back (:727-729). Before the version is settled the level still counts,
         * TLS 1.2 style: a warning is dropped and reading goes on, a fatal one ends it, and any
         * other level is unexpected_message (:730-738). */
        if (n != 2u) {
            hs_alert(hs, LC_ALERT_UNEXPECTED_MESSAGE);
            hs_fail(hs, "an alert record of %zu bytes", n);
            return -1;
        }
        if (data[1] == LC_ALERT_CLOSE_NOTIFY) {
            hs_fail(hs, "the server closed the connection (close_notify) during the handshake");
            return -1;
        }
        if ((hs->have_vers && !hs->tls12) || data[0] == 2u) {
            hs_fail(hs, "server sent alert %u: %s", (unsigned)data[1], alert_text(data[1]));
            return -1;
        }
        if (data[0] == 1u)
            return hs_ignore(hs);
        hs_alert(hs, LC_ALERT_UNEXPECTED_MESSAGE);
        hs_fail(hs, "an alert of level %u, which is neither warning nor fatal", (unsigned)data[0]);
        return -1;

    case LC_REC_CHANGE_CIPHER_SPEC:
        /* A middlebox-pleasing ChangeCipherSpec may appear at any point and carries nothing: TLS
         * 1.3 keeps it only so the exchange looks like a resumed 1.2 one. IGNORED IS NOT THE SAME
         * AS UNCHECKED: the body must be the single 0x01 (:741-743, decode_error), no handshake
         * message may be split across it (:745-747), and only then is it dropped (:753-755). Send
         * `14 03 03 00 00` at a stock client and it answers 50; this client used to swallow it.
         * Before the version is settled the reference would refuse it as unexpected (:756-758),
         * but the first-record rule has already refused it in silence by then. */
        if (n != 1u || data[0] != 0x01u) {
            hs_alert(hs, LC_ALERT_DECODE_ERROR);
            hs_fail(hs, "ChangeCipherSpec carrying %zu bytes instead of the single 0x01", n);
            return -1;
        }
        if (hs->plain_len > 0u) {
            hs_alert(hs, LC_ALERT_UNEXPECTED_MESSAGE);
            hs_fail(hs, "ChangeCipherSpec in the middle of a handshake message");
            return -1;
        }
        /* TLS 1.2: taken only where readRecordOrCCS is told to expect it, and unexpected anywhere
         * else (vendor/utls/conn.go:764-769). */
        if (hs->tls12) {
            if (hs->st12 != ST12_CCS) {
                hs_alert(hs, LC_ALERT_UNEXPECTED_MESSAGE);
                hs_fail(hs, "ChangeCipherSpec where the TLS 1.2 flight does not expect one");
                return -1;
            }
            hs->ccs_taken12 = 1;
            return 1;
        }
        if (!hs->have_vers) {
            hs_alert(hs, LC_ALERT_UNEXPECTED_MESSAGE);
            hs_fail(hs, "ChangeCipherSpec before the version is settled");
            return -1;
        }
        return hs_ignore(hs);

    case LC_REC_HANDSHAKE:
        /* An empty handshake record is not a message waiting for more: `if len(data) == 0 {
         * sendAlert(alertUnexpectedMessage) }` (:777-780). This client used to append nothing and
         * wait. */
        if (n == 0u) {
            hs_alert(hs, LC_ALERT_UNEXPECTED_MESSAGE);
            hs_fail(hs, "an empty handshake record");
            return -1;
        }
        if (hs->tls12 && hs->st12 == ST12_CCS) {
            hs_alert(hs, LC_ALERT_UNEXPECTED_MESSAGE); /* :777-780, expectChangeCipherSpec */
            hs_fail(hs, "a handshake record where the ChangeCipherSpec was due");
            return -1;
        }
        return 0;

    default:
        /* Application data during the handshake (:763-766), or a type TLS does not have (:714-715):
         * unexpected_message either way. */
        hs_alert(hs, LC_ALERT_UNEXPECTED_MESSAGE);
        hs_fail(hs, "unexpected content type 0x%02x during the handshake", type);
        return -1;
    }
}

static void tls12_begin(lc_client_hs *hs, const lc_server_hello *sh, const lc_sh_expect *ex,
                        const uint8_t *whole, size_t whole_len);

static void phase_server_hello_wait(lc_client_hs *hs)
{
    hs_stage(hs, "reading ServerHello");
}

/* ---- phase two: the ServerHello and the handshake keys ---------------------- */

static void phase_server_hello(lc_client_hs *hs, lc_client *cl, int fresh)
{
    uint8_t         type = 0;
    const uint8_t  *body = NULL, *whole = NULL;
    size_t          body_len = 0, whole_len = 0;
    lc_server_hello sh;

    /* Without a fresh record when the window already holds a whole message — what a retry left
     * behind it; see msg_waiting. */
    if (fresh) {
        const uint8_t *rec = hs->rx;
        size_t         rec_len = hs->rx_len;

    /* The header has been judged already — the SSLv2 byte, the version, the first-record rule and
     * the length, in lc_client_hs_feed and in the reference's order — so what is left is what the
     * record carries: an alert, a ChangeCipherSpec after a retry, or handshake bytes. */
        int kind = hs_record_kind(hs, rec[0], rec + LC_REC_HEADER, rec_len - LC_REC_HEADER);
        if (kind != 0)
            return;

        if (hs_msg_add(hs, rec + LC_REC_HEADER, rec_len - LC_REC_HEADER) != 0) {
        /* A limit of this client's own — the reference grows a buffer instead — so the alert is the
         * one it gives its own internal failures rather than one that blames the peer. */
        hs_own(hs);
        hs_fail(hs, "the server's first flight does not fit the reassembly window");
            return;
        }
    }
    int mrc = hs_msg_take(hs, &type, &body, &body_len, &whole, &whole_len);
    if (mrc == 0)
        return; /* split across records: stay in this phase and take the next one */
    if (mrc < 0) {
        /* Larger than the reference reads: `if n > maxHandshakeSize { c.sendAlert(alertInternalError)
         * }` (vendor/utls/conn.go:1114-1117), 80 and not the 10 this shared with the branch below.
         * The ceiling at this point is 64 KiB for every type, a Certificate included — the larger
         * one is for after the version is settled; see hs_msg_ceiling. */
        hs_alert(hs, LC_ALERT_INTERNAL_ERROR);
        hs_fail(hs, "a handshake message larger than the reference reads, before any key exists");
        return;
    }
    if (type != LC_HS_SERVER_HELLO) {
        /* BOTH HALVES OF THIS CONDITION ARE unexpected_message IN THE REFERENCE, by two different
         * routes that happen to meet here. A message whose framing does not parse dies in
         * unmarshalHandshakeMessage, which readHandshake calls — `if !m.unmarshal(data) { return
         * nil, c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage)) }`
         * (vendor/utls/conn.go:1192-1194), as does one whose type it does not know (:1176-1184) —
         * and a well-formed message that is simply not the expected one dies one layer up:
         *
         *     serverHello, ok := msg.(*serverHelloMsg)
         *     if !ok {
         *         c.sendAlert(alertUnexpectedMessage)
         *         return unexpectedMessageError(serverHello, msg)
         *     }                                    (vendor/utls/handshake_client.go:313-317)
         *
         * This client collapses the two into one sentence, which is fine for the log and was not
         * fine for the wire: the same anomalous first flight that gets alert 10 from a Go client
         * got a bare FIN from this one. */
        hs_alert_type(hs, type); /* vendor/utls/handshake_client.go:315,
           vendor/utls/conn.go:1186 */
        hs_fail(hs, "the first message is not a ServerHello");
        return;
    }
    /* THE SHAPE, THEN THE VERDICT, in that order and never interleaved — see lc_parse_server_hello
     * for what it cost when this parser refused as it read. The verdict is the reference's sequence
     * of checks from pickTLSVersion to processServerHello, and it compares the message against the
     * hello as it went out: read back out of hs->hello rather than kept beside it, because the hello
     * IS the record of what was offered and a second copy is a second thing to keep true.
     *
     * Which hello this answers is the one fact the verdict needs from here: after a retry the
     * version checks move (pickTLSVersion no longer runs, vendor/utls/handshake_client_tls13.go:506)
     * and the suite must be the one the retry chose. */
    lc_sh_expect ex;
    if (lc_sh_expect_from_hello(hs->hello, hs->info.len, &ex) != 0) {
        hs_own(hs);
        hs_fail(hs, "our own hello does not parse, which is this client being wrong about itself");
        return;
    }
    ex.retried = hs->retried;
    ex.retry_suite = hs->retry_suite;
    if (lc_parse_server_hello(body, body_len, &sh) != 0 || lc_check_server_hello(&sh, &ex) != 0) {
        /* A hello refused after pickTLSVersion has set `c.vers`, and its alert goes out with the
         * version that implies — see lc_client_hs_alert_record. sh.vers_settled is zero for one
         * that did not parse: lc_parse_server_hello clears the struct first. */
        if (sh.vers_settled)
            hs->have_vers = 1;
        hs_alert(hs, sh.alert);
        hs_fail(hs, "%s", sh.why);
        return;
    }

    /* The version is settled: lc_check_server_hello refuses anything but TLS 1.3, so a hello that
     * passed is the reference's pickTLSVersion having succeeded, and this is where it latches
     * `c.haveVers = true` (vendor/utls/handshake_client.go:558) — before the HelloRetryRequest
     * branch below, because in the reference pickTLSVersion runs before hs.handshake() and it is
     * inside hs.handshake() that a retry is recognised. From here on every record's version byte is
     * checked; see the record header, which is the only reader of this flag. */
    hs->have_vers = 1;

    if (sh.tls12) {
        tls12_begin(hs, &sh, &ex, whole, whole_len);
        return;
    }

    if (sh.is_hello_retry) {
        /* Legal TLS, but a REALITY server never sends one, and handling it would mean rebuilding the
         * hello with a different group — worth doing later, not silently mishandling now.
         *
         * ⚠️ "NEVER SENDS ONE" IS NOW A DERIVATION RATHER THAN A HOPE, and the derivation names the
         * single thing that would break it. The reference server picks its group like this
         * (vendor/utls/handshake_server_tls13.go:209-246): take the server's curve preferences,
         * keep only what the client listed in supported_groups, stable-sort so that groups the
         * client sent a KEY SHARE for come first, then stable-sort AGAIN so that post-quantum groups
         * come first — and that second sort is the one that wins. Whatever ends up at the head is
         * `selectedGroup`, and if the client sent no key share for it, out goes the retry (:241-246).
         *
         * So a retry needs a group we ADVERTISE but do not SHARE, and which the server prefers.
         * Read out of a hello this client actually builds (lc-hello against the packaged table),
         * supported_groups is 0x11ec, 0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101, and key_share
         * carries 0x11ec (1216 bytes), 0x001d (32) and 0x0017 (65) — the list length 0x052d is those
         * three and nothing else. The only post-quantum name among the seven is 0x11ec, and we share
         * it; if a server does not know 0x11ec then no post-quantum group survives the filter at all
         * and the first sort decides, which puts 0x001d or 0x0017 in front — both shared. There is no
         * arrangement of server preferences that reaches the retry from this hello.
         *
         * ⚠️ AND THE CONDITION THAT WOULD END THAT, written down because it looks like an
         * optimisation: advertise a second post-quantum group without sending its key share. The
         * hybrid share is 1216 bytes of a 1878-byte hello, so "drop the big one, keep the name" is
         * exactly the change someone makes to shrink a hello on a slow link — and it turns this
         * branch from unreachable into a hang on the first server that prefers the group. A
         * fingerprint table is data, so no compiler will say a word.
         *
         * For the PACKAGED table that is already gated and needs nothing further: test/fphello
         * compares its output against a frozen uTLS vector and skips only the client random, the
         * session id, the key share PUBLIC KEYS and the GREASE values — "every extension, its order,
         * every list and every length" is compared, so a key_share that lost an entry fails there.
         * What is not gated is a table supplied by hand, because no vector exists for one. Written
         * down rather than guarded, so that the next reader does not build a second check for the
         * half that already has one.
         *
         * NO ALERT, and unlike the three silences named at hs_alert this one is not the reference's
         * behaviour either — there is none to copy, because the reference ANSWERS a retry and goes
         * on. Any alert here would be a fiction: no Go client sends one for a message that is
         * perfectly legal. The difference a peer sees is that we stop, and no alert code makes that
         * smaller. The fix is to implement the retry, which is the debt this comment records.
         *
         * ⚠️ AND THE RETRY ALONE WOULD NOT CLOSE IT, which is worth knowing before somebody starts:
         * ClientHello2 must carry a key share for THE GROUP THE SERVER NAMED, and this build can
         * generate a key for three groups — x25519, secp256r1, x25519mlkem768 (fp/fpt.c,
         * lc_fpt_caps). The shipped fingerprint ADVERTISES five; 0x0018 and 0x0019 are named and
         * have no key exchange behind them anywhere in the tree. So a probe that wants to see this
         * branch simply retries with secp384r1 and arrives back at the same silent close, having
         * cost us the whole retry machinery — a second hello, the message_hash transcript rewrite
         * of RFC 8446 4.4.1, the cookie echo — for nothing.
         *
         * Closing it therefore means P-384 and P-521 key exchange first, and only then the retry.
         * That is a different piece of work with a different cost, and stating the order here is
         * the point: the retry is the visible half and the curves are the half that decides whether
         * it helps. Written after the sieve of 2026-08-29 asked why CurveP384 had no constant.
         *
         * ⚠️ BOTH ARE DONE NOW — the curves in tls/kex.c with test/kex, the retry by the splice
         * below — and the reasoning that follows is kept because it is what decided the SHAPE of
         * the answer, not because anything here is still open. It was written after building the
         * mechanism the obvious way and then removing it again.
         *
         * What a second hello must be: RFC 8446 4.1.2 says ClientHello2 is ClientHello1 with the
         * key_share reduced to the server's one group, the cookie echoed if one came, and — this is
         * the part that decides everything — `legacy_session_id` IDENTICAL. The reference gets that
         * for free because Go mutates ONE hello object and re-marshals it: the random, the session
         * id, the cipher order and every GREASE draw are the first hello's, unchanged. Our builder
         * draws all of them fresh on every call, so a hello2 built the obvious way differs from the
         * reference's in the random, in three GREASE values and in the session id — and the session
         * id is where REALITY's stamp lives, so re-drawing it also destroys the authentication that
         * the reference carries over intact.
         *
         * Which means the honest trade is not "closed versus open": it is a client that STOPS
         * against a client whose second hello differs from uTLS's in bytes nobody has captured. The
         * first is one distinguisher, the second is several, and only the first is known.
         *
         * ⚠️ WHAT UNBLOCKED IT was that vector, and it was made rather than reasoned about:
         * `tools/fp retry` drives uTLS through a synthetic HelloRetryRequest over a net.Pipe and
         * dumps the SECOND message. What it showed decided the implementation — hello2 is hello1
         * with key_share reduced to one entry and every one of the 339 bytes after it identical,
         * the 281-byte ECH GREASE included — so the operation here is a SPLICE of the hello already
         * built, and agreement follows by construction instead of from a second builder that would
         * have to be kept in step with the first forever.
         *
         * The cookie was the last part still refused, and it fell to the same method on 2026-08-30:
         * see lc_hello_splice_cookie in fp/hello.c, where the answer turned out to be that the
         * reference has no fixed
         * position to copy. */
        if (sh.cookie != NULL) {
            /* Echoed before the key share is spliced; see lc_hello_splice_cookie in fp/hello.c for
             * why that order, and
             * for the measurement that replaced this branch's old refusal. Failure here is silent
             * because the only ways it can fail are a hello that would outgrow its buffer or a
             * random draw that could not be made — neither of which the reference has an alert
             * for, since neither can happen to it. */
            if (lc_hello_splice_cookie(hs->hello, MAX_HELLO_OUT, &hs->info, sh.cookie,
                                       sh.cookie_len) != 0) {
                hs_fail(hs, "the retry's cookie does not fit the second hello");
                return;
            }
        }
        /* The group, when one is named, must be one this build can key. Since 2026-08-29 that is
         * all five the fingerprint advertises, which is what makes answering a retry possible at
         * all — before the two NIST curves arrived, a retry naming secp384r1 landed here and
         * stopped. */
        /* ONE CHECK WHERE THE REFERENCE HAS TWO, AND THE ANSWERS DIFFER — which is safe here only
         * because of what this build advertises.
         *
         * processHelloRetryRequest asks them in order: a selected group that is not in our
         * supported_curves is `illegal_parameter` ("server selected unsupported group",
         * vendor/utls/handshake_client_tls13.go:329-332), and a group that IS ours but has no
         * implementation behind it is `internal_error` — the fault being the client's own curve
         * list (vendor/utls/handshake_client_tls13.go:344-347).
         *
         * key_share_len_for covers exactly the groups this client offers — X25519MLKEM768, X25519
         * and the three NIST curves — so "cannot key" and "never advertised" are the same set, and
         * the reference's answer for that set is illegal_parameter. A fingerprint table carrying a
         * group this build cannot key (FFDHE, which no table here does) would separate them, and
         * then this branch would owe internal_error to the half that is ours. */
        size_t klen = 0;
        if (sh.selected_group != 0u) {
            klen = key_share_len_for(sh.selected_group);
            if (klen == 0u) {
                hs_alert(hs, LC_ALERT_ILLEGAL_PARAMETER);
                hs_fail(hs, "the retry asks for group 0x%04x, which this build cannot key",
                        sh.selected_group);
                return;
            }
        }
        /* The transcript starts HERE and not at the second ServerHello, and it does not start with
         * the first hello. RFC 8446 4.4.1 replaces ClientHello1 with a synthetic message —
         * `message_hash` (254), a three-byte length, and the hash of the hello it stands for — so
         * that both sides agree on a transcript neither side can rewrite by choosing a retry. */
        if (lc_tls_suite_params(sh.cipher_suite, &hs->alg, &hs->hash, &hs->key_len) != 0) {
            hs_own(hs);
            hs_fail(hs, "cipher suite 0x%04x passed the check and has no parameters",
                    sh.cipher_suite);
            return;
        }
        hs->hlen = lc_hash_len(hs->hash);
        uint8_t h1[LC_HASH_MAX];
        if (lc_hash_digest(hs->hash, hs->hello, hs->info.len, h1) != 0) {
            hs_own(hs);
            hs_fail(hs, "cannot hash the first hello");
            return;
        }
        if (lc_transcript_init(&hs->tr, hs->hash) != 0) {
            hs_own(hs);
            hs_fail(hs, "cannot start a transcript");
            return;
        }
        hs->tr_ready = 1;
        uint8_t synth[4];
        synth[0] = 0xfeu; /* message_hash */
        synth[1] = 0x00u;
        synth[2] = 0x00u;
        synth[3] = (uint8_t)hs->hlen;
        lc_transcript_add(&hs->tr, synth, sizeof synth);
        lc_transcript_add(&hs->tr, h1, hs->hlen);
        lc_transcript_add(&hs->tr, whole, whole_len);

        /* Only when a group was named. A cookie-only retry re-sends the SAME key shares, so both
         * the splice and the key generation would be undoing work that is already correct: the
         * first hello's public halves are in the buffer and their private halves are in hs->keys.
         * The reference skips the identical branch for the identical reason. */
        if (sh.selected_group != 0u) {
            if (lc_hello_splice_key_share(hs->hello, MAX_HELLO_OUT, &hs->info, sh.selected_group,
                                          klen) != 0) {
                hs_own(hs);
                hs_fail(hs, "cannot build the second hello");
                return;
            }
            if (fill_key_shares(hs->hello, &hs->info, &hs->keys, hs->err, sizeof hs->err) != 0) {
                hs->ph = PH_FAILED;
                return;
            }
        }
        /* NOT RE-STAMPED, and that is the reference's own behaviour rather than a shortcut: the
         * session id is carried over untouched — measured, see lc_hello_splice_key_share in
         * fp/hello.c — so REALITY's
         * payload rides into the second hello exactly as it rode into the first. A fresh stamp
         * would need a fresh session id, which the protocol forbids. */
        lc_transcript_add(&hs->tr, hs->hello, hs->info.len);

        hs_stage(hs, "sending the second ClientHello");

        /* THE DUMMY ChangeCipherSpec GOES OUT HERE, BEFORE THE SECOND HELLO, and its absence used
         * to be a one-record difference an active prober could read off the wire in the clear.
         *
         * The reference sends it on the retry path and sends it FIRST:
         *
         *     if err := hs.sendDummyChangeCipherSpec(); err != nil { return err }
         *     if err := hs.processHelloRetryRequest(); err != nil { return err }
         *                             (vendor/utls/handshake_client_tls13.go:91-97)
         *
         * and `c.buffering` is only set afterwards, at :136, so the CCS leaves the socket on its
         * own, ahead of CH2. The reference wire on a retry is therefore CH1 → CCS → CH2, while
         * ours was CH1 → CH2. Everything here is before any key is derived, so the missing 0x14
         * record was plaintext and free to read — the cheapest possible way to tell this client
         * from a stock one, for anyone willing to answer a hello with a HelloRetryRequest.
         *
         * It is NOT added to the transcript: a ChangeCipherSpec is not a handshake message and is
         * never hashed. It also must not be sent twice — the reference guards with `sentDummyCCS`,
         * and here hs->retried, set just below, is that same flag for the Finished path. */
        hs->tx[0] = LC_REC_CHANGE_CIPHER_SPEC;
        hs->tx[1] = 0x03;
        hs->tx[2] = 0x03;
        hs->tx[3] = 0x00;
        hs->tx[4] = 0x01;
        hs->tx[5] = 0x01;

        hs->tx[LC_CCS_RECORD + 0u] = LC_REC_HANDSHAKE;
        hs->tx[LC_CCS_RECORD + 1u] = 0x03;
        /* the second hello's record version is 0x0303, as the reference sends */
        hs->tx[LC_CCS_RECORD + 2u] = 0x03;
        hs->tx[LC_CCS_RECORD + 3u] = (uint8_t)(hs->info.len >> 8);
        hs->tx[LC_CCS_RECORD + 4u] = (uint8_t)hs->info.len;
        memcpy(hs->tx + LC_CCS_RECORD + LC_REC_HEADER, hs->hello, hs->info.len);
        hs->tx_len = LC_CCS_RECORD + LC_REC_HEADER + hs->info.len;
        hs->tx_off = 0;
        /* TWO WRITES, NOT ONE. The reference writes the dummy ChangeCipherSpec and then the second
         * hello, each with its own Write: sendDummyChangeCipherSpec and writeHandshakeRecord run
         * before `c.buffering = true`, which comes only after the retry has been dealt with
         * (vendor/utls/handshake_client_tls13.go:91-97, :136, :489), and Conn.write sends at once
         * unless it is set (vendor/utls/conn.go:951-959). With TCP_NODELAY, Go's default, that is a six-byte segment and then the hello.
         * ⚠️ UNTIL 2026-09-27 both left in one write, one segment. */
        hs->tx_cut = LC_CCS_RECORD;
        hs->retried = 1;
        hs->retry_suite = sh.cipher_suite;
        /* What followed the retry in its record stays, and is where the second ServerHello is read
         * from first — see where the first ServerHello drops its own. */
        hs_msg_drop(hs, whole_len);
        return;
    }

    /* sendDummyChangeCipherSpec, at the reference's point: after processServerHello and before the
     * key exchange (vendor/utls/handshake_client_tls13.go:136-142). There it is BUFFERED — c.buffering
     * went on just before processServerHello — so on success it leaves with the client's Finished,
     * where phase_finish puts it, and on ANY failure from here on the handshake's error path flushes
     * the buffer (vendor/utls/u_conn.go:371-375) and the alert leaves with the ChangeCipherSpec
     * ahead of it. This client sent the alert alone, which a passive observer can count and anyone
     * who can corrupt one record after the ServerHello can trigger. Owed until one of the two
     * carries it; a retry has already sent it (`sentDummyCCS`), which is what `retried` says. */
    if (!hs->retried)
        hs->ccs_owed = 1;

    /* The suite is settled: lc_check_server_hello refused one this hello did not offer, one that is
     * not among the three TLS 1.3 suites, and one a retry had not chosen. So this only looks up what
     * the choice implies. All three are accepted — the fingerprint decides the ORDER they are
     * offered in, and a client that understood only the first failed against a live server
     * choosing 0x1302. */
    if (lc_tls_suite_params(sh.cipher_suite, &hs->alg, &hs->hash, &hs->key_len) != 0) {
        hs_own(hs);
        hs_fail(hs, "cipher suite 0x%04x passed the check and has no parameters", sh.cipher_suite);
        return;
    }
    cl->hash = hs->hash;
    hs->hlen = lc_hash_len(hs->hash);

    /* ⚠️ AFTER A RETRY THE TRANSCRIPT ALREADY EXISTS AND ALREADY HOLDS THREE MESSAGES — the
     * synthetic message_hash standing for the first hello, the retry itself, and the second hello.
     * Starting it again here would throw all three away and hash a transcript the server does not
     * have, which fails every Finished with no hint of why. And the suite cannot move: RFC 8446
     * have, which fails every Finished with no hint of why. And the suite cannot move: RFC 8446
     * 4.1.4 requires the ServerHello after a retry to name the same one, because the transcript is
     * already being hashed with the hash that choice implies — lc_check_server_hello holds it to
     * that, at the reference's point in the order. */
    if (!hs->retried && lc_transcript_init(&hs->tr, hs->hash) != 0) {
        hs_own(hs);
        hs_fail(hs, "cannot start a transcript");
        return;
    }
    hs->tr_ready = 1;
    /* The hello as it went out, which for a REALITY connection means AFTER the stamp: the sealed
     * payload sits in its session_id, and hashing the bytes from before the stamp would hash a
     * message the server never saw. */
    if (!hs->retried)
        lc_transcript_add(&hs->tr, hs->hello, hs->info.len);
    /* Hashed straight out of the reassembly window, which outlives this function, so copying the
     * message aside first would buy nothing. */
    lc_transcript_add(&hs->tr, whole, whole_len);

    /* WHAT FOLLOWED THE SERVERHELLO IN ITS RECORD IS KEPT, and read as the first bytes of the
     * flight. The reference reads handshake messages out of one buffer, c.hand, which a change of
     * key does not empty: whatever the ServerHello's record carried after it is where the next
     * readHandshake starts, before any record is read (vendor/utls/conn.go:1082-1090), and
     * a record of any other type arriving while it is there is unexpected_message
     * (vendor/utls/conn.go:707-710). Dropped at the end of this function rather than here, because
     * `sh` points into the window until the key exchange has read it.
     *
     * ⚠️ UNTIL 2026-09-27 it was thrown away as "bytes from two different key epochs", and the
     * flight started empty: a ServerHello with anything behind it was answered as if nothing were. */

    hs_stage(hs, "deriving handshake keys");
    uint8_t shared[LC_KEX_SHARED_MAX];
    size_t  shared_len = 0;
    /* ⚠️ WITH AN ALERT, WHICH THIS PATH DID NOT SEND — found by the reverse sieve on 2026-08-29,
     * the one true gap it reported in 222 reference functions.
     *
     * Every other refusal in this function speaks: internal_error above and below, and
     * illegal_parameter on a suite the hello did not offer. This one set PH_FAILED and returned,
     * so alert_pending stayed 0 and the caller hung up with a bare FIN. An unoffered
     * group — "server selected unsupported group" — is
     * alertIllegalParameter (vendor/utls/handshake_client_tls13.go:536-541) and so is a share it
     * cannot use (vendor/utls/handshake_client_tls13.go:581-585), value 47 in each case.
     * An offered GREASE group now fails keyExchangeForCurveID with internal_error (80).
     *
     * ⚠️ AND A PROBE CAN REACH IT WITHOUT KNOWING ANYTHING, which is what makes it a distinguisher
     * rather than a tidiness point: our supported_groups advertises five codepoints and we carry a
     * key share for three of them (see tls/kex.h — 0x0018 and 0x0019 are named and never keyed). A
     * ServerHello selecting secp384r1 therefore lands here on any connection an on-path observer
     * cares to answer, and no key exists yet at this stage, so the reference's alert goes out in
     * the CLEAR — seven bytes, `15 03 03 00 02 02 2f`, against our silence. One record to send,
     * one answer to tell the two clients apart, exactly like the SSLv2 byte and the CCS body this
     * file already answers.
     *
     * hs_fail is not called: shared_for has already written the sentence, and hs_fail would
     * overwrite the specific reason with a general one. */
    int shared_result = shared_for(&hs->keys, &sh, shared, &shared_len, hs->err, sizeof hs->err);
    if (shared_result != 0) {
        hs_alert(hs, shared_result == -2 ? LC_ALERT_INTERNAL_ERROR : LC_ALERT_ILLEGAL_PARAMETER);
        hs->ph = PH_FAILED;
        return;
    }

    uint8_t early[LC_HASH_MAX], derived[LC_HASH_MAX];
    /* Checked, because everything below is derived from it: on a failure this left `empty_hash`
     * holding whatever the frame held before, and the schedule carried on and produced traffic
     * secrets from it. The QUIC twin of this file (quic/qtls.c) checks every one of these calls;
     * this one checked none. */
    if (lc_hash_digest(hs->hash, NULL, 0, hs->empty_hash) != 0) {
        hs_own(hs);
        hs_fail(hs, "the hash of the empty string failed");
        return;
    }
    {
        uint8_t zeros[LC_HASH_MAX];
        memset(zeros, 0, hs->hlen);
        int ok = lc_hkdf_extract(hs->hash, NULL, 0, zeros, hs->hlen, early) == 0 &&
                 lc_derive_secret(hs->hash, early, "derived", hs->empty_hash, derived) == 0 &&
                 lc_hkdf_extract(hs->hash, derived, hs->hlen, shared, shared_len,
                                 hs->hs_secret) == 0;
        /* The precursors of the handshake secret, wiped on both paths. The failure path used to
         * return with all three still in the frame, which is the one path where the connection is
         * abandoned and the frame is reused soonest. */
        lc_wipe(early, sizeof early);
        lc_wipe(derived, sizeof derived);
        lc_wipe(shared, sizeof shared);
        if (!ok) {
            hs_own(hs);
            hs_fail(hs, "the handshake schedule failed");
            return;
        }
    }

    uint8_t th[LC_HASH_MAX];
    if (lc_transcript_snapshot(&hs->tr, th) != 0) {
        hs_own(hs);
        hs_fail(hs, "cannot take the transcript hash");
        return;
    }
    if (lc_derive_secret(hs->hash, hs->hs_secret, "c hs traffic", th, hs->c_hs) != 0 ||
        lc_derive_secret(hs->hash, hs->hs_secret, "s hs traffic", th, hs->s_hs) != 0) {
        hs_own(hs);
        hs_fail(hs, "cannot derive handshake traffic secrets");
        return;
    }

    {
        /* Both halves are decided before anything is wiped, so that the two failure exits leave no
         * more behind than the successful one: the earlier shape returned with a live traffic key
         * still in this frame. */
        uint8_t key[32], iv[LC_AEAD_NONCE];
        int     server_ok =
            lc_hkdf_expand_label(hs->hash, hs->s_hs, "key", NULL, 0, key, hs->key_len) == 0 &&
            lc_hkdf_expand_label(hs->hash, hs->s_hs, "iv", NULL, 0, iv, sizeof iv) == 0 &&
            lc_record_key_init(&hs->s_keys, hs->alg, key, iv) == 0;
        int client_ok = server_ok &&
            lc_hkdf_expand_label(hs->hash, hs->c_hs, "key", NULL, 0, key, hs->key_len) == 0 &&
            lc_hkdf_expand_label(hs->hash, hs->c_hs, "iv", NULL, 0, iv, sizeof iv) == 0 &&
            lc_record_key_init(&hs->c_keys, hs->alg, key, iv) == 0;
        lc_wipe(key, sizeof key);
        lc_wipe(iv, sizeof iv);
        if (!client_ok) {
            if (server_ok)
                lc_record_key_free(&hs->s_keys);
            hs_own(hs);
            hs_fail(hs, server_ok ? "cannot build the client handshake keys"
                                  : "cannot build the server handshake keys");
            return;
        }
    }
    hs->hs_keys_ready = 1;

    hs_stage(hs, "reading the server flight");
    hs_msg_drop(hs, whole_len);
    hs->ph = PH_FLIGHT;
}

/* ---- phase three: the server flight ----------------------------------------- */



/* WHICH MESSAGE THE ENCRYPTED FLIGHT EXPECTS NEXT, AND WHAT A PEER GETS FOR SENDING ANOTHER.
 *
 * The reference reads this flight as a sequence of expectations, not as a bag of messages:
 * readServerParameters wants EncryptedExtensions, readServerCertificate wants an optional
 * CertificateRequest and then a Certificate and then a CertificateVerify, readServerFinished wants
 * a Finished (vendor/utls/handshake_client_tls13.go:625-700, :702-820, :822-871). Anything else —
 * a known message out of turn, or a type Go does not know at all — is refused with
 * unexpected_message, either from the type assertion at the call site or from the `default` of
 * unmarshalHandshakeMessage (vendor/utls/conn.go:1176-1184).
 *
 * This client used to take whatever arrived, in any order, and silently drop what it had no arm
 * for. That is an active distinguisher and a cheap one: send a NewSessionTicket in the middle of
 * the flight, or a message type nobody defines, and a stock client tears the connection down with
 * alert 10 while this one hashed it and carried on. The peer who can do that is the node or the
 * site it fronts — which is exactly who a prober arranges to be.
 *
 * The states are the reference's steps. LC_FLIGHT_CERT covers both the Certificate and the
 * CertificateRequest that may precede it, because that is the one place the sequence branches. */
#define LC_FLIGHT_EE   0u /* EncryptedExtensions, and nothing else, opens the flight */
#define LC_FLIGHT_CERT 1u /* Certificate, or the CertificateRequest that may come first */
#define LC_FLIGHT_CERT_SEEN_REQ 2u /* the request has been read; the Certificate is still due */
#define LC_FLIGHT_CV   3u /* CertificateVerify */
#define LC_FLIGHT_FIN  4u /* the server's Finished */
#define LC_FLIGHT_DONE 5u /* nothing more belongs to this flight */

/* The state after |type| has been accepted in state |state|, or LC_FLIGHT_BAD if |type| does not
 * belong there. A CompressedCertificate stands in for a Certificate: the reference accepts it in
 * the same position (vendor/utls/u_handshake_client.go:33-41). */
#define LC_FLIGHT_BAD 0xffu

static uint8_t flight_next(uint8_t state, uint8_t type)
{
    switch (state) {
    case LC_FLIGHT_EE:
        return type == LC_HS_ENCRYPTED_EXT ? LC_FLIGHT_CERT : LC_FLIGHT_BAD;
    case LC_FLIGHT_CERT:
        /* The request is read and the state does not move: what follows it is still the
         * Certificate, and a second request is not a thing the reference reads twice — its
         * certReq branch runs once and then falls through to the type assertion below it
         * (vendor/utls/handshake_client_tls13.go:728-740). */
        if (type == LC_HS_CERTIFICATE_REQUEST)
            return LC_FLIGHT_CERT_SEEN_REQ;
        return (type == LC_HS_CERTIFICATE || type == LC_HS_COMPRESSED_CERTIFICATE)
                   ? LC_FLIGHT_CV
                   : LC_FLIGHT_BAD;
    case LC_FLIGHT_CERT_SEEN_REQ:
        return (type == LC_HS_CERTIFICATE || type == LC_HS_COMPRESSED_CERTIFICATE)
                   ? LC_FLIGHT_CV
                   : LC_FLIGHT_BAD;
    case LC_FLIGHT_CV:
        return type == LC_HS_CERTIFICATE_VERIFY ? LC_FLIGHT_FIN : LC_FLIGHT_BAD;
    case LC_FLIGHT_FIN:
        return type == LC_HS_FINISHED ? LC_FLIGHT_DONE : LC_FLIGHT_BAD;
    default:
        return LC_FLIGHT_BAD;
    }
}


/* Consumes one record of the flight. Sets *done when the server's Finished has been verified. */
/* The Certificate into the transcript as the reference puts it there. -1 for no memory, which is
 * ours to answer, and -2 when the reference's own marshal would fail: its transcriptMsg returns that
 * error and the handshake ends with no alert. */
static int transcript_certificate(lc_client_hs *hs, const uint8_t *body, size_t body_len)
{
    uint8_t *re = malloc(body_len + 4u);
    if (re == NULL)
        return -1;
    size_t n = lc_cert13_remarshal(body, body_len, re, body_len + 4u);
    if (n > 0u)
        lc_transcript_add(&hs->tr, re, n);
    free(re);
    return n > 0u ? 0 : -2;
}

/* One record of the flight onto the end of the window. -1 when there is nothing more to do with it:
 * the handshake failed, or the record was one the reference ignores. */
static int flight_record(lc_client_hs *hs)
{
    const uint8_t *rec = hs->rx;
    size_t         rec_len = hs->rx_len;

    /* A ChangeCipherSpec is passed through unopened — "In TLS 1.3, change_cipher_spec messages are
     * to be ignored without being decrypted" (vendor/utls/conn.go:347-351) — and every other record
     * is opened; what either turns out to be is hs_record_kind's to judge. The ChangeCipherSpec
     * rules that lived here — one byte of 0x01, never in the middle of a message — are there now,
     * shared with the phase before this one, where a Go server puts a ChangeCipherSpec after a
     * HelloRetryRequest. They came from the reverse sieve, the only real gap it found in 244
     * candidates: `14 03 03 00 00` at a stock client gets decode_error, and this client used to
     * swallow it. */
    uint8_t        type_in = 0;
    const uint8_t *data = NULL;
    size_t         got = 0;
    if (rec[0] == LC_REC_CHANGE_CIPHER_SPEC) {
        type_in = LC_REC_CHANGE_CIPHER_SPEC;
        data = rec + LC_REC_HEADER;
        got = rec_len - LC_REC_HEADER;
    } else {
        /* Decrypted onto the end of whatever an earlier record left waiting, not over it. The room
         * is taken first because the window grows for a message larger than the inline one — and
         * because `hs->plain` is a pointer now, `sizeof` it is the size of a pointer and not of the
         * buffer it points at, which is exactly the kind of arithmetic that turns into a decryption
         * failure two layers away from the mistake. */
        if (hs_msg_reserve(hs, rec_len) != 0) {
            hs_own(hs);
            hs_fail(hs, "no room to open a record of %zu bytes", rec_len);
            return -1;
        }
        int rc = lc_record_unprotect(&hs->s_keys, rec, rec_len, hs->plain + hs->plain_len,
                                     hs->plain_cap - hs->plain_len, &got, &type_in);
        if (rc != 0) {
            /* bad_record_mac for a record that does not open — one relabelled on the outside as
             * well, since the tag covers the header — and, for one that does, unexpected_message
             * when it was sealed under another header or is all padding and record_overflow when
             * it opens to too much; see lc_record_unprotect, and the window grown above to the
             * whole record, which is what lets it open one. This sent decrypt_error (51) for every
             * one of them, the number the reference keeps for a signature that does not verify, and a
             * relabelled plaintext record got unexpected_message before any open was tried: two
             * different bytes back for records anyone on the path can forge. */
            hs_alert(hs, (uint8_t)-rc);
            hs_fail(hs, "a server record does not open");
            return -1;
        }
        data = hs->plain + hs->plain_len;
    }
    int kind = hs_record_kind(hs, type_in, data, got);
    if (kind != 0)
        return -1;
    hs->plain_len += got;
    return 0;
}

static void phase_flight(lc_client_hs *hs, lc_client *cl, int *done, int fresh)
{
    /* Without a fresh record when the window already holds a whole message — what the ServerHello's
     * record carried behind it; see msg_waiting. */
    if (fresh && flight_record(hs) != 0)
        return;

    uint8_t        type = 0;
    const uint8_t *body = NULL, *whole = NULL;
    size_t         body_len = 0, whole_len = 0;

    int mrc;
    while ((mrc = hs_msg_take(hs, &type, &body, &body_len, &whole, &whole_len)) == 1) {
        /* The message has to be the one this flight is waiting for. What it gets for not being it
         * is what the reference gives: alert 10, from the type assertion or from the default arm
         * of unmarshalHandshakeMessage. */
        uint8_t next = flight_next(hs->flight, type);
        if (next == LC_FLIGHT_BAD) {
            hs_alert_type(hs, type);
            hs_fail(hs, "the peer sent handshake message 0x%02x where the flight expects %s",
                    (unsigned)type,
                    hs->flight == LC_FLIGHT_EE     ? "EncryptedExtensions"
                    : hs->flight == LC_FLIGHT_CV   ? "CertificateVerify"
                    : hs->flight == LC_FLIGHT_FIN  ? "Finished"
                    : hs->flight == LC_FLIGHT_DONE ? "nothing more"
                                                   : "a Certificate");
            return;
        }
        hs->flight = next;

        /* Read and remembered, and the transcript takes it at the bottom of the loop like every
         * other message — `transcriptMsg(certReq, hs.transcript)`
         * (vendor/utls/handshake_client_tls13.go:728-732). What it changes is our own flight: see
         * phase_finish. */
        if (type == LC_HS_CERTIFICATE_REQUEST) {
            /* Unmarshalled before it is believed: a request that does not parse is
             * unexpected_message (vendor/utls/conn.go:1185-1186). This took any bytes at all as a
             * request, and answered a malformed one with the empty Certificate it answers a real
             * one with — which the reference never reaches. */
            if (!lc_cert_request_parses(body, body_len)) {
                hs_alert(hs, LC_ALERT_UNEXPECTED_MESSAGE);
                hs_fail(hs, "the node's CertificateRequest does not parse");
                return;
            }
            hs->cert_requested = 1;
            lc_transcript_add(&hs->tr, whole, whole_len);
            hs_msg_drop(hs, whole_len);
            continue;
        }

        /* A COMPRESSED CERTIFICATE, WHICH THIS CLIENT ASKS FOR AND READS.
         *
         * The hello carries compress_certificate — extension 27, algorithms zlib, brotli and zstd —
         * because the fingerprint it is built from carries it, and a server is entitled to answer
         * any of the three with a CompressedCertificate (RFC 8879) instead of a Certificate. The
         * reference decompresses all three and carries on
         * (vendor/utls/u_handshake_client.go:52-141), and so does this: tls/certcomp has held all
         * three decoders since 2026-09-05. What stood here — "nothing here can", and "the message
         * is REFUSED" — was written before them and outlived them.
         *
         * Before the decoders the message was refused by name; before THAT it fell off the end of
         * the loop, left no leaf behind and reached CertificateVerify with nothing to check — which
         * surfaced as "no certificate to check the signature against" and read as a broken server
         * rather than a message nobody had implemented.
         *
         * MEASURED, because "some servers" is not a plan: of seven public sites probed on
         * 2026-08-18, www.example.com, www.cloudflare.com and discord.com — all Cloudflare — sent
         * this, every one of them choosing brotli; google, avito, kinopoisk and microsoft sent an
         * ordinary Certificate. It costs nothing on the authenticated REALITY path, where the peer
         * is Xray and Go's TLS server implements no compression at all, and everything on the
         * masquerade path when the node's dest sits behind Cloudflare.
         *
         * ⚠️ AND THE HELLO OFFERS ALL THREE, WHICH IS THE OPPOSITE OF WHAT THIS SAID. The sentence
         * here was "the hello now offers zlib and nothing else, which is what stops brotli arriving
         * in the first place" — a description of the FINGERPRINT, stated backwards, in the file
         * that reads the reply. Trimming the list was undone when the other two decoders were built
         * in, and tls/certcomp.h has said so since ("ALL THREE, AS THE CAPTURE HAS THEM — zlib,
         * brotli, zstd, in that order"); this line was left behind pointing at it as if it agreed.
         *
         * Measured rather than reasoned, 2026-09-10: a hello built from the shipped table carries
         * compress_certificate with a six-byte list — 0x0001, 0x0002, 0x0003. Brotli is exactly
         * what a Cloudflare dest will now choose, and inflating it here is not a fallback but the
         * ordinary path. What arrives is inflated and then treated as the Certificate it stands for.
         *
         * THE TRANSCRIPT GETS THE COMPRESSED MESSAGE, not this one. `whole` is added at the bottom
         * of the loop and is untouched by any of it, which is what the reference does —
         * `transcriptMsg(compressedCertMsg, hs.transcript)` and then the decompressed message is
         * returned for PROCESSING only (vendor/utls/u_handshake_client.go:33-41). Hashing what we
         * unpacked instead of what was sent would fail every CertificateVerify and every Finished. */
        /* ENCRYPTED EXTENSIONS, AS uTLS READS THEM: the message unmarshalled whole, then the
         * protocol, then application settings, then two extensions a TLS server over TCP may not
         * send — see lc_utls_ee_alert.
         *
         * This branch once did not exist, on the argument that the message arrives under the
         * handshake keys and so only the peer can reach it. The keys come from an exchange with
         * whoever answered the hello; REALITY authenticates the peer only at the Certificate, one
         * message later, so anyone who can answer our hello can put an EncryptedExtensions in
         * front of us. And Xray's REALITY client IS uTLS
         * (vendor/Xray-core/transport/internet/reality/reality.go:162), so these checks run inside
         * its handshake on every connection, whatever Xray does with the result afterwards.
         *
         * ⚠️ AND ALPS IS NOT "NOTHING SENT BACK", which this said: uTLS stores the bytes without
         * validating them (vendor/utls/u_handshake_messages.go:62-71), but then refuses ALPS that
         * came without a negotiated protocol, with unsupported_extension
         * (vendor/utls/u_handshake_client.go:166-176, vendor/utls/handshake_client_tls13.go:651-658).
         * And a server's ALPS is answered with an EncryptedExtensions of our own after its Finished
         * (vendor/utls/u_handshake_client.go:143-164), which this said the client did not build —
         * it does now: see lc_utls_alps_answer and the flight in phase_finish. */
        if (type == LC_HS_ENCRYPTED_EXT) {
            uint8_t a = lc_utls_ee_alert(hs->hello, hs->info.len, body, body_len, 0);
            if (a != 0u) {
                hs_alert(hs, a);
                hs_fail(hs, a == LC_ALERT_UNEXPECTED_MESSAGE ? "the node's EncryptedExtensions does not parse"
                            : a == LC_ALERT_NO_APPLICATION_PROTOCOL
                                ? "the node chose an application protocol we did not offer"
                                : "the node's EncryptedExtensions carries an extension it may not send");
                return;
            }
            hs->alps_answer_len = lc_utls_alps_answer(body, body_len, hs->alps_answer);
        }

        if (type == LC_HS_COMPRESSED_CERTIFICATE) {
            size_t n = 0;
            char   why[192];
            /* ALLOCATED WHEN IT IS FIRST NEEDED, AND SIZED TO WHAT THE MESSAGE DECLARES — ALL OF IT.
             *
             * The reference allocates `m.uncompressedLength + 4` at this point
             * (vendor/utls/u_handshake_client.go:100), so the peer's own number decides the size, up
             * to the sixteen megabytes three bytes can say; this asks for the same number. A dest
             * behind Cloudflare chooses brotli (measured above), so this is an ordinary path, and
             * what it costs is one allocation for each handshake that meets it. Freed with the
             * handshake, so no failure path below has to remember it.
             *
             * ⚠️ IT WAS CAPPED AT THE CERTIFICATE MESSAGE'S OWN CEILING, 262144, until 2026-09-25,
             * and a longer declaration was refused where the reference opens it — measured there, a
             * 300000-byte certificate opens (test/certcomp/reference_open.h). An open divergence
             * awaiting the maintainer, closed on "finish it to the ideal", with memory what a router has
             * to spare. Nothing asks the machine first any more (L1, gone 29.09): a failed allocation
             * answers internal_error, the alert this path already gave one.
             *
             * The length lives at bytes 2..4 of the body — `algorithm(2) | uncompressed_length(3)`
             * — and a body too short to hold even that is refused by lc_certcomp_open below, with
             * the alert the reference sends. */
            size_t want = lc_utls_certcomp_want(body, body_len);

            if (hs->opened_cap < want) {
                free(hs->opened);
                hs->opened = malloc(want);
                hs->opened_cap = want;
                if (hs->opened == NULL) {
                    hs->opened_cap = 0;
                    hs_own(hs);
                    hs_fail(hs, "no memory to open a compressed certificate");
                    return;
                }
            }
            uint8_t *opened = hs->opened;
            size_t   offered_len = 0;
            const uint8_t *offered =
                lc_ch_ext(hs->hello, hs->info.len, LC_EXT_COMPRESS_CERTIFICATE, &offered_len);
            int opened_alert = lc_certcomp_open(body, body_len, offered, offered_len, opened,
                                                hs->opened_cap, &n, why, sizeof why, NULL, 0);
            if (opened_alert != 0) {
                /* 10 for a header that does not read, 80 for no memory, 42 for the rest — see
                 * lc_certcomp_open. A declared length of zero opens to an empty body, which the
                 * Certificate verdict below answers 10, as the reference's unmarshal does. */
                hs_alert(hs, (uint8_t)opened_alert);
                hs_fail(hs, "%s", why);
                return;
            }
            type = LC_HS_CERTIFICATE;
            body = opened;
            body_len = n;
        }

        /* The leaf is kept on EVERY plane and not only when REALITY is in play, because the message
         * that proves the peer holds its key arrives next and has nothing to check against
         * otherwise. */
        /* The two refusals a Certificate message can earn, and they are not the same one: see
         * lc_utls_cert_msg_alert above phase_flight. */
        if (type == LC_HS_CERTIFICATE) {
            uint8_t a = lc_utls_cert_msg_alert(body, body_len);
            if (a != 0u) {
                hs_alert(hs, a);
                hs_fail(hs, a == LC_ALERT_DECODE_ERROR
                                ? "the peer sent a Certificate message with no certificates in it"
                            : a == LC_ALERT_BAD_CERTIFICATE
                                ? "a certificate the peer sent does not parse as X.509, or carries "
                                  "an RSA key over 8192 bits"
                                : "the peer's Certificate message does not parse");
                return;
            }

            const uint8_t *leaf = NULL;
            size_t         leaf_len = 0;
            (void)lc_cert_first_from_message(body, body_len, &leaf, &leaf_len);

            /* Kept on the heap, sized to the leaf. Go reads whatever the peer sent and so does
             * this now: the fixed field it used to be copied into was a refusal the reference does
             * not have, and a field sized to the new ceiling would be 256 KB carried by every
             * handshake for a certificate that is two kilobytes. */
            free(hs->cert_der);
            hs->cert_der = malloc(leaf_len ? leaf_len : 1u);
            if (hs->cert_der == NULL) {
                hs->cert_der_len = 0;
                hs_own(hs);
                hs_fail(hs, "no memory for the peer's certificate");
                return;
            }

            memcpy(hs->cert_der, leaf, leaf_len);
            hs->cert_der_len = leaf_len;
        }

        /* CERTIFICATEVERIFY, CHECKED — WHICH IT WAS NOT, ON THIS PLANE, AT ALL.
         *
         * The message used to fall through to the transcript and nothing else, so any peer could
         * answer our hello with any certificate and sixty-four bytes of noise and be believed. The
         * reference has no such path: verifyHandshakeSignature is called unconditionally
         * (vendor/utls/handshake_client_tls13.go:865-869) — no branch on InsecureSkipVerify, and
         * none on what REALITY's VerifyPeerCertificate callback decided, because that callback runs
         * earlier and in ADDITION to this, not instead of it 
         * (vendor/Xray-core/transport/internet/reality/reality.go:142-150 installs it as
         * VerifyPeerCertificate on a config that also has
         * InsecureSkipVerify true).
         *
         * So it is checked here for every peer, whatever REALITY concluded about it. A REALITY node
         * signs with Ed25519 and nothing else (vendor/REALITY/auth.go:209-210), which is why
         * src/tls/ed25519.c exists: without it this check could only be made on the masquerade path
         * and would have had to be skipped on the plane's own, and a rule about when a signature may
         * be skipped is not something the reference contains.
         *
         * The transcript hash is taken BEFORE the message is added, because the signature covers the
         * handshake up to and including Certificate — the same reason the Finished check below takes
         * its snapshot before its own message. */
        if (type == LC_HS_CERTIFICATE_VERIFY) {
            uint8_t th_cert[LC_HASH_MAX];
            if (lc_transcript_snapshot(&hs->tr, th_cert) != 0) {
                hs_own(hs);
                hs_fail(hs, "cannot take the transcript hash");
                return;
            }
            char    why[192];
            uint8_t alert = LC_ALERT_DECRYPT_ERROR;
            if (lc_cert_verify(hs->cert_der, hs->cert_der_len, hs->hash, th_cert, body, body_len, 0, 1,
                               why, sizeof why, &alert, NULL, 0) != 0) {
                /* Different refusals wear different alerts, because the reference gives them
                 * different ones, and the verifier is what knows which happened. This used to
                 * choose between two by asking whether a certificate had arrived — right for those
                 * two and silent about the rest, so an unsupported signature scheme went out as
                 * decrypt_error where the reference sends illegal_parameter
                 * (vendor/utls/handshake_client_tls13.go:853-855). */
                hs_alert(hs, alert);
                hs_fail(hs, "%s", why);
                return;
            }
            hs->cert_verified = 1;
        }

        if (type == LC_HS_CERTIFICATE && hs->cfg.use_reality) {
            const uint8_t *der = hs->cert_der;
            size_t         der_len = hs->cert_der_len;
            lc_cert        crt;
            if (der_len == 0u) {
                snprintf(cl->reality_note, sizeof cl->reality_note,
                         "no certificate in the message");
            } else if (lc_cert_parse(der, der_len, &crt) != 0) {
                /* Almost always the donor's certificate: real sites use RSA or ECDSA, and this
                 * parser accepts only the ed25519 shape REALITY generates. Which makes a parse
                 * failure the clearest evidence there is that the server took us for a stranger. */
                snprintf(cl->reality_note, sizeof cl->reality_note,
                         "%u-byte certificate is not the ed25519 shape REALITY sends",
                         (unsigned)der_len);
            } else if (lc_reality_verify_cert(cl->reality_auth_key, crt.public_key,
                                              crt.public_key_len, crt.signature,
                                              crt.signature_len) != 0) {
                snprintf(cl->reality_note, sizeof cl->reality_note,
                         "ed25519 certificate present but its HMAC does not match our auth key");
            } else {
                cl->reality_verified = 1;
            }

            /* THE KEY-TYPE SWITCH RUNS FIRST, ON EITHER OUTCOME, because that is where the
             * reference has it: verifyServerCertificate type-checks every parsed leaf before any
             * verification happens (vendor/utls/handshake_client.go:1239-1249). On the verified
             * branch this can never fire — REALITY leaves are ed25519 by construction — and that is
             * the reason to keep it unconditional rather than tuck it into the stranger branch:
             * the order of refusals on the wire is the fingerprint, not our knowledge of which
             * branch was doomed. */
            if (der != NULL && der_len > 0 && lc_cert_key_supported(der, der_len) == 0) {
                hs_alert(hs, LC_ALERT_UNSUPPORTED_CERTIFICATE); /* vendor/utls/handshake_client.go:1247 */
                hs_fail(hs, "the node's certificate carries a public key that is not RSA, ECDSA "
                            "or Ed25519");
                return;
            }

            /* AND WHEN IT DID NOT AUTHENTICATE, THE CERTIFICATE IS CHECKED THE ORDINARY WAY.
             *
             * A certificate that does not carry our HMAC means the server treated us as a stranger
             * and is proxying the real site — so what we are holding is that site's certificate, and
             * the reference verifies it exactly as a browser would: chain to a system root, valid
             * for the name we asked for
             * (vendor/Xray-core/transport/internet/reality/reality.go:129-139, with Roots left nil,
             * which is Go for "the machine's store"). A failure there comes back out of
             * VerifyPeerCertificate, and crypto/tls answers it with alertBadCertificate and
             * abandons the handshake (vendor/utls/handshake_client.go:1251-1256).
             *
             * This used to have no branch at all, with a comment saying the handshake continues
             * "exactly as a browser's would, because behaving differently is what would give us
             * away". The first half was wrong in the way that matters: a browser handed an
             * unverifiable certificate does not continue, it stops — so continuing was itself the
             * behaviour that differs. And the second half had it backwards. Without this check the
             * node that does not know us and the man in the middle are ONE event: both produce a
             * finished handshake against a certificate nobody looked at, and both then get the
             * spider, which is this client sending a real browser's HTTP/2 request over a session
             * an attacker terminated.
             *
             * The success case is unchanged and is the whole point of the spider: a genuine
             * masquerade — the node serving the real site to a stranger — verifies, and we go on to
             * behave like the browser we claimed to be. */
            if (!cl->reality_verified) {
                char why[192];
                if (lc_chain_verify(body, body_len, hs->cfg.sni, why, sizeof why) != 0) {
                    hs_alert(hs, LC_ALERT_BAD_CERTIFICATE); /* vendor/utls/handshake_client.go:1254 */
                    hs_fail(hs, "the node did not authenticate and its certificate is not valid "
                                "for %s either: %s", hs->cfg.sni ? hs->cfg.sni : "the name asked for",
                            why);
                    return;
                }
            }
        }
        if (type == LC_HS_FINISHED) {
            uint8_t th_before[LC_HASH_MAX];
            if (lc_transcript_snapshot(&hs->tr, th_before) != 0) {
                hs_own(hs);
                hs_fail(hs, "cannot take the transcript hash");
                return;
            }
            if (lc_finished_check(hs->hash, hs->s_hs, th_before, body, body_len) != 0) {
                hs_alert(hs, LC_ALERT_DECRYPT_ERROR);
                hs_fail(hs, "the server Finished does not verify");
                return;
            }
            /* A flight that reached Finished without proving possession of a certificate is refused,
             * rather than accepted because the message that would have failed never arrived.
             *
             * The reference reads Certificate and then CertificateVerify as one step and treats a
             * missing one as unexpected_message (vendor/utls/handshake_client_tls13.go:786-791).
             * Only a PSK handshake legitimately skips both, and this client offers no PSK at all —
             * psk_key_exchange_modes is not in its hello — so there is no case where their absence
             * is anything but a peer avoiding the check. */
            if (!hs->cert_verified) {
                hs_alert(hs, LC_ALERT_UNEXPECTED_MESSAGE); /* :847 */
                hs_fail(hs, "the peer finished without proving it holds a certificate");
                return;
            }
            *done = 1;
        }
        /* A Certificate is hashed as the reference hashes it — re-marshalled, see
         * lc_cert13_remarshal — and not as it came: transcriptMsg writes `msg.marshal()` for any
         * message without its original bytes (vendor/utls/handshake_messages.go:2009-2023), and
         * certificateMsgTLS13 keeps none. A CompressedCertificate is hashed as it came, which is
         * what its own reader does. ⚠️ UNTIL 2026-09-27 the wire bytes, so an entry extension the
         * reference drops — or two it merges, or two it reorders — was in our transcript and not in
         * its: a Finished it refuses, we accepted. */
        if (whole[0] == LC_HS_CERTIFICATE) {
            int trc = transcript_certificate(hs, body, body_len);
            if (trc != 0) {
                if (trc == -1)
                    hs_own(hs);
                hs_fail(hs, trc == -1 ? "no memory to hash the Certificate"
                                      : "the Certificate does not marshal again");
                return;
            }
        } else {
            lc_transcript_add(&hs->tr, whole, whole_len);
        }
        hs_msg_drop(hs, whole_len);
        if (*done)
            break;
    }
    /* Nothing is reported for a message that is merely incomplete: the loop simply stops and the
     * next record continues it. Only a message too large ends the handshake here, and it ends it
     * with the alert Go sends for the same thing — `c.sendAlertLocked(alertInternalError)`
     * (vendor/utls/conn.go:1114-1117), where this client used to send decode_error. */
    if (mrc < 0) {
        hs_alert(hs, LC_ALERT_INTERNAL_ERROR);
        hs_fail(hs, "a handshake message of type 0x%02x larger than the reference reads",
                (unsigned)hs->plain[0]);
    }
}

/* ---- TLS 1.2 (T3) ---------------------------------------------------------------------------
 *
 * WHAT uTLS DOES WHEN THE SERVER ANSWERS THE PARROT'S HELLO WITH TLS 1.2, which is to go on:
 * hs12.handshake() (vendor/utls/u_handshake_client.go:569-579, vendor/utls/handshake_client.go:
 * 567-662). A full handshake always — Xray's REALITY client keeps no session cache, so there is
 * nothing to resume — read as doFullHandshake reads it: a Certificate, then perhaps a
 * CertificateStatus, then the certificate is verified, then perhaps a ServerKeyExchange, then perhaps
 * a CertificateRequest, then the ServerHelloDone; our Certificate if one was asked for, the
 * ClientKeyExchange, a ChangeCipherSpec and our Finished in one flush; and then the server's
 * NewSessionTicket if it said it would send one, its ChangeCipherSpec and its Finished.
 *
 * Every message is unmarshalled before it is looked at — readHandshake — and one that does not
 * unmarshal is unexpected_message whatever it is (unmarshalHandshakeMessage,
 * vendor/utls/conn.go:1192-1194); a message that is
 * not the one expected is unexpected_message too (unexpectedMessageError at each step).
 *
 * The server this meets is a site: the one the REALITY node forwards a stranger to, or one the spider
 * fetches. It stopped here with protocol_version until 29.09, the answer mail.ru — one of twenty-two
 * sites probed on 2026-08-18 — got for serving TLS 1.2 alone. */

/* certificateMsg.unmarshal, its own arithmetic included: the total and each length are uint32, and the
 * walk asks for FOUR bytes where a length takes three (vendor/utls/handshake_messages.go:1483-1517). */
static int cert12_parses(const uint8_t *body, size_t len, size_t *count)
{
    if (len + 4u < 7u)
        return 0;
    uint32_t total = (uint32_t)body[0] << 16 | (uint32_t)body[1] << 8 | body[2];
    if ((uint32_t)len + 4u != total + 7u)
        return 0;
    const uint8_t *d = body + 3;
    size_t         left = len - 3u;
    size_t         n = 0;
    while (total > 0u) {
        if (left < 4u)
            return 0;
        uint32_t one = (uint32_t)d[0] << 16 | (uint32_t)d[1] << 8 | d[2];
        if (left < 3u + (size_t)one)
            return 0;
        d += 3u + one;
        left -= 3u + one;
        total -= 3u + one;
        n++;
    }
    *count = n;
    return 1;
}

/* The certificates of a TLS 1.2 Certificate in the TLS 1.3 message form — an empty request context,
 * and an empty extension block behind each entry — which is what the checks this client already
 * makes of a chain read (lc_utls_cert_msg_alert, lc_chain_verify). */
static int cert12_as13(lc_client_hs *hs, const uint8_t *body, size_t len, size_t count)
{
    size_t need = 1u + 3u + (len - 3u) + 2u * count;
    free(hs->chain13);
    hs->chain13 = malloc(need);
    if (hs->chain13 == NULL)
        return -1;
    uint8_t *o = hs->chain13;
    size_t   list = need - 4u;
    o[0] = 0u;
    o[1] = (uint8_t)(list >> 16);
    o[2] = (uint8_t)(list >> 8);
    o[3] = (uint8_t)list;
    size_t at = 4u, off = 3u;
    for (size_t i = 0; i < count; i++) {
        size_t one = (size_t)body[off] << 16 | (size_t)body[off + 1u] << 8 | body[off + 2u];
        memcpy(o + at, body + off, 3u + one);
        at += 3u + one;
        o[at++] = 0u;
        o[at++] = 0u;
        off += 3u + one;
    }
    hs->chain13_len = at;
    return 0;
}

/* certificateRequestMsg.unmarshal with hasSignatureAlgorithm, for TLS 1.2
 * (vendor/utls/handshake_messages.go:1834-1905). */
static int cert_req12_parses(const uint8_t *b, size_t len)
{
    if (len < 1u)
        return 0;
    size_t types = b[0];
    const uint8_t *d = b + 1;
    size_t         left = len - 1u;
    if (types == 0u || left <= types)
        return 0;
    d += types;
    left -= types;
    if (left < 2u)
        return 0;
    size_t sigs = (size_t)d[0] << 8 | d[1];
    d += 2;
    left -= 2u;
    if ((sigs & 1u) != 0u || left < sigs)
        return 0;
    d += sigs;
    left -= sigs;
    if (left < 2u)
        return 0;
    size_t cas = (size_t)d[0] << 8 | d[1];
    d += 2;
    left -= 2u;
    if (left < cas)
        return 0;
    const uint8_t *c = d;
    size_t         c_left = cas;
    while (c_left > 0u) {
        if (c_left < 2u)
            return 0;
        size_t one = (size_t)c[0] << 8 | c[1];
        c += 2;
        c_left -= 2u;
        if (c_left < one)
            return 0;
        c += one;
        c_left -= one;
    }
    return left == cas;
}

/* newSessionTicketMsg.unmarshal for TLS 1.2: a lifetime hint and a two-byte-prefixed ticket that is
 * the rest (vendor/utls/handshake_messages.go:1963-1981). */
static int nst12_parses(const uint8_t *b, size_t len)
{
    if (len < 6u)
        return 0;
    return ((size_t)b[4] << 8 | b[5]) == len - 6u;
}

/* certificateStatusMsg.unmarshal: OCSP, and a response that is not empty and is all there is
 * (vendor/utls/handshake_messages.go:1700-1711). */
static int status12_parses(const uint8_t *b, size_t len)
{
    if (len < 4u || b[0] != 1u)
        return 0;
    size_t n = (size_t)b[1] << 16 | (size_t)b[2] << 8 | b[3];
    return n != 0u && n == len - 4u;
}

/* Whether a message of |type| in |body| unmarshals, for the types this handshake reads; any other
 * type the reference knows is refused as the wrong message either way, with the same alert. */
static int msg12_parses(uint8_t type, const uint8_t *body, size_t len)
{
    size_t count;
    switch (type) {
    case LC_HS_CERTIFICATE:         return cert12_parses(body, len, &count);
    case LC_HS_CERTIFICATE_STATUS:  return status12_parses(body, len);
    case LC_HS_CERTIFICATE_REQUEST: return cert_req12_parses(body, len);
    case LC_HS_SERVER_HELLO_DONE:   return len == 0u;
    case LC_HS_NEW_SESSION_TICKET:  return nst12_parses(body, len);
    default:                        return 1;
    }
}

/* processServerHello and the start of handshake(), up to the first message after the ServerHello
 * (vendor/utls/handshake_client.go:567-604, :912-997). */
static void tls12_begin(lc_client_hs *hs, const lc_server_hello *sh, const lc_sh_expect *ex,
                        const uint8_t *whole, size_t whole_len)
{
    hs->tls12 = 1;

    /* pickCipherSuite: offered AND in uTLS's table, or handshake_failure (:665-684). */
    int offered = 0;
    for (size_t i = 0; i + 1u < ex->suites_len; i += 2u)
        if (((uint16_t)((uint16_t)ex->suites[i] << 8 | ex->suites[i + 1u])) == sh->cipher_suite)
            offered = 1;
    if (!offered || !lc_tls12_suite_known_to_go(sh->cipher_suite)) {
        hs_alert(hs, LC_ALERT_HANDSHAKE_FAILURE);
        hs_fail(hs, "the server chose TLS 1.2 suite 0x%04x, which the hello did not offer",
                sh->cipher_suite);
        return;
    }
    hs->s12 = lc_tls12_suite_by_id(sh->cipher_suite);
    if (hs->s12 == NULL) {
        /* 3DES or RC4, which no shipped hello offers — see tls/suite.h. */
        hs_alert(hs, LC_ALERT_INTERNAL_ERROR);
        hs_fail(hs, "the server chose TLS 1.2 suite 0x%04x, which this build does not run",
                sh->cipher_suite);
        return;
    }
    /* The compression method (:911-914). */
    if (sh->compression != 0u) {
        hs_alert(hs, LC_ALERT_UNEXPECTED_MESSAGE);
        hs_fail(hs, "the server selected a compression method");
        return;
    }
    /* A first handshake's renegotiation_info must be empty (:916-922). */
    if (sh->reneg && sh->reneg_len != 0u) {
        hs_alert(hs, LC_ALERT_HANDSHAKE_FAILURE);
        hs_fail(hs, "the initial handshake had a non-empty renegotiation extension");
        return;
    }
    /* checkALPN off QUIC: no selection is fine; a selection when we offered none, or one we did not
     * offer, is unsupported_extension (:934-937, :980-997). */
    if (sh->alpn != NULL) {
        size_t         off_len = 0;
        const uint8_t *off = lc_ch_ext(hs->hello, hs->info.len, EXT_ALPN, &off_len);
        int            found = 0;
        if (off != NULL && off_len >= 2u) {
            for (size_t at = 2; at < off_len;) {
                size_t n = off[at++];
                if (n > off_len - at)
                    break;
                if (n == sh->alpn_len && memcmp(off + at, sh->alpn, n) == 0)
                    found = 1;
                at += n;
            }
        }
        if (!found) {
            hs_alert(hs, LC_ALERT_UNSUPPORTED_EXTENSION);
            hs_fail(hs, "the server selected an application protocol the hello did not offer");
            return;
        }
    }

    hs->ocsp12 = sh->ocsp;
    hs->ticket12 = sh->ticket;
    hs->ems12 = sh->ems;
    memcpy(hs->server_random12, sh->random, 32u);

    /* The finished hash, on the suite's PRF hash, with the hello and the ServerHello in it (:589-604). */
    hs->hash = hs->s12->prf;
    hs->hlen = lc_hash_len(hs->hash);
    if (lc_transcript_init(&hs->tr, hs->hash) != 0) {
        hs_own(hs);
        hs_fail(hs, "cannot start a transcript");
        return;
    }
    hs->tr_ready = 1;
    lc_transcript_add(&hs->tr, hs->hello, hs->info.len);
    lc_transcript_add(&hs->tr, whole, whole_len);

    hs->st12 = ST12_CERT;
    hs_stage(hs, "reading the TLS 1.2 server flight");
    hs_msg_drop(hs, whole_len);
    hs->ph = PH_FLIGHT12;
}

/* verifyServerCertificate for the chain the Certificate carried (vendor/utls/handshake_client.go:
 * 1143-1268): every certificate parses and no RSA key is over 8192 bits, the leaf's key is one Go
 * has, and then REALITY's VerifyPeerCertificate — our HMAC, or a chain valid for the name asked for
 * (vendor/Xray-core/transport/internet/reality/reality.go:101-140). */
static int tls12_verify_certificate(lc_client_hs *hs, lc_client *cl)
{
    uint8_t a = lc_utls_cert_msg_alert(hs->chain13, hs->chain13_len);
    if (a != 0u) {
        hs_alert(hs, a);
        hs_fail(hs, "a certificate the server sent does not parse as X.509, or carries an RSA key over "
                    "8192 bits");
        return -1;
    }
    const uint8_t *leaf = NULL;
    size_t         leaf_len = 0;
    (void)lc_cert_first_from_message(hs->chain13, hs->chain13_len, &leaf, &leaf_len);
    free(hs->cert_der);
    hs->cert_der = malloc(leaf_len ? leaf_len : 1u);
    if (hs->cert_der == NULL) {
        hs->cert_der_len = 0;
        hs_own(hs);
        hs_fail(hs, "no memory for the server's certificate");
        return -1;
    }
    memcpy(hs->cert_der, leaf, leaf_len);
    hs->cert_der_len = leaf_len;

    int leaf_kind = lc_cert_key_supported(leaf, leaf_len);
    if (leaf_kind == 2) {
        /* vendor/utls/handshake_client.go:1241-1245 refuses ML-DSA before
         * VerifyPeerCertificate when the negotiated version is below TLS 1.3. */
        hs_alert(hs, LC_ALERT_ILLEGAL_PARAMETER);
        hs_fail(hs, "the server's certificate uses ML-DSA, which requires TLS 1.3");
        return -1;
    }
    if (leaf_kind == 0) {
        hs_alert(hs, LC_ALERT_UNSUPPORTED_CERTIFICATE);
        hs_fail(hs, "the server's certificate carries a public key that is not RSA, ECDSA or Ed25519");
        return -1;
    }
    if (hs->cfg.use_reality) {
        lc_cert crt;
        if (lc_cert_parse(leaf, leaf_len, &crt) == 0 &&
            lc_reality_verify_cert(cl->reality_auth_key, crt.public_key, crt.public_key_len,
                                   crt.signature, crt.signature_len) == 0) {
            cl->reality_verified = 1;
        } else {
            snprintf(cl->reality_note, sizeof cl->reality_note,
                     "the server answered with TLS 1.2, which REALITY is not");
            char why[192];
            if (lc_chain_verify(hs->chain13, hs->chain13_len, hs->cfg.sni, why, sizeof why) != 0) {
                hs_alert(hs, LC_ALERT_BAD_CERTIFICATE);
                hs_fail(hs, "the node did not authenticate and its certificate is not valid for %s "
                            "either: %s",
                        hs->cfg.sni ? hs->cfg.sni : "the name asked for", why);
                return -1;
            }
        }
    }
    return 0;
}

/* ecdheKeyAgreement.processServerKeyExchange (vendor/utls/key_agreement.go:271-373): the curve, our
 * key on it, the shared secret, our ClientKeyExchange, and the signature. Every way it fails is
 * illegal_parameter at doFullHandshake (vendor/utls/handshake_client.go:735-741). */
static int tls12_server_key_exchange(lc_client_hs *hs, const uint8_t *k, size_t len)
{
    if (hs->s12->kx == LC_KX_RSA)
        return -1; /* rsaKeyAgreement: "tls: unexpected ServerKeyExchange" (:77-79) */
    if (len < 4u || k[0] != 3u)
        return -1;
    uint16_t curve = (uint16_t)((uint16_t)k[1] << 8 | k[2]);
    size_t   pub_len = k[3];
    if (pub_len + 4u > len)
        return -1;
    const uint8_t *pub = k + 4;
    const uint8_t *sig = k + 4u + pub_len;
    size_t         sig_len = len - 4u - pub_len;
    if (sig_len < 2u)
        return -1;

    uint8_t priv[LC_P521_KEY], mine[LC_P521_POINT];
    size_t  mine_len = 0;
    int     rc = -1;
    switch (curve) {
    case LC_GROUP_X25519:
        if (pub_len == LC_X25519_KEY && lc_x25519_keygen(priv, mine) == 0 &&
            lc_x25519(priv, pub, hs->pms12) == 0) {
            hs->pms12_len = LC_X25519_SHARED;
            mine_len = LC_X25519_KEY;
            rc = 0;
        }
        break;
    case LC_GROUP_SECP256R1:
        if (pub_len == LC_P256_POINT && lc_p256_keygen(priv, mine) == 0 &&
            lc_p256_shared(priv, pub, hs->pms12) == 0) {
            hs->pms12_len = LC_P256_SHARED;
            mine_len = LC_P256_POINT;
            rc = 0;
        }
        break;
    case LC_GROUP_SECP384R1:
        if (pub_len == LC_P384_POINT && lc_p384_keygen(priv, mine) == 0 &&
            lc_p384_shared(priv, pub, hs->pms12) == 0) {
            hs->pms12_len = LC_P384_SHARED;
            mine_len = LC_P384_POINT;
            rc = 0;
        }
        break;
    case LC_GROUP_SECP521R1:
        if (pub_len == LC_P521_POINT && lc_p521_keygen(priv, mine) == 0 &&
            lc_p521_shared(priv, pub, hs->pms12) == 0) {
            hs->pms12_len = LC_P521_SHARED;
            mine_len = LC_P521_POINT;
            rc = 0;
        }
        break;
    default:
        break; /* "tls: server selected unsupported curve" */
    }
    lc_wipe(priv, sizeof priv);
    if (rc != 0)
        return -1;
    hs->ckx12[0] = (uint8_t)mine_len;
    memcpy(hs->ckx12 + 1, mine, mine_len);
    hs->ckx12_len = 1u + mine_len;

    size_t         sa_len = 0;
    const uint8_t *sa = lc_ch_ext(hs->hello, hs->info.len, 0x000du, &sa_len);
    return lc_skx12_verify(hs->cert_der, hs->cert_der_len, sa, sa_len, hs->s12->kx == LC_KX_ECDHE_RSA,
                           hs->hello + 6, hs->server_random12, k, 4u + pub_len, sig, sig_len);
}

/* rsaKeyAgreement.generateClientKeyExchange: the hello's version and forty-six random bytes, encrypted
 * PKCS #1 v1.5 to the certificate's RSA key (vendor/utls/key_agreement.go:82-105). A failure is
 * internal_error (vendor/utls/handshake_client.go:792-796). */
static int rnd_cb12(void *unused, unsigned char *out, size_t len)
{
    (void)unused;
    return lc_rnd(out, len) == 0 ? 0 : -1;
}

static int tls12_rsa_client_key_exchange(lc_client_hs *hs)
{
    hs->pms12[0] = hs->hello[4];
    hs->pms12[1] = hs->hello[5];
    if (lc_rnd(hs->pms12 + 2, 46u) != 0)
        return -1;
    hs->pms12_len = 48u;

    const uint8_t *spki = NULL;
    size_t         spki_len = 0;
    if (lc_cert_spki(hs->cert_der, hs->cert_der_len, &spki, &spki_len) != 0)
        return -1;
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    unsigned char *p = (unsigned char *)(uintptr_t)spki;
    int            rc = mbedtls_pk_parse_subpubkey(&p, spki + spki_len, &pk);
    size_t         n = 0;
    if (rc == 0 && (mbedtls_pk_get_type(&pk) != MBEDTLS_PK_RSA || mbedtls_pk_get_bitlen(&pk) < 1024u))
        rc = -1; /* "incorrect key type for selected ciphersuite"; and rsa1024min */
    if (rc == 0)
        rc = mbedtls_pk_encrypt(&pk, hs->pms12, 48u, hs->ckx12 + 2, &n, sizeof hs->ckx12 - 2u, rnd_cb12,
                                NULL);
    mbedtls_pk_free(&pk);
    if (rc != 0)
        return -1;
    hs->ckx12[0] = (uint8_t)(n >> 8);
    hs->ckx12[1] = (uint8_t)n;
    hs->ckx12_len = 2u + n;
    return 0;
}

/* One handshake message of ours into `tx`, in a record of its own, and into the transcript —
 * writeHandshakeRecord (vendor/utls/conn.go:1056-1069). |sealed| once the ChangeCipherSpec is out. */
static int tls12_write_msg(lc_client_hs *hs, uint8_t type, const uint8_t *body, size_t len, int sealed)
{
    uint8_t msg[4u + 2u + 1024u + 16u];
    if (len > sizeof msg - 4u)
        return -1;
    msg[0] = type;
    msg[1] = (uint8_t)(len >> 16);
    msg[2] = (uint8_t)(len >> 8);
    msg[3] = (uint8_t)len;
    memcpy(msg + 4, body, len);
    lc_transcript_add(&hs->tr, msg, 4u + len);
    size_t room = sizeof hs->tx - hs->tx_len;
    if (sealed) {
        size_t n = 0;
        if (lc_record_protect(&hs->c_keys, LC_REC_HANDSHAKE, msg, 4u + len, 0, hs->tx + hs->tx_len,
                              room, &n) != 0)
            return -1;
        hs->tx_len += n;
        return 0;
    }
    if (room < LC_REC_HEADER + 4u + len)
        return -1;
    uint8_t *r = hs->tx + hs->tx_len;
    r[0] = LC_REC_HANDSHAKE;
    r[1] = 0x03u;
    r[2] = 0x03u;
    r[3] = (uint8_t)((4u + len) >> 8);
    r[4] = (uint8_t)(4u + len);
    memcpy(r + LC_REC_HEADER, msg, 4u + len);
    hs->tx_len += LC_REC_HEADER + 4u + len;
    return 0;
}

/* The client's half after the ServerHelloDone: doFullHandshake from :788 to its end, establishKeys and
 * sendFinished, flushed together (vendor/utls/handshake_client.go:781-881, :883-903, :1104-1118). */
static void tls12_client_flight(lc_client_hs *hs)
{
    /* An empty Certificate, if one was asked for: nothing is configured to send. */
    if (hs->cert_req12) {
        static const uint8_t empty[3] = { 0, 0, 0 };
        if (tls12_write_msg(hs, LC_HS_CERTIFICATE, empty, sizeof empty, 0) != 0) {
            hs_own(hs);
            hs_fail(hs, "cannot write the empty Certificate");
            return;
        }
    }
    if (hs->s12->kx == LC_KX_RSA) {
        if (tls12_rsa_client_key_exchange(hs) != 0) {
            hs_alert(hs, LC_ALERT_INTERNAL_ERROR);
            hs_fail(hs, "cannot encrypt the premaster secret to the server's key");
            return;
        }
    } else if (hs->ckx12_len == 0u) {
        /* "tls: missing ServerKeyExchange message" (vendor/utls/key_agreement.go:375-378). */
        hs_alert(hs, LC_ALERT_INTERNAL_ERROR);
        hs_fail(hs, "the server sent no ServerKeyExchange for an ECDHE suite");
        return;
    }
    if (tls12_write_msg(hs, LC_HS_CLIENT_KEY_EXCHANGE, hs->ckx12, hs->ckx12_len, 0) != 0) {
        hs_own(hs);
        hs_fail(hs, "cannot write the ClientKeyExchange");
        return;
    }

    /* The master secret: extended over the transcript so far when the server agreed to it (:810-817). */
    int ok;
    if (hs->ems12) {
        uint8_t th[LC_HASH_MAX];
        ok = lc_transcript_snapshot(&hs->tr, th) == 0 &&
             lc_tls12_master_ems(hs->hash, hs->pms12, hs->pms12_len, th, hs->master12) == 0;
    } else {
        ok = lc_tls12_master(hs->hash, hs->pms12, hs->pms12_len, hs->hello + 6, hs->server_random12,
                             hs->master12) == 0;
    }
    lc_wipe(hs->pms12, sizeof hs->pms12);

    /* establishKeys: the key block, in keysFromMasterSecret's order (vendor/utls/prf.go:135-154). */
    uint8_t        block[2u * 32u + 2u * 32u + 2u * 16u];
    const lc_tls12_suite *s = hs->s12;
    size_t         blen = 2u * s->mac_len + 2u * s->key_len + 2u * s->iv_len;
    ok = ok && lc_tls12_key_block(hs->hash, hs->master12, hs->hello + 6, hs->server_random12, block,
                                  blen) == 0;
    const uint8_t *c_mac = block, *s_mac = block + s->mac_len;
    const uint8_t *c_key = block + 2u * s->mac_len, *s_key = c_key + s->key_len;
    const uint8_t *c_iv = s_key + s->key_len, *s_iv = c_iv + s->iv_len;
    ok = ok && lc_record_key_init12(&hs->c_keys, s, c_key, c_iv, c_mac, 0) == 0;
    if (ok && lc_record_key_init12(&hs->rd12, s, s_key, s_iv, s_mac, 1) != 0) {
        lc_record_key_free(&hs->c_keys);
        ok = 0;
    }
    lc_wipe(block, sizeof block);
    if (!ok) {
        hs_own(hs);
        hs_fail(hs, "cannot derive the TLS 1.2 keys");
        return;
    }
    hs->rd12_ready = 1;

    /* writeChangeCipherRecord, and from here our records are sealed — an alert included, which is why
     * c_keys is where lc_client_hs_alert_record looks. */
    if (sizeof hs->tx - hs->tx_len < LC_CCS_RECORD) {
        hs_own(hs);
        hs_fail(hs, "no room for the ChangeCipherSpec");
        return;
    }
    static const uint8_t ccs[LC_CCS_RECORD] = { LC_REC_CHANGE_CIPHER_SPEC, 0x03u, 0x03u, 0x00u, 0x01u,
                                                0x01u };
    memcpy(hs->tx + hs->tx_len, ccs, sizeof ccs);
    hs->tx_len += sizeof ccs;
    hs->hs_keys_ready = 1;

    uint8_t th[LC_HASH_MAX], verify[LC_TLS12_VERIFY_LEN];
    if (lc_transcript_snapshot(&hs->tr, th) != 0 ||
        lc_tls12_finished(hs->hash, hs->master12, 0, th, verify) != 0 ||
        tls12_write_msg(hs, LC_HS_FINISHED, verify, sizeof verify, 1) != 0) {
        hs_own(hs);
        hs_fail(hs, "cannot write our Finished");
        return;
    }
    hs->tx_off = 0;

    /* readSessionTicket first, when the ServerHello said one comes (:1034-1057). */
    hs->st12 = hs->ticket12 ? ST12_TICKET : ST12_CCS;
    hs_stage(hs, "reading the server's Finished");
}

/* One record of the TLS 1.2 flight: opened under the server's keys once its ChangeCipherSpec has
 * come, and then sorted as readRecordOrCCS sorts it. Returns 0 for handshake bytes appended, 1 for a
 * record that is done with — a ChangeCipherSpec taken, or one the reference ignores — and -1 when the
 * handshake is over. */
static int tls12_record(lc_client_hs *hs)
{
    const uint8_t *rec = hs->rx;
    size_t         rec_len = hs->rx_len;
    const uint8_t *data = rec + LC_REC_HEADER;
    size_t         n = rec_len - LC_REC_HEADER;

    if (hs->peer_ccs12) {
        if (hs_msg_reserve(hs, LC_REC_MAX_PLAINTEXT + 2048u) != 0) {
            hs_own(hs);
            hs_fail(hs, "no room to open a record");
            return -1;
        }
        uint8_t inner = 0;
        size_t  got = 0;
        int     rc = lc_record_unprotect(&hs->rd12, rec, rec_len, hs->plain + hs->plain_len,
                                         hs->plain_cap - hs->plain_len, &got, &inner);
        if (rc != 0) {
            hs_alert(hs, (uint8_t)(-rc));
            hs_fail(hs, "a record from the server does not open under its TLS 1.2 keys");
            return -1;
        }
        data = hs->plain + hs->plain_len;
        n = got;
    }
    int kind = hs_record_kind(hs, rec[0], data, n);
    if (kind != 0)
        return kind < 0 ? -1 : 1;
    if (hs->peer_ccs12)
        hs->plain_len += n;
    else if (hs_msg_add(hs, data, n) != 0) {
        hs_own(hs);
        hs_fail(hs, "the server's flight does not fit the reassembly window");
        return -1;
    }
    return 0;
}

static void phase_flight12(lc_client_hs *hs, lc_client *cl, int *done, int fresh)
{
    if (fresh) {
        int r = tls12_record(hs);
        if (r < 0)
            return;
        if (r == 1) {
            /* A ChangeCipherSpec in its place: changeCipherSpec, and the server's records are sealed
             * from the next one on, its sequence starting at zero (vendor/utls/conn.go:218-228,
             * :748-769). */
            if (hs->st12 == ST12_CCS && hs->ccs_taken12) {
                hs->ccs_taken12 = 0;
                hs->peer_ccs12 = 1;
                hs->st12 = ST12_FINISHED;
            }
            return;
        }
    }

    uint8_t        type = 0;
    const uint8_t *body = NULL, *whole = NULL;
    size_t         body_len = 0, whole_len = 0;
    int            mrc;
    while ((mrc = hs_msg_take(hs, &type, &body, &body_len, &whole, &whole_len)) == 1) {
        /* readHandshake: the message unmarshals, or unexpected_message (unmarshalHandshakeMessage,
         * vendor/utls/conn.go:1192-1194). */
        if (!msg12_parses(type, body, body_len)) {
            hs_alert(hs, LC_ALERT_UNEXPECTED_MESSAGE);
            hs_fail(hs, "the server's handshake message 0x%02x does not parse", (unsigned)type);
            return;
        }
        uint8_t st = hs->st12;

        if (st == ST12_CERT) {
            size_t count = 0;
            /* `if !ok || len(certMsg.certificates) == 0` (vendor/utls/handshake_client.go:681-685). */
            if (type != LC_HS_CERTIFICATE || !cert12_parses(body, body_len, &count) || count == 0u) {
                hs_alert_type(hs, type);
                hs_fail(hs, "the server's TLS 1.2 flight does not begin with a Certificate");
                return;
            }
            if (cert12_as13(hs, body, body_len, count) != 0) {
                hs_own(hs);
                hs_fail(hs, "no memory for the server's chain");
                return;
            }
            hs->st12 = ST12_STATUS;
        } else if (st == ST12_STATUS && type == LC_HS_CERTIFICATE_STATUS) {
            /* Only if the ServerHello acknowledged status_request (:704-724). */
            if (!hs->ocsp12) {
                hs_alert(hs, LC_ALERT_UNEXPECTED_MESSAGE);
                hs_fail(hs, "tls: received unexpected CertificateStatus message");
                return;
            }
            hs->st12 = ST12_KX;
        } else if (st == ST12_TICKET) {
            if (type != LC_HS_NEW_SESSION_TICKET) {
                hs_alert_type(hs, type);
                hs_fail(hs, "the server promised a session ticket and sent message 0x%02x",
                        (unsigned)type);
                return;
            }
            /* hs.ticket = ..., and nothing is saved: the reference has no cache (:1055, :1076-1078). */
            hs->st12 = ST12_CCS;
        } else if (st == ST12_CCS) {
            /* readChangeCipherSpec: a handshake record here is unexpected (readRecordOrCCS,
             * vendor/utls/conn.go:785-788);
             * the record path refuses it before it reaches this — see hs_record_kind. */
            hs_alert(hs, LC_ALERT_UNEXPECTED_MESSAGE);
            hs_fail(hs, "a handshake message where the ChangeCipherSpec was due");
            return;
        } else if (st == ST12_FINISHED) {
            if (type != LC_HS_FINISHED) {
                hs_alert_type(hs, type);
                hs_fail(hs, "the server sent message 0x%02x where its Finished was due", (unsigned)type);
                return;
            }
            /* serverSum over the transcript before this message, constant time
             * (vendor/utls/handshake_client.go:1040-1045). */
            uint8_t th[LC_HASH_MAX], verify[LC_TLS12_VERIFY_LEN];
            uint8_t diff = (uint8_t)(body_len == sizeof verify ? 0u : 1u);
            if (lc_transcript_snapshot(&hs->tr, th) != 0 ||
                lc_tls12_finished(hs->hash, hs->master12, 1, th, verify) != 0) {
                hs_own(hs);
                hs_fail(hs, "cannot compute the server's Finished");
                return;
            }
            for (size_t i = 0; i < sizeof verify && i < body_len; i++)
                diff |= (uint8_t)(verify[i] ^ body[i]);
            if (diff != 0u) {
                hs_alert(hs, LC_ALERT_HANDSHAKE_FAILURE);
                hs_fail(hs, "tls: server's Finished message was incorrect");
                return;
            }
            lc_transcript_add(&hs->tr, whole, whole_len);
            hs_msg_drop(hs, whole_len);
            *done = 1;
            return;
        } else {
            /* After the Certificate and any CertificateStatus: the certificate is verified once,
             * AFTER the next message has been read — which is the reference's order: readHandshake
             * first, verifyServerCertificate second (vendor/utls/handshake_client.go:687-719). */
            if (!hs->cert_checked12) {
                if (tls12_verify_certificate(hs, cl) != 0)
                    return;
                hs->cert_checked12 = 1;
            }
            if (type == LC_HS_SERVER_KEY_EXCHANGE && (st == ST12_STATUS || st == ST12_KX)) {
                if (tls12_server_key_exchange(hs, body, body_len) != 0) {
                    hs_alert(hs, LC_ALERT_ILLEGAL_PARAMETER);
                    hs_fail(hs, "the server's key exchange parameters do not verify");
                    return;
                }
                hs->st12 = ST12_REQ;
            } else if (type == LC_HS_CERTIFICATE_REQUEST && st != ST12_DONE) {
                hs->cert_req12 = 1;
                hs->st12 = ST12_DONE;
            } else if (type == LC_HS_SERVER_HELLO_DONE) {
                lc_transcript_add(&hs->tr, whole, whole_len);
                hs_msg_drop(hs, whole_len);
                tls12_client_flight(hs);
                return;
            } else {
                hs_alert_type(hs, type);
                hs_fail(hs, "the server sent message 0x%02x out of the TLS 1.2 flight's order",
                        (unsigned)type);
                return;
            }
        }
        lc_transcript_add(&hs->tr, whole, whole_len);
        hs_msg_drop(hs, whole_len);
    }
    if (mrc < 0) {
        hs_alert(hs, LC_ALERT_INTERNAL_ERROR);
        hs_fail(hs, "a handshake message of type 0x%02x larger than the reference reads",
                (unsigned)hs->plain[0]);
    }
}

/* The handshake is done: the keys the Finished messages were sealed under are the connection's, their
 * sequences where the Finished left them. Moved rather than copied, so that the handshake's free
 * does not release what the connection now holds. */
static void tls12_finish(lc_client_hs *hs, lc_client *cl)
{
    cl->rd = hs->rd12;
    cl->wr = hs->c_keys;
    memset(&hs->rd12, 0, sizeof hs->rd12);
    memset(&hs->c_keys, 0, sizeof hs->c_keys);
    hs->rd12_ready = 0;
    hs->hs_keys_ready = 0;
    cl->hash = hs->hash;
    lc_wipe(hs->master12, sizeof hs->master12);
    hs_stage(hs, "TLS 1.2 established");
    hs->ph = PH_FINISHED;
}

/* ---- phase four: our Finished and the application keys ---------------------- */

static void phase_finish(lc_client_hs *hs, lc_client *cl)
{
    hs_stage(hs, "sending Finished");
    uint8_t th[LC_HASH_MAX];
    if (lc_transcript_snapshot(&hs->tr, th) != 0) {
        hs_own(hs);
        hs_fail(hs, "cannot take the transcript hash");
        return;
    }

    uint8_t master[LC_HASH_MAX], c_ap[LC_HASH_MAX], s_ap[LC_HASH_MAX];
    {
        uint8_t derived2[LC_HASH_MAX], zeros[LC_HASH_MAX];
        memset(zeros, 0, hs->hlen);
        int ok =
            lc_derive_secret(hs->hash, hs->hs_secret, "derived", hs->empty_hash, derived2) == 0 &&
            lc_hkdf_extract(hs->hash, derived2, hs->hlen, zeros, hs->hlen, master) == 0 &&
            lc_derive_secret(hs->hash, master, "c ap traffic", th, c_ap) == 0 &&
            lc_derive_secret(hs->hash, master, "s ap traffic", th, s_ap) == 0;
        lc_wipe(derived2, sizeof derived2);
        if (!ok) {
            /* The three below are wiped at the end of the path that succeeds; this is the other
             * exit, where a schedule that broke at its last step left the earlier ones populated. */
            lc_wipe(master, sizeof master);
            lc_wipe(c_ap, sizeof c_ap);
            lc_wipe(s_ap, sizeof s_ap);
            hs_own(hs);
            hs_fail(hs, "the application schedule failed");
            return;
        }
    }

    /* From here every exit goes through `out`, because the three secrets above and the key and iv
     * below are alive across it. Wiping only on the way out of the successful path — as this did —
     * leaves an entire application traffic key in a frame that the event loop hands straight to the
     * HTTP/2 and QPACK parsers, and those read bytes the peer chose. */
    {
        uint8_t vd[LC_HASH_MAX];
        uint8_t msg[4 + LC_HASH_MAX];
        uint8_t th_fin[LC_HASH_MAX];
        int     ok = 1;
        size_t  at = 0;

        /* THE DUMMY ChangeCipherSpec, WHICH EVERY REAL CLIENT SENDS AND THIS ONE DID NOT.
         *
         * TLS 1.3 has no use for the record — the "compatibility mode" of RFC 8446 appendix D.4
         * is the whole of its purpose — but a client that omits it is telling anyone counting
         * records that it is not the client it claims to be, and this whole tree exists to make
         * that count come out right. utls sends it from sendDummyChangeCipherSpec
         * (vendor/utls/handshake_client_tls13.go:92 and
         * vendor/utls/handshake_client_tls13.go:140), skipping it only when the transport is
         * QUIC — `if hs.c.quic != nil { return nil }` is the first thing in the function itself
         * (vendor/utls/handshake_client_tls13.go:239-241) — which is why the QUIC plane
         * in quic/qtls.c is right not to send one and is left alone.
         *
         * It goes out with the Finished rather than on its own because that is what the
         * reference produces: c.buffering is set before processServerHello and the flush comes
         * after the client's Finished, so both records leave in one write. The body is the
         * single byte 0x01 (vendor/utls/conn.go:1076, `writeRecordLocked(recordTypeChangeCipherSpec,
         * []byte{1})`) and it is plaintext — the record layer is not yet in force for it.
         *
         * ⚠️ ONCE PER CONNECTION, WHICH IS WHY THE RETRY PATH IS ASKED ABOUT HERE. The
         * reference sends this record from a function that returns immediately if it has
         * already run — `if hs.sentDummyCCS { return nil }`
         * (vendor/utls/handshake_client_tls13.go:242-244) — and on a HelloRetryRequest it has
         * already run, ahead of the second ClientHello. Sending it here as well would put TWO
         * 0x14 records on a retried handshake where the reference puts one, which is the same
         * kind of countable difference as omitting it altogether, only in the other direction.
         * hs->retried is this client's sentDummyCCS. */
        if (!hs->retried) {
            hs->tx[0] = LC_REC_CHANGE_CIPHER_SPEC;
            hs->tx[1] = 0x03;
            hs->tx[2] = 0x03;
            hs->tx[3] = 0x00;
            hs->tx[4] = 0x01;
            hs->tx[5] = 0x01;
            at = LC_CCS_RECORD;
            hs->ccs_owed = 0;
        }

        /* THE ANSWER TO A CertificateRequest, WHICH IS A MESSAGE AND NOT A SILENCE.
         *
         * A server may ask for a client certificate; this client has none to give, and the
         * reference's answer to that is not to stay quiet. getClientCertificate returns an empty
         * Certificate, sendClientCertificate writes it out, and only THEN does the empty chain
         * skip the CertificateVerify that would have followed
         * (vendor/utls/handshake_client_tls13.go:873-914). So the flight is Certificate then
         * Finished, and a client that sends Finished alone is one message short of every Go client
         * on the wire — against a server that asked, which is a server that is watching the answer.
         *
         * The bytes are the whole message: type 0x0b, length 4, an empty request context and an
         * empty list. Go marshals exactly that for an empty certificate — `b.AddUint8(0)` for the
         * context and a zero-length list from marshalCertificate
         * (vendor/utls/handshake_messages.go:1525-1542). The context is empty rather than echoed
         * because Go does not echo it either.
         *
         * It is hashed like any message we send, which is why the verify_data below is taken from a
         * snapshot made after it rather than from the one the application secrets used: those cover
         * the transcript through the SERVER's Finished, and this message comes after.
         *
         * AND BEFORE IT, THE ANSWER TO THE SERVER'S APPLICATION SETTINGS when there were any: uTLS
         * writes it from serverFinishedReceived, which runs before sendClientCertificate
         * (vendor/utls/handshake_client_tls13.go:156-161), as its own record and into the
         * transcript the same way (vendor/utls/u_handshake_client.go:152-164). */
        if (hs->alps_answer_len != 0u) {
            size_t n = 0;
            ok = lc_record_protect(&hs->c_keys, LC_REC_HANDSHAKE, hs->alps_answer,
                                   hs->alps_answer_len, 0, hs->tx + at, sizeof hs->tx - at,
                                   &n) == 0;
            if (ok) {
                at += n;
                lc_transcript_add(&hs->tr, hs->alps_answer, hs->alps_answer_len);
            }
        }
        if (ok && hs->cert_requested) {
            size_t n = 0;
            ok = lc_record_protect(&hs->c_keys, LC_REC_HANDSHAKE, lc_empty_certificate,
                                   sizeof lc_empty_certificate, 0,
                                   hs->tx + at, sizeof hs->tx - at, &n) == 0;
            if (ok) {
                at += n;
                lc_transcript_add(&hs->tr, lc_empty_certificate,
                                  sizeof lc_empty_certificate);
            }
        }

        if (ok)
            ok = lc_transcript_snapshot(&hs->tr, th_fin) == 0;
        if (ok)
            ok = lc_finished_verify_data(hs->hash, hs->c_hs, th_fin, vd) == 0;
        if (ok) {
            msg[0] = LC_HS_FINISHED;
            msg[1] = 0;
            msg[2] = 0;
            msg[3] = (uint8_t)hs->hlen;
            memcpy(msg + 4, vd, hs->hlen);

            size_t out_len = 0;
            ok = lc_record_protect(&hs->c_keys, LC_REC_HANDSHAKE, msg, 4u + hs->hlen, 0,
                                   hs->tx + at, sizeof hs->tx - at, &out_len) == 0;
            if (ok) {
                hs->tx_len = at + out_len;
                hs->tx_off = 0;
            }
        }
        lc_wipe(vd, sizeof vd);
        lc_wipe(msg, sizeof msg);
        lc_wipe(th_fin, sizeof th_fin);
        if (!ok) {
            hs_own(hs);
            hs_fail(hs, "cannot build and seal our Finished");
            goto out;
        }
    }

    {
        uint8_t key[32], iv[LC_AEAD_NONCE];
        int     ok =
            lc_hkdf_expand_label(hs->hash, s_ap, "key", NULL, 0, key, hs->key_len) == 0 &&
            lc_hkdf_expand_label(hs->hash, s_ap, "iv", NULL, 0, iv, sizeof iv) == 0 &&
            lc_record_key_init(&cl->rd, hs->alg, key, iv) == 0 &&
            lc_hkdf_expand_label(hs->hash, c_ap, "key", NULL, 0, key, hs->key_len) == 0 &&
            lc_hkdf_expand_label(hs->hash, c_ap, "iv", NULL, 0, iv, sizeof iv) == 0 &&
            lc_record_key_init(&cl->wr, hs->alg, key, iv) == 0;
        lc_wipe(key, sizeof key);
        lc_wipe(iv, sizeof iv);
        if (!ok) {
            /* cl->rd may already hold a live cipher context — the second half of the chain is what
             * failed. Released here, or it stays allocated for as long as the caller keeps the
             * lc_client, and lc-tunnel makes a fresh one per reconnect. */
            lc_client_free(cl);
            hs_own(hs);
            hs_fail(hs, "cannot build the application keys");
            goto out;
        }
        /* And what they were built from, for KeyUpdate — see lc_client. */
        memcpy(cl->s_ap, s_ap, hs->hlen);
        memcpy(cl->c_ap, c_ap, hs->hlen);
        cl->alg = hs->alg;
        cl->key_len = hs->key_len;
    }

out:
    lc_wipe(master, sizeof master);
    lc_wipe(c_ap, sizeof c_ap);
    lc_wipe(s_ap, sizeof s_ap);
    if (hs->ph == PH_FAILED)
        return;

    hs_stage(hs, "handshake complete");
    hs->ph = PH_FINISHED;
}

/* ---- alerts ------------------------------------------------------------------
 *
 * A TLS alert is two bytes — level and description — in a record of its own, and this client sent
 * none, ever. Not on a refusal, and not at the end of a connection that worked.
 *
 * The second half is the expensive one. Go's tls.Conn.Close sends close_notify whenever the
 * handshake has completed (vendor/utls/conn.go:1434-1467, the isHandshakeComplete test at :1457,
 * calling closeNotify at :1482-1493), and Xray closes the REALITY
 * connection through exactly that (`defer conn.Close()`,
 * vendor/Xray-core/proxy/vless/outbound/outbound.go:201). So every Xray-over-REALITY connection ends
 * with one final encrypted record — five bytes of header, two of alert, one of inner type, sixteen
 * of tag — immediately before the FIN. Ours ended with a bare FIN. "Is there a 24-byte record before
 * the FIN" is a one-line rule over any TLS flow, it needs no state and no decryption, and it held on
 * 100% of our proxied connections.
 *
 * The LEVEL is derived rather than passed: warning for close_notify, fatal for everything else,
 * which is what sendAlertLocked does (vendor/utls/conn.go:849-855). */

/* The two bytes of an alert, in ONE place. They were written out at both builders — the same
 * conditional, the same comment — and that is the shape this file complains about elsewhere: two
 * copies of one rule, which agree until somebody changes the copy the other does not include. The
 * rule is small enough to look harmless and load-bearing enough that disagreeing would send a peer
 * a fatal alert marked warning, or the reverse. */
static void alert_body(uint8_t desc, uint8_t body[2])
{
    /* Warning for close_notify and no_renegotiation, fatal for everything else
     * (vendor/utls/conn.go:849-855). */
    body[0] = (desc == LC_ALERT_CLOSE_NOTIFY || desc == LC_ALERT_NO_RENEGOTIATION) ? 1u : 2u;
    body[1] = desc;
}

size_t lc_client_alert_record(lc_client *cl, uint8_t desc, uint8_t *out, size_t cap)
{
    uint8_t body[2];
    alert_body(desc, body);

    size_t n = 0;
    if (lc_record_protect(&cl->wr, LC_REC_ALERT, body, sizeof body, 0, out, cap, &n) != 0)
        return 0;
    return n;
}

/* Puts the owed alert on the wire, if one is owed and there is a key to seal it with.
 *
 * Best effort by design: the peer has just been refused, so the write may well fail, and a failed
 * write here must not replace the reason the handshake ended. The reference takes the same view for
 * close_notify — it records the write error and returns the original one.
 *
 * Before handshake keys exist the record goes out in the clear, which is what the record layer does
 * at that point in the handshake; after they exist it is sealed with the client's handshake key,
 * because that is the write key in force until the application keys replace it. */
/* ⚠️ SPLIT FROM THE WRITER BECAUSE THE PRODUCT CANNOT USE THE WRITER, and for a while that meant
 * the product sent no alert at all.
 *
 * lc_client_hs_send_alert owns a descriptor and blocks on it until a deadline, which suits
 * lc-probe — it runs one handshake and has nothing else to do. lc-tunnel drives this machine from
 * an event loop and must not block on anything, so it never called it, so every alert this file
 * takes such care to choose was recorded into a struct and thrown away with it. The gate could not
 * see it: the suites end at "the right alert is pending", and the one program verified on hardware
 * was the one that flushes.
 *
 * So the RECORD is built here and the writing belongs to whoever owns the socket. lc-tunnel puts it
 * in the queue it already has and flushes that non-blocking, which also keeps the order right —
 * writing straight to the descriptor would put the alert AHEAD of a hello still waiting in the
 * queue on a slow socket.
 *
 * Once it commits to building, the debt is cleared whether or not the caller manages to write what
 * it gets back: one refusal is one alert, and a caller that retried would send two. A buffer too
 * small to hold one is the exception — nothing was built, so nothing is owed away. */
size_t lc_client_hs_alert_record(lc_client_hs *hs, uint8_t *out, size_t cap)
{
    /* ONE THRESHOLD, THE LARGER ONE, so that the promise above holds on both branches. This asked
     * for seven — the length of the unkeyed form — and a caller offering, say, twelve got past the
     * guard, lost its alert to a sealing failure, and had the debt cleared underneath it. The
     * sealed form needs LC_CLIENT_ALERT_MAX, and refusing below that is the only threshold that
     * makes "nothing built, nothing owed away" true whatever the handshake has reached. */
    if (!hs->alert_pending || cap < LC_CLIENT_ALERT_MAX)
        return 0;
    /* Nothing after a failure of our own, not even a ChangeCipherSpec buffered ahead of it: the
     * reference's process ended with it unsent. See hs_own. */
    if (hs->own) {
        hs->alert_pending = 0;
        hs->ccs_owed = 0;
        return 0;
    }
    /* One write's worth per call. Twice over and unbuffered, the first call hands out one copy and
     * leaves the other owed, so that a caller writing what each call returns makes two writes — see
     * `alert_split`. */
    int copies = hs->alert_twice ? 2 : 1;
    if (hs->alert_split) {
        hs->alert_split = 0;
        hs->alert_twice = 0;
        copies = 1;
    } else {
        hs->alert_pending = 0;
    }

    /* The ChangeCipherSpec the reference had buffered, flushed ahead of the alert — see
     * `ccs_owed`. Plaintext whatever the alert is, as the reference writes it. */
    size_t at = 0;
    if (hs->ccs_owed) {
        static const uint8_t ccs[LC_CCS_RECORD] = { LC_REC_CHANGE_CIPHER_SPEC, 0x03u, 0x03u,
                                                    0x00u, 0x01u, 0x01u };
        memcpy(out, ccs, sizeof ccs);
        at = sizeof ccs;
        hs->ccs_owed = 0;
    }

    uint8_t body[2];
    alert_body(hs->alert_desc, body);

    /* Once, or twice for a handshake type the reference does not know — see hs_alert_type. Each
     * sealed copy is its own record under its own sequence number, as two writes are. */
    for (int copy = 0; copy < copies; copy++) {
        size_t n = 0;
        if (hs->hs_keys_ready) {
            if (lc_record_protect(&hs->c_keys, LC_REC_ALERT, body, sizeof body, 0, out + at,
                                  cap - at, &n) != 0)
                return 0;
        } else {
            /* 0x0301 until a version is settled, 0x0303 after: writeRecordLocked writes `c.vers`,
             * VersionTLS10 while it is still zero and VersionTLS12 for 1.3
             * (vendor/utls/conn.go:1016-1025). `have_vers` is `c.vers != 0` here — see where
             * phase_server_hello sets it. ⚠️ UNTIL 2026-09-27 always 0x0303: an alert to a first
             * record that was not a ServerHello said "1.2" where uTLS says "1.0". */
            out[at + 0u] = LC_REC_ALERT;
            out[at + 1u] = 0x03u;
            out[at + 2u] = hs->have_vers ? 0x03u : 0x01u;
            out[at + 3u] = 0x00u;
            out[at + 4u] = 0x02u;
            out[at + 5u] = body[0];
            out[at + 6u] = body[1];
            n = 7u;
        }
        at += n;
    }
    return at;
}

void lc_client_hs_send_alert(lc_client_hs *hs, int fd, uint64_t deadline_ms)
{
    if (fd < 0)
        return;

    uint8_t rec[LC_REC_MAX_WIRE];
    size_t  n;
    /* Each call is one write's worth — see alert_split. */
    while ((n = lc_client_hs_alert_record(hs, rec, sizeof rec)) > 0)
        (void)lc_write_full(fd, rec, n, deadline_ms);
}

/* ---- the driver -------------------------------------------------------------- */

lc_client_progress lc_client_hs_step(lc_client_hs *hs, lc_client *cl)
{
    if (hs->ph == PH_HELLO) {
        memset(cl, 0, sizeof *cl);
        cl->hash = LC_SHA256;
        phase_hello(hs, cl);
    }

    /* Sending comes before anything else at every phase: the peer is waiting on it, and a machine
     * that asked for input while holding output it never handed over would deadlock. */
    for (;;) {
        if (hs->ph == PH_FAILED) {
            snprintf(cl->stage, sizeof cl->stage, "%s", hs->stage);
            return LC_HS_FAILED;
        }
        if (hs->tx_len > hs->tx_off) {
            snprintf(cl->stage, sizeof cl->stage, "%s", hs->stage);
            return LC_HS_WANT_WRITE;
        }
        if (hs->ph == PH_SERVER_HELLO && hs->rx_len == 0u)
            phase_server_hello_wait(hs);
        if (hs->ph == PH_FINISHED) {
            hs->ph = PH_DONE;
            continue;
        }
        if (hs->ph == PH_DONE) {
            snprintf(cl->stage, sizeof cl->stage, "%s", hs->stage);
            return LC_HS_OK;
        }
        int fresh = record_ready(hs);
        if (!fresh && !((hs->ph == PH_SERVER_HELLO || hs->ph == PH_FLIGHT || hs->ph == PH_FLIGHT12) &&
                        msg_waiting(hs))) {
            snprintf(cl->stage, sizeof cl->stage, "%s", hs->stage);
            return LC_HS_WANT_READ;
        }

        switch (hs->ph) {
        case PH_SERVER_HELLO:
            phase_server_hello(hs, cl, fresh);
            if (fresh)
                record_drop(hs);
            break;
        case PH_FLIGHT: {
            int done = 0;
            phase_flight(hs, cl, &done, fresh);
            if (fresh)
                record_drop(hs);
            if (done && hs->ph != PH_FAILED)
                phase_finish(hs, cl);
            break;
        }
        case PH_FLIGHT12: {
            int done = 0;
            phase_flight12(hs, cl, &done, fresh);
            if (fresh)
                record_drop(hs);
            if (done && hs->ph != PH_FAILED)
                tls12_finish(hs, cl);
            break;
        }
        default:
            hs_own(hs);
            hs_fail(hs, "the handshake reached an impossible state");
            break;
        }
    }
}

/* ---- the blocking wrapper ---------------------------------------------------- */

int lc_client_hs_run(lc_client_hs *hs, lc_client *cl, int fd, uint64_t deadline_ms,
                     char *err, size_t err_cap)
{
    int rc = -1;
    for (;;) {
        lc_client_progress p = lc_client_hs_step(hs, cl);
        if (p == LC_HS_OK) {
            rc = 0;
            break;
        }
        if (p == LC_HS_FAILED) {
            lc_client_hs_send_alert(hs, fd, deadline_ms);
            say(err, err_cap, "%s", lc_client_hs_error(hs));
            break;
        }
        if (p == LC_HS_WANT_WRITE) {
            size_t         n = 0;
            const uint8_t *out = lc_client_hs_out(hs, &n);
            if (lc_write_full(fd, out, n, deadline_ms) != 0) {
                say(err, err_cap, "cannot send during %s", hs->stage);
                break;
            }
            lc_client_hs_out_taken(hs, n);
            continue;
        }

        /* Exactly the bytes the machine is missing, which keeps the clean-close case distinct: a
         * server that decides we are a stranger closes mid-flight, and reading more than is due
         * would report that as a truncation instead.
         *
         * Taken a few kilobytes at a time rather than a whole record in one frame. Nothing in this
         * loop needs the record whole — the state machine is fed incrementally by design and asks
         * for what it still wants — while a record-sized local was the largest stack frame in the
         * tree, in a function that goes on to call mbedTLS point multiplication deeper down the same
         * stack. On the main thread that is comfortable; conn.c already records what the same shape
         * costs the day it meets musl's 128 KB thread stack. */
        size_t want = lc_client_hs_want(hs);
        int    failed = 0;
        while (want > 0u) {
            uint8_t buf[4096];
            size_t  chunk = want < sizeof buf ? want : sizeof buf;
            int     r = lc_read_full(fd, buf, chunk, deadline_ms);
            if (r != 0) {
                say(err, err_cap, r > 0 ? "server closed the connection during %s"
                                        : "nothing arrived during %s", hs->stage);
                failed = 1;
                break;
            }
            if (lc_client_hs_feed(hs, buf, chunk) != chunk) {
                say(err, err_cap, "the handshake refused bytes it asked for");
                failed = 1;
                break;
            }
            want -= chunk;
        }
        if (failed)
            break;
    }

    return rc;
}

int lc_client_handshake(lc_client *cl, int fd, const lc_client_config *cfg,
                        uint64_t deadline_ms, char *err, size_t err_cap)
{
    lc_client_hs *hs = lc_client_hs_new(cfg);
    if (hs == NULL) {
        say(err, err_cap, "out of memory for the handshake");
        return -1;
    }
    int rc = lc_client_hs_run(hs, cl, fd, deadline_ms, err, err_cap);
    lc_client_hs_free(hs);
    return rc;
}

/* ---- KeyUpdate ---------------------------------------------------------------- */

/* One generation on: `secret` becomes HKDF-Expand-Label(secret, "traffic upd", "", Hash.length),
 * and `k` its key and iv with the sequence number at zero. */
static int next_generation(lc_client *cl, uint8_t *secret, lc_record_key *k)
{
    size_t  hlen = lc_hash_len(cl->hash);
    uint8_t next[LC_HASH_MAX], key[32], iv[LC_AEAD_NONCE];
    int     ok = lc_hkdf_expand_label(cl->hash, secret, "traffic upd", NULL, 0, next, hlen) == 0 &&
             lc_hkdf_expand_label(cl->hash, next, "key", NULL, 0, key, cl->key_len) == 0 &&
             lc_hkdf_expand_label(cl->hash, next, "iv", NULL, 0, iv, sizeof iv) == 0;
    if (ok) {
        lc_record_key_free(k);
        ok = lc_record_key_init(k, cl->alg, key, iv) == 0;
        memcpy(secret, next, hlen);
    }
    lc_wipe(next, sizeof next);
    lc_wipe(key, sizeof key);
    lc_wipe(iv, sizeof iv);
    return ok ? 0 : -1;
}

int lc_client_update_read(lc_client *cl)
{
    return next_generation(cl, cl->s_ap, &cl->rd);
}

int lc_client_update_write(lc_client *cl)
{
    return next_generation(cl, cl->c_ap, &cl->wr);
}

size_t lc_client_key_update_record(lc_client *cl, uint8_t *out, size_t cap)
{
    /* `keyUpdateMsg{}` — update_requested false (vendor/utls/conn.go:1360-1365). */
    static const uint8_t msg[5] = { LC_HS_KEY_UPDATE, 0, 0, 1, 0 };
    size_t               n = 0;
    if (cap < LC_CLIENT_KEY_UPDATE_MAX ||
        lc_record_protect(&cl->wr, LC_REC_HANDSHAKE, msg, sizeof msg, 0, out, cap, &n) != 0)
        return 0;
    return n;
}

void lc_client_free(lc_client *cl)
{
    lc_record_key_free(&cl->rd);
    lc_record_key_free(&cl->wr);
    lc_wipe(cl->reality_auth_key, sizeof cl->reality_auth_key);
    lc_wipe(cl->s_ap, sizeof cl->s_ap);
    lc_wipe(cl->c_ap, sizeof cl->c_ap);
}

const uint8_t *lc_client_hs_leftover(const lc_client_hs *hs, size_t *len)
{
    *len = hs->plain_len;
    return hs->plain;
}
