/* What this client PUTS ON THE WIRE when it refuses, which for most of its life was nothing.
 *
 * A failed handshake is two separate things, and only one of them was ever tested: the sentence in
 * our own log, and the alert the peer reads. Twenty-six of the refusals in client.c wrote the first
 * and skipped the second, so the socket simply died — and a bare FIN where every Go client sends
 * seven bytes is exactly the kind of difference this whole client exists to not have. The suites
 * that cover the handshake all check the sentence, because the sentence is what a test naturally
 * reaches for; none of them looked at the wire, which is why the gap survived every green run.
 *
 * ⚠️ HALF OF THIS FILE ASSERTS THAT NOTHING IS SENT, and those cases are not filler. Three refusals
 * are silent ON PURPOSE and each one matches the reference — a received alert is not answered, a
 * first record that is not a handshake record gets a header error rather than an alert
 * (vendor/utls/conn.go:666-673), and a hello that will not build has nobody to tell. Without a test
 * pinning them, the next reader sees the asymmetry, "fixes" it, and creates the very distinguisher
 * the other half of this file removes. Symmetry is the bug here, not the goal.
 *
 * White box, like test/hsframe: alert_pending and alert_desc are internal to client.c and there is
 * no public way to ask "what would this client have sent". The alternative — a live peer that
 * misbehaves in six different ways on demand — proves less and cannot run in the gate. */

#include "tls/client.c"
#include "certverify_vectors.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

/* A Certificate message body with one or two entries and no extensions: an empty context, the
 * list's three bytes of length, and each entry as three bytes of length, the certificate and two
 * bytes of empty extensions. A second entry of NULL is left out. */
static size_t cert_msg(uint8_t *out, const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len)
{
    size_t at = 4u;
    const uint8_t *certs[2] = { a, b };
    size_t         lens[2] = { a_len, b_len };
    for (unsigned i = 0; i < 2u; i++) {
        if (certs[i] == NULL)
            continue;
        out[at++] = (uint8_t)(lens[i] >> 16);
        out[at++] = (uint8_t)(lens[i] >> 8);
        out[at++] = (uint8_t)lens[i];
        memcpy(out + at, certs[i], lens[i]);
        at += lens[i];
        out[at++] = 0x00u;
        out[at++] = 0x00u;
    }
    size_t list = at - 4u;
    out[0] = 0x00u;
    out[1] = (uint8_t)(list >> 16);
    out[2] = (uint8_t)(list >> 8);
    out[3] = (uint8_t)list;
    return at;
}

/* A handshake state that has already sent its hello and is waiting to read, which is where every
 * refusal below happens. Returns NULL if the shipped fingerprint table is not readable. */
static lc_client_hs *armed_from(const char *path, uint8_t *table, size_t *table_len)
{
    FILE *tf = fopen(path, "rb");
    if (tf == NULL)
        return NULL;
    *table_len = fread(table, 1, 8192, tf);
    fclose(tf);

    lc_client_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.table = table;
    cfg.table_len = *table_len;
    cfg.sni = "example.com";

    lc_client_hs *hs = lc_client_hs_new(&cfg);
    if (hs == NULL)
        return NULL;

    lc_client cl;
    memset(&cl, 0, sizeof cl);
    if (lc_client_hs_step(hs, &cl) != LC_HS_WANT_WRITE) {
        lc_client_hs_free(hs);
        return NULL;
    }
    size_t n = 0;
    (void)lc_client_hs_out(hs, &n);
    lc_client_hs_out_taken(hs, n);
    if (lc_client_hs_step(hs, &cl) != LC_HS_WANT_READ) {
        lc_client_hs_free(hs);
        return NULL;
    }
    return hs;
}

static lc_client_hs *armed(uint8_t *table, size_t *table_len)
{
    return armed_from("package/files/fingerprint.fpt", table, table_len);
}

/* The public keys a built hello offers for X25519MLKEM768 and X25519, found by walking the message
 * rather than by offset: the Chrome table shuffles its extensions. Returns 0 when both are there. */
static int hello_key_shares(const uint8_t *h, size_t len, const uint8_t **hybrid, size_t *hybrid_len,
                            const uint8_t **x25519)
{
    size_t p = 4u + 2u + 32u;
    if (p + 1u > len)
        return -1;
    p += 1u + h[p];
    if (p + 2u > len)
        return -1;
    p += 2u + ((size_t)h[p] << 8 | h[p + 1u]);
    if (p + 1u > len)
        return -1;
    p += 1u + h[p];
    if (p + 2u > len)
        return -1;
    size_t end = p + 2u + ((size_t)h[p] << 8 | h[p + 1u]);
    p += 2u;
    *hybrid = NULL;
    *x25519 = NULL;
    while (p + 4u <= end && end <= len) {
        unsigned type = (unsigned)h[p] << 8 | h[p + 1u];
        size_t   elen = (size_t)h[p + 2u] << 8 | h[p + 3u];
        size_t   body = p + 4u;
        if (type == 0x0033u && body + 2u <= end) {
            size_t q = body + 2u, qend = body + elen;
            while (q + 4u <= qend) {
                unsigned grp = (unsigned)h[q] << 8 | h[q + 1u];
                size_t   klen = (size_t)h[q + 2u] << 8 | h[q + 3u];
                if (grp == 0x11ecu) {
                    *hybrid = h + q + 4u;
                    *hybrid_len = klen;
                } else if (grp == 0x001du && klen == 32u) {
                    *x25519 = h + q + 4u;
                }
                q += 4u + klen;
            }
        }
        p = body + elen;
    }
    return *hybrid != NULL && *x25519 != NULL && *hybrid_len >= 32u ? 0 : -1;
}

/* Feeds whole bytes and runs the machine, the way the run loop does. */
static lc_client_progress drive(lc_client_hs *hs, const uint8_t *rec, size_t len)
{
    lc_client cl;
    memset(&cl, 0, sizeof cl);
    size_t off = 0;
    for (;;) {
        if (off < len) {
            size_t took = lc_client_hs_feed(hs, rec + off, len - off);
            off += took;
            if (took == 0u)
                break;
        }
        lc_client_progress p = lc_client_hs_step(hs, &cl);
        if (p != LC_HS_WANT_READ || off >= len)
            return p;
    }
    return lc_client_hs_step(hs, &cl);
}

/* Builds a ServerHello record that parses: the session id is ECHOED from our own hello, because
 * this client checks that echo before it looks at anything else and a random id would be refused
 * one branch too early. `group` and a key share of `share_len` bytes are what the case under test
 * varies; everything else is the smallest well-formed message that reaches key agreement. */
/* The random every HelloRetryRequest carries — SHA-256 of "HelloRetryRequest", RFC 8446 4.1.3. A
 * ServerHello is a retry if and only if its random is this, which is why a test can turn one into
 * the other by changing thirty-two bytes and nothing else. */
static const uint8_t hrr_random[32] = {
    0xcfu, 0x21u, 0xadu, 0x74u, 0xe5u, 0x9au, 0x61u, 0x11u, 0xbeu, 0x1du, 0x8cu, 0x02u,
    0x1eu, 0x65u, 0xb8u, 0x91u, 0xc2u, 0xa2u, 0x11u, 0x16u, 0x7au, 0xbbu, 0x8cu, 0x5eu,
    0x07u, 0x9eu, 0x09u, 0xe2u, 0xc8u, 0xa8u, 0x33u, 0x9cu,
};

/* The extension types of a ClientHello, in order, plus where a cookie sits if one does. Order is
 * the whole of what a fingerprint is, so it is the only thing worth asserting about an echo whose
 * position the reference draws at random. */
struct exts {
    uint16_t       type[64];
    size_t         n;
    const uint8_t *cookie;    /* extension_data of the cookie extension, NULL if absent */
    size_t         cookie_len;
    size_t         cookie_at; /* index among the extensions, SIZE_MAX when absent */
};

static int read_exts(const uint8_t *h, size_t total, size_t sid_off, size_t sid_len, struct exts *o)
{
    o->n = 0;
    o->cookie = NULL;
    o->cookie_len = 0;
    o->cookie_at = (size_t)-1;

    size_t off = sid_off + sid_len;
    if (off + 2u > total)
        return -1;
    size_t cs = (size_t)h[off] << 8 | h[off + 1u];
    off += 2u + cs;
    if (off + 1u > total)
        return -1;
    off += 1u + h[off];
    if (off + 2u > total)
        return -1;
    size_t etotal = (size_t)h[off] << 8 | h[off + 1u];
    off += 2u;
    size_t end = off + etotal;
    if (end > total)
        return -1;
    while (off + 4u <= end) {
        uint16_t t = (uint16_t)((uint16_t)h[off] << 8 | h[off + 1u]);
        size_t   l = (size_t)h[off + 2u] << 8 | h[off + 3u];
        if (off + 4u + l > end || o->n >= 64u)
            return -1;
        if (t == 0x002cu) {
            o->cookie = h + off + 4u;
            o->cookie_len = l;
            o->cookie_at = o->n;
        }
        o->type[o->n++] = t;
        off += 4u + l;
    }
    return off == end ? 0 : -1;
}

static size_t server_hello(const lc_client_hs *hs, uint16_t group, size_t share_len,
                           const uint8_t *cookie, size_t cookie_len, uint8_t *out, size_t cap)
{
    uint8_t body[512];
    size_t  n = 0;
    body[n++] = 0x03u;
    body[n++] = 0x03u;
    if (share_len == 0u)
        memcpy(body + n, hrr_random, 32); /* share_len 0 means: build a retry, not a hello */
    else
        memset(body + n, 0, 32);
    n += 32;
    body[n++] = (uint8_t)hs->info.sid_len;
    memcpy(body + n, hs->hello + hs->info.sid_off, hs->info.sid_len);
    n += hs->info.sid_len;
    body[n++] = 0x13u; /* TLS_AES_128_GCM_SHA256, which every fingerprint here offers */
    body[n++] = 0x01u;
    body[n++] = 0x00u; /* legacy_compression_method */

    uint8_t ext[128];
    size_t  e = 0;
    ext[e++] = 0x00u; ext[e++] = 0x2bu; ext[e++] = 0x00u; ext[e++] = 0x02u;
    ext[e++] = 0x03u; ext[e++] = 0x04u;                     /* supported_versions: TLS 1.3 */
    /* Group 0 means NO key_share extension at all, which is what a retry asking only for a
     * cookie looks like on the wire. */
    if (group != 0u) {
        ext[e++] = 0x00u; ext[e++] = 0x33u;                     /* key_share */
    if (share_len == 0u) {
        /* A retry names the group and sends no share with it. */
        ext[e++] = 0x00u; ext[e++] = 0x02u;
        ext[e++] = (uint8_t)(group >> 8); ext[e++] = (uint8_t)group;
    } else {
        ext[e++] = (uint8_t)((4u + share_len) >> 8); ext[e++] = (uint8_t)(4u + share_len);
        ext[e++] = (uint8_t)(group >> 8); ext[e++] = (uint8_t)group;
        ext[e++] = (uint8_t)(share_len >> 8); ext[e++] = (uint8_t)share_len;
        memset(ext + e, 0xa5, share_len);
        e += share_len;
    }
    }
    if (cookie != NULL && cookie_len > 0u) {
        /* `opaque cookie<1..2^16-1>` inside the extension, RFC 8446 4.2.2. */
        ext[e++] = 0x00u; ext[e++] = 0x2cu;
        ext[e++] = (uint8_t)((cookie_len + 2u) >> 8); ext[e++] = (uint8_t)(cookie_len + 2u);
        ext[e++] = (uint8_t)(cookie_len >> 8); ext[e++] = (uint8_t)cookie_len;
        memcpy(ext + e, cookie, cookie_len);
        e += cookie_len;
    }

    body[n++] = (uint8_t)(e >> 8);
    body[n++] = (uint8_t)e;
    memcpy(body + n, ext, e);
    n += e;

    if (cap < n + 9u)
        return 0;
    out[0] = 0x16u; out[1] = 0x03u; out[2] = 0x03u;
    out[3] = (uint8_t)((n + 4u) >> 8); out[4] = (uint8_t)(n + 4u);
    out[5] = 0x02u;                                          /* ServerHello */
    out[6] = 0x00u; out[7] = (uint8_t)(n >> 8); out[8] = (uint8_t)n;
    memcpy(out + 9, body, n);
    return n + 9u;
}

/* The same message, but with the random and the whole extension block handed in.
 *
 * server_hello above ties the two together — a retry is "no share", and the random follows from
 * that — which is exactly right for the cases it was written for and cannot express the ones below:
 * a RETRY THAT CARRIES A SHARE, a forbidden extension with a body of a chosen shape, or a hello
 * whose random holds the downgrade canary. Rather than add a fourth meaning to share_len and
 * disturb the cases that already pass, this builder asks for the two fields outright. */
static size_t hello_bytes(const lc_client_hs *hs, const uint8_t *random32, const uint8_t *exts,
                          size_t exts_len, uint8_t *out, size_t cap)
{
    uint8_t body[512];
    size_t  n = 0;
    body[n++] = 0x03u;
    body[n++] = 0x03u;
    memcpy(body + n, random32, 32);
    n += 32;
    body[n++] = (uint8_t)hs->info.sid_len;
    memcpy(body + n, hs->hello + hs->info.sid_off, hs->info.sid_len);
    n += hs->info.sid_len;
    body[n++] = 0x13u;
    body[n++] = 0x01u;
    body[n++] = 0x00u;
    body[n++] = (uint8_t)(exts_len >> 8);
    body[n++] = (uint8_t)exts_len;
    memcpy(body + n, exts, exts_len);
    n += exts_len;

    if (cap < n + 9u)
        return 0;
    out[0] = 0x16u; out[1] = 0x03u; out[2] = 0x03u;
    out[3] = (uint8_t)((n + 4u) >> 8); out[4] = (uint8_t)(n + 4u);
    out[5] = 0x02u;
    out[6] = 0x00u; out[7] = (uint8_t)(n >> 8); out[8] = (uint8_t)n;
    memcpy(out + 9, body, n);
    return n + 9u;
}

/* A handshake that has answered a HelloRetryRequest and handed over its second hello: the version
 * is settled and no key exists, which is the state a Go server's dummy ChangeCipherSpec arrives in. */
static lc_client_hs *after_retry(uint8_t *table, size_t *table_len)
{
    lc_client_hs *hs = armed(table, table_len);
    if (hs == NULL)
        return NULL;
    uint8_t rec[512];
    size_t  n = server_hello(hs, 0x0018u, 0u, NULL, 0u, rec, sizeof rec);
    (void)drive(hs, rec, n);
    size_t out_n = 0;
    /* Two writes: the ChangeCipherSpec, then the second hello. */
    for (int w = 0; w < 2; w++) {
        (void)lc_client_hs_out(hs, &out_n);
        lc_client_hs_out_taken(hs, out_n);
    }
    if (hs->ph == PH_FAILED || hs->retried != 1 || !hs->have_vers) {
        lc_client_hs_free(hs);
        return NULL;
    }
    return hs;
}

/* One that took an ordinary ServerHello and holds handshake keys: the encrypted flight is next. */
static lc_client_hs *in_flight(uint8_t *table, size_t *table_len)
{
    lc_client_hs *hs = armed(table, table_len);
    if (hs == NULL)
        return NULL;
    uint8_t rec[512];
    size_t  n = server_hello(hs, 0x001du, 32u, NULL, 0u, rec, sizeof rec);
    (void)drive(hs, rec, n);
    size_t out_n = 0;
    (void)lc_client_hs_out(hs, &out_n);
    lc_client_hs_out_taken(hs, out_n);
    if (hs->ph != PH_FLIGHT) {
        lc_client_hs_free(hs);
        return NULL;
    }
    return hs;
}

/* Drives one record and says what came of it: 0 when the machine carries on with nothing owed,
 * -1 when it stopped in silence, or the alert it stopped with. */
static int outcome(lc_client_hs *hs, const uint8_t *rec, size_t len)
{
    (void)drive(hs, rec, len);
    if (hs->ph != PH_FAILED)
        return hs->alert_pending ? 1000 : 0;
    return hs->alert_pending ? (int)hs->alert_desc : -1;
}

int main(void)
{
    static uint8_t table[8192];
    size_t         table_len = 0;

    printf("\nthe alerts a refusal owes\n");

    /* A RECORD LARGER THAN THE LIMIT — alert 22, AND WHICH LIMIT DEPENDS ON WHETHER KEYS EXIST.
     *
     * ⚠️ THIS BLOCK ASSERTED THE OPPOSITE UNTIL 2026-09-06, and the comment that stood here
     * explained why at length: `vers == TLS13 && n > 16640 || n > 18432` was read as meaning that
     * before the version is settled a record up to 18432 "is accepted without comment", so the
     * test pinned silence as the reference's behaviour and called an alert a distinguisher.
     *
     * The reference has a SECOND ceiling, on the opened length, and in that window it is the one
     * that fires:
     *
     *     if len(data) > maxPlaintext {
     *         return c.in.setErrorLocked(c.sendAlert(alertRecordOverflow))
     *     }                                        (vendor/utls/conn.go:693-694)
     *
     * `decrypt` returns the payload untouched while hc.cipher is nil (vendor/utls/conn.go:342-352),
     * so before keys the body IS the plaintext and anything over 16384 gets record_overflow. Both
     * of the old assertions were therefore backwards: 16640 is not accepted in that window, and
     * 16641 is not refused in silence. Found by the sieve reading the pair against the source.
     *
     * The boundary is asserted from both sides, because an off-by-one in either direction is what a
     * single absurd length would miss. */
    {
        lc_client_hs *hs = armed(table, &table_len);
        expect(hs != NULL, "a handshake arms from the shipped fingerprint table");
        if (hs != NULL) {
            const uint8_t hdr[5] = { 0x16u, 0x03u, 0x03u, 0x40u, 0x00u }; /* 16384 */
            (void)lc_client_hs_feed(hs, hdr, sizeof hdr);
            expect(hs->ph != PH_FAILED && hs->alert_pending == 0,
                   "before keys, a 16384-byte record — maxPlaintext exactly — is accepted");
            lc_client_hs_free(hs);
        }

        /* One byte more, and 16641 and 18432 — between the two ceilings, where the wire check is
         * silent and the plaintext check is not: record_overflow, but only once the WHOLE record
         * is in, since the plaintext check reads the body (vendor/utls/conn.go:680, :693-695).
         * ⚠️ Until 2026-09-27 these asserted the alert on the header alone. */
        static uint8_t big[5 + 18432];
        static const unsigned sizes[3] = { 16385u, 16641u, 18432u };
        for (unsigned k = 0; k < 3; k++) {
            hs = armed(table, &table_len);
            if (hs == NULL)
                continue;
            memset(big, 0, sizeof big);
            big[0] = 0x16u; big[1] = 0x03u; big[2] = 0x03u;
            big[3] = (uint8_t)(sizes[k] >> 8); big[4] = (uint8_t)sizes[k];
            (void)drive(hs, big, 5u + sizes[k] - 1u);
            int waited = hs->ph != PH_FAILED && hs->alert_pending == 0;
            (void)drive(hs, big + 5u + sizes[k] - 1u, 1u);
            char what[160];
            snprintf(what, sizeof what,
                     "before a version, %u bytes: nothing until the body is in, then record_overflow",
                     sizes[k]);
            expect(waited && hs->alert_pending == 1 && hs->alert_desc == LC_ALERT_RECORD_OVERFLOW,
                   what);
            lc_client_hs_free(hs);
        }

        /* And once keys exist the ciphertext ceiling is the wider one: the tag and the inner
         * content type ride on top of the plaintext, so 16640 is legal there and only 16641 is not. */
        hs = armed(table, &table_len);
        if (hs != NULL) {
            hs->have_vers = 1;
            const uint8_t hdr[5] = { 0x16u, 0x03u, 0x03u, 0x41u, 0x00u }; /* 16640 */
            (void)lc_client_hs_feed(hs, hdr, sizeof hdr);
            expect(hs->ph != PH_FAILED && hs->alert_pending == 0,
                   "after keys, 16640 — the largest legal ciphertext — is accepted");
            lc_client_hs_free(hs);
        }

        hs = armed(table, &table_len);
        if (hs != NULL) {
            hs->have_vers = 1; /* what accepting a ServerHello does */
            const uint8_t hdr[5] = { 0x16u, 0x03u, 0x03u, 0x41u, 0x01u }; /* 16641 */
            (void)drive(hs, hdr, sizeof hdr);
            expect(hs->alert_pending == 1 && hs->alert_desc == LC_ALERT_RECORD_OVERFLOW,
                   "after it, the same record is refused with record_overflow (22)");
            lc_client_hs_free(hs);
        }

        /* The plaintext check reads every record that is not opened, and two of those come after
         * the version is settled: a ChangeCipherSpec in the encrypted flight, passed through
         * unopened (vendor/utls/conn.go:346-351), and a handshake record after a retry, when no key
         * exists yet. Both are within the 1.3 wire ceiling at 16385 and both are record_overflow
         * (:693-695) — not the decode_error a ChangeCipherSpec of the wrong size otherwise gets, nor
         * a message the handshake goes on to read. */
        {
            static uint8_t over[5 + 16385];
            memset(over, 0x01, sizeof over);
            over[1] = 0x03u; over[2] = 0x03u; over[3] = 0x40u; over[4] = 0x01u;
            over[0] = 0x14u;
            hs = in_flight(table, &table_len);
            if (hs != NULL) {
                (void)drive(hs, over, sizeof over);
                expect(hs->alert_pending == 1 && hs->alert_desc == LC_ALERT_RECORD_OVERFLOW,
                       "a ChangeCipherSpec of 16385 bytes in the flight is record_overflow");
                lc_client_hs_free(hs);
            }
            over[0] = 0x16u;
            hs = after_retry(table, &table_len);
            if (hs != NULL) {
                (void)drive(hs, over, sizeof over);
                expect(hs->alert_pending == 1 && hs->alert_desc == LC_ALERT_RECORD_OVERFLOW,
                       "and so is a handshake record of 16385 bytes after a retry");
                lc_client_hs_free(hs);
            }
        }

        /* Above the pre-1.3 ceiling both ends complain, version or no version. */
        hs = armed(table, &table_len);
        if (hs != NULL) {
            const uint8_t hdr[5] = { 0x16u, 0x03u, 0x03u, 0x48u, 0x01u }; /* 18433 */
            (void)drive(hs, hdr, sizeof hdr);
            expect(hs->alert_pending == 1 && hs->alert_desc == LC_ALERT_RECORD_OVERFLOW,
                   "and 18433 — past maxCiphertext — says record_overflow either way");
            lc_client_hs_free(hs);
        }
    }

    /* THE VERSION BYTE, AND THE FIRST RECORD'S EXEMPTION FROM IT — alert 70, or nothing.
     *
     * RFC 8446 5.1 says legacy_record_version "MUST be ignored for all purposes"; the reference
     * checks it anyway and sends protocol_version (vendor/utls/conn.go:661-664), but only once
     * c.haveVers is set, which happens when the ServerHello's version is accepted
     * (utls/handshake_client.go:558). Both halves matter and they pull in opposite directions: checking
     * too little leaves a client that swallows what every Go client refuses, checking too early
     * refuses a first record the reference does not look at. */
    {
        lc_client_hs *hs = armed(table, &table_len);
        if (hs != NULL) {
            const uint8_t hdr[5] = { 0x16u, 0x03u, 0x04u, 0x00u, 0x10u };
            (void)lc_client_hs_feed(hs, hdr, sizeof hdr);
            expect(hs->ph != PH_FAILED && hs->alert_pending == 0,
                   "before the version is settled a record saying 0x0304 is not refused for it");
            lc_client_hs_free(hs);
        }

        hs = armed(table, &table_len);
        if (hs != NULL) {
            hs->have_vers = 1; /* what accepting a ServerHello does */
            const uint8_t hdr[5] = { 0x16u, 0x03u, 0x04u, 0x00u, 0x10u };
            (void)drive(hs, hdr, sizeof hdr);
            expect(hs->alert_pending == 1 && hs->alert_desc == LC_ALERT_PROTOCOL_VERSION,
                   "after it, the same record is refused with protocol_version (70)");
            lc_client_hs_free(hs);
        }

        hs = armed(table, &table_len);
        if (hs != NULL) {
            hs->have_vers = 1;
            const uint8_t hdr[5] = { 0x16u, 0x03u, 0x03u, 0x00u, 0x10u };
            (void)lc_client_hs_feed(hs, hdr, sizeof hdr);
            expect(hs->ph != PH_FAILED && hs->alert_pending == 0,
                   "and 0x0303 passes, so the check is on the value and not on the flag");
            lc_client_hs_free(hs);
        }
    }

    /* A FIRST MESSAGE THAT IS NOT A SERVERHELLO — alert 10.
     *
     * Two routes in the reference meet at this one branch: a message whose type or framing does not
     * parse dies in unmarshalHandshakeMessage, under readHandshake, with unexpected_message
     * (utls/conn.go:1184, :1192-1194), and a well-formed message that is simply the wrong one dies at the type assertion with the same alert
     * (utls/handshake_client.go:313-317). EncryptedExtensions is the honest wrong message here — it is
     * the one that legitimately follows a ServerHello, so arriving first is a peer out of order
     * rather than a peer sending garbage. */
    {
        lc_client_hs *hs = armed(table, &table_len);
        if (hs != NULL) {
            const uint8_t rec[13] = { 0x16u, 0x03u, 0x03u, 0x00u, 0x08u,
                                      0x08u, 0x00u, 0x00u, 0x04u, 0xaau, 0xbbu, 0xccu, 0xddu };
            (void)drive(hs, rec, sizeof rec);
            expect(hs->alert_pending == 1 && hs->alert_desc == LC_ALERT_UNEXPECTED_MESSAGE,
                   "EncryptedExtensions where a ServerHello belongs is refused with "
                   "unexpected_message (10)");
            lc_client_hs_free(hs);
        }
    }

    /* THE STANDALONE X25519 KEY IS THE HYBRID'S HALF ONLY WHERE THE PROFILE SAYS SO.
     *
     * uTLS reuses the classical key for a parrot that wraps the pair in
     * ReuseHybridAndClassicalKeyShares — Firefox 148 (vendor/utls/u_parrots.go:1613) — and generates
     * a key of its own for one that does not, which is Chrome 133 (:946-950, :3304). This client
     * reused it for every profile, so every Chrome hello carried two equal 32-byte ranges at offsets
     * where the reference's never match. Asked of the real machine, on both shipped tables, because
     * the fault was in which of the two the rule was applied to. */
    {
        static const char *const tables[2] = { "package/files/fingerprint.fpt",
                                               "test/fphello/chrome.fpt" };
        static const int         reuse[2] = { 1, 0 };
        for (unsigned t = 0; t < 2u; t++) {
            static uint8_t ktable[8192];
            size_t         klen = 0;
            lc_client_hs  *hs = armed_from(tables[t], ktable, &klen);
            expect(hs != NULL, reuse[t] ? "a Firefox hello is built by the real machine"
                                        : "and a Chrome hello");
            if (hs == NULL)
                continue;
            size_t         hlen = 0, hyb_len = 0;
            const uint8_t *hello = lc_client_hs_hello(hs, &hlen);
            const uint8_t *hyb = NULL, *x = NULL;
            int found = hello_key_shares(hello, hlen, &hyb, &hyb_len, &x) == 0;
            int same = found && memcmp(hyb + hyb_len - 32u, x, 32u) == 0;
            expect(found && same == reuse[t],
                   reuse[t] ? "Firefox's X25519 share IS the hybrid's classical half, as its parrot marks"
                            : "Chrome's X25519 share is a key of its own, as its unmarked parrot generates");
            lc_client_hs_free(hs);
        }
    }

    /* ENCRYPTED EXTENSIONS, AS uTLS JUDGES THEM — lc_utls_ee_alert.
     *
     * Asked of the rule directly rather than through the machine: the message arrives under the
     * handshake keys, so driving to it would mean deriving them and then measuring the harness. The
     * hello is a real one, built from the shipped table, because the offered list is the table's.
     *
     * The message is unmarshalled whole first — a malformed extension anywhere is
     * unexpected_message (vendor/utls/conn.go:1185-1186) — and then judged in readServerParameters'
     * order: the protocol (120), ALPS with no protocol (110), quic_transport_parameters (110),
     * early_data (110) (vendor/utls/handshake_client_tls13.go:625-675). uTLS has no repeat check
     * here, so a second ALPN is read and the last one stands. */
    {
        lc_client_hs *hs = armed(table, &table_len);
        if (hs != NULL) {
            size_t         hlen = 0;
            const uint8_t *hello = lc_client_hs_hello(hs, &hlen);
            static const uint8_t H2[]    = { 0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x32 };
            static const uint8_t SPDY[]  = { 0x00, 0x10, 0x00, 0x09, 0x00, 0x07, 0x06,
                                             0x73, 0x70, 0x64, 0x79, 0x2f, 0x33 };
            static const uint8_t BADA[]  = { 0x00, 0x10, 0x00, 0x05, 0x00, 0x04, 0x02, 0x68, 0x32 };
            static const uint8_t EARLY[] = { 0x00, 0x2a, 0x00, 0x00 };
            static const uint8_t EARLY1[] = { 0x00, 0x2a, 0x00, 0x01, 0x00 };
            static const uint8_t QTP[]   = { 0x00, 0x39, 0x00, 0x02, 0x40, 0x01 };
            static const uint8_t ALPS[]  = { 0x44, 0xcd, 0x00, 0x02, 0x00, 0x00 };
            static const uint8_t JUNK[]  = { 0x7a, 0x7a, 0x00, 0x09, 0x00 };
            static const uint8_t SNI1[]  = { 0x00, 0x00, 0x00, 0x01, 0x41 };
            static const struct {
                const uint8_t *e[3];
                size_t         n[3];
                uint8_t        want;
                const char    *what;
            } cases[] = {
                { { NULL }, { 0 }, 0, "an EncryptedExtensions naming no protocol is accepted, as it is off QUIC" },
                { { H2 }, { sizeof H2 }, 0, "a protocol the hello offered is accepted" },
                { { SPDY }, { sizeof SPDY }, LC_ALERT_NO_APPLICATION_PROTOCOL,
                  "a protocol the hello never offered is no_application_protocol (120)" },
                { { BADA }, { sizeof BADA }, LC_ALERT_UNEXPECTED_MESSAGE,
                  "an ALPN extension that does not parse is unexpected_message (10), not 120" },
                { { SPDY, JUNK }, { sizeof SPDY, sizeof JUNK }, LC_ALERT_UNEXPECTED_MESSAGE,
                  "a protocol never offered AND a malformed extension after it: 10, the whole "
                  "message is read before the protocol is judged" },
                { { SPDY, H2 }, { sizeof SPDY, sizeof H2 }, 0,
                  "two ALPN extensions: the last one stands, as uTLS has no repeat check here" },
                { { H2, SNI1 }, { sizeof H2, sizeof SNI1 }, 0,
                  "a server_name with a body is stepped over, uTLS having no case for it here" },
                { { ALPS }, { sizeof ALPS }, LC_ALERT_UNSUPPORTED_EXTENSION,
                  "ALPS with no protocol negotiated is unsupported_extension" },
                { { H2, ALPS }, { sizeof H2, sizeof ALPS }, 0, "ALPS with one is accepted" },
                { { H2, QTP }, { sizeof H2, sizeof QTP }, LC_ALERT_UNSUPPORTED_EXTENSION,
                  "quic_transport_parameters over TCP is unsupported_extension" },
                { { H2, EARLY }, { sizeof H2, sizeof EARLY }, LC_ALERT_UNSUPPORTED_EXTENSION,
                  "early_data this client never offered is unsupported_extension" },
                { { H2, EARLY1 }, { sizeof H2, sizeof EARLY1 }, LC_ALERT_UNEXPECTED_MESSAGE,
                  "and early_data with a body does not unmarshal: 10" },
            };
            for (size_t c = 0; c < sizeof cases / sizeof cases[0]; c++) {
                uint8_t ee[128];
                size_t  n = 2u;
                for (unsigned k = 0; k < 3u && cases[c].e[k] != NULL; k++) {
                    memcpy(ee + n, cases[c].e[k], cases[c].n[k]);
                    n += cases[c].n[k];
                }
                ee[0] = (uint8_t)((n - 2u) >> 8);
                ee[1] = (uint8_t)(n - 2u);
                expect(lc_utls_ee_alert(hello, hlen, ee, n, 0) == cases[c].want, cases[c].what);
            }
            lc_client_hs_free(hs);
        }
    }

    /* AND WHAT A SERVER'S ALPS IS ANSWERED WITH — lc_utls_alps_answer.
     *
     * utlsClientEncryptedExtensionsMsg.marshal with the codepoint the server used and the settings
     * Xray leaves empty (vendor/utls/u_handshake_messages.go:80-106): type 8, length 6, a block of 4,
     * the codepoint, zero. The last of two codepoints is the one, because utlsUnmarshal overwrites it
     * for each (vendor/utls/u_handshake_messages.go:62-71), and what the server's settings said is
     * not echoed. Asked of the rule for the reason lc_utls_ee_alert is; the stand nodealert's
     * `alps` scenarios hold the whole flight against the reference client. */
    {
        static const uint8_t H2[]   = { 0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x32 };
        static const uint8_t NEW[]  = { 0x44, 0xcd, 0x00, 0x00 };
        static const uint8_t OLD[]  = { 0x44, 0x69, 0x00, 0x00 };
        static const uint8_t SETS[] = { 0x44, 0xcd, 0x00, 0x06, 0x00, 0x03, 0x00, 0x00, 0x10, 0x00 };
        static const struct {
            const uint8_t *e[3];
            size_t         n[3];
            uint8_t        cp_hi, cp_lo; /* 0, 0: no answer */
            const char    *what;
        } cases[] = {
            { { H2 }, { sizeof H2 }, 0, 0, "no ALPS, no answer" },
            { { H2, NEW }, { sizeof H2, sizeof NEW }, 0x44, 0xcd,
              "ALPS under the new codepoint (17613) is answered under it" },
            { { H2, OLD }, { sizeof H2, sizeof OLD }, 0x44, 0x69,
              "and under the old one (17513), under that" },
            { { H2, OLD, NEW }, { sizeof H2, sizeof OLD, sizeof NEW }, 0x44, 0xcd,
              "both: the last one stands" },
            { { NEW, H2, OLD }, { sizeof NEW, sizeof H2, sizeof OLD }, 0x44, 0x69,
              "both the other way round: the last one still" },
            { { H2, SETS }, { sizeof H2, sizeof SETS }, 0x44, 0xcd,
              "the server's settings are not echoed: ours are empty whatever it sent" },
        };
        for (size_t c = 0; c < sizeof cases / sizeof cases[0]; c++) {
            uint8_t ee[64], out[LC_ALPS_ANSWER_LEN];
            size_t  n = 2u;
            for (unsigned k = 0; k < 3u && cases[c].e[k] != NULL; k++) {
                memcpy(ee + n, cases[c].e[k], cases[c].n[k]);
                n += cases[c].n[k];
            }
            ee[0] = (uint8_t)((n - 2u) >> 8);
            ee[1] = (uint8_t)(n - 2u);
            memset(out, 0xa5, sizeof out);
            size_t got = lc_utls_alps_answer(ee, n, out);
            if (cases[c].cp_hi == 0u) {
                expect(got == 0u, cases[c].what);
            } else {
                const uint8_t want[LC_ALPS_ANSWER_LEN] = { 0x08u, 0x00u, 0x00u, 0x06u, 0x00u, 0x04u,
                                                           cases[c].cp_hi, cases[c].cp_lo, 0x00u, 0x00u };
                expect(got == LC_ALPS_ANSWER_LEN && memcmp(out, want, sizeof want) == 0, cases[c].what);
            }
        }
    }

    /* AND HOW LARGE THE BUFFER A COMPRESSED CERTIFICATE OPENS INTO IS — lc_utls_certcomp_want.
     *
     * The declared length, whatever it is: the reference allocates `m.uncompressedLength + 4`
     * (vendor/utls/u_handshake_client.go:100) and opens a 300000-byte certificate
     * (test/certcomp/reference_open.h). Until 2026-09-25 this was capped at the Certificate message's
     * 262144 and a longer one refused; test/certcomp holds the opener, this the size it is given. */
    {
        static const struct {
            uint8_t     b[5];
            size_t      n;
            size_t      want;
            const char *what;
        } cases[] = {
            { { 0x00, 0x02, 0x00, 0x07, 0xd0 }, 5u, 2000u, "an ordinary certificate: its own 2000 bytes" },
            { { 0x00, 0x02, 0x04, 0x00, 0x01 }, 5u, 262145u,
              "one byte over the Certificate message's ceiling: all of it, not 262144" },
            { { 0x00, 0x03, 0x04, 0x93, 0xe0 }, 5u, 300000u, "300000, which the reference opens: all of it" },
            { { 0x00, 0x01, 0xff, 0xff, 0xff }, 5u, 0xffffffu, "the most three bytes can say: all of it" },
            { { 0x00, 0x02, 0x00, 0x07 }, 4u, 0u, "a body too short to say: nothing" },
        };
        for (size_t c = 0; c < sizeof cases / sizeof cases[0]; c++)
            expect(lc_utls_certcomp_want(cases[c].b, cases[c].n) == cases[c].want, cases[c].what);
    }

    /* ⚠️ THE SAME MISSING EXTENSION, TWO DIFFERENT ALERTS — and which one depends on whether a
     * HelloRetryRequest has been through.
     *
     * The reference answers a missing supported_versions with missing_extension
     * (vendor/utls/handshake_client_tls13.go:186-188), but nothing reaches that line on a first
     * ServerHello: pickTLSVersion runs before the 1.3 machine and, for a parrot that offers 1.2,
     * negotiates 1.2 instead (vendor/utls/handshake_client.go:545-555). After a retry pickTLSVersion
     * no longer runs (utls/handshake_client_tls13.go:506), and 109 is the answer.
     *
     * BOTH halves are here on purpose. Only the second is the fix; asserting it alone would pass on
     * a client that answered 109 to everything, which is the opposite defect and the one that would
     * be shipped by "just use the reference's alert". The pair is what says the client knows which
     * hello it is looking at. Found by the sieve, 2026-09-09. */
    {
        lc_client_hs *hs = armed(table, &table_len);
        if (hs != NULL) {
            uint8_t zero[32];
            memset(zero, 0, sizeof zero);
            uint8_t rec[512];
            size_t  n = hello_bytes(hs, zero, NULL, 0u, rec, sizeof rec);
            (void)drive(hs, rec, n);
            /* A FIRST ServerHello without supported_versions is TLS 1.2 to the reference, and it goes
             * on as hs12 does — until pickCipherSuite, which finds TLS_AES_128_GCM_SHA256 on the
             * hello and not among the TLS 1.2 suites and answers handshake_failure
             * (vendor/utls/handshake_client.go:664-668). protocol_version until 29.09 (T3). */
            expect(hs->alert_pending == 1 && hs->alert_desc == LC_ALERT_HANDSHAKE_FAILURE,
                   "a FIRST ServerHello without supported_versions is TLS 1.2, and its TLS 1.3 suite is "
                   "handshake_failure (40), not protocol_version (70)");
            lc_client_hs_free(hs);
        }
    }
    {
        /* `retried` is set here rather than by driving a real HelloRetryRequest first, and that is a
         * deliberate narrowing, not a shortcut around a failing test. Feeding a retry and then a
         * second ServerHello through the same handle does not work in this harness — the machine has
         * its own second ClientHello to hand out between the two, and `drive` has no way to take it
         * — so a test written that way would be measuring the harness. What the fix actually turns
         * on is one flag, and this sets exactly that flag and nothing else: same message, same
         * builder, same drive as the case above, one field different, two different alerts. The
         * suite reaches into `hs->` throughout for the same reason. */
        lc_client_hs *hs = armed(table, &table_len);
        if (hs != NULL) {
            hs->retried = 1;
            uint8_t zero[32];
            memset(zero, 0, sizeof zero);
            uint8_t rec[512];
            size_t  n = hello_bytes(hs, zero, NULL, 0u, rec, sizeof rec);
            (void)drive(hs, rec, n);
            expect(hs->alert_pending == 1 && hs->alert_desc == LC_ALERT_MISSING_EXTENSION,
                   "the SAME message on a client that has been retried is refused with "
                   "missing_extension (109), which is where the reference's branch becomes reachable");
            lc_client_hs_free(hs);
        }
    }

    /* server_name IN A ServerHello: allowed, and required to be EMPTY.
     *
     * The reference names it and refuses a body — `case extensionServerName: if len(extData) != 0 {
     * return false }` (vendor/utls/handshake_messages.go:1026-1029) — while a failed unmarshal is
     * unexpected_message (utls/conn.go:1185-1186). It is not in the forbidden set: an empty one is an
     * acknowledgement the reference records and carries on from.
     *
     * The pair is the point. Asserting only the refusal would pass on a client that refused
     * server_name outright, which is the opposite defect: that one would break against any server
     * that legitimately acknowledges the name. So the second case says the empty form is NOT
     * refused for this reason. Found by the sieve's reverse pass, 2026-09-09. */
    {
        lc_client_hs *hs = armed(table, &table_len);
        if (hs != NULL) {
            uint8_t zero[32];
            memset(zero, 0, sizeof zero);
            static const uint8_t with_body[] = {
                0x00u, 0x2bu, 0x00u, 0x02u, 0x03u, 0x04u, /* supported_versions: TLS 1.3 */
                0x00u, 0x00u, 0x00u, 0x01u, 0x41u,        /* server_name, one byte of body */
            };
            uint8_t rec[512];
            size_t  n = hello_bytes(hs, zero, with_body, sizeof with_body, rec, sizeof rec);
            (void)drive(hs, rec, n);
            expect(hs->alert_pending == 1 && hs->alert_desc == LC_ALERT_UNEXPECTED_MESSAGE,
                   "a ServerHello whose server_name carries a body is refused with "
                   "unexpected_message (10), as a message that does not unmarshal");
            lc_client_hs_free(hs);
        }
    }
    {
        lc_client_hs *hs = armed(table, &table_len);
        if (hs != NULL) {
            uint8_t zero[32];
            memset(zero, 0, sizeof zero);
            static const uint8_t empty[] = {
                0x00u, 0x2bu, 0x00u, 0x02u, 0x03u, 0x04u, /* supported_versions: TLS 1.3 */
                0x00u, 0x00u, 0x00u, 0x00u,               /* server_name, empty — the acknowledgement */
            };
            uint8_t rec[512];
            size_t  n = hello_bytes(hs, zero, empty, sizeof empty, rec, sizeof rec);
            (void)drive(hs, rec, n);
            expect(hs->alert_desc != LC_ALERT_UNEXPECTED_MESSAGE,
                   "while an EMPTY server_name is not what refuses the message — the reference "
                   "takes it as an acknowledgement and so does this");
            lc_client_hs_free(hs);
        }
    }

    printf("\nthe refusals that are silent on purpose\n");

    /* AN ALERT IS NOT ANSWERED WITH AN ALERT. The peer has already said why it is going; the
     * reference's record layer hands a received alert up as an error and writes nothing back. */
    {
        lc_client_hs *hs = armed(table, &table_len);
        if (hs != NULL) {
            const uint8_t rec[7] = { 0x15u, 0x03u, 0x03u, 0x00u, 0x02u, 0x02u, 0x28u };
            (void)drive(hs, rec, sizeof rec);
            expect(hs->ph == PH_FAILED, "a fatal alert from the server ends the handshake");
            expect(hs->alert_pending == 0, "and nothing is sent back — an alert is not answered");
            lc_client_hs_free(hs);
        }
    }

    /* A FIRST RECORD THAT IS NOT A HANDSHAKE RECORD gets a header error and no alert, because
     * whatever is on the other end may not be speaking TLS at all and an alert would tell it more
     * than it told us (vendor/utls/conn.go:666-673). */
    {
        lc_client_hs *hs = armed(table, &table_len);
        if (hs != NULL) {
            const uint8_t rec[8] = { 0x17u, 0x03u, 0x03u, 0x00u, 0x03u, 0x01u, 0x02u, 0x03u };
            (void)drive(hs, rec, sizeof rec);
            expect(hs->ph == PH_FAILED, "application_data before the ServerHello ends the handshake");
            expect(hs->alert_pending == 0, "and does so in silence, as the reference does");
            lc_client_hs_free(hs);
        }
    }

    /* A FAILURE OF OUR OWN SENDS NOTHING, not even a ChangeCipherSpec the reference had buffered:
     * where this client runs out of memory or a hash will not compute, the reference's process has
     * ended and the server hears no alert (hs_own). And it takes the alert's place, so an
     * internal_error cascading from it does not go out either. */
    {
        lc_client_hs *hs = armed(table, &table_len);
        expect(hs != NULL, "a client for a failure of its own");
        if (hs != NULL) {
            hs->ccs_owed = 1;
            hs_own(hs);
            hs_alert(hs, LC_ALERT_INTERNAL_ERROR); /* must not win: the first one stands */
            uint8_t out[LC_CLIENT_ALERT_MAX + 16u];
            expect(lc_client_hs_alert_record(hs, out, sizeof out) == 0 && hs->alert_pending == 0 &&
                       hs->ccs_owed == 0,
                   "a failure of our own writes no alert and no buffered ChangeCipherSpec");
            lc_client_hs_free(hs);
        }
    }

    printf("\nthe alert on the wire\n");

    /* THE BYTES THEMSELVES, before any key exists — which is where every refusal above happens, so
     * an alert that could only be written sealed would be no alert at all. Seven bytes: the record
     * header, the level, the description. The level is fatal (2) for everything but close_notify,
     * which the reference derives rather than taking from its caller (utls/conn.go:849-855). */
    {
        lc_client_hs *hs = armed(table, &table_len);
        int           sv[2] = { -1, -1 };
        expect(hs != NULL && socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0,
               "a socket pair opens to catch what is written");
        if (hs != NULL && sv[0] >= 0) {
            hs_alert(hs, LC_ALERT_UNEXPECTED_MESSAGE);
            hs_alert(hs, LC_ALERT_INTERNAL_ERROR); /* must not win: the first one stands */
            lc_client_hs_send_alert(hs, sv[0], lc_now_ms() + 5000u);

            uint8_t  got[16];
            ssize_t  n = recv(sv[1], got, sizeof got, MSG_DONTWAIT);
            const uint8_t want[7] = { 0x15u, 0x03u, 0x01u, 0x00u, 0x02u, 0x02u, 0x0au };
            expect(n == 7 && memcmp(got, want, 7) == 0,
                   "an unkeyed alert before any version goes out in the clear as 15 03 01 00 02 02 0a");
            expect(hs->alert_pending == 0, "and is owed only once");
            close(sv[0]);
            close(sv[1]);
        }
        if (hs != NULL)
            lc_client_hs_free(hs);
    }

    /* AND THE VERSION IN THAT HEADER FOLLOWS `c.vers`: VersionTLS10 while it is zero, VersionTLS12
     * once pickTLSVersion has set it (vendor/utls/conn.go:1016-1025,
     * vendor/utls/handshake_client.go:557). A hello whose version is refused is answered before the
     * version is set; one refused by a later check — here, no key share
     * (vendor/utls/handshake_client_tls13.go:532-535) — after it. */
    {
        static const uint8_t v13[6] = { 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04 };
        static const uint8_t v99[6] = { 0x00, 0x2b, 0x00, 0x02, 0x03, 0x05 };
        static const struct { const uint8_t *ext; uint8_t vers, desc; const char *what; } vc[] = {
            { v99, 0x01u, 0x46u, "a version refused by pickTLSVersion is answered as 15 03 01, 70" },
            { v13, 0x03u, 0x2fu, "a hello refused after it is answered as 15 03 03, 47" },
        };
        for (size_t i = 0; i < sizeof vc / sizeof vc[0]; i++) {
            lc_client_hs *hs = armed(table, &table_len);
            if (hs == NULL)
                continue;
            uint8_t random32[32], rec[512], room[LC_CLIENT_ALERT_MAX];
            memset(random32, 0x5a, sizeof random32);
            size_t len = hello_bytes(hs, random32, vc[i].ext, 6, rec, sizeof rec);
            (void)outcome(hs, rec, len);
            size_t n = lc_client_hs_alert_record(hs, room, sizeof room);
            expect(n == 7u && room[0] == 0x15u && room[1] == 0x03u && room[2] == vc[i].vers &&
                       room[6] == vc[i].desc,
                   vc[i].what);
            lc_client_hs_free(hs);
        }
    }

    /* THE KEY THE REFERENCE RETAINS is the first classical share's, but the peer key is now
     * parsed on its declared curve (vendor/utls/key_schedule.go:186-209).
     * The shipped table offers X25519MLKEM768, X25519 and secp256r1, so a server naming secp256r1
     * with either a 65-byte share or a 32-byte share is refused 47. The old uTLS helper
     * accepted the 32-byte share as X25519, ignoring the declared curve. */
    {
        lc_client_hs *hs = armed(table, &table_len);
        if (hs != NULL) {
            expect(hs->keys.have_p256 && hs->keys.ecdhe_group == LC_GROUP_X25519,
                   "the shipped hello carries a secp256r1 share, and X25519 is its first classical");
            uint8_t rec[512];
            size_t  n = server_hello(hs, LC_GROUP_SECP256R1, LC_P256_POINT, NULL, 0u, rec, sizeof rec);
            (void)drive(hs, rec, n);
            expect(hs->alert_pending == 1 && hs->alert_desc == LC_ALERT_ILLEGAL_PARAMETER,
                   "a server choosing secp256r1 with a 65-byte share is refused 47, as uTLS refuses it");
            lc_client_hs_free(hs);
        }
        hs = armed(table, &table_len);
        if (hs != NULL) {
            uint8_t rec[512];
            size_t  n = server_hello(hs, LC_GROUP_SECP256R1, LC_X25519_KEY, NULL, 0u, rec, sizeof rec);
            (void)drive(hs, rec, n);
            expect(hs->ph == PH_FAILED && hs->alert_pending == 1 &&
                       hs->alert_desc == LC_ALERT_ILLEGAL_PARAMETER,
                   "a P-256 share of 32 bytes is refused on its declared curve (47)");
            lc_client_hs_free(hs);
        }
    }

    printf("\nthe record a caller that cannot block asks for\n");

    /* ⚠️ THE SEAM THIS WHOLE FILE NEARLY MISSED. Every check above proves an alert is CHOSEN, and
     * for a long time that was all any of them proved: lc-tunnel drives the handshake from an event
     * loop, never called the blocking writer, and threw the choice away with the struct. The one
     * program that flushed — lc-probe, through lc_client_hs_run — was also the one every hardware
     * check used, so the product shipped without a single handshake alert and nothing went red.
     *
     * lc_client_hs_alert_record is what a caller owning a non-blocking socket asks for instead. It
     * must hand back the SAME bytes the writer would put on the wire, and it must clear the debt so
     * that a refusal cannot become two alerts. */
    {
        lc_client_hs *hs = armed(table, &table_len);
        if (hs != NULL) {
            hs_alert(hs, LC_ALERT_RECORD_OVERFLOW);

            uint8_t rec[LC_REC_MAX_WIRE];
            size_t  n = lc_client_hs_alert_record(hs, rec, sizeof rec);
            const uint8_t want[7] = { 0x15u, 0x03u, 0x01u, 0x00u, 0x02u, 0x02u, 0x16u };
            expect(n == 7 && memcmp(rec, want, 7) == 0,
                   "the record handed to a non-blocking caller is the byte-for-byte alert");

            size_t again = lc_client_hs_alert_record(hs, rec, sizeof rec);
            expect(again == 0, "and asking twice yields nothing — one refusal is one alert");
            lc_client_hs_free(hs);
        }

        /* A buffer that cannot hold one must not swallow the debt: nothing was built, so the alert
         * is still owed and the next caller with room gets it.
         *
         * ⚠️ TWELVE, NOT FOUR, and the difference is the whole point. Four is refused by any
         * threshold. Twelve is larger than the unkeyed record and smaller than the sealed one, so
         * it is exactly the size that got past a guard written against the SMALLER form: past the
         * check, into a sealing failure, out with the debt already cleared and no alert anywhere.
         * A test that only tried four would have called that green. */
        hs = armed(table, &table_len);
        if (hs != NULL) {
            hs_alert(hs, LC_ALERT_UNEXPECTED_MESSAGE);
            uint8_t small[12];
            expect(lc_client_hs_alert_record(hs, small, sizeof small) == 0 && hs->alert_pending == 1,
                   "a buffer between the unkeyed and sealed sizes leaves the alert owed");

            uint8_t room[LC_CLIENT_ALERT_MAX];
            expect(lc_client_hs_alert_record(hs, room, sizeof room) == 7,
                   "and the next caller with room still gets it");
            lc_client_hs_free(hs);
        }
    }

    /* ⚠️ A FIRST RECORD WHOSE VERSION IS >= 0x1000 — REFUSED, AND IN SILENCE.
     *
     * The other half of vendor/utls/conn.go:666-673, and the half this client did not have until
     * 2026-08-29: `(typ != Alert && typ != Handshake) || vers >= 0x1000`. The header of this file
     * has cited that line since it was written, for the `typ` half; the version half was missing in
     * client.c and nothing here asked about it, so the citation covered a gap instead of a rule.
     *
     * `16 FF FF 00 05` is a handshake record — the type dispatcher lets it through — so before the
     * fix it was parsed as a ServerHello and answered with an alert. The reference answers with a
     * bare FIN. Both halves are asserted: the refusal happens, and NOTHING is queued to be sent.
     *
     * 0x0FFF is the last version this rule accepts and 0x1000 the first it refuses; testing only
     * something absurd like 0xFFFF would pass against an off-by-one in either direction. The
     * accepted one must not be refused BY THIS RULE — it goes on to fail as a malformed hello,
     * which is a different refusal and is allowed to speak. */
    {
        /* WHOLE RECORDS, header and body: the dispatcher these three exercise runs only once a
         * complete record is in hand, and a five-byte header alone leaves the machine waiting for
         * the body it announced. The first version of this case fed the header by itself, and two
         * of the three assertions failed for that reason and not for the one under test — which is
         * the failure mode a test must never have, since it reads as a verdict on the code. */
        lc_client_hs *hs = armed(table, &table_len);
        if (hs != NULL) {
            const uint8_t bad[10] = { 0x16u, 0xffu, 0xffu, 0x00u, 0x05u,
                                      0x02u, 0x00u, 0x00u, 0x01u, 0x00u };
            (void)drive(hs, bad, sizeof bad);
            expect(hs->ph == PH_FAILED, "a first record with version 0xffff is refused");
            expect(hs->alert_pending == 0,
                   "and refused in silence, as the reference's header error is");
            lc_client_hs_free(hs);
        }

        /* 0x0fff is the last version the rule accepts, so this record must reach the parser instead
         * — where its truncated ServerHello is refused WITH an alert. That the answer is audible is
         * what proves the silent rule did not fire; asserting only "not failed" would pass against
         * a machine that never looked at the record at all. */
        hs = armed(table, &table_len);
        if (hs != NULL) {
            const uint8_t edge[10] = { 0x16u, 0x0fu, 0xffu, 0x00u, 0x05u,
                                       0x02u, 0x00u, 0x00u, 0x01u, 0x00u };
            (void)drive(hs, edge, sizeof edge);
            expect(hs->alert_pending == 1,
                   "while 0x0fff, the last below the rule, reaches the parser and is answered");
            lc_client_hs_free(hs);
        }

        /* And the byte that IS answered, so the two are pinned against each other: uTLS tests 0x80
         * before the rule above, so a record that is both an SSLv2 header and an impossible version
         * gets the alert rather than the silence. */
        hs = armed(table, &table_len);
        if (hs != NULL) {
            const uint8_t sslv2[10] = { 0x80u, 0xffu, 0xffu, 0x00u, 0x05u,
                                        0x00u, 0x00u, 0x00u, 0x00u, 0x00u };
            (void)drive(hs, sslv2, sizeof sslv2);
            expect(hs->ph == PH_FAILED && hs->alert_pending == 1 &&
                       hs->alert_desc == LC_ALERT_PROTOCOL_VERSION,
                   "an SSLv2 header still gets protocol_version, version rule notwithstanding");
            lc_client_hs_free(hs);
        }
    }

    /* ⚠️ A KEY SHARE THIS CLIENT CANNOT USE — alert 47, and it was SILENT until 2026-08-29.
     *
     * Found by the reverse sieve: the shared_for failure path set PH_FAILED and returned without
     * hs_alert, so the caller hung up with a bare FIN while the reference sends illegal_parameter
     * (vendor/utls/handshake_client_tls13.go:536-541 for a group it did not offer, :601-605 for a
     * share it cannot use). No key exists at this stage, so the reference's alert travels in the
     * clear — seven bytes against our silence, which is a distinguisher one record long.
     *
     * Two cases, because the path has two doors. secp384r1 is the probe's door: this client
     * ADVERTISES 0x0018 in supported_groups and never carries a key for it (tls/kex.h), so any
     * on-path answer selecting it lands here. A short x25519 share is the other: the group is one
     * we key, and the length is what fails. */
    {
        lc_client_hs *hs = armed(table, &table_len);
        if (hs != NULL) {
            uint8_t rec[512];
            size_t  n = server_hello(hs, 0x0018u, 2u, NULL, 0u, rec, sizeof rec);
            expect(n > 0, "a ServerHello selecting secp384r1 is built");
            (void)drive(hs, rec, n);
            expect(hs->alert_pending == 1 && hs->alert_desc == LC_ALERT_ILLEGAL_PARAMETER,
                   "a group we advertise but never key is refused with illegal_parameter (47)");
            lc_client_hs_free(hs);
        }

        hs = armed(table, &table_len);
        if (hs != NULL) {
            uint8_t rec[512];
            size_t  n = server_hello(hs, 0x001du, 2u, NULL, 0u, rec, sizeof rec);
            (void)drive(hs, rec, n);
            expect(hs->alert_pending == 1 && hs->alert_desc == LC_ALERT_ILLEGAL_PARAMETER,
                   "and so is an x25519 share of the wrong length");
            lc_client_hs_free(hs);
        }
    }

    printf("\nthe second hello a retry asks for\n");

    {
        lc_client_hs *hs = armed_from("test/fphello/chrome.fpt", table, &table_len);
        if (hs != NULL) {
            /* Exercise an offered GREASE share from the actual Chrome preset.
             * keyExchangeForCurveID cannot implement GREASE; latest uTLS sends
             * internal_error before attempting ECDH (handshake_client_tls13.go:576-580). */
            uint8_t rec[512];
            expect(hs->keys.grease_group != 0u, "the Chrome hello really offers a GREASE key share");
            size_t n = server_hello(hs, hs->keys.grease_group, 2u, NULL, 0u, rec, sizeof rec);
            expect(n > 0, "a ServerHello selecting an offered GREASE share is built");
            (void)drive(hs, rec, n);
            expect(hs->ph == PH_FAILED && hs->alert_pending == 1 &&
                       hs->alert_desc == LC_ALERT_INTERNAL_ERROR,
                   "an offered GREASE group with no key exchange gets internal_error (80)");
            lc_client_hs_free(hs);
        }
    }

    /* ⚠️ WHAT IS ASSERTED IS THE MEASURED PROPERTY, not a guess about it. tools/fp's `retry`
     * subcommand drove uTLS through a HelloRetryRequest and dumped both messages: hello2 is hello1
     * with the key_share extension replaced and NOTHING else — random carried over, session id
     * carried over, and the 339 bytes after key_share identical to the byte. That is the shape this
     * client must produce, so that is what these cases check, on the real builder output. */
    {
        lc_client_hs *hs = armed(table, &table_len);
        if (hs != NULL) {
            uint8_t first[MAX_HELLO_OUT];
            size_t  first_len = hs->info.len;
            memcpy(first, hs->hello, first_len);
            size_t sid_off = hs->info.sid_off;

            uint8_t rec[512];
            size_t  n = server_hello(hs, 0x0018u, 0u, NULL, 0u, rec, sizeof rec); /* 0 share = a retry */
            expect(n > 0, "a HelloRetryRequest naming secp384r1 is built");
            (void)drive(hs, rec, n);

            expect(hs->ph != PH_FAILED && hs->retried == 1,
                   "the client answers it instead of stopping");
            expect(hs->info.slot_count == 1 && hs->info.slots[0].group == 0x0018u &&
                       hs->info.slots[0].len == LC_P384_POINT,
                   "and the second hello offers exactly one share, secp384r1, 97 bytes");
            expect(memcmp(first + 6, hs->hello + 6, 32) == 0,
                   "the random is carried over, as the reference carries it");
            expect(memcmp(first + sid_off, hs->hello + sid_off, 32) == 0,
                   "and so is the session id, which is where REALITY's stamp lives");

            /* Everything after key_share must be byte-identical — the 339 bytes the capture showed.
             * Compared from the END, because that is where the two messages line up: the key_share
             * shrank, so every offset before it matches and every offset after it has moved. */
            size_t tail = 300u;
            expect(first_len > tail && hs->info.len > tail &&
                       memcmp(first + first_len - tail, hs->hello + hs->info.len - tail, tail) == 0,
                   "and every byte after the key share is the first hello's, unchanged");
            lc_client_hs_free(hs);
        }

        /* A retry asking for a group the first hello already offered: illegal_parameter, because a
         * server asking for what it already had is a server doing something no server does. */
        hs = armed(table, &table_len);
        if (hs != NULL) {
            uint8_t rec[512];
            size_t  n = server_hello(hs, 0x001du, 0u, NULL, 0u, rec, sizeof rec);
            (void)drive(hs, rec, n);
            expect(hs->alert_pending == 1 && hs->alert_desc == LC_ALERT_ILLEGAL_PARAMETER,
                   "a retry asking for a group already offered is refused with 47");
            lc_client_hs_free(hs);
        }

        /* ⚠️ A RETRY CARRYING A COOKIE, AND WHAT IS ASSERTED IS THE REFERENCE'S RULE RATHER THAN A
         * POSITION. The reference inserts the echo at `p.Intn(len(Extensions) - 2)`
         * (vendor/utls/handshake_client_tls13.go:413-419), so there is nothing constant to compare
         * against and a test that pinned one index would be pinning our own coin toss. Measured
         * with `tools/fp retry -cookie` over twenty runs: indices 0 through 11 of fifteen.
         *
         * What IS constant, and is what these check: the bytes come back verbatim, the count grows
         * by exactly one, at least two extensions still follow the cookie (the reference's -2), and
         * every other extension keeps the order it had in the first hello. */
        hs = armed(table, &table_len);
        if (hs != NULL) {
            static const uint8_t cookie[16] = {
                0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
                0x88u, 0x99u, 0xaau, 0xbbu, 0xccu, 0xddu, 0xeeu, 0xffu,
            };
            struct exts e1, e2;
            int         ok1 = read_exts(hs->hello, hs->info.len, hs->info.sid_off, hs->info.sid_len,
                                        &e1) == 0;

            uint8_t rec[512];
            size_t  n = server_hello(hs, 0x0018u, 0u, cookie, sizeof cookie, rec, sizeof rec);
            (void)drive(hs, rec, n);
            expect(ok1 && hs->ph != PH_FAILED && hs->retried == 1,
                   "a retry carrying a cookie is answered rather than refused");

            int ok2 = read_exts(hs->hello, hs->info.len, hs->info.sid_off, hs->info.sid_len,
                                &e2) == 0;
            expect(ok2 && e2.cookie != NULL && e2.cookie_len == sizeof cookie + 2u &&
                       ((size_t)e2.cookie[0] << 8 | e2.cookie[1]) == sizeof cookie &&
                       memcmp(e2.cookie + 2, cookie, sizeof cookie) == 0,
                   "the cookie comes back verbatim, framed as opaque cookie<1..2^16-1>");
            expect(ok2 && e2.n == e1.n + 1u && e1.n >= 3u && e2.cookie_at <= e1.n - 3u,
                   "at an index the draw can reach, with at least two extensions still after it");

            size_t j = 0;
            int    same = ok2;
            for (size_t i = 0; same && i < e2.n; i++) {
                if (i == e2.cookie_at)
                    continue;
                if (j >= e1.n || e2.type[i] != e1.type[j])
                    same = 0;
                j++;
            }
            expect(same && j == e1.n,
                   "and nothing else moved: the other extensions keep the first hello's order");
            lc_client_hs_free(hs);
        }

        /* ⚠️ A COOKIE-ONLY RETRY IS LEGAL AND WAS REFUSED UNTIL 2026-08-30. RFC 8446 4.1.4 lets
         * a HelloRetryRequest carry a cookie and no selected_group — a server checking the return
         * address without keeping state — and the reference walks such a message past its
         * illegal_parameter and past the whole key-share branch
         * (vendor/utls/handshake_client_tls13.go:311-346). This client sent group 0 into
         * key_share_len_for, got 0 back and answered illegal_parameter to every one of them. The
         * fault was unreachable while a cookie could not be echoed at all, which is why closing
         * the cookie is what exposed it. */
        hs = armed(table, &table_len);
        if (hs != NULL) {
            static const uint8_t ck2[8] = { 0xdeu, 0xadu, 0xbeu, 0xefu, 0x01u, 0x02u, 0x03u, 0x04u };
            struct exts e1, e2;
            int         ok1 = read_exts(hs->hello, hs->info.len, hs->info.sid_off, hs->info.sid_len,
                                        &e1) == 0;
            size_t      len1 = hs->info.len;
            unsigned    slots1 = hs->info.slot_count;
            uint16_t    grp1 = hs->info.slot_count > 0u ? hs->info.slots[0].group : 0u;

            uint8_t rec[512];
            size_t  n = server_hello(hs, 0x0000u, 0u, ck2, sizeof ck2, rec, sizeof rec);
            (void)drive(hs, rec, n);
            expect(ok1 && hs->ph != PH_FAILED && hs->retried == 1,
                   "a retry asking only for a cookie is answered, not refused");

            int ok2 = read_exts(hs->hello, hs->info.len, hs->info.sid_off, hs->info.sid_len,
                                &e2) == 0;
            expect(ok2 && e2.cookie != NULL && e2.cookie_len == sizeof ck2 + 2u &&
                       memcmp(e2.cookie + 2, ck2, sizeof ck2) == 0,
                   "with the cookie echoed and nothing else added");
            /* The key shares are the FIRST hello's, untouched: no group was named, so there is
             * nothing to replace and no private half to draw again. */
            expect(hs->info.slot_count == slots1 &&
                       (slots1 == 0u || hs->info.slots[0].group == grp1),
                   "and the first hello's key shares carried over, not rebuilt");
            expect(hs->info.len == len1 + 4u + 2u + sizeof ck2,
                   "so the second hello is the first plus exactly one cookie extension");
            lc_client_hs_free(hs);
        }

        /* A retry that names no group AND carries no cookie asks for nothing at all. */
        hs = armed(table, &table_len);
        if (hs != NULL) {
            uint8_t rec[512];
            size_t  n = server_hello(hs, 0x0000u, 0u, NULL, 0u, rec, sizeof rec);
            (void)drive(hs, rec, n);
            expect(hs->alert_pending == 1 && hs->alert_desc == LC_ALERT_ILLEGAL_PARAMETER,
                   "a retry that changes nothing is refused with 47, as the reference refuses it");
            lc_client_hs_free(hs);
        }

        /* And a second retry: unexpected_message, whatever it asks for. */
        hs = armed(table, &table_len);
        if (hs != NULL) {
            uint8_t rec[512];
            size_t  n = server_hello(hs, 0x0018u, 0u, NULL, 0u, rec, sizeof rec);
            (void)drive(hs, rec, n);
            /* ⚠️ THE SECOND HELLO HAS TO BE TAKEN BEFORE ANYTHING ELSE IS FED. After a retry the
             * machine is WANT_WRITE — it has a hello queued — and drive() only feeds while it is
             * WANT_READ, so a record pushed now would sit unread and the case would fail for that
             * reason rather than the one under test. The run loop drains the same way. */
            size_t out_n = 0;
            /* Both writes — the ChangeCipherSpec, then the hello. */
            do {
                (void)lc_client_hs_out(hs, &out_n);
                lc_client_hs_out_taken(hs, out_n);
            } while (out_n > 0);
            size_t again = server_hello(hs, 0x0019u, 0u, NULL, 0u, rec, sizeof rec);
            (void)drive(hs, rec, again);
            expect(hs->alert_pending == 1 && hs->alert_desc == LC_ALERT_UNEXPECTED_MESSAGE,
                   "and a second retry is refused with unexpected_message (10)");
            lc_client_hs_free(hs);
        }
    }

    printf("\nwhat a record carries behind the ServerHello\n");

    /* c.hand OUTLIVES THE KEY CHANGE. Whatever the ServerHello's record carried after it is where
     * the reference's next readHandshake starts, before any record is read
     * (vendor/utls/conn.go:1082-1090), and a record of another type arriving while it is there is
     * unexpected_message (:707-710). So an EncryptedExtensions in the same plaintext record is read
     * as the flight's first message at once, two stray bytes behind the hello make the next
     * ChangeCipherSpec a refusal, and a retry with the second ServerHello behind it is answered
     * and then read on without waiting. */
    {
        static const uint8_t ee[6] = { 0x08, 0x00, 0x00, 0x02, 0x00, 0x00 };
        static const uint8_t ccs[6] = { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
        uint8_t rec[1024];

        lc_client_hs *hs = armed(table, &table_len);
        if (hs != NULL) {
            size_t n = server_hello(hs, 0x001du, 32u, NULL, 0u, rec, sizeof rec);
            memcpy(rec + n, ee, sizeof ee);
            size_t body = n - 5u + sizeof ee;
            rec[3] = (uint8_t)(body >> 8);
            rec[4] = (uint8_t)body;
            (void)drive(hs, rec, n + sizeof ee);
            expect(hs->ph == PH_FLIGHT && hs->flight == LC_FLIGHT_CERT && hs->alert_pending == 0,
                   "an EncryptedExtensions behind the ServerHello in its record is read at once");
            lc_client_hs_free(hs);
        }

        hs = armed(table, &table_len);
        if (hs != NULL) {
            size_t n = server_hello(hs, 0x001du, 32u, NULL, 0u, rec, sizeof rec);
            rec[n] = 0x08u;
            rec[n + 1u] = 0x00u;
            size_t body = n - 5u + 2u;
            rec[3] = (uint8_t)(body >> 8);
            rec[4] = (uint8_t)body;
            (void)drive(hs, rec, n + 2u);
            int waiting = hs->ph == PH_FLIGHT && hs->alert_pending == 0;
            (void)drive(hs, ccs, sizeof ccs);
            expect(waiting && hs->alert_pending == 1 && hs->alert_desc == LC_ALERT_UNEXPECTED_MESSAGE,
                   "two bytes behind it make the next ChangeCipherSpec unexpected_message");
            lc_client_hs_free(hs);
        }

        hs = armed(table, &table_len);
        if (hs != NULL) {
            /* The retry names secp384r1, and the second ServerHello behind it answers with a
             * share that is no secp384r1 point — so reading it at once shows as the 47 its key
             * exchange draws, with no further record fed. The session id is carried over from the
             * first hello, which is what lets both be built now. */
            uint8_t sh2[512];
            size_t  n = server_hello(hs, 0x0018u, 0u, NULL, 0u, rec, sizeof rec);
            size_t  m = server_hello(hs, 0x0018u, LC_P384_POINT, NULL, 0u, sh2, sizeof sh2);
            memcpy(rec + n, sh2 + 5u, m - 5u);
            size_t body = n - 5u + m - 5u;
            rec[3] = (uint8_t)(body >> 8);
            rec[4] = (uint8_t)body;
            lc_client cl;
            memset(&cl, 0, sizeof cl);
            (void)drive(hs, rec, n + m - 5u);
            size_t out_n = 0;
            do {
                (void)lc_client_hs_out(hs, &out_n);
                lc_client_hs_out_taken(hs, out_n);
            } while (out_n > 0);
            lc_client_progress p = lc_client_hs_step(hs, &cl);
            expect(hs->retried == 1 && p == LC_HS_FAILED && hs->alert_pending == 1 &&
                       hs->alert_desc == LC_ALERT_ILLEGAL_PARAMETER,
                   "a second ServerHello behind the retry is read without waiting for a record");
            lc_client_hs_free(hs);
        }
    }

    /* AND THE CERTIFICATE GOES INTO THE TRANSCRIPT AS THE REFERENCE MARSHALS IT AGAIN, not as it
     * came (vendor/utls/handshake_messages.go:2009-2023): an entry extension uTLS does not keep is
     * in the bytes and not in the hash. Fed as plaintext behind the ServerHello, which is the path
     * above, so no record has to be sealed; the hash is then rebuilt by hand both ways. */
    {
        lc_client_hs *hs = armed(table, &table_len);
        if (hs != NULL) {
            static uint8_t rec[2048];
            static uint8_t hello[4096];
            size_t         hello_len = hs->info.len;
            memcpy(hello, hs->hello, hello_len);

            size_t n = server_hello(hs, 0x001du, 32u, NULL, 0u, rec, sizeof rec);
            size_t sh_len = n - 5u;
            static const uint8_t ee[6] = { 0x08, 0x00, 0x00, 0x02, 0x00, 0x00 };
            memcpy(rec + n, ee, sizeof ee);
            size_t at = n + sizeof ee;

            /* Certificate: empty context, one entry — the certificate and an extension 0x1234. */
            size_t cert_at = at;
            size_t entry = 3u + cv_ed_cert_len + 2u + 7u;
            size_t body_len = 1u + 3u + entry;
            rec[at++] = 0x0bu;
            rec[at++] = (uint8_t)(body_len >> 16); rec[at++] = (uint8_t)(body_len >> 8);
            rec[at++] = (uint8_t)body_len;
            rec[at++] = 0x00u;
            rec[at++] = (uint8_t)(entry >> 16); rec[at++] = (uint8_t)(entry >> 8);
            rec[at++] = (uint8_t)entry;
            rec[at++] = (uint8_t)(cv_ed_cert_len >> 16); rec[at++] = (uint8_t)(cv_ed_cert_len >> 8);
            rec[at++] = (uint8_t)cv_ed_cert_len;
            memcpy(rec + at, cv_ed_cert, cv_ed_cert_len);
            at += cv_ed_cert_len;
            static const uint8_t ext[9] = { 0x00, 0x07, 0x12, 0x34, 0x00, 0x03, 0xaa, 0xbb, 0xcc };
            memcpy(rec + at, ext, sizeof ext);
            at += sizeof ext;

            size_t rbody = at - 5u;
            rec[3] = (uint8_t)(rbody >> 8);
            rec[4] = (uint8_t)rbody;
            (void)drive(hs, rec, at);

            uint8_t got[LC_HASH_MAX], want[LC_HASH_MAX], wire[LC_HASH_MAX], re[2048];
            size_t  re_len = lc_cert13_remarshal(rec + cert_at + 4u, body_len, re, sizeof re);
            lc_transcript a, b;
            int ok = hs->ph == PH_FLIGHT && hs->flight == LC_FLIGHT_CV && re_len == at - cert_at - 7u &&
                     lc_transcript_snapshot(&hs->tr, got) == 0 &&
                     lc_transcript_init(&a, hs->hash) == 0;
            if (ok) {
                lc_transcript_add(&a, hello, hello_len);
                lc_transcript_add(&a, rec + 5u, sh_len);
                lc_transcript_add(&a, ee, sizeof ee);
                ok = lc_transcript_init(&b, hs->hash) == 0;
                lc_transcript_add(&b, hello, hello_len);
                lc_transcript_add(&b, rec + 5u, sh_len);
                lc_transcript_add(&b, ee, sizeof ee);
                lc_transcript_add(&a, re, re_len);
                lc_transcript_add(&b, rec + cert_at, at - cert_at);
                ok = ok && lc_transcript_snapshot(&a, want) == 0 &&
                     lc_transcript_snapshot(&b, wire) == 0;
                lc_transcript_free(&a);
                lc_transcript_free(&b);
            }
            expect(ok && memcmp(got, want, hs->hlen) == 0 && memcmp(got, wire, hs->hlen) != 0,
                   "a Certificate with an extension uTLS drops is hashed without it");
            lc_client_hs_free(hs);
        }
    }

    printf("\nrecords that are not handshake bytes\n");

    /* Each of these is the reference's readRecordOrCCS read against ours
     * (vendor/utls/conn.go:612-804), before the version is settled, after a retry settled it, and once keys exist. The
     * answers differ between the three states, which is what the three groups are for. */
    {
        static const uint8_t warn[7] = { 0x15u, 0x03u, 0x03u, 0x00u, 0x02u, 0x01u, 0x5au };
        lc_client_hs *hs = armed(table, &table_len);
        if (hs != NULL) {
            int r = 0;
            for (unsigned i = 0; i < 32u && r == 0; i++)
                r = outcome(hs, warn, sizeof warn);
            expect(r == 0, "thirty-two warning alerts before the ServerHello are dropped, as the "
                           "reference drops them");
            expect(outcome(hs, warn, sizeof warn) == LC_ALERT_UNEXPECTED_MESSAGE,
                   "and the thirty-third is unexpected_message: too many ignored records");
            lc_client_hs_free(hs);
        }
    }
    {
        static const struct { uint8_t rec[8]; size_t len; int want; const char *what; } pre[] = {
            { { 0x15, 0x03, 0x03, 0x00, 0x03, 0x02, 0x28, 0x00 }, 8, LC_ALERT_UNEXPECTED_MESSAGE,
              "an alert record of three bytes is unexpected_message, not a silent end" },
            { { 0x15, 0x03, 0x03, 0x00, 0x01, 0x02 }, 6, LC_ALERT_UNEXPECTED_MESSAGE,
              "and so is one of a single byte" },
            { { 0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00 }, 7, -1,
              "close_notify ends the handshake in silence, as an end of stream" },
            { { 0x15, 0x03, 0x03, 0x00, 0x02, 0x03, 0x28 }, 7, LC_ALERT_UNEXPECTED_MESSAGE,
              "an alert of level three is unexpected_message" },
            { { 0x16, 0x03, 0x03, 0x00, 0x00 }, 5, LC_ALERT_UNEXPECTED_MESSAGE,
              "an empty handshake record is unexpected_message, where this client used to wait" },
            { { 0x17, 0x03, 0x03, 0x50, 0x00 }, 5, -1,
              "a first record of application data declaring 20480 bytes is refused in silence, "
              "not with record_overflow: the first-record rule comes before the length" },
        };
        for (size_t i = 0; i < sizeof pre / sizeof pre[0]; i++) {
            lc_client_hs *hs = armed(table, &table_len);
            if (hs == NULL)
                continue;
            expect(outcome(hs, pre[i].rec, pre[i].len) == pre[i].want, pre[i].what);
            lc_client_hs_free(hs);
        }
    }
    {
        /* A first message typed as a Certificate and declaring 70000 bytes: the Certificate ceiling
         * is for after the version is settled (vendor/utls/conn.go:1102-1117), so this is 64 KiB's
         * internal_error — and one declaring 60000 is simply waited for. */
        static const uint8_t big[9]   = { 0x16, 0x03, 0x03, 0x00, 0x04, 0x0b, 0x01, 0x11, 0x70 };
        static const uint8_t under[9] = { 0x16, 0x03, 0x03, 0x00, 0x04, 0x0b, 0x00, 0xea, 0x60 };
        static const uint8_t bigsh[9] = { 0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x01, 0x11, 0x70 };
        lc_client_hs *hs = armed(table, &table_len);
        if (hs != NULL) {
            expect(outcome(hs, big, sizeof big) == LC_ALERT_INTERNAL_ERROR,
                   "a first message of 70000 bytes typed as a Certificate is internal_error: the "
                   "larger ceiling is not yet in force");
            lc_client_hs_free(hs);
        }
        hs = armed(table, &table_len);
        if (hs != NULL) {
            expect(outcome(hs, under, sizeof under) == 0,
                   "while one of 60000 bytes is waited for, as the reference waits");
            lc_client_hs_free(hs);
        }
        hs = armed(table, &table_len);
        if (hs != NULL) {
            expect(outcome(hs, bigsh, sizeof bigsh) == LC_ALERT_INTERNAL_ERROR,
                   "and a ServerHello declaring 70000 bytes is internal_error too, not the "
                   "unexpected_message it shared with a wrong type");
            lc_client_hs_free(hs);
        }
    }
    {
        static const struct { uint8_t rec[7]; size_t len; int want; const char *what; } post[] = {
            { { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 }, 6, 0,
              "after a retry, the dummy ChangeCipherSpec a Go server sends is dropped — it used to "
              "end the handshake as not a handshake record" },
            { { 0x14, 0x03, 0x03, 0x00, 0x01, 0x00 }, 6, LC_ALERT_DECODE_ERROR,
              "a ChangeCipherSpec whose byte is not 0x01 is decode_error" },
            { { 0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x5a }, 7, -1,
              "a warning alert once the version is settled ends the handshake in silence: TLS 1.3 "
              "has no warnings" },
            { { 0x17, 0x03, 0x03, 0x00, 0x01, 0x00 }, 6, LC_ALERT_UNEXPECTED_MESSAGE,
              "application data with no key yet is unexpected_message" },
        };
        for (size_t i = 0; i < sizeof post / sizeof post[0]; i++) {
            lc_client_hs *hs = after_retry(table, &table_len);
            expect(hs != NULL, "a handshake reaches the state after a retry");
            if (hs == NULL)
                continue;
            expect(outcome(hs, post[i].rec, post[i].len) == post[i].want, post[i].what);
            lc_client_hs_free(hs);
        }
    }
    {
        static uint8_t forged[5 + 32] = { 0x17, 0x03, 0x03, 0x00, 0x20 };
        memset(forged + 5, 0x33, 32);
        static const uint8_t plain_alert[7] = { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28 };
        static const uint8_t sslv2[6]       = { 0x80, 0x03, 0x03, 0x00, 0x01, 0x00 };
        static const uint8_t ccs[6]         = { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
        static const uint8_t ccs2[7]        = { 0x14, 0x03, 0x03, 0x00, 0x02, 0x01, 0x01 };
        static const struct { const uint8_t *rec; size_t len; int want; const char *what; } fl[] = {
            { forged, sizeof forged, LC_ALERT_BAD_RECORD_MAC,
              "in the flight, a record that does not open is bad_record_mac, not decrypt_error" },
            { plain_alert, sizeof plain_alert, LC_ALERT_BAD_RECORD_MAC,
              "a plaintext alert in the flight is bad_record_mac too: the tag covers the type" },
            { sslv2, sizeof sslv2, LC_ALERT_PROTOCOL_VERSION,
              "a record of type 0x80 in the flight is protocol_version, as on the first record" },
            { ccs, sizeof ccs, 0, "a ChangeCipherSpec in the flight is dropped" },
            { ccs2, sizeof ccs2, LC_ALERT_DECODE_ERROR, "and one of two bytes is decode_error" },
        };
        for (size_t i = 0; i < sizeof fl / sizeof fl[0]; i++) {
            lc_client_hs *hs = in_flight(table, &table_len);
            expect(hs != NULL, "a handshake reaches the encrypted flight");
            if (hs == NULL)
                continue;
            expect(outcome(hs, fl[i].rec, fl[i].len) == fl[i].want, fl[i].what);
            lc_client_hs_free(hs);
        }
    }

    /* THE ChangeCipherSpec THE REFERENCE HAD BUFFERED, flushed ahead of the alert.
     *
     * uTLS sets c.buffering before processServerHello, buffers the dummy ChangeCipherSpec right
     * after it, and on any error flushes what it holds (vendor/utls/handshake_client_tls13.go:136-142,
     * vendor/utls/u_conn.go:371-375). So a refusal from the ServerHello's own checks leaves as the
     * alert alone, and every refusal after them leaves as `14 03 03 00 01 01` and then the alert —
     * sealed once the handshake keys exist. The three states, each with the record it must yield. */
    {
        static const uint8_t ccs[6] = { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
        uint8_t room[LC_CLIENT_ALERT_MAX];

        lc_client_hs *hs = in_flight(table, &table_len);
        if (hs != NULL) {
            static uint8_t forged[5 + 32] = { 0x17, 0x03, 0x03, 0x00, 0x20 };
            memset(forged + 5, 0x33, 32);
            (void)outcome(hs, forged, sizeof forged);
            size_t n = lc_client_hs_alert_record(hs, room, sizeof room);
            expect(n == 6u + 5u + 19u && memcmp(room, ccs, 6) == 0 && room[6] == 0x17u &&
                       room[9] == 0x00u && room[10] == 0x13u,
                   "a refusal in the flight leaves as the ChangeCipherSpec and then the sealed "
                   "alert, thirty bytes, as the reference flushes them");
            lc_client_hs_free(hs);
        }

        hs = armed(table, &table_len);
        if (hs != NULL) {
            uint8_t rec[512];
            size_t  n = server_hello(hs, 0x001du, 31u, NULL, 0u, rec, sizeof rec);
            (void)outcome(hs, rec, n);
            size_t m = lc_client_hs_alert_record(hs, room, sizeof room);
            expect(m == 13u && memcmp(room, ccs, 6) == 0 && room[6] == 0x15u && room[12] == 0x2fu,
                   "a key share that does not work is refused after the ChangeCipherSpec was "
                   "buffered: the ChangeCipherSpec and a plaintext illegal_parameter");
            lc_client_hs_free(hs);
        }

        hs = armed(table, &table_len);
        if (hs != NULL) {
            static const uint8_t ck[1] = { 0x5a };
            uint8_t rec[512];
            size_t  n = server_hello(hs, 0x001du, 32u, ck, sizeof ck, rec, sizeof rec);
            (void)outcome(hs, rec, n);
            size_t m = lc_client_hs_alert_record(hs, room, sizeof room);
            expect(m == 7u && room[0] == 0x15u && room[6] == LC_ALERT_UNSUPPORTED_EXTENSION,
                   "while a refusal by the ServerHello's own checks leaves as the alert alone");
            lc_client_hs_free(hs);
        }

        hs = after_retry(table, &table_len);
        if (hs != NULL) {
            static const uint8_t bad_ccs[6] = { 0x14, 0x03, 0x03, 0x00, 0x01, 0x00 };
            (void)outcome(hs, bad_ccs, sizeof bad_ccs);
            size_t m = lc_client_hs_alert_record(hs, room, sizeof room);
            expect(m == 7u && room[0] == 0x15u,
                   "and after a retry, which has already sent its ChangeCipherSpec, alone too");
            lc_client_hs_free(hs);
        }

        /* Past the second ServerHello's checks, where the first handshake would owe one: the
         * retry's ChangeCipherSpec already went out ahead of the second hello, and sentDummyCCS
         * makes the reference's second call a no-op (vendor/utls/handshake_client_tls13.go:242-244). */
        hs = after_retry(table, &table_len);
        if (hs != NULL) {
            uint8_t rec[512];
            size_t  n = server_hello(hs, 0x0018u, 10u, NULL, 0u, rec, sizeof rec);
            (void)outcome(hs, rec, n);
            size_t m = lc_client_hs_alert_record(hs, room, sizeof room);
            expect(m == 7u && room[0] == 0x15u && room[6] == LC_ALERT_ILLEGAL_PARAMETER,
                   "and a retried handshake refused at its key share sends the alert without a "
                   "second ChangeCipherSpec");
            lc_client_hs_free(hs);
        }
    }

    /* A HANDSHAKE TYPE THE REFERENCE DOES NOT KNOW draws unexpected_message TWICE — uTLS's hook
     * for its extra types sends one from its default case and the switch it returns to sends the
     * second (vendor/utls/u_conn.go:836-837, vendor/utls/conn.go:1184) — while a type it knows,
     * arriving where it is not expected, draws it once. Both as the first message and in the
     * flight, where the two copies are sealed under consecutive sequence numbers. */
    {
        static const uint8_t alert10[7] = { 0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x0a };
        static const uint8_t unknown[9] = { 0x16, 0x03, 0x03, 0x00, 0x04, 0x07, 0x00, 0x00, 0x00 };
        static const uint8_t known[9]   = { 0x16, 0x03, 0x03, 0x00, 0x04, 0x0e, 0x00, 0x00, 0x00 };
        uint8_t room[LC_CLIENT_ALERT_MAX];

        lc_client_hs *hs = armed(table, &table_len);
        if (hs != NULL) {
            (void)outcome(hs, unknown, sizeof unknown);
            size_t n = lc_client_hs_alert_record(hs, room, sizeof room);
            uint8_t room2[LC_CLIENT_ALERT_MAX], room3[LC_CLIENT_ALERT_MAX];
            size_t  n2 = lc_client_hs_alert_record(hs, room2, sizeof room2);
            size_t  n3 = lc_client_hs_alert_record(hs, room3, sizeof room3);
            expect(n == 7u && n2 == 7u && n3 == 0u && memcmp(room, alert10, 7) == 0 &&
                       memcmp(room2, alert10, 7) == 0,
                   "a first message of an unknown type is answered with two unexpected_message "
                   "records, as uTLS answers it — in two writes, as nothing is buffered yet");
            lc_client_hs_free(hs);
        }
        hs = armed(table, &table_len);
        if (hs != NULL) {
            (void)outcome(hs, known, sizeof known);
            size_t n = lc_client_hs_alert_record(hs, room, sizeof room);
            expect(n == 7u && memcmp(room, alert10, 7) == 0,
                   "while a known type in the wrong place — ServerHelloDone first — gets one");
            lc_client_hs_free(hs);
        }
    }

    printf("\nwhat an active prober reads back, in the clear\n");

    /* Everything below is answered before a key exists, so the alert leaves as a plaintext record
     * and its one descriptor byte is readable by whoever sent the message. None of it happens
     * against a real REALITY or Hysteria node — only against something crafted — which is exactly
     * the traffic this client is supposed to look ordinary to. */

    /* THE DUMMY ChangeCipherSpec ON THE RETRY PATH, and its ORDER.
     *
     * The reference sends it from sendDummyChangeCipherSpec BEFORE processHelloRetryRequest
     * (vendor/utls/handshake_client_tls13.go:91-97), with c.buffering still off, so the wire is
     * CH1 → CCS → CH2. Checking only that a CCS exists somewhere would pass on the old code too,
     * because one was already bundled with Finished; the byte that matters is that it comes first. */
    {
        lc_client_hs *hs = armed(table, &table_len);
        if (hs != NULL) {
            uint8_t rec[512];
            size_t  n = server_hello(hs, 0x0018u, 0u, NULL, 0u, rec, sizeof rec);
            (void)drive(hs, rec, n);
            size_t         out_n = 0;
            const uint8_t *q     = lc_client_hs_out(hs, &out_n);
            expect(q != NULL && out_n == 6u && q[0] == 0x14u && q[1] == 0x03u && q[2] == 0x03u &&
                       q[3] == 0x00u && q[4] == 0x01u && q[5] == 0x01u,
                   "a retry is answered with the dummy ChangeCipherSpec first, in a write of its own");
            lc_client_hs_out_taken(hs, out_n);
            q = lc_client_hs_out(hs, &out_n);
            expect(q != NULL && out_n > 5u && q[0] == 0x16u && q[1] == 0x03u && q[2] == 0x03u,
                   "and the second hello in the next (handshake_client_tls13.go:92-98, :136, :481)");
            lc_client_hs_free(hs);
        }
    }

    /* A RETRY THAT CARRIES A KEY SHARE — alert 50, not 10, but only once the retry has asked for
     * something.
     *
     * The reference's parser accepts the longer form into serverShare and the message SUCCEEDS; the
     * refusal comes afterwards, `if serverShare.group != 0 { sendAlert(alertDecodeError) }`
     * (vendor/utls/handshake_client_tls13.go:321-324). One check BEFORE it is
     * `if selectedGroup == 0 && cookie == nil` (:312-315), and a retry carrying a share instead of a
     * bare group has selectedGroup zero — so with no cookie it is 47 that goes out, and 50 is reached
     * only when a cookie gets it past that line. This test expected 50 for the cookie-less retry
     * until the checks moved into one place and ran in the reference's order. */
    {
        lc_client_hs *hs = armed(table, &table_len);
        if (hs != NULL) {
            const uint8_t exts[] = { 0x00u, 0x2bu, 0x00u, 0x02u, 0x03u, 0x04u,
                                     0x00u, 0x33u, 0x00u, 0x08u, 0x00u, 0x18u,
                                     0x00u, 0x04u, 0xa5u, 0xa5u, 0xa5u, 0xa5u };
            uint8_t       rec[512];
            size_t        n = hello_bytes(hs, hrr_random, exts, sizeof exts, rec, sizeof rec);
            (void)drive(hs, rec, n);
            expect(hs->alert_pending == 1 && hs->alert_desc == LC_ALERT_ILLEGAL_PARAMETER,
                   "a HelloRetryRequest carrying a key share and no cookie is refused with "
                   "illegal_parameter (47): it changes nothing, and that check comes first");
            lc_client_hs_free(hs);
        }
    }
    {
        lc_client_hs *hs = armed(table, &table_len);
        if (hs != NULL) {
            const uint8_t exts[] = { 0x00u, 0x2bu, 0x00u, 0x02u, 0x03u, 0x04u,
                                     0x00u, 0x33u, 0x00u, 0x08u, 0x00u, 0x18u,
                                     0x00u, 0x04u, 0xa5u, 0xa5u, 0xa5u, 0xa5u,
                                     0x00u, 0x2cu, 0x00u, 0x03u, 0x00u, 0x01u, 0x5au };
            uint8_t       rec[512];
            size_t        n = hello_bytes(hs, hrr_random, exts, sizeof exts, rec, sizeof rec);
            (void)drive(hs, rec, n);
            expect(hs->alert_pending == 1 && hs->alert_desc == LC_ALERT_DECODE_ERROR,
                   "the same retry WITH a cookie is refused with decode_error (50)");
            lc_client_hs_free(hs);
        }
    }

    /* AND ONE WHOSE SHARE DOES NOT PARSE stays a parse failure — alert 10. The inner length says
     * nine where four bytes follow, so the reference's readUint16LengthPrefixed fails and the whole
     * unmarshal returns false. Two different answers to two different faults. */
    {
        lc_client_hs *hs = armed(table, &table_len);
        if (hs != NULL) {
            const uint8_t exts[] = { 0x00u, 0x2bu, 0x00u, 0x02u, 0x03u, 0x04u,
                                     0x00u, 0x33u, 0x00u, 0x08u, 0x00u, 0x18u,
                                     0x00u, 0x09u, 0xa5u, 0xa5u, 0xa5u, 0xa5u };
            uint8_t       rec[512];
            size_t        n = hello_bytes(hs, hrr_random, exts, sizeof exts, rec, sizeof rec);
            (void)drive(hs, rec, n);
            expect(hs->alert_pending == 1 && hs->alert_desc == LC_ALERT_UNEXPECTED_MESSAGE,
                   "a retry whose key share is malformed is refused with unexpected_message (10)");
            lc_client_hs_free(hs);
        }
    }

    /* WHAT AN ORDINARY ServerHello MAY NOT CARRY, three answers the reference gives and this client
     * did not. All three are read by an on-path prober off the first message the server sends, in
     * the clear, before any key exists — and in all three this client used to say nothing at all
     * where a browser sends an alert and closes. Found by the sieve's reverse pass, which asks what
     * the reference checks that we do not. */
    {
        /* A cookie belongs to a retry: utls/handshake_client_tls13.go:522-525, alert 110. */
        lc_client_hs *hs = armed(table, &table_len);
        if (hs != NULL) {
            uint8_t       rnd[32];
            const uint8_t exts[] = { 0x00u, 0x2bu, 0x00u, 0x02u, 0x03u, 0x04u,
                                     0x00u, 0x2cu, 0x00u, 0x04u, 0x00u, 0x02u, 0xa5u, 0xa5u,
                                     0x00u, 0x33u, 0x00u, 0x08u, 0x00u, 0x1du,
                                     0x00u, 0x04u, 0xa5u, 0xa5u, 0xa5u, 0xa5u };
            uint8_t rec[512];
            memset(rnd, 0, sizeof rnd);
            size_t n = hello_bytes(hs, rnd, exts, sizeof exts, rec, sizeof rec);
            (void)drive(hs, rec, n);
            expect(hs->alert_pending == 1 && hs->alert_desc == LC_ALERT_UNSUPPORTED_EXTENSION,
                   "a cookie in an ordinary ServerHello is refused with unsupported_extension (110)");
            lc_client_hs_free(hs);
        }

        /* A bare group where a share belongs: utls/handshake_client_tls13.go:527-530, alert 50. */
        hs = armed(table, &table_len);
        if (hs != NULL) {
            uint8_t       rnd[32];
            const uint8_t exts[] = { 0x00u, 0x2bu, 0x00u, 0x02u, 0x03u, 0x04u,
                                     0x00u, 0x33u, 0x00u, 0x02u, 0x00u, 0x1du };
            uint8_t rec[512];
            memset(rnd, 0, sizeof rnd);
            size_t n = hello_bytes(hs, rnd, exts, sizeof exts, rec, sizeof rec);
            (void)drive(hs, rec, n);
            expect(hs->alert_pending == 1 && hs->alert_desc == LC_ALERT_DECODE_ERROR,
                   "a two-byte key_share in an ordinary ServerHello says decode_error (50)");
            lc_client_hs_free(hs);
        }

        /* A PSK selected out of a list we never sent: utls/handshake_client_tls13.go:543-549, alert 47.
         * The reference compares the index against its own identities; this client has none, so
         * every index fails and presence alone is the answer.
         *
         * ⚠️ AND THE KEY SHARE HERE IS THE RIGHT WIDTH ON PURPOSE, because the first version of
         * this test was vacuum. It carried x25519 with four bytes of share, which is refused for
         * its LENGTH with the same alert 47 — so the assertion passed with the psk extension
         * removed and with the code under test disabled. Checked both ways before trusting it: a
         * control run without the extension, and a mutation of the branch. A thirty-two byte share
         * is well-formed, so nothing else in this message answers 47, and the extension is the only
         * thing that can. */
        hs = armed(table, &table_len);
        if (hs != NULL) {
            uint8_t rnd[32];
            uint8_t exts[64];
            size_t  e = 0;
            /* supported_versions = TLS 1.3 */
            exts[e++] = 0x00u; exts[e++] = 0x2bu; exts[e++] = 0x00u; exts[e++] = 0x02u;
            exts[e++] = 0x03u; exts[e++] = 0x04u;
            /* pre_shared_key, selected_identity = 0 */
            exts[e++] = 0x00u; exts[e++] = 0x29u; exts[e++] = 0x00u; exts[e++] = 0x02u;
            exts[e++] = 0x00u; exts[e++] = 0x00u;
            /* key_share: x25519 with a share of the width the group requires */
            exts[e++] = 0x00u; exts[e++] = 0x33u; exts[e++] = 0x00u; exts[e++] = 0x24u;
            exts[e++] = 0x00u; exts[e++] = 0x1du; exts[e++] = 0x00u; exts[e++] = 0x20u;
            for (unsigned i = 0; i < 32u; i++)
                exts[e++] = 0xa5u;
            uint8_t rec[512];
            memset(rnd, 0, sizeof rnd);
            size_t n = hello_bytes(hs, rnd, exts, e, rec, sizeof rec);
            (void)drive(hs, rec, n);
            expect(hs->alert_pending == 1 && hs->alert_desc == LC_ALERT_ILLEGAL_PARAMETER,
                   "a pre_shared_key in a ServerHello says illegal_parameter (47)");
            lc_client_hs_free(hs);
        }
    }

    /* A FORBIDDEN EXTENSION WITH A BODY — alert 10, because the reference never gets as far as the
     * forbidden check: session_ticket sets a flag and consumes nothing, so the trailing
     * `if !extData.Empty() { return false }` fails the unmarshal. */
    {
        lc_client_hs *hs = armed(table, &table_len);
        if (hs != NULL) {
            uint8_t       rnd[32];
            const uint8_t exts[] = { 0x00u, 0x2bu, 0x00u, 0x02u, 0x03u, 0x04u,
                                     0x00u, 0x23u, 0x00u, 0x01u, 0x00u,
                                     0x00u, 0x33u, 0x00u, 0x08u, 0x00u, 0x18u,
                                     0x00u, 0x04u, 0xa5u, 0xa5u, 0xa5u, 0xa5u };
            uint8_t       rec[512];
            size_t        n;
            memset(rnd, 0, sizeof rnd);
            n = hello_bytes(hs, rnd, exts, sizeof exts, rec, sizeof rec);
            (void)drive(hs, rec, n);
            expect(hs->alert_pending == 1 && hs->alert_desc == LC_ALERT_UNEXPECTED_MESSAGE,
                   "a forbidden extension carrying a body is refused with unexpected_message (10)");
            lc_client_hs_free(hs);
        }
    }

    /* AND THE SAME EXTENSION, EMPTY, still earns 110 — it parses, so it reaches the verdict the
     * reference gives a well-formed forbidden extension. */
    {
        lc_client_hs *hs = armed(table, &table_len);
        if (hs != NULL) {
            uint8_t       rnd[32];
            const uint8_t exts[] = { 0x00u, 0x2bu, 0x00u, 0x02u, 0x03u, 0x04u,
                                     0x00u, 0x23u, 0x00u, 0x00u,
                                     0x00u, 0x33u, 0x00u, 0x08u, 0x00u, 0x18u,
                                     0x00u, 0x04u, 0xa5u, 0xa5u, 0xa5u, 0xa5u };
            uint8_t       rec[512];
            size_t        n;
            memset(rnd, 0, sizeof rnd);
            n = hello_bytes(hs, rnd, exts, sizeof exts, rec, sizeof rec);
            (void)drive(hs, rec, n);
            expect(hs->alert_pending == 1 && hs->alert_desc == LC_ALERT_UNSUPPORTED_EXTENSION,
                   "a well-formed forbidden extension is still refused with "
                   "unsupported_extension (110)");
            lc_client_hs_free(hs);
        }
    }

    /* THE DOWNGRADE CANARY — alert 47 where this used to say 109.
     *
     * A server forced down to TLS 1.2 sends no supported_versions at all, so the canary in the tail
     * of its random is the only thing that names the fault. The reference answers illegal_parameter
     * (vendor/utls/handshake_client.go:327-333). */
    {
        lc_client_hs *hs = armed(table, &table_len);
        if (hs != NULL) {
            uint8_t       rnd[32];
            const uint8_t exts[] = { 0x00u, 0x33u, 0x00u, 0x08u, 0x00u, 0x18u,
                                     0x00u, 0x04u, 0xa5u, 0xa5u, 0xa5u, 0xa5u };
            uint8_t       rec[512];
            size_t        n;
            memset(rnd, 0, sizeof rnd);
            memcpy(rnd + 24, "DOWNGRD\x01", 8);
            n = hello_bytes(hs, rnd, exts, sizeof exts, rec, sizeof rec);
            (void)drive(hs, rec, n);
            expect(hs->alert_pending == 1 && hs->alert_desc == LC_ALERT_ILLEGAL_PARAMETER,
                   "a ServerHello flagging a downgrade to TLS 1.2 is refused with "
                   "illegal_parameter (47)");
            lc_client_hs_free(hs);
        }
    }

    /* AND WITHOUT THE CANARY it is TLS 1.2, and the handshake goes on as hs12's — to
     * pickCipherSuite, which answers this hello's TLS 1.3 suite with handshake_failure
     * (vendor/utls/handshake_client.go:664-668). It was protocol_version (70) until 29.09, when this
     * client could not speak TLS 1.2 (T3), and missing_extension (109) before 2026-09-07. */
    {
        lc_client_hs *hs = armed(table, &table_len);
        if (hs != NULL) {
            uint8_t       rnd[32];
            const uint8_t exts[] = { 0x00u, 0x33u, 0x00u, 0x08u, 0x00u, 0x18u,
                                     0x00u, 0x04u, 0xa5u, 0xa5u, 0xa5u, 0xa5u };
            uint8_t       rec[512];
            size_t        n;
            memset(rnd, 0, sizeof rnd);
            n = hello_bytes(hs, rnd, exts, sizeof exts, rec, sizeof rec);
            (void)drive(hs, rec, n);
            expect(hs->alert_pending == 1 && hs->alert_desc == LC_ALERT_HANDSHAKE_FAILURE,
                   "a TLS 1.2 ServerHello without the canary goes on as TLS 1.2, and its TLS 1.3 suite is "
                   "handshake_failure (40)");
            lc_client_hs_free(hs);
        }
    }

    /* THE ORDER OF THE ENCRYPTED FLIGHT, WHICH THIS CLIENT USED TO HAVE NO OPINION ABOUT.
     *
     * Every message that arrived under the handshake keys was hashed and handed to whichever arm
     * knew it, in any order, and a type with no arm was dropped in silence. The reference reads the
     * flight as a sequence and answers anything out of place with alert 10 — from the type
     * assertion at each step (vendor/utls/handshake_client_tls13.go:625-700, :702-820, :822-871) or
     * from the default of unmarshalHandshakeMessage for a type it does not know
     * (vendor/utls/conn.go:1176-1184).
     *
     * The table is asked directly rather than through a handshake, because reaching this flight
     * needs the server's keys and the question here is only which message may follow which. */
    expect(flight_next(LC_FLIGHT_EE, LC_HS_ENCRYPTED_EXT) == LC_FLIGHT_CERT,
           "EncryptedExtensions opens the flight");
    expect(flight_next(LC_FLIGHT_EE, LC_HS_CERTIFICATE) == LC_FLIGHT_BAD,
           "and a Certificate in its place is refused");
    expect(flight_next(LC_FLIGHT_EE, LC_HS_NEW_SESSION_TICKET) == LC_FLIGHT_BAD,
           "as is a NewSessionTicket, which belongs after the handshake and not in it");
    expect(flight_next(LC_FLIGHT_CERT, LC_HS_CERTIFICATE_REQUEST) == LC_FLIGHT_CERT_SEEN_REQ,
           "a CertificateRequest may come before the Certificate");
    expect(flight_next(LC_FLIGHT_CERT_SEEN_REQ, LC_HS_CERTIFICATE_REQUEST) == LC_FLIGHT_BAD,
           "but not twice");
    expect(flight_next(LC_FLIGHT_CERT_SEEN_REQ, LC_HS_CERTIFICATE) == LC_FLIGHT_CV,
           "and the Certificate still follows it");
    expect(flight_next(LC_FLIGHT_CERT, LC_HS_COMPRESSED_CERTIFICATE) == LC_FLIGHT_CV,
           "a CompressedCertificate stands in the Certificate's place");
    expect(flight_next(LC_FLIGHT_CV, LC_HS_CERTIFICATE_VERIFY) == LC_FLIGHT_FIN,
           "CertificateVerify follows the certificate");
    expect(flight_next(LC_FLIGHT_CV, LC_HS_FINISHED) == LC_FLIGHT_BAD,
           "and a Finished that skips it is refused — the reference reads the two as one step");
    expect(flight_next(LC_FLIGHT_FIN, LC_HS_FINISHED) == LC_FLIGHT_DONE, "Finished ends the flight");
    expect(flight_next(LC_FLIGHT_DONE, LC_HS_FINISHED) == LC_FLIGHT_BAD,
           "and nothing belongs after it");
    expect(flight_next(LC_FLIGHT_CERT, 0x2au) == LC_FLIGHT_BAD,
           "a handshake type nobody defines is refused wherever it lands");

    /* THE ANSWER TO A CertificateRequest IS A MESSAGE, AND THESE ARE ITS BYTES.
     *
     * Type 0x0b, length 4, an empty request context, an empty list. Marshalled by Go as
     * `b.AddUint8(0)` for the context and a zero-length list from marshalCertificate
     * (vendor/utls/handshake_messages.go:1525-1542). A client that answers a request with silence
     * is one message short of every Go client on the wire, against the one peer that is watching
     * for the answer. */
    {
        const uint8_t want[8] = { 0x0bu, 0x00u, 0x00u, 0x04u, 0x00u, 0x00u, 0x00u, 0x00u };
        expect(memcmp(lc_empty_certificate, want, sizeof want) == 0,
               "the empty Certificate is the reference's eight bytes");
    }

    /* A CERTIFICATE MESSAGE EARNS TWO DIFFERENT REFUSALS, AND THIS CLIENT USED TO GIVE NEITHER.
     *
     * An empty list is answered where it is found — `c.sendAlert(alertDecodeError)`, "received
     * empty certificates message" (vendor/utls/handshake_client_tls13.go:759-762) — and bytes that
     * do not make a Certificate never reach that check, because unmarshal failed and
     * unmarshalHandshakeMessage, under readHandshake, has already sent alert 10. Before this, both went on to fail later at CertificateVerify,
     * wearing whatever alert that step chose. */
    {
        /* context 0, list 0: well formed, and empty. */
        const uint8_t empty[4] = { 0x00u, 0x00u, 0x00u, 0x00u };
        expect(lc_utls_cert_msg_alert(empty, sizeof empty) == LC_ALERT_DECODE_ERROR,
               "a Certificate carrying no certificates is decode_error (50)");

        /* Too short for the list length at all. */
        const uint8_t stub[2] = { 0x00u, 0x00u };
        expect(lc_utls_cert_msg_alert(stub, sizeof stub) == LC_ALERT_UNEXPECTED_MESSAGE,
               "a Certificate that does not parse is unexpected_message (10)");

        /* A list that claims more than the message holds. */
        const uint8_t lying[8] = { 0x00u, 0x00u, 0xffu, 0xffu, 0x30u, 0x00u, 0x00u, 0x00u };
        expect(lc_utls_cert_msg_alert(lying, sizeof lying) == LC_ALERT_UNEXPECTED_MESSAGE,
               "and so is one whose list runs past the message");

        /* One entry of three bytes with no extensions: the shortest thing that UNMARSHALS — and
         * then verifyServerCertificate parses it as X.509 and refuses it
         * (vendor/utls/handshake_client.go:1143-1150). This asserted 0 until 2026-09-24, when the
         * verdict read the leaf's framing and nothing of the leaf. */
        const uint8_t one[12] = { 0x00u, 0x00u, 0x00u, 0x08u, 0x00u, 0x00u,
                                  0x03u, 0x30u, 0x01u, 0x02u, 0x00u, 0x00u };
        expect(lc_utls_cert_msg_alert(one, sizeof one) == LC_ALERT_BAD_CERTIFICATE,
               "a certificate that is not X.509 is bad_certificate (42)");

        /* The whole message before the empty list: a context that is not empty fails unmarshal,
         * and that is 10 even around an empty list (vendor/utls/handshake_messages.go:1581-1597).
         * This answered 50 for it. */
        const uint8_t ctx_empty[5] = { 0x01u, 0xaau, 0x00u, 0x00u, 0x00u };
        expect(lc_utls_cert_msg_alert(ctx_empty, sizeof ctx_empty) == LC_ALERT_UNEXPECTED_MESSAGE,
               "a context that is not empty is 10 before the empty list is looked at");

        /* And with real certificates: a leaf the parser reads goes on; a malformed entry behind it
         * fails unmarshal (10); an empty or unparseable entry behind it, or an empty leaf, is 42 —
         * the first two of which passed while only the leaf was read. */
        uint8_t msg[64u + sizeof cv_ec_cert + sizeof cv_ed_cert];
        size_t  n = cert_msg(msg, cv_ec_cert, sizeof cv_ec_cert, NULL, 0);
        expect(lc_utls_cert_msg_alert(msg, n) == 0u, "a leaf that parses is one to go on with");

        /* ⚠️ AND AN Ed25519 LEAF, WHICH IS EVERY REALITY NODE'S (vendor/REALITY/auth.go:209-210).
         * mbedTLS cannot parse one; Go can. The first draft of this check asked mbedTLS alone and
         * would have answered 42 to every node this client exists to reach — nothing else in the
         * tree fed an Ed25519 certificate through it. */
        expect(lc_x509_parses(cv_ed_cert, sizeof cv_ed_cert, NULL) == 1,
               "an Ed25519 certificate parses, as it does for Go");
        n = cert_msg(msg, cv_ed_cert, sizeof cv_ed_cert, NULL, 0);
        expect(lc_utls_cert_msg_alert(msg, n) == 0u,
               "and a REALITY node's Ed25519 leaf is one to go on with");

        const uint8_t junk[3] = { 0x30u, 0x01u, 0x02u };
        n = cert_msg(msg, cv_ec_cert, sizeof cv_ec_cert, junk, sizeof junk);
        expect(lc_utls_cert_msg_alert(msg, n) == LC_ALERT_BAD_CERTIFICATE,
               "an intermediate that is not X.509 is 42, though the leaf is fine");

        n = cert_msg(msg, cv_ec_cert, sizeof cv_ec_cert, junk, 0);
        expect(lc_utls_cert_msg_alert(msg, n) == LC_ALERT_BAD_CERTIFICATE,
               "and so is an intermediate of no bytes, which unmarshal takes and the parse does not");

        n = cert_msg(msg, cv_ec_cert, sizeof cv_ec_cert, junk, sizeof junk);
        n -= 2u; /* the second entry's extensions length, cut off */
        size_t list = n - 4u;
        msg[1] = (uint8_t)(list >> 16);
        msg[2] = (uint8_t)(list >> 8);
        msg[3] = (uint8_t)list;
        expect(lc_utls_cert_msg_alert(msg, n) == LC_ALERT_UNEXPECTED_MESSAGE,
               "a malformed entry behind a good leaf fails the whole message (10)");

        n = cert_msg(msg, junk, 0, NULL, 0);
        expect(lc_utls_cert_msg_alert(msg, n) == LC_ALERT_BAD_CERTIFICATE,
               "a leaf of no bytes is 42, not 10");
    }

    printf("\n%s\n", failures == 0 ? "all ok" : "FAILURES");
    return failures == 0 ? 0 : 1;
}
