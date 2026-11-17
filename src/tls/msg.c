#include "tls/msg.h"
#include "cert/cert.h"
#include "cert/chain.h"
#include "tls/certverify.h"
#include "core/wipe.h"
#include "tls/goerr.h"

#include <stdio.h>
#include <string.h>

#include <mbedtls/md.h>

/* The random a server puts in a HelloRetryRequest instead of a real one. RFC 8446 defines it as a
 * literal constant so that a client can tell the two apart without a separate message type. */
static const uint8_t hello_retry_random[32] = {
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
};

#define EXT_KEY_SHARE 0x0033u
#define EXT_COOKIE 0x002cu
#define EXT_SUPPORTED_VERSIONS 0x002bu
/* pre_shared_key, which a server may only select from what the client offered — and this client
 * offers none. See the refusal in lc_check_server_hello. */
#define EXT_PRE_SHARED_KEY 0x0029u

/* The six a TLS 1.3 ServerHello may not carry. They are named here because the reference names
 * them, one by one, in a single condition — see the note above the check in lc_parse_server_hello. */
#define EXT_STATUS_REQUEST 0x0005u
#define EXT_SCT 0x0012u
#define EXT_EXTENDED_MASTER_SECRET 0x0017u
#define EXT_SESSION_TICKET 0x0023u
#define EXT_RENEGOTIATION_INFO 0xff01u
/* Allowed in a ServerHello and required to be EMPTY. Not in the forbidden set below: the reference
 * accepts it as an acknowledgement and carries on (`m.serverNameAck = true`), it just refuses a
 * body — `case extensionServerName: if len(extData) != 0 { return false }`,
 * vendor/utls/handshake_messages.go:1026-1030. */
#define EXT_SERVER_NAME 0x0000u
/* Two more the reference READS in a ServerHello and this parser used to step over as unknown.
 * ec_point_formats is a one-byte-prefixed list that must not be empty
 * (vendor/utls/handshake_messages.go:1015-1020), so a malformed one fails the unmarshal;
 * encrypted_client_hello is copied whatever it holds (:1021-1025) and refused for being there at all
 * on the retry path. Codepoints at vendor/utls/common.go:116 and :135. */
#define EXT_EC_POINT_FORMATS 0x000bu
#define EXT_ECH 0xfe0du

void lc_msg_reader_init(lc_msg_reader *r, const uint8_t *buf, size_t len)
{
    r->p = buf;
    r->len = len;
    r->off = 0;
}

int lc_msg_next(lc_msg_reader *r, uint8_t *type,
                const uint8_t **body, size_t *body_len,
                const uint8_t **whole, size_t *whole_len)
{
    if (r->off == r->len)
        return 0;
    if (r->len - r->off < 4u)
        return -1;

    const uint8_t *m = r->p + r->off;
    size_t         n = (size_t)m[1] << 16 | (size_t)m[2] << 8 | (size_t)m[3];
    if (n > r->len - r->off - 4u)
        return -1;

    *type = m[0];
    *body = m + 4;
    *body_len = n;
    *whole = m;
    *whole_len = n + 4u;
    r->off += n + 4u;
    return 1;
}

int lc_parse_server_hello(const uint8_t *body, size_t len, lc_server_hello *out)
{
    memset(out, 0, sizeof *out);

    /* ONLY THE SHAPE IS JUDGED HERE. Every refusal from this function is the reference's answer to
     * a message that does not unmarshal — unexpected_message (vendor/utls/conn.go:1185-1186) — and
     * what the message SAYS is judged by lc_check_server_hello, after all of it has parsed.
     *
     * ⚠️ THIS PARSER USED TO REFUSE AS IT READ: the legacy version and the compression method with
     * illegal_parameter before the extensions were reached, a pre_shared_key and a misshapen
     * key_share in the middle of the loop. Go takes the whole ServerHello first —
     * serverHelloMsg.unmarshal (vendor/utls/handshake_messages.go:909-1036) — and only a message
     * that parsed reaches pickTLSVersion and checkServerHelloOrHRR. So a crafted hello with one
     * fault of meaning and one of shape got 47 or 50 from us where every Go client sends 10, and
     * one with two faults of meaning got whichever alert our early return happened to reach first.
     * The same message, answered in the clear, before any key exists. */
    out->why = "the ServerHello does not parse";
    out->alert = LC_ALERT_UNEXPECTED_MESSAGE;

    /* legacy_version, random, legacy_session_id_echo, cipher_suite, legacy_compression_method —
     * read, and judged later: the reference compares the version and the compression method in
     * checkServerHelloOrHRR (vendor/utls/handshake_client_tls13.go:195-200, :216-219), and the
     * session id and the suite against what we sent, which the verdict is handed. */
    size_t off = 0;
    if (len < 2u + 32u + 1u)
        return -1;
    out->legacy_version = (uint16_t)((uint16_t)body[0] << 8 | body[1]);
    off += 2u;

    out->random = body + off;
    out->is_hello_retry = memcmp(body + off, hello_retry_random, sizeof hello_retry_random) == 0;
    off += 32u;

    size_t sid_len = body[off++];
    if (sid_len > len - off)
        return -1;
    out->session_id = body + off;
    out->session_id_len = sid_len;
    off += sid_len;

    if (len - off < 3u)
        return -1;
    out->cipher_suite = (uint16_t)((uint16_t)body[off] << 8 | body[off + 1u]);
    off += 2u;
    out->compression = body[off];
    off += 1u;

    /* "ServerHello is optionally followed by extension data" (vendor/utls/handshake_messages.go:921-924):
     * a message that ends here PARSED. It carries no supported_versions, so the version check is
     * what refuses it — protocol_version, not the unexpected_message this used to answer by
     * demanding an extensions block the reference does not demand. */
    if (off == len)
        return 0;
    if (len - off < 2u)
        return -1;
    size_t ext_total = (size_t)body[off] << 8 | body[off + 1u];
    off += 2u;
    if (ext_total != len - off)
        return -1;

    size_t end = len;

    /* Every identifier already met, so that a second one is refused rather than allowed to win.
     *
     * The reference keeps a set and fails the whole message on a repeat — `if seenExts[extension]
     * { return false }` in serverHelloMsg.unmarshal (vendor/utls/handshake_messages.go:931-943),
     * and unmarshal returning false is an unexpected_message alert, not a recovery. This loop used
     * to take the last occurrence of each, so a message carrying two key_share extensions was read
     * as having the second one — a difference between what we verify and what a Go peer verifies,
     * on a message that decides which key the connection uses.
     *
     * ⚠️ AND THE REFERENCE DOES NOT REFUSE A LONG LIST, WHICH THIS USED TO DO. The paragraph here
     * claimed a message with more than sixteen distinct extensions "does not exist" and that
     * refusing the seventeenth "is the same answer the reference gives it for a different reason".
     * Both halves are wrong. uTLS keeps a map, so the count is bounded by nothing, and unknown
     * extensions are stepped over rather than refused:
     *
     *     default:
     *         // Ignore unknown extensions.
     *         continue
     *                    (vendor/utls/handshake_messages.go:1031-1033)
     *
     * So a ServerHello padded with GREASE — seventeen distinct identifiers, none of them repeated —
     * is accepted by every Go client and was answered by this one with unexpected_message and a
     * closed connection. It is the FIRST message the server sends, in the clear, so an active
     * prober could tell this client from a browser with one reply. Found by the sieve, 2026-09-06.
     *
     * ⚠️ AND IT IS NO LONGER A TABLE AT ALL, because a table has a size and the reference's map does
     * not. This held sixty-four entries and stopped recording past that — so a repeat whose first
     * occurrence sat beyond the sixty-fourth distinct identifier was accepted where the reference
     * refuses it. Bounded-and-then-lenient is not what `if seenExts[extension] { return false }`
     * does; it is an approximation of it, and the message this parses is the first thing a server
     * sends.
     *
     * The set is the records already walked. Asking "have I seen this identifier" by re-reading
     * them costs a second pass over a list that a ServerHello keeps in single digits, and it needs
     * no memory and has no limit — the same answer as the map, for every message rather than for
     * the first sixty-four. Every record before this one was length-checked by the iteration that
     * passed it, so the walk cannot leave the block. */
    size_t ext_start = off;

    while (off < end) {
        if (end - off < 4u)
            return -1;
        size_t   rec = off;
        uint16_t ext = (uint16_t)((uint16_t)body[off] << 8 | body[off + 1u]);
        size_t   n = (size_t)body[off + 2u] << 8 | body[off + 3u];
        off += 4u;
        if (n > end - off)
            return -1;

        for (size_t p = ext_start; p < rec;) {
            uint16_t prev = (uint16_t)((uint16_t)body[p] << 8 | body[p + 1u]);
            size_t   plen = (size_t)body[p + 2u] << 8 | body[p + 3u];
            if (prev == ext)
                return -1;
            p += 4u + plen;
        }

        /* THE SIX A TLS 1.3 ServerHello MAY NOT CARRY — status_request, session_ticket,
         * extended_master_secret, renegotiation_info, ALPN and SCT — are all TLS 1.2 machinery. Our
         * own hello offers four of them because Go's hello offers them, and offering is not the
         * same as accepting one back: the verdict refuses them with unsupported_extension
         * (vendor/utls/handshake_client_tls13.go:200-209).
         *
         * ⚠️ BUT THE BODY IS READ HERE, because in the reference the reading is what decides WHICH
         * alert the server gets: 110 only for a forbidden extension that is otherwise WELL FORMED,
         * and 10 for one that is not, since a body it cannot parse fails the whole unmarshal and
         * never reaches the forbidden check at all.
         *
         * Three of the six carry nothing. The reference sets a flag and consumes no bytes —
         * `case extensionStatusRequest: m.ocspStapling = true` and the same shape for
         * session_ticket and extended_master_secret — and then, at the bottom of the loop,
         * `if !extData.Empty() { return false }`. So a non-empty body on any of those three is a
         * parse failure. The other three are parsed for real, and their framing has to hold:
         * renegotiation_info is one uint8-prefixed block and nothing after it, ALPN is a uint16
         * list holding exactly one non-empty uint8-prefixed name, SCT is a non-empty uint16 list of
         * non-empty uint16-prefixed entries that ends exactly where the list does
         * (vendor/utls/handshake_messages.go:946-987, :1036-1038). */
        if (ext == EXT_STATUS_REQUEST || ext == EXT_EXTENDED_MASTER_SECRET ||
            ext == EXT_SESSION_TICKET) {
            if (n != 0u)
                return -1;
            out->forbidden = 1;
            if (ext == EXT_STATUS_REQUEST)
                out->ocsp = 1;
            else if (ext == EXT_SESSION_TICKET)
                out->ticket = 1;
            else
                out->ems = 1;
        } else if (ext == EXT_SERVER_NAME) {
            /* Allowed, and required to be empty: the reference names it and refuses any content
             * (vendor/utls/handshake_messages.go:1026-1030), because in a ServerHello it carries
             * nothing and exists only to say "noted". Found by the sieve's reverse pass, 2026-09-09. */
            if (n != 0u)
                return -1;
        } else if (ext == EXT_RENEGOTIATION_INFO) {
            if (n < 1u || (size_t)body[off] != n - 1u)
                return -1;
            out->forbidden = 1;
            out->reneg = 1;
            out->reneg_len = body[off];
        } else if (ext == EXT_ALPN) {
            /* uint16 list length, then exactly one uint8-prefixed name, neither empty. */
            if (n < 3u)
                return -1;
            size_t list = (size_t)body[off] << 8 | body[off + 1u];
            if (list == 0u || list != n - 2u)
                return -1;
            size_t name = body[off + 2u];
            if (name == 0u || name != list - 1u)
                return -1;
            out->forbidden = 1;
            out->alpn = body + off + 3u;
            out->alpn_len = name;
        } else if (ext == EXT_SCT) {
            if (n < 2u)
                return -1;
            size_t sct_list = (size_t)body[off] << 8 | body[off + 1u];
            if (sct_list == 0u || sct_list != n - 2u)
                return -1;
            size_t sct_at  = off + 2u;
            size_t sct_end = off + n;
            while (sct_at < sct_end) {
                if (sct_end - sct_at < 2u)
                    return -1;
                size_t one = (size_t)body[sct_at] << 8 | body[sct_at + 1u];
                if (one == 0u || one > sct_end - sct_at - 2u)
                    return -1;
                sct_at += 2u + one;
            }
            if (sct_at != sct_end)
                return -1;
            out->forbidden = 1;
        } else if (ext == EXT_SUPPORTED_VERSIONS) {
            /* In a ServerHello this carries the single chosen version, not a list: `ReadUint16`, and
             * nothing may follow it (vendor/utls/handshake_messages.go:988-991, :1036-1038). A body
             * of any other length does not unmarshal — unexpected_message, which this used to
             * answer with illegal_parameter together with every version that was not 1.3. WHICH
             * version is the verdict's question, and its answer depends on which hello this is. */
            if (n != 2u)
                return -1;
            out->version = (uint16_t)((uint16_t)body[off] << 8 | body[off + 1u]);
        } else if (ext == EXT_COOKIE) {
            /* `opaque cookie<1..2^16-1>` (RFC 8446 4.2.2): an inner length that has to account for
             * the whole extension and must not be zero, which the grammar makes illegal rather
             * than empty (vendor/utls/handshake_messages.go:992-996). */
            if (n < 2u)
                return -1;
            size_t clen = (size_t)body[off] << 8 | body[off + 1u];
            if (clen == 0u || clen + 2u != n)
                return -1;
            out->cookie = body + off + 2u;
            out->cookie_len = clen;
        } else if (ext == EXT_PRE_SHARED_KEY) {
            /* `m.selectedIdentityPresent = true`, then `ReadUint16(&m.selectedIdentity)` and nothing
             * after it (vendor/utls/handshake_messages.go:1010-1014). A body that is not two bytes
             * does not unmarshal — 10, which this answered with 47 by refusing on presence alone,
             * and answered in the middle of the loop, ahead of every later extension's shape. What
             * a selection out of our empty list earns is the verdict's, at the reference's point. */
            if (n != 2u)
                return -1;
            out->psk = 1;
        } else if (ext == EXT_KEY_SHARE) {
            /* TWO FORMS, TOLD APART BY LENGTH AND BY NOTHING ELSE, which is the reference's reading:
             *
             *     if len(extData) == 2 { ReadUint16(&m.selectedGroup) }
             *     else { ReadUint16(&m.serverShare.group); readUint16LengthPrefixed(&extData,
             *                                                  &m.serverShare.data) }
             *                             (vendor/utls/handshake_messages.go:997-1009)
             *
             * "This extension has different formats in SH and HRR, accept either and let the
             * handshake logic decide." So a well-formed share in a retry, or a bare group in an
             * ordinary hello, PARSES — and the handshake answers either with decode_error (50) at
             * its own point in the order (vendor/utls/handshake_client_tls13.go:321-324 and
             * :527-530). This parser used to refuse both right here, which put the 50 ahead of every
             * check the reference runs before it: the version, the session id, the suite. Only a
             * share whose own framing is broken fails the parse and earns the 10. */
            if (n == 2u) {
                out->selected_group = (uint16_t)((uint16_t)body[off] << 8 | body[off + 1u]);
            } else {
                if (n < 4u)
                    return -1;
                size_t klen = (size_t)body[off + 2u] << 8 | body[off + 3u];
                if (klen != n - 4u)
                    return -1;
                out->group = (uint16_t)((uint16_t)body[off] << 8 | body[off + 1u]);
                out->key_share = body + off + 4u;
                out->key_share_len = klen;
            }
        } else if (ext == EXT_EC_POINT_FORMATS) {
            if (n < 1u || body[off] == 0u || (size_t)body[off] != n - 1u)
                return -1;
        } else if (ext == EXT_ECH) {
            out->ech = 1;
        }
        off += n;
    }
    return 0;
}

/* GREASE, which a list carries and nobody means (RFC 8701): uTLS's isGREASEUint16
 * (vendor/utls/u_common.go:723-727), the test it applies when it reads the version range out of
 * supported_versions (vendor/utls/u_conn.go:708). */
static int grease16(uint16_t v)
{
    return (v >> 8) == (v & 0xffu) && (v & 0xfu) == 0xau;
}

int lc_sh_expect_from_hello(const uint8_t *hello, size_t len, lc_sh_expect *ex)
{
    memset(ex, 0, sizeof *ex);
    if (len < 4u || hello[0] != LC_HS_CLIENT_HELLO)
        return -1;
    const uint8_t *b = hello + 4;
    size_t         blen = (size_t)hello[1] << 16 | (size_t)hello[2] << 8 | hello[3];
    if (blen != len - 4u || blen < 2u + 32u + 1u)
        return -1;

    size_t off = 2u + 32u;
    size_t sid = b[off++];
    if (sid > blen - off)
        return -1;
    ex->session_id = b + off;
    ex->session_id_len = sid;
    off += sid;

    if (blen - off < 2u)
        return -1;
    size_t suites = (size_t)b[off] << 8 | b[off + 1u];
    off += 2u;
    if ((suites & 1u) != 0u || suites > blen - off)
        return -1;
    ex->suites = b + off;
    ex->suites_len = suites;
    off += suites;

    if (blen - off < 1u)
        return -1;
    size_t comp = b[off++];
    if (comp > blen - off)
        return -1;
    off += comp;

    if (blen - off < 2u)
        return -1;
    size_t ext_total = (size_t)b[off] << 8 | b[off + 1u];
    off += 2u;
    if (ext_total != blen - off)
        return -1;

    while (off < blen) {
        if (blen - off < 4u)
            return -1;
        uint16_t ext = (uint16_t)((uint16_t)b[off] << 8 | b[off + 1u]);
        size_t   n = (size_t)b[off + 2u] << 8 | b[off + 3u];
        off += 4u;
        if (n > blen - off)
            return -1;
        if (ext == EXT_SUPPORTED_VERSIONS) {
            if (n < 1u || (size_t)b[off] != n - 1u || (b[off] & 1u) != 0u)
                return -1;
            for (size_t i = 1u; i + 1u < n; i += 2u) {
                uint16_t v = (uint16_t)((uint16_t)b[off + i] << 8 | b[off + i + 1u]);
                if (!grease16(v) && (ex->min_version == 0u || v < ex->min_version))
                    ex->min_version = v;
            }
        } else if (ext == EXT_KEY_SHARE) {
            if (n < 2u || ((size_t)b[off] << 8 | b[off + 1u]) != n - 2u)
                return -1;
            for (size_t i = 2u; i < n;) {
                if (n - i < 4u)
                    return -1;
                size_t klen = (size_t)b[off + i + 2u] << 8 | b[off + i + 3u];
                if (klen > n - i - 4u || ex->share_count == LC_SH_MAX_SHARES)
                    return -1;
                ex->shares[ex->share_count++] =
                    (uint16_t)((uint16_t)b[off + i] << 8 | b[off + i + 1u]);
                i += 4u + klen;
            }
        }
        off += n;
    }
    /* A hello with no supported_versions is not a TLS 1.3 hello, and neither plane sends one. */
    return ex->min_version == 0u ? -1 : 0;
}

static int suite_listed(const lc_sh_expect *ex, uint16_t suite)
{
    for (size_t i = 0; i + 1u < ex->suites_len; i += 2u)
        if ((uint16_t)((uint16_t)ex->suites[i] << 8 | ex->suites[i + 1u]) == suite)
            return 1;
    return 0;
}

static int share_listed(const lc_sh_expect *ex, uint16_t group)
{
    for (unsigned i = 0; i < ex->share_count; i++)
        if (ex->shares[i] == group)
            return 1;
    return 0;
}

static int refuse(lc_server_hello *sh, uint8_t alert, const char *why, const char *go)
{
    sh->alert = alert;
    sh->why = why;
    sh->go = go;
    return -1;
}

int lc_check_server_hello(lc_server_hello *sh, const lc_sh_expect *ex)
{
    /* THE REFERENCE'S ORDER, AND ONLY IT. Each check below is one `if` of the reference, in the
     * order the reference reaches them, with the alert it sends. The order is not tidiness: a
     * ServerHello with two faults gets the alert of whichever check comes first, and a prober that
     * sends one learns the order from the single byte that comes back. Where two adjacent checks
     * send the same alert the order between them cannot be seen, and the comment says so.
     *
     * ---- the first hello only: pickTLSVersion and the downgrade canary ----
     *
     *     peerVersion := serverHello.vers
     *     if serverHello.supportedVersion != 0 { peerVersion = serverHello.supportedVersion }
     *     vers, ok := c.config.mutualVersion(roleClient, []uint16{peerVersion})
     *     if !ok { c.sendAlert(alertProtocolVersion) }
     *                                  (vendor/utls/handshake_client.go:545-555, reached at :319
     *                                   and on the parroted path at vendor/utls/u_handshake_client.go:526)
     *
     * After a HelloRetryRequest the second hello never reaches that function — it goes straight to
     * checkServerHelloOrHRR (vendor/utls/handshake_client_tls13.go:506) — which is why the version
     * checks there, 109 and 47, are reachable on it and mostly not on the first. */
    /* A retry answers a hello sent after the first ServerHello had set the version. */
    if (ex->retried)
        sh->vers_settled = 1;
    if (!ex->retried) {
        uint16_t peer = sh->version != 0u ? sh->version : sh->legacy_version;
        /* pickTLSVersion's words, the version as Go's %x prints it (vendor/utls/handshake_client.go:
         * 545-563). */
        snprintf(sh->go_buf, sizeof sh->go_buf,
                 LC_GO("tls: server selected unsupported protocol version %x"), (unsigned)peer);
        if (peer < ex->min_version || peer > 0x0304u)
            return refuse(sh, LC_ALERT_PROTOCOL_VERSION,
                          "the server chose a protocol version the hello did not offer", sh->go_buf);
        /* `c.vers = vers` (:571): whatever refuses the hello from here does so with a version set. */
        sh->vers_settled = 1;
        /* The canary, read only when the version landed below 1.3 — `maxVers == VersionTLS13 &&
         * c.vers <= VersionTLS12 && (tls12Downgrade || tls11Downgrade)`
         * (vendor/utls/handshake_client.go:324-333, the eight bytes at vendor/utls/common.go:247-248).
         * A 1.3 server that ends up at 1.2 writes them so that a 1.3-capable client can tell an
         * honest 1.2 server from a middlebox that stripped the offer. */
        if (peer != 0x0304u && (memcmp(sh->random + 24, "DOWNGRD\x01", 8) == 0 ||
                                memcmp(sh->random + 24, "DOWNGRD\x00", 8) == 0))
            return refuse(sh, LC_ALERT_ILLEGAL_PARAMETER,
                          "the server flagged a downgrade in its random, which means a middlebox "
                          "stripped our TLS 1.3 offer on the way out", NULL);
        /* TLS 1.2, AND THE HANDSHAKE GOES ON AS THE REFERENCE'S DOES. A browser parrot offers 1.2, so
         * mutualVersion succeeds on a 1.2 answer and uTLS carries on with hs12.handshake()
         * (vendor/utls/u_handshake_client.go:569-579): the checks below are TLS 1.3's and it never
         * makes them. This stopped here with protocol_version until 29.09 (T3) — the answer a TLS
         * 1.2-only site got, mail.ru among twenty-two probed on 2026-08-18. The QUIC plane never
         * gets here: its hello offers 1.3 alone, and the first check above refuses anything else
         * (vendor/quic-go/internal/handshake/tls_conn_utls.go:75-76). What follows is tls/client.c's,
         * from the suite onwards. */
        if (peer != 0x0304u) {
            sh->tls12 = 1;
            return 0;
        }
    }

    /* ---- checkServerHelloOrHRR (vendor/utls/handshake_client_tls13.go:182-235), every hello ----
     *
     * missing_extension IS reachable on a first hello: a legacy_version of 0x0304 with no
     * supported_versions passes pickTLSVersion as 1.3, because the peer version falls back to the
     * legacy field, and then dies here — "server selected TLS 1.3 using the legacy version field".
     * This file used to answer that one 47, from a legacy-version test it ran before anything else. */
    if (sh->version == 0u)
        return refuse(sh, LC_ALERT_MISSING_EXTENSION,
                      "the server selected TLS 1.3 using the legacy version field", LC_GO("tls: server selected TLS 1.3 using the legacy version field")); /* :185-188 */
    if (sh->version != 0x0304u)
        return refuse(sh, LC_ALERT_ILLEGAL_PARAMETER,
                      "the server selected a version other than TLS 1.3 after a HelloRetryRequest", LC_GO("tls: server selected an invalid version after a HelloRetryRequest")); /* :190-193 */
    if (sh->legacy_version != 0x0303u)
        return refuse(sh, LC_ALERT_ILLEGAL_PARAMETER,
                      "the server put something other than TLS 1.2 in the legacy version field", LC_GO("tls: server sent an incorrect legacy version")); /* :195-198 */
    if (sh->forbidden)
        return refuse(sh, LC_ALERT_UNSUPPORTED_EXTENSION,
                      "the server answered with an extension TLS 1.3 forbids in a ServerHello, "
                      "which a TLS 1.2 server does and a TLS 1.3 one never does", LC_GO("tls: server sent a ServerHello extension forbidden in TLS 1.3")); /* :200-209 */
    /* The session id must come back as it went out (:211-214). On the REALITY plane that field is
     * where lc_reality_stamp put the authenticator, so a peer echoing something else has not seen
     * what we sent. Checked on a HelloRetryRequest as well, which the retry path used to skip. */
    if (sh->session_id_len != ex->session_id_len ||
        memcmp(sh->session_id, ex->session_id, ex->session_id_len) != 0)
        return refuse(sh, LC_ALERT_ILLEGAL_PARAMETER,
                      "the server did not echo the session id it was sent", LC_GO("tls: server did not echo the legacy session ID"));
    /* 47 in uTLS (:216-219) and 50 in the standard library the QUIC plane's reference is built
     * with — see `stdlib` in lc_sh_expect. */
    if (sh->compression != 0u)
        return refuse(sh, ex->stdlib ? LC_ALERT_DECODE_ERROR : LC_ALERT_ILLEGAL_PARAMETER,
                      "the server selected a compression method, which TLS 1.3 has none of", LC_GO("tls: server selected unsupported compression format"));
    /* mutualCipherSuiteTLS13 (vendor/utls/cipher_suites.go:661) answers only a suite that is BOTH in
     * our hello and one of the three TLS 1.3 suites, so either failing is the same 47. The
     * changed-suite check comes first in the reference (:223-231); with one alert for both the
     * order cannot be seen. */
    int usable = suite_listed(ex, sh->cipher_suite) &&
                 sh->cipher_suite >= 0x1301u && sh->cipher_suite <= 0x1303u;
    if (ex->retried && sh->cipher_suite != ex->retry_suite)
        return refuse(sh, LC_ALERT_ILLEGAL_PARAMETER,
                      "the ServerHello changed the cipher suite the retry had chosen", LC_GO("tls: server changed cipher suite after a HelloRetryRequest"));
    if (!usable)
        return refuse(sh, LC_ALERT_ILLEGAL_PARAMETER,
                      "the server chose a cipher suite this hello did not offer, or one that is not "
                      "a TLS 1.3 suite", LC_GO("tls: server chose an unconfigured cipher suite"));

    if (sh->is_hello_retry && !ex->retried) {
        /* ---- processHelloRetryRequest (vendor/utls/handshake_client_tls13.go:252-347) ---- */
        if (sh->ech)
            return refuse(sh, LC_ALERT_UNSUPPORTED_EXTENSION,
                          "the retry carried encrypted_client_hello, which this hello did not "
                          "offer for real", LC_GO("tls: unexpected encrypted client hello extension in serverHello")); /* :302-305 */
        /* A retry that names no group but DOES carry a cookie is legal — it is how a server checks
         * the return address without keeping state — and the reference's test is exactly the pair
         * (:311-314). */
        if (sh->selected_group == 0u && sh->cookie == NULL)
            return refuse(sh, LC_ALERT_ILLEGAL_PARAMETER, "a HelloRetryRequest that changes nothing", LC_GO("tls: server sent an unnecessary HelloRetryRequest message"));
        /* A retry names the group it wants and sends no share with it; one that sends a share is
         * decode_error (:320-323): alert 50 on the wire, in the clear, where a message that did not
         * parse would get 10. */
        if (sh->group != 0u)
            return refuse(sh, LC_ALERT_DECODE_ERROR,
                          "the retry carried a key share where it may only name a group", LC_GO("tls: received malformed key_share extension"));
        /* A group the first hello already sent a share for is a server asking for what it had
         * (:333-338). Whether the group is one we advertise at all comes one check before it in
         * the reference (:328-331) and is the caller's, together with whether this build can key
         * it; all three are 47, so the split cannot be seen. */
        if (sh->selected_group != 0u && share_listed(ex, sh->selected_group))
            return refuse(sh, LC_ALERT_ILLEGAL_PARAMETER,
                          "the retry asks for a group the first hello already sent a share for", LC_GO("tls: server sent an unnecessary HelloRetryRequest key_share"));
        return 0;
    }

    /* ---- processServerHello (vendor/utls/handshake_client_tls13.go:514-553) ---- */
    if (sh->is_hello_retry)
        return refuse(sh, LC_ALERT_UNEXPECTED_MESSAGE,
                      "a second HelloRetryRequest, which the protocol does not allow", LC_GO("tls: server sent two HelloRetryRequest messages")); /* :509-512 */
    if (sh->cookie != NULL)
        return refuse(sh, LC_ALERT_UNSUPPORTED_EXTENSION,
                      "the server sent a cookie in a ServerHello that is not a retry", LC_GO("tls: server sent a cookie in a normal ServerHello")); /* :514-517 */
    if (sh->selected_group != 0u)
        return refuse(sh, LC_ALERT_DECODE_ERROR,
                      "the server named a group where a key share belongs", LC_GO("tls: malformed key_share extension")); /* :519-522 */
    if (sh->group == 0u)
        return refuse(sh, LC_ALERT_ILLEGAL_PARAMETER,
                      "the server chose TLS 1.3 and sent no key share", LC_GO("tls: server did not send a key share")); /* :524-527 */
    if (!share_listed(ex, sh->group))
        return refuse(sh, LC_ALERT_ILLEGAL_PARAMETER,
                      "the server answered with a key share for a group this hello sent none for", LC_GO("tls: server selected unsupported group")); /* :528-533 */
    /* A SELECTION OUT OF A LIST THIS CLIENT NEVER SENT: `if int(hs.serverHello.selectedIdentity)
     * >= len(hs.hello.pskIdentities)` (:539-542). This client offers no identities and never will —
     * it does not resume — so every index fails the comparison and the number need not be read. */
    if (sh->psk)
        return refuse(sh, LC_ALERT_ILLEGAL_PARAMETER,
                      "the server selected a pre-shared key, and this client offered none", LC_GO("tls: server selected an invalid PSK"));
    return 0;
}

int lc_finished_verify_data(lc_hash h, const uint8_t *traffic_secret,
                            const uint8_t *transcript_hash, uint8_t *out)
{
    size_t hlen = lc_hash_len(h);

    /* The finished key is expanded from the traffic secret with an EMPTY context — unlike almost
     * every other derivation in the schedule, which takes the transcript. The transcript enters
     * one step later, as the message being authenticated. */
    uint8_t finished_key[LC_HASH_MAX];
    if (lc_hkdf_expand_label(h, traffic_secret, "finished", NULL, 0, finished_key, hlen) != 0)
        return -1;

    const mbedtls_md_info_t *info =
        mbedtls_md_info_from_type(h == LC_SHA384 ? MBEDTLS_MD_SHA384 : MBEDTLS_MD_SHA256);
    if (info == NULL)
        return -1;

    int rc = mbedtls_md_hmac(info, finished_key, hlen, transcript_hash, hlen, out) == 0 ? 0 : -1;
    lc_wipe(finished_key, sizeof finished_key);
    return rc;
}

int lc_finished_check(lc_hash h, const uint8_t *traffic_secret,
                      const uint8_t *transcript_hash,
                      const uint8_t *body, size_t body_len)
{
    size_t hlen = lc_hash_len(h);
    if (body_len != hlen)
        return -1;

    uint8_t want[LC_HASH_MAX];
    if (lc_finished_verify_data(h, traffic_secret, transcript_hash, want) != 0)
        return -1;

    /* Constant time: a comparison that stops at the first wrong byte tells an attacker how much of
     * a forged tag was right, one byte at a time. */
    uint8_t diff = 0;
    for (size_t i = 0; i < hlen; i++)
        diff = (uint8_t)(diff | (want[i] ^ body[i]));

    lc_wipe(want, sizeof want);
    return diff == 0 ? 0 : -1;
}


/* The whole of the Certificate message this client sends when a server asks for one: type 0x0b,
 * length 4, an empty request context and an empty list. Go marshals exactly this for an empty
 * certificate — `b.AddUint8(0)` for the context and a zero-length list from marshalCertificate
 * (vendor/utls/handshake_messages.go:1525-1542) — and the context is empty rather than echoed
 * because Go does not echo it either. At file scope so that the suite can hold these eight bytes to
 * the reference's without a handshake to drive. Shared by both planes: the standard library
 * marshals the same eight bytes for the QUIC plane
 * (GOROOT/src/crypto/tls/handshake_client_tls13.go:783-791). */
const uint8_t lc_empty_certificate[8] = {LC_HS_CERTIFICATE, 0x00, 0x00, 0x04,
                                         0x00,              0x00, 0x00, 0x00};
int lc_alpn_selected(const uint8_t *body, size_t len, const uint8_t **name, size_t *name_len)
{
    if (len < 3u)
        return -1;
    size_t list = (size_t)body[0] << 8 | body[1];
    size_t nlen = body[2];
    /* Every clause of the reference's, in one place: the list is not empty, it accounts for exactly
     * the rest of the extension, the name is not empty, and it accounts for exactly the rest of the
     * list — so a second name has nowhere to be. */
    if (list == 0u || list != len - 2u || nlen == 0u || nlen != list - 1u)
        return -1;
    *name = body + 3u;
    *name_len = nlen;
    return 0;
}

/* A u16-prefixed, non-empty list of two-byte signature schemes that is the whole of `b`. */
static int sigalg_list_ok(const uint8_t *b, size_t n)
{
    if (n < 2u)
        return 0;
    size_t list = (size_t)b[0] << 8 | b[1];
    return list != 0u && list == n - 2u && (list & 1u) == 0u;
}

int lc_cert_request_parses(const uint8_t *body, size_t len)
{
    if (len < 1u || body[0] != 0u) /* the request context, which must be empty */
        return 0;
    size_t off = 1u;
    if (len - off < 2u || ((size_t)body[off] << 8 | body[off + 1u]) != len - off - 2u)
        return 0;
    off += 2u;
    while (off < len) {
        if (len - off < 4u)
            return 0;
        uint16_t ext = (uint16_t)((uint16_t)body[off] << 8 | body[off + 1u]);
        size_t   n = (size_t)body[off + 2u] << 8 | body[off + 3u];
        off += 4u;
        if (n > len - off)
            return 0;
        const uint8_t *b = body + off;
        switch (ext) {
        case 0x0005u: /* status_request: a flag, and nothing may follow it */
        case 0x0012u: /* signed_certificate_timestamp: the same */
            if (n != 0u)
                return 0;
            break;
        case 0x000du: /* signature_algorithms */
        case 0x0032u: /* signature_algorithms_cert */
            if (!sigalg_list_ok(b, n))
                return 0;
            break;
        case 0x002fu: { /* certificate_authorities: non-empty, each name non-empty */
            if (n < 2u)
                return 0;
            size_t list = (size_t)b[0] << 8 | b[1];
            if (list == 0u || list != n - 2u)
                return 0;
            for (size_t p = 2u; p < n;) {
                if (n - p < 2u)
                    return 0;
                size_t dn = (size_t)b[p] << 8 | b[p + 1u];
                p += 2u;
                if (dn == 0u || dn > n - p)
                    return 0;
                p += dn;
            }
            break;
        }
        default:
            break;
        }
        off += n;
    }
    return 1;
}

int lc_hs_utls_knows(uint8_t type)
{
    switch (type) {
    case 0u: case 1u: case 2u: case 4u: case 5u: case 8u: case 11u: case 12u: case 13u:
    case 14u: case 15u: case 16u: case 20u: case 22u: case 24u: case 25u:
        return 1;
    default:
        return 0;
    }
}

/* ---- uTLS's verdicts on the server flight, shared by both planes -------------- */

/* THE THREE PIECES OF `checkALPN`, WHICH THIS CLIENT DID NOT HAVE.
 *
 * The reference compares the protocol the server chose against the list ITS OWN HELLO offered —
 * `checkALPN(hs.hello.alpnProtocols, encryptedExtensions.alpnProtocol, c.quic != nil)`
 * (vendor/utls/handshake_client_tls13.go:639-646, checkALPN at
 * vendor/utls/handshake_client.go:1001-1018). So does this: the hello is kept for the transcript
 * anyway, and reading the offer back out of it is what the reference does rather than a trick.
 *
 * `hello_alpn` walks our own ClientHello to the ALPN extension body; `alpn_list_has` answers
 * whether that body names a protocol. The server's choice is taken out of EncryptedExtensions by
 * lc_utls_ee_alert, with the strictness `encryptedExtensionsMsg.unmarshal` applies to it. */
const uint8_t *lc_ch_ext(const uint8_t *h, size_t len, uint16_t type, size_t *out_len)
{
    size_t off = 4u; /* handshake type and its 24-bit length */
    if (len < off + 2u + 32u + 1u)
        return NULL;
    off += 2u + 32u;
    size_t sid = h[off];
    off += 1u + sid;
    if (len < off + 2u)
        return NULL;
    size_t cs = (size_t)h[off] << 8 | h[off + 1u];
    off += 2u + cs;
    if (len < off + 1u)
        return NULL;
    size_t comp = h[off];
    off += 1u + comp;
    if (len < off + 2u)
        return NULL;
    size_t total = (size_t)h[off] << 8 | h[off + 1u];
    off += 2u;
    if (total > len - off)
        return NULL;
    size_t end = off + total;
    while (off + 4u <= end) {
        uint16_t ext = (uint16_t)((uint16_t)h[off] << 8 | h[off + 1u]);
        size_t   n = (size_t)h[off + 2u] << 8 | h[off + 3u];
        off += 4u;
        if (n > end - off)
            return NULL;
        if (ext == type) {
            *out_len = n;
            return h + off;
        }
        off += n;
    }
    return NULL;
}

static const uint8_t *hello_alpn(const uint8_t *h, size_t len, size_t *out_len)
{
    return lc_ch_ext(h, len, EXT_ALPN, out_len);
}

static int alpn_list_has(const uint8_t *list, size_t list_len, const uint8_t *name, size_t name_len)
{
    if (list_len < 2u)
        return 0;
    size_t total = (size_t)list[0] << 8 | list[1];
    if (total != list_len - 2u)
        return 0;
    size_t off = 2u;
    while (off < list_len) {
        size_t n = list[off];
        off += 1u;
        if (n == 0u || n > list_len - off)
            return 0;
        if (n == name_len && memcmp(list + off, name, n) == 0)
            return 1;
        off += n;
    }
    return 0;
}



/* AN EMPTY LIST AND A MESSAGE THAT DOES NOT PARSE ARE TWO REFUSALS, NOT ONE.
 *
 * The reference separates them and this client used to have neither: a Certificate carrying no
 * certificates left cert_der_len at zero and went on, to fail later at CertificateVerify with an
 * alert of that step's choosing. Go answers the empty list where it finds it —
 * `c.sendAlert(alertDecodeError)` and "received empty certificates message"
 * (vendor/utls/handshake_client_tls13.go:759-762) — and a message whose bytes do not make a
 * Certificate never reaches that check at all, because unmarshal failed and
 * unmarshalHandshakeMessage, under readHandshake, already sent alert 10
 * (vendor/utls/conn.go:1192-1194).
 *
 * The walk is cert/cert.c's lc_cert_next_from_message, which tells a list that ended (1) from one
 * that is malformed (-1) — the difference between these two refusals.
 *
 * THE WHOLE MESSAGE FIRST, THEN WHETHER IT HOLDS ANYTHING, THEN EVERY CERTIFICATE IN IT — the
 * reference's order. unmarshal walks every entry before anything else looks
 * (certificateMsgTLS13.unmarshal, vendor/utls/handshake_messages.go:1581-1597); the empty list is
 * refused where readServerCertificate finds it; and verifyServerCertificate then parses every
 * certificate and weighs every RSA key before it looks at the leaf's type, a failure of either
 * being bad_certificate (vendor/utls/handshake_client.go:1143-1159). The leaf's type (43) and the
 * chain (42) follow, in the arm that reads the message.
 *
 * What stood here looked at the list's length before the rest of the message — a non-empty
 * context around an empty list was 50 where the reference says 10 — and then read the leaf and
 * nothing after it, so a malformed entry behind a good leaf, a leaf of zero bytes and an
 * intermediate that is not X.509 all passed.
 *
 * Returns 0 when the message is one this client can go on with, or the alert it has earned. */
uint8_t lc_utls_cert_msg_alert(const uint8_t *body, size_t body_len)
{
    size_t         off = 0;
    unsigned       count = 0;
    const uint8_t *der = NULL;
    size_t         der_len = 0;
    int            step;
    while ((step = lc_cert_next_from_message(body, body_len, &off, &der, &der_len)) == 0)
        count++;
    if (step < 0)
        return LC_ALERT_UNEXPECTED_MESSAGE;
    if (count == 0u)
        return LC_ALERT_DECODE_ERROR; /* :819-822 */

    /* each certificate parsed, then its RSA key weighed — N.BitLen() as the parser read it */
    off = 0;
    while (lc_cert_next_from_message(body, body_len, &off, &der, &der_len) == 0) {
        size_t bits = 0;
        if (!lc_x509_parses(der, der_len, &bits) || bits > LC_MAX_RSA_BITS)
            return LC_ALERT_BAD_CERTIFICATE;
    }

    return 0u;
}

/* What EncryptedExtensions has earned on this plane: 0 to go on, or the alert to send — uTLS's
 * verdict, whole.
 *
 * FIRST THE MESSAGE, AS encryptedExtensionsMsg.unmarshal READS IT (vendor/utls/handshake_messages.go:
 * 1101-1169): one two-byte-prefixed block that is the whole message, ALPN as one non-empty name in
 * a non-empty list, early_data empty, the transport parameters, encrypted_client_hello and the two
 * ALPS codepoints taken as they come (vendor/utls/u_handshake_messages.go:62-71), and anything else
 * stepped over. There is NO repeat check in uTLS's version of this message — a second ALPN is read
 * again and the last one stands — and no server_name case; the standard library has both, which
 * is the QUIC plane's business (quic/qtls.c). A message that does not unmarshal is
 * unexpected_message (vendor/utls/conn.go:1185-1186).
 *
 * THEN WHAT IT SAYS, in readServerParameters' order (vendor/utls/handshake_client_tls13.go:625-675):
 * the protocol, against the list our own hello offered — no selection is fine off QUIC, a
 * selection we did not offer is no_application_protocol (checkALPN, vendor/utls/handshake_client.go:
 * 1001-1018); ALPS with no protocol negotiated, unsupported_extension (vendor/utls/u_handshake_client.go:
 * 166-176); quic_transport_parameters, which a TLS server over TCP may not send, unsupported_extension;
 * and early_data this client never offered, unsupported_extension.
 *
 * This used to stop at the first ALPN extension and look at nothing after it, so a malformed
 * extension behind it was accepted, a duplicate was the first rather than the last, and the three
 * refusals after the protocol did not exist. */
uint8_t lc_utls_ee_alert(const uint8_t *hello, size_t hello_len, const uint8_t *body,
                         size_t body_len, int quic)
{
    if (body_len < 2u || ((size_t)body[0] << 8 | body[1]) != body_len - 2u)
        return LC_ALERT_UNEXPECTED_MESSAGE;
    const uint8_t *sel = NULL;
    size_t         sel_len = 0;
    int            alps = 0, params = 0, early = 0;
    size_t         off = 2u;
    while (off < body_len) {
        if (body_len - off < 4u)
            return LC_ALERT_UNEXPECTED_MESSAGE;
        uint16_t ext = (uint16_t)((uint16_t)body[off] << 8 | body[off + 1u]);
        size_t   n = (size_t)body[off + 2u] << 8 | body[off + 3u];
        off += 4u;
        if (n > body_len - off)
            return LC_ALERT_UNEXPECTED_MESSAGE;
        if (ext == EXT_ALPN) {
            if (lc_alpn_selected(body + off, n, &sel, &sel_len) != 0)
                return LC_ALERT_UNEXPECTED_MESSAGE;
        } else if (ext == 0x0039u) { /* quic_transport_parameters */
            params = 1;
        } else if (ext == 0x002au) { /* early_data */
            if (n != 0u)
                return LC_ALERT_UNEXPECTED_MESSAGE;
            early = 1;
        } else if (ext == 17513u || ext == 17613u) { /* ALPS, old and new codepoints */
            alps = 1;
        }
        off += n;
    }

    size_t         off_len = 0;
    const uint8_t *offered = hello_alpn(hello, hello_len, &off_len);
    if (sel != NULL) {
        if (offered == NULL || !alpn_list_has(offered, off_len, sel, sel_len))
            return LC_ALERT_NO_APPLICATION_PROTOCOL;
    } else if (quic && offered != NULL) {
        /* Over QUIC a client that offered protocols needs the server to pick one: "server did not
         * select an ALPN protocol", RFC 9001 §8.1 (checkALPN, vendor/utls/handshake_client.go:
         * 1001-1018, with `c.quic != nil`). */
        return LC_ALERT_NO_APPLICATION_PROTOCOL;
    }
    if (alps && sel == NULL)
        return LC_ALERT_UNSUPPORTED_EXTENSION;
    /* The transport parameters are QUIC's and nobody else's: missing_extension without them on
     * QUIC, unsupported_extension with them anywhere else (vendor/utls/handshake_client_tls13.go:
     * 658-670). */
    if (quic && !params)
        return LC_ALERT_MISSING_EXTENSION;
    if (!quic && params)
        return LC_ALERT_UNSUPPORTED_EXTENSION;
    if (early)
        return LC_ALERT_UNSUPPORTED_EXTENSION;
    return 0u;
}

/* THE ANSWER TO A SERVER'S APPLICATION SETTINGS, WHICH uTLS GIVES AND THIS CLIENT DID NOT.
 *
 * When the server's EncryptedExtensions carried ALPS — and a protocol, or lc_utls_ee_alert has
 * already refused it — uTLS writes an EncryptedExtensions of its own after the server's Finished
 * and before its Certificate and Finished: serverFinishedReceived calls
 * sendClientEncryptedExtensions (vendor/utls/u_handshake_client.go:143-164), from the handshake
 * right after readServerFinished (vendor/utls/handshake_client_tls13.go:152-156). It carries one
 * extension, under the codepoint the server used — the LAST of the two, when it sent both, since
 * utlsUnmarshal overwrites it for each (vendor/utls/u_handshake_messages.go:62-71) — and the
 * settings the client holds for the chosen protocol (vendor/utls/u_handshake_client.go:178-185),
 * which come from Config.ApplicationSettings. Xray never sets that map, so the settings are empty
 * and the message is these ten bytes, as utlsClientEncryptedExtensionsMsg.marshal writes them
 * (vendor/utls/u_handshake_messages.go:80-106): type 8, length 6, an extension block of 4, the
 * codepoint, a zero length.
 *
 * WHETHER OUR HELLO OFFERED ALPS DOES NOT ENTER INTO IT: the reference asks only about the version
 * and the protocol. The shipped table is Firefox's, which offers none, and a real server does not
 * volunteer settings nobody asked for — so on the wire this is the Chrome tables' answer to a server
 * that speaks ALPS, BoringSSL's among them. The REALITY node never sends it: its
 * EncryptedExtensions has ALPN, the QUIC parameters, early data and ECH, and nothing else
 * (vendor/REALITY/handshake_messages.go:1013-1054). Where it does arrive is the path Xray takes when
 * the certificate is not the node's but verifies against the system roots
 * (vendor/Xray-core/transport/internet/reality/reality.go:129-139): the handshake completes with
 * the real site, and the spider runs over it. */
/* Every verdict lc_utls_ee_alert gives after the message has read is another alert than 10, so
 * reading is the absence of that one — with no hello, whose offered list only the verdicts after
 * the read look at. */
int lc_utls_ee_reads(const uint8_t *body, size_t body_len)
{
    return lc_utls_ee_alert(NULL, 0u, body, body_len, 0) != LC_ALERT_UNEXPECTED_MESSAGE;
}

/* utlsCompressedCertificateMsg.unmarshal (vendor/utls/u_handshake_messages.go:43-54): the
 * algorithm, the uncompressed length, and a three-byte-prefixed block — with nothing checked after
 * it, since no s.Empty() follows. */
int lc_utls_certcomp_reads(const uint8_t *body, size_t body_len)
{
    return body_len >= 8u &&
           ((size_t)body[5] << 16 | (size_t)body[6] << 8 | body[7]) <= body_len - 8u;
}

/* See client.h, and the allocation in phase_flight for why the declared length and nothing else. */
size_t lc_utls_certcomp_want(const uint8_t *body, size_t body_len)
{
    return body_len >= 5u ? ((size_t)body[2] << 16 | (size_t)body[3] << 8 | body[4]) : 0u;
}

size_t lc_utls_alps_answer(const uint8_t *body, size_t body_len, uint8_t out[LC_ALPS_ANSWER_LEN])
{
    uint16_t cp = 0;
    size_t   off = 2u;
    while (off + 4u <= body_len) {
        uint16_t ext = (uint16_t)((uint16_t)body[off] << 8 | body[off + 1u]);
        size_t   n = (size_t)body[off + 2u] << 8 | body[off + 3u];
        off += 4u;
        if (n > body_len - off)
            return 0;
        if (ext == 17513u || ext == 17613u)
            cp = ext;
        off += n;
    }
    if (cp == 0u)
        return 0;
    out[0] = LC_HS_ENCRYPTED_EXT;
    out[1] = 0x00u;
    out[2] = 0x00u;
    out[3] = 0x06u;
    out[4] = 0x00u;
    out[5] = 0x04u;
    out[6] = (uint8_t)(cp >> 8);
    out[7] = (uint8_t)cp;
    out[8] = 0x00u;
    out[9] = 0x00u;
    return LC_ALPS_ANSWER_LEN;
}
