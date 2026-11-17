#include "tls/stdmsg.h"

#include "tls/alert.h"
#include "tls/msg.h"

#include <string.h>

/* A cursor over a byte string, the part of cryptobyte.String these readers use: every read either
 * takes what it asked for and moves on, or takes nothing and says so. */
typedef struct {
    const uint8_t *p;
    size_t         n;
} cur;

static int take(cur *c, size_t k, cur *out)
{
    if (c->n < k)
        return 0;
    if (out != NULL) {
        out->p = c->p;
        out->n = k;
    }
    c->p += k;
    c->n -= k;
    return 1;
}

static int u8(cur *c, unsigned *v)
{
    if (c->n < 1u)
        return 0;
    *v = c->p[0];
    return take(c, 1u, NULL);
}

static int u16(cur *c, unsigned *v)
{
    if (c->n < 2u)
        return 0;
    *v = (unsigned)c->p[0] << 8 | c->p[1];
    return take(c, 2u, NULL);
}

static int u24(cur *c, size_t *v)
{
    if (c->n < 3u)
        return 0;
    *v = (size_t)c->p[0] << 16 | (size_t)c->p[1] << 8 | c->p[2];
    return take(c, 3u, NULL);
}

static int pre8(cur *c, cur *out)
{
    unsigned k;
    return u8(c, &k) && take(c, k, out);
}

static int pre16(cur *c, cur *out)
{
    unsigned k;
    return u16(c, &k) && take(c, k, out);
}

static int pre24(cur *c, cur *out)
{
    size_t k;
    return u24(c, &k) && take(c, k, out);
}

/* A list of two-byte values, non-empty, as signature_algorithms and supported_groups are read. */
static int u16_list(cur *c)
{
    cur list;
    if (!pre16(c, &list) || list.n == 0u)
        return 0;
    unsigned v;
    while (list.n != 0u)
        if (!u16(&list, &v))
            return 0;
    return 1;
}

/* Extension identifiers the readers below name, from GOROOT/src/crypto/tls/common.go. */
enum {
    X_SERVER_NAME = 0,
    X_STATUS_REQUEST = 5,
    X_SUPPORTED_CURVES = 10,
    X_SUPPORTED_POINTS = 11,
    X_SIGNATURE_ALGORITHMS = 13,
    X_ALPN = 16,
    X_SCT = 18,
    X_EXTENDED_MASTER_SECRET = 23,
    X_SESSION_TICKET = 35,
    X_PRE_SHARED_KEY = 41,
    X_EARLY_DATA = 42,
    X_SUPPORTED_VERSIONS = 43,
    X_COOKIE = 44,
    X_PSK_MODES = 45,
    X_CERTIFICATE_AUTHORITIES = 47,
    X_SIGNATURE_ALGORITHMS_CERT = 50,
    X_KEY_SHARE = 51,
    X_QUIC_TRANSPORT_PARAMETERS = 57,
    X_RENEGOTIATION_INFO = 0xff01,
    X_ENCRYPTED_CLIENT_HELLO = 0xfe0d,
};

/* A duplicate extension, as `seenExts` catches it: the set is small (an extension block is at most
 * 65535 bytes, four per entry), so a bitmap over all identifiers costs 8 KiB and no hashing. */
typedef struct {
    uint8_t bits[8192];
} seen_set;

static int seen_once(seen_set *s, unsigned id)
{
    uint8_t m = (uint8_t)(1u << (id & 7u));
    if (s->bits[id >> 3] & m)
        return 0;
    s->bits[id >> 3] |= m;
    return 1;
}

/* clientHelloMsg.unmarshal (GOROOT/src/crypto/tls/handshake_messages.go:420-682,
 * go1.25.14 — as every citation in this file). */
static int um_client_hello(cur s)
{
    seen_set seen;
    memset(&seen, 0, sizeof seen);
    unsigned vers;
    cur      x;
    if (!take(&s, 4u, NULL) || !u16(&s, &vers) || !take(&s, 32u, NULL) || !pre8(&s, &x))
        return 0;
    cur suites;
    if (!pre16(&s, &suites))
        return 0;
    unsigned v;
    while (suites.n != 0u)
        if (!u16(&suites, &v))
            return 0;
    if (!pre8(&s, &x))
        return 0;
    if (s.n == 0u)
        return 1;
    cur exts;
    if (!pre16(&s, &exts) || s.n != 0u)
        return 0;
    while (exts.n != 0u) {
        unsigned id;
        cur      d;
        if (!u16(&exts, &id) || !pre16(&exts, &d))
            return 0;
        if (!seen_once(&seen, id))
            return 0;
        switch (id) {
        case X_SERVER_NAME: {
            cur list;
            if (!pre16(&d, &list) || list.n == 0u)
                return 0;
            int have = 0;
            while (list.n != 0u) {
                unsigned type;
                cur      name;
                if (!u8(&list, &type) || !pre16(&list, &name) || name.n == 0u)
                    return 0;
                if (type != 0u)
                    continue;
                if (have)
                    return 0;
                have = 1;
                if (name.p[name.n - 1u] == '.')
                    return 0;
            }
            break;
        }
        case X_STATUS_REQUEST: {
            unsigned type;
            if (!u8(&d, &type) || !pre16(&d, &x) || !pre16(&d, &x))
                return 0;
            break;
        }
        case X_SUPPORTED_CURVES:
        case X_SIGNATURE_ALGORITHMS:
        case X_SIGNATURE_ALGORITHMS_CERT:
            if (!u16_list(&d))
                return 0;
            break;
        case X_SUPPORTED_POINTS:
            if (!pre8(&d, &x) || x.n == 0u)
                return 0;
            break;
        case X_SESSION_TICKET:
            (void)take(&d, d.n, NULL);
            break;
        case X_RENEGOTIATION_INFO:
            if (!pre8(&d, &x))
                return 0;
            break;
        case X_EXTENDED_MASTER_SECRET:
        case X_SCT:
        case X_EARLY_DATA:
            break;
        case X_ALPN: {
            cur list;
            if (!pre16(&d, &list) || list.n == 0u)
                return 0;
            while (list.n != 0u)
                if (!pre8(&list, &x) || x.n == 0u)
                    return 0;
            break;
        }
        case X_SUPPORTED_VERSIONS: {
            cur list;
            if (!pre8(&d, &list) || list.n == 0u)
                return 0;
            while (list.n != 0u)
                if (!u16(&list, &v))
                    return 0;
            break;
        }
        case X_COOKIE:
            if (!pre16(&d, &x) || x.n == 0u)
                return 0;
            break;
        case X_KEY_SHARE: {
            cur shares;
            if (!pre16(&d, &shares))
                return 0;
            while (shares.n != 0u)
                if (!u16(&shares, &v) || !pre16(&shares, &x) || x.n == 0u)
                    return 0;
            break;
        }
        case X_PSK_MODES:
            if (!pre8(&d, &x))
                return 0;
            break;
        case X_QUIC_TRANSPORT_PARAMETERS:
        case X_ENCRYPTED_CLIENT_HELLO:
            (void)take(&d, d.n, NULL);
            break;
        case X_PRE_SHARED_KEY: {
            if (exts.n != 0u)
                return 0; /* pre_shared_key must be the last extension */
            cur ids;
            if (!pre16(&d, &ids) || ids.n == 0u)
                return 0;
            while (ids.n != 0u)
                if (!pre16(&ids, &x) || !take(&ids, 4u, NULL) || x.n == 0u)
                    return 0;
            cur binders;
            if (!pre16(&d, &binders) || binders.n == 0u)
                return 0;
            while (binders.n != 0u)
                if (!pre8(&binders, &x) || x.n == 0u)
                    return 0;
            break;
        }
        default:
            continue;
        }
        if (d.n != 0u)
            return 0;
    }
    return 1;
}

/* encryptedExtensionsMsg.unmarshal (GOROOT/src/crypto/tls/handshake_messages.go:1056-1121). */
static int um_encrypted_extensions(cur s)
{
    seen_set seen;
    memset(&seen, 0, sizeof seen);
    cur exts, x;
    if (!take(&s, 4u, NULL) || !pre16(&s, &exts) || s.n != 0u)
        return 0;
    while (exts.n != 0u) {
        unsigned id;
        cur      d;
        if (!u16(&exts, &id) || !pre16(&exts, &d))
            return 0;
        if (!seen_once(&seen, id))
            return 0;
        switch (id) {
        case X_ALPN: {
            cur list;
            if (!pre16(&d, &list) || list.n == 0u)
                return 0;
            if (!pre8(&list, &x) || x.n == 0u || list.n != 0u)
                return 0;
            break;
        }
        case X_QUIC_TRANSPORT_PARAMETERS:
        case X_ENCRYPTED_CLIENT_HELLO:
            (void)take(&d, d.n, NULL);
            break;
        case X_EARLY_DATA:
            break;
        case X_SERVER_NAME:
            if (d.n != 0u)
                return 0;
            break;
        default:
            continue;
        }
        if (d.n != 0u)
            return 0;
    }
    return 1;
}

/* keyUpdateMsg.unmarshal (GOROOT/src/crypto/tls/handshake_messages.go:1153-1170). */
static int um_key_update(cur s)
{
    unsigned r;
    return take(&s, 4u, NULL) && u8(&s, &r) && s.n == 0u && r <= 1u;
}

/* newSessionTicketMsgTLS13.unmarshal (GOROOT/src/crypto/tls/handshake_messages.go:1206-1245). */
static int um_ticket13(cur s)
{
    cur x, exts;
    if (!take(&s, 4u, NULL) || !take(&s, 8u, NULL) || !pre8(&s, &x) || !pre16(&s, &x) ||
        !pre16(&s, &exts) || s.n != 0u)
        return 0;
    while (exts.n != 0u) {
        unsigned id;
        cur      d;
        if (!u16(&exts, &id) || !pre16(&exts, &d))
            return 0;
        if (id != X_EARLY_DATA)
            continue;
        if (!take(&d, 4u, NULL) || d.n != 0u)
            return 0;
    }
    return 1;
}

/* certificateRequestMsgTLS13.unmarshal (GOROOT/src/crypto/tls/handshake_messages.go:1315-1389). */
static int um_cert_request13(cur s)
{
    cur ctx, exts, x;
    if (!take(&s, 4u, NULL) || !pre8(&s, &ctx) || ctx.n != 0u || !pre16(&s, &exts) || s.n != 0u)
        return 0;
    while (exts.n != 0u) {
        unsigned id;
        cur      d;
        if (!u16(&exts, &id) || !pre16(&exts, &d))
            return 0;
        switch (id) {
        case X_STATUS_REQUEST:
        case X_SCT:
            break;
        case X_SIGNATURE_ALGORITHMS:
        case X_SIGNATURE_ALGORITHMS_CERT:
            if (!u16_list(&d))
                return 0;
            break;
        case X_CERTIFICATE_AUTHORITIES: {
            cur auths;
            if (!pre16(&d, &auths) || auths.n == 0u)
                return 0;
            while (auths.n != 0u)
                if (!pre16(&auths, &x) || x.n == 0u)
                    return 0;
            break;
        }
        default:
            continue;
        }
        if (d.n != 0u)
            return 0;
    }
    return 1;
}

/* certificateMsg.unmarshal, the TLS 1.2 form
 * (GOROOT/src/crypto/tls/handshake_messages.go:1425-1459) — including its `len(d) < 4` for a
 * three-byte length and its unsigned subtraction, both kept as they are. */
static int um_cert12(const uint8_t *data, size_t len)
{
    if (len < 7u)
        return 0;
    uint32_t certs = (uint32_t)data[4] << 16 | (uint32_t)data[5] << 8 | data[6];
    if ((uint32_t)len != certs + 7u)
        return 0;
    const uint8_t *d = data + 7;
    size_t         dn = len - 7u;
    while (certs > 0u) {
        if (dn < 4u)
            return 0;
        uint32_t one = (uint32_t)d[0] << 16 | (uint32_t)d[1] << 8 | d[2];
        if ((uint32_t)dn < 3u + one)
            return 0;
        d += 3u + one;
        dn -= 3u + one;
        certs -= 3u + one;
    }
    return 1;
}

/* certificateMsgTLS13.unmarshal and unmarshalCertificate
 * (GOROOT/src/crypto/tls/handshake_messages.go:1523-1599). */
static int um_cert13(cur s)
{
    cur ctx, list, x;
    if (!take(&s, 4u, NULL) || !pre8(&s, &ctx) || ctx.n != 0u || !pre24(&s, &list))
        return 0;
    unsigned n = 0;
    while (list.n != 0u) {
        cur exts;
        if (!pre24(&list, &x) || !pre16(&list, &exts))
            return 0;
        n++;
        while (exts.n != 0u) {
            unsigned id;
            cur      d;
            if (!u16(&exts, &id) || !pre16(&exts, &d))
                return 0;
            if (n > 1u)
                continue;
            if (id == X_STATUS_REQUEST) {
                unsigned type;
                if (!u8(&d, &type) || type != 1u || !pre24(&d, &x) || x.n == 0u)
                    return 0;
            } else if (id == X_SCT) {
                cur scts;
                if (!pre16(&d, &scts) || scts.n == 0u)
                    return 0;
                while (scts.n != 0u)
                    if (!pre16(&scts, &x) || x.n == 0u)
                        return 0;
            } else {
                continue;
            }
            if (d.n != 0u)
                return 0;
        }
    }
    return s.n == 0u;
}

/* certificateStatusMsg.unmarshal (GOROOT/src/crypto/tls/handshake_messages.go:1642-1653). */
static int um_cert_status(cur s)
{
    unsigned type;
    cur      resp;
    return take(&s, 4u, NULL) && u8(&s, &type) && type == 1u && pre24(&s, &resp) && resp.n != 0u &&
           s.n == 0u;
}

/* certificateRequestMsg.unmarshal, the TLS 1.2 form
 * (GOROOT/src/crypto/tls/handshake_messages.go:1776-1848), without the signature algorithms its
 * `hasSignatureAlgorithm` adds: that is c.vers >= VersionTLS12, and this form is read only while
 * c.vers is still 0 — once it is TLS 1.3 the TLS 1.3 form is read instead. */
static int um_cert_request12(const uint8_t *data, size_t len)
{
    if (len < 5u)
        return 0;
    uint32_t length = (uint32_t)data[1] << 16 | (uint32_t)data[2] << 8 | data[3];
    if ((uint32_t)len - 4u != length)
        return 0;
    size_t types = data[4];
    data += 5;
    len -= 5u;
    if (types == 0u || len <= types)
        return 0;
    data += types;
    len -= types;
    if (len < 2u)
        return 0;
    size_t cas = (size_t)data[0] << 8 | data[1];
    data += 2;
    len -= 2u;
    if (len < cas)
        return 0;
    const uint8_t *c = data;
    size_t         cn = cas;
    data += cas;
    len -= cas;
    while (cn > 0u) {
        if (cn < 2u)
            return 0;
        size_t one = (size_t)c[0] << 8 | c[1];
        c += 2;
        cn -= 2u;
        if (cn < one)
            return 0;
        c += one;
        cn -= one;
    }
    return len == 0u;
}

/* certificateVerifyMsg.unmarshal (GOROOT/src/crypto/tls/handshake_messages.go:1871-1883). */
static int um_cert_verify(cur s, int sigalgs)
{
    cur sig;
    unsigned v;
    if (!take(&s, 4u, NULL))
        return 0;
    if (sigalgs && !u16(&s, &v))
        return 0;
    return pre16(&s, &sig) && s.n == 0u;
}

/* newSessionTicketMsg.unmarshal, the TLS 1.2 form
 * (GOROOT/src/crypto/tls/handshake_messages.go:1905-1923). */
static int um_ticket12(const uint8_t *data, size_t len)
{
    if (len < 10u)
        return 0;
    uint32_t length = (uint32_t)data[1] << 16 | (uint32_t)data[2] << 8 | data[3];
    if ((uint32_t)len - 4u != length)
        return 0;
    size_t ticket = (size_t)data[8] << 8 | data[9];
    return len - 10u == ticket;
}

/* The switch in unmarshalHandshakeMessage (GOROOT/src/crypto/tls/conn.go:1127-1193): fifteen
 * types, three of them read by the length check alone — HelloRequest, EndOfEarlyData and
 * ServerHelloDone (GOROOT/src/crypto/tls/handshake_messages.go:1131-1133, :1663-1665) — two that
 * cannot fail once framed — ServerKeyExchange (:1617-1623) and ClientKeyExchange (:1683-1693) —
 * and ServerHello through the parser the verdict already uses. */
uint8_t lc_std_misplaced_alert(const uint8_t *msg, size_t len, int tls13)
{
    cur s = { msg, len };
    int ok;
    switch (msg[0]) {
    case 0:  /* HelloRequest */
    case 5:  /* EndOfEarlyData */
    case 14: /* ServerHelloDone */
        ok = len == 4u;
        break;
    case 1: ok = um_client_hello(s); break;
    case 2: {
        lc_server_hello sh;
        ok = lc_parse_server_hello(msg + 4, len - 4u, &sh) == 0;
        break;
    }
    case 4: ok = tls13 ? um_ticket13(s) : um_ticket12(msg, len); break;
    case 8: ok = um_encrypted_extensions(s); break;
    case 11: ok = tls13 ? um_cert13(s) : um_cert12(msg, len); break;
    case 12: /* ServerKeyExchange */
    case 16: /* ClientKeyExchange — its length is the header's, which the framing already holds */
        ok = 1;
        break;
    case 13: ok = tls13 ? um_cert_request13(s) : um_cert_request12(msg, len); break;
    case 15: ok = um_cert_verify(s, tls13); break;
    case 20: { /* Finished: the rest of the message, whatever it is */
        cur x;
        ok = take(&s, 1u, NULL) && pre24(&s, &x) && s.n == 0u;
        break;
    }
    case 22: ok = um_cert_status(s); break;
    case 24: ok = um_key_update(s); break;
    default: return LC_ALERT_UNEXPECTED_MESSAGE;
    }
    return ok ? LC_ALERT_UNEXPECTED_MESSAGE : LC_ALERT_DECODE_ERROR;
}

int lc_std_ticket13_reads(const uint8_t *msg, size_t len)
{
    cur s = { msg, len };
    return um_ticket13(s);
}

int lc_std_key_update_reads(const uint8_t *msg, size_t len, int *update_requested)
{
    cur s = { msg, len };
    if (!um_key_update(s))
        return 0;
    *update_requested = msg[4] == 1u;
    return 1;
}
