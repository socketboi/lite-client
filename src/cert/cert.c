#include "cert/cert.h"

#include <string.h>

/* DER tags this walk meets. */
#define TAG_INTEGER 0x02u
#define TAG_BIT_STRING 0x03u
#define TAG_OID 0x06u
#define TAG_SEQUENCE 0x30u
#define TAG_CONTEXT_0 0xa0u /* [0] EXPLICIT, the optional version field */

/* id-Ed25519, 1.3.101.112. The whole AlgorithmIdentifier for ed25519 is this OID and nothing else —
 * no parameters — which makes the check a plain comparison. */
static const uint8_t oid_ed25519[] = { 0x06, 0x03, 0x2b, 0x65, 0x70 };

typedef struct {
    const uint8_t *p;
    size_t         len;
    size_t         off;
} der_cur;

/* Reads one tag-length-value at the cursor. Content is returned without copying; the cursor moves
 * past the whole element. Definite lengths only — BER's indefinite form does not occur in
 * certificates and accepting it would only widen the input surface. */
static int der_read(der_cur *c, uint8_t *tag, const uint8_t **val, size_t *val_len)
{
    if (c->len - c->off < 2u)
        return -1;

    *tag = c->p[c->off];
    size_t off = c->off + 1u;
    size_t n;

    uint8_t first = c->p[off++];
    if (first < 0x80u) {
        n = first;
    } else {
        size_t count = first & 0x7fu;
        /* A zero count is the indefinite form; more than four bytes of length is a size no
         * certificate has and no buffer here could hold. */
        if (count == 0u || count > 4u || count > c->len - off)
            return -1;
        n = 0;
        for (size_t i = 0; i < count; i++)
            n = n << 8 | c->p[off + i];
        off += count;
        /* Lengths must be encoded minimally; a padded one is a different encoding of the same
         * value, and accepting both means two inputs hash differently but parse the same. */
        if (n < 0x80u)
            return -1;
    }

    if (n > c->len - off)
        return -1;

    *val = c->p + off;
    *val_len = n;
    c->off = off + n;
    return 0;
}

/* Steps over one element without looking inside it. */
static int der_skip(der_cur *c)
{
    uint8_t        tag;
    const uint8_t *val;
    size_t         len;
    return der_read(c, &tag, &val, &len);
}

static int walk_to_spki(const uint8_t *der, size_t len, der_cur *at);

int lc_cert_parse(const uint8_t *der, size_t len, lc_cert *out)
{
    memset(out, 0, sizeof *out);

    /* Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue } */
    der_cur top = { der, len, 0 };
    uint8_t tag;
    const uint8_t *cert_body;
    size_t cert_len;
    if (der_read(&top, &tag, &cert_body, &cert_len) != 0 || tag != TAG_SEQUENCE)
        return -1;

    der_cur cert = { cert_body, cert_len, 0 };

    const uint8_t *tbs;
    size_t tbs_len;
    if (der_read(&cert, &tag, &tbs, &tbs_len) != 0 || tag != TAG_SEQUENCE)
        return -1;

    if (der_skip(&cert) != 0) /* signatureAlgorithm */
        return -1;

    const uint8_t *sig;
    size_t sig_len;
    if (der_read(&cert, &tag, &sig, &sig_len) != 0 || tag != TAG_BIT_STRING)
        return -1;
    /* A BIT STRING starts with a count of unused trailing bits. For a signature it is always zero,
     * and a non-zero value would shift every byte that follows. */
    if (sig_len < 1u || sig[0] != 0x00u)
        return -1;
    out->signature = sig + 1;
    out->signature_len = sig_len - 1u;

    /* The same walk lc_cert_spki uses, taken through the one implementation of it: the field's
     * position is counted rather than recognised, and a second copy of that counting would be a
     * second thing to get right. */
    (void)tbs;
    (void)tbs_len;
    der_cur t;
    if (walk_to_spki(der, len, &t) != 0)
        return -1;

    /* SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING } */
    const uint8_t *spki;
    size_t spki_len;
    if (der_read(&t, &tag, &spki, &spki_len) != 0 || tag != TAG_SEQUENCE)
        return -1;

    der_cur s = { spki, spki_len, 0 };
    const uint8_t *alg;
    size_t alg_len;
    if (der_read(&s, &tag, &alg, &alg_len) != 0 || tag != TAG_SEQUENCE)
        return -1;
    /* The algorithm must be ed25519 and carry no parameters. Anything else is not a REALITY
     * server, and guessing at another key type would mean authenticating against something the
     * protocol never defined. */
    if (alg_len != sizeof oid_ed25519 || memcmp(alg, oid_ed25519, sizeof oid_ed25519) != 0)
        return -1;

    const uint8_t *key;
    size_t key_len;
    if (der_read(&s, &tag, &key, &key_len) != 0 || tag != TAG_BIT_STRING)
        return -1;
    if (key_len != LC_ED25519_PUBLIC + 1u || key[0] != 0x00u)
        return -1;

    out->public_key = key + 1;
    out->public_key_len = LC_ED25519_PUBLIC;
    return 0;
}

/* The walk down to subjectPublicKeyInfo, shared by the two questions asked of a certificate.
 * Leaves the cursor positioned at that field, having consumed everything before it. */
static int walk_to_spki(const uint8_t *der, size_t len, der_cur *at)
{
    der_cur        top = { der, len, 0 };
    uint8_t        tag;
    const uint8_t *cert_body;
    size_t         cert_len;
    if (der_read(&top, &tag, &cert_body, &cert_len) != 0 || tag != TAG_SEQUENCE)
        return -1;

    der_cur        cert = { cert_body, cert_len, 0 };
    const uint8_t *tbs;
    size_t         tbs_len;
    if (der_read(&cert, &tag, &tbs, &tbs_len) != 0 || tag != TAG_SEQUENCE)
        return -1;

    at->p = tbs;
    at->len = tbs_len;
    at->off = 0;
    if (at->len < 2u)
        return -1;

    /* version is optional, so the field is the seventh element when it is present and the sixth
     * when it is not; nothing in between is distinguishable by tag. */
    unsigned to_skip = (at->p[0] == TAG_CONTEXT_0) ? 6u : 5u;
    for (unsigned i = 0; i < to_skip; i++) {
        if (der_skip(at) != 0)
            return -1;
    }
    return 0;
}

int lc_cert_spki(const uint8_t *der, size_t len, const uint8_t **spki, size_t *spki_len)
{
    der_cur t;
    if (walk_to_spki(der, len, &t) != 0)
        return -1;

    /* Taken with its header rather than as a body: the cursor's position before and after the read
     * bracket the whole element, and a key parser is given the SEQUENCE, not its contents. */
    size_t         start = t.off;
    uint8_t        tag;
    const uint8_t *body;
    size_t         body_len;
    if (der_read(&t, &tag, &body, &body_len) != 0 || tag != TAG_SEQUENCE)
        return -1;

    *spki = t.p + start;
    *spki_len = t.off - start;
    return 0;
}

int lc_cert_key_supported(const uint8_t *der, size_t len)
{
    const uint8_t *spki;
    size_t         spki_len;
    if (lc_cert_spki(der, len, &spki, &spki_len) != 0)
        return -1;

    /* SPKI is SEQUENCE { AlgorithmIdentifier, BIT STRING }; the algorithm's OID is the first
     * element of the inner SEQUENCE. Walked by hand like the rest of this file — three tag/length
     * pairs — because pulling mbedTLS in here would decide the answer by which parsers that build
     * happens to carry, and the question is about the WIRE'S claim, not our parser's appetite. */
    der_cur t = { .p = spki, .len = spki_len, .off = 0 };
    uint8_t        tag;
    const uint8_t *body;
    size_t         body_len;
    if (der_read(&t, &tag, &body, &body_len) != 0 || tag != TAG_SEQUENCE)
        return -1;
    der_cur alg = { .p = body, .len = body_len, .off = 0 };
    if (der_read(&alg, &tag, &body, &body_len) != 0 || tag != TAG_SEQUENCE)
        return -1;
    der_cur oid = { .p = body, .len = body_len, .off = 0 };
    if (der_read(&oid, &tag, &body, &body_len) != 0 || tag != TAG_OID)
        return -1;

    /* The classical keys the reference accepts (vendor/utls/handshake_client.go:1239-1249), by the OIDs
     * their SPKIs carry: rsaEncryption 1.2.840.113549.1.1.1, id-ecPublicKey 1.2.840.10045.2.1,
     * id-Ed25519 1.3.101.112. Ed448 (1.3.101.113) is the nearest alien and differs in one byte. */
    static const uint8_t oid_rsa[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
    static const uint8_t oid_ec[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
    static const uint8_t oid_ed[] = { 0x2b, 0x65, 0x70 };
    static const uint8_t oid_mldsa[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03 };
    if ((body_len == sizeof oid_rsa && memcmp(body, oid_rsa, sizeof oid_rsa) == 0) ||
        (body_len == sizeof oid_ec && memcmp(body, oid_ec, sizeof oid_ec) == 0) ||
        (body_len == sizeof oid_ed && memcmp(body, oid_ed, sizeof oid_ed) == 0))
        return 1;
    if (body_len == sizeof oid_mldsa + 1u &&
        memcmp(body, oid_mldsa, sizeof oid_mldsa) == 0 &&
        body[sizeof oid_mldsa] >= 0x11u && body[sizeof oid_mldsa] <= 0x13u)
        return 2;
    return 0;
}

size_t lc_cert_rsa_bits(const uint8_t *der, size_t len)
{
    const uint8_t *spki;
    size_t         spki_len;
    if (lc_cert_spki(der, len, &spki, &spki_len) != 0)
        return 0;

    /* SEQUENCE { SEQUENCE { OID, params }, BIT STRING { RSAPublicKey } }, and RSAPublicKey is
     * SEQUENCE { INTEGER modulus, INTEGER publicExponent } (RFC 8017 A.1.1). */
    static const uint8_t oid_rsa[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
    der_cur        t = { .p = spki, .len = spki_len, .off = 0 };
    uint8_t        tag;
    const uint8_t *body;
    size_t         body_len;
    if (der_read(&t, &tag, &body, &body_len) != 0 || tag != TAG_SEQUENCE)
        return 0;
    der_cur in = { .p = body, .len = body_len, .off = 0 };
    if (der_read(&in, &tag, &body, &body_len) != 0 || tag != TAG_SEQUENCE)
        return 0;
    der_cur alg = { .p = body, .len = body_len, .off = 0 };
    if (der_read(&alg, &tag, &body, &body_len) != 0 || tag != TAG_OID ||
        body_len != sizeof oid_rsa || memcmp(body, oid_rsa, sizeof oid_rsa) != 0)
        return 0;
    if (der_read(&in, &tag, &body, &body_len) != 0 || tag != TAG_BIT_STRING || body_len < 1u ||
        body[0] != 0u)
        return 0;
    der_cur key = { .p = body + 1, .len = body_len - 1u, .off = 0 };
    if (der_read(&key, &tag, &body, &body_len) != 0 || tag != TAG_SEQUENCE)
        return 0;
    der_cur nums = { .p = body, .len = body_len, .off = 0 };
    if (der_read(&nums, &tag, &body, &body_len) != 0 || tag != TAG_INTEGER)
        return 0;
    while (body_len > 0u && body[0] == 0u) {
        body++;
        body_len--;
    }
    if (body_len == 0u)
        return 0;
    size_t bits = (body_len - 1u) * 8u;
    for (uint8_t top = body[0]; top != 0u; top = (uint8_t)(top >> 1))
        bits++;
    return bits;
}

int lc_cert_scheme_fits(const uint8_t *der, size_t len, uint16_t scheme)
{
    const uint8_t *spki;
    size_t         spki_len;
    if (lc_cert_spki(der, len, &spki, &spki_len) != 0)
        return 0;
    static const uint8_t oid_rsa[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
    static const uint8_t oid_ec[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
    static const uint8_t oid_ed[] = { 0x2b, 0x65, 0x70 };
    static const uint8_t p256[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
    static const uint8_t p384[] = { 0x2b, 0x81, 0x04, 0x00, 0x22 };
    static const uint8_t p521[] = { 0x2b, 0x81, 0x04, 0x00, 0x23 };

    der_cur        t = { .p = spki, .len = spki_len, .off = 0 };
    uint8_t        tag;
    const uint8_t *body;
    size_t         body_len;
    if (der_read(&t, &tag, &body, &body_len) != 0 || tag != TAG_SEQUENCE)
        return 0;
    der_cur in = { .p = body, .len = body_len, .off = 0 };
    if (der_read(&in, &tag, &body, &body_len) != 0 || tag != TAG_SEQUENCE)
        return 0;
    der_cur alg = { .p = body, .len = body_len, .off = 0 };
    if (der_read(&alg, &tag, &body, &body_len) != 0 || tag != TAG_OID)
        return 0;
#define OID_IS(o) (body_len == sizeof(o) && memcmp(body, o, sizeof(o)) == 0)
    if (OID_IS(oid_ed))
        return scheme == 0x0807u;
    if (OID_IS(oid_rsa)) {
        /* pub.Size() against each scheme's minModulusBytes: 2 * hash + 2 for PSS. */
        size_t bytes = (lc_cert_rsa_bits(der, len) + 7u) / 8u;
        return (scheme == 0x0804u && bytes >= 66u) || (scheme == 0x0805u && bytes >= 98u) ||
               (scheme == 0x0806u && bytes >= 130u);
    }
    if (OID_IS(oid_ec)) {
        if (der_read(&alg, &tag, &body, &body_len) != 0 || tag != TAG_OID)
            return 0;
        return (OID_IS(p256) && scheme == 0x0403u) || (OID_IS(p384) && scheme == 0x0503u) ||
               (OID_IS(p521) && scheme == 0x0603u);
    }
#undef OID_IS
    return 0;
}

/* The two per-entry extensions the reference understands, and the one status type it accepts. */
#define CERT_EXT_STATUS_REQUEST 5u
#define CERT_EXT_SCT            18u
#define CERT_STATUS_TYPE_OCSP   1u

/* ⚠️ THE EXTENSIONS OF THE LEAF ARE PARSED, NOT STEPPED OVER — which is where this walk and the
 * reference parted company.
 *
 * Stepping over the block is right for the LENGTHS and was taken for the whole answer. The
 * reference reads every record's frame, and for the leaf it reads the two extensions it knows and
 * refuses the message when either is malformed:
 *
 *     for !extensions.Empty() {
 *         if !extensions.ReadUint16(&extension) ||
 *             !extensions.ReadUint16LengthPrefixed(&extData) { return false }
 *         if len(certificate.Certificate) > 1 { continue }   // not the leaf
 *         switch extension {
 *         case extensionStatusRequest:
 *             if !extData.ReadUint8(&statusType) || statusType != statusTypeOCSP ||
 *                 !readUint24LengthPrefixed(&extData, &certificate.OCSPStaple) ||
 *                 len(certificate.OCSPStaple) == 0 { return false }
 *         case extensionSCT:
 *             if !extData.ReadUint16LengthPrefixed(&sctList) || sctList.Empty() { return false }
 *             for !sctList.Empty() {
 *                 if !readUint16LengthPrefixed(&sctList, &sct) || len(sct) == 0 { return false }
 *             }
 *         default:
 *             continue                                       // unknown: not even emptied
 *         }
 *         if !extData.Empty() { return false }
 *     }              (vendor/utls/handshake_messages.go:1611-1653)
 *
 * THREE RULES, AND EACH ONE IS A DIFFERENT ANSWER TO A DIFFERENT MESSAGE. The frame of every
 * record is checked on every entry, leaf or not. The CONTENT is checked only on the leaf — the
 * `continue` above is reached after the current certificate has already been appended, so
 * "more than one" means "this is not the first". And an extension neither of those numbers is
 * skipped whole, without even the trailing-bytes check the known two get.
 *
 * The reference is a client that keeps the staple and the SCTs; this one keeps neither, and that
 * is not a reason to skip the check — the message this walks carries the node's proof, and a peer
 * whose Certificate is refused by every Go client and accepted by ours is a peer that has told
 * itself apart from a browser. Not prober-reachable: it arrives under the handshake keys. The same
 * argument, and the same conclusion, as the empty-context check above.
 *
 * Returns 0 when the block is one the reference would accept. */
static int check_entry_extensions(const uint8_t *e, size_t n, int leaf)
{
    size_t q = 0;
    while (q < n) {
        if (n - q < 4u)
            return -1;
        size_t type = (size_t)e[q] << 8 | e[q + 1u];
        size_t blen = (size_t)e[q + 2u] << 8 | e[q + 3u];
        q += 4u;
        if (blen > n - q)
            return -1;

        const uint8_t *b = e + q;
        q += blen;

        if (!leaf)
            continue;

        if (type == CERT_EXT_STATUS_REQUEST) {
            /* One status type, then a 24-bit length that must account for the rest of the body
             * exactly: the reference reads the staple and then requires extData to be empty, so a
             * short staple with bytes after it is refused as loudly as a long one. */
            if (blen < 4u || b[0] != CERT_STATUS_TYPE_OCSP)
                return -1;
            size_t staple = (size_t)b[1] << 16 | (size_t)b[2] << 8 | b[3];
            if (staple == 0u || staple != blen - 4u)
                return -1;
        } else if (type == CERT_EXT_SCT) {
            if (blen < 2u)
                return -1;
            size_t list = (size_t)b[0] << 8 | b[1];
            /* Non-empty, and the whole of the body: sctList.Empty() is a refusal, and so is
             * anything left in extData once the list has been read. */
            if (list == 0u || list != blen - 2u)
                return -1;
            for (size_t r = 2u; r < blen;) {
                if (blen - r < 2u)
                    return -1;
                size_t sct = (size_t)b[r] << 8 | b[r + 1u];
                r += 2u;
                if (sct == 0u || sct > blen - r)
                    return -1;
                r += sct;
            }
        }
        /* Anything else: skipped whole. The reference's default arm continues before the
         * trailing-bytes check, so an unknown extension is not even required to be well used. */
    }
    return 0;
}

int lc_cert_next_from_message(const uint8_t *body, size_t len, size_t *off,
                              const uint8_t **der, size_t *der_len)
{
    /* The leaf is the entry parsed by the call that also reads the message header, because the
     * cursor is only zero once. Same test the reference makes with the length of the list it has
     * appended to so far, written against the one piece of state this walk carries. */
    const int leaf = *off == 0u;

    /* ⚠️ THIS FILE CITED NOTHING UNTIL NOW, WHICH KEPT IT OUT OF THE SIEVE — and the forward
     * pass cannot find anything in a file it never opens. src/cert/cert.c stood in COVERAGE.md
     * among those, at 260 lines, and what it parses is the message that carries the node's
     * proof: lc_cert_parse
     * decides whether the key is the ed25519 shape REALITY generates, and everything the REALITY
     * check then does rests on that answer. Read and cited on 2026-08-28; the reading found one
     * real divergence, closed below.
     *
     * Certificate ::= struct {
     *   opaque certificate_request_context<0..2^8-1>;
     *   CertificateEntry certificate_list<0..2^24-1>; }
     *
     * and each entry is a 24-bit length, the certificate, then its own 16-bit extensions block.
     * The reference walks the same shape in unmarshalCertificate — `ReadUint24LengthPrefixed` for
     * the list, then per entry a certificate and its extensions
     * (vendor/utls/handshake_messages.go:1599-1618).
     *
     * The header is read when the cursor is at zero and never again; after any entry the cursor is
     * past a certificate, so it cannot be zero and the two cases stay apart without a flag. */
    size_t p = *off;
    if (p == 0u) {
        if (len < 1u)
            return -1;
        size_t ctx_len = body[0];
        if (ctx_len > len - 1u)
            return -1;
        /* ⚠️ AND IT MUST BE EMPTY, which this skipped over. RFC 8446 §4.4.2 says the
         * certificate_request_context "SHALL be zero length" when the server is the one
         * authenticating — it only carries anything in answer to a CertificateRequest, which a
         * client never sends. The reference enforces exactly that and refuses the whole message
         * otherwise:
         *
         *     if !s.Skip(4) || // message type and uint24 length field
         *         !s.ReadUint8LengthPrefixed(&context) || !context.Empty() ||
         *         !unmarshalCertificate(&s, &m.certificate) ||
         *         !s.Empty() {
         *         return false
         *     }                    (vendor/utls/handshake_messages.go:1581-1591)
         *
         * — and a false from unmarshal becomes unexpected_message in readHandshake. We read the
         * length and stepped past it, so a peer sending a non-empty context got a client that
         * parsed on where every Go one stops. It is the message that carries the node's proof, so
         * accepting a shape the reference calls malformed is not a place to be lenient.
         *
         * Not reachable by a prober: this arrives under the handshake keys, so only a peer that
         * completed the key exchange can send one. Closed anyway because it is one line and the
         * reference is unambiguous — the argument for leaving EncryptedExtensions unchecked was
         * that checking it needed a parser this client does not have, and that argument does not
         * apply to a byte already in hand. */
        if (ctx_len != 0u)
            return -1;
        p = 1u + ctx_len;

        if (len - p < 3u)
            return -1;
        size_t list_len = (size_t)body[p] << 16 | (size_t)body[p + 1u] << 8 | body[p + 2u];
        p += 3u;
        if (list_len != len - p)
            return -1;
    }

    if (p == len)
        return 1;

    if (len - p < 3u)
        return -1;
    size_t cert_len = (size_t)body[p] << 16 | (size_t)body[p + 1u] << 8 | body[p + 2u];
    p += 3u;
    /* A certificate of no bytes is an ENTRY, not a malformed list: the reference's walk reads it
     * with readUint24LengthPrefixed, which takes a zero length
     * (vendor/utls/handshake_messages.go:1599-1610), and it is the X.509 parse after it that
     * refuses it — bad_certificate on the REALITY plane, decode_error on the QUIC one. Refusing it
     * here answered 10 on the REALITY plane, where the reference says 42. */
    if (cert_len > len - p)
        return -1;

    *der = body + p;
    *der_len = cert_len;
    p += cert_len;

    /* The per-entry extensions. Read rather than assumed empty: they are where a certificate's OCSP
     * response and SCTs travel in TLS 1.3, they are present on real chains, and a walk that skipped
     * them would read the next entry's length out of the middle of them. Their CONTENTS are the
     * subject of check_entry_extensions above. */
    if (len - p < 2u)
        return -1;
    size_t ext_len = (size_t)body[p] << 8 | body[p + 1u];
    p += 2u;
    if (ext_len > len - p)
        return -1;
    if (check_entry_extensions(body + p, ext_len, leaf) != 0)
        return -1;
    p += ext_len;

    *off = p;
    return 0;
}

int lc_cert_first_from_message(const uint8_t *body, size_t len,
                               const uint8_t **der, size_t *der_len)
{
    size_t off = 0;
    /* An exhausted list — the peer sent none — is a failure to THIS caller, which asked for one. */
    return lc_cert_next_from_message(body, len, &off, der, der_len) == 0 ? 0 : -1;
}

/* Big-endian into `out`, `n` bytes of `v`. */
static void put_be(uint8_t *out, size_t v, unsigned n)
{
    for (unsigned i = 0; i < n; i++)
        out[i] = (uint8_t)(v >> (8u * (n - 1u - i)));
}

size_t lc_cert13_remarshal(const uint8_t *body, size_t len, uint8_t *out, size_t cap)
{
    /* certificateMsgTLS13.marshal (vendor/utls/handshake_messages.go:1525-1542) over what
     * unmarshalCertificate kept (:1599-1657): an empty request context, every certificate, and on
     * the leaf alone the OCSP staple and the SCTs — the last staple the entry carried, and every
     * SCT of every SCT extension, in that order and in one extension — written by
     * marshalCertificate (:1544-1579). Anything else an entry carried is not kept, so it is not
     * written. The body has already passed lc_cert_next_from_message, whose checks are
     * unmarshalCertificate's. */
    size_t         o = 0, off = 0, der_len = 0;
    const uint8_t *der = NULL;
    int            leaf = 1;

    if (cap < 8u)
        return 0;
    out[o++] = 0x0bu; /* typeCertificate */
    o += 3u;
    out[o++] = 0u; /* certificate_request_context */
    size_t list_at = o;
    o += 3u;

    while (lc_cert_next_from_message(body, len, &off, &der, &der_len) == 0) {
        if (cap - o < 3u + der_len + 2u)
            return 0;
        put_be(out + o, der_len, 3u);
        memcpy(out + o + 3u, der, der_len);
        o += 3u + der_len;
        size_t ext_at = o;
        o += 2u;

        if (leaf) {
            const uint8_t *e = der + der_len + 2u;
            size_t         n = (size_t)der[der_len] << 8 | der[der_len + 1u];
            const uint8_t *staple = NULL;
            size_t         staple_len = 0, scts = 0;
            int            have_scts = 0;
            for (size_t q = 0; q + 4u <= n;) {
                size_t t = (size_t)e[q] << 8 | e[q + 1u], bl = (size_t)e[q + 2u] << 8 | e[q + 3u];
                if (t == CERT_EXT_STATUS_REQUEST) {
                    staple = e + q + 8u;
                    staple_len = bl - 4u;
                } else if (t == CERT_EXT_SCT) {
                    have_scts = 1;
                    scts += bl - 2u;
                }
                q += 4u + bl;
            }
            if (staple != NULL) {
                if (cap - o < 8u + staple_len)
                    return 0;
                put_be(out + o, CERT_EXT_STATUS_REQUEST, 2u);
                put_be(out + o + 2u, 4u + staple_len, 2u);
                out[o + 4u] = CERT_STATUS_TYPE_OCSP;
                put_be(out + o + 5u, staple_len, 3u);
                memcpy(out + o + 8u, staple, staple_len);
                o += 8u + staple_len;
            }
            if (have_scts) {
                /* One extension for all of them, as the builder writes it; past sixteen bits the
                 * reference's builder fails and so does this. */
                if (scts > 0xffffu - 2u || cap - o < 6u + scts)
                    return 0;
                put_be(out + o, CERT_EXT_SCT, 2u);
                put_be(out + o + 2u, 2u + scts, 2u);
                put_be(out + o + 4u, scts, 2u);
                o += 6u;
                for (size_t q = 0; q + 4u <= n;) {
                    size_t t = (size_t)e[q] << 8 | e[q + 1u], bl = (size_t)e[q + 2u] << 8 | e[q + 3u];
                    if (t == CERT_EXT_SCT) {
                        memcpy(out + o, e + q + 6u, bl - 2u);
                        o += bl - 2u;
                    }
                    q += 4u + bl;
                }
            }
        }
        put_be(out + ext_at, o - ext_at - 2u, 2u);
        leaf = 0;
    }

    put_be(out + list_at, o - list_at - 3u, 3u);
    put_be(out + 1u, o - 4u, 3u);
    return o;
}
