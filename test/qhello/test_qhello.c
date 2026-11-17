/* The QUIC ClientHello, held to what the reference client puts on the wire.
 *
 * WHY THIS FILE EXISTS, AND IT IS NOT A HYPOTHETICAL. The REALITY hello has had a gate since
 * test/fphello: the shipped fingerprint table is rendered and compared byte for byte against a
 * frozen uTLS capture, so a drift fails here rather than in somebody else's traffic analysis. The
 * hello of the OTHER plane — this one, built by hand in src/quic/qtls.c — had no such check, and on
 * 2026-08-25 that showed: it offered twelve signature schemes where the reference offers seven, and
 * omitted signature_algorithms_cert entirely. Both had been there since the extension was written.
 * Nothing in the tree could have noticed.
 *
 * WHERE THE EXPECTED VALUES COME FROM — measured, not copied out of a specification. A server was
 * built from vendor/quic-go (the apernet fork, the one hysteria itself runs on) with
 * `tls.Config.GetConfigForClient` printing the parsed hello, and the reference hysteria client was
 * pointed at it. What it offered is what is asserted below. `ClientHelloInfo.Extensions` gives the
 * identifiers IN THE ORDER THEY WERE SENT, which is the part no amount of reading the source would
 * have settled.
 *
 * Rebuild that stand rather than trusting this file if the numbers here ever need changing; the
 * recipe is forty lines of Go and hysteria itself wires no qlog tracer, so its own server cannot be
 * asked. ⚠️ `go mod tidy` before building it: without it the build fails on go.sum, the stand never
 * starts, and a diff of two empty captures says "no differences".
 *
 * WHAT IS DELIBERATELY NOT ASSERTED: the cipher suite ORDER. It depends on whether the machine has
 * AES acceleration — Go reorders on exactly that, and so does qtls.c through
 * lc_qtls_aesgcm_hardware — so a fixed expectation here would assert the build host rather than the
 * client. The suites themselves are checked; their order has its own reasoning in qtls.c. */

#include "quic/qtls.c"

#include <stdio.h>
#include <string.h>
#include "trust_anchors.h"

static int fails;

static void ok(int cond, const char *what)
{
    if (cond) {
        printf("  ok    %s\n", what);
    } else {
        printf("  FAIL  %s\n", what);
        fails++;
    }
}

/* The identifiers the reference sent, in its order. 13 is signature_algorithms and 50 is
 * signature_algorithms_cert — the pair this file was written for. */
static const uint16_t expect_exts[] = { 0, 11, 65281, 23, 18, 57, 5, 10, 13, 50, 16, 43, 51 };

/* supportedSignatureAlgorithms(minVersion) with a TLS 1.3 minimum: the default list with every
 * PKCS#1 v1.5 scheme and both SHA-1 ones deleted. See the block in qtls.c for Go's own code. */
static const uint16_t expect_sigs[] = { 0x0804u, 0x0403u, 0x0807u, 0x0805u, 0x0806u,
                                        0x0503u, 0x0603u };

/* supportedSignatureAlgorithmsCert(): the same default list, UNFILTERED. Go includes SHA-1 and
 * PKCS#1 here on purpose — a peer holding only a PKCS#1-signed chain should send it rather than
 * decide we would refuse it. */
static const uint16_t expect_sigs_cert[] = { 0x0804u, 0x0403u, 0x0807u, 0x0805u, 0x0806u, 0x0401u,
                                             0x0501u, 0x0601u, 0x0503u, 0x0603u, 0x0201u, 0x0203u };

static uint16_t be16(const uint8_t *p) { return (uint16_t)((uint16_t)p[0] << 8 | p[1]); }

/* A QUIC varint, read back out of what this client wrote. RFC 9000 §16: the top two bits of the
 * first byte say how many bytes the number occupies, and the remaining six are its top bits.
 *
 * Written here rather than taken from src/quic/varint.c on purpose. The point of these assertions is
 * what reached the wire; decoding it with the same code that encoded it would make a pair of
 * matching mistakes agree, which is the one outcome that must not read as a pass. */
static int tp_varint(const uint8_t *p, size_t len, size_t *off, uint64_t *v)
{
    if (*off >= len)
        return -1;
    unsigned n = 1u << (p[*off] >> 6);
    if (len - *off < n)
        return -1;
    uint64_t x = (uint64_t)(p[*off] & 0x3fu);
    for (unsigned i = 1; i < n; i++)
        x = (x << 8) | p[*off + i];
    *off += n;
    *v = x;
    return 0;
}

/* Walks the hello and hands back the extension identifiers in order plus the two bodies wanted.
 * Returns 0 on a well-formed message. Deliberately strict: a length that runs past the end is a
 * failure and not a truncation, because a hello this code cannot parse is one it should not have
 * produced. */
static int walk(const uint8_t *h, size_t len, uint16_t *ids, size_t *n_ids,
                const uint8_t **bodies, size_t *blens,
                const uint8_t **sigs, size_t *sigs_len,
                const uint8_t **sigs_cert, size_t *sigs_cert_len,
                const uint8_t **tparams, size_t *tparams_len)
{
    size_t off = 0;
    *n_ids = 0;
    *sigs = *sigs_cert = *tparams = NULL;
    *sigs_len = *sigs_cert_len = *tparams_len = 0;

    if (len < 4u || h[0] != LC_HS_CLIENT_HELLO)
        return -1;
    size_t body = (size_t)h[1] << 16 | (size_t)h[2] << 8 | h[3];
    if (body + 4u != len)
        return -1;
    off = 4u;

    off += 2u;  /* legacy_version */
    off += 32u; /* random */
    if (off >= len)
        return -1;
    off += 1u + h[off]; /* legacy_session_id */

    if (off + 2u > len)
        return -1;
    off += 2u + be16(h + off); /* cipher_suites */

    if (off >= len)
        return -1;
    off += 1u + h[off]; /* legacy_compression_methods */

    if (off + 2u > len)
        return -1;
    size_t ext_total = be16(h + off);
    off += 2u;
    if (off + ext_total != len)
        return -1;

    size_t end = off + ext_total;
    while (off + 4u <= end) {
        uint16_t type = be16(h + off);
        uint16_t elen = be16(h + off + 2u);
        off += 4u;
        if (off + elen > end)
            return -1;
        if (*n_ids < 64u) {
            bodies[*n_ids] = h + off;
            blens[*n_ids] = elen;
            ids[(*n_ids)++] = type;
        }
        /* ⚠️ THE NUMBERS, NOT THE NAMES. Using EXT_SIGNATURE_ALGORITHMS_CERT here would make this
         * test follow the code instead of the wire: a change to the #define moves the constant in
         * both places at once and the assertion below stays green while the extension goes out
         * under a different identifier. Measured — mutating the define from 0x0032 to 0x0031 left
         * "signature_algorithms_cert is present" passing, and only the hardcoded order caught it.
         * 13 and 50 are what IANA assigned and what the reference sent; they are the truth this
         * file is here to hold, so they are written out. */
        if (type == 0x000du) {
            *sigs = h + off;
            *sigs_len = elen;
        } else if (type == 0x0032u) {
            *sigs_cert = h + off;
            *sigs_cert_len = elen;
        } else if (type == 0x0039u) {
            /* quic_transport_parameters. 57 written out for the reason two lines of comment above
             * give about 13 and 50: the identifier on the wire is the fact, and a #define that moves
             * would move the assertion with it. */
            *tparams = h + off;
            *tparams_len = elen;
        }
        off += elen;
    }
    return off == end ? 0 : -1;
}

/* One extension's body, by identifier, out of what walk collected. Returns NULL when the hello did
 * not carry it — which is itself an answer worth asserting, so absence is not an error here. */
static const uint8_t *body_of(const uint16_t *ids, const uint8_t **bodies, const size_t *blens,
                              size_t n, uint16_t want, size_t *out_len)
{
    for (size_t i = 0; i < n; i++) {
        if (ids[i] == want) {
            *out_len = blens[i];
            return bodies[i];
        }
    }
    *out_len = 0;
    return NULL;
}

/* A list-of-u16 extension body: a two-byte length, then that many bytes of pairs. */
static int list_is(const uint8_t *body, size_t len, const uint16_t *want, size_t n_want)
{
    if (body == NULL || len < 2u)
        return 0;
    if (be16(body) != len - 2u)
        return 0;
    if (len - 2u != n_want * 2u)
        return 0;
    for (size_t i = 0; i < n_want; i++) {
        if (be16(body + 2u + i * 2u) != want[i])
            return 0;
    }
    return 1;
}

/* One transport parameter out of a blob: its identifier, its value's bytes. */
typedef struct {
    uint64_t       id;
    const uint8_t *val;
    size_t         len;
    size_t         id_width; /* bytes its identifier took on the wire */
} tp_entry;

static size_t tp_split(const uint8_t *p, size_t len, tp_entry *out, size_t cap)
{
    size_t off = 0, n = 0;
    while (off < len && n < cap) {
        uint64_t id = 0, l = 0;
        size_t   at = off;
        if (tp_varint(p, len, &off, &id) != 0)
            return 0;
        size_t w = off - at;
        if (tp_varint(p, len, &off, &l) != 0 || l > len - off)
            return 0;
        out[n].id = id;
        out[n].val = p + off;
        out[n].len = (size_t)l;
        out[n].id_width = w;
        n++;
        off += (size_t)l;
    }
    return off == len ? n : 0;
}

static uint64_t tp_value(const tp_entry *e)
{
    size_t   off = 0;
    uint64_t v = UINT64_MAX;
    if (tp_varint(e->val, e->len, &off, &v) != 0 || off != e->len)
        return UINT64_MAX;
    return v;
}

/* THE HELLO WHILE PARROTING CHROME — hysteria's default from 2.11.
 *
 * WHERE THE EXPECTED VALUES COME FROM. The shape of the message is the fork's own spec,
 * chromeQUICClientHelloSpec (vendor/quic-go/internal/handshake/chrome_client_hello.go:20-76),
 * rendered through uTLS by tools/fp into src/quic/chrome_hello.h and gated by check-fingerprint; what
 * is asserted here is that qtls.c builds from that table what the spec says, and the parameters
 * marshalChrome writes (vendor/quic-go/internal/wire/transport_parameters_chrome.go:49-156) with the
 * values the parrot pins (vendor/quic-go/chrome_parrot.go:12-39). The same things were read off the
 * wire from the reference client itself by tools/vendorcap/qstand. */
static void chrome_cases(void)
{
    printf("\nthe same, while parroting Chrome\n\n");

    /* What ngtcp2 encodes for lc_qparams(p, 1), in ngtcp2's order, with four entries marshalChrome
     * does NOT write — ack_delay_exponent, max_ack_delay, disable_active_migration and
     * active_connection_id_limit — so their absence below is the writer's doing. */
    static const uint8_t params[] = {
        0x0fu, 0x00u,                                   /* initial_source_connection_id, empty */
        0x05u, 0x04u, 0x80u, 0x60u, 0x00u, 0x00u,       /* 6291456 */
        0x06u, 0x04u, 0x80u, 0x60u, 0x00u, 0x00u,
        0x07u, 0x04u, 0x80u, 0x60u, 0x00u, 0x00u,
        0x04u, 0x04u, 0x80u, 0xf0u, 0x00u, 0x00u,       /* 15728640 */
        0x08u, 0x02u, 0x40u, 0x64u,                     /* 100 */
        0x09u, 0x02u, 0x40u, 0x67u,                     /* 103 */
        0x03u, 0x02u, 0x45u, 0xc0u,                     /* 1472 */
        0x0au, 0x01u, 0x03u,
        0x0bu, 0x01u, 0x19u,
        0x0cu, 0x00u,
        0x01u, 0x04u, 0x80u, 0x00u, 0x75u, 0x30u,       /* 30000 ms */
        0x0eu, 0x01u, 0x02u,
        0x20u, 0x04u, 0x80u, 0x01u, 0x00u, 0x00u,       /* 65536 */
    };

    static uint8_t hello[4096];
    size_t         hello_len = 0;
    lc_qtls        q;
    memset(&q, 0, sizeof q);
    q.chrome = 1;
    if (build_hello_chrome(&q, "stand.local", params, sizeof params, hello, sizeof hello,
                           &hello_len) != 0) {
        printf("  FAIL  the Chrome hello could not be built at all\n");
        fails++;
        return;
    }

    uint16_t       ids[64];
    size_t         n_ids = 0;
    const uint8_t *bodies[64];
    size_t         blens[64];
    const uint8_t *sigs, *sigs_cert, *tp;
    size_t         sigs_len, sigs_cert_len, tp_len;
    ok(walk(hello, hello_len, ids, &n_ids, bodies, blens, &sigs, &sigs_len, &sigs_cert,
            &sigs_cert_len, &tp, &tp_len) == 0,
       "the Chrome hello parses end to end");

    /* The twelve of the 2.13.0 spec and no other, in whatever order this hello drew. */
    static const uint16_t want_set[] = { 0u, 10u, 13u, 16u, 27u, 43u, 45u, 51u, 57u, 17613u,
                                         0xfe0du, 0xca34u };
    int set_ok = n_ids == sizeof want_set / sizeof want_set[0];
    for (size_t i = 0; set_ok && i < sizeof want_set / sizeof want_set[0]; i++) {
        size_t seen = 0;
        for (size_t j = 0; j < n_ids; j++)
            seen += ids[j] == want_set[i];
        set_ok = seen == 1u;
    }
    ok(set_ok, "twelve extensions, the spec's: trust_anchors, no GREASE extension, no padding, no point formats");
    size_t anchors_len;
    const uint8_t *anchors = body_of(ids, bodies, blens, n_ids, 0xca34u, &anchors_len);
    ok(anchors != NULL && anchors_len == sizeof reference_trust_anchors &&
           memcmp(anchors, reference_trust_anchors, sizeof reference_trust_anchors) == 0,
       "trust_anchors bytes match the actual quic-go reference, including ordering and lengths");

    /* Suites in the spec's order whatever the hardware — uTLS sends the list as written. */
    {
        size_t off = 4u + 2u + 32u;
        int    sid_empty = hello[off] == 0u;
        off += 1u + hello[off];
        static const uint8_t suites[] = { 0x00u, 0x06u, 0x13u, 0x01u, 0x13u, 0x02u, 0x13u, 0x03u };
        ok(sid_empty, "an empty legacy session id, as uTLS leaves it over QUIC");
        ok(memcmp(hello + off, suites, sizeof suites) == 0,
           "three suites, AES-128 first whatever this machine has");
    }

    size_t         n;
    const uint8_t *b;
    static const uint8_t groups[] = { 0x00u, 0x08u, 0x11u, 0xecu, 0x00u, 0x1du, 0x00u, 0x17u,
                                      0x00u, 0x18u };
    b = body_of(ids, bodies, blens, n_ids, 10u, &n);
    ok(b != NULL && n == sizeof groups && memcmp(b, groups, n) == 0,
       "four groups: X25519MLKEM768, X25519, P-256, P-384 — no P-521, no GREASE");
    static const uint16_t chrome_sigs[] = { 0x0403u, 0x0804u, 0x0401u, 0x0503u, 0x0805u,
                                            0x0501u, 0x0806u, 0x0601u, 0x0201u };
    ok(list_is(sigs, sigs_len, chrome_sigs, sizeof chrome_sigs / sizeof chrome_sigs[0]),
       "the nine signature schemes of the spec, in its order, PKCS#1 and SHA-1 included");
    ok(sigs_cert == NULL, "and no signature_algorithms_cert");
    static const uint8_t alpn[] = { 0x00u, 0x03u, 0x02u, 'h', '3' };
    b = body_of(ids, bodies, blens, n_ids, 16u, &n);
    ok(b != NULL && n == sizeof alpn && memcmp(b, alpn, n) == 0, "ALPN h3");
    b = body_of(ids, bodies, blens, n_ids, 17613u, &n);
    ok(b != NULL && n == sizeof alpn && memcmp(b, alpn, n) == 0, "ALPS at 17613, for h3");
    static const uint8_t brotli[] = { 0x02u, 0x00u, 0x02u };
    b = body_of(ids, bodies, blens, n_ids, 27u, &n);
    ok(b != NULL && n == sizeof brotli && memcmp(b, brotli, n) == 0,
       "certificate compression offers brotli alone");
    static const uint8_t v13[] = { 0x02u, 0x03u, 0x04u };
    b = body_of(ids, bodies, blens, n_ids, 43u, &n);
    ok(b != NULL && n == sizeof v13 && memcmp(b, v13, n) == 0, "TLS 1.3 only, no GREASE version");
    static const uint8_t dhe[] = { 0x01u, 0x01u };
    b = body_of(ids, bodies, blens, n_ids, 45u, &n);
    ok(b != NULL && n == sizeof dhe && memcmp(b, dhe, n) == 0, "psk_dhe_ke");

    b = body_of(ids, bodies, blens, n_ids, 51u, &n);
    int ks_ok = b != NULL && n == 2u + (4u + 1216u) + (4u + 32u) && be16(b) == n - 2u &&
                be16(b + 2) == 4588u && be16(b + 4) == 1216u && be16(b + 2 + 4 + 1216) == 29u &&
                be16(b + 2 + 4 + 1216 + 2) == 32u;
    ok(ks_ok, "key_share: the hybrid, then bare X25519");
    /* ApplyPreset gives each share its own key (vendor/utls-hy/u_parrots.go:2875-2922). Not
     * structural here, unlike the crypto/tls hello above: the two are generated apart, so equal
     * tails would mean the shares came from one key. */
    ok(ks_ok && memcmp(b + 2 + 4 + 1216 - 32, b + 2 + 4 + 1216 + 4, 32) != 0,
       "and the X25519 share has a key of its own, not the hybrid's classical half");

    b = body_of(ids, bodies, blens, n_ids, 0xfe0du, &n);
    ok(b != NULL && n > 10u + 32u &&
           (be16(b + 8u + 32u) == 144u || be16(b + 8u + 32u) == 176u ||
            be16(b + 8u + 32u) == 208u || be16(b + 8u + 32u) == 240u),
       "GREASE ECH with one of BoringSSL's four payload lengths");

    /* The transport parameters, as marshalChrome writes them. */
    tp_entry e[32];
    size_t   ne = tp != NULL ? tp_split(tp, tp_len, e, 32u) : 0u;
    ok(ne == 13u, "thirteen transport parameters");
    uint64_t want_vals[][2] = {
        { 0x01u, 30000u }, { 0x03u, 1472u }, { 0x04u, 15728640u }, { 0x05u, 6291456u },
        { 0x06u, 6291456u }, { 0x07u, 6291456u }, { 0x08u, 100u }, { 0x09u, 103u },
        { 0x20u, 65536u },
    };
    int vals_ok = 1, have_scid = 0, have_vi = 0, vi_ok = 0, have_opts = 0, have_grease = 0,
        grease_ok = 0, dropped = 1;
    for (size_t i = 0; i < sizeof want_vals / sizeof want_vals[0]; i++) {
        int found = 0;
        for (size_t j = 0; j < ne; j++)
            if (e[j].id == want_vals[i][0])
                found += tp_value(&e[j]) == want_vals[i][1];
        vals_ok = vals_ok && found == 1;
    }
    for (size_t j = 0; j < ne; j++) {
        if (e[j].id == 0x0fu)
            have_scid = e[j].len == 0u;
        if (e[j].id == 0x11u) {
            have_vi = 1;
            vi_ok = e[j].len == 12u && be16(e[j].val) == 0u && be16(e[j].val + 2) == 1u &&
                    ((be16(e[j].val + 4) == 0u && be16(e[j].val + 6) == 1u &&
                      (e[j].val[8] & 0x0fu) == 0x0au && (e[j].val[11] & 0x0fu) == 0x0au) ||
                     (be16(e[j].val + 8) == 0u && be16(e[j].val + 10) == 1u &&
                      (e[j].val[4] & 0x0fu) == 0x0au && (e[j].val[7] & 0x0fu) == 0x0au));
        }
        if (e[j].id == 0x3128u)
            have_opts = e[j].len == 4u && memcmp(e[j].val, "ORIG", 4) == 0;
        if (e[j].id % 31u == 27u && e[j].id >= (1ull << 30)) {
            have_grease++;
            grease_ok = e[j].id_width == 8u && e[j].len <= 15u;
        }
        if (e[j].id == 0x0au || e[j].id == 0x0bu || e[j].id == 0x0cu || e[j].id == 0x0eu)
            dropped = 0;
    }
    ok(vals_ok, "the numbers the parrot pins: 30 s, 1472, 15728640, 6291456 thrice, 100, 103, 65536");
    ok(have_scid, "initial_source_connection_id, empty");
    ok(have_vi && vi_ok, "version_information: version 1 chosen, then 1 and a GREASE version");
    ok(have_opts, "google_connection_options, ORIG");
    ok(have_grease == 1 && grease_ok, "one GREASE parameter, 31N+27 in eight bytes, 0..15 of value");
    ok(dropped, "and none of the four Chrome leaves to their defaults");

    /* THE DRAWS DIFFER BETWEEN HELLOS: the extension order (the shuffle), the parameter order (a
     * second, independent shuffle), where GREASE sits in version_information. Two hundred hellos is
     * far past what any of these needs to show both sides. */
    int ext_moved = 0, tp_moved = 0, vi_both[2] = { 0, 0 }, ech_lens = 0;
    uint16_t first_ids[64];
    size_t   first_n = n_ids;
    memcpy(first_ids, ids, sizeof first_ids);
    uint64_t first_tp0 = ne != 0u ? e[0].id : 0u;
    unsigned seen_len = 0;
    for (int k = 0; k < 200; k++) {
        lc_qtls q2;
        memset(&q2, 0, sizeof q2);
        q2.chrome = 1;
        if (build_hello_chrome(&q2, "stand.local", params, sizeof params, hello, sizeof hello,
                               &hello_len) != 0 ||
            walk(hello, hello_len, ids, &n_ids, bodies, blens, &sigs, &sigs_len, &sigs_cert,
                 &sigs_cert_len, &tp, &tp_len) != 0)
            break;
        if (n_ids == first_n && memcmp(ids, first_ids, n_ids * sizeof ids[0]) != 0)
            ext_moved = 1;
        tp_entry e2[32];
        size_t   ne2 = tp_split(tp, tp_len, e2, 32u);
        if (ne2 != 0u && e2[0].id != first_tp0)
            tp_moved = 1;
        for (size_t j = 0; j < ne2; j++)
            if (e2[j].id == 0x11u && e2[j].len == 12u)
                vi_both[be16(e2[j].val + 6) == 1u ? 0 : 1] = 1;
        b = body_of(ids, bodies, blens, n_ids, 0xfe0du, &n);
        if (b != NULL && n > 42u)
            seen_len |= 1u << ((be16(b + 40u) - 144u) / 32u & 3u);
    }
    for (unsigned bit = 0; bit < 4u; bit++)
        ech_lens += (int)(seen_len >> bit & 1u);
    ok(ext_moved, "the extension order changes from one hello to the next");
    ok(tp_moved, "and so does the order of the transport parameters");
    ok(vi_both[0] && vi_both[1], "the GREASE version comes first in some hellos and second in others");
    ok(ech_lens == 4, "all four GREASE ECH lengths appear");
}

int main(void)
{
    printf("\nthe QUIC ClientHello, against what the reference client sends\n\n");

    /* ⚠️ THE INPUT IS IN NGTCP2'S ORDER, WHICH IS THE ONLY WAY THE REORDERING IS TESTED AT ALL.
     *
     * This blob used to be three entries that happened to be in the output order already, so the
     * writer could have been a straight copy and nothing here would have noticed. What the writer
     * actually does is move the parameters into quic-go's order, drop what quic-go never writes, and
     * synthesise the one entry ngtcp2 refuses to encode — none of which a sorted three-entry input
     * can tell apart from doing nothing.
     *
     * So this is what ngtcp2 really produces for this configuration, in the order qtls.c names:
     * initial_source_connection_id first, then 05 06 07 04 09 03 0b 01 0e. Two deliberate departures
     * from that: initial_max_streams_bidi is ABSENT, because ngtcp2 skips a zero and the writer has
     * to put it back; and max_datagram_frame_size IS present, because hysteria keeps it off the wire
     * and the writer has to drop it.
     *
     * ⚠️ ACK_DELAY_EXPONENT AND DISABLE_ACTIVE_MIGRATION ARE NOT HERE, and their absence is the
     * reference's rather than a shortcut. Marshal writes each only when it differs from the RFC
     * default — `if p.AckDelayExponent != protocol.DefaultAckDelayExponent` and
     * `if p.DisableActiveMigration` (transport_parameters.go:403-412) — and quic-go sets
     * AckDelayExponent to protocol.AckDelayExponent, which IS 3, which IS
     * DefaultAckDelayExponent (internal/protocol/protocol.go:134, params.go:137, quic-go/connection.go:337). So neither
     * reaches the wire. ngtcp2 skips both for the same reason, so a faithful input has neither.
     *
     * This matters more than an unused test vector: the qlog measurement quic/params.h rests on
     * reports EFFECTIVE parameters, and an absent one reads there as its default. "ack_delay_exponent
     * 3 on both" was therefore true of that capture whether the byte was sent or not, and could not
     * have told the two apart. The list below can.
     *
     * The values are the ones quic/params.c states, encoded as ngtcp2 would encode them. */
    static const uint8_t params[] = {
        0x0fu, 0x04u, 0xde, 0xad, 0xbe, 0xef,     /* initial_source_connection_id */
        0x05u, 0x04u, 0x80u, 0x80u, 0x00u, 0x00u, /* initial_max_stream_data_bidi_local  8388608 */
        0x06u, 0x04u, 0x80u, 0x80u, 0x00u, 0x00u, /* initial_max_stream_data_bidi_remote 8388608 */
        0x07u, 0x04u, 0x80u, 0x80u, 0x00u, 0x00u, /* initial_max_stream_data_uni         8388608 */
        0x04u, 0x04u, 0x81u, 0x40u, 0x00u, 0x00u, /* initial_max_data                   20971520 */
        0x09u, 0x02u, 0x40u, 0x64u,               /* initial_max_streams_uni                 100 */
        0x03u, 0x02u, 0x45u, 0xacu,               /* max_udp_payload_size                   1452 */
        0x0bu, 0x01u, 0x1au,                      /* max_ack_delay                         26 ms */
        0x01u, 0x04u, 0x80u, 0x00u, 0x75u, 0x30u, /* max_idle_timeout                   30 000 ms */
        0x0eu, 0x01u, 0x04u,                      /* active_connection_id_limit                4 */
        0x20u, 0x02u, 0x44u, 0xb0u,               /* max_datagram_frame_size — must be DROPPED */
    };

    /* What has to come back, and in this sequence: TransportParameters.Marshal's own run of writes
     * (vendor/quic-go/internal/wire/transport_parameters.go:360-457). It is the same eleven the
     * comment above qtls.c's order[] names as quic-go's line. Written as numbers for the reason the
     * extension identifiers are — see the note in walk(). */
    static const uint8_t expect_tp[] = { 0x05u, 0x06u, 0x07u, 0x04u, 0x08u, 0x09u,
                                         0x01u, 0x03u, 0x0bu, 0x0eu, 0x0fu };

    lc_qtls q;
    memset(&q, 0, sizeof q);

    static uint8_t hello[4096];
    size_t         hello_len = 0;
    if (build_hello(&q, "stand.local", params, sizeof params, hello, sizeof hello, &hello_len) != 0) {
        printf("  FAIL  the hello could not be built at all\n");
        return 1;
    }

    uint16_t       ids[64];
    size_t         n_ids = 0;
    const uint8_t *bodies[64];
    size_t         blens[64];
    const uint8_t *sigs = NULL, *sigs_cert = NULL, *tparams = NULL;
    size_t         sigs_len = 0, sigs_cert_len = 0, tparams_len = 0;
    if (walk(hello, hello_len, ids, &n_ids, bodies, blens, &sigs, &sigs_len, &sigs_cert,
             &sigs_cert_len, &tparams, &tparams_len) != 0) {
        printf("  FAIL  the hello this client built does not parse\n");
        return 1;
    }

    int order_ok = n_ids == sizeof expect_exts / sizeof expect_exts[0];
    for (size_t i = 0; order_ok && i < n_ids; i++)
        order_ok = ids[i] == expect_exts[i];
    if (!order_ok) {
        printf("  ---   sent:");
        for (size_t i = 0; i < n_ids; i++)
            printf(" %u", ids[i]);
        printf("\n  ---   want:");
        for (size_t i = 0; i < sizeof expect_exts / sizeof expect_exts[0]; i++)
            printf(" %u", expect_exts[i]);
        printf("\n");
    }
    ok(order_ok, "the extensions are the reference's, in the reference's order");

    ok(sigs != NULL, "signature_algorithms is present");
    ok(list_is(sigs, sigs_len, expect_sigs, sizeof expect_sigs / sizeof expect_sigs[0]),
       "signature_algorithms is the seven a TLS 1.3 minimum leaves");

    ok(sigs_cert != NULL, "signature_algorithms_cert is present at all");
    ok(list_is(sigs_cert, sigs_cert_len, expect_sigs_cert,
               sizeof expect_sigs_cert / sizeof expect_sigs_cert[0]),
       "signature_algorithms_cert is the full twelve, unfiltered");

    /* The two lists must not be the same list: that is the shape the bug had — one extension
     * carrying everything — and an edit that reunited them would otherwise pass everything above. */
    ok(sigs_len != sigs_cert_len, "the two lists are not the same list");

    /* ⚠️ AND THE PARAMETERS INSIDE EXTENSION 57, WHICH NOTHING ASKED UNTIL 2026-09-01.
     *
     * write_params_without_datagram_size was already RUN by this suite — the hello could not be
     * built without it — and its output was never looked at. So the reordering, the dropped
     * max_datagram_frame_size and the synthesised initial_max_streams_bidi were carried on the wire
     * of every connection with nothing holding them, and quic/params.h rests its whole case for
     * indistinguishability on exactly those three. Running a function is not testing it. */
    ok(tparams != NULL, "the hello carries quic_transport_parameters at all");

    uint8_t tp_ids[64];
    size_t  n_tp = 0;
    int     tp_parsed = tparams != NULL;
    int     greased_first = 0, bidi_zero = 0, datagram_dropped = 1, defaults_absent = 1;
    if (tparams != NULL) {
        size_t o = 0;
        while (o < tparams_len) {
            uint64_t id = 0, vlen = 0;
            if (tp_varint(tparams, tparams_len, &o, &id) != 0 ||
                tp_varint(tparams, tparams_len, &o, &vlen) != 0 ||
                vlen > tparams_len - o) {
                tp_parsed = 0;
                break;
            }
            /* The greased entry Marshal opens with: `27 + 31*n`, so `id % 31 == 27` and nothing a
             * real parameter uses can collide with it. It is skipped rather than expected by value —
             * it is random by design, and pinning it would pin the randomness. */
            if (n_tp == 0 && id % 31u == 27u) {
                greased_first = 1;
            } else {
                if (id == 0x08u)
                    bidi_zero = (vlen == 1u && tparams[o] == 0x00u);
                if (id == 0x20u)
                    datagram_dropped = 0;
                if (id == 0x0au || id == 0x0cu)
                    defaults_absent = 0;
                if (n_tp < sizeof tp_ids)
                    tp_ids[n_tp++] = (uint8_t)id;
            }
            o += (size_t)vlen;
        }
    }
    ok(tp_parsed, "the parameters this client wrote parse back");
    ok(greased_first, "a greased entry opens the list, as Marshal opens it");

    int tp_order_ok = tp_parsed && n_tp == sizeof expect_tp / sizeof expect_tp[0];
    for (size_t i = 0; tp_order_ok && i < n_tp; i++)
        tp_order_ok = tp_ids[i] == expect_tp[i];
    if (!tp_order_ok && tp_parsed) {
        printf("        got: ");
        for (size_t i = 0; i < n_tp; i++)
            printf(" %02x", tp_ids[i]);
        printf("\n        want:");
        for (size_t i = 0; i < sizeof expect_tp / sizeof expect_tp[0]; i++)
            printf(" %02x", expect_tp[i]);
        printf("\n");
    }
    ok(tp_order_ok, "the parameters come out in quic-go's order, not the one ngtcp2 handed in");

    /* Named separately from the order above because they fail differently and for different
     * reasons: one is an entry ngtcp2 refuses to encode, the other one hysteria refuses to send. */
    ok(bidi_zero, "initial_max_streams_bidi is written back as `08 01 00`, which ngtcp2 drops");
    ok(datagram_dropped, "max_datagram_frame_size is gone, as OmitMaxDatagramFrameSize requires");
    ok(defaults_absent,
       "ack_delay_exponent and disable_active_migration are absent, as Marshal leaves defaults out");

    /* ⚠️ THE TWO ENTRIES THE REAL INPUT CANNOT REACH, ASKED ON A HYPOTHETICAL ONE.
     *
     * order[] in qtls.c names thirteen identifiers; the eleven above are all that ngtcp2 ever hands
     * it for this configuration, so the places of ack_delay_exponent and disable_active_migration in
     * that list are unreachable from any real hello — and therefore held by nothing. On 2026-09-01
     * those two were transposed in the tree and every check in this file still passed.
     *
     * They are not decoration: quic/params.c sets neither today, but either becoming non-default
     * puts it on the wire in whatever place the array gives it, and Marshal's place for them is
     * max_ack_delay FIRST, then ack_delay_exponent, then disable_active_migration
     * (transport_parameters.go:398-412). So the input below is one ngtcp2 does not produce, asked
     * precisely because the answer would otherwise never be looked at. */
    static const uint8_t params_all[] = {
        0x05u, 0x04u, 0x80u, 0x08u, 0x00u, 0x00u, 0x06u, 0x04u, 0x80u, 0x08u, 0x00u, 0x00u,
        0x07u, 0x04u, 0x80u, 0x08u, 0x00u, 0x00u, 0x04u, 0x04u, 0x80u, 0x14u, 0x00u, 0x00u,
        0x09u, 0x02u, 0x40u, 0x64u, 0x03u, 0x02u, 0x45u, 0xacu, 0x0bu, 0x01u, 0x1au,
        0x01u, 0x04u, 0x80u, 0x00u, 0x75u, 0x30u,
        0x0au, 0x01u, 0x04u, /* ack_delay_exponent, non-default so that it travels */
        0x0cu, 0x00u,        /* disable_active_migration */
        0x0eu, 0x01u, 0x04u, 0x0fu, 0x04u, 0xde, 0xad, 0xbe, 0xef,
    };
    static const uint8_t expect_tp_all[] = { 0x05u, 0x06u, 0x07u, 0x04u, 0x08u, 0x09u, 0x01u,
                                             0x03u, 0x0bu, 0x0au, 0x0cu, 0x0eu, 0x0fu };

    lc_qtls q2;
    memset(&q2, 0, sizeof q2);
    static uint8_t hello2[4096];
    size_t         hello2_len = 0;
    int            all_ok = 0;
    if (build_hello(&q2, "stand.local", params_all, sizeof params_all, hello2, sizeof hello2,
                    &hello2_len) == 0) {
        uint16_t       ids2[64];
        size_t         n2 = 0;
        const uint8_t *s2 = NULL, *sc2 = NULL, *tp2 = NULL;
        size_t         s2l = 0, sc2l = 0, tp2l = 0;
        const uint8_t *bod2[64];
        size_t         bl2[64];
        if (walk(hello2, hello2_len, ids2, &n2, bod2, bl2, &s2, &s2l, &sc2, &sc2l, &tp2, &tp2l) == 0 &&
            tp2 != NULL) {
            uint8_t got[64];
            size_t  n_got = 0, o = 0;
            int     bad = 0, first = 1;
            while (o < tp2l && !bad) {
                uint64_t id = 0, vlen = 0;
                if (tp_varint(tp2, tp2l, &o, &id) != 0 || tp_varint(tp2, tp2l, &o, &vlen) != 0 ||
                    vlen > tp2l - o) {
                    bad = 1;
                    break;
                }
                if (first && id % 31u == 27u)
                    first = 0;
                else if (n_got < sizeof got)
                    got[n_got++] = (uint8_t)id;
                o += (size_t)vlen;
            }
            all_ok = !bad && n_got == sizeof expect_tp_all / sizeof expect_tp_all[0];
            for (size_t i = 0; all_ok && i < n_got; i++)
                all_ok = got[i] == expect_tp_all[i];
        }
    }
    ok(all_ok, "given every parameter, all thirteen come out in Marshal's order");

    /* THREE EXTENSION BODIES THAT NOTHING HELD EITHER. The order of the extensions was asserted from
     * the day this file was written and their CONTENTS were not, apart from the two signature lists
     * it was written for. Each of these three is on the wire of every connection. */
    size_t         glen = 0, alen = 0, klen = 0;
    const uint8_t *groups = body_of(ids, bodies, blens, n_ids, 0x000au, &glen);
    const uint8_t *alpn = body_of(ids, bodies, blens, n_ids, 0x0010u, &alen);
    const uint8_t *kshare = body_of(ids, bodies, blens, n_ids, 0x0033u, &klen);

    /* defaultCurvePreferences() of Go 1.26: X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024,
     * X25519, P-256, P-384, P-521 (GOROOT/src/crypto/tls/defaults.go:21-35, go1.26.6) — hysteria
     * 2.12 is built with it. 4588, 4587 and 4589 are the hybrids. */
    static const uint16_t expect_groups[] = { 4588u, 4587u, 4589u, 29u, 23u, 24u, 25u };
    ok(list_is(groups, glen, expect_groups, sizeof expect_groups / sizeof expect_groups[0]),
       "supported_groups is Go 1.26's seven, in Go's order");

    /* http3.Transport sets NextProtos to exactly one name (vendor/quic-go/http3/transport.go:361,
     * NextProtoH3 at http3/server.go:26). One, not "h3 among others". */
    int alpn_ok = alpn != NULL && alen == 5u && be16(alpn) == 3u && alpn[2] == 2u &&
                  memcmp(alpn + 3, "h3", 2) == 0;
    ok(alpn_ok, "ALPN offers h3 and nothing else");

    /* TWO SHARES ON ONE EPHEMERAL. Go sends the hybrid and a bare X25519 fallback REUSING the same
     * X25519 key, as draft-ietf-tls-hybrid-design-09 §3.2 allows — `hello.keyShares =
     * append(hello.keyShares, keyShare{group: X25519, data: x25519EphemeralKey})`
     * (vendor/utls/handshake_client.go:184-189). Two independently generated keys would look
     * identical to every other check here and to any server, and would cost only the property the
     * reuse exists for: the two shares of one client agreeing, which an observer comparing them
     * across a capture is exactly who would notice.
     *
     * ⚠️ AND THE SECOND ASSERTION BELOW CANNOT FAIL TODAY, which is said out loud rather than left
     * to read as a check that holds something. qtls.c:310 is `const uint8_t *pub = share +
     * LC_MLKEM_EK` — a pointer INTO the hybrid share, not a second buffer — so the two are the same
     * bytes by construction and comparing them compares a thing with itself. Measured rather than
     * reasoned: mutating hybrid.c to assemble the share from the wrong half leaves this green,
     * because both sides of the comparison move together.
     *
     * It is kept because the day someone gives the fallback its own generation — the obvious shape
     * of that refactor — is the day it stops being vacuous, and it costs one line to have the check
     * already standing. What holds the property TODAY is the aliasing, and the place to look is
     * qtls.c:300-310, not here. */
    int ks_ok = 0, ks_shared = 0;
    if (kshare != NULL && klen == 2u + (4u + 1216u) + (4u + 32u) && be16(kshare) == klen - 2u) {
        const uint8_t *e1 = kshare + 2, *e2 = kshare + 2 + 4 + 1216;
        ks_ok = be16(e1) == 4588u && be16(e1 + 2) == 1216u && be16(e2) == 29u &&
                be16(e2 + 2) == 32u;
        ks_shared = ks_ok && memcmp(e1 + 4 + 1216 - 32, e2 + 4, 32) == 0;
    }
    ok(ks_ok, "key_share is exactly two entries, the hybrid then bare X25519");
    ok(ks_shared, "and the X25519 share is the hybrid's own tail (structural today — see above)");

    chrome_cases();

    printf("\n");
    return fails == 0 ? 0 : 1;
}
