#include "tls/record.h"
#include "tls/alert.h"
#include "core/rnd.h"
#include "core/wipe.h"

#include <string.h>

#include <mbedtls/md.h>

/* Protected records always announce themselves as application_data with a legacy version of
 * TLS 1.2. Both are lies the specification requires, so that a 1.3 connection looks like a resumed
 * 1.2 one to middleboxes that only read headers. */
static const uint8_t outer_version[2] = { 0x03, 0x03 };

int lc_record_key_init(lc_record_key *k, lc_aead_alg alg, const uint8_t *key, const uint8_t *iv)
{
    k->tls12 = 0;
    k->cbc_ready = 0;
    memcpy(k->iv, iv, LC_AEAD_NONCE);
    k->seq = 0;
    k->alg = alg;
    k->key_len = lc_aead_key_len(alg);
    if (k->key_len == 0u || k->key_len > sizeof k->key)
        return -1;
    memcpy(k->key, key, k->key_len);
    return lc_aead_init(&k->aead, alg, key);
}

void lc_record_key_free(lc_record_key *k)
{
    if (!k->tls12 || k->mode12 != LC_REC12_CBC)
        lc_aead_free(&k->aead);
    if (k->cbc_ready)
        mbedtls_aes_free(&k->cbc);
    k->cbc_ready = 0;
    lc_wipe(k->mac_key, sizeof k->mac_key);
    lc_wipe(k->iv, sizeof k->iv);
    lc_wipe(k->key, sizeof k->key);
    k->key_len = 0;
    k->seq = 0;
    k->tls12 = 0;
}

/* RFC 8446 section 5.3: the sequence number is left-padded to the IV length and exclusive-ored
 * into it. The IV itself never changes, so the nonce is unique exactly as long as the counter is —
 * which is why every path that builds a nonce also advances it. */
static void nonce_for(const lc_record_key *k, uint8_t out[LC_AEAD_NONCE])
{
    memcpy(out, k->iv, LC_AEAD_NONCE);
    for (unsigned i = 0; i < 8u; i++) {
        unsigned shift = 8u * (7u - i);
        out[LC_AEAD_NONCE - 8u + i] ^= (uint8_t)(k->seq >> shift);
    }
}


/* ---- TLS 1.2 records (T3) ----------------------------------------------------------------------
 *
 * halfConn.encrypt and halfConn.decrypt for the three kinds of suite uTLS can run with this hello
 * (vendor/utls/conn.go:342-565): an AEAD with an explicit nonce (AES-GCM), an AEAD whose nonce is the
 * IV exclusive-ored with the sequence (ChaCha20-Poly1305, as in TLS 1.3), and CBC with a MAC in
 * front of the padding. The type is the header's, not the plaintext's; nothing is hidden inside. */

int lc_record_key_init12(lc_record_key *k, const lc_tls12_suite *suite, const uint8_t *key,
                         const uint8_t *iv, const uint8_t *mac_key, int for_reading)
{
    memset(k, 0, sizeof *k);
    k->tls12 = 1;
    k->mode12 = (uint8_t)suite->mode;
    if (suite->mode == LC_REC12_CBC) {
        /* cipherAES keeps a decrypter for the reading side and an encrypter for the writing one
         * (vendor/utls/cipher_suites.go:412-418); the IV of the key block is not used at all in TLS
         * 1.1 and later, where every record carries its own. */
        mbedtls_aes_init(&k->cbc);
        int rc = for_reading ? mbedtls_aes_setkey_dec(&k->cbc, key, (unsigned)suite->key_len * 8u)
                             : mbedtls_aes_setkey_enc(&k->cbc, key, (unsigned)suite->key_len * 8u);
        if (rc != 0) {
            mbedtls_aes_free(&k->cbc);
            return -1;
        }
        k->cbc_ready = 1;
        k->mac_len = suite->mac_len;
        k->mac_sha256 = suite->mac_len == 32u;
        memcpy(k->mac_key, mac_key, suite->mac_len);
        return 0;
    }
    lc_aead_alg alg = suite->mode == LC_REC12_CHACHA ? LC_AEAD_CHACHA20_POLY1305
                      : suite->key_len == 32u        ? LC_AEAD_AES_256_GCM
                                                     : LC_AEAD_AES_128_GCM;
    /* aeadAESGCM's fixed four bytes or aeadChaCha20Poly1305's whole twelve
     * (vendor/utls/cipher_suites.go:508-533, :572-584). */
    memcpy(k->iv, iv, suite->iv_len);
    return lc_aead_init(&k->aead, alg, key);
}

static void seq_bytes(uint64_t seq, uint8_t out[8])
{
    for (unsigned i = 0; i < 8u; i++)
        out[i] = (uint8_t)(seq >> (8u * (7u - i)));
}

/* tls10MAC: HMAC over the sequence, the header as it would read with the plaintext's length, and the
 * plaintext (vendor/utls/cipher_suites.go:611-621). |extra| is hashed after the digest is taken and
 * thrown away — the reference's gesture at a constant time against Lucky13, kept for the same reason. */
static int mac12(const lc_record_key *k, const uint8_t hdr[LC_REC_HEADER], size_t len, const uint8_t *pt,
                 const uint8_t *extra, size_t extra_len, uint8_t out[32])
{
    const mbedtls_md_info_t *info =
        mbedtls_md_info_from_type(k->mac_sha256 ? MBEDTLS_MD_SHA256 : MBEDTLS_MD_SHA1);
    mbedtls_md_context_t ctx;
    uint8_t              seq[8], h[LC_REC_HEADER];
    int                  rc = -1;

    seq_bytes(k->seq, seq);
    memcpy(h, hdr, LC_REC_HEADER);
    h[3] = (uint8_t)(len >> 8);
    h[4] = (uint8_t)len;
    mbedtls_md_init(&ctx);
    if (info != NULL && mbedtls_md_setup(&ctx, info, 1) == 0 &&
        mbedtls_md_hmac_starts(&ctx, k->mac_key, k->mac_len) == 0 &&
        mbedtls_md_hmac_update(&ctx, seq, sizeof seq) == 0 &&
        mbedtls_md_hmac_update(&ctx, h, sizeof h) == 0 &&
        mbedtls_md_hmac_update(&ctx, pt, len) == 0 && mbedtls_md_hmac_finish(&ctx, out) == 0) {
        rc = 0;
        if (extra_len > 0)
            (void)mbedtls_md_update(&ctx, extra, extra_len);
    }
    mbedtls_md_free(&ctx);
    return rc;
}

static int protect12(lc_record_key *k, uint8_t type, const uint8_t *pt, size_t pt_len, uint8_t *out,
                     size_t out_cap, size_t *out_len)
{
    if (pt_len > LC_REC_MAX_PLAINTEXT)
        return -1;

    uint8_t hdr[LC_REC_HEADER] = { type, 0x03u, 0x03u, (uint8_t)(pt_len >> 8), (uint8_t)pt_len };
    uint8_t seq[8];
    seq_bytes(k->seq, seq);
    size_t body;

    if (k->mode12 == LC_REC12_CBC) {
        /* MAC, then padding to the block — paddingLen - 1 in every padding byte, at least one — then
         * CBC behind a random IV of its own (vendor/utls/conn.go:539-553, :487-505). */
        size_t plain = pt_len + k->mac_len;
        size_t pad = 16u - plain % 16u;
        body = 16u + plain + pad;
        if (out_cap < LC_REC_HEADER + body)
            return -1;
        uint8_t *iv = out + LC_REC_HEADER;
        uint8_t *dst = iv + 16u;
        if (lc_rnd(iv, 16u) != 0)
            return -1;
        uint8_t mac[32];
        if (mac12(k, hdr, pt_len, pt, NULL, 0, mac) != 0)
            return -1;
        if (pt_len != 0u)
            memmove(dst, pt, pt_len);
        memcpy(dst + pt_len, mac, k->mac_len);
        memset(dst + plain, (int)(pad - 1u), pad);
        uint8_t ivc[16];
        memcpy(ivc, iv, 16u);
        if (mbedtls_aes_crypt_cbc(&k->cbc, MBEDTLS_AES_ENCRYPT, plain + pad, ivc, dst, dst) != 0)
            return -1;
        lc_wipe(mac, sizeof mac);
    } else {
        /* The additional data is the sequence and the header with the plaintext's length
         * (vendor/utls/conn.go:534-537); GCM writes its explicit nonce, which is the sequence
         * number, ahead of the ciphertext (:487-500). */
        uint8_t aad[8u + LC_REC_HEADER], nonce[LC_AEAD_NONCE];
        memcpy(aad, seq, 8u);
        memcpy(aad + 8u, hdr, LC_REC_HEADER);
        size_t explicit_len = k->mode12 == LC_REC12_GCM ? 8u : 0u;
        body = explicit_len + pt_len + LC_AEAD_TAG;
        if (out_cap < LC_REC_HEADER + body)
            return -1;
        if (k->mode12 == LC_REC12_GCM) {
            memcpy(nonce, k->iv, 4u);
            memcpy(nonce + 4u, seq, 8u);
            memcpy(out + LC_REC_HEADER, seq, 8u);
        } else {
            memcpy(nonce, k->iv, LC_AEAD_NONCE);
            for (unsigned i = 0; i < 8u; i++)
                nonce[4u + i] ^= seq[i];
        }
        size_t   sealed = 0;
        uint8_t *dst = out + LC_REC_HEADER + explicit_len;
        if (pt_len != 0u)
            memmove(dst, pt, pt_len);
        if (lc_aead_seal(&k->aead, nonce, aad, sizeof aad, dst, pt_len, dst,
                         out_cap - LC_REC_HEADER - explicit_len, &sealed) != 0 ||
            sealed != pt_len + LC_AEAD_TAG)
            return -1;
    }
    hdr[3] = (uint8_t)(body >> 8);
    hdr[4] = (uint8_t)body;
    memcpy(out, hdr, LC_REC_HEADER);
    *out_len = LC_REC_HEADER + body;
    k->seq++;
    return 0;
}

/* extractPadding, in constant time: how much to strip, and 0xff when the padding is good
 * (vendor/utls/conn.go:280-328). */
static size_t extract_padding(const uint8_t *p, size_t len, uint8_t *good_out)
{
    uint8_t pad = p[len - 1u];
    size_t  t = len - 1u - pad;
    uint8_t good = (uint8_t)((int32_t)~(uint32_t)t >> 31);
    size_t  check = len < 256u ? len : 256u;
    for (size_t i = 0; i < check; i++) {
        size_t  ti = (size_t)pad - i;
        uint8_t mask = (uint8_t)((int32_t)~(uint32_t)ti >> 31);
        good &= (uint8_t) ~((mask & pad) ^ (mask & p[len - 1u - i]));
    }
    good &= (uint8_t)(good << 4);
    good &= (uint8_t)(good << 2);
    good &= (uint8_t)(good << 1);
    good = (uint8_t)((int8_t)good >> 7);
    pad &= good;
    *good_out = good;
    return (size_t)pad + 1u;
}

static int unprotect12(lc_record_key *k, const uint8_t *rec, size_t rec_len, uint8_t *out, size_t out_cap,
                       size_t *out_len, uint8_t *inner_type)
{
    const int bad_mac = -(int)LC_ALERT_BAD_RECORD_MAC;
    if (rec_len < LC_REC_HEADER)
        return bad_mac;
    size_t body_len = rec_len - LC_REC_HEADER;
    if (((size_t)rec[3] << 8 | rec[4]) != body_len)
        return bad_mac;
    const uint8_t *payload = rec + LC_REC_HEADER;
    uint8_t seq[8];
    seq_bytes(k->seq, seq);
    size_t n;

    if (k->mode12 == LC_REC12_CBC) {
        /* `minPayload := explicitNonceLen + roundUp(hc.mac.Size()+1, blockSize)`, and a length that
         * is not whole blocks (vendor/utls/conn.go:387-392). */
        size_t min_payload = 16u + ((k->mac_len + 1u + 15u) / 16u) * 16u;
        if (body_len % 16u != 0u || body_len < min_payload)
            return bad_mac;
        size_t plen = body_len - 16u;
        if (plen > out_cap)
            return bad_mac;
        uint8_t ivc[16];
        memcpy(ivc, payload, 16u);
        if (mbedtls_aes_crypt_cbc(&k->cbc, MBEDTLS_AES_DECRYPT, plen, ivc, payload + 16u, out) != 0)
            return bad_mac;
        uint8_t good = 0;
        size_t  strip = extract_padding(out, plen, &good);
        /* `n := len(payload) - macSize - paddingLen`, floored at zero (:441-442). */
        size_t mac_at = plen >= (size_t)k->mac_len + strip ? plen - k->mac_len - strip : 0u;
        uint8_t local[32];
        uint8_t hdr[LC_REC_HEADER];
        memcpy(hdr, rec, LC_REC_HEADER);
        if (mac12(k, hdr, mac_at, out, out + mac_at + k->mac_len, plen - mac_at - k->mac_len, local) != 0)
            return bad_mac;
        uint8_t diff = 0;
        for (size_t i = 0; i < k->mac_len; i++)
            diff |= (uint8_t)(local[i] ^ out[mac_at + i]);
        lc_wipe(local, sizeof local);
        if (diff != 0u || good != 0xffu) {
            lc_wipe(out, plen);
            return bad_mac;
        }
        n = mac_at;
    } else {
        size_t explicit_len = k->mode12 == LC_REC12_GCM ? 8u : 0u;
        if (body_len < explicit_len)
            return bad_mac;
        uint8_t nonce[LC_AEAD_NONCE];
        if (k->mode12 == LC_REC12_GCM) {
            memcpy(nonce, k->iv, 4u);
            memcpy(nonce + 4u, payload, 8u);
        } else {
            memcpy(nonce, k->iv, LC_AEAD_NONCE);
            for (unsigned i = 0; i < 8u; i++)
                nonce[4u + i] ^= seq[i];
        }
        const uint8_t *ct = payload + explicit_len;
        size_t         ct_len = body_len - explicit_len;
        if (ct_len < LC_AEAD_TAG || ct_len - LC_AEAD_TAG > out_cap)
            return bad_mac;
        size_t  pl = ct_len - LC_AEAD_TAG;
        uint8_t aad[8u + LC_REC_HEADER];
        memcpy(aad, seq, 8u);
        memcpy(aad + 8u, rec, 3u);
        aad[11] = (uint8_t)(pl >> 8);
        aad[12] = (uint8_t)pl;
        size_t opened = 0;
        if (lc_aead_open(&k->aead, nonce, aad, sizeof aad, ct, ct_len, out, out_cap, &opened) != 0)
            return bad_mac;
        n = opened;
    }
    /* `if len(data) > maxPlaintext { sendAlert(alertRecordOverflow) }` (vendor/utls/conn.go:693-695). */
    if (n > LC_REC_MAX_PLAINTEXT) {
        lc_wipe(out, n);
        return -(int)LC_ALERT_RECORD_OVERFLOW;
    }
    *inner_type = rec[0];
    *out_len = n;
    k->seq++;
    return 0;
}

static void write_header(uint8_t hdr[LC_REC_HEADER], size_t body_len)
{
    hdr[0] = LC_REC_APPLICATION_DATA;
    hdr[1] = outer_version[0];
    hdr[2] = outer_version[1];
    hdr[3] = (uint8_t)(body_len >> 8);
    hdr[4] = (uint8_t)body_len;
}

int lc_record_protect(lc_record_key *k, uint8_t inner_type,
                      const uint8_t *pt, size_t pt_len, size_t pad,
                      uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (k->tls12)
        return pad != 0u ? -1 : protect12(k, inner_type, pt, pt_len, out, out_cap, out_len);
    /* The inner plaintext is the payload, then the real content type, then padding. */
    if (pt_len > LC_REC_MAX_PLAINTEXT || pad > LC_REC_MAX_PLAINTEXT - pt_len)
        return -1;
    size_t inner_len = pt_len + 1u + pad;
    if (inner_len > LC_REC_MAX_INNER)
        return -1;

    size_t body_len = inner_len + LC_AEAD_TAG;
    if (out_cap < LC_REC_HEADER + body_len)
        return -1;

    uint8_t hdr[LC_REC_HEADER];
    write_header(hdr, body_len);

    /* The inner plaintext is assembled in place, right after the header, and encrypted from there
     * into the same region: mbedTLS allows the buffers to coincide, and a router has better uses
     * for sixteen kilobytes than a second copy of every record. */
    uint8_t *body = out + LC_REC_HEADER;
    if (pt_len != 0u)
        memcpy(body, pt, pt_len);
    body[pt_len] = inner_type;
    if (pad > 0)
        memset(body + pt_len + 1u, 0, pad);

    uint8_t nonce[LC_AEAD_NONCE];
    nonce_for(k, nonce);

    size_t sealed = 0;
    if (lc_aead_seal(&k->aead, nonce, hdr, LC_REC_HEADER, body, inner_len,
                     body, out_cap - LC_REC_HEADER, &sealed) != 0)
        return -1;
    if (sealed != body_len)
        return -1;

    memcpy(out, hdr, LC_REC_HEADER);
    *out_len = LC_REC_HEADER + body_len;
    k->seq++;
    return 0;
}

int lc_record_unprotect(lc_record_key *k, const uint8_t *rec, size_t rec_len,
                        uint8_t *out, size_t out_cap, size_t *out_len, uint8_t *inner_type)
{
    if (k->tls12)
        return unprotect12(k, rec, rec_len, out, out_cap, out_len, inner_type);

    /* ⚠️ EVERY FAILURE HERE HAS A NUMBER, and they come in the reference's order: the tag first,
     * then what the open record says (vendor/utls/conn.go:373-427). Anything a peer without our keys
     * can send ends at the tag, as bad_record_mac — a payload too short for one, a tag that does not
     * verify. This function used to answer them all with a bare -1, which the handshake then sent
     * as decrypt_error (51): a different byte, in reply to a record anyone on the path can forge. The
     * number is returned negated so that every caller testing `!= 0` keeps working unchanged. */
    const int bad_mac = -(int)LC_ALERT_BAD_RECORD_MAC;

    if (rec_len < LC_REC_HEADER)
        return bad_mac;
    size_t body_len = (size_t)rec[3] << 8 | rec[4];
    if (body_len + LC_REC_HEADER != rec_len)
        return bad_mac;
    /* Shorter than a tag, Open fails (:384-387). A body of exactly a tag is not refused: it opens,
     * to nothing, and nothing is read below as application data with no bytes — which is what the
     * reference makes of it, its scan for the content type running zero times. */
    if (body_len < LC_AEAD_TAG)
        return bad_mac;
    /* ⚠️ AND A BODY THAT DOES NOT FIT `out` CANNOT BE OPENED, so it is answered as though its tag had
     * failed — which is right for everybody but a peer holding the key and writing an inner
     * plaintext over 2^14 + 1, where the reference opens it and answers record_overflow (:416-418).
     * Callers that can meet such a peer pass LC_REC_MAX_OPEN and get the reference's answer: the
     * handshake (its window is grown to the whole record) and lc-tunnel. */
    if (body_len - LC_AEAD_TAG > out_cap)
        return bad_mac;

    uint8_t nonce[LC_AEAD_NONCE];
    nonce_for(k, nonce);

    size_t opened = 0;
    if (lc_aead_open(&k->aead, nonce, rec, LC_REC_HEADER,
                     rec + LC_REC_HEADER, body_len, out, out_cap, &opened) != 0)
        return bad_mac;

    /* THE OUTER CONTENT TYPE, WHICH TLS 1.3 FIXES AT application_data — checked once the tag has
     * verified, as the reference checks it (:412-415). The header is the additional data the tag
     * covers (:374-378), so a record relabelled on the path fails the tag above and draws 20; only a
     * peer that SEALED it under another type gets this far, and gets unexpected_message. A
     * ChangeCipherSpec never arrives here: the reference passes it through unopened (:348-352), and
     * every caller handles it first. */
    if (rec[0] != LC_REC_APPLICATION_DATA) {
        lc_wipe(out, opened);
        return -(int)LC_ALERT_UNEXPECTED_MESSAGE;
    }
    if (opened > LC_REC_MAX_INNER) {
        lc_wipe(out, opened);
        return -(int)LC_ALERT_RECORD_OVERFLOW;
    }

    /* The true content type is the last non-zero byte; everything after it was padding. A record
     * that is all zeroes has no content type — `if i == 0 { return nil, 0, alertUnexpectedMessage }`
     * (:419-428). An empty one has nothing to scan, and keeps the type it came under. The sequence
     * number does not advance on a refusal: the connection is over. */
    if (opened == 0u) {
        *inner_type = LC_REC_APPLICATION_DATA;
        *out_len = 0;
        k->seq++;
        return 0;
    }
    size_t end = opened;
    while (end > 0 && out[end - 1u] == 0x00)
        end--;
    if (end == 0)
        return -(int)LC_ALERT_UNEXPECTED_MESSAGE;

    *inner_type = out[end - 1u];
    *out_len = end - 1u;
    k->seq++;
    return 0;
}
