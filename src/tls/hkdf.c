#include "tls/hkdf.h"

#include <string.h>

#include <mbedtls/md.h>

/* The label prefix every TLS 1.3 derivation carries. Its length is part of the wire format, so it
 * is written out rather than computed with strlen at each call. */
static const char tls13_prefix[] = "tls13 ";
#define TLS13_PREFIX_LEN 6u

static mbedtls_md_type_t md_type(lc_hash h)
{
    return h == LC_SHA384 ? MBEDTLS_MD_SHA384 : MBEDTLS_MD_SHA256;
}

size_t lc_hash_len(lc_hash h)
{
    return h == LC_SHA384 ? 48u : 32u;
}

int lc_hash_digest(lc_hash h, const uint8_t *in, size_t in_len, uint8_t *out)
{
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(md_type(h));
    if (info == NULL)
        return -1;
    return mbedtls_md(info, in, in_len, out) == 0 ? 0 : -1;
}

int lc_hkdf_extract(lc_hash h, const uint8_t *salt, size_t salt_len,
                    const uint8_t *ikm, size_t ikm_len, uint8_t *out)
{
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(md_type(h));
    if (info == NULL)
        return -1;

    /* RFC 5869: an absent salt is HashLen zero bytes. The schedule starts exactly there, so this
     * is the normal path rather than an edge case, and the reference gets the same value from Go's
     * crypto/hkdf, which substitutes the zero salt itself. What is derived from the result is
     * `tls13.ExpandLabel(c.hash.New, trafficSecret, "key", nil, c.keyLen)` and its `"iv"` twin
     * (vendor/utls/key_schedule.go:31-32). */
    uint8_t zeros[LC_HASH_MAX];
    if (salt == NULL) {
        memset(zeros, 0, sizeof zeros);
        salt = zeros;
        salt_len = lc_hash_len(h);
    }
    return mbedtls_md_hmac(info, salt, salt_len, ikm, ikm_len, out) == 0 ? 0 : -1;
}

/* ⚠️ THIS FILE NAMED NO REFERENCE LINE UNTIL NOW, WHICH KEPT IT OUT OF THE SIEVE.
 *
 * Pairs are built from the references our comments make, so a file that cites nothing is never
 * opened by the forward pass — COVERAGE.md listed src/tls/hkdf.c among those. It is the
 * TLS 1.3 key schedule: every traffic key, every Finished and the REALITY authentication key
 * come through it, and a divergence here either breaks every connection or, worse, quietly
 * agrees with nobody. It was checked by nothing but somebody reading it. On 2026-08-28 somebody
 * did, found it identical step for step, and left the citations below so that it is checked
 * rather than trusted.
 *
 * HkdfLabel, the whole of it, is vendor/utls/internal/tls13/tls13.go:21-45 — reached from
 * vendor/utls/key_schedule.go:23-44, where every `tls13.ExpandLabel(...)` call in the reference
 * goes. */
int lc_hkdf_label(const char *label, const uint8_t *ctx, size_t ctx_len,
                  size_t out_len, uint8_t *info, size_t info_cap, size_t *info_len)
{
    size_t label_len = strlen(label);
    /* The wire format gives one byte to each length, and RFC 8446 additionally requires the
     * prefixed label to be at least seven bytes. Both are refused here rather than truncated.
     *
     * The reference bounds the same two quantities in the same place and PANICS on either —
     * `if len("tls13 ")+len(label) > 255 || len(context) > 255 { panic(...) }`
     * (vendor/utls/internal/tls13/tls13.go:22-32) — with a comment explaining that it should
     * be impossible because labels are fixed strings. Refusing rather than panicking is the only
     * difference, and it is a difference in what a bug does to the process, not in any byte. */
    if (label_len == 0 || TLS13_PREFIX_LEN + label_len > 255u || ctx_len > 255u)
        return -1;
    if (out_len > 0xffffu)
        return -1;

    size_t need = 2u + 1u + TLS13_PREFIX_LEN + label_len + 1u + ctx_len;
    if (need > info_cap)
        return -1;

    /* The five pieces, in the reference's own order: two bytes of length big-endian, one byte of
     * prefixed-label length, the prefix, the label, one byte of context length, the context.
     *
     *     hkdfLabel = byteorder.BEAppendUint16(hkdfLabel, uint16(length))
     *     hkdfLabel = append(hkdfLabel, byte(len("tls13 ")+len(label)))
     *     hkdfLabel = append(hkdfLabel, "tls13 "...)
     *     hkdfLabel = append(hkdfLabel, label...)
     *     hkdfLabel = append(hkdfLabel, byte(len(context)))
     *     hkdfLabel = append(hkdfLabel, context...)
     *                          (vendor/utls/internal/tls13/tls13.go:34-39)
     *
     * The prefix is "tls13 " WITH THE SPACE, six bytes, which is why TLS13_PREFIX_LEN is 6 and not
     * 5 — the one thing here that is easy to get wrong and impossible to notice, since both ends
     * would simply derive different keys and blame the network. */
    size_t i = 0;
    info[i++] = (uint8_t)(out_len >> 8);
    info[i++] = (uint8_t)out_len;
    info[i++] = (uint8_t)(TLS13_PREFIX_LEN + label_len);
    memcpy(info + i, tls13_prefix, TLS13_PREFIX_LEN);
    i += TLS13_PREFIX_LEN;
    memcpy(info + i, label, label_len);
    i += label_len;
    info[i++] = (uint8_t)ctx_len;
    if (ctx_len > 0) {
        memcpy(info + i, ctx, ctx_len);
        i += ctx_len;
    }
    *info_len = i;
    return 0;
}

/* HKDF-Expand of RFC 5869, inlined rather than taken from mbedtls_hkdf_expand so that the info
 * buffer stays on our stack and the code path is the same on every platform this ends up on. */
int lc_hkdf_expand(lc_hash h, const uint8_t *prk,
                       const uint8_t *info, size_t info_len,
                       uint8_t *out, size_t out_len)
{
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(md_type(h));
    if (md == NULL)
        return -1;

    size_t hlen = lc_hash_len(h);
    if (out_len > 255u * hlen)
        return -1;

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    int rc = -1;
    if (mbedtls_md_setup(&ctx, md, 1) != 0)
        goto done;

    uint8_t t[LC_HASH_MAX];
    size_t  t_len = 0;
    size_t  done_len = 0;
    uint8_t counter = 1;

    while (done_len < out_len) {
        if (mbedtls_md_hmac_starts(&ctx, prk, hlen) != 0)
            goto done;
        /* T(1) has no previous block; every later block is chained onto the one before it. */
        if (t_len > 0 && mbedtls_md_hmac_update(&ctx, t, t_len) != 0)
            goto done;
        if (mbedtls_md_hmac_update(&ctx, info, info_len) != 0)
            goto done;
        if (mbedtls_md_hmac_update(&ctx, &counter, 1) != 0)
            goto done;
        if (mbedtls_md_hmac_finish(&ctx, t) != 0)
            goto done;
        t_len = hlen;

        size_t take = out_len - done_len < hlen ? out_len - done_len : hlen;
        memcpy(out + done_len, t, take);
        done_len += take;
        counter++;
    }
    rc = 0;

done:
    mbedtls_md_free(&ctx);
    return rc;
}

int lc_hkdf_expand_label(lc_hash h, const uint8_t *secret, const char *label,
                         const uint8_t *ctx, size_t ctx_len, uint8_t *out, size_t out_len)
{
    /* Two length bytes, the label with its prefix and length byte, and the context with its own —
     * all bounded above by the one-byte length fields, so the largest possible HkdfLabel is small
     * and fits on the stack. */
    uint8_t info[2 + 1 + 255 + 1 + 255];
    size_t  info_len = 0;
    if (lc_hkdf_label(label, ctx, ctx_len, out_len, info, sizeof info, &info_len) != 0)
        return -1;
    return lc_hkdf_expand(h, secret, info, info_len, out, out_len);
}

int lc_derive_secret(lc_hash h, const uint8_t *secret, const char *label,
                     const uint8_t *transcript_hash, uint8_t *out)
{
    size_t hlen = lc_hash_len(h);
    return lc_hkdf_expand_label(h, secret, label, transcript_hash, hlen, out, hlen);
}
