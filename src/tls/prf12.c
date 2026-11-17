#include "tls/prf12.h"

#include "core/wipe.h"

#include <string.h>

#include <mbedtls/md.h>

static const mbedtls_md_info_t *md_of(lc_hash h)
{
    return mbedtls_md_info_from_type(h == LC_SHA384 ? MBEDTLS_MD_SHA384 : MBEDTLS_MD_SHA256);
}

/* pHash as tls12.go writes it: A(1) = HMAC(secret, seed), then HMAC(secret, A(i) || seed) for each
 * block and A(i+1) = HMAC(secret, A(i)), the last block cut to what is left. */
int lc_prf12(lc_hash h, const uint8_t *secret, size_t secret_len, const char *label,
             const uint8_t *seed, size_t seed_len, uint8_t *out, size_t out_len)
{
    const mbedtls_md_info_t *info = md_of(h);
    size_t                   label_len = strlen(label);
    size_t                   hlen = lc_hash_len(h);
    uint8_t                  ls[64 + 2u * 32u + LC_HASH_MAX]; /* label || seed */
    uint8_t                  a[LC_HASH_MAX], b[LC_HASH_MAX];
    mbedtls_md_context_t     ctx;
    int                      rc = -1;

    if (info == NULL || label_len + seed_len > sizeof ls)
        return -1;
    memcpy(ls, label, label_len);
    memcpy(ls + label_len, seed, seed_len);
    size_t ls_len = label_len + seed_len;

    mbedtls_md_init(&ctx);
    if (mbedtls_md_setup(&ctx, info, 1) != 0 || mbedtls_md_hmac_starts(&ctx, secret, secret_len) != 0)
        goto done;
    if (mbedtls_md_hmac_update(&ctx, ls, ls_len) != 0 || mbedtls_md_hmac_finish(&ctx, a) != 0)
        goto done;
    while (out_len > 0) {
        if (mbedtls_md_hmac_reset(&ctx) != 0 || mbedtls_md_hmac_update(&ctx, a, hlen) != 0 ||
            mbedtls_md_hmac_update(&ctx, ls, ls_len) != 0 || mbedtls_md_hmac_finish(&ctx, b) != 0)
            goto done;
        size_t n = out_len < hlen ? out_len : hlen;
        memcpy(out, b, n);
        out += n;
        out_len -= n;
        if (mbedtls_md_hmac_reset(&ctx) != 0 || mbedtls_md_hmac_update(&ctx, a, hlen) != 0 ||
            mbedtls_md_hmac_finish(&ctx, a) != 0)
            goto done;
    }
    rc = 0;
done:
    mbedtls_md_free(&ctx);
    lc_wipe(a, sizeof a);
    lc_wipe(b, sizeof b);
    lc_wipe(ls, sizeof ls);
    return rc;
}

int lc_tls12_master(lc_hash h, const uint8_t *pms, size_t pms_len, const uint8_t client_random[32],
                    const uint8_t server_random[32], uint8_t out[LC_TLS12_MASTER_LEN])
{
    uint8_t seed[64];
    memcpy(seed, client_random, 32);
    memcpy(seed + 32, server_random, 32);
    return lc_prf12(h, pms, pms_len, "master secret", seed, sizeof seed, out, LC_TLS12_MASTER_LEN);
}

int lc_tls12_master_ems(lc_hash h, const uint8_t *pms, size_t pms_len, const uint8_t *transcript_hash,
                        uint8_t out[LC_TLS12_MASTER_LEN])
{
    return lc_prf12(h, pms, pms_len, "extended master secret", transcript_hash, lc_hash_len(h), out,
                    LC_TLS12_MASTER_LEN);
}

int lc_tls12_key_block(lc_hash h, const uint8_t master[LC_TLS12_MASTER_LEN],
                       const uint8_t client_random[32], const uint8_t server_random[32],
                       uint8_t *out, size_t out_len)
{
    /* The server's random first here, the client's first for the master secret. */
    uint8_t seed[64];
    memcpy(seed, server_random, 32);
    memcpy(seed + 32, client_random, 32);
    return lc_prf12(h, master, LC_TLS12_MASTER_LEN, "key expansion", seed, sizeof seed, out, out_len);
}

int lc_tls12_finished(lc_hash h, const uint8_t master[LC_TLS12_MASTER_LEN], int server,
                      const uint8_t *transcript_hash, uint8_t out[LC_TLS12_VERIFY_LEN])
{
    return lc_prf12(h, master, LC_TLS12_MASTER_LEN, server ? "server finished" : "client finished",
                    transcript_hash, lc_hash_len(h), out, LC_TLS12_VERIFY_LEN);
}
