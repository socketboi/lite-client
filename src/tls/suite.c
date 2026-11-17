#include "tls/suite.h"

/* ⚠️ THREE LINES OF TABLE, NO CITATION, AND NOTHING DECRYPTS IF ONE FIGURE IS WRONG — which is why
 * a file this short was worth opening. The sieve never did: it names no reference, so no pair
 * exists, and a key length of 16 where the suite wants 32 would have been found by nobody until a
 * connection silently carried garbage.
 *
 * The reference keeps the same three rows, and each row is the same four things — code, key length,
 * AEAD, hash:
 *
 *     var cipherSuitesTLS13 = []*cipherSuiteTLS13{
 *         {TLS_AES_128_GCM_SHA256, 16, aeadAESGCMTLS13, crypto.SHA256},
 *         {TLS_CHACHA20_POLY1305_SHA256, 32, aeadChaCha20Poly1305, crypto.SHA256},
 *         {TLS_AES_256_GCM_SHA384, 32, aeadAESGCMTLS13, crypto.SHA384},
 *     }                                    (vendor/utls/cipher_suites.go:213-217)
 *
 * Two things about that list matter as much as the numbers in it. It has exactly three entries — no
 * CCM suites, though TLS 1.3 defines them — so `default: return -1` below is the same refusal and
 * not a shortcut. And the order differs from ours, which is deliberate on both sides: this is a
 * lookup, not the preference list that goes on the wire. What a peer sees is built in fp/hello.c
 * from the fingerprint table, and THAT order is the one that has to match. */
int lc_tls_suite_params(uint16_t suite, lc_aead_alg *aead, lc_hash *hash, size_t *key_len)
{
    lc_aead_alg a;
    lc_hash     h;
    size_t      k;

    switch (suite) {
    case 0x1301u: a = LC_AEAD_AES_128_GCM;       h = LC_SHA256; k = 16u; break;
    case 0x1302u: a = LC_AEAD_AES_256_GCM;       h = LC_SHA384; k = 32u; break;
    case 0x1303u: a = LC_AEAD_CHACHA20_POLY1305; h = LC_SHA256; k = 32u; break;
    default:      return -1;
    }

    if (aead != NULL)
        *aead = a;
    if (hash != NULL)
        *hash = h;
    if (key_len != NULL)
        *key_len = k;
    return 0;
}

/* cipherSuites (vendor/utls/cipher_suites.go:151-174) and the two utlsSupportedCipherSuites appends
 * (vendor/utls/u_common.go:746-751), in that order, less 3DES and RC4 — see suite.h. The OLD_ pair is
 * the pre-standard ChaCha20-Poly1305 code point, and uTLS runs it on the same AEAD as the standard one. */
static const lc_tls12_suite tls12_suites[] = {
    { 0xcca8u, 32u, 0u, 12u, LC_KX_ECDHE_RSA,   LC_REC12_CHACHA, LC_SHA256, 1u },
    { 0xcca9u, 32u, 0u, 12u, LC_KX_ECDHE_ECDSA, LC_REC12_CHACHA, LC_SHA256, 1u },
    { 0xc02fu, 16u, 0u,  4u, LC_KX_ECDHE_RSA,   LC_REC12_GCM,    LC_SHA256, 1u },
    { 0xc02bu, 16u, 0u,  4u, LC_KX_ECDHE_ECDSA, LC_REC12_GCM,    LC_SHA256, 1u },
    { 0xc030u, 32u, 0u,  4u, LC_KX_ECDHE_RSA,   LC_REC12_GCM,    LC_SHA384, 1u },
    { 0xc02cu, 32u, 0u,  4u, LC_KX_ECDHE_ECDSA, LC_REC12_GCM,    LC_SHA384, 1u },
    { 0xc027u, 16u, 32u, 16u, LC_KX_ECDHE_RSA,  LC_REC12_CBC,    LC_SHA256, 1u },
    { 0xc013u, 16u, 20u, 16u, LC_KX_ECDHE_RSA,  LC_REC12_CBC,    LC_SHA256, 0u },
    { 0xc023u, 16u, 32u, 16u, LC_KX_ECDHE_ECDSA, LC_REC12_CBC,   LC_SHA256, 1u },
    { 0xc009u, 16u, 20u, 16u, LC_KX_ECDHE_ECDSA, LC_REC12_CBC,   LC_SHA256, 0u },
    { 0xc014u, 32u, 20u, 16u, LC_KX_ECDHE_RSA,  LC_REC12_CBC,    LC_SHA256, 0u },
    { 0xc00au, 32u, 20u, 16u, LC_KX_ECDHE_ECDSA, LC_REC12_CBC,   LC_SHA256, 0u },
    { 0x009cu, 16u, 0u,  4u, LC_KX_RSA,         LC_REC12_GCM,    LC_SHA256, 1u },
    { 0x009du, 32u, 0u,  4u, LC_KX_RSA,         LC_REC12_GCM,    LC_SHA384, 1u },
    { 0x003cu, 16u, 32u, 16u, LC_KX_RSA,        LC_REC12_CBC,    LC_SHA256, 1u },
    { 0x002fu, 16u, 20u, 16u, LC_KX_RSA,        LC_REC12_CBC,    LC_SHA256, 0u },
    { 0x0035u, 32u, 20u, 16u, LC_KX_RSA,        LC_REC12_CBC,    LC_SHA256, 0u },
    { 0xcc13u, 32u, 0u, 12u, LC_KX_ECDHE_RSA,   LC_REC12_CHACHA, LC_SHA256, 1u },
    { 0xcc14u, 32u, 0u, 12u, LC_KX_ECDHE_ECDSA, LC_REC12_CHACHA, LC_SHA256, 1u },
};

const lc_tls12_suite *lc_tls12_suite_by_id(uint16_t id)
{
    for (size_t i = 0; i < sizeof tls12_suites / sizeof tls12_suites[0]; i++)
        if (tls12_suites[i].id == id)
            return &tls12_suites[i];
    return NULL;
}

int lc_tls12_suite_known_to_go(uint16_t id)
{
    /* The five this build leaves out: TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, TLS_RSA_WITH_3DES_EDE_CBC_SHA,
     * TLS_RSA_WITH_RC4_128_SHA, TLS_ECDHE_RSA_WITH_RC4_128_SHA, TLS_ECDHE_ECDSA_WITH_RC4_128_SHA. */
    return lc_tls12_suite_by_id(id) != NULL || id == 0xc012u || id == 0x000au || id == 0x0005u ||
           id == 0xc011u || id == 0xc007u;
}
