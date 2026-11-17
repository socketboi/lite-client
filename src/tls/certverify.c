#include "tls/certverify.h"

#include "cert/cert.h"
#include "cert/gosig.h"
#include "cert/mldsa.h"
#include "cert/x509go.h"
#include "tls/ed25519.h"
#include "tls/goerr.h"
#include "core/wipe.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <mbedtls/md.h>

/* uTLS's words for the refusal the next say() makes, into |go| when the caller wants them — the
 * first ones only, as the first reason is the one kept. */
static void gosay(char *go, size_t cap, const char *fmt, ...)
{
    if (go != NULL && cap != 0 && go[0] == '\0') {
        va_list ap;
        va_start(ap, fmt);
        lc_go_vsnprintf(go, cap, fmt, ap);
        va_end(ap);
    }
}

/* THE LEAF'S KEY, AS THE REFERENCE'S x509.ParseCertificate READ IT — go1.26.6's on the QUIC plane,
 * go1.27.1's on the REALITY plane — which is what verifyHandshakeSignature's type switch sees
 * (vendor/utls/auth.go:23-78). The certificate check before this has already refused a leaf the
 * parser refuses; one that still does not parse here is a nil key. `c` is freed by the caller. */
static void leaf_key(const uint8_t *der, size_t len, int go127, lc_gocert *c, lc_gopubkey *k)
{
    memset(c, 0, sizeof *c);
    if (lc_x509_go_parse_fields(go127, der, len, c, NULL, NULL) != 0) {
        memset(c, 0, sizeof *c);
        memset(k, 0, sizeof *k);
        return;
    }
    lc_gopubkey_of(c, k);
}

static int say(char *err, size_t cap, uint8_t *alert_out, uint8_t alert,
               const char *fmt, ...)
{
    if (err != NULL && cap != 0) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err, cap, fmt, ap);
        va_end(ap);
    }
    if (alert_out != NULL)
        *alert_out = alert;
    return -1;
}

/* RFC 8446 4.4.3 defines what is signed: sixty-four spaces, the context string, a zero byte, then
 * the transcript hash up to and including Certificate. Everything but ed25519 signs the digest of
 * that rather than the bytes, which is why the hash is computed here and handed over pre-made.
 *
 * The scheme list mirrors what the hello offers, minus the three PKCS#1 v1.5 codes: TLS 1.3 forbids
 * them in this message even though they remain legal for signatures inside a chain. The reference
 * implementation in vendor/REALITY refuses them at the same point and for the same reason. */
int lc_cert_verify(const uint8_t *cert_der, size_t cert_der_len,
                   lc_hash hash, const uint8_t *transcript_hash,
                   const uint8_t *body, size_t body_len, int stdlib, int go127,
                   char *err, size_t err_cap, uint8_t *alert,
                   char *go, size_t go_cap)
{
    if (go != NULL && go_cap != 0)
        go[0] = '\0';

    if (cert_der == NULL || cert_der_len == 0u)
        return say(err, err_cap, alert, LC_ALERT_UNEXPECTED_MESSAGE, "no certificate to check the signature against");

    /* certificateVerifyMsg.unmarshal: a scheme, a two-byte-prefixed signature, and nothing after it
     * (vendor/utls/handshake_messages.go:1929-1941). A message that does not unmarshal is
     * unexpected_message in uTLS (vendor/utls/conn.go:1185-1186) and decode_error in the standard
     * library (GOROOT/src/crypto/tls/conn.go:1185-1186, go1.25.14). This answered decode_error on
     * both planes for a length that disagreed, and unexpected_message for a body too short to
     * hold one — the TLS plane's number for one, the QUIC plane's for neither. */
    uint8_t unmarshal = stdlib ? LC_ALERT_DECODE_ERROR : LC_ALERT_UNEXPECTED_MESSAGE;
    if (body_len < 4u || (size_t)((size_t)body[2] << 8 | body[3]) != body_len - 4u)
        gosay(go, go_cap, LC_GO("local error: tls: unexpected message"));
    if (body_len < 4u)
        return say(err, err_cap, alert, unmarshal, "a CertificateVerify of %zu bytes", body_len);
    uint16_t scheme = (uint16_t)((uint16_t)body[0] << 8 | body[1]);
    size_t   sig_len = (size_t)body[2] << 8 | body[3];
    if (sig_len != body_len - 4u)
        return say(err, err_cap, alert, unmarshal, "the signature length does not match the message");
    const uint8_t *sig = body + 4;

    /* THE SCHEME, BEFORE ANY VERIFYING, the way each reference asks.
     *
     * Both refuse with illegal_parameter a scheme outside their list — uTLS's is the default list
     * whole (vendor/utls/defaults.go:42-60), and then it refuses PKCS#1 v1.5 and SHA-1 by name
     * (vendor/utls/handshake_client_tls13.go:852-863); the standard library's list for TLS 1.3 has
     * neither in it to begin with (GOROOT/src/crypto/tls/common.go:1709-1747).
     * Xray's Go 1.27 uTLS additionally supports the three ML-DSA schemes.
     *
     * THE STANDARD LIBRARY THEN ASKS A SECOND QUESTION uTLS DOES NOT: whether the scheme is one the
     * certificate's key can sign with at all — Ed25519 for Ed25519, the ECDSA scheme of the key's
     * own curve, the PSS schemes the modulus is long enough for
     * (GOROOT/src/crypto/tls/handshake_client_tls13.go:681-685). uTLS lets the verification fail
     * instead, and says decrypt_error. So on the QUIC plane an Ed25519 signature over an ECDSA
     * certificate, or a P-256 scheme from a P-384 key, is 47 before anything is checked; on the
     * TLS plane it is 51 after. */
    int pkcs1_or_sha1 = scheme == 0x0401u || scheme == 0x0501u || scheme == 0x0601u ||
                        scheme == 0x0201u || scheme == 0x0203u;
    /* Only the Xray reference moved: Hysteria's standard-library and uTLS
     * profiles keep their pinned scheme list (vendor/utls-hy/defaults.go). */
    int mldsa = !stdlib && go127 && scheme >= 0x0904u && scheme <= 0x0906u;
    int tls13 = mldsa || scheme == 0x0804u || scheme == 0x0805u || scheme == 0x0806u || scheme == 0x0403u ||
                scheme == 0x0503u || scheme == 0x0603u || scheme == 0x0807u;
    if (!tls13 || pkcs1_or_sha1)
        gosay(go, go_cap, LC_GO("tls: certificate used with invalid signature algorithm"));
    if (!tls13 && !(pkcs1_or_sha1 && !stdlib))
        return say(err, err_cap, alert, LC_ALERT_ILLEGAL_PARAMETER,
                   "the peer signed with scheme 0x%04x, which is not on the list", (unsigned)scheme);
    if (pkcs1_or_sha1)
        return say(err, err_cap, alert, LC_ALERT_ILLEGAL_PARAMETER,
                   "the peer signed with scheme 0x%04x, which TLS 1.3 does not allow here",
                   (unsigned)scheme);
    if (stdlib && !lc_cert_scheme_fits(cert_der, cert_der_len, scheme))
        return say(err, err_cap, alert, LC_ALERT_ILLEGAL_PARAMETER,
                   "the peer signed with scheme 0x%04x, which its certificate's key cannot sign with",
                   (unsigned)scheme);

    /* THE KEY AND THE SIGNATURE ARE GO'S TO JUDGE, not mbedTLS's.
     *
     * verifyHandshakeSignature asks the scheme's type of key or answers "expected an ... public
     * key, got %T", then hands the key and the signature to ed25519.Verify, ecdsa.VerifyASN1,
     * rsa.VerifyPKCS1v15 or rsa.VerifyPSS with the salt the length of the digest
     * (vendor/utls/auth.go:23-78; the standard library's crypto/tls the same), and every refusal is
     * decrypt_error (vendor/utls/handshake_client_tls13.go:808-812). The key is the one the
     * reference's parser read (leaf_key); the checks are cert/gosig.h's port of those functions,
     * go1.26.6's and go1.27.1's alike on this path.
     *
     * mbedTLS stood here until 2026-09-30, and it is not the same judge: its DER reader for an ECDSA
     * signature takes an INTEGER with a leading zero and a length in long form where cryptobyte
     * takes neither — so a signature anyone can re-encode from a genuine one passed here and failed
     * in the reference — and whether it held a PSS salt to the digest's length depended on how the
     * router's mbedTLS was built (MBEDTLS_USE_PSA_CRYPTO: vendor/mbedtls/library/pk.c:1246-1258). */
    lc_gocert   leaf;
    lc_gopubkey key;
    leaf_key(cert_der, cert_der_len, go127, &leaf, &key);

    /* The signed content. RFC 8446 4.4.3: sixty-four spaces, the context string, a single zero byte,
     * the transcript hash.
     *
     * The zero is a separator, not a C terminator, and it is the one byte of this construction that
     * looks like an artefact of the language it is written in. Left out — the string copied as its
     * thirty-three characters — every signature in the world fails to verify and the peer is refused
     * as an impostor, which is exactly how this was found. vendor/REALITY writes the context with the
     * zero inside the constant (vendor/REALITY/auth.go:106, "TLS 1.3, server CertificateVerify\x00") for that reason;
     * sizeof does the same here, and cannot drift from the string beside it. */
    static const char ctx_str[] = "TLS 1.3, server CertificateVerify";
    uint8_t content[64u + sizeof ctx_str + LC_HASH_MAX];
    size_t  n = 64u;
    memset(content, 0x20, 64u);
    memcpy(content + n, ctx_str, sizeof ctx_str); /* the trailing zero is part of the content */
    n += sizeof ctx_str;
    size_t th_len = lc_hash_len(hash);
    memcpy(content + n, transcript_hash, th_len);
    n += th_len;

    uint8_t digest[64];
    int     rc = 0;

    /* ED25519 FIRST, BECAUSE IT IS NOT LIKE THE OTHERS: it signs the content, not a digest of it.
     * It is the scheme a REALITY node uses, and it uses no other: a Go server holding an Ed25519 key
     * has exactly one entry in its list — `case ed25519.PublicKey: sigAlgs =
     * []SignatureScheme{Ed25519}` (vendor/REALITY/auth.go:209-210). mbedTLS has no Ed25519, so
     * src/tls/ed25519.c does, by Go's rules for the key. A signature of the wrong length is one that
     * does not verify — ed25519.Verify answers false — and so decrypt_error with the rest. */
    if (scheme == 0x0807u) {
        if (key.kind != LC_GOSIG_KEY_ED25519) {
            gosay(go, go_cap,
                  LC_GO("tls: invalid signature by the server certificate: expected an Ed25519 public key, got %T"),
                  lc_gopubkey_type(&key));
            rc = say(err, err_cap, alert, LC_ALERT_DECRYPT_ERROR,
                     "the peer signed with ed25519 and its certificate's key is not one");
        } else if (sig_len != LC_ED25519_SIG || lc_ed25519_verify(key.ed25519, content, n, sig) != 0) {
            gosay(go, go_cap,
                  LC_GO("tls: invalid signature by the server certificate: Ed25519 verification failure"));
            rc = say(err, err_cap, alert, LC_ALERT_DECRYPT_ERROR,
                     "the peer did not prove it holds the key in its certificate");
        }
        goto out;
    }

    if (mldsa) {
        /* vendor/utls/auth.go:49-58 verifies the un-hashed content with the
         * parameter set on the key. It does not add a scheme/parameter check. */
        if (key.kind != LC_GOSIG_KEY_MLDSA) {
            gosay(go, go_cap,
                  LC_GO("tls: invalid signature by the server certificate: expected an ML-DSA public key, got %T"),
                  lc_gopubkey_type(&key));
            rc = say(err, err_cap, alert, LC_ALERT_DECRYPT_ERROR,
                     "the peer signed with ML-DSA and its certificate's key is not one");
        } else {
            lc_obuf why = { 0 };
            int vr = lc_mldsa_verify(key.mldsa, key.mldsa_pk, key.mldsa_pk_len,
                                     content, n, sig, sig_len, &why);
            if (vr == -1) {
                gosay(go, go_cap, LC_GO("tls: invalid signature by the server certificate: ML-DSA verification failure: %s"),
                      why.p != NULL ? why.p : "");
                rc = say(err, err_cap, alert, LC_ALERT_DECRYPT_ERROR,
                         "the peer's ML-DSA signature does not verify: %s", why.p != NULL ? why.p : "");
            } else if (vr != 0) {
                rc = say(err, err_cap, alert, LC_ALERT_INTERNAL_ERROR,
                         "cannot verify the peer's ML-DSA signature");
            }
            free(why.p);
        }
        goto out;
    }

    mbedtls_md_type_t md;
    int               is_pss, hash_id;
    switch (scheme) {
    case 0x0804u: md = MBEDTLS_MD_SHA256; hash_id = LC_GOSIG_HASH_SHA256; is_pss = 1; break; /* rsa_pss_rsae_sha256 */
    case 0x0805u: md = MBEDTLS_MD_SHA384; hash_id = LC_GOSIG_HASH_SHA384; is_pss = 1; break;
    case 0x0806u: md = MBEDTLS_MD_SHA512; hash_id = LC_GOSIG_HASH_SHA512; is_pss = 1; break;
    case 0x0403u: md = MBEDTLS_MD_SHA256; hash_id = LC_GOSIG_HASH_SHA256; is_pss = 0; break; /* ecdsa_secp256r1_sha256 */
    case 0x0503u: md = MBEDTLS_MD_SHA384; hash_id = LC_GOSIG_HASH_SHA384; is_pss = 0; break;
    case 0x0603u: md = MBEDTLS_MD_SHA512; hash_id = LC_GOSIG_HASH_SHA512; is_pss = 0; break;
    default:
        /* Including the PKCS#1 v1.5 codes the hello offers: legal to advertise, not legal here. */
        rc = say(err, err_cap, alert, LC_ALERT_ILLEGAL_PARAMETER,
                 "the peer signed with scheme 0x%04x, which this build cannot verify", (unsigned)scheme);
        goto out;
    }
    /* The digest is taken with mbedTLS directly rather than through lc_hash, because SHA-512 belongs
     * to signature schemes and not to the key schedule: adding it to that enum would raise
     * LC_HASH_MAX from 48 to 64 and grow every secret buffer in the client for a hash the schedule
     * never uses. */
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(md);
    if (info == NULL || mbedtls_md(info, content, n, digest) != 0) {
        rc = say(err, err_cap, alert, LC_ALERT_INTERNAL_ERROR, "cannot digest the signed content");
        goto out;
    }
    size_t dlen = mbedtls_md_get_size(info);

    /* THE SCHEME MUST NAME THE KEY THE CERTIFICATE ACTUALLY CARRIES: an RSA key for PSS, an ECDSA
     * one for ECDSA, or "expected ..." — and nothing about the curve. On the REALITY plane that is
     * uTLS's behaviour; on the QUIC plane the pairing was already refused above, with the standard
     * library's illegal_parameter, by lc_cert_scheme_fits. */
    if (is_pss ? key.kind != LC_GOSIG_KEY_RSA : key.kind != LC_GOSIG_KEY_ECDSA) {
        gosay(go, go_cap,
              is_pss ? LC_GO("tls: invalid signature by the server certificate: expected an RSA public key, got %T")
                     : LC_GO("tls: invalid signature by the server certificate: expected an ECDSA public key, got %T"),
              lc_gopubkey_type(&key));
        rc = say(err, err_cap, alert, LC_ALERT_DECRYPT_ERROR,
                 "the peer signed with scheme 0x%04x and its certificate's key is another kind",
                 (unsigned)scheme);
        goto out;
    }
    if (is_pss) {
        /* ⚠️ AND AN RSA KEY HAS A CEILING, because verifying one is work an attacker chooses the size
         * of: 8192, the reference's own `defaultMaxRSAKeySize` (vendor/utls/handshake_client.go:1122),
         * applied through checkKeySize at :1131-1136 with alertBadCertificate. The certificate
         * message is refused for it before this runs; this is the same number once more. */
        size_t bits = 0;
        for (size_t i = 0; i < key.rsa_n_len && bits == 0u; i++)
            if (key.rsa_n[i] != 0u)
                for (unsigned b = 8; b > 0u && bits == 0u; b--)
                    if ((key.rsa_n[i] >> (b - 1u)) & 1u)
                        bits = (key.rsa_n_len - i - 1u) * 8u + b;
        if (bits > LC_MAX_RSA_BITS) {
            rc = say(err, err_cap, alert, LC_ALERT_BAD_CERTIFICATE,
                     "the peer's RSA key is larger than this client will verify");
            goto out;
        }
        lc_obuf why = { 0 };
        int     vr = lc_go_rsa_verify(1, hash_id, digest, dlen, sig, sig_len, &key, &why);
        if (vr == -1) {
            gosay(go, go_cap, LC_GO("tls: invalid signature by the server certificate: %s"),
                  why.p != NULL ? why.p : "");
            rc = say(err, err_cap, alert, LC_ALERT_DECRYPT_ERROR, "the peer's signature does not verify: %s",
                     why.p != NULL ? why.p : "");
        } else if (vr != 0) {
            rc = say(err, err_cap, alert, LC_ALERT_INTERNAL_ERROR, "cannot verify the peer's RSA signature");
        }
        free(why.p);
    } else {
        int vr = lc_go_ecdsa_verify_asn1(&key, digest, dlen, sig, sig_len);
        if (vr == 0) {
            gosay(go, go_cap,
                  LC_GO("tls: invalid signature by the server certificate: ECDSA verification failure"));
            rc = say(err, err_cap, alert, LC_ALERT_DECRYPT_ERROR,
                     "the peer did not prove it holds the key in its certificate");
        } else if (vr != 1) {
            rc = say(err, err_cap, alert, LC_ALERT_INTERNAL_ERROR, "cannot verify the peer's ECDSA signature");
        }
    }

out:
    lc_gocert_free(&leaf);
    lc_wipe(content, sizeof content);
    lc_wipe(digest, sizeof digest);
    return rc;
}

int lc_skx12_verify(const uint8_t *cert_der, size_t cert_der_len, const uint8_t *hello_sigalgs,
                    size_t hello_sigalgs_len, int rsa_suite, const uint8_t client_random[32],
                    const uint8_t server_random[32], const uint8_t *params, size_t params_len,
                    const uint8_t *sig, size_t sig_len)
{
    /* `signatureAlgorithm := ...sig[0..1]; sig = sig[2:]; if len(sig) < 2 { errServerKeyExchange }`,
     * then the list the hello offered (vendor/utls/key_agreement.go:339-341). */
    if (sig_len < 2u)
        return -1;
    uint16_t scheme = (uint16_t)((uint16_t)sig[0] << 8 | sig[1]);
    sig += 2;
    sig_len -= 2;
    if (sig_len < 2u)
        return -1;
    int offered = 0;
    if (hello_sigalgs != NULL && hello_sigalgs_len >= 2u) {
        size_t list = (size_t)hello_sigalgs[0] << 8 | hello_sigalgs[1];
        for (size_t i = 2; i + 1u < 2u + list && i + 1u < hello_sigalgs_len; i += 2u)
            if (((uint16_t)((uint16_t)hello_sigalgs[i] << 8 | hello_sigalgs[i + 1u])) == scheme)
                offered = 1;
    }
    if (!offered)
        return -1;

    /* typeAndHashFromSignatureScheme (vendor/utls/auth.go:135-167). */
    enum { PKCS1, PSS, ECDSA, ED25519 } type;
    mbedtls_md_type_t md = MBEDTLS_MD_NONE;
    switch (scheme) {
    case 0x0201u: type = PKCS1; md = MBEDTLS_MD_SHA1; break;
    case 0x0401u: type = PKCS1; md = MBEDTLS_MD_SHA256; break;
    case 0x0501u: type = PKCS1; md = MBEDTLS_MD_SHA384; break;
    case 0x0601u: type = PKCS1; md = MBEDTLS_MD_SHA512; break;
    case 0x0804u: type = PSS; md = MBEDTLS_MD_SHA256; break;
    case 0x0805u: type = PSS; md = MBEDTLS_MD_SHA384; break;
    case 0x0806u: type = PSS; md = MBEDTLS_MD_SHA512; break;
    case 0x0203u: type = ECDSA; md = MBEDTLS_MD_SHA1; break;
    case 0x0403u: type = ECDSA; md = MBEDTLS_MD_SHA256; break;
    case 0x0503u: type = ECDSA; md = MBEDTLS_MD_SHA384; break;
    case 0x0603u: type = ECDSA; md = MBEDTLS_MD_SHA512; break;
    case 0x0807u: type = ED25519; break;
    default: return -1;
    }
    /* `if (sigType == signaturePKCS1v15 || sigType == signatureRSAPSS) != ka.isRSA` (:343-345), then
     * the signature's own length (:347-351). */
    if ((type == PKCS1 || type == PSS) != (rsa_suite != 0))
        return -1;
    size_t n = (size_t)sig[0] << 8 | sig[1];
    if (n + 2u != sig_len)
        return -1;
    sig += 2;

    /* hashForServerKeyExchange: the randoms and the parameters, digested — or, for Ed25519, as they
     * are (vendor/utls/key_agreement.go:129-136). */
    uint8_t msg[64u + 4u + 255u];
    if (params_len > sizeof msg - 64u)
        return -1;
    memcpy(msg, client_random, 32u);
    memcpy(msg + 32u, server_random, 32u);
    memcpy(msg + 64u, params, params_len);
    size_t msg_len = 64u + params_len;

    /* The key as go1.27.1's parser read it, and the scheme's kind of key or nothing
     * (vendor/utls/auth.go:34-70) — then Go's checks, as in lc_cert_verify. */
    lc_gocert   leaf;
    lc_gopubkey key;
    leaf_key(cert_der, cert_der_len, 1, &leaf, &key);
    int rc = -1;

    if (type == ED25519) {
        if (key.kind == LC_GOSIG_KEY_ED25519 && n == LC_ED25519_SIG &&
            lc_ed25519_verify(key.ed25519, msg, msg_len, sig) == 0)
            rc = 0;
        goto out;
    }

    int hash_id = md == MBEDTLS_MD_SHA1     ? LC_GOSIG_HASH_SHA1
                  : md == MBEDTLS_MD_SHA256 ? LC_GOSIG_HASH_SHA256
                  : md == MBEDTLS_MD_SHA384 ? LC_GOSIG_HASH_SHA384
                                            : LC_GOSIG_HASH_SHA512;
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(md);
    uint8_t                  digest[64];
    if (info == NULL || mbedtls_md(info, msg, msg_len, digest) != 0)
        goto out;
    size_t dlen = mbedtls_md_get_size(info);

    if (type == ECDSA) {
        rc = key.kind == LC_GOSIG_KEY_ECDSA && lc_go_ecdsa_verify_asn1(&key, digest, dlen, sig, n) == 1 ? 0 : -1;
    } else if (key.kind == LC_GOSIG_KEY_RSA) {
        /* rsa.VerifyPKCS1v15 or rsa.VerifyPSS, the 1024-bit floor (rsa1024min) and all */
        rc = lc_go_rsa_verify(type == PSS, hash_id, digest, dlen, sig, n, &key, NULL) == 0 ? 0 : -1;
    }
    lc_wipe(digest, sizeof digest);
out:
    lc_gocert_free(&leaf);
    lc_wipe(msg, sizeof msg);
    return rc;
}
