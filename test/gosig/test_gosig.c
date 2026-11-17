/* cert/gosig.c against Go's own x509 checkSignature: every vector tools/sigvec wrote down, the
 * verdict and the words. checkSignature's answers do not depend on the width of Go's int — the one
 * input that does, an RSA exponent, is a number ParseCertificate has already fitted into one — so
 * one set of answers serves the router and the host alike.
 *
 * ML-DSA's verification is the ML-DSA port's (lc_mldsa_verify, see gosig.c), and this file stands
 * in for it: it answers what mldsa.Verify answered for the vector at hand, and checks that it is
 * called exactly when checkSignature would call mldsa.Verify, with the key, the unhashed message
 * and the signature that call would get. Built with -DLC_GOSIG_REAL_MLDSA and linked with
 * cert/mldsa.c instead, the ML-DSA vectors run end to end through the port.
 *
 * Built with -DLC_GOSIG_VS_TLS_ED25519 and linked with tls/ed25519.c and tls/fe25519.c, it also
 * puts every PureEd25519 vector to the TLS plane's verifier, which uTLS's CertificateVerify on both
 * planes reaches through the same ed25519.Verify, and fails where its verdict is not Go's — the
 * build test-ed25519go makes. */
#include "cert/gosig.h"

#include "reference.h"

#ifdef LC_GOSIG_VS_TLS_ED25519
#include "tls/ed25519.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int      failures;
static unsigned shown;

static const sv_vec *current;
static int           ml_calls, ml_wrong_args;

#ifndef LC_GOSIG_REAL_MLDSA

static int same(const uint8_t *a, size_t an, const uint8_t *b, size_t bn)
{
    return an == bn && (an == 0u || memcmp(a, b, an) == 0);
}

int lc_mldsa_verify(int params, const uint8_t *pk, size_t pk_len, const uint8_t *msg, size_t msg_len,
                    const uint8_t *sig, size_t sig_len, lc_obuf *err)
{
    const sv_key *k = &sv_keys[current->key];
    ml_calls++;
    if (params != k->ml || !same(pk, pk_len, sv_pool + k->mpk_off, k->mpk_len) ||
        !same(msg, msg_len, sv_pool + current->msg_off, current->msg_len) ||
        !same(sig, sig_len, sv_pool + current->sig_off, current->sig_len))
        ml_wrong_args++;
    if (current->ml_inner[0] == '\0')
        return 0;
    lc_obuf_add(err, current->ml_inner, strlen(current->ml_inner));
    return -1;
}
#endif

static lc_gopubkey key_of(const sv_key *k)
{
    lc_gopubkey p;
    memset(&p, 0, sizeof p);
    p.kind = k->kind;
    p.rsa_n = k->n_nil ? NULL : sv_pool + k->n_off;
    p.rsa_n_len = k->n_len;
    p.rsa_e = k->e;
    p.curve = k->curve;
    p.point = sv_pool + k->pt_off;
    p.point_len = k->pt_len;
    if (k->kind == LC_GOSIG_KEY_ED25519)
        memcpy(p.ed25519, sv_pool + k->ed_off, 32);
    p.mldsa = k->ml;
    p.mldsa_pk = sv_pool + k->mpk_off;
    p.mldsa_pk_len = k->mpk_len;
    return p;
}

/* Which family a vector belongs to, for the summary: by the key it is checked against. */
static const char *const FAMILY[] = { "a nil key",  "RSA keys",     "DSA keys",
                                       "ECDSA keys", "Ed25519 keys", "ML-DSA keys" };

int main(void)
{
    printf("x509 checkSignature, go1.27.1, allowSHA1 false\n");

    size_t nv = sizeof sv_vecs / sizeof sv_vecs[0];
    int    per[6] = { 0 }, bad[6] = { 0 };
    for (size_t i = 0; i < nv; i++) {
        const sv_vec *v = &sv_vecs[i];
        const sv_key *k = &sv_keys[v->key];
        lc_gopubkey   pub = key_of(k);
        lc_obuf       err = { 0 };
        current = v;
        ml_calls = ml_wrong_args = 0;
        int rc = lc_go_check_signature(v->alg, sv_pool + v->msg_off, v->msg_len, sv_pool + v->sig_off,
                                       v->sig_len, &pub, &err);
        const char *got = rc == 0    ? ""
                          : rc == -2 ? "(could not answer)"
                          : err.p != NULL ? err.p
                                          : "(no words)";
        int ok = rc != -2 && (rc == 0) == (v->want[0] == '\0') && strcmp(got, v->want) == 0 &&
                 ml_wrong_args == 0;
#ifndef LC_GOSIG_REAL_MLDSA
        ok = ok && ml_calls == v->ml_reach;
#endif
        per[k->kind]++;
        if (!ok) {
            bad[k->kind]++;
            failures++;
            if (shown++ < 30)
                printf("  FAIL  %s\n        Go:   \"%s\"\n        this: \"%s\"%s\n", v->what, v->want, got,
                       ml_calls != v->ml_reach ? " (ML-DSA reached wrongly)"
                       : ml_wrong_args         ? " (ML-DSA called with the wrong arguments)"
                                               : "");
        }
        free(err.p);
    }
    for (int f = 0; f < 6; f++)
        if (per[f] != 0)
            printf("  %-4s  %d vectors with %s: every verdict and every word Go's (%d differ)\n",
                   bad[f] == 0 ? "ok" : "FAIL", per[f], FAMILY[f], bad[f]);

    /* The same, with no place for the words: the verdict must not depend on being asked for them. */
    {
        int differ = 0;
        for (size_t i = 0; i < nv; i++) {
            const sv_vec *v = &sv_vecs[i];
            lc_gopubkey   pub = key_of(&sv_keys[v->key]);
            current = v;
            int rc = lc_go_check_signature(v->alg, sv_pool + v->msg_off, v->msg_len, sv_pool + v->sig_off,
                                           v->sig_len, &pub, NULL);
            if ((rc == 0) != (v->want[0] == '\0') || rc == -2)
                differ++;
        }
        printf("  %-4s  the same %zu verdicts with err = NULL (%d differ)\n", differ == 0 ? "ok" : "FAIL", nv, differ);
        failures += differ;
    }

    /* A nil key passed as NULL is the nil key. */
    {
        lc_obuf err = { 0 };
        int     rc = lc_go_check_signature(LC_GO_SIG_SHA256_RSA, (const uint8_t *)"x", 1,
                                           (const uint8_t *)"y", 1, NULL, &err);
        int     ok = rc == -1 && err.p != NULL &&
                 strcmp(err.p, "x509: cannot verify signature: algorithm unimplemented") == 0;
        printf("  %-4s  pub = NULL is a nil PublicKey\n", ok ? "ok" : "FAIL");
        failures += !ok;
        free(err.p);
    }

    /* SignatureAlgorithm.String() and PublicKeyAlgorithm.String(), as Go printed them. */
    {
        int  differ = 0;
        char nb[24];
        for (int a = -1; a <= 22; a++)
            differ += strcmp(lc_go_sig_alg_name(a, nb), sv_alg_names[a + 1]) != 0;
        for (int a = -1; a <= 7; a++)
            differ += strcmp(lc_go_pk_alg_name(a, nb), sv_pk_names[a + 1]) != 0;
        printf("  %-4s  the names of algorithms -1..22 and of key algorithms -1..7 (%d differ)\n",
               differ == 0 ? "ok" : "FAIL", differ);
        failures += differ;
    }

#ifdef LC_GOSIG_VS_TLS_ED25519
    {
        int n = 0, differ = 0;
        for (size_t i = 0; i < nv; i++) {
            const sv_vec *v = &sv_vecs[i];
            const sv_key *k = &sv_keys[v->key];
            if (v->alg != LC_GO_SIG_PURE_ED25519 || k->kind != LC_GOSIG_KEY_ED25519 || v->sig_len != 64u)
                continue;
            n++;
            int tls_ok = lc_ed25519_verify(sv_pool + k->ed_off, sv_pool + v->msg_off, v->msg_len,
                                           sv_pool + v->sig_off) == 0;
            int go_ok = v->want[0] == '\0';
            if (tls_ok != go_ok) {
                differ++;
                printf("  FAIL  tls/ed25519.c %s where Go %s: %s\n        A = ", tls_ok ? "accepts" : "refuses",
                       go_ok ? "accepts" : "refuses", v->what);
                for (int j = 0; j < 32; j++)
                    printf("%02x", sv_pool[k->ed_off + (uint32_t)j]);
                printf("\n        sig = ");
                for (uint32_t j = 0; j < 64u; j++)
                    printf("%02x", sv_pool[v->sig_off + j]);
                printf("\n        msg = ");
                for (uint32_t j = 0; j < v->msg_len; j++)
                    printf("%02x", sv_pool[v->msg_off + j]);
                printf("\n");
            }
        }
        printf("  %-4s  tls/ed25519.c against Go on %d 64-byte Ed25519 vectors: %d verdicts differ\n",
               differ == 0 && n > 100 ? "ok" : "FAIL", n, differ);
        failures += differ + (n > 100 ? 0 : 1);
    }
#endif

    if (failures) {
        printf("%d FAILED\n", failures);
        return 1;
    }
    printf("all good\n");
    return 0;
}
