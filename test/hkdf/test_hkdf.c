/* The key schedule against RFC 8448.
 *
 * Every value here comes from the document, extracted by tools/vectors/extract.awk — nothing is
 * typed in by hand, because a mistyped test vector produces a test that passes on wrong code.
 *
 * The three operations are checked separately. They fail in different ways: a broken label makes
 * every derivation wrong at once, a broken expand makes only long outputs wrong, and a broken
 * extract makes only the first step wrong. Testing them together would leave the failure mode
 * ambiguous exactly when it matters. */

#include "tls/hkdf.h"
#include "test_vectors.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void check(const char *what, const uint8_t *got, size_t got_len,
                  const uint8_t *want, size_t want_len)
{
    if (got_len == want_len && memcmp(got, want, want_len) == 0) {
        printf("  ok    %s (%zu bytes)\n", what, want_len);
        return;
    }
    printf("  FAIL  %s\n", what);
    printf("        want:");
    for (size_t i = 0; i < want_len; i++)
        printf(" %02x", want[i]);
    printf("\n        got: ");
    for (size_t i = 0; i < got_len; i++)
        printf(" %02x", got[i]);
    printf("\n");
    failures++;
}

/* An extract step: salt, input keying material, expected secret. */
static void t_extract(const char *what, const uint8_t *salt, size_t salt_len,
                      const uint8_t *ikm, size_t ikm_len,
                      const uint8_t *want, size_t want_len)
{
    uint8_t out[LC_HASH_MAX];
    if (lc_hkdf_extract(LC_SHA256, salt, salt_len, ikm, ikm_len, out) != 0) {
        printf("  FAIL  %s: extract returned an error\n", what);
        failures++;
        return;
    }
    check(what, out, lc_hash_len(LC_SHA256), want, want_len);
}

/* A derivation: the HkdfLabel is checked against the "info" the RFC prints, then the expansion
 * against "expanded". */
static void t_derive(const char *what, const char *label,
                     const uint8_t *prk, const uint8_t *hash, size_t hash_len,
                     const uint8_t *want_info, size_t want_info_len,
                     const uint8_t *want_out, size_t want_out_len)
{
    uint8_t info[512];
    size_t  info_len = 0;
    char    label_buf[64];
    snprintf(label_buf, sizeof label_buf, "%s", label);

    if (lc_hkdf_label(label_buf, hash, hash_len, want_out_len, info, sizeof info, &info_len) != 0) {
        printf("  FAIL  %s: label construction returned an error\n", what);
        failures++;
        return;
    }
    char info_name[96];
    snprintf(info_name, sizeof info_name, "%s — HkdfLabel", what);
    check(info_name, info, info_len, want_info, want_info_len);

    uint8_t out[LC_HASH_MAX];
    if (lc_hkdf_expand_label(LC_SHA256, prk, label_buf, hash, hash_len, out, want_out_len) != 0) {
        printf("  FAIL  %s: expand returned an error\n", what);
        failures++;
        return;
    }
    check(what, out, want_out_len, want_out, want_out_len);
}

#define SZ(a) (sizeof(a) / sizeof((a)[0]))

int main(void)
{
    printf("RFC 8448, simple 1-RTT handshake\n");

    /* The schedule starts from nothing: an all-zero salt and an all-zero PSK. */
    t_extract("extract early", NULL, 0,
              srv_extract_early_ikm, SZ(srv_extract_early_ikm),
              srv_extract_early_secret, SZ(srv_extract_early_secret));

    t_derive("derive \"derived\" for handshake", "derived",
             srv_derive_hs_derived_prk, srv_derive_hs_derived_hash, SZ(srv_derive_hs_derived_hash),
             srv_derive_hs_derived_info, SZ(srv_derive_hs_derived_info),
             srv_derive_hs_derived_expanded, SZ(srv_derive_hs_derived_expanded));

    /* The one step where the ECDHE shared secret enters the schedule. */
    t_extract("extract handshake",
              srv_extract_handshake_salt, SZ(srv_extract_handshake_salt),
              srv_extract_handshake_ikm, SZ(srv_extract_handshake_ikm),
              srv_extract_handshake_secret, SZ(srv_extract_handshake_secret));

    t_derive("derive \"c hs traffic\"", "c hs traffic",
             srv_derive_c_hs_traffic_prk, srv_derive_c_hs_traffic_hash, SZ(srv_derive_c_hs_traffic_hash),
             srv_derive_c_hs_traffic_info, SZ(srv_derive_c_hs_traffic_info),
             srv_derive_c_hs_traffic_expanded, SZ(srv_derive_c_hs_traffic_expanded));

    t_derive("derive \"s hs traffic\"", "s hs traffic",
             srv_derive_s_hs_traffic_prk, srv_derive_s_hs_traffic_hash, SZ(srv_derive_s_hs_traffic_hash),
             srv_derive_s_hs_traffic_info, SZ(srv_derive_s_hs_traffic_info),
             srv_derive_s_hs_traffic_expanded, SZ(srv_derive_s_hs_traffic_expanded));

    t_derive("derive \"derived\" for master", "derived",
             srv_derive_master_derived_prk, srv_derive_master_derived_hash, SZ(srv_derive_master_derived_hash),
             srv_derive_master_derived_info, SZ(srv_derive_master_derived_info),
             srv_derive_master_derived_expanded, SZ(srv_derive_master_derived_expanded));

    /* The master secret takes no new keying material — the zero IKM is the point. */
    t_extract("extract master",
              srv_extract_master_salt, SZ(srv_extract_master_salt),
              srv_extract_master_ikm, SZ(srv_extract_master_ikm),
              srv_extract_master_secret, SZ(srv_extract_master_secret));

    t_derive("derive \"c ap traffic\"", "c ap traffic",
             srv_derive_c_ap_traffic_prk, srv_derive_c_ap_traffic_hash, SZ(srv_derive_c_ap_traffic_hash),
             srv_derive_c_ap_traffic_info, SZ(srv_derive_c_ap_traffic_info),
             srv_derive_c_ap_traffic_expanded, SZ(srv_derive_c_ap_traffic_expanded));

    t_derive("derive \"s ap traffic\"", "s ap traffic",
             srv_derive_s_ap_traffic_prk, srv_derive_s_ap_traffic_hash, SZ(srv_derive_s_ap_traffic_hash),
             srv_derive_s_ap_traffic_info, SZ(srv_derive_s_ap_traffic_info),
             srv_derive_s_ap_traffic_expanded, SZ(srv_derive_s_ap_traffic_expanded));

    t_derive("derive \"exp master\"", "exp master",
             srv_derive_exp_master_prk, srv_derive_exp_master_hash, SZ(srv_derive_exp_master_hash),
             srv_derive_exp_master_info, SZ(srv_derive_exp_master_info),
             srv_derive_exp_master_expanded, SZ(srv_derive_exp_master_expanded));

    t_derive("derive \"res master\"", "res master",
             cli_derive_res_master_prk, cli_derive_res_master_hash, SZ(cli_derive_res_master_hash),
             cli_derive_res_master_info, SZ(cli_derive_res_master_info),
             cli_derive_res_master_expanded, SZ(cli_derive_res_master_expanded));

    /* Record keys: the only derivations with an empty context and a length other than one digest.
     * A key is 16 bytes and an IV is 12, so these also exercise short expansions. */
    t_derive("handshake write key", "key",
             srv_wkeys_handshake_data_prk, NULL, 0,
             srv_wkeys_handshake_data_key_info, SZ(srv_wkeys_handshake_data_key_info),
             srv_wkeys_handshake_data_key_expanded, SZ(srv_wkeys_handshake_data_key_expanded));

    t_derive("handshake write iv", "iv",
             srv_wkeys_handshake_data_prk, NULL, 0,
             srv_wkeys_handshake_data_iv_info, SZ(srv_wkeys_handshake_data_iv_info),
             srv_wkeys_handshake_data_iv_expanded, SZ(srv_wkeys_handshake_data_iv_expanded));

    t_derive("application write key", "key",
             srv_wkeys_application_data_prk, NULL, 0,
             srv_wkeys_application_data_key_info, SZ(srv_wkeys_application_data_key_info),
             srv_wkeys_application_data_key_expanded, SZ(srv_wkeys_application_data_key_expanded));

    t_derive("application write iv", "iv",
             srv_wkeys_application_data_prk, NULL, 0,
             srv_wkeys_application_data_iv_info, SZ(srv_wkeys_application_data_iv_info),
             srv_wkeys_application_data_iv_expanded, SZ(srv_wkeys_application_data_iv_expanded));

    printf("\n%s\n", failures == 0 ? "key schedule matches RFC 8448" : "KEY SCHEDULE IS WRONG");
    return failures == 0 ? 0 : 1;
}
