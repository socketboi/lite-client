/* Transcript hash and key exchange, against the same RFC 8448 trace.
 *
 * These two are tested together because the trace ties them together: the shared secret produced by
 * the key exchange is the input keying material of the handshake extract, and the transcript hashes
 * are the context of the derivations that follow. Both are already pinned by the key schedule test,
 * so hitting them from this side closes the loop — every value in the schedule is now reachable
 * from the raw handshake messages and the two private keys, with nothing taken on trust. */

#include "tls/kex.h"
#include "tls/transcript.h"
#include "test_vectors.h"

#include <stdio.h>
#include <string.h>

#define SZ(a) (sizeof(a) / sizeof((a)[0]))

static int failures;

static void check(const char *what, const uint8_t *got, const uint8_t *want, size_t len)
{
    if (memcmp(got, want, len) == 0) {
        printf("  ok    %s (%zu bytes)\n", what, len);
        return;
    }
    printf("  FAIL  %s\n        want:", what);
    for (size_t i = 0; i < len; i++)
        printf(" %02x", want[i]);
    printf("\n        got: ");
    for (size_t i = 0; i < len; i++)
        printf(" %02x", got[i]);
    printf("\n");
    failures++;
}

/* The transcript at a given point, built from the handshake messages the trace printed.
 * The record layer is deliberately absent: these are message bytes, and a message that arrived
 * split across two records has to hash identically to one that did not. */
static void transcript_at(const char *what, const uint8_t *want, size_t want_len,
                          int include_server_flight, int include_client_finished)
{
    lc_transcript t;
    if (lc_transcript_init(&t, LC_SHA256) != 0) {
        printf("  FAIL  %s: cannot start a transcript\n", what);
        failures++;
        return;
    }

    lc_transcript_add(&t, cli_record_1_payload, SZ(cli_record_1_payload)); /* ClientHello */
    lc_transcript_add(&t, srv_record_1_payload, SZ(srv_record_1_payload)); /* ServerHello */
    if (include_server_flight)
        lc_transcript_add(&t, srv_record_2_payload, SZ(srv_record_2_payload));
    if (include_client_finished)
        lc_transcript_add(&t, cli_record_2_payload, SZ(cli_record_2_payload));

    uint8_t got[LC_HASH_MAX];
    if (lc_transcript_snapshot(&t, got) != 0) {
        printf("  FAIL  %s: cannot read the transcript\n", what);
        failures++;
    } else {
        check(what, got, want, want_len);
    }
    lc_transcript_free(&t);
}

int main(void)
{
    printf("RFC 8448 transcript and key exchange\n");

    /* The transcript at the three points the schedule reads it. Each expected value is the "hash"
     * the trace prints for the derivation that consumes it — so if the transcript is wrong, the
     * secrets derived from it are wrong too, and this says which of the two broke. */
    transcript_at("transcript after ServerHello",
                  srv_derive_c_hs_traffic_hash, SZ(srv_derive_c_hs_traffic_hash), 0, 0);
    transcript_at("transcript after server Finished",
                  srv_derive_c_ap_traffic_hash, SZ(srv_derive_c_ap_traffic_hash), 1, 0);
    transcript_at("transcript after client Finished",
                  cli_derive_res_master_hash, SZ(cli_derive_res_master_hash), 1, 1);

    /* Reading the transcript must not disturb it: the handshake carries on afterwards, and a
     * snapshot that consumed the state would leave every later derivation wrong. */
    {
        lc_transcript t;
        if (lc_transcript_init(&t, LC_SHA256) == 0) {
            lc_transcript_add(&t, cli_record_1_payload, SZ(cli_record_1_payload));
            lc_transcript_add(&t, srv_record_1_payload, SZ(srv_record_1_payload));
            uint8_t first[LC_HASH_MAX], second[LC_HASH_MAX];
            lc_transcript_snapshot(&t, first);
            lc_transcript_snapshot(&t, second);
            check("snapshot is repeatable", second, first, lc_hash_len(LC_SHA256));

            lc_transcript_add(&t, srv_record_2_payload, SZ(srv_record_2_payload));
            uint8_t after[LC_HASH_MAX];
            lc_transcript_snapshot(&t, after);
            if (memcmp(after, first, lc_hash_len(LC_SHA256)) == 0) {
                printf("  FAIL  adding a message did not change the transcript\n");
                failures++;
            } else {
                printf("  ok    adding a message changes the transcript\n");
            }
            lc_transcript_free(&t);
        }
    }

    /* Key exchange, from both directions. The shared secret is the IKM the handshake extract
     * consumed, so agreeing with it means agreeing with everything the schedule produced. */
    {
        uint8_t shared[LC_X25519_SHARED];
        if (lc_x25519(cli_x25519_private_key, srv_x25519_public_key, shared) != 0) {
            printf("  FAIL  client-side X25519 returned an error\n");
            failures++;
        } else {
            check("X25519, client private against server public",
                  shared, srv_extract_handshake_ikm, SZ(srv_extract_handshake_ikm));
        }

        if (lc_x25519(srv_x25519_private_key, cli_x25519_public_key, shared) != 0) {
            printf("  FAIL  server-side X25519 returned an error\n");
            failures++;
        } else {
            check("X25519, server private against client public",
                  shared, srv_extract_handshake_ikm, SZ(srv_extract_handshake_ikm));
        }
    }

    /* Deriving a public key from a private one has to agree with what the trace recorded — this is
     * where a little-endian/big-endian mix-up hides, because a wrong conversion still produces a
     * self-consistent key pair that simply fails against every real peer. */
    {
        uint8_t pub[LC_X25519_KEY];
        if (lc_x25519_public(cli_x25519_private_key, pub) != 0) {
            printf("  FAIL  deriving the client public key returned an error\n");
            failures++;
        } else {
            check("client public key from its private key",
                  pub, cli_x25519_public_key, SZ(cli_x25519_public_key));
        }
    }

    /* A freshly generated pair must agree with itself both ways round. */
    {
        uint8_t a_priv[LC_X25519_KEY], a_pub[LC_X25519_KEY];
        uint8_t b_priv[LC_X25519_KEY], b_pub[LC_X25519_KEY];
        uint8_t ab[LC_X25519_SHARED], ba[LC_X25519_SHARED];
        if (lc_x25519_keygen(a_priv, a_pub) != 0 || lc_x25519_keygen(b_priv, b_pub) != 0) {
            printf("  FAIL  key generation returned an error\n");
            failures++;
        } else if (lc_x25519(a_priv, b_pub, ab) != 0 || lc_x25519(b_priv, a_pub, ba) != 0) {
            printf("  FAIL  agreement on generated keys returned an error\n");
            failures++;
        } else {
            check("generated pair agrees both ways", ab, ba, LC_X25519_SHARED);
        }
    }

    /* A low-order peer key yields an all-zero secret, which RFC 7748 says must be refused. Without
     * this the client would happily use a value an attacker can predict. */
    {
        uint8_t priv[LC_X25519_KEY], pub[LC_X25519_KEY], shared[LC_X25519_SHARED];
        static const uint8_t low_order[LC_X25519_KEY] = { 0 }; /* the identity point */
        if (lc_x25519_keygen(priv, pub) == 0) {
            if (lc_x25519(priv, low_order, shared) == 0) {
                printf("  FAIL  a low-order peer key was accepted\n");
                failures++;
            } else {
                printf("  ok    low-order peer key rejected\n");
            }
        }
    }

    printf("\n%s\n", failures == 0 ? "transcript and key exchange match RFC 8448"
                                   : "TRANSCRIPT OR KEY EXCHANGE IS WRONG");
    return failures == 0 ? 0 : 1;
}
