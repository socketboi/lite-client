/* REALITY, against a reference transcribed from Xray and the REALITY server.
 *
 * The vector is a stamped ClientHello. This test takes that same buffer, stamps it again with the
 * same inputs, and requires the result to come out identical — which works precisely because the
 * first thing stamping does is zero session_id, so whatever was there before cannot influence the
 * outcome. If it could, this test would be meaningless, and that is worth knowing about the design.
 *
 * There is no server here, and there cannot be: the point of REALITY is that a wrong client is
 * indistinguishable from an ordinary browser, so a live server answers a broken client with a
 * perfectly good web page and no error at all. Everything provable without one is proved here. */

#include "reality/reality.h"
#include "tls/kex.h"
#include "reality_vectors.h"

#include <stdio.h>
#include <string.h>

#define SZ(a) (sizeof(a) / sizeof((a)[0]))

static int failures;

static void ok(const char *what) { printf("  ok    %s\n", what); }

static void fail(const char *what)
{
    printf("  FAIL  %s\n", what);
    failures++;
}

static void check_bytes(const char *what, const uint8_t *got, const uint8_t *want, size_t len)
{
    if (memcmp(got, want, len) == 0) {
        printf("  ok    %s (%zu bytes)\n", what, len);
        return;
    }
    printf("  FAIL  %s\n", what);
    for (size_t i = 0; i < len; i++) {
        if (got[i] != want[i]) {
            printf("        first difference at byte %zu: %02x against %02x\n", i, got[i], want[i]);
            break;
        }
    }
    failures++;
}

static lc_reality_config config(void)
{
    lc_reality_config cfg;
    memcpy(cfg.public_key, reality_vec_server_public, LC_REALITY_KEY);
    memcpy(cfg.short_id, reality_vec_short_id, LC_REALITY_SHORT_ID);
    memcpy(cfg.version, reality_vec_version, sizeof cfg.version);
    return cfg;
}

int main(void)
{
    printf("REALITY against the reference implementation\n");

    lc_reality_config cfg = config();

    /* ---- stamping ---- */
    static uint8_t hello[SZ(reality_vec_hello_stamped)];
    memcpy(hello, reality_vec_hello_stamped, sizeof hello);

    uint8_t auth_key[LC_REALITY_AUTH_KEY];
    if (lc_reality_stamp(hello, sizeof hello, REALITY_VEC_SID_OFF, &cfg,
                         reality_vec_client_private, REALITY_VEC_TIME, auth_key) != 0) {
        fail("stamping returned an error");
        return 1;
    }
    check_bytes("authentication key", auth_key, reality_vec_auth_key, SZ(reality_vec_auth_key));
    check_bytes("stamped ClientHello", hello, reality_vec_hello_stamped, sizeof hello);

    /* The server derives the same key from the other half of the exchange. Checking that direction
     * too is what distinguishes a correct derivation from one that merely agrees with itself. */
    {
        uint8_t shared[LC_X25519_SHARED];
        if (lc_x25519(reality_vec_server_private, reality_vec_client_public, shared) != 0) {
            fail("the server-side exchange returned an error");
        } else {
            /* The key schedule from the server's side is the same function; only the inputs differ.
             * Rather than duplicate it here, the shared secret is checked against what the client
             * computed from the opposite pair. */
            uint8_t client_shared[LC_X25519_SHARED];
            if (lc_x25519(reality_vec_client_private, reality_vec_server_public, client_shared) != 0)
                fail("the client-side exchange returned an error");
            else
                check_bytes("both ends agree on the shared secret", shared, client_shared, sizeof shared);
        }
    }

    /* ---- authenticating the server ---- */
    if (lc_reality_verify_cert(reality_vec_auth_key,
                               reality_vec_cert_public, SZ(reality_vec_cert_public),
                               reality_vec_cert_signature, SZ(reality_vec_cert_signature)) != 0)
        fail("a genuine REALITY certificate did not authenticate");
    else
        ok("server certificate authenticates");

    /* A wrong key must fail. This is the branch that decides whether we are talking to our server
     * or to the site it hides behind, so it gets its own check rather than being assumed. */
    {
        uint8_t wrong[LC_REALITY_AUTH_KEY];
        memcpy(wrong, reality_vec_auth_key, sizeof wrong);
        wrong[0] ^= 0x01u;
        if (lc_reality_verify_cert(wrong, reality_vec_cert_public, SZ(reality_vec_cert_public),
                                   reality_vec_cert_signature, SZ(reality_vec_cert_signature)) == 0)
            fail("a wrong authentication key still authenticated the certificate");
        else
            ok("wrong authentication key rejected");

        static uint8_t bad_sig[SZ(reality_vec_cert_signature)];
        memcpy(bad_sig, reality_vec_cert_signature, sizeof bad_sig);
        bad_sig[63] ^= 0x01u;
        if (lc_reality_verify_cert(reality_vec_auth_key,
                                   reality_vec_cert_public, SZ(reality_vec_cert_public),
                                   bad_sig, sizeof bad_sig) == 0)
            fail("a tampered signature still authenticated");
        else
            ok("tampered signature rejected");
    }

    /* ---- what must change the stamp ---- */
    /* Each of these is a field the server reads out of the sealed payload or checks the tag
     * against. If any of them could change without changing the output, it would not be
     * authenticated at all. */
    {
        static uint8_t again[SZ(reality_vec_hello_stamped)];
        uint8_t        key2[LC_REALITY_AUTH_KEY];

        struct {
            const char *what;
            int         which;
        } cases[] = {
            { "a different short id changes the stamp", 0 },
            { "a different timestamp changes the stamp", 1 },
            { "a different version changes the stamp", 2 },
            { "a single changed byte elsewhere in the hello changes the stamp", 3 },
        };

        for (size_t i = 0; i < SZ(cases); i++) {
            memcpy(again, reality_vec_hello_stamped, sizeof again);
            lc_reality_config c2 = config();
            uint32_t          t = REALITY_VEC_TIME;

            switch (cases[i].which) {
            case 0: c2.short_id[7] ^= 0x01u; break;
            case 1: t += 1u; break;
            case 2: c2.version[2] += 1u; break;
            case 3: again[100] ^= 0x01u; break;
            default: break;
            }

            if (lc_reality_stamp(again, sizeof again, REALITY_VEC_SID_OFF, &c2,
                                 reality_vec_client_private, t, key2) != 0) {
                fail(cases[i].what);
                continue;
            }
            if (memcmp(again + REALITY_VEC_SID_OFF, reality_vec_hello_stamped + REALITY_VEC_SID_OFF,
                       LC_REALITY_SESSION_ID) == 0)
                fail(cases[i].what);
            else
                ok(cases[i].what);
        }
    }

    /* ---- refusing what cannot be stamped ---- */
    {
        static uint8_t small[32];
        uint8_t        key3[LC_REALITY_AUTH_KEY];
        if (lc_reality_stamp(small, sizeof small, REALITY_VEC_SID_OFF, &cfg,
                             reality_vec_client_private, REALITY_VEC_TIME, key3) == 0)
            fail("a hello too short to hold session_id was stamped anyway");
        else
            ok("hello too short refused");

        if (lc_reality_stamp(hello, sizeof hello, 4u, &cfg,
                             reality_vec_client_private, REALITY_VEC_TIME, key3) == 0)
            fail("a session_id offset with no room for the random was accepted");
        else
            ok("impossible session_id offset refused");
    }

    printf("\n%s\n", failures == 0 ? "REALITY matches the reference" : "REALITY IS WRONG");
    return failures == 0 ? 0 : 1;
}
