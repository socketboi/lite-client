/* What one REALITY handshake's asymmetric work costs on the machine this actually runs on.
 *
 * WHY THIS EXISTS. Measured on a live router 2026-08-25: sixty connections arriving at once made
 * lc-tunnel spend 25.05 seconds of processor for 25 seconds of wall clock — one core, saturated,
 * 24.63 of those seconds in userspace — and connections took 5 to 10 seconds to open. Nothing was
 * dropped, but a person waits those ten seconds. The same box doing an ordinary TLS 1.3 handshake
 * to the same node through curl and the system mbedTLS spends 92 ms of processor; ours spends 328.
 *
 * That is a 3.6× difference, and the obvious explanation — "the post-quantum group costs it" — is a
 * guess. There are two suspects and they are not the same size:
 *
 *   - X25519MLKEM768, which curl did not negotiate and we always do, because it is the group every
 *     current browser fingerprint offers first and offering anything else is identifiable.
 *   - X25519 itself, which mbedTLS computes through its GENERIC ECP ladder rather than a
 *     Curve25519-specific field implementation — and a REALITY handshake needs THREE scalar
 *     multiplications, not two: one to generate, one for the TLS exchange, and one more against the
 *     node's static key, which is how REALITY authenticates (see reality/reality.h).
 *
 * A number here settles which, and settling it is the difference between "this is the price of
 * looking like a browser" and "this is a library choice we can revisit".
 *
 * ⚠️ AND IT IS SETTLED: THE POST-QUANTUM GROUP IS NOT THE COST. Run on both boxes we ship to,
 * 20 rounds each, 2026-09-20 — the MT7621 column is the one that matters, since that is the router
 * whose connections took ten seconds:
 *
 *                                    Cortex-A53    MT7621        share of a handshake
 *     ML-KEM-768 keygen                 0.30 ms      1.36 ms
 *     ML-KEM-768 decapsulation          0.49         2.01         both together: 3 %
 *     X25519 keygen                     4.14        16.14
 *     X25519 scalar mult (one of 3)     4.17        16.46         three of them: 37 %
 *     lc_hybrid_keygen (the hello)      4.41        17.56
 *     lc_hybrid_shared (the reply)      4.66        18.50
 *     Ed25519 verify (ours, on mpi)    24.26        79.47         60 %
 *
 * ML-KEM is three milliseconds of about a hundred and thirty. The post-quantum group this client
 * offers because every browser fingerprint offers it first costs almost nothing; what cost was that
 * BOTH of the other two went through mbedTLS's generic bignum — X25519 through its generic ECP
 * ladder, and our Ed25519 verifier on mbedtls_mpi — instead of arithmetic written for 2^255-19. So
 * it was the second answer the paragraph above offers: a library choice, not the price of looking
 * like a browser.
 *
 * What that costs where it is felt: REALITY opens a tunnel per connection, so a page that makes
 * twenty of them pays about 1.6 seconds of Ed25519 alone on the MT7621. Read live on that box the
 * same day, carrying a household on REALITY: forty-four tunnels, not one of them opened in under
 * 250 ms, the worst 1221 ms — which is this table plus two round trips and nothing else.
 *
 * ⚠️ AND THEN IT WAS ACTED ON, SO THE TABLE ABOVE IS HISTORY. Three changes on 2026-09-20, all
 * measured on that same Xiaomi:
 *
 *                                       before       after
 *     Ed25519 verify (ours)             82.38        11.00    two changes, see below
 *     X25519 scalar mult (one of 3)     16.40         5.30    src/tls/x25519.c, its own field
 *     a whole handshake                134.7         30.2   the four rows above, added up
 *
 * ⚠️ AND IT WAS CHECKED LIVE, BECAUSE A BENCH MEASURES THE PART IT CHOSE TO MEASURE. The table
 * above is asymmetric work in isolation; what a person waits for is a whole REALITY handshake, and
 * most of that is the network. So lc-probe was built from this commit and from the commit before
 * any of these three changes, and the two were run ALTERNATELY on the Xiaomi against a live server,
 * twelve handshakes each, inside the same minute:
 *
 *                 min    median   worst    (milliseconds, whole handshake, same box, same node)
 *   before        409      510     1000
 *   after         280      360      780
 *
 * ICMP to that node is 92 ms, so two round trips are 184 ms of every one of those numbers and
 * nothing this client does can touch them. The 129 ms that came off the minimum and the 150 off the
 * median are close to the 106 ms the table predicts, and the rest is jitter — read the min, not the
 * worst: the three outliers above 800 ms in the "before" column are the path, not the processor.
 *
 * ALTERNATED, NOT RUN IN TWO BLOCKS, on purpose. A link to a server abroad is not the same thing
 * two minutes apart, and a block design would have measured that instead.
 *
 * Ed25519 took two steps. The first kept mbedtls_mpi and stopped paying a 510-bit fold for an
 * addition of two residues (src/tls/ed25519.c, fe_weak): 82.38 to 47.95. The second moved it off
 * mbedtls_mpi entirely onto the field written for X25519, once that field existed and was proved
 * against RFC 7748 and against mbedTLS itself: 47.95 to 11.00. So the field is shared by both
 * curves and is checked by both suites, which is the whole reason there is one copy of it.
 *
 * Measured through lc_hybrid and lc_x25519 — the same calls the handshake makes — rather than
 * through the primitives underneath, because the wrappers are what the connection pays for.
 *
 * Cross-compiled and run ON THE DEVICE, like bench-aead beside it; the answer on x86 is a different
 * question with a different answer.
 */

#include "tls/hybrid.h"
#include "tls/kex.h"
#include "tls/ed25519.h"
#include "tls/mlkem.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#define ROUNDS 20u

static uint64_t now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

static void say(const char *name, uint64_t total_us, unsigned rounds)
{
    printf("  %-40s %7.2f ms\n", name, (double)total_us / rounds / 1000.0);
}

int main(void)
{
    printf("\nwhat a handshake's asymmetric work costs here (%u rounds each)\n\n", ROUNDS);

    /* The two halves of the hybrid, separately, because the whole point is to tell them apart. */
    uint8_t  ek[LC_MLKEM_EK], dk[LC_MLKEM_DK], ss[LC_MLKEM_SS];
    uint64_t t0 = now_us();
    for (unsigned i = 0; i < ROUNDS; i++) {
        if (lc_mlkem_keygen(ek, dk) != 0) {
            printf("  ML-KEM keygen FAILED\n");
            return 1;
        }
    }
    say("ML-KEM-768 keygen", now_us() - t0, ROUNDS);

    /* Decapsulation takes any ciphertext-shaped buffer: FIPS 203 rejects implicitly, returning a
     * pseudo-random secret rather than an error, so a fixed buffer exercises the full cost. */
    uint8_t ct[LC_MLKEM_CT];
    memset(ct, 0x5a, sizeof ct);
    t0 = now_us();
    for (unsigned i = 0; i < ROUNDS; i++) {
        if (lc_mlkem_decap(ct, dk, ss) != 0) {
            printf("  ML-KEM decap FAILED\n");
            return 1;
        }
    }
    say("ML-KEM-768 decapsulation", now_us() - t0, ROUNDS);

    uint8_t priv[LC_X25519_KEY], pub[LC_X25519_KEY];
    t0 = now_us();
    for (unsigned i = 0; i < ROUNDS; i++) {
        if (lc_x25519_keygen(priv, pub) != 0) {
            printf("  X25519 keygen FAILED\n");
            return 1;
        }
    }
    say("X25519 keygen (our own field)", now_us() - t0, ROUNDS);

    uint8_t shared[LC_X25519_SHARED];
    t0 = now_us();
    for (unsigned i = 0; i < ROUNDS; i++) {
        if (lc_x25519(priv, pub, shared) != 0) {
            printf("  X25519 shared FAILED\n");
            return 1;
        }
    }
    say("X25519 scalar mult (one of THREE)", now_us() - t0, ROUNDS);

    /* And the two calls the handshake actually makes, so the sum above can be checked against
     * something rather than trusted. */
    lc_hybrid_key k;
    uint8_t       share[LC_HYBRID_SHARE];
    t0 = now_us();
    for (unsigned i = 0; i < ROUNDS; i++) {
        if (lc_hybrid_keygen(&k, share) != 0) {
            printf("  hybrid keygen FAILED\n");
            return 1;
        }
        lc_hybrid_key_free(&k);
    }
    say("lc_hybrid_keygen (what the hello costs)", now_us() - t0, ROUNDS);

    uint8_t peer[LC_HYBRID_CT], secret[LC_HYBRID_SECRET];
    memset(peer, 0x5a, sizeof peer);
    if (lc_hybrid_keygen(&k, share) != 0) {
        printf("  hybrid keygen FAILED\n");
        return 1;
    }
    t0 = now_us();
    for (unsigned i = 0; i < ROUNDS; i++) {
        if (lc_hybrid_shared(&k, peer, secret) != 0) {
            printf("  hybrid shared FAILED\n");
            return 1;
        }
    }
    say("lc_hybrid_shared (what the reply costs)", now_us() - t0, ROUNDS);
    lc_hybrid_key_free(&k);

    /* AND THE ONE THAT TURNED OUT TO BE THE ANSWER.
     *
     * A REALITY node holds an Ed25519 key, so its CertificateVerify is Ed25519 or nothing (see
     * tls/ed25519.h), and this client checks it on every connection. mbedTLS 3.6 has no Ed25519 at
     * all, so this is the one asymmetric primitive the tree implements itself — since 2026-09-20 on
     * the field in src/tls/fe25519.c, and before that on mbedtls_mpi, which is generic
     * arbitrary-precision arithmetic with no specialisation for this prime. Two scalar
     * multiplications is still the largest single number on this list, and it is what a person waits
     *
     * RFC 8032 §7.1 TEST 1 — the same vector test/ed25519 checks correctness against, so a change
     * that makes this faster and wrong fails there rather than passing here. */
    static const uint8_t ed_pub[LC_ED25519_PUBKEY] = {
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a
    };
    static const uint8_t ed_sig[LC_ED25519_SIG] = {
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82,
        0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49,
        0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c,
        0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43,
        0x8e, 0x7a, 0x10, 0x0b
    };
    t0 = now_us();
    for (unsigned i = 0; i < ROUNDS; i++) {
        if (lc_ed25519_verify(ed_pub, NULL, 0, ed_sig) != 0) {
            printf("  Ed25519 verify FAILED on a vector that must pass\n");
            return 1;
        }
    }
    say("Ed25519 verify (ours, own field)", now_us() - t0, ROUNDS);

    printf("\n");
    return 0;
}
