/* Header protection: the five bytes that hide the packet number.
 *
 * This function had no test at all, which is worse than it sounds. Every packet this client sends
 * and every packet it receives goes through it, and it is the FIRST thing that runs on a QUIC
 * packet — a wrong mask makes a packet whose number the peer cannot recover, so the peer drops it
 * without a word. There is no error code for that anywhere: the handshake simply never completes
 * and the log says the path went silent. That failure is indistinguishable, from inside this
 * client, from a node that is being blocked.
 *
 * The gap was found the way these things usually are: a change to this function was made, the whole
 * 579-check suite stayed green, and only then did anyone ask what the suite had actually verified
 * about it. Nothing. It compiled.
 *
 * So the vectors are RFC 9001's own — Appendix A.2 (client Initial), A.3 (server Initial) and A.5
 * (ChaCha20), the same numbers every other QUIC implementation is checked against. Being wrong here
 * in the same way as everyone else is impossible; being wrong alone is what this catches.
 *
 * The last case is the one that belongs to this tree rather than to the RFC: the mask must not
 * depend on how many times the context has been used before. AES header protection keeps an
 * expanded key schedule now instead of rebuilding it per call, and the failure mode of getting that
 * wrong is a context that works once and then drifts — which the RFC vectors, each run against a
 * fresh context, would never notice. */

#include "quic/qcrypto.c"

#include <stdio.h>
#include <string.h>

static int failures;

static void expect(int cond, const char *what)
{
    if (cond) {
        printf("  ok    %s\n", what);
        return;
    }
    printf("  FAIL  %s\n", what);
    failures++;
}

/* Vectors are written the way the RFC prints them, so they can be compared against it by eye.
 *
 * The length is checked rather than trusted: a vector transcribed one byte short makes this read
 * past the end of a string literal, and what it finds there is whatever the linker put next — which
 * is stable enough that the test then fails identically every run and looks exactly like a broken
 * implementation. That is not a hypothetical; it is how the ChaCha20 key below was first written,
 * with the RFC's second line dropped. */
static void unhex(const char *hex, uint8_t *out, size_t outlen)
{
    if (strlen(hex) != outlen * 2) {
        printf("  FAIL  a vector is %zu hex chars where %zu were wanted: %s\n", strlen(hex),
               outlen * 2, hex);
        failures++;
        memset(out, 0, outlen);
        return;
    }
    for (size_t i = 0; i < outlen; i++) {
        unsigned byte = 0;
        sscanf(hex + i * 2, "%2x", &byte);
        out[i] = (uint8_t)byte;
    }
}

/* Builds the context the way conn.c does: the algorithm travels inside native_handle. */
static int hp_init(ngtcp2_crypto_cipher_ctx *ctx, lc_aead_alg alg, const char *key_hex)
{
    ngtcp2_crypto_cipher cipher;
    cipher.native_handle = AS_HANDLE(alg);

    uint8_t key[32];
    unhex(key_hex, key, lc_aead_key_len(alg));

    return ngtcp2_crypto_cipher_ctx_encrypt_init(ctx, &cipher, key);
}

static void check_vector(const char *label, lc_aead_alg alg, const char *key_hex,
                         const char *sample_hex, const char *mask_hex)
{
    ngtcp2_crypto_cipher_ctx ctx;
    memset(&ctx, 0, sizeof ctx);

    if (hp_init(&ctx, alg, key_hex) != 0) {
        printf("  FAIL  %s — the context would not initialise\n", label);
        failures++;
        return;
    }

    uint8_t sample[16], want[5], got[5];
    unhex(sample_hex, sample, sizeof sample);
    unhex(mask_hex, want, sizeof want);
    memset(got, 0, sizeof got);

    int rc = ngtcp2_crypto_hp_mask(got, NULL, &ctx, sample);
    expect(rc == 0 && memcmp(got, want, sizeof got) == 0, label);

    ngtcp2_crypto_cipher_ctx_free(&ctx);
}

int main(void)
{
    printf("\nheader protection: RFC 9001 vectors\n\n");

    /* A.2 — the client's Initial packet. */
    check_vector("AES-128: the client Initial mask is 437b9aec36", LC_AEAD_AES_128_GCM,
                 "9f50449e04a0e810283a1e9933adedd2", "d1b1c98dd7689fb8ec11d242b123dc9b",
                 "437b9aec36");

    /* A.3 — the server's Initial packet, a different key against the same code path. */
    check_vector("AES-128: the server Initial mask is 2ec0d8356a", LC_AEAD_AES_128_GCM,
                 "c206b8d9b9f0f37644430b490eeaa314", "2cd0991cd25b0aac406a5816b6394100",
                 "2ec0d8356a");

    /* A.5 — ChaCha20, which shares nothing with the branch above except its caller. */
    check_vector("ChaCha20: the mask is aefefe7d03", LC_AEAD_CHACHA20_POLY1305,
                 "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4",
                 "5e5cd55c41f69080575d7999c25a5bfb", "aefefe7d03");

    printf("\nheader protection: a context is good for the whole key phase\n\n");

    /* One context, many packets — which is how it is actually used: ngtcp2 installs the key once
     * per encryption level and then calls this for every packet at that level. */
    {
        ngtcp2_crypto_cipher_ctx ctx;
        memset(&ctx, 0, sizeof ctx);
        expect(hp_init(&ctx, LC_AEAD_AES_128_GCM, "9f50449e04a0e810283a1e9933adedd2") == 0,
               "the context initialises");

        uint8_t sample[16], want[5];
        unhex("d1b1c98dd7689fb8ec11d242b123dc9b", sample, sizeof sample);
        unhex("437b9aec36", want, sizeof want);

        int stable = 1;
        for (int i = 0; i < 1000; i++) {
            uint8_t got[5];
            if (ngtcp2_crypto_hp_mask(got, NULL, &ctx, sample) != 0 ||
                memcmp(got, want, sizeof got) != 0) {
                stable = 0;
                break;
            }
        }
        expect(stable, "a thousand packets later the same sample still gives the same mask");

        /* Interleaving samples, because a stored schedule that some call quietly overwrote would
         * survive the loop above and fail here. */
        uint8_t other[16], other_want[5], got[5];
        unhex("2cd0991cd25b0aac406a5816b6394100", other, sizeof other);
        ngtcp2_crypto_hp_mask(other_want, NULL, &ctx, other);
        ngtcp2_crypto_hp_mask(got, NULL, &ctx, sample);
        expect(memcmp(got, want, sizeof got) == 0,
               "and a different sample in between does not disturb it");
        ngtcp2_crypto_hp_mask(got, NULL, &ctx, other);
        expect(memcmp(got, other_want, sizeof got) == 0, "nor the other way round");

        ngtcp2_crypto_cipher_ctx_free(&ctx);
        expect(ctx.native_handle == NULL, "and freeing it clears the handle");
    }

    printf("\n%s\n", failures == 0 ? "all good" : "FAILURES");
    return failures != 0;
}
