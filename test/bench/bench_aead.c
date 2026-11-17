/* What the three TLS 1.3 cipher suites cost on the machine this actually runs on.
 *
 * The question is not academic on a router: MIPS has no AES instructions, so the suite the server
 * happens to choose decides how much of the processor a tunnel spends on being a tunnel. The client
 * cannot choose — the list it offers is the browser fingerprint it is imitating, and reordering it
 * is exactly what REALITY exists to prevent — so the lever, if there is one worth pulling, is on
 * the node. This says whether there is.
 *
 * Measured through lc_aead, which is the same code the record layer uses, in record-sized pieces,
 * because a benchmark over one huge buffer measures a case that never happens here. */

#include "tls/aead.h"

#include <mbedtls/cipher.h>

#include <stdio.h>
#include <string.h>
#include <time.h>

/* A TLS record's worth. Everything this client encrypts is at most this.
 *
 * OVERRIDABLE, because the largest record is not the record this client mostly seals. The note in
 * src/tls/aead.h compares a profile of the live tunnel — 5628 ms of AEAD per 20 MB, which is
 * 28.4 Mbit/s — against this bench's figure and calls the bench "a kinder case", on the grounds that
 * real records average 8143 bytes and arrive cold while this loop is hot and full-sized. That was
 * never checked at the smaller size, because the size was a constant here. Now:
 *
 *     make … EXTRA_CFLAGS=-DCHUNK=8143u   …/bench-aead
 *
 * and the two cases can be compared instead of asserted. EXTRA_CFLAGS reaches THIS file because the
 * bench-aead rule passes it to the harness compile as well; it is appended to $(CFLAGS), which is
 * what the other two objects in that rule are built with, and the harness is the only one that
 * reads CHUNK.
 *
 * ⚠️ AND THE ANSWER, so that nobody runs it again to find out: the size does not matter here. On the
 * target router, AES-128-GCM costs 443 ms per megabyte at 8143 bytes against 442 at 16 KB, and
 * ChaCha20-Poly1305 is slightly cheaper small (89 against 93). Whatever makes the live tunnel's AEAD
 * slower than this loop, it is not the length of a record. */
#ifndef CHUNK
#define CHUNK 16384u
#endif
#define TOTAL_MB 8u

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static int run(const char *name, lc_aead_alg alg)
{
    uint8_t key[32];
    memset(key, 0x5a, sizeof key);

    lc_aead a;
    if (lc_aead_init(&a, alg, key) != 0) {
        printf("  %-22s NOT SUPPORTED by this build of mbedtls\n", name);
        return -1;
    }

    static uint8_t pt[CHUNK];
    static uint8_t ct[CHUNK + LC_AEAD_TAG];
    memset(pt, 0x33, sizeof pt);

    uint8_t nonce[LC_AEAD_NONCE];
    memset(nonce, 0, sizeof nonce);
    const uint8_t aad[5] = { 0x17, 0x03, 0x03, 0x40, 0x00 };

    unsigned rounds = TOTAL_MB * 1024u * 1024u / CHUNK;
    size_t   out_len = 0;

    uint64_t t0 = now_ms();
    for (unsigned i = 0; i < rounds; i++) {
        nonce[11] = (uint8_t)i;
        if (lc_aead_seal(&a, nonce, aad, sizeof aad, pt, sizeof pt, ct, sizeof ct, &out_len) != 0) {
            printf("  %-22s FAILED on round %u\n", name, i);
            lc_aead_free(&a);
            return -1;
        }
    }
    uint64_t seal_ms = now_ms() - t0;

    /* ⚠️ THE NONCE THAT SEALED WHAT `ct` HOLDS, and the result checked. This loop used to open the
     * one record left in `ct` — the last round's — under nonce 0, 1, 2… and throw the answer away,
     * so every round but the last failed its tag. gcm_open authenticates before it decrypts, which
     * made a failure cost GHASH alone: the "open" column was GHASH without the counter mode, 173 ms
     * per megabyte against a true 265 on the target router (2026-09-21), and "decryption only,
     * 46 Mbit/s" was quoted as that box's ceiling for a year of arguments about speed. It is about
     * 30. Found by a sampling profile of the live tunnel, whose GHASH alone cost what this bench
     * said the whole decryption did. The same record is opened every round; for a speed that is
     * fine, and it is the only record whose tag is right. */
    const uint8_t last = (uint8_t)(rounds - 1u);
    size_t        ct_len = out_len;
    t0 = now_ms();
    for (unsigned i = 0; i < rounds; i++) {
        nonce[11] = last;
        size_t pt_len = 0;
        if (lc_aead_open(&a, nonce, aad, sizeof aad, ct, ct_len, pt, sizeof pt, &pt_len) != 0) {
            printf("  %-22s open FAILED on round %u — the number below would not be a decryption\n",
                   name, i);
            lc_aead_free(&a);
            return -1;
        }
    }
    uint64_t open_ms = now_ms() - t0;

    lc_aead_free(&a);

    uint64_t both = seal_ms + open_ms;
    printf("  %-22s seal %4llu ms, open %4llu ms, per megabyte %5llu ms, %4llu Mbit/s\n",
           name, (unsigned long long)seal_ms, (unsigned long long)open_ms,
           (unsigned long long)(both / TOTAL_MB),
           both == 0 ? 0ull : (unsigned long long)(TOTAL_MB * 8u * 1000u / both));
    return 0;
}

/* THE SAME CIPHER WITHOUT THE AUTHENTICATION, which is what turns the line above from a number into
 * an explanation.
 *
 * CTR is AES-GCM's own encrypting half: identical key schedule, identical block function, no GHASH.
 * So GCM minus CTR is what the authentication costs, and the subtraction checks itself — GHASH does
 * not depend on the key length, so the figure taken from the 128-bit pair and the one taken from the
 * 256-bit pair have to agree. Measured 2026-08-26 they agreed to 0.3%, which is the whole reason to
 * trust what they say: on this processor GHASH is 82% of AES-GCM, and the AES is not the problem.
 *
 * Timed one way only. Encrypting and decrypting cost the same here and the point of this arm is the
 * difference against the line above, not a second throughput figure. */
static void run_raw(const char *name, mbedtls_cipher_type_t type, unsigned keybits)
{
    mbedtls_cipher_context_t c;
    mbedtls_cipher_init(&c);

    const mbedtls_cipher_info_t *info = mbedtls_cipher_info_from_type(type);
    uint8_t                      key[32];
    memset(key, 0x5a, sizeof key);
    if (info == NULL || mbedtls_cipher_setup(&c, info) != 0 ||
        mbedtls_cipher_setkey(&c, key, (int)keybits, MBEDTLS_ENCRYPT) != 0) {
        printf("  %-22s NOT SUPPORTED by this build of mbedtls\n", name);
        mbedtls_cipher_free(&c);
        return;
    }

    static uint8_t pt[CHUNK];
    static uint8_t ct[CHUNK + LC_AEAD_TAG];
    memset(pt, 0x33, sizeof pt);

    /* ASKED FOR, NOT ASSUMED. A block cipher in CTR mode takes a sixteen-byte counter block and
     * ChaCha20 takes a twelve-byte nonce, and writing 16 for both is how this line first came out:
     * the AES arms ran and the ChaCha arm failed on round zero, which reads as "unsupported" and is
     * a wrong constant. */
    uint8_t iv[16];
    memset(iv, 0, sizeof iv);
    int    want_iv = mbedtls_cipher_get_iv_size(&c);
    size_t iv_len  = sizeof iv;
    if (want_iv > 0 && (size_t)want_iv <= sizeof iv)
        iv_len = (size_t)want_iv;

    unsigned rounds = TOTAL_MB * 1024u * 1024u / CHUNK;
    uint64_t t0 = now_ms();
    for (unsigned i = 0; i < rounds; i++) {
        size_t olen = 0;
        if (mbedtls_cipher_set_iv(&c, iv, iv_len) != 0 || mbedtls_cipher_reset(&c) != 0 ||
            mbedtls_cipher_update(&c, pt, CHUNK, ct, &olen) != 0) {
            printf("  %-22s FAILED on round %u\n", name, i);
            mbedtls_cipher_free(&c);
            return;
        }
    }
    uint64_t ms = now_ms() - t0;

    printf("  %-22s one way %4llu ms, %4llu Mbit/s\n", name, (unsigned long long)ms,
           ms == 0 ? 0ull : (unsigned long long)(TOTAL_MB * 8u * 1000u / ms));
    mbedtls_cipher_free(&c);
}

int main(void)
{
    printf("\nWhat the ciphers cost on this machine: %u MB through each, in %u-byte chunks\n"
           "(every line covers both directions, as the tunnel pays them)\n\n",
           TOTAL_MB, CHUNK);

    run("AES-128-GCM", LC_AEAD_AES_128_GCM);
    run("AES-256-GCM", LC_AEAD_AES_256_GCM);
    run("ChaCha20-Poly1305", LC_AEAD_CHACHA20_POLY1305);

    printf("\nAnd the same ciphers with the authentication taken away, so that the difference\n"
           "names what it costs. GCM minus CTR is GHASH, and the two must agree:\n\n");

    run_raw("AES-128-CTR", MBEDTLS_CIPHER_AES_128_CTR, 128u);
    run_raw("AES-256-CTR", MBEDTLS_CIPHER_AES_256_CTR, 256u);
    run_raw("ChaCha20", MBEDTLS_CIPHER_CHACHA20, 256u);

    printf("\nThe number that matters is \"per megabyte\": the tunnel pays it twice,\n"
           "once in each direction, and on this processor that is the ceiling on speed.\n");
    return 0;
}
