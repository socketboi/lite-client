/* ChaCha20, as the references compute it.
 *
 * Both planes that can negotiate ChaCha20-Poly1305 reach it through golang.org/x/crypto: quic-go
 * seals packets with chacha20poly1305.New and masks headers with chacha20.NewUnauthenticatedCipher
 * (vendor/quic-go/internal/handshake/cipher_suite.go, header_protector.go:116-121), and uTLS takes the
 * same package for TLS 1.3 records. The version hysteria's build resolves is x/crypto v0.54.0
 * (vendor/hysteria/app/go.mod:82), and this is its chacha20 package:
 *
 *   - the Cipher of chacha_generic.go — key, nonce and counter as words, a buffer of keystream that
 *     XORKeyStream draws from before it makes more, and SetCounter's rule for moving inside it;
 *   - xorKeyStreamBlocksGeneric, with the three counter-free quarter rounds of the first column
 *     round worked out once per cipher (p1..p15) — everywhere but arm64, with bufSize one block
 *     (chacha_noasm.go);
 *   - on arm64, xorKeyStreamVX from chacha_arm64.s: four blocks at once, one per lane of a NEON
 *     register, and bufSize four blocks. Go builds it for every arm64 target (`gc && !purego`,
 *     chacha_arm64.go) with no check of the processor, because Advanced SIMD is part of AArch64
 *     itself; so is this, by compiler target rather than at run time.
 *
 * The output is ChaCha20's and does not depend on the path — RFC 8439 is RFC 8439 — so what the
 * choice decides is what a packet costs: see the end of src/tls/aead.h for what it measured. */
#ifndef LC_TLS_CHACHA_H
#define LC_TLS_CHACHA_H

#include <stddef.h>
#include <stdint.h>

#define LC_CHACHA_KEY 32u
#define LC_CHACHA_NONCE 12u
#define LC_CHACHA_BLOCK 64u

/* bufSize: four blocks where the keystream is made four at a time, one elsewhere. */
#if defined(__aarch64__)
#define LC_CHACHA_BUF 256u
#else
#define LC_CHACHA_BUF 64u
#endif

typedef struct {
    uint32_t key[8];
    uint32_t counter;
    uint32_t nonce[3];

    uint8_t  buf[LC_CHACHA_BUF];
    size_t   len; /* keystream still unused at the END of buf */

    int      overflow;

    int      precomp_done;
    uint32_t p1, p5, p9, p13;
    uint32_t p2, p6, p10, p14;
    uint32_t p3, p7, p11, p15;
} lc_chacha;

/* NewUnauthenticatedCipher with a twelve-byte nonce. */
void lc_chacha_init(lc_chacha *c, const uint8_t key[LC_CHACHA_KEY], const uint8_t nonce[LC_CHACHA_NONCE]);

/* SetCounter. Returns -1 where Go panics — a counter moved backwards past what was already output. */
int lc_chacha_set_counter(lc_chacha *c, uint32_t counter);

/* XORKeyStream. In place is allowed. Returns -1 where Go panics — the 32-bit counter would wrap. */
int lc_chacha_xor(lc_chacha *c, uint8_t *dst, const uint8_t *src, size_t len);

/* "neon" or "generic": which path this build takes, for the tests to insist on. */
const char *lc_chacha_name(void);

#endif
