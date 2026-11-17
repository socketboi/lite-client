/* GHASH, the authentication half of AES-GCM — the reference's own algorithm, ported line for line.
 *
 * WHICH REFERENCE, AND WHY THIS ONE. The client this replaces on a router is Xray, which is Go, and on
 * mipsle Go has no assembly for GCM: gcm_noasm.go routes it to the generic code in
 * crypto/internal/fips140/aes/gcm/ghash.go, a 4-bit table of multiples of H (Shoup's method) with a
 * sixteen-entry reduction table. That file is what this one is — the same table, built the same way
 * (per call, from H, in bit-reversed order), the same multiply, the same handling of a short last
 * block. Names follow it: productTable, ghashDouble, ghashAdd, ghashMul, ghashUpdate.
 *
 * WHAT IT REPLACED, AND WHAT IT COST. BearSSL's br_ghash_ctmul, a constant-time multiply built from
 * 32-bit products. A sampling profile of the live REALITY tunnel on the MT7621 (2026-09-21) put it
 * at 51.6 % of the core, against 26.6 % for the AES itself; on that CPU it costs 172 ms per MB where
 * this costs 88, and both give the same answer on 2000 random inputs.
 *
 * ⚠️ AND WHAT THE REFERENCE'S ALGORITHM GIVES UP, stated rather than hidden. A table indexed by bits
 * of the value being multiplied is not constant-time: which entries are read depends on the data,
 * and a cache that can be observed can in principle leak it. Go accepts that on every platform it has
 * no assembly for, which is where Xray runs on these routers; the maintainer chose the reference's
 * algorithm with that stated (2026-09-21).
 *
 * AND WHERE GO DOES HAVE ASSEMBLY, SO DOES THIS (2026-09-22). On aarch64 with the AES and PMULL
 * extensions — Go's own condition, gcm_asm.go:34-35 — the multiply is the carry-less instruction
 * instead of the table, which is also constant-time. Chosen at run time from the CPU's hwcaps, so one
 * binary is right on every arm64 box: a Cortex-A53 with the crypto extension takes PMULL, a core
 * without it (a Raspberry Pi 4's A72, for one) takes the table. MIPS, x86 and 32-bit ARM never
 * compile the PMULL path at all. On the AX3000T it took AES-128-GCM from 334 to 1 185 Mbit/s one way;
 * see ghash.c for the measurement that asked for it.
 *
 * x86-64 with AES, PCLMULQDQ, SSE4.1 and SSSE3 now takes carry-less multiplication too,
 * under Go 1.27's supportsAESGCM condition. Its one-block intrinsics are derived from
 * the pinned mbedTLS aesni.c, rather than Go's interleaved assembly. Neither the CPU
 * selection nor its instructions change the TLS cipher list or wire bytes. */
#ifndef LC_TLS_GHASH_H
#define LC_TLS_GHASH_H

#include <stddef.h>
#include <stdint.h>

#define LC_GHASH_BLOCK 16u

/* GHASH_H over each input in turn, each zero-padded to a block boundary, starting from zero —
 * `ghash(out, H, inputs...)`. Up to three inputs, which is what GCM hands it: the additional data,
 * the ciphertext and the lengths block. A NULL input with zero length is skipped. */
void lc_ghash(uint8_t out[LC_GHASH_BLOCK], const uint8_t h[LC_GHASH_BLOCK],
              const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len,
              const uint8_t *c, size_t c_len);

/* Which lc_ghash takes on this CPU: "pclmul", "pmull" or "generic". For the gate, which has to know
 * that the arm64 run it made under qemu went down the path an arm64 router takes — a test that passes
 * on the other path proves nothing about this one. */
const char *lc_ghash_name(void);

/* AES in GCM's counter mode on the ARMv8 crypto extension, taken under the same condition as the
 * PMULL GHASH — see ghash.c. Kept here beside it because it is the other half of the same GCM and
 * is compiled the same way. The round keys, 11 for AES-128 and 15 for AES-256. */
typedef struct {
    uint8_t  rk[15][16];
    unsigned rounds; /* 0 when this CPU takes mbedTLS's AES instead */
} lc_aes_hw;

/* 0 when this CPU has the extension and the key is 16 or 32 bytes; -1 otherwise, and the caller
 * keeps its own AES. */
int lc_aes_hw_init(lc_aes_hw *k, const uint8_t *key, size_t key_len);

/* `len` bytes of `in` xored with the keystream from counter block `block` on, the last thirty-two
 * bits of which advance by one per block (GCM's inc32). In place is allowed. */
void lc_aes_hw_ctr32(const lc_aes_hw *k, const uint8_t block[LC_GHASH_BLOCK], const uint8_t *in,
                     size_t len, uint8_t *out);

/* Which counter mode lc_aead takes on this CPU: "aese" or "mbedtls". */
const char *lc_aes_ctr_name(void);

#endif
