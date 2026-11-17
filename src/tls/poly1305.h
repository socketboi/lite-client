/* Poly1305, as the references compute it where the machine lets that be fast.
 *
 * The references take it from golang.org/x/crypto/internal/poly1305 at v0.54.0, the version
 * hysteria's build resolves (vendor/hysteria/app/go.mod:82). On every processor this client runs on
 * that is sum_generic.go — assembly exists only for amd64, ppc64, s390x and loong64 — so on a machine
 * with a 64x64->128 multiply this is sum_generic.go: the accumulator in three 64-bit limbs and r in
 * two, each block a schoolbook multiply with the reduction folded into the carry (updateGeneric), the
 * final subtract of p chosen in constant time (finalize), and the sixteen-byte buffer macGeneric keeps
 * between writes. bits.Mul64, Add64 and Sub64 become the machine's own instructions there, and so
 * do they here, through unsigned __int128.
 *
 * ⚠️ AND WHERE THERE IS NO SUCH MULTIPLY IT IS mbedTLS's, WHICH IS A CHOICE AND IS STATED AS ONE. The
 * MIPS routers have no 128-bit product, and Go's generic form there emulates every 64-bit multiply
 * and carry in 32-bit halves: measured on the MT7621, 8 MB took 489 ms in this port of it against
 * 62 ms in the router's own mbedTLS, whose limbs are 32 bits wide. That is the whole of the
 * ChaCha20-Poly1305 that plane carried until 2026-09-23, so the Hysteria2 tunnel on those routers
 * would have lost more than half its cipher speed to follow a representation Go picked for 64-bit
 * machines. The tag is Poly1305's either way — the two agree on every input test/aead gives them —
 * so what the choice decides is the cost of a packet, not a byte on the wire. The same line is drawn
 * in src/tls/fe25519.h, for the same reason.
 *
 * LC_POLY1305_MBEDTLS forces the mbedTLS side on a host that has the product, so that the gate runs
 * what the MIPS routers run (test-aead-mbedpoly in the Makefile). */
#ifndef LC_TLS_POLY1305_H
#define LC_TLS_POLY1305_H

#include <stddef.h>
#include <stdint.h>

#define LC_POLY1305_KEY 32u
#define LC_POLY1305_TAG 16u

#if defined(__SIZEOF_INT128__) && !defined(LC_POLY1305_MBEDTLS)
#define LC_POLY1305_GO 1
typedef struct {
    uint64_t h[3];
    uint64_t r[2];
    uint64_t s[2];
    uint8_t  buffer[LC_POLY1305_TAG];
    size_t   offset;
} lc_poly1305;
#else
#include <mbedtls/poly1305.h>
typedef struct {
    mbedtls_poly1305_context ctx;
} lc_poly1305;
#endif

void lc_poly1305_init(lc_poly1305 *m, const uint8_t key[LC_POLY1305_KEY]);
void lc_poly1305_write(lc_poly1305 *m, const uint8_t *p, size_t len);
/* Finishes the MAC. Unlike Go's Sum, the MAC is spent afterwards: the AEAD never writes to one it has
 * summed, and mbedTLS's finish does not allow it. */
void lc_poly1305_sum(lc_poly1305 *m, uint8_t out[LC_POLY1305_TAG]);

/* "go" or "mbedtls": which of the two this build computes with, for the tests to report. */
const char *lc_poly1305_name(void);

#endif
