/* Append-only byte buffer over memory the caller owns.
 *
 * No allocation happens here, on purpose: this code runs on a router with 34 MB of usable RAM, and
 * a proxy that mallocs per packet is a proxy that fragments itself to death over a week of uptime.
 * The caller decides where the bytes live; this only appends into them.
 *
 * Overflow is sticky rather than fatal. Every write past the end sets err and becomes a no-op, so
 * the caller checks once at the end instead of after every field — and a truncated buffer can never
 * be mistaken for a complete one. */
#ifndef LC_BUF_H
#define LC_BUF_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *p;
    size_t   cap;
    size_t   len;
    int      err; /* set once a write did not fit; never cleared */
} lc_buf;

void lc_buf_init(lc_buf *b, uint8_t *mem, size_t cap);

void lc_buf_u8(lc_buf *b, uint8_t v);
void lc_buf_u16(lc_buf *b, uint16_t v); /* big-endian, as everything on the TLS wire */
void lc_buf_u24(lc_buf *b, uint32_t v); /* handshake length */
void lc_buf_write(lc_buf *b, const uint8_t *src, size_t n);
void lc_buf_zero(lc_buf *b, size_t n);

/* Reserve n bytes and return where they start, so the caller can fill them in place (random data,
 * a key). Returns NULL if they do not fit — and the buffer is marked failed. */
uint8_t *lc_buf_reserve(lc_buf *b, size_t n);

#endif
