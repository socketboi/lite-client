#include "core/buf.h"

#include <string.h>

void lc_buf_init(lc_buf *b, uint8_t *mem, size_t cap)
{
    b->p = mem;
    b->cap = cap;
    b->len = 0;
    b->err = 0;
}

/* fits reports whether n more bytes go in, and marks the buffer failed if they do not. Every write
 * goes through it, which is why a single check of b->err at the end is enough. */
static int fits(lc_buf *b, size_t n)
{
    if (b->err)
        return 0;
    if (n > b->cap - b->len) {
        b->err = 1;
        return 0;
    }
    return 1;
}

void lc_buf_u8(lc_buf *b, uint8_t v)
{
    if (!fits(b, 1))
        return;
    b->p[b->len++] = v;
}

void lc_buf_u16(lc_buf *b, uint16_t v)
{
    if (!fits(b, 2))
        return;
    b->p[b->len++] = (uint8_t)(v >> 8);
    b->p[b->len++] = (uint8_t)v;
}

void lc_buf_u24(lc_buf *b, uint32_t v)
{
    if (!fits(b, 3))
        return;
    b->p[b->len++] = (uint8_t)(v >> 16);
    b->p[b->len++] = (uint8_t)(v >> 8);
    b->p[b->len++] = (uint8_t)v;
}

void lc_buf_write(lc_buf *b, const uint8_t *src, size_t n)
{
    if (!fits(b, n))
        return;
    memcpy(b->p + b->len, src, n);
    b->len += n;
}

void lc_buf_zero(lc_buf *b, size_t n)
{
    if (!fits(b, n))
        return;
    memset(b->p + b->len, 0, n);
    b->len += n;
}

uint8_t *lc_buf_reserve(lc_buf *b, size_t n)
{
    if (!fits(b, n))
        return NULL;
    uint8_t *at = b->p + b->len;
    b->len += n;
    return at;
}
