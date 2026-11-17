/* Bytes and runes as Go reads and writes them, for the ports of Go's text packages (core/idna.c,
 * core/unorm.c, core/ubidi.c): a growable buffer that remembers running out of memory, and
 * unicode/utf8's decoding and encoding with Go's answers for what is not UTF-8. */
#ifndef LC_GOTEXT_H
#define LC_GOTEXT_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char  *p;
    size_t n, cap;
    int    oom;
} lc_obuf;

static inline void lc_obuf_add(lc_obuf *b, const void *s, size_t n)
{
    if (b->oom)
        return;
    if (b->n + n + 1u > b->cap) {
        size_t cap = b->cap != 0u ? b->cap : 64u;
        while (cap < b->n + n + 1u)
            cap *= 2u;
        char *p = realloc(b->p, cap);
        if (p == NULL) {
            b->oom = 1;
            return;
        }
        b->p = p;
        b->cap = cap;
    }
    if (n != 0u)
        memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = '\0';
}

static inline void lc_obuf_byte(lc_obuf *b, uint8_t c)
{
    lc_obuf_add(b, &c, 1u);
}

#define LC_RUNE_ERROR 0xfffdu
#define LC_MAX_RUNE   0x10ffffu

/* utf8.DecodeRune (GOROOT/src/unicode/utf8/utf8.go): the rune and its width, which for a byte that
 * starts nothing valid — or a sequence cut short — is RuneError and 1. `range` over a string walks
 * the same way. `n` is at least 1. */
static inline size_t lc_go_rune(const uint8_t *s, size_t n, uint32_t *r)
{
    uint8_t c = s[0];
    if (c < 0x80u) {
        *r = c;
        return 1;
    }
    size_t   w;
    uint8_t  lo = 0x80u, hi = 0xbfu;
    uint32_t v;
    if (c >= 0xc2u && c <= 0xdfu) {
        w = 2;
        v = c & 0x1fu;
    } else if (c >= 0xe0u && c <= 0xefu) {
        w = 3;
        v = c & 0x0fu;
        if (c == 0xe0u)
            lo = 0xa0u;
        else if (c == 0xedu)
            hi = 0x9fu;
    } else if (c >= 0xf0u && c <= 0xf4u) {
        w = 4;
        v = c & 0x07u;
        if (c == 0xf0u)
            lo = 0x90u;
        else if (c == 0xf4u)
            hi = 0x8fu;
    } else {
        *r = LC_RUNE_ERROR;
        return 1;
    }
    if (n < w || s[1] < lo || s[1] > hi) {
        *r = LC_RUNE_ERROR;
        return 1;
    }
    v = v << 6 | (s[1] & 0x3fu);
    for (size_t i = 2; i < w; i++) {
        if (s[i] < 0x80u || s[i] > 0xbfu) {
            *r = LC_RUNE_ERROR;
            return 1;
        }
        v = v << 6 | (s[i] & 0x3fu);
    }
    *r = v;
    return w;
}

/* utf8.EncodeRune into `e`, its length returned — RuneError for a surrogate or a value past
 * MaxRune, as string(rune) and []rune-to-string write them. */
static inline size_t lc_go_encode(uint8_t *e, uint32_t r)
{
    if ((r >= 0xd800u && r <= 0xdfffu) || r > LC_MAX_RUNE)
        r = LC_RUNE_ERROR;
    if (r < 0x80u) {
        e[0] = (uint8_t)r;
        return 1;
    }
    if (r < 0x800u) {
        e[0] = (uint8_t)(0xc0u | r >> 6);
        e[1] = (uint8_t)(0x80u | (r & 0x3fu));
        return 2;
    }
    if (r < 0x10000u) {
        e[0] = (uint8_t)(0xe0u | r >> 12);
        e[1] = (uint8_t)(0x80u | (r >> 6 & 0x3fu));
        e[2] = (uint8_t)(0x80u | (r & 0x3fu));
        return 3;
    }
    e[0] = (uint8_t)(0xf0u | r >> 18);
    e[1] = (uint8_t)(0x80u | (r >> 12 & 0x3fu));
    e[2] = (uint8_t)(0x80u | (r >> 6 & 0x3fu));
    e[3] = (uint8_t)(0x80u | (r & 0x3fu));
    return 4;
}

static inline void lc_obuf_rune(lc_obuf *b, uint32_t r)
{
    uint8_t e[4];
    lc_obuf_add(b, e, lc_go_encode(e, r));
}

/* A block of a generated trie stored as ranges (x/text's triegen): the first entry of a block is
 * its header — the stride in `value`, the number of ranges in `lo` — and a byte outside every range
 * is 0. */
typedef struct {
    uint16_t value;
    uint8_t  lo, hi;
} lc_uni_range;

/* sparseBlocks.lookup (x/text's triegen, as in GOROOT/src/vendor/golang.org/x/net/idna/trie.go). */
static inline uint16_t lc_uni_sparse(const uint16_t *offset, const lc_uni_range *values, uint32_t n,
                                     uint8_t b)
{
    uint16_t off = offset[n];
    uint16_t lo = (uint16_t)(off + 1u), hi = (uint16_t)(lo + values[off].lo);
    while (lo < hi) {
        uint16_t m = (uint16_t)(lo + (hi - lo) / 2u);
        if (values[m].lo <= b && b <= values[m].hi)
            return (uint16_t)(values[m].value + (uint16_t)(b - values[m].lo) * values[off].value);
        if (b < values[m].lo)
            hi = m;
        else
            lo = (uint16_t)(m + 1u);
    }
    return 0;
}

#endif
