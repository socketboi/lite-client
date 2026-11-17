/* strconv.Quote and strconv.IsPrint (GOROOT/src/strconv/quote.go, go1.26.6). core/goprint.h is
 * that toolchain's isprint.go, its four tables turned into C by tools/goprint/gen.sh — go1.26.6's
 * and not go1.27's, which has newer Unicode, because the texts quoted here are hysteria's. */
#include "core/goquote.h"

#include "core/goprint.h"

static const char lowerhex[] = "0123456789abcdef";

/* bsearch (quote.go:495-507): the first index whose entry is not below v. */
static size_t search16(const uint16_t *s, size_t n, uint16_t v)
{
    size_t i = 0, j = n;
    while (i < j) {
        size_t h = i + ((j - i) >> 1);
        if (s[h] < v)
            i = h + 1u;
        else
            j = h;
    }
    return i;
}

static size_t search32(const uint32_t *s, size_t n, uint32_t v)
{
    size_t i = 0, j = n;
    while (i < j) {
        size_t h = i + ((j - i) >> 1);
        if (s[h] < v)
            i = h + 1u;
        else
            j = h;
    }
    return i;
}

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

/* IsPrint (quote.go:518-562). */
int lc_go_is_print(uint32_t r)
{
    if (r <= 0xffu) {
        if (r >= 0x20u && r <= 0x7eu)
            return 1;
        if (r >= 0xa1u && r <= 0xffu)
            return r != 0xadu;
        return 0;
    }
    if (r < 0x10000u) {
        uint16_t rr = (uint16_t)r;
        size_t   i = search16(go_is_print16, COUNT(go_is_print16), rr);
        if (i >= COUNT(go_is_print16) || rr < go_is_print16[i & ~(size_t)1] ||
            go_is_print16[i | 1u] < rr)
            return 0;
        size_t j = search16(go_is_not_print16, COUNT(go_is_not_print16), rr);
        return !(j < COUNT(go_is_not_print16) && go_is_not_print16[j] == rr);
    }
    size_t i = search32(go_is_print32, COUNT(go_is_print32), r);
    if (i >= COUNT(go_is_print32) || r < go_is_print32[i & ~(size_t)1] || go_is_print32[i | 1u] < r)
        return 0;
    if (r >= 0x20000u)
        return 1;
    uint16_t rr = (uint16_t)(r - 0x10000u);
    size_t   j = search16(go_is_not_print32, COUNT(go_is_not_print32), rr);
    return !(j < COUNT(go_is_not_print32) && go_is_not_print32[j] == rr);
}

/* appendEscapedRune (quote.go:64-119), with quote '"', neither ASCIIonly nor graphicOnly. */
static void escaped_rune(lc_obuf *b, uint32_t r)
{
    if (r == '"' || r == '\\') {
        lc_obuf_byte(b, '\\');
        lc_obuf_byte(b, (uint8_t)r);
        return;
    }
    if (lc_go_is_print(r)) {
        lc_obuf_rune(b, r);
        return;
    }
    const char *esc = NULL;
    switch (r) {
    case '\a': esc = "\\a"; break;
    case '\b': esc = "\\b"; break;
    case '\f': esc = "\\f"; break;
    case '\n': esc = "\\n"; break;
    case '\r': esc = "\\r"; break;
    case '\t': esc = "\\t"; break;
    case '\v': esc = "\\v"; break;
    default: break;
    }
    if (esc != NULL) {
        lc_obuf_add(b, esc, 2u);
        return;
    }
    char   out[10];
    size_t n = 0;
    if (r < ' ' || r == 0x7fu) {
        out[n++] = '\\';
        out[n++] = 'x';
        out[n++] = lowerhex[(r >> 4) & 0xfu];
        out[n++] = lowerhex[r & 0xfu];
    } else {
        if (r > LC_MAX_RUNE || (r >= 0xd800u && r <= 0xdfffu))
            r = LC_RUNE_ERROR; /* !utf8.ValidRune */
        if (r < 0x10000u) {
            out[n++] = '\\';
            out[n++] = 'u';
            for (int s = 12; s >= 0; s -= 4)
                out[n++] = lowerhex[(r >> s) & 0xfu];
        } else {
            out[n++] = '\\';
            out[n++] = 'U';
            for (int s = 28; s >= 0; s -= 4)
                out[n++] = lowerhex[(r >> s) & 0xfu];
        }
    }
    lc_obuf_add(b, out, n);
}

/* appendQuotedWith (quote.go:31-52). */
void lc_go_quote(lc_obuf *out, const uint8_t *s, size_t n)
{
    lc_obuf_byte(out, '"');
    size_t i = 0;
    while (i < n) {
        uint32_t r;
        size_t   w = lc_go_rune(s + i, n - i, &r);
        if (w == 1u && r == LC_RUNE_ERROR) {
            char x[4] = { '\\', 'x', lowerhex[s[i] >> 4], lowerhex[s[i] & 0xfu] };
            lc_obuf_add(out, x, 4u);
        } else {
            escaped_rune(out, r);
        }
        i += w;
    }
    lc_obuf_byte(out, '"');
}
