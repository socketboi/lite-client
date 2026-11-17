#include "core/ubidi.h"

#include "core/gotext.h"

#include "unitables_bidi.h"

/* bidi.LookupString (GOROOT/src/vendor/golang.org/x/text/unicode/bidi/prop.go) — the []byte Lookup
 * is the same code: the Properties' two bytes, the entry and — for a three-byte rune — its last
 * byte, and the width. Every block of this trie is stored whole. */
static void bidi_lookup(const uint8_t *s, size_t n, uint8_t *entry, uint8_t *last, size_t *sz)
{
    uint8_t c0 = s[0];
    size_t  need = c0 < 0x80u ? 1u : c0 < 0xc2u ? 0u : c0 < 0xe0u ? 2u : c0 < 0xf0u ? 3u : c0 < 0xf8u ? 4u : 0u;
    *entry = *last = 0;
    *sz = 1;
    if (c0 < 0x80u) {
        *entry = bidi_values[c0];
        return;
    }
    if (need == 0u)
        return; /* Properties{}, 1 */
    if (n < need) {
        *sz = 0;
        return;
    }
    uint32_t i = bidi_index[c0];
    for (size_t k = 1; k < need; k++) {
        if (s[k] < 0x80u || s[k] >= 0xc0u)
            return; /* Properties{}, 1 however far it got */
        if (k + 1u < need)
            i = bidi_index[(i << 6) + s[k]];
    }
    *entry = bidi_values[(i << 6) + s[need - 1u]];
    if (need == 3u)
        *last = s[2];
    *sz = need;
}

/* Properties.Class: the entry's class, and for the controls the last byte's. */
unsigned lc_bidi_class(const char *str, size_t n, size_t *sz)
{
    uint8_t entry, last;
    bidi_lookup((const uint8_t *)str, n, &entry, &last, sz);
    unsigned c = entry & 0x0fu;
    if (c == LC_BIDI_CONTROL) {
        /* controlByteToClass */
        static const uint8_t control[16] = {
            [0xd] = LC_BIDI_LRO, [0xe] = LC_BIDI_RLO, [0xa] = LC_BIDI_LRE,
            [0xb] = LC_BIDI_RLE, [0xc] = LC_BIDI_PDF, [0x6] = LC_BIDI_LRI,
            [0x7] = LC_BIDI_RLI, [0x8] = LC_BIDI_FSI, [0x9] = LC_BIDI_PDI,
        };
        c = control[last & 0xfu];
    }
    return c;
}

/* ---- bidirule (GOROOT/src/vendor/golang.org/x/text/secure/bidirule) ------------------------------ */

enum { RULE_INITIAL, RULE_LTR, RULE_LTR_FINAL, RULE_RTL, RULE_RTL_FINAL, RULE_INVALID };

#define B(c) (1u << (c))

static const struct {
    uint8_t  next;
    uint16_t mask;
} transitions[6][2] = {
    [RULE_INITIAL] = { { RULE_LTR_FINAL, B(LC_BIDI_L) }, { RULE_RTL_FINAL, B(LC_BIDI_R) | B(LC_BIDI_AL) } },
    [RULE_RTL] = { { RULE_RTL_FINAL, B(LC_BIDI_R) | B(LC_BIDI_AL) | B(LC_BIDI_EN) | B(LC_BIDI_AN) },
                   { RULE_RTL, B(LC_BIDI_ES) | B(LC_BIDI_CS) | B(LC_BIDI_ET) | B(LC_BIDI_ON) |
                                   B(LC_BIDI_BN) | B(LC_BIDI_NSM) } },
    [RULE_RTL_FINAL] = { { RULE_RTL_FINAL, B(LC_BIDI_R) | B(LC_BIDI_AL) | B(LC_BIDI_EN) | B(LC_BIDI_AN) |
                                               B(LC_BIDI_NSM) },
                         { RULE_RTL, B(LC_BIDI_ES) | B(LC_BIDI_CS) | B(LC_BIDI_ET) | B(LC_BIDI_ON) |
                                         B(LC_BIDI_BN) } },
    [RULE_LTR] = { { RULE_LTR_FINAL, B(LC_BIDI_L) | B(LC_BIDI_EN) },
                   { RULE_LTR, B(LC_BIDI_ES) | B(LC_BIDI_CS) | B(LC_BIDI_ET) | B(LC_BIDI_ON) |
                                   B(LC_BIDI_BN) | B(LC_BIDI_NSM) } },
    [RULE_LTR_FINAL] = { { RULE_LTR_FINAL, B(LC_BIDI_L) | B(LC_BIDI_EN) | B(LC_BIDI_NSM) },
                         { RULE_LTR, B(LC_BIDI_ES) | B(LC_BIDI_CS) | B(LC_BIDI_ET) | B(LC_BIDI_ON) |
                                         B(LC_BIDI_BN) } },
    [RULE_INVALID] = { { RULE_INVALID, 0 }, { RULE_INVALID, 0 } },
};

#define EXCLUSIVE_RTL (B(LC_BIDI_EN) | B(LC_BIDI_AN))
#define IS_RTL        (B(LC_BIDI_R) | B(LC_BIDI_AL) | B(LC_BIDI_AN))

int lc_bidirule_valid(const char *str, size_t len)
{
    /* ValidString: advanceString over the whole string, then isFinal. */
    unsigned state = RULE_INITIAL;
    uint16_t seen = 0;
    for (size_t n = 0; n < len;) {
        size_t   sz;
        unsigned cls = lc_bidi_class(str + n, len - n, &sz);
        if ((uint8_t)str[n] >= 0x80u && sz <= 1u)
            return 0; /* invalid UTF-8, or incomplete: n short of the end either way */
        /* uint16(1 << e.Class()): the classes past fifteen shift out of it */
        uint16_t c = (uint16_t)(cls < 16u ? 1u << cls : 0u);
        seen |= c;
        if ((seen & EXCLUSIVE_RTL) == EXCLUSIVE_RTL)
            return 0;
        if ((transitions[state][0].mask & c) != 0u) {
            state = transitions[state][0].next;
        } else if ((transitions[state][1].mask & c) != 0u) {
            state = transitions[state][1].next;
        } else {
            state = RULE_INVALID;
            if ((seen & IS_RTL) != 0u)
                return 0;
        }
        n += sz;
    }
    return state == RULE_LTR_FINAL || state == RULE_RTL_FINAL || state == RULE_INITIAL;
}

int lc_bidirule_rtl(const char *str, size_t len)
{
    for (size_t i = 0; i < len;) {
        size_t   sz;
        unsigned c = lc_bidi_class(str + i, len - i, &sz);
        if (sz == 0u) {
            i++;
            continue;
        }
        if (c == LC_BIDI_R || c == LC_BIDI_AL || c == LC_BIDI_AN)
            return 1;
        i += sz;
    }
    return 0;
}
