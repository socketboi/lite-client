/* core/unorm, core/ubidi and idna.Lookup in core/idna against GOROOT's own x/text and x/net/idna.
 *
 * tools/unitables folds what the real functions return into checksums: every table lookup a port
 * can make — every rune, and every malformed sequence of the shapes the tries tell apart — and
 * what NFC, QuickSpan, IsNormalString, the Bidi Rule and Lookup.ToASCII make of a hundred thousand
 * strings drawn from a pool of pieces by a generator this file runs the same way. A checksum says
 * only THAT something differs, so the first strings are there in full as well, to say what. */
#include "core/idna.c"
#include "core/ubidi.c"
#include "core/unorm.c"

#include "univec.h"

#include <stdio.h>

static int failures;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

/* FNV-1a, 64 bits, and a number as its eight little-endian bytes — the generator's. */
static void fnv(uint64_t *h, const void *p, size_t n)
{
    const uint8_t *b = p;
    for (size_t i = 0; i < n; i++) {
        *h ^= b[i];
        *h *= 1099511628211ull;
    }
}

static void fnv_num(uint64_t *h, uint64_t v)
{
    uint8_t b[8];
    for (unsigned i = 0; i < 8u; i++)
        b[i] = (uint8_t)(v >> (8u * i));
    fnv(h, b, sizeof b);
}

#define FNV_START 14695981039346656037ull

static uint64_t h_idna = FNV_START, h_nfc = FNV_START, h_bidi = FNV_START, h_props = FNV_START;
static unsigned sequences;

static void one(const uint8_t *s, size_t n)
{
    size_t   sz;
    uint16_t v = lookup(s, n, &sz);
    fnv_num(&h_idna, (uint64_t)v << 8 | sz);
    v = nfc_lookup(s, n, &sz);
    fnv_num(&h_nfc, (uint64_t)v << 8 | sz);
    props p = comp_info(v, sz);
    uint64_t f[7] = { p.pos, p.size, p.ccc, p.tccc, p.nlead, p.flags, p.index };
    for (unsigned i = 0; i < 7u; i++)
        fnv_num(&h_props, f[i]);
    uint8_t entry, last;
    bidi_lookup(s, n, &entry, &last, &sz);
    uint64_t b = (uint64_t)entry << 16 | (uint64_t)last << 8 | sz;
    fnv_num(&h_bidi, b); /* LookupString */
    fnv_num(&h_bidi, b); /* Lookup: the same code */
    sequences++;
}

/* The generator's sequences, in its order. */
static void all_sequences(void)
{
    uint8_t s[4];
    for (uint32_t r = 0; r <= 0x10ffffu; r++) {
        if (r >= 0xd800u && r <= 0xdfffu) {
            s[0] = (uint8_t)(0xe0u | r >> 12);
            s[1] = (uint8_t)(0x80u | (r >> 6 & 0x3fu));
            s[2] = (uint8_t)(0x80u | (r & 0x3fu));
            one(s, 3);
            continue;
        }
        one(s, lc_go_encode(s, r));
    }
    static const uint8_t edges[] = { 0x00, 0x41, 0x7f, 0x80, 0x9f, 0xa0, 0xbf, 0xc0, 0xff };
    for (unsigned c0 = 0x80; c0 <= 0xffu; c0++) {
        s[0] = (uint8_t)c0;
        one(s, 1);
        for (unsigned c1 = 0; c1 <= 0xffu; c1++) {
            s[1] = (uint8_t)c1;
            one(s, 2);
        }
        for (unsigned a = 0; a < sizeof edges; a++)
            for (unsigned b = 0; b < sizeof edges; b++) {
                s[1] = edges[a];
                s[2] = edges[b];
                one(s, 3);
                for (unsigned c = 0; c < sizeof edges; c++) {
                    s[3] = edges[c];
                    one(s, 4);
                }
            }
    }
}

/* splitmix64, the generator's. */
static uint64_t rng = UNIVEC_SEED;

static uint64_t next(void)
{
    rng += 0x9e3779b97f4a7c15ull;
    uint64_t z = rng;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}

static size_t draw(char *out)
{
    size_t   len = 0;
    unsigned n = (unsigned)(next() % 13u);
    uint64_t m = sizeof univec_pool / sizeof univec_pool[0];
    if ((next() & 1u) == 0u)
        m = UNIVEC_FRIENDLY;
    for (unsigned i = 0; i < n; i++) {
        uint64_t p = next() % m;
        memcpy(out + len, univec_pool[p], univec_pool_len[p]);
        len += univec_pool_len[p];
    }
    return len;
}

static const char *show(const char *s, size_t n)
{
    static char buf[1024];
    size_t      o = 0;
    for (size_t i = 0; i < n && o + 5u < sizeof buf; i++) {
        uint8_t c = (uint8_t)s[i];
        if (c >= 0x20u && c < 0x7fu)
            buf[o++] = (char)c;
        else
            o += (size_t)snprintf(buf + o, sizeof buf - o, "\\x%02x", c);
    }
    buf[o] = '\0';
    return buf;
}

int main(void)
{
    printf("unicode: every lookup of the three tries, against GOROOT's x/text and x/net/idna\n");
    all_sequences();
    ok(sequences == UNIVEC_SEQUENCES, "the same sequences as the generator's");
    ok(h_idna == UNIVEC_IDNA_TRIE, "the UTS #46 trie, on every rune and every malformed shape");
    ok(h_nfc == UNIVEC_NFC_TRIE, "the NFC trie, the same");
    ok(h_bidi == UNIVEC_BIDI_TRIE, "the bidi trie, the same");
    ok(h_props == UNIVEC_NFC_PROPS, "and what compInfo makes of every NFC value");

    /* Every rune in four places through Lookup, and in two through NFC — see tools/unitables. */
    {
        uint64_t hl = FNV_START, hn = FNV_START;
        unsigned errs = 0;
        int      mem = 0;
        for (uint32_t r = 0; r <= 0x10ffffu && !mem; r++) {
            if (r >= 0xd800u && r <= 0xdfffu)
                continue;
            uint8_t c[4];
            size_t  cn = lc_go_encode(c, r);
            char    s[16];
            size_t  sn[4];
            char    forms[4][16];
            memcpy(forms[0], c, cn);
            sn[0] = cn;
            forms[1][0] = 'a';
            memcpy(forms[1] + 1, c, cn);
            forms[1][1 + cn] = 'b';
            sn[1] = cn + 2u;
            memcpy(forms[2], "\xd8\xa8", 2);
            memcpy(forms[2] + 2, c, cn);
            memcpy(forms[2] + 2 + cn, "\xe2\x80\x8c\xd8\xa8", 5);
            sn[2] = cn + 7u;
            memcpy(forms[3], "\xe0\xa4\x95", 3);
            memcpy(forms[3] + 3, c, cn);
            memcpy(forms[3] + 3 + cn, "\xe2\x80\x8d", 3);
            sn[3] = cn + 6u;
            for (unsigned f = 0; f < 4u; f++) {
                char  *a = NULL;
                size_t an = 0;
                int    rc = lc_idna_lookup(forms[f], sn[f], &a, &an);
                mem |= rc == -2;
                if (rc != 0) {
                    errs++;
                    an = 0;
                }
                fnv(&hl, a, an);
                fnv_num(&hl, rc != 0);
                free(a);
            }
            for (unsigned f = 0; f < 2u; f++) {
                size_t k = 0;
                if (f == 1u)
                    s[k++] = 'a';
                memcpy(s + k, c, cn);
                char  *o = NULL;
                size_t on = 0;
                mem |= lc_nfc(s, k + cn, &o, &on) != 0;
                fnv(&hn, o, on);
                fnv_num(&hn, on);
                free(o);
            }
        }
        char line[140];
        snprintf(line, sizeof line,
                 "every rune in four places through Lookup.ToASCII, %u errors as in Go (%u)", errs,
                 (unsigned)UNIVEC_RUNES_LOOKUP_ERRORS);
        ok(!mem && hl == UNIVEC_RUNES_LOOKUP && errs == UNIVEC_RUNES_LOOKUP_ERRORS, line);
        ok(!mem && hn == UNIVEC_RUNES_NFC, "every rune alone and after a letter through NFC.String");
    }

    /* Names chosen for one rule each: joiners, the Bidi Rule, decoded labels, hyphens, marks. */
    {
        unsigned bad = 0, count = (unsigned)(sizeof univec_named / sizeof univec_named[0]);
        for (unsigned i = 0; i < count; i++) {
            char  *a = NULL;
            size_t an = 0;
            int    rc = lc_idna_lookup(univec_named[i].in, strlen(univec_named[i].in), &a, &an);
            int    same = (rc != 0) == univec_named[i].err &&
                       (rc != 0 || (an == strlen(univec_named[i].lookup) &&
                                    memcmp(a, univec_named[i].lookup, an) == 0));
            if (!same) {
                bad++;
                printf("        [%s]: ", show(univec_named[i].in, strlen(univec_named[i].in)));
                printf("got %s%s, ", rc != 0 ? "error " : "", show(a != NULL ? a : "", rc != 0 ? 0 : an));
                printf("Go %s%s\n", univec_named[i].err ? "error " : "",
                       show(univec_named[i].lookup, strlen(univec_named[i].lookup)));
            }
            free(a);
        }
        char line[120];
        snprintf(line, sizeof line, "%u names, one rule each, as Lookup.ToASCII makes them", count);
        ok(bad == 0u, line);
    }

    printf("\nwhat the functions make of %u drawn strings\n", (unsigned)UNIVEC_DRAWS);
    uint64_t h[6];
    for (unsigned i = 0; i < 6u; i++)
        h[i] = FNV_START;
    static char s[1 << 16];
    unsigned    errs = 0, rtl = 0, shown_bad = 0;
    for (unsigned i = 0; i < UNIVEC_DRAWS; i++) {
        size_t n = draw(s);
        char  *a = NULL, *nfc = NULL;
        size_t an = 0, nn = 0;
        int    rc = lc_idna_lookup(s, n, &a, &an);
        if (rc == -2 || lc_nfc(s, n, &nfc, &nn) != 0) {
            ok(0, "memory");
            return 1;
        }
        if (rc != 0) {
            errs++;
            an = 0;
        }
        fnv(&h[0], a, an);
        fnv_num(&h[0], rc != 0);
        fnv(&h[1], nfc, nn);
        fnv_num(&h[1], nn);
        fnv_num(&h[2], lc_nfc_quick_span(s, n));
        fnv_num(&h[3], (uint64_t)lc_nfc_is_normal(s, n));
        fnv_num(&h[4], (uint64_t)lc_bidirule_valid(s, n));
        int d = lc_bidirule_rtl(s, n);
        rtl += (unsigned)d;
        fnv_num(&h[5], (uint64_t)d);
        if (i < sizeof univec_shown / sizeof univec_shown[0]) {
            const char *wl = univec_shown[i].lookup, *wn = univec_shown[i].nfc;
            int same = (rc != 0) == univec_shown[i].lookup_err && an == strlen(wl) &&
                       memcmp(a != NULL ? a : "", wl, an) == 0 && nn == strlen(wn) &&
                       memcmp(nfc, wn, nn) == 0;
            if (!same && shown_bad++ < 12u) {
                printf("        [%s]\n", show(s, n));
                printf("          lookup %s%s,", rc != 0 ? "error " : "", show(a != NULL ? a : "", an));
                printf(" Go %s%s\n", univec_shown[i].lookup_err ? "error " : "", show(wl, strlen(wl)));
                printf("          nfc %s,", show(nfc, nn));
                printf(" Go %s\n", show(wn, strlen(wn)));
            }
        }
        free(a);
        free(nfc);
    }
    char line[160];
    snprintf(line, sizeof line, "the first %u in full: Lookup.ToASCII and NFC.String as Go's",
             (unsigned)(sizeof univec_shown / sizeof univec_shown[0]));
    ok(shown_bad == 0u, line);
    snprintf(line, sizeof line, "Lookup.ToASCII: every one, %u of them errors as in Go (%u)", errs,
             (unsigned)UNIVEC_LOOKUP_ERRORS);
    ok(h[0] == UNIVEC_LOOKUP && errs == UNIVEC_LOOKUP_ERRORS, line);
    ok(h[1] == UNIVEC_NFC, "NFC.String: every one");
    ok(h[2] == UNIVEC_QUICKSPAN, "NFC.QuickSpan: every one");
    ok(h[3] == UNIVEC_ISNORMAL, "NFC.IsNormalString: every one");
    ok(h[4] == UNIVEC_BIDIRULE, "bidirule.ValidString: every one");
    snprintf(line, sizeof line, "bidirule.DirectionString: every one, %u right to left as in Go (%u)",
             rtl, (unsigned)UNIVEC_RTL);
    ok(h[5] == UNIVEC_DIRECTION && rtl == UNIVEC_RTL, line);

    printf(failures == 0 ? "\nall good\n" : "\n%d failed\n", failures);
    return failures == 0 ? 0 : 1;
}
