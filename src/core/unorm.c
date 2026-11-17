#include "core/unorm.h"

#include "core/gotext.h"

#include "unitables_nfc.h"

/* The port follows GOROOT/src/vendor/golang.org/x/text/unicode/norm, Go 1.27's copy:
 * composition.go (the reorder buffer, stream-safe counting, composition), normalize.go (quickSpan,
 * decomposeSegment, String, IsNormalString), forminfo.go (Properties, compInfo), input.go and the
 * NFC trie of tables17.0.0.go — NFC only, input always a whole string (atEOF). */

enum { MAX_NON_STARTERS = 30, MAX_BUFFER = MAX_NON_STARTERS + 2, MAX_BYTE_BUFFER = 4 * MAX_BUFFER };
enum { SS_SUCCESS, SS_STARTER, SS_OVERFLOW };
enum { I_SUCCESS = 0, I_SHORT_DST = -1 };

typedef struct {
    uint8_t  pos, size, ccc, tccc, nlead, flags;
    uint16_t index;
} props;

/* ---- the trie and what it says of a rune --------------------------------------------------------- */

static uint16_t nfc_value(uint32_t n, uint8_t b)
{
    if (n < NFC_DENSE)
        return nfc_values[(n << 6) + b];
    return lc_uni_sparse(nfc_sparse_offset, nfc_sparse, n - NFC_DENSE, b);
}

static int cont(uint8_t c)
{
    return c >= 0x80u && c < 0xc0u;
}

/* nfcTrie.lookupString: the value and how many bytes it covers — 0 for a sequence cut short by the
 * end, and a malformed one covering the bytes up to the one that breaks it. */
static uint16_t nfc_lookup(const uint8_t *s, size_t len, size_t *sz)
{
    uint8_t c0 = s[0];
    *sz = 1;
    if (c0 < 0x80u)
        return nfc_values[c0];
    if (c0 < 0xc2u)
        return 0;
    size_t need = c0 < 0xe0u ? 2u : c0 < 0xf0u ? 3u : c0 < 0xf8u ? 4u : 0u;
    if (need == 0u)
        return 0;
    if (len < need) {
        *sz = 0;
        return 0;
    }
    uint32_t i = nfc_index[c0];
    for (size_t k = 1; k < need; k++) {
        if (!cont(s[k])) {
            *sz = k;
            return 0;
        }
        if (k + 1u < need)
            i = nfc_index[(i << 6) + s[k]];
    }
    *sz = need;
    return nfc_value(i, s[need - 1u]);
}

/* The length byte in front of a decomposition, Go 1.27's way: five bits, with 31 standing for 33,
 * and the three bits above them the qcInfo (headerLenMask and headerFlagsMask,
 * GOROOT/src/vendor/golang.org/x/text/unicode/norm/forminfo.go:37-39, and Decomposition, :151-163).
 * Go 1.26 had six bits of length and two of flags, and Unicode 17 has a 33-byte decomposition —
 * a compatibility one, which the NFC trie never points at (none of its 2143 decomposing runes
 * does), so 31 is kept as Go reads it but never read. */
static uint8_t decomp_len(uint8_t h)
{
    uint8_t n = h & 0x1fu;
    return n == 31u ? 33u : n;
}

/* compInfo (forminfo.go). */
static props comp_info(uint16_t v, size_t sz)
{
    props p = { 0 };
    p.size = (uint8_t)sz;
    if (v == 0u)
        return p;
    if (v >= 0x8000u) {
        p.ccc = (uint8_t)v;
        p.tccc = (uint8_t)v;
        p.flags = (uint8_t)(v >> 8);
        if (p.ccc > 0u || (p.flags & 0x8u) != 0u)
            p.nlead = (uint8_t)(p.flags & 0x3u);
        return p;
    }
    uint8_t h = nfc_decomps[v];
    p.flags = (uint8_t)(((h & 0xe0u) >> 2) | 0x4u);
    p.index = v;
    if (v >= NFC_FIRST_CCC) {
        v = (uint16_t)(v + decomp_len(h) + 1u);
        uint8_t c = nfc_decomps[v];
        p.tccc = (uint8_t)(c >> 2);
        p.flags |= (uint8_t)(c & 0x3u);
        if (v >= NFC_FIRST_LEADING_CCC) {
            p.nlead = (uint8_t)(c & 0x3u);
            if (v >= NFC_FIRST_STARTER_WITH_NLEAD) {
                p.flags &= 0x03u;
                p.index = 0;
                return p;
            }
            p.ccc = nfc_decomps[v + 1u];
        }
    }
    return p;
}

static props info_at(const uint8_t *s, size_t len, size_t i)
{
    size_t   sz;
    uint16_t v = nfc_lookup(s + i, len - i, &sz);
    return comp_info(v, sz);
}

static int boundary_before(props p)
{
    return p.ccc == 0u && (p.flags & 0x8u) == 0u;
}

static int yes_c(props p)
{
    return (p.flags & 0x10u) == 0u;
}

static int combines_backward(props p)
{
    return (p.flags & 0x8u) != 0u;
}

static int has_decomposition(props p)
{
    return (p.flags & 0x4u) != 0u;
}

/* streamSafe.next (composition.go). */
static int ss_next(uint8_t *ss, props p)
{
    unsigned n = p.nlead;
    *ss = (uint8_t)(*ss + n);
    if (*ss > MAX_NON_STARTERS) {
        *ss = 0;
        return SS_OVERFLOW;
    }
    if (n == 0u) {
        *ss = (uint8_t)(p.flags & 0x3u);
        return SS_STARTER;
    }
    return SS_SUCCESS;
}

/* quickSpan (normalize.go), at the end of the input: how far the input is NFC already, and
 * whether that is all of it. */
static size_t quick_span(const uint8_t *s, size_t len, size_t i, int *ok)
{
    uint8_t last_cc = 0, ss = 0;
    size_t  last_seg = i, n = len;
    while (i < n) {
        size_t j = i;
        while (j < n && s[j] < 0x80u)
            j++;
        if (j != i) {
            i = j;
            last_seg = i - 1u;
            last_cc = 0;
            ss = 0;
            continue;
        }
        props info = info_at(s, len, i);
        if (info.size == 0u) {
            *ok = 1;
            return n;
        }
        int st = ss_next(&ss, info);
        if (st == SS_STARTER) {
            last_seg = i;
        } else if (st == SS_OVERFLOW) {
            *ok = 0;
            return last_seg;
        } else if (last_cc > info.ccc) {
            *ok = 0;
            return last_seg;
        }
        if (!yes_c(info))
            break;
        last_cc = info.ccc;
        i += info.size;
    }
    if (i == n) {
        *ok = 1;
        return n;
    }
    *ok = 0;
    return last_seg;
}

/* ---- the reorder buffer (composition.go) --------------------------------------------------------- */

typedef struct rb rb;
struct rb {
    props   rune[MAX_BUFFER];
    uint8_t byte[MAX_BYTE_BUFFER];
    uint8_t nbyte;
    uint8_t ss;
    int     nrune;

    const uint8_t *src;
    size_t         nsrc;

    int (*flush)(rb *);
    lc_obuf out;    /* appendFlush's */
    size_t  cmp_bp; /* IsNormalString's */
};

static void insert_ordered(rb *b, props info)
{
    /* Stream-safe counting keeps a segment to MAX_BUFFER runes — thirty non-starters, a starter
     * and a grapheme joiner — so the reference never indexes past the end here; nor does this. */
    if (b->nrune >= MAX_BUFFER)
        return;
    int n = b->nrune;
    if (info.ccc > 0u)
        for (; n > 0; n--) {
            if (b->rune[n - 1].ccc <= info.ccc)
                break;
            b->rune[n] = b->rune[n - 1];
        }
    b->nrune++;
    info.pos = b->nbyte;
    b->nbyte = (uint8_t)(b->nbyte + 4u);
    b->rune[n] = info;
}

/* copy(rb.byte[rb.nbyte:], ...): no more than the buffer holds. */
static size_t put_bytes(rb *b, const uint8_t *p, size_t n)
{
    size_t room = MAX_BYTE_BUFFER - (size_t)b->nbyte;
    if (n > room)
        n = room;
    memcpy(b->byte + b->nbyte, p, n);
    return n;
}

static void insert_single(rb *b, const uint8_t *p, props info)
{
    put_bytes(b, p, info.size);
    insert_ordered(b, info);
}

static void insert_cgj(rb *b)
{
    static const uint8_t cgj[2] = { 0xcd, 0x8f }; /* U+034F */
    props p = { 0 };
    p.size = 2;
    insert_single(b, cgj, p);
}

static void append_rune(rb *b, uint32_t r)
{
    if (b->nrune >= MAX_BUFFER || b->nbyte + 4u > MAX_BYTE_BUFFER)
        return; /* as insert_ordered */
    uint8_t bn = b->nbyte;
    size_t  sz = lc_go_encode(b->byte + bn, r);
    b->nbyte = (uint8_t)(b->nbyte + 4u);
    props p = { 0 };
    p.pos = bn;
    p.size = (uint8_t)sz;
    b->rune[b->nrune++] = p;
}

static void assign_rune(rb *b, int pos, uint32_t r)
{
    uint8_t bn = b->rune[pos].pos;
    size_t  sz = lc_go_encode(b->byte + bn, r);
    props   p = { 0 };
    p.pos = bn;
    p.size = (uint8_t)sz;
    b->rune[pos] = p;
}

static uint32_t rune_at(const rb *b, int n)
{
    uint32_t r = LC_RUNE_ERROR; /* utf8.DecodeRune of nothing */
    if (b->rune[n].size != 0u)
        (void)lc_go_rune(b->byte + b->rune[n].pos, b->rune[n].size, &r);
    return r;
}

enum {
    HANGUL_BASE = 0xac00,
    JAMO_L_BASE = 0x1100,
    JAMO_L_END = 0x1113,
    JAMO_V_BASE = 0x1161,
    JAMO_V_END = 0x1176,
    JAMO_T_BASE = 0x11a7,
    JAMO_T_END = 0x11c3,
    JAMO_T_COUNT = 28,
    JAMO_V_COUNT = 21,
    JAMO_VT_COUNT = 21 * 28,
    JAMO_LVT_COUNT = 19 * 21 * 28,
    HANGUL_END = HANGUL_BASE + JAMO_LVT_COUNT,
};

/* isHangulString: the three bytes of a syllable, U+AC00 to U+D7A3. */
static int is_hangul(const uint8_t *s, size_t n)
{
    if (n < 3u)
        return 0;
    uint8_t b0 = s[0], b1 = s[1];
    if (b0 < 0xeau)
        return 0;
    if (b0 == 0xeau)
        return b1 >= 0xb0u;
    if (b0 < 0xedu)
        return 1;
    if (b0 > 0xedu)
        return 0;
    if (b1 < 0x9eu)
        return 1;
    return b1 == 0x9eu && s[2] < 0xa4u;
}

/* input.hangul: the syllable at `p`, or 0. */
static uint32_t hangul_at(const uint8_t *s, size_t len, size_t p)
{
    if (!is_hangul(s + p, len - p))
        return 0;
    uint32_t r;
    return lc_go_rune(s + p, len - p, &r) == 3u ? r : 0u;
}

static void decompose_hangul(rb *b, uint32_t r)
{
    r -= HANGUL_BASE;
    uint32_t x = r % JAMO_T_COUNT;
    r /= JAMO_T_COUNT;
    append_rune(b, JAMO_L_BASE + r / JAMO_V_COUNT);
    append_rune(b, JAMO_V_BASE + r % JAMO_V_COUNT);
    if (x != 0u)
        append_rune(b, JAMO_T_BASE + x);
}

static void combine_hangul(rb *b, int s, int i, int k)
{
    int bn = b->nrune;
    for (; i < bn; i++) {
        uint8_t ccc_b = b->rune[k - 1].ccc, ccc_c = b->rune[i].ccc;
        if (ccc_b == 0u)
            s = k - 1;
        if (s != k - 1 && ccc_b >= ccc_c) {
            b->rune[k++] = b->rune[i];
            continue;
        }
        uint32_t l = rune_at(b, s), v = rune_at(b, i);
        if (JAMO_L_BASE <= l && l < JAMO_L_END && JAMO_V_BASE <= v && v < JAMO_V_END)
            assign_rune(b, s,
                        HANGUL_BASE + (l - JAMO_L_BASE) * JAMO_VT_COUNT + (v - JAMO_V_BASE) * JAMO_T_COUNT);
        else if (HANGUL_BASE <= l && l < HANGUL_END && JAMO_T_BASE < v && v < JAMO_T_END &&
                 (l - HANGUL_BASE) % JAMO_T_COUNT == 0u)
            assign_rune(b, s, l + v - JAMO_T_BASE);
        else
            b->rune[k++] = b->rune[i];
    }
    b->nrune = k;
}

/* combine: recompMap[uint16(a)<<16 + uint16(b)], or 0. */
static uint32_t combine(uint32_t a, uint32_t c)
{
    uint32_t key = (a & 0xffffu) << 16 | (c & 0xffffu);
    size_t   lo = 0, hi = sizeof nfc_recomp / sizeof nfc_recomp[0];
    while (lo < hi) {
        size_t m = lo + (hi - lo) / 2u;
        if (nfc_recomp[m][0] == key)
            return nfc_recomp[m][1];
        if (nfc_recomp[m][0] < key)
            lo = m + 1u;
        else
            hi = m;
    }
    return 0;
}

static void compose(rb *b)
{
    int bn = b->nrune;
    if (bn == 0)
        return;
    int k = 1;
    for (int s = 0, i = 1; i < bn; i++) {
        const uint8_t *p = b->byte + b->rune[i].pos;
        /* isJamoVT(rb.bytesAt(i)) */
        if (p[0] == 0xe1u && b->rune[i].size >= 2u && (p[1] & 0xfcu) == 0x84u) {
            combine_hangul(b, s, i, k);
            return;
        }
        props ii = b->rune[i];
        if (combines_backward(ii)) {
            uint8_t ccc_b = b->rune[k - 1].ccc, ccc_c = ii.ccc;
            int     blocked = 0;
            if (ccc_b == 0u)
                s = k - 1;
            else
                blocked = s != k - 1 && ccc_b >= ccc_c;
            if (!blocked) {
                uint32_t combined = combine(rune_at(b, s), rune_at(b, i));
                if (combined != 0u) {
                    assign_rune(b, s, combined);
                    continue;
                }
            }
        }
        b->rune[k++] = b->rune[i];
    }
    b->nrune = k;
}

static int do_flush(rb *b)
{
    compose(b);
    int res = b->flush(b);
    b->nrune = 0;
    b->nbyte = 0;
    return res;
}

static int append_flush(rb *b)
{
    for (int i = 0; i < b->nrune; i++)
        lc_obuf_add(&b->out, b->byte + b->rune[i].pos, b->rune[i].size);
    return 1;
}

static int insert_decomposed(rb *b, const uint8_t *d, size_t dn)
{
    for (size_t i = 0; i < dn;) {
        props info = info_at(d, dn, i);
        if (boundary_before(info) && b->nrune > 0 && !do_flush(b))
            return I_SHORT_DST;
        size_t take = info.size <= dn - i ? info.size : dn - i;
        i += put_bytes(b, d + i, take);
        insert_ordered(b, info);
        if (take == 0u)
            break; /* a decomposition is whole UTF-8: never */
    }
    return I_SUCCESS;
}

static int insert_flush(rb *b, size_t i, props info)
{
    uint32_t r = hangul_at(b->src, b->nsrc, i);
    if (r != 0u) {
        decompose_hangul(b, r);
        return I_SUCCESS;
    }
    if (has_decomposition(info)) {
        if (info.index == 0u)
            return I_SUCCESS; /* Decomposition() of nothing: no runes */
        uint8_t n = decomp_len(nfc_decomps[info.index]);
        return insert_decomposed(b, nfc_decomps + info.index + 1u, n);
    }
    insert_single(b, b->src + i, info);
    return I_SUCCESS;
}

/* decomposeSegment (normalize.go), at the end of the input. */
static long decompose_segment(rb *b, size_t sp)
{
    props info = info_at(b->src, b->nsrc, sp);
    if (info.size == 0u)
        return 0;
    int st = ss_next(&b->ss, info);
    if (st == SS_STARTER) {
        if (b->nrune > 0)
            goto end;
    } else if (st == SS_OVERFLOW) {
        insert_cgj(b);
        goto end;
    }
    if (insert_flush(b, sp, info) != I_SUCCESS)
        return I_SHORT_DST;
    for (;;) {
        sp += info.size;
        if (sp >= b->nsrc)
            break;
        info = info_at(b->src, b->nsrc, sp);
        if (info.size == 0u)
            break;
        st = ss_next(&b->ss, info);
        if (st == SS_STARTER)
            break;
        if (st == SS_OVERFLOW) {
            insert_cgj(b);
            break;
        }
        if (insert_flush(b, sp, info) != I_SUCCESS)
            return I_SHORT_DST;
    }
end:
    if (!do_flush(b))
        return I_SHORT_DST;
    return (long)sp;
}

/* appendQuick (normalize.go). */
static size_t append_quick(rb *b, size_t i)
{
    if (b->nsrc == i)
        return i;
    int    ok;
    size_t end = quick_span(b->src, b->nsrc, i, &ok);
    lc_obuf_add(&b->out, b->src + i, end - i);
    return end;
}

/* ---- the Form's methods -------------------------------------------------------------------------- */

int lc_nfc(const char *s, size_t n, char **out, size_t *on)
{
    const uint8_t *u = (const uint8_t *)s;
    int            ok;
    size_t         q = quick_span(u, n, 0, &ok);
    rb            *b = calloc(1, sizeof *b);
    if (b == NULL)
        return -2;
    b->src = u;
    b->nsrc = n;
    b->flush = append_flush;
    lc_obuf_add(&b->out, s, ok ? n : q);
    if (!ok)
        /* doAppendInner */
        for (size_t p = q; p < n;) {
            long r = decompose_segment(b, p);
            p = append_quick(b, r < 0 ? 0u : (size_t)r);
        }
    int oom = b->out.oom;
    *out = b->out.p;
    *on = b->out.n;
    free(b);
    if (oom) {
        free(*out);
        return -2;
    }
    return 0;
}

size_t lc_nfc_quick_span(const char *s, size_t n)
{
    int ok;
    return quick_span((const uint8_t *)s, n, 0, &ok);
}

static int cmp_flush(rb *b)
{
    for (int i = 0; i < b->nrune; i++) {
        props info = b->rune[i];
        if (b->cmp_bp + info.size > b->nsrc)
            return 0;
        if (memcmp(b->src + b->cmp_bp, b->byte + info.pos, info.size) != 0)
            return 0;
        b->cmp_bp += info.size;
    }
    return 1;
}

int lc_nfc_is_normal(const char *s, size_t n)
{
    const uint8_t *u = (const uint8_t *)s;
    int            ok;
    size_t         bp = quick_span(u, n, 0, &ok);
    if (ok)
        return 1;
    rb b;
    memset(&b, 0, sizeof b);
    b.src = u;
    b.nsrc = n;
    b.flush = cmp_flush;
    while (bp < n) {
        b.cmp_bp = bp;
        long r = decompose_segment(&b, bp);
        if (r < 0)
            return 0;
        bp = quick_span(u, n, (size_t)r, &ok);
    }
    return 1;
}
