#include "core/idna.h"

#include "core/gotext.h"
#include "core/ubidi.h"
#include "core/unorm.h"

#include "unitables_idna.h"

static int ascii(const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if ((uint8_t)s[i] >= 0x80u)
            return 0;
    return 1;
}

/* ---- punycode (GOROOT/src/vendor/golang.org/x/net/idna/punycode.go) ---------------------------- */

enum { BASE = 36, DAMP = 700, INITIAL_BIAS = 72, INITIAL_N = 128, SKEW = 38, TMAX = 26, TMIN = 1 };

/* madd: a + b*c, and whether that passes MaxInt32. */
static int madd(int32_t a, int32_t b, int32_t c, int32_t *next)
{
    int64_t p = (int64_t)b * (int64_t)c;
    if (p > (int64_t)INT32_MAX - a)
        return 1;
    *next = (int32_t)(a + p);
    return 0;
}

static int decode_digit(uint8_t x, int32_t *d)
{
    if (x >= '0' && x <= '9')
        *d = (int32_t)(x - ('0' - 26));
    else if (x >= 'A' && x <= 'Z')
        *d = (int32_t)(x - 'A');
    else if (x >= 'a' && x <= 'z')
        *d = (int32_t)(x - 'a');
    else
        return 0;
    return 1;
}

static uint8_t encode_digit(int32_t d)
{
    return (uint8_t)(d < 26 ? d + 'a' : d + ('0' - 26));
}

static int32_t adapt(int32_t delta, int32_t points, int first)
{
    delta = first ? delta / DAMP : delta / 2;
    delta += delta / points;
    int32_t k = 0;
    while (delta > ((BASE - TMIN) * TMAX) / 2) {
        delta /= BASE - TMIN;
        k += BASE;
    }
    return k + (BASE - TMIN + 1) * delta / (delta + SKEW);
}

static int32_t threshold(int32_t k, int32_t bias)
{
    if (k <= bias)
        return TMIN;
    if (k >= bias + TMAX)
        return TMAX;
    return k - bias;
}

/* decode, section 6.2: the label after "xn--", into runes and out as UTF-8. -1 on punyError. */
static int decode(const char *enc, size_t n, lc_obuf *out)
{
    if (n == 0u)
        return 0;
    size_t pos = 0;
    for (size_t i = n; i-- > 0;)
        if (enc[i] == '-') {
            pos = i + 1u;
            break;
        }
    if (pos == 1u)
        return -1;
    if (pos == n) {
        lc_obuf_add(out, enc, n - 1u);
        return 0;
    }
    /* Every step inserts one rune and reads at least one byte, so this is room enough. */
    uint32_t *rs = malloc((n + 1u) * sizeof *rs);
    if (rs == NULL) {
        out->oom = 1;
        return 0;
    }
    size_t len = 0;
    if (pos != 0u)
        for (size_t i = 0; i < pos - 1u;) {
            uint32_t r;
            i += lc_go_rune((const uint8_t *)enc + i, pos - 1u - i, &r);
            rs[len++] = r;
        }
    int32_t i = 0, bias = INITIAL_BIAS;
    int64_t nn = INITIAL_N;
    int     rc = 0;
    while (pos < n && rc == 0) {
        int32_t old = i, w = 1;
        for (int32_t k = BASE;; k += BASE) {
            int32_t digit;
            if (pos == n || !decode_digit((uint8_t)enc[pos], &digit)) {
                rc = -1;
                break;
            }
            pos++;
            if (madd(i, digit, w, &i)) {
                rc = -1;
                break;
            }
            int32_t t = threshold(k, bias);
            if (digit < t)
                break;
            if (madd(0, w, BASE - t, &w)) {
                rc = -1;
                break;
            }
        }
        if (rc != 0)
            break;
        if (len >= 1024u) {
            rc = -1;
            break;
        }
        int32_t x = (int32_t)(len + 1u);
        bias = adapt(i - old, x, old == 0);
        /* n += i / x in an int32, then `n < 0 || n > MaxRune`: both are a sum past MaxRune here,
         * since neither term is negative. */
        nn += i / x;
        i %= x;
        if (nn > (int64_t)LC_MAX_RUNE) {
            rc = -1;
            break;
        }
        memmove(rs + i + 1, rs + i, (len - (size_t)i) * sizeof *rs);
        rs[i] = (uint32_t)nn;
        len++;
        i++;
    }
    if (rc == 0)
        for (size_t j = 0; j < len; j++)
            lc_obuf_rune(out, rs[j]);
    free(rs);
    return rc;
}

/* encode, section 6.3, with "xn--" in front. -1 on punyError. */
static int encode(const char *s, size_t n, lc_obuf *out)
{
    const uint8_t *u = (const uint8_t *)s;
    lc_obuf_add(out, "xn--", 4u);
    int32_t b = 0, remaining = 0;
    for (size_t i = 0; i < n;) {
        uint32_t r;
        i += lc_go_rune(u + i, n - i, &r);
        /* `if unicode16 && r == 0xfffd` (GOROOT/src/vendor/golang.org/x/net/idna/punycode.go:111-113):
         * a range over the label, so an invalid byte, which ranges as U+FFFD, is one too. */
        if (r == 0xfffdu)
            return -1;
        if (r < 0x80u) {
            b++;
            lc_obuf_byte(out, (uint8_t)r);
        } else {
            remaining++;
        }
    }
    int32_t h = b, delta = 0, bias = INITIAL_BIAS, nn = INITIAL_N;
    if (b > 0)
        lc_obuf_byte(out, '-');
    while (remaining != 0) {
        int32_t m = INT32_MAX;
        for (size_t i = 0; i < n;) {
            uint32_t r;
            i += lc_go_rune(u + i, n - i, &r);
            if (m > (int32_t)r && (int32_t)r >= nn)
                m = (int32_t)r;
        }
        if (madd(delta, m - nn, h + 1, &delta))
            return -1;
        nn = m;
        for (size_t i = 0; i < n;) {
            uint32_t r;
            i += lc_go_rune(u + i, n - i, &r);
            if ((int32_t)r < nn) {
                if (delta == INT32_MAX)
                    return -1; /* delta++ wrapped: `if delta < 0` */
                delta++;
                continue;
            }
            if ((int32_t)r > nn)
                continue;
            int32_t q = delta;
            for (int32_t k = BASE;; k += BASE) {
                int32_t t = threshold(k, bias);
                if (q < t)
                    break;
                lc_obuf_byte(out, encode_digit(t + (q - t) % (BASE - t)));
                q = (q - t) / (BASE - t);
            }
            lc_obuf_byte(out, encode_digit(q));
            bias = adapt(delta, h + 1, h == b);
            delta = 0;
            h++;
            remaining--;
        }
        delta++;
        nn++;
    }
    return 0;
}


/* ---- the UTS #46 trie (GOROOT/src/vendor/golang.org/x/net/idna: trieval.go, trie.go and
 * the trie of tables17.0.0.go) ------------------------------------------------------------------- */

static uint16_t idna_value(uint32_t n, uint8_t b)
{
    if (n < IDNA_DENSE)
        return idna_values[(n << 6) + b];
    return lc_uni_sparse(idna_sparse_offset, idna_sparse, n - IDNA_DENSE, b);
}

/* idnaTrie.lookupString: the value and the bytes it covers — 0 for a sequence cut short by the end,
 * and a malformed one covering the bytes up to the one that breaks it. */
static uint16_t lookup(const uint8_t *s, size_t len, size_t *sz)
{
    uint8_t c0 = s[0];
    *sz = 1;
    if (c0 < 0x80u)
        return idna_values[c0];
    size_t need = c0 < 0xc2u ? 0u : c0 < 0xe0u ? 2u : c0 < 0xf0u ? 3u : c0 < 0xf8u ? 4u : 0u;
    if (need == 0u)
        return 0;
    if (len < need) {
        *sz = 0;
        return 0;
    }
    uint32_t i = idna_index[c0];
    for (size_t k = 1; k < need; k++) {
        if (s[k] < 0x80u || s[k] >= 0xc0u) {
            *sz = k;
            return 0;
        }
        if (k + 1u < need)
            i = idna_index[(i << 6) + s[k]];
    }
    *sz = need;
    return idna_value(i, s[need - 1u]);
}

/* The categories (trieval.go), as the Lookup profile simplifies them: non-transitional — so a
 * deviation is valid — and with the STD3 rules, so what they disallow is disallowed. */
enum { CAT_UNKNOWN = 0, CAT_MAPPED = 1, CAT_VALID = 0x08, CAT_DISALLOWED = 0x40, CAT_IGNORED = 0xc0 };

static unsigned category(uint16_t c)
{
    unsigned small = c & 0x3u;
    unsigned cat = small != 0u ? small : (c & 0xf8u);
    switch (cat) {
    case 2u:    /* disallowedSTD3Mapped */
    case 0x80u: /* disallowedSTD3Valid */
        return CAT_DISALLOWED;
    case 3u:    /* deviation */
    case 0x18u: /* validNV8 */
    case 0x28u: /* validXV8 */
        return CAT_VALID;
    default:
        return cat;
    }
}

static int is_mapped(uint16_t c)
{
    return (c & 0x3u) != 0u;
}

/* info.isBidi: an unmapped rune by its own bit, a mapped one by its bidi class. */
static int is_bidi(uint16_t c, const char *s, size_t n)
{
    if (!is_mapped(c))
        return (c & 0x1800u) == 0x0800u;
    size_t   sz;
    unsigned cls = lc_bidi_class(s, n, &sz);
    return cls == LC_BIDI_R || cls == LC_BIDI_AL || cls == LC_BIDI_AN;
}

/* info.appendMapping (idna.go): the mapping from the table, or the rune's own bytes with a
 * pattern XORed over their end. */
static void append_mapping(lc_obuf *b, uint16_t c, const char *s, size_t n)
{
    unsigned index = c >> 3;
    if ((c & 0x4u) == 0u) {
        lc_obuf_add(b, idna_mappings + idna_mapping_index[index],
                    (size_t)(idna_mapping_index[index + 1u] - idna_mapping_index[index]));
        return;
    }
    lc_obuf_add(b, s, n);
    if (b->oom)
        return;
    if ((c & 0xe000u) == 0xe000u) {
        b->p[b->n - 1u] = (char)((uint8_t)b->p[b->n - 1u] ^ (uint8_t)index);
        return;
    }
    for (size_t p = b->n - idna_xor[index]; p < b->n; p++) {
        index++;
        b->p[p] = (char)((uint8_t)b->p[p] ^ idna_xor[index]);
    }
}

/* validateAndMap (idna.go): each rune kept, dropped or replaced by its mapping, then NFC —
 * of the whole when a rune was changed and the result is not plainly NFC, or when nothing was
 * changed and a rune that may need it was kept. -1 on the first error: nothing after it can take
 * it back. */
static int validate_and_map(const char *s, size_t len, lc_obuf *out, int *bidi)
{
    lc_obuf  b = { 0 };
    size_t   k = 0;
    uint16_t combined = 0;
    for (size_t i = 0; i < len;) {
        size_t   sz;
        uint16_t v = lookup((const uint8_t *)s + i, len - i, &sz);
        if (sz == 0u) {
            free(b.p);
            return -1; /* the rest is cut short: a rune error */
        }
        combined |= v;
        *bidi = *bidi || is_bidi(v, s + i, len - i);
        size_t start = i;
        i += sz;
        switch (category(v)) {
        case CAT_VALID:
            continue;
        case CAT_DISALLOWED:
            /* Unicode 16 delays the error to validateLabel
             * (GOROOT/src/vendor/golang.org/x/net/idna/idna.go:552-558): kept as it is. */
            continue;
        case CAT_MAPPED:
            lc_obuf_add(&b, s + k, start - k);
            append_mapping(&b, v, s + start, sz);
            break;
        case CAT_IGNORED:
            lc_obuf_add(&b, s + k, start - k);
            break;
        case CAT_UNKNOWN:
            lc_obuf_add(&b, s + k, start - k);
            lc_obuf_add(&b, "\xef\xbf\xbd", 3u); /* U+FFFD */
            break;
        default:
            break;
        }
        k = i;
    }
    char  *nfc = NULL;
    size_t nn = 0;
    int    rc = 0;
    if (k == 0u) {
        if ((combined & 0x2000u) != 0u) /* mayNeedNorm */
            rc = lc_nfc(s, len, &nfc, &nn);
        else
            lc_obuf_add(out, s, len);
    } else {
        lc_obuf_add(&b, s + k, len - k);
        if (b.oom)
            rc = -2;
        else if (lc_nfc_quick_span(b.p, b.n) != b.n)
            rc = lc_nfc(b.p, b.n, &nfc, &nn);
        else
            lc_obuf_add(out, b.p, b.n);
    }
    if (rc == 0 && nfc != NULL)
        lc_obuf_add(out, nfc, nn);
    free(nfc);
    free(b.p);
    return rc != 0 || out->oom ? -2 : 0;
}

/* validateLabel (idna.go), with the Lookup profile's options: the hyphens, a combining mark
 * first, and the joiners (RFC 5892 appendix A.1 and A.2) walked through joinStates — whose entries
 * that are not written down are stateStart. */
enum { ST_START, ST_VIRAMA, ST_BEFORE, ST_BEFORE_VIRAMA, ST_AFTER, ST_FAIL };
enum { J_L = 1, J_D, J_T, J_R, J_ZWJ, J_ZWNJ, J_VIRAMA };

static const uint8_t join_states[6][8] = {
    [ST_START] = { [J_L] = ST_BEFORE, [J_D] = ST_BEFORE, [J_ZWNJ] = ST_FAIL, [J_ZWJ] = ST_FAIL,
                   [J_VIRAMA] = ST_VIRAMA },
    [ST_VIRAMA] = { [J_L] = ST_BEFORE, [J_D] = ST_BEFORE },
    [ST_BEFORE] = { [J_L] = ST_BEFORE, [J_D] = ST_BEFORE, [J_T] = ST_BEFORE, [J_ZWNJ] = ST_AFTER,
                    [J_ZWJ] = ST_FAIL, [J_VIRAMA] = ST_BEFORE_VIRAMA },
    [ST_BEFORE_VIRAMA] = { [J_L] = ST_BEFORE, [J_D] = ST_BEFORE, [J_T] = ST_BEFORE },
    [ST_AFTER] = { [J_L] = ST_FAIL, [J_D] = ST_BEFORE, [J_T] = ST_AFTER, [J_R] = ST_START,
                   [J_ZWNJ] = ST_FAIL, [J_ZWJ] = ST_FAIL, [J_VIRAMA] = ST_AFTER },
    [ST_FAIL] = { ST_FAIL, ST_FAIL, ST_FAIL, ST_FAIL, ST_FAIL, ST_FAIL, ST_FAIL, ST_FAIL },
};

static const char zwj[3] = { '\xe2', '\x80', '\x8d' };
static const char zwnj[3] = { '\xe2', '\x80', '\x8c' };

static int has(const char *s, size_t n, const char *what)
{
    for (size_t i = 0; i + 3u <= n; i++)
        if (memcmp(s + i, what, 3) == 0)
            return 1;
    return 0;
}

static int validate_label(const char *s, size_t n)
{
    if (n == 0u)
        return 0;
    if (n > 4u && s[2] == '-' && s[3] == '-')
        return -1;
    if (s[0] == '-' || s[n - 1u] == '-')
        return -1;
    /* Unicode 16's TR 46 checks the runes here, once the label is decoded, where validateAndMap no
     * longer does (GOROOT/src/vendor/golang.org/x/net/idna/idna.go:796-812): each one valid, and an
     * ASCII one only a letter, a digit or a hyphen (allowedSTD3, :768-775; the Lookup profile has
     * the STD3 rules, and a label holds no dot). Uppercase is mapped away before this. */
    for (size_t i = 0; i < n;) {
        size_t   rsz;
        uint16_t v = lookup((const uint8_t *)s + i, n - i, &rsz);
        if (rsz == 0u || category(v) != CAT_VALID)
            return -1;
        if (rsz == 1u && !((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= '0' && s[i] <= '9') ||
                           s[i] == '-'))
            return -1;
        i += rsz;
    }
    size_t   sz;
    uint16_t x = lookup((const uint8_t *)s, n, &sz);
    if ((x & 0x1003u) == 0x1000u) /* isModifier */
        return -1;
    if (!has(s, n, zwj) && !has(s, n, zwnj))
        return 0;
    unsigned st = ST_START;
    for (size_t i = 0;;) {
        unsigned jt = is_mapped(x) ? 0u : (unsigned)(x >> 8 & 0x7u);
        if (sz == 3u && memcmp(s + i, zwj, 3) == 0)
            jt = J_ZWJ;
        else if (sz == 3u && memcmp(s + i, zwnj, 3) == 0)
            jt = J_ZWNJ;
        st = join_states[st][jt];
        if ((x & 0x1803u) == 0x1800u) /* isViramaModifier */
            st = join_states[st][J_VIRAMA];
        i += sz;
        if (i == n || sz == 0u) /* a label here is whole UTF-8: sz is never 0 */
            break;
        x = lookup((const uint8_t *)s + i, n - i, &sz);
    }
    return st == ST_FAIL || st == ST_AFTER ? -1 : 0;
}

/* validateFromPunycode (idna.go): a decoded label must be NFC, and every rune in it valid. */
static int from_punycode(const char *s, size_t n)
{
    if (!lc_nfc_is_normal(s, n))
        return -1;
    for (size_t i = 0; i < n;) {
        size_t   sz;
        uint16_t v = lookup((const uint8_t *)s + i, n - i, &sz);
        if (sz == 0u || category(v) != CAT_VALID)
            return -1;
        i += sz;
    }
    return 0;
}

/* ---- Profile.process (GOROOT/src/vendor/golang.org/x/net/idna/idna.go, Go 1.27) ---------------
 *
 * The first error is the one returned, and the callers only ask whether there was one, so this
 * stops at it. The labels are strings.Split's: process walks them with labelIter, which skips a
 * label only when it is an empty one at the end — and an empty label is one none of its loops
 * changes, so what it joins back is what splitting, converting and joining makes. */

typedef struct {
    const char *p;
    size_t      n;
    char       *own; /* a decoded label's own string */
} label;

static int labels(const char *s, size_t n, int lookup_profile, int bidi, lc_obuf *res)
{
    size_t count = 1;
    for (size_t i = 0; i < n; i++)
        count += s[i] == '.';
    label *ls = calloc(count, sizeof *ls);
    if (ls == NULL)
        return -2;
    for (size_t i = 0, at = 0; i < count; i++) {
        const char *dot = memchr(s + at, '.', n - at);
        ls[i].p = s + at;
        ls[i].n = dot != NULL ? (size_t)(dot - (s + at)) : n - at;
        at += ls[i].n + 1u;
    }

    int rc = 0;
    for (size_t i = 0; i < count && rc == 0; i++) {
        label *l = &ls[i];
        if (l->n == 0u)
            continue;
        if (l->n >= 4u && memcmp(l->p, "xn--", 4) == 0) {
            lc_obuf u = { 0 };
            lc_obuf_add(&u, "", 0u);
            if (decode(l->p + 4, l->n - 4u, &u) != 0) {
                rc = -1;
            } else if (u.oom) {
                rc = -2;
            } else if (u.n > 0u && ascii(u.p, u.n)) {
                rc = -1; /* "a xn-- label which contains only ASCII characters" */
            } else {
                l->own = u.p;
                l->p = u.p;
                l->n = u.n;
                u.p = NULL;
                if (lookup_profile) {
                    bidi = bidi || lc_bidirule_rtl(l->p, l->n);
                    if (from_punycode(l->p, l->n) != 0 || validate_label(l->p, l->n) != 0)
                        rc = -1;
                }
            }
            free(u.p);
        } else if (lookup_profile && validate_label(l->p, l->n) != 0) {
            rc = -1;
        }
    }
    if (rc == 0 && lookup_profile && bidi)
        for (size_t i = 0; i < count && rc == 0; i++)
            if (!lc_bidirule_valid(ls[i].p, ls[i].n))
                rc = -1;

    for (size_t i = 0; i < count && rc == 0; i++) {
        if (i > 0u)
            lc_obuf_byte(res, '.');
        if (ascii(ls[i].p, ls[i].n))
            lc_obuf_add(res, ls[i].p, ls[i].n);
        else if (encode(ls[i].p, ls[i].n, res) != 0)
            rc = -1;
    }
    for (size_t i = 0; i < count; i++)
        free(ls[i].own);
    free(ls);
    return rc != 0 ? rc : res->oom ? -2 : 0;
}

static int process(const char *s, size_t n, int lookup_profile, char **out, size_t *on)
{
    lc_obuf mapped = { 0 }, res = { 0 };
    int     bidi = 0, rc = 0;
    lc_obuf_add(&mapped, "", 0u);
    if (lookup_profile) {
        rc = validate_and_map(s, n, &mapped, &bidi);
        s = mapped.p;
        n = mapped.n;
    }
    lc_obuf_add(&res, "", 0u); /* an empty name is an empty string, not NULL */
    if (rc == 0 && mapped.oom)
        rc = -2;
    if (rc == 0)
        rc = labels(s, n, lookup_profile, bidi, &res);
    free(mapped.p);
    if (rc != 0) {
        free(res.p);
        return rc;
    }
    *out = res.p;
    *on = res.n;
    return 0;
}

int lc_idna_to_ascii(const char *s, size_t n, char **out, size_t *on)
{
    return process(s, n, 0, out, on);
}

int lc_idna_lookup(const char *s, size_t n, char **out, size_t *on)
{
    return process(s, n, 1, out, on);
}
