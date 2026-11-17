/* x509.ParseCertificate (GOROOT/src/crypto/x509/parser.go, go1.26.6 and go1.27.1), with the
 * cryptobyte readers it stands on (GOROOT/src/vendor/golang.org/x/crypto/cryptobyte/asn1.go) — see
 * cert/x509go.h. Where the two toolchains part, the rule is taken by `x->go127`, and each such place
 * says what go1.27.1 does differently. */
#include "cert/x509go.h"

#include "cert/mldsa.h"
#include "core/goquote.h"
#include "core/netip.h"
#include "reality/url.h"
#include "tls/goerr.h"

#include <mbedtls/bignum.h>

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* How wide Go's int is where the reference runs (32 bits on mipsel), and whether its P-256 is the
 * assembly one: `//go:build (amd64 || arm64 || ppc64le || s390x) && !purego`
 * (GOROOT/src/crypto/internal/fips140/nistec/p256_asm.go). */
#define GO_INT64 (UINTPTR_MAX > 0xffffffffu)
#if defined(__x86_64__) || defined(__aarch64__) || defined(__s390x__) ||                          \
    (defined(__powerpc64__) && defined(__LITTLE_ENDIAN__))
#define GO_P256_ASM 1
#else
#define GO_P256_ASM 0
#endif

/* ---- the words --------------------------------------------------------------------------------- */

static int fail(lc_obuf *e, const char *text)
{
    if (e != NULL)
        lc_obuf_add(e, text, strlen(text));
    return -1;
}

/* A Go format, the literal kept as Go's so that check-qgo-reasons can find it: %d takes an int, and
 * %s, %q, %v and %x a string the caller has already written as Go would (%q quoted by
 * lc_go_quote, %x in lowercase hex). */
static int failf(lc_obuf *e, const char *gofmt, ...)
{
    if (e == NULL)
        return -1;
    va_list ap;
    va_start(ap, gofmt);
    for (const char *f = gofmt; *f != '\0'; f++) {
        if (f[0] != '%' || f[1] == '\0') {
            lc_obuf_byte(e, (uint8_t)*f);
            continue;
        }
        f++;
        if (*f == 'd') {
            char num[24];
            int  n = snprintf(num, sizeof num, "%d", va_arg(ap, int));
            lc_obuf_add(e, num, (size_t)n);
        } else {
            const char *s = va_arg(ap, const char *);
            lc_obuf_add(e, s, strlen(s));
        }
    }
    va_end(ap);
    return -1;
}

/* %q of bytes, as a NUL-terminated string the caller frees. NULL when memory ran out. */
static char *quoted(const uint8_t *s, size_t n)
{
    lc_obuf b = { 0 };
    lc_go_quote(&b, s, n);
    if (b.oom) {
        free(b.p);
        return NULL;
    }
    return b.p;
}

/* ---- cryptobyte -------------------------------------------------------------------------------- */

typedef struct {
    const uint8_t *p;
    size_t         n;
} cs;

#define T_BOOLEAN   0x01u
#define T_INTEGER   0x02u
#define T_BITSTRING 0x03u
#define T_OCTETS    0x04u
#define T_OID       0x06u
#define T_UTCTIME   0x17u
#define T_GENTIME   0x18u
#define T_SEQUENCE  0x30u
#define T_SET       0x31u

/* One parse: which toolchain's rules, and where the fields go when somebody wants them (NULL for a
 * verdict alone, which is all the QUIC plane asks). */
typedef struct {
    int        go127;
    lc_gocert *out;
} px;

static lc_gobytes gb(cs s)
{
    return (lc_gobytes){ s.p, s.n };
}

/* append to a list; 0, or -2 when memory ran out */
static int list_push(lc_gobytes_list *l, cs s)
{
    if (l->n == l->cap) {
        size_t      cap = l->cap != 0u ? l->cap * 2u : 4u;
        lc_gobytes *a = realloc(l->a, cap * sizeof *a);
        if (a == NULL)
            return -2;
        l->a = a;
        l->cap = cap;
    }
    l->a[l->n++] = gb(s);
    return 0;
}

static int grow(void **a, size_t *n, size_t size)
{
    void *p = realloc(*a, (*n + 1u) * size);
    if (p == NULL)
        return -2;
    *a = p;
    (*n)++;
    return 0;
}

static char *dup_bytes(const void *s, size_t n)
{
    char *p = malloc(n + 1u);
    if (p != NULL) {
        if (n != 0u)
            memcpy(p, s, n);
        p[n] = '\0';
    }
    return p;
}

/* readASN1 (asn1.go:755-825): one element, DER lengths only, low tag numbers only. On failure the
 * string is where it was. */
static int read_any(cs *s, cs *out, uint8_t *tag, int skip_header)
{
    if (s->n < 2u)
        return 0;
    uint8_t t = s->p[0], lb = s->p[1];
    if ((t & 0x1fu) == 0x1fu)
        return 0;
    if (tag != NULL)
        *tag = t;
    uint32_t length, header;
    if ((lb & 0x80u) == 0u) {
        length = (uint32_t)lb + 2u;
        header = 2u;
    } else {
        unsigned ll = lb & 0x7fu;
        if (ll == 0u || ll > 4u || s->n < 2u + ll)
            return 0;
        uint32_t len32 = 0;
        for (unsigned i = 0; i < ll; i++)
            len32 = len32 << 8 | s->p[2u + i];
        if (len32 < 128u)
            return 0;
        if ((len32 >> ((ll - 1u) * 8u)) == 0u)
            return 0;
        header = 2u + ll;
        if (header + len32 < len32)
            return 0;
        length = header + len32;
    }
    if (!GO_INT64 && length > 0x7fffffffu)
        return 0; /* int(length) < 0 */
    if (s->n < length)
        return 0;
    /* ReadBytes advances s, then writes out — so when they are the same string, as in
     * `der.ReadASN1(&der, ...)`, out is what is left. */
    cs got = { s->p + (skip_header ? header : 0u), length - (skip_header ? header : 0u) };
    s->p += length;
    s->n -= length;
    *out = got;
    return 1;
}

static int read(cs *s, cs *out, uint8_t tag)
{
    uint8_t t;
    return read_any(s, out, &t, 1) && t == tag;
}

static int read_element(cs *s, cs *out, uint8_t tag)
{
    uint8_t t;
    return read_any(s, out, &t, 0) && t == tag;
}

static int peek(const cs *s, uint8_t tag)
{
    return s->n > 0u && s->p[0] == tag;
}

static int read_optional(cs *s, cs *out, int *present, uint8_t tag)
{
    *present = peek(s, tag);
    return !*present || read(s, out, tag);
}

static int skip_optional(cs *s, uint8_t tag)
{
    cs unused;
    return !peek(s, tag) || read(s, &unused, tag);
}

/* checkASN1Integer (asn1.go:298-311). */
static int int_ok(cs b)
{
    if (b.n == 0u)
        return 0;
    if (b.n == 1u)
        return 1;
    return !((b.p[0] == 0u && (b.p[1] & 0x80u) == 0u) || (b.p[0] == 0xffu && (b.p[1] & 0x80u) != 0u));
}

/* readASN1Int64 through asn1Signed (asn1.go:350-371), under any tag. */
static int read_int64_tag(cs *s, int64_t *out, uint8_t tag)
{
    cs b;
    if (!read(s, &b, tag) || !int_ok(b) || b.n > 8u)
        return 0;
    uint64_t v = (b.p[0] & 0x80u) ? UINT64_MAX : 0u;
    for (size_t i = 0; i < b.n; i++)
        v = v << 8 | b.p[i];
    *out = (int64_t)v;
    return 1;
}

/* ReadASN1Integer into a Go int: int64 first, then the width of the machine's int. */
static int read_goint(cs *s, int64_t *out)
{
    if (!read_int64_tag(s, out, T_INTEGER))
        return 0;
    return GO_INT64 || (*out >= INT32_MIN && *out <= INT32_MAX);
}

/* ReadASN1Integer into a Go uint (asn1.go:373-396). */
static int read_gouint(cs *s, uint64_t *out)
{
    cs b;
    if (!read(s, &b, T_INTEGER) || !int_ok(b))
        return 0;
    if (b.n > 9u || (b.n == 9u && b.p[0] != 0u) || (b.p[0] & 0x80u) != 0u)
        return 0;
    uint64_t v = 0;
    for (size_t i = 0; i < b.n; i++)
        v = v << 8 | b.p[i];
    if (!GO_INT64 && v > UINT32_MAX)
        return 0;
    *out = v;
    return 1;
}

/* ReadASN1Integer into a *big.Int (asn1.go:315-333): the sign, and the magnitude's bytes for a
 * positive one (leading zeros included). */
static int read_big(cs *s, int *sign, cs *mag)
{
    cs b;
    if (!read(s, &b, T_INTEGER) || !int_ok(b))
        return 0;
    if (b.p[0] & 0x80u)
        *sign = -1;
    else
        *sign = b.n == 1u && b.p[0] == 0u ? 0 : 1;
    if (mag != NULL)
        *mag = b;
    return 1;
}

static int read_bool(cs *s, int *out)
{
    cs b;
    if (!read(s, &b, T_BOOLEAN) || b.n != 1u || (b.p[0] != 0u && b.p[0] != 0xffu))
        return 0;
    *out = b.p[0] != 0u;
    return 1;
}

/* readBase128Int (asn1.go:421-449): at most five bytes, no leading 0x80, under 2^31. */
static int base128(cs *s, uint32_t *out)
{
    uint32_t ret = 0;
    for (unsigned i = 0; s->n > 0u; i++) {
        if (i == 5u || ret >= (1u << 24))
            return 0;
        ret <<= 7;
        uint8_t b = s->p[0];
        s->p++;
        s->n--;
        if (i == 0u && b == 0x80u)
            return 0;
        ret |= b & 0x7fu;
        if ((b & 0x80u) == 0u) {
            *out = ret;
            return 1;
        }
    }
    return 0;
}

/* ReadASN1ObjectIdentifier (asn1.go:453-488): `content` is the OID's bytes, which name one list of
 * components and no other once they read — so two OIDs are equal exactly when these are. */
static int read_oid(cs *s, cs *content)
{
    cs b;
    if (!read(s, &b, T_OID) || b.n == 0u)
        return 0;
    cs       w = b;
    uint32_t v;
    while (w.n > 0u)
        if (!base128(&w, &v))
            return 0;
    *content = b;
    return 1;
}

/* The components of an OID that read: up to `max` of them into `out`, and how many there are. */
static size_t oid_components(cs b, uint32_t *out, size_t max)
{
    size_t   n = 0;
    uint32_t v;
    base128(&b, &v);
    uint32_t first = v < 80u ? v / 40u : 2u, second = v < 80u ? v % 40u : v - 80u;
    if (n < max)
        out[n] = first;
    n++;
    if (n < max)
        out[n] = second;
    n++;
    while (b.n > 0u) {
        base128(&b, &v);
        if (n < max)
            out[n] = v;
        n++;
    }
    return n;
}

/* ObjectIdentifier.String (GOROOT/src/encoding/asn1/asn1.go:233-246). */
static void oid_string(lc_obuf *out, cs b)
{
    uint32_t v;
    base128(&b, &v);
    char num[48];
    int  n = snprintf(num, sizeof num, "%u.%u", v < 80u ? v / 40u : 2u, v < 80u ? v % 40u : v - 80u);
    lc_obuf_add(out, num, (size_t)n);
    while (b.n > 0u) {
        base128(&b, &v);
        n = snprintf(num, sizeof num, ".%u", v);
        lc_obuf_add(out, num, (size_t)n);
    }
}

static int oid_is(cs b, const uint8_t *want, size_t n)
{
    return b.n == n && memcmp(b.p, want, n) == 0;
}

/* ReadASN1BitString (asn1.go:550-568): the bytes, and the bit length. */
static int read_bits(cs *s, cs *bytes, size_t *bitlen)
{
    cs b;
    if (!read(s, &b, T_BITSTRING) || b.n == 0u)
        return 0;
    uint8_t pad = b.p[0];
    if (pad > 7u || (b.n == 1u && pad != 0u) ||
        (b.n > 1u && (b.p[b.n - 1u] & ((1u << pad) - 1u)) != 0u))
        return 0;
    bytes->p = b.p + 1;
    bytes->n = b.n - 1u;
    *bitlen = bytes->n * 8u - pad;
    return 1;
}

/* ---- time -------------------------------------------------------------------------------------- */

/* What time.Parse reads and time.Format writes back unchanged, which is all that ReadASN1UTCTime
 * and ReadASN1GeneralizedTime accept (asn1.go:492-546): the digits of the layout, each field in
 * its range and the day in its month — Feb 29 by the year Parse settled on — then "Z" or a
 * numeric offset of at most 24 hours and 59 minutes that is not zero, since Format writes a zero
 * offset as "Z". Anything Parse takes that Format does not give back — a fraction of a second, a
 * single-digit hour, "+0000" — fails the round trip. */
static int digits(const uint8_t *p, size_t n, int *v)
{
    int x = 0;
    for (size_t i = 0; i < n; i++) {
        if (p[i] < '0' || p[i] > '9')
            return 0;
        x = x * 10 + (p[i] - '0');
    }
    *v = x;
    return 1;
}

static int days_in(int month, int year)
{
    static const int days[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    if (month == 2 && year % 4 == 0 && (year % 100 != 0 || year % 400 == 0))
        return 29;
    return days[month - 1];
}

/* A time as it was written: the instant in Unix seconds, and the zone's offset east of UTC, `utc`
 * for "Z" — what time.Time holds and Format(time.RFC3339) prints. */
typedef struct {
    int64_t unix;
    int32_t off;
    int     utc;
} gotime;

/* Days from 1970-01-01 to a date of the proleptic Gregorian calendar. */
static int64_t days_from_civil(int64_t y, int m, int d)
{
    y -= m <= 2;
    int64_t  era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);
    unsigned doy = (unsigned)((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1);
    unsigned doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
    return era * 146097 + (int64_t)doe - 719468;
}

/* The date and time fields from `p` on — month, day, hour, minute and, when `seconds`, second —
 * then the zone, which must end the string. */
static int time_rest(const uint8_t *p, size_t n, int year, int seconds, gotime *t)
{
    size_t need = seconds ? 10u : 8u;
    int    mo, d, h, mi, s = 0;
    if (n < need || !digits(p, 2, &mo) || !digits(p + 2, 2, &d) || !digits(p + 4, 2, &h) ||
        !digits(p + 6, 2, &mi) || (seconds && !digits(p + 8, 2, &s)))
        return 0;
    if (mo < 1 || mo > 12 || h >= 24 || mi >= 60 || s >= 60 || d < 1 || d > days_in(mo, year))
        return 0;
    p += need;
    n -= need;
    int32_t off = 0;
    int     utc = 1;
    if (!(n == 1u && p[0] == 'Z')) {
        int hh, mm;
        if (n != 5u || (p[0] != '+' && p[0] != '-') || !digits(p + 1, 2, &hh) ||
            !digits(p + 3, 2, &mm))
            return 0;
        if (!(hh <= 24 && mm < 60 && (hh != 0 || mm != 0)))
            return 0;
        off = (int32_t)((hh * 60 + mm) * 60 * (p[0] == '-' ? -1 : 1));
        utc = 0;
    }
    t->unix = days_from_civil(year, mo, d) * 86400 + h * 3600 + mi * 60 + s - off;
    t->off = off;
    t->utc = utc;
    return 1;
}

/* ReadASN1UTCTime (asn1.go:510-535): the year time.Parse settles on for "06" (69 and up are 19xx),
 * then a hundred years back for 2050 and later. AddDate(-100, 0, 0) moves a Feb 29 to a Feb 29: a
 * year from 2050 to 2068 and the one a century before are leap alike. */
static int utc_ok(cs t, gotime *out)
{
    int yy;
    if (t.n < 2u || !digits(t.p, 2, &yy))
        return 0;
    int year = yy >= 69 ? 1900 + yy : 2000 + yy;
    /* "060102150405Z0700", and failing that "0601021504Z0700" (asn1.go:520-529) */
    if (!time_rest(t.p + 2, t.n - 2u, year, 1, out) && !time_rest(t.p + 2, t.n - 2u, year, 0, out))
        return 0;
    if (year >= 2050) {
        int64_t local = out->unix + out->off;
        int64_t day = local >= 0 ? local / 86400 : (local - 86399) / 86400;
        int64_t within = local - day * 86400;
        /* the same month and day a century earlier: shift by the days between the two dates */
        int64_t back = days_from_civil(year, 1, 1) - days_from_civil(year - 100, 1, 1);
        out->unix = (day - back) * 86400 + within - out->off;
    }
    return 1;
}

static int generalized_ok(cs t, gotime *out)
{
    int year;
    return t.n >= 4u && digits(t.p, 4, &year) && time_rest(t.p + 4, t.n - 4u, year, 1, out);
}

/* readASN1Time (parser.go:261-276 in go1.27.1, parseTime in go1.26.6: the same rules). */
static int parse_time(cs *der, gotime *out, lc_obuf *e)
{
    cs     t;
    gotime scratch;
    if (out == NULL)
        out = &scratch;
    if (peek(der, T_UTCTIME)) {
        if (!read(der, &t, T_UTCTIME) || !utc_ok(t, out))
            return fail(e, LC_GO("x509: malformed UTCTime"));
    } else if (peek(der, T_GENTIME)) {
        if (!read(der, &t, T_GENTIME) || !generalized_ok(t, out))
            return fail(e, LC_GO("x509: malformed GeneralizedTime"));
    } else {
        return fail(e, LC_GO("x509: unsupported time format"));
    }
    return 0;
}

/* ---- strings and names ------------------------------------------------------------------------- */

/* isPrintable (parser.go:35-54). */
static int printable(uint8_t b)
{
    return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') ||
           (b >= '\'' && b <= ')') || (b >= '+' && b <= '/') || b == ' ' || b == ':' || b == '=' ||
           b == '?' || b == '*' || b == '&';
}

/* isIA5String (GOROOT/src/crypto/x509/x509.go:1186-1195): every rune ASCII — a byte of a rune
 * past it, or of no rune at all, fails. */
static int ia5(const uint8_t *s, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (s[i] >= 0x80u)
            return 0;
    return 1;
}

/* isIA5String's error: x509: %q cannot be encoded as an IA5String. */
static void ia5_error(lc_obuf *e, const uint8_t *s, size_t n)
{
    char *q = quoted(s, n);
    failf(e, LC_GO("x509: %q cannot be encoded as an IA5String"), q != NULL ? q : "");
    free(q);
}

/* utf8.AppendRune of a rune below 0x10000 that is not a surrogate. */
static void put_rune(lc_obuf *b, unsigned r)
{
    uint8_t u[3];
    if (r < 0x80u) {
        lc_obuf_byte(b, (uint8_t)r);
    } else if (r < 0x800u) {
        u[0] = (uint8_t)(0xc0u | r >> 6);
        u[1] = (uint8_t)(0x80u | (r & 0x3fu));
        lc_obuf_add(b, u, 2);
    } else {
        u[0] = (uint8_t)(0xe0u | r >> 12);
        u[1] = (uint8_t)(0x80u | (r >> 6 & 0x3fu));
        u[2] = (uint8_t)(0x80u | (r & 0x3fu));
        lc_obuf_add(b, u, 3);
    }
}

/* The Go string parseASN1String returns for a value it accepted: T61String read as Latin-1 and
 * BMPString as UCS-2 (its terminator dropped), each turned UTF-8; the rest as they are. */
static void asn1_string_value(uint8_t tag, cs v, lc_obuf *s)
{
    if (tag == 0x14) {
        for (size_t i = 0; i < v.n; i++)
            put_rune(s, v.p[i]);
    } else if (tag == 0x1e) {
        size_t n = v.n;
        if (n >= 2u && v.p[n - 1u] == 0u && v.p[n - 2u] == 0u)
            n -= 2u;
        for (size_t i = 0; i + 1u < n; i += 2u)
            put_rune(s, (unsigned)v.p[i] << 8 | v.p[i + 1u]);
    } else {
        lc_obuf_add(s, v.p, v.n);
    }
}

/* parseASN1String (parser.go:60-139): 0, or -1 with its error's text in `e`. */
static int asn1_string(uint8_t tag, cs v, lc_obuf *e)
{
    switch (tag) {
    case 0x14: /* T61String: Latin-1, anything */
        return 0;
    case 0x13:
        for (size_t i = 0; i < v.n; i++)
            if (!printable(v.p[i]))
                return fail(e, LC_GO("invalid PrintableString"));
        return 0;
    case 0x0c:
        for (size_t i = 0; i < v.n;) {
            uint32_t r;
            size_t   w = lc_go_rune(v.p + i, v.n - i, &r);
            if (w == 1u && r == LC_RUNE_ERROR)
                return fail(e, LC_GO("invalid UTF-8 string"));
            i += w;
        }
        return 0;
    case 0x1e: {
        if (v.n % 2u != 0u)
            return fail(e, LC_GO("invalid BMPString"));
        size_t n = v.n;
        if (n >= 2u && v.p[n - 1u] == 0u && v.p[n - 2u] == 0u)
            n -= 2u;
        for (size_t i = 0; i < n; i += 2u) {
            unsigned point = (unsigned)v.p[i] << 8 | v.p[i + 1u];
            if (point == 0xfffeu || point == 0xffffu || (point >= 0xfdd0u && point <= 0xfdefu) ||
                (point >= 0xd800u && point <= 0xdfffu))
                return fail(e, LC_GO("invalid BMPString"));
        }
        return 0;
    }
    case 0x16:
        if (!ia5(v.p, v.n))
            return fail(e, LC_GO("invalid IA5String"));
        return 0;
    case 0x12:
        for (size_t i = 0; i < v.n; i++)
            if (!((v.p[i] >= '0' && v.p[i] <= '9') || v.p[i] == ' '))
                return fail(e, LC_GO("invalid NumericString"));
        return 0;
    default: {
        char num[8];
        snprintf(num, sizeof num, "%u", (unsigned)tag);
        return failf(e, LC_GO("unsupported string type: %v"), num);
    }
    }
}

/* readASN1Any (go1.27.1 parser.go:143-204): 0 with `*is_string` when the value is a Go string, or
 * -1 with the words. What it accepts beyond go1.26.6's strings — an INTEGER, a BIT STRING, a time,
 * any element at all in the default case — is where the two parsers differ on a Name. */
static int read_asn1_any(cs *der, cs *value, uint8_t *tag, int *is_string, lc_obuf *e)
{
    cs full;
    *is_string = 0;
    if (!read_any(der, &full, tag, 0))
        return fail(e, LC_GO("invalid ASN.1 element"));
    cs inner = full;
    switch (*tag) {
    case 0x14: case 0x13: case 0x0c: case 0x1e: case 0x16: case 0x12:
        (void)read_any(&inner, value, tag, 1);
        *is_string = 1;
        return asn1_string(*tag, *value, e);
    case T_INTEGER: {
        int64_t i;
        return read_int64_tag(&inner, &i, T_INTEGER) ? 0 : fail(e, LC_GO("invalid ASN.1 integer"));
    }
    case T_BITSTRING: {
        cs     b;
        size_t bits;
        return read_bits(&inner, &b, &bits) ? 0 : fail(e, LC_GO("invalid ASN.1 BIT STRING"));
    }
    case T_OID: {
        cs oid;
        return read_oid(&inner, &oid) ? 0 : fail(e, LC_GO("invalid ASN.1 OBJECT IDENTIFIER"));
    }
    case T_UTCTIME: case T_GENTIME:
        return parse_time(&inner, NULL, e);
    case T_BOOLEAN: {
        int b;
        return read_bool(&inner, &b) ? 0 : fail(e, LC_GO("invalid ASN.1 BOOLEAN"));
    }
    default: /* an OCTET STRING, a NULL, and any other element: read, and nothing to check */
        return 0;
    }
}

static const uint8_t OID_CN[] = { 0x55, 0x04, 0x03 }; /* 2.5.4.3 */
static const uint8_t OID_O[] = { 0x55, 0x04, 0x0a };  /* 2.5.4.10 */

/* Name.FillFromRDNSequence (GOROOT/src/crypto/x509/pkix/pkix.go), the two fields read here: the
 * last commonName that is a string, and the first organizationName. */
static int fill_name(lc_gocert *c, cs type, uint8_t tag, cs value)
{
    int cn = oid_is(type, OID_CN, sizeof OID_CN);
    if (!cn && !(oid_is(type, OID_O, sizeof OID_O) && c->subject_o == NULL))
        return 0;
    lc_obuf s = { 0 };
    asn1_string_value(tag, value, &s);
    char *text = s.p != NULL ? s.p : dup_bytes("", 0);
    if (s.oom || text == NULL) {
        free(s.p);
        return -2;
    }
    if (cn) {
        free(c->subject_cn);
        c->subject_cn = text;
        c->subject_cn_n = s.n;
    } else {
        c->subject_o = text;
        c->subject_o_n = s.n;
    }
    return 0;
}

/* parseName (parser.go:143-181 in go1.26.6, :208-241 in go1.27.1). `subject` asks for the fields
 * of the subject to be filled in. */
static int parse_name(px *x, cs raw, int subject, lc_obuf *e)
{
    if (!read(&raw, &raw, T_SEQUENCE))
        return fail(e, LC_GO("x509: invalid RDNSequence"));
    while (raw.n > 0u) {
        cs set;
        if (!read(&raw, &set, T_SET))
            return fail(e, LC_GO("x509: invalid RDNSequence"));
        while (set.n > 0u) {
            cs      atav, type, value;
            uint8_t tag;
            if (!read(&set, &atav, T_SEQUENCE))
                return fail(e, LC_GO("x509: invalid RDNSequence: invalid attribute"));
            if (!read_oid(&atav, &type))
                return fail(e, LC_GO("x509: invalid RDNSequence: invalid attribute type"));
            lc_obuf inner = { 0 };
            int     is_string = 1;
            if (x->go127) {
                if (read_asn1_any(&atav, &value, &tag, &is_string, &inner) != 0) {
                    failf(e, LC_GO("x509: invalid RDNSequence: invalid attribute value: %s"),
                          inner.p != NULL ? inner.p : "");
                    free(inner.p);
                    return -1;
                }
            } else {
                if (!read_any(&atav, &value, &tag, 1))
                    return fail(e, LC_GO("x509: invalid RDNSequence: invalid attribute value"));
                if (asn1_string(tag, value, &inner) != 0) {
                    failf(e, LC_GO("x509: invalid RDNSequence: invalid attribute value: %s"),
                          inner.p != NULL ? inner.p : "");
                    free(inner.p);
                    return -1;
                }
            }
            free(inner.p);
            if (subject && x->out != NULL && is_string && fill_name(x->out, type, tag, value) != 0)
                return -2;
        }
    }
    return 0;
}

/* parseAI (parser.go:183-199): the algorithm, and its parameters as one whole element, or none. */
static int parse_ai(cs der, cs *oid, cs *params, lc_obuf *e)
{
    params->p = NULL;
    params->n = 0;
    if (!read_oid(&der, oid))
        return fail(e, LC_GO("x509: malformed OID"));
    if (der.n == 0u)
        return 0;
    uint8_t tag;
    if (!read_any(&der, params, &tag, 0))
        return fail(e, LC_GO("x509: malformed parameters"));
    return 0;
}

/* ---- public keys -------------------------------------------------------------------------------- */

static const uint8_t OID_RSA[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
static const uint8_t OID_ECDSA[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
static const uint8_t OID_ED25519[] = { 0x2b, 0x65, 0x70 };
static const uint8_t OID_DSA[] = { 0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01 };
static const uint8_t OID_P224[] = { 0x2b, 0x81, 0x04, 0x00, 0x21 };
static const uint8_t OID_P256[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
static const uint8_t OID_P384[] = { 0x2b, 0x81, 0x04, 0x00, 0x22 };
static const uint8_t OID_P521[] = { 0x2b, 0x81, 0x04, 0x00, 0x23 };
/* id-ml-dsa-44/65/87, 2.16.840.1.101.3.4.3.17-19 (GOROOT/src/crypto/x509/x509.go:530-532 in
 * go1.27.1); go1.26.6 knows none of them */
static const uint8_t OID_MLDSA44[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11 };
static const uint8_t OID_MLDSA65[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12 };
static const uint8_t OID_MLDSA87[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13 };

static int mldsa_set(cs oid)
{
    return oid_is(oid, OID_MLDSA44, sizeof OID_MLDSA44)   ? LC_GO_MLDSA44
           : oid_is(oid, OID_MLDSA65, sizeof OID_MLDSA65) ? LC_GO_MLDSA65
           : oid_is(oid, OID_MLDSA87, sizeof OID_MLDSA87) ? LC_GO_MLDSA87
                                                          : 0;
}

/* getPublicKeyAlgorithmFromOID (x509.go:538-558 in go1.27.1). */
static int pk_algorithm(const px *x, cs oid)
{
    if (oid_is(oid, OID_RSA, sizeof OID_RSA))
        return LC_GO_PK_RSA;
    if (oid_is(oid, OID_DSA, sizeof OID_DSA))
        return LC_GO_PK_DSA;
    if (oid_is(oid, OID_ECDSA, sizeof OID_ECDSA))
        return LC_GO_PK_ECDSA;
    if (oid_is(oid, OID_ED25519, sizeof OID_ED25519))
        return LC_GO_PK_ED25519;
    if (x->go127 && mldsa_set(oid) != 0)
        return LC_GO_PK_MLDSA;
    return LC_GO_PK_UNKNOWN;
}

/* The four curves namedCurveFromOID knows (GOROOT/src/crypto/x509/x509.go), each with the names
 * crypto/internal/fips140/nistec gives its refusals, p and b in hex. */
typedef struct {
    const char *point_encoding, *element_encoding, *not_on_curve;
    size_t      size;
    const char *p, *b;
} curve;

static const curve P224 = {
    LC_GO("invalid P224 point encoding"), LC_GO("invalid P224Element encoding"),
    LC_GO("P224 point not on curve"), 28,
    "ffffffffffffffffffffffffffffffff000000000000000000000001",
    "b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
};
static const curve P256 = {
    LC_GO("invalid P256 point encoding"),
#if GO_P256_ASM
    LC_GO("invalid P256 element encoding"),
#else
    LC_GO("invalid P256Element encoding"),
#endif
    LC_GO("P256 point not on curve"), 32,
    "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
};
static const curve P384 = {
    LC_GO("invalid P384 point encoding"), LC_GO("invalid P384Element encoding"),
    LC_GO("P384 point not on curve"), 48,
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
    "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
};
static const curve P521 = {
    LC_GO("invalid P521 point encoding"), LC_GO("invalid P521Element encoding"),
    LC_GO("P521 point not on curve"), 66,
    "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
};

/* ecdsa.ParseUncompressedPublicKey (GOROOT/src/crypto/ecdsa/ecdsa.go:107-131) through the FIPS
 * module's NewPublicKey and the curve's SetBytes (crypto/internal/fips140/ecdsa/ecdsa.go:184-196,
 * nistec/p*.go): the tag, the length, each coordinate below p — P-256's assembly checks both before
 * it says a word, fiat checks x then y, in the same words — and y² = x³ - 3x + b. */
static int ec_point(const curve *c, const uint8_t *d, size_t n, lc_obuf *e)
{
    if (n < 1u || d[0] != 4u)
        return fail(e, LC_GO("ecdsa: invalid uncompressed public key"));
    if (n != 1u + 2u * c->size)
        return fail(e, c->point_encoding);
    mbedtls_mpi p, b, x, y, l, r, t;
    mbedtls_mpi_init(&p);
    mbedtls_mpi_init(&b);
    mbedtls_mpi_init(&x);
    mbedtls_mpi_init(&y);
    mbedtls_mpi_init(&l);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&t);
    int rc = -2;
    if (mbedtls_mpi_read_string(&p, 16, c->p) != 0 || mbedtls_mpi_read_string(&b, 16, c->b) != 0 ||
        mbedtls_mpi_read_binary(&x, d + 1, c->size) != 0 ||
        mbedtls_mpi_read_binary(&y, d + 1 + c->size, c->size) != 0)
        goto out;
    if (mbedtls_mpi_cmp_mpi(&x, &p) >= 0 || mbedtls_mpi_cmp_mpi(&y, &p) >= 0) {
        rc = fail(e, c->element_encoding);
        goto out;
    }
    /* l = y² mod p; r = (x³ - 3x + b) mod p */
    if (mbedtls_mpi_mul_mpi(&l, &y, &y) != 0 || mbedtls_mpi_mod_mpi(&l, &l, &p) != 0 ||
        mbedtls_mpi_mul_mpi(&r, &x, &x) != 0 || mbedtls_mpi_mul_mpi(&r, &r, &x) != 0 ||
        mbedtls_mpi_mul_int(&t, &x, 3) != 0 || mbedtls_mpi_sub_mpi(&r, &r, &t) != 0 ||
        mbedtls_mpi_add_mpi(&r, &r, &b) != 0 || mbedtls_mpi_mod_mpi(&r, &r, &p) != 0)
        goto out;
    rc = mbedtls_mpi_cmp_mpi(&l, &r) == 0 ? 0 : fail(e, c->not_on_curve);
out:
    mbedtls_mpi_free(&p);
    mbedtls_mpi_free(&b);
    mbedtls_mpi_free(&x);
    mbedtls_mpi_free(&y);
    mbedtls_mpi_free(&l);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&t);
    return rc;
}

/* BitString.RightAlign (GOROOT/src/encoding/asn1/asn1.go:181-195), into `out`, which has room for
 * `bytes.n` bytes; `out` is `bytes` itself when nothing moves. */
static cs right_align(cs bytes, size_t bitlen, uint8_t *buf)
{
    unsigned shift = 8u - (unsigned)(bitlen % 8u);
    if (shift == 8u || bytes.n == 0u)
        return bytes;
    buf[0] = (uint8_t)(bytes.p[0] >> shift);
    for (size_t i = 1; i < bytes.n; i++)
        buf[i] = (uint8_t)(bytes.p[i - 1u] << (8u - shift) | bytes.p[i] >> shift);
    return (cs){ buf, bytes.n };
}

static size_t bit_len(cs mag)
{
    size_t i = 0;
    while (i < mag.n && mag.p[i] == 0u)
        i++;
    if (i == mag.n)
        return 0;
    size_t  bits = (mag.n - i) * 8u;
    uint8_t top = mag.p[i];
    while ((top & 0x80u) == 0u) {
        top = (uint8_t)(top << 1);
        bits--;
    }
    return bits;
}

/* parsePublicKey (parser.go:249-342), for the four algorithms getPublicKeyAlgorithmFromOID knows:
 * 0 or -1 with the words, -2 when memory ran out. */
static int parse_public_key(px *x, cs alg, cs params, cs data, size_t *rsa_bits, lc_obuf *e)
{
    lc_gocert *out = x->out;
    if (oid_is(alg, OID_RSA, sizeof OID_RSA)) {
        if (!(params.n == 2u && params.p[0] == 0x05u && params.p[1] == 0u))
            return fail(e, LC_GO("x509: RSA key missing NULL parameters"));
        cs      der = data, n;
        int     sign;
        int64_t exp;
        if (!read(&der, &der, T_SEQUENCE))
            return fail(e, LC_GO("x509: invalid RSA public key"));
        if (!read_big(&der, &sign, &n))
            return fail(e, LC_GO("x509: invalid RSA modulus"));
        if (!read_goint(&der, &exp))
            return fail(e, LC_GO("x509: invalid RSA public exponent"));
        if (sign <= 0)
            return fail(e, LC_GO("x509: RSA modulus is not a positive number"));
        if (exp <= 0)
            return fail(e, LC_GO("x509: RSA public exponent is not a positive number"));
        *rsa_bits = bit_len(n);
        if (out != NULL) {
            out->rsa_n = gb(n);
            out->rsa_e = exp;
        }
        return 0;
    }
    if (oid_is(alg, OID_ECDSA, sizeof OID_ECDSA)) {
        cs pd = params, named;
        if (!read_oid(&pd, &named))
            return fail(e, LC_GO("x509: invalid ECDSA parameters"));
        const curve *c = oid_is(named, OID_P224, sizeof OID_P224)   ? &P224
                         : oid_is(named, OID_P256, sizeof OID_P256) ? &P256
                         : oid_is(named, OID_P384, sizeof OID_P384) ? &P384
                         : oid_is(named, OID_P521, sizeof OID_P521) ? &P521
                                                                    : NULL;
        if (c == NULL)
            return fail(e, LC_GO("x509: unsupported elliptic curve"));
        if (out != NULL)
            out->curve = c == &P224 ? LC_GO_P224 : c == &P256 ? LC_GO_P256 : c == &P384 ? LC_GO_P384 : LC_GO_P521;
        return ec_point(c, data.p, data.n, e);
    }
    if (oid_is(alg, OID_ED25519, sizeof OID_ED25519)) {
        if (params.n != 0u)
            return fail(e, LC_GO("x509: Ed25519 key encoded with illegal parameters"));
        if (data.n != 32u)
            return fail(e, LC_GO("x509: wrong Ed25519 public key size"));
        return 0;
    }
    if (x->go127 && mldsa_set(alg) != 0) {
        /* parser.go:366-374 in go1.27.1; the parameter set cannot be unknown here, the OID having
         * named it */
        if (params.n != 0u)
            return fail(e, LC_GO("x509: ML-DSA key encoded with illegal parameters"));
        if (out != NULL)
            out->mldsa = mldsa_set(alg);
        return lc_mldsa_public_key_ok(mldsa_set(alg), data.p, data.n, e) == 0 ? 0 : -1;
    }
    /* DSA, the fourth */
    cs  der = data, pd = params;
    int y, pp, q, g;
    if (!read_big(&der, &y, NULL))
        return fail(e, LC_GO("x509: invalid DSA public key"));
    if (!read(&pd, &pd, T_SEQUENCE) || !read_big(&pd, &pp, NULL) || !read_big(&pd, &q, NULL) ||
        !read_big(&pd, &g, NULL))
        return fail(e, LC_GO("x509: invalid DSA parameters"));
    if (y <= 0 || pp <= 0 || q <= 0 || g <= 0)
        return fail(e, LC_GO("x509: zero or negative DSA parameter"));
    return 0;
}

/* ---- names in extensions ------------------------------------------------------------------------ */

/* domainNameValid (parser.go:1292-1347). */
static int domain_valid(const uint8_t *s, size_t n, int constraint)
{
    if (n == 0u)
        return 1;
    if (s[n - 1u] == '.')
        return 0;
    if (constraint && s[0] == '.') {
        s++;
        n--;
    }
    long last = -1;
    for (size_t i = 0; i <= n; i++) {
        if (i < n && (s[i] < 33u || s[i] > 126u))
            return 0;
        if (i == n || s[i] == '.') {
            long label = (long)i - (last >= 0 ? last + 1 : 0);
            if (label == 0)
                return 0;
            last = (long)i;
        }
    }
    return 1;
}

/* domainToReverseLabels's verdict (GOROOT/src/crypto/x509/verify.go): every label non-empty and
 * of bytes 33..126, no empty label at the end — and nothing at all is fine. */
static int reverse_labels_ok(const uint8_t *s, size_t n)
{
    if (n == 0u)
        return 1;
    if (s[n - 1u] == '.')
        return 0;
    size_t start = 0;
    for (size_t i = 0; i <= n; i++) {
        if (i == n || s[i] == '.') {
            if (i == start)
                return 0;
            start = i + 1u;
        } else if (s[i] < 33u || s[i] > 126u) {
            return 0;
        }
    }
    return 1;
}

/* parseRFC2821Mailbox's verdict (GOROOT/src/crypto/x509/verify.go:264-383). go1.27.1 ends it
 * otherwise: the domain is held to domainNameValid, and may not hold an '@' (verify.go:392-399). */
static int mailbox_ok(int go127, const uint8_t *in, size_t n)
{
    if (n == 0u)
        return 0;
    size_t i = 0, local = 0;
    if (in[0] == '"') {
        i = 1;
        for (;;) {
            if (i >= n)
                return 0;
            uint8_t c = in[i++];
            if (c == '"')
                break;
            if (c == '\\') {
                if (i >= n)
                    return 0;
                uint8_t d = in[i];
                if (d == 11u || d == 12u || (d >= 1u && d <= 9u) || (d >= 14u && d <= 127u))
                    i++;
                else
                    return 0;
            } else if (!(c == 11u || c == 12u || c == 32u || c == 33u || c == 127u ||
                         (c >= 1u && c <= 8u) || (c >= 14u && c <= 31u) || (c >= 35u && c <= 91u) ||
                         (c >= 93u && c <= 126u))) {
                return 0;
            }
        }
    } else {
        /* Atom ("." Atom)*: atext, and a backslash taking whatever byte follows it (the fallthrough
         * at :328-339); then no '.' first or last in what was taken, and never two together. */
        int first_dot = 0, last_dot = 0, two_dots = 0;
        while (i < n) {
            uint8_t c = in[i];
            if (c == '\\') {
                i++;
                if (i >= n)
                    return 0;
            } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                         (c != 0u && strchr("!#$%&'*+-/=?^_`{|}~.", c) != NULL))) {
                break;
            }
            int dot = in[i++] == '.';
            if (local == 0u)
                first_dot = dot;
            else if (dot && last_dot)
                two_dots = 1;
            last_dot = dot;
            local++;
        }
        if (local == 0u || first_dot || last_dot || two_dots)
            return 0;
    }
    if (i >= n || in[i] != '@')
        return 0;
    i++;
    if (go127)
        return domain_valid(in + i, n - i, 0) && memchr(in + i, '@', n - i) == NULL;
    return reverse_labels_ok(in + i, n - i);
}

/* isValidIPMask (parser.go:509-531). */
static int mask_ok(const uint8_t *m, size_t n)
{
    int zero = 0;
    for (size_t i = 0; i < n; i++) {
        if (zero) {
            if (m[i] != 0u)
                return 0;
            continue;
        }
        switch (m[i]) {
        case 0x00: case 0x80: case 0xc0: case 0xe0: case 0xf0: case 0xf8: case 0xfc: case 0xfe:
            zero = 1;
            break;
        case 0xff:
            break;
        default:
            return 0;
        }
    }
    return 1;
}

/* A string %q'd into a Go format with one %q in it. */
static int fail_q(lc_obuf *e, const char *gofmt, const uint8_t *s, size_t n)
{
    char *q = quoted(s, n);
    if (q == NULL)
        return -2;
    failf(e, gofmt, q);
    free(q);
    return -1;
}

/* "x509: invalid constraint value: " + isIA5String's error. */
static int fail_constraint_ia5(lc_obuf *e, const uint8_t *s, size_t n)
{
    fail(e, LC_GO("x509: invalid constraint value: "));
    ia5_error(e, s, n);
    return -1;
}

/* Where one subtree list's values go: Permitted* or Excluded*. */
typedef struct {
    lc_gobytes_list *dns, *email, *uri;
    lc_goipnet     **ip;
    size_t          *ip_n;
} nc_lists;

/* net.IP.To4 of sixteen bytes: an IPv4-mapped address. */
static int v4_mapped(const uint8_t *ip)
{
    static const uint8_t prefix[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
    return memcmp(ip, prefix, sizeof prefix) == 0;
}

/* getValues of parseNameConstraintsExtension (parser.go:568-659 in go1.26.6, :642-737 in
 * go1.27.1). A subtree of a type it does not read sets `*unhandled`. */
static int nc_subtrees(px *x, cs subtrees, const nc_lists *to, int *unhandled, lc_obuf *e)
{
    while (subtrees.n > 0u) {
        cs      seq, value;
        uint8_t tag;
        if (!read(&subtrees, &seq, T_SEQUENCE) || !read_any(&seq, &value, &tag, 1))
            return fail(e, LC_GO("x509: invalid NameConstraints extension"));
        switch (tag) {
        case 0x82: /* dNSName */
            if (!ia5(value.p, value.n))
                return fail_constraint_ia5(e, value.p, value.n);
            if (!domain_valid(value.p, value.n, 1))
                return fail_q(e, LC_GO("x509: failed to parse dnsName constraint %q"), value.p, value.n);
            if (to != NULL && list_push(to->dns, value) != 0)
                return -2;
            break;
        case 0x87: { /* iPAddress */
            if (value.n != 8u && value.n != 32u)
                return failf(e, LC_GO("x509: IP constraint contained value of length %d"), (int)value.n);
            size_t half = value.n / 2u;
            if (!mask_ok(value.p + half, half)) {
                char hex[33];
                for (size_t i = 0; i < half; i++)
                    snprintf(hex + 2u * i, 3, "%02x", value.p[half + i]);
                return failf(e, LC_GO("x509: IP constraint contained invalid mask %x"), hex);
            }
            if (x->go127 && half == 16u && v4_mapped(value.p))
                return fail(e, LC_GO("x509: IP constraint contained IPv4-mapped IPv6 address"));
            if (to != NULL) {
                if (grow((void **)to->ip, to->ip_n, sizeof **to->ip) != 0)
                    return -2;
                lc_goipnet *r = &(*to->ip)[*to->ip_n - 1u];
                memset(r, 0, sizeof *r);
                memcpy(r->ip, value.p, half);
                memcpy(r->mask, value.p + half, half);
                r->len = half;
            }
            break;
        }
        case 0x81: /* rfc822Name */
            if (!ia5(value.p, value.n))
                return fail_constraint_ia5(e, value.p, value.n);
            if (memchr(value.p, '@', value.n) != NULL ? !mailbox_ok(x->go127, value.p, value.n)
                                                      : !domain_valid(value.p, value.n, 1))
                return fail_q(e, LC_GO("x509: failed to parse rfc822Name constraint %q"), value.p,
                              value.n);
            if (to != NULL && list_push(to->email, value) != 0)
                return -2;
            break;
        case 0x86: /* uniformResourceIdentifier */
            if (!ia5(value.p, value.n))
                return fail_constraint_ia5(e, value.p, value.n);
            if (lc_net_parse_ip_ok((const char *)value.p, value.n))
                return fail_q(e, LC_GO("x509: failed to parse URI constraint %q: cannot be IP address"),
                              value.p, value.n);
            if (!domain_valid(value.p, value.n, 1))
                return fail_q(e, LC_GO("x509: failed to parse URI constraint %q"), value.p, value.n);
            if (to != NULL && list_push(to->uri, value) != 0)
                return -2;
            break;
        default:
            *unhandled = 1;
            break;
        }
    }
    return 0;
}

/* parseNameConstraintsExtension (parser.go:533-670 in go1.26.6, :607-748 in go1.27.1). */
static int name_constraints(px *x, cs value, int *unhandled, lc_obuf *e)
{
    cs  outer = value, top, permitted = { 0 }, excluded = { 0 };
    int have_p = 0, have_e = 0;
    if (!read(&outer, &top, T_SEQUENCE) || outer.n != 0u ||
        !read_optional(&top, &permitted, &have_p, 0xa0u) ||
        !read_optional(&top, &excluded, &have_e, 0xa1u) || top.n != 0u)
        return fail(e, LC_GO("x509: invalid NameConstraints extension"));
    if ((!have_p && !have_e) || (permitted.n == 0u && excluded.n == 0u))
        return fail(e, LC_GO("x509: empty name constraints extension"));
    lc_gocert *c = x->out;
    nc_lists   p = { 0 }, ex = { 0 };
    if (c != NULL) {
        p = (nc_lists){ &c->permitted_dns, &c->permitted_email, &c->permitted_uri, &c->permitted_ip,
                        &c->permitted_ip_n };
        ex = (nc_lists){ &c->excluded_dns, &c->excluded_email, &c->excluded_uri, &c->excluded_ip,
                         &c->excluded_ip_n };
    }
    int rc = nc_subtrees(x, permitted, c != NULL ? &p : NULL, unhandled, e);
    return rc != 0 ? rc : nc_subtrees(x, excluded, c != NULL ? &ex : NULL, unhandled, e);
}

/* The URI of a SAN, for the constraint check: its Host and its String(). */
static int keep_uri(lc_gocert *c, const lc_url *u)
{
    lc_str s = { 0 };
    if (lc_url_string(u, &s) != 0)
        return -2;
    char *host = dup_bytes(u->host.p != NULL ? u->host.p : "", u->host.n);
    char *str = s.p != NULL ? s.p : dup_bytes("", 0);
    if (host == NULL || str == NULL || grow((void **)&c->uris, &c->uris_n, sizeof *c->uris) != 0) {
        free(host);
        free(str);
        return -2;
    }
    c->uris[c->uris_n - 1u] = (lc_gouri){ host, u->host.n, str, s.n };
    return 0;
}

/* parseSANExtension through forEachSAN (parser.go:382-441 in go1.26.6, :451-515 in go1.27.1):
 * `*names` counts what it kept, which processExtensions needs to know. */
static int san(px *x, cs der, size_t *names, lc_obuf *e)
{
    lc_gocert *c = x->out;
    *names = 0;
    if (!read(&der, &der, T_SEQUENCE))
        return fail(e, LC_GO("x509: invalid subject alternative names"));
    while (der.n > 0u) {
        cs      name;
        uint8_t tag;
        if (!read_any(&der, &name, &tag, 1))
            return fail(e, LC_GO("x509: invalid subject alternative name"));
        switch (tag) {
        case 0x81:
            if (!ia5(name.p, name.n))
                return fail(e, LC_GO("x509: SAN rfc822Name is malformed"));
            if (c != NULL && list_push(&c->email_addresses, name) != 0)
                return -2;
            ++*names;
            break;
        case 0x82:
            if (!ia5(name.p, name.n))
                return fail(e, LC_GO("x509: SAN dNSName is malformed"));
            if (c != NULL && list_push(&c->dns_names, name) != 0)
                return -2;
            ++*names;
            break;
        case 0x86: {
            if (!ia5(name.p, name.n))
                return fail(e, LC_GO("x509: SAN uniformResourceIdentifier is malformed"));
            lc_url  u = { 0 };
            lc_obuf why = { 0 };
            int     urc = lc_url_parse_why((const char *)name.p, name.n, &u, &why);
            int     rc = 0;
            if (urc == LC_URL_NOMEM || why.oom) {
                rc = -2;
            } else if (urc != 0) {
                char *q = quoted(name.p, name.n);
                if (q == NULL)
                    rc = -2;
                else
                    rc = failf(e, LC_GO("x509: cannot parse URI %q: %s"), q, why.p != NULL ? why.p : "");
                free(q);
            } else if (u.host.n > 0u && !domain_valid((const uint8_t *)u.host.p, u.host.n, 0)) {
                rc = fail_q(e, LC_GO("x509: cannot parse URI %q: invalid domain"), name.p, name.n);
            } else if (c != NULL) {
                rc = keep_uri(c, &u);
            }
            free(why.p);
            lc_url_free(&u);
            if (rc != 0)
                return rc;
            ++*names;
            break;
        }
        case 0x87:
            if (name.n != 4u && name.n != 16u) {
                char num[24];
                snprintf(num, sizeof num, "%zu", name.n);
                fail(e, LC_GO("x509: cannot parse IP address of length "));
                return fail(e, num); /* + strconv.Itoa(len(data)) */
            }
            if (x->go127 && name.n == 16u && v4_mapped(name.p))
                return fail(e, LC_GO("x509: SAN iPAddress contains IPv4-mapped IPv6 address"));
            if (c != NULL && list_push(&c->ip_addresses, name) != 0)
                return -2;
            ++*names;
            break;
        default:
            break;
        }
    }
    return 0;
}

/* newOIDFromDER (GOROOT/src/crypto/x509/oid.go:33-52). */
static int oid_der_ok(cs b)
{
    if (b.n == 0u || (b.p[b.n - 1u] & 0x80u) != 0u)
        return 0;
    size_t start = 0;
    for (size_t i = 0; i < b.n; i++) {
        if (i == start && b.p[i] == 0x80u)
            return 0;
        if ((b.p[i] & 0x80u) == 0u)
            start = i + 1u;
    }
    return 1;
}

static const uint8_t OID_AIA[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01 };

/* The ExtKeyUsage an OID names, Go's numbering (extKeyUsageOIDs, x509.go:722-739 in go1.27.1), or
 * -1 for one it does not know. */
static int ext_key_usage(cs oid)
{
    static const struct {
        uint8_t n, der[10];
    } known[] = {
        { 4, { 0x55, 0x1d, 0x25, 0x00 } },                                      /* any */
        { 8, { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 } },              /* serverAuth */
        { 8, { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02 } },              /* clientAuth */
        { 8, { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03 } },              /* codeSigning */
        { 8, { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04 } },              /* emailProtection */
        { 8, { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x05 } },              /* ipsecEndSystem */
        { 8, { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x06 } },              /* ipsecTunnel */
        { 8, { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x07 } },              /* ipsecUser */
        { 8, { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08 } },              /* timeStamping */
        { 8, { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09 } },              /* OCSPSigning */
        { 10, { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0a, 0x03, 0x03 } }, /* msSGC */
        { 9, { 0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x04, 0x01 } },        /* nsSGC */
        { 10, { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x16 } }, /* msCodeCom */
        { 10, { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3d, 0x01, 0x01 } }, /* msKernelCode */
    };
    for (size_t i = 0; i < sizeof known / sizeof known[0]; i++)
        if (oid_is(oid, known[i].der, known[i].n))
            return (int)i;
    return -1;
}

/* One extension, as processExtensions reads it (parser.go:672-882 in go1.26.6, :750-960 in
 * go1.27.1): the words when it does not parse, the fields when somebody wants them, and
 * `*unhandled` for what goes on UnhandledCriticalExtensions if it is critical. */
static int process_extension(px *x, cs id, int critical, cs value, int *unhandled, lc_obuf *e)
{
    lc_gocert *c = x->out;
    uint32_t   comp[5];
    size_t     nc = oid_components(id, comp, 5);
    *unhandled = 0;
    if (nc == 4u && comp[0] == 2u && comp[1] == 5u && comp[2] == 29u) {
        cs v = value;
        switch (comp[3]) {
        case 15: { /* key usage: bits 0 to 8, BitString.At */
            cs     bytes;
            size_t bits;
            if (!read_bits(&v, &bytes, &bits))
                return fail(e, LC_GO("x509: invalid key usage"));
            if (c != NULL) {
                c->key_usage = 0;
                for (size_t i = 0; i < 9u; i++)
                    if (i < bits && ((unsigned)bytes.p[i / 8u] >> (7u - i % 8u) & 1u) != 0u)
                        c->key_usage |= 1 << i;
            }
            return 0;
        }
        case 19: { /* basic constraints */
            int     ca = 0;
            int64_t max_path = -1;
            if (!read(&v, &v, T_SEQUENCE))
                return fail(e, LC_GO("x509: invalid basic constraints"));
            if (peek(&v, T_BOOLEAN) && !read_bool(&v, &ca))
                return fail(e, LC_GO("x509: invalid basic constraints"));
            if (peek(&v, T_INTEGER)) {
                uint64_t mpl;
                if (!read_gouint(&v, &mpl) || mpl > (GO_INT64 ? (uint64_t)INT64_MAX : (uint64_t)INT32_MAX))
                    return fail(e, LC_GO("x509: invalid basic constraints"));
                max_path = (int64_t)mpl;
            }
            if (c != NULL) {
                c->is_ca = ca;
                c->max_path_len = max_path;
                c->basic_constraints_valid = 1;
                c->max_path_len_zero = max_path == 0;
            }
            return 0;
        }
        case 17: { /* SAN: a critical one that yielded no name is unhandled */
            size_t names;
            int    rc = san(x, v, &names, e);
            if (rc == 0 && names == 0u)
                *unhandled = 1;
            return rc;
        }
        case 30:
            return name_constraints(x, v, unhandled, e);
        case 31: { /* CRL distribution points */
            if (!read(&v, &v, T_SEQUENCE))
                return fail(e, LC_GO("x509: invalid CRL distribution points"));
            while (v.n > 0u) {
                cs  dp, name;
                int present;
                if (!read(&v, &dp, T_SEQUENCE))
                    return fail(e, LC_GO("x509: invalid CRL distribution point"));
                if (!read_optional(&dp, &name, &present, 0xa0u))
                    return fail(e, LC_GO("x509: invalid CRL distribution point"));
                if (!present)
                    continue;
                if (!read(&name, &name, 0xa0u))
                    return fail(e, LC_GO("x509: invalid CRL distribution point"));
                while (name.n > 0u) {
                    cs uri;
                    if (!peek(&name, 0x86u))
                        break;
                    if (!read(&name, &uri, 0x86u))
                        return fail(e, LC_GO("x509: invalid CRL distribution point"));
                }
            }
            return 0;
        }
        case 35: { /* authority key identifier */
            cs akid;
            if (critical)
                return fail(e, LC_GO("x509: authority key identifier incorrectly marked critical"));
            if (!read(&v, &akid, T_SEQUENCE))
                return fail(e, LC_GO("x509: invalid authority key identifier"));
            if (peek(&akid, 0x80u)) {
                if (!read(&akid, &akid, 0x80u))
                    return fail(e, LC_GO("x509: invalid authority key identifier"));
                if (c != NULL)
                    c->authority_key_id = gb(akid);
            } else if (c != NULL) {
                c->authority_key_id = (lc_gobytes){ NULL, 0 };
            }
            return 0;
        }
        case 36: { /* policy constraints */
            int64_t pv;
            if (!read(&v, &v, T_SEQUENCE))
                return fail(e, LC_GO("x509: invalid policy constraints extension"));
            if (peek(&v, 0x80u)) {
                if (!read_int64_tag(&v, &pv, 0x80u))
                    return fail(e, LC_GO("x509: invalid policy constraints extension"));
                if (!GO_INT64 && (pv < INT32_MIN || pv > INT32_MAX))
                    return fail(e, LC_GO("x509: policy constraints requireExplicitPolicy field overflows int"));
                if (c != NULL) {
                    c->require_explicit_policy = pv;
                    c->require_explicit_policy_zero = pv == 0;
                }
            }
            if (peek(&v, 0x81u)) {
                if (!read_int64_tag(&v, &pv, 0x81u))
                    return fail(e, LC_GO("x509: invalid policy constraints extension"));
                if (!GO_INT64 && (pv < INT32_MIN || pv > INT32_MAX))
                    return fail(e, LC_GO("x509: policy constraints inhibitPolicyMapping field overflows int"));
                if (c != NULL) {
                    c->inhibit_policy_mapping = pv;
                    c->inhibit_policy_mapping_zero = pv == 0;
                }
            }
            return 0;
        }
        case 37: { /* extended key usage */
            if (!read(&v, &v, T_SEQUENCE))
                return fail(e, LC_GO("x509: invalid extended key usages"));
            if (c != NULL) {
                free(c->ext_key_usage);
                c->ext_key_usage = NULL;
                c->ext_key_usage_n = 0;
                c->unknown_ext_key_usage_n = 0;
            }
            while (v.n > 0u) {
                cs eku;
                if (!read_oid(&v, &eku))
                    return fail(e, LC_GO("x509: invalid extended key usages"));
                if (c == NULL)
                    continue;
                int known = ext_key_usage(eku);
                if (known < 0) {
                    c->unknown_ext_key_usage_n++;
                } else {
                    if (grow((void **)&c->ext_key_usage, &c->ext_key_usage_n, sizeof(int)) != 0)
                        return -2;
                    c->ext_key_usage[c->ext_key_usage_n - 1u] = known;
                }
            }
            return 0;
        }
        case 14: { /* subject key identifier */
            cs skid;
            if (critical)
                return fail(e, LC_GO("x509: subject key identifier incorrectly marked critical"));
            if (!read(&v, &skid, T_OCTETS))
                return fail(e, LC_GO("x509: invalid subject key identifier"));
            if (c != NULL)
                c->subject_key_id = gb(skid);
            return 0;
        }
        case 32: { /* certificate policies: no OID twice, each one newOIDFromDER takes */
            if (!read(&v, &v, T_SEQUENCE))
                return fail(e, LC_GO("x509: invalid certificate policies"));
            cs all = v;
            if (c != NULL)
                c->policies.n = 0;
            while (v.n > 0u) {
                cs cp, oid;
                if (!read(&v, &cp, T_SEQUENCE) || !read(&cp, &oid, T_OID))
                    return fail(e, LC_GO("x509: invalid certificate policies"));
                /* seenOIDs: the same bytes in an earlier policy */
                cs before = all;
                while (before.p < oid.p) {
                    cs pcp, poid;
                    if (!read(&before, &pcp, T_SEQUENCE) || !read(&pcp, &poid, T_OID) ||
                        poid.p >= oid.p)
                        break;
                    if (poid.n == oid.n && memcmp(poid.p, oid.p, oid.n) == 0)
                        return fail(e, LC_GO("x509: invalid certificate policies"));
                }
                if (!oid_der_ok(oid))
                    return fail(e, LC_GO("x509: invalid certificate policies"));
                if (c != NULL && list_push(&c->policies, oid) != 0)
                    return -2;
            }
            return 0;
        }
        case 33: { /* policy mappings */
            if (!read(&v, &v, T_SEQUENCE))
                return fail(e, LC_GO("x509: invalid policy mappings extension"));
            while (v.n > 0u) {
                cs s, issuer, subject;
                if (!read(&v, &s, T_SEQUENCE) || !read(&s, &issuer, T_OID) || !read(&s, &subject, T_OID))
                    return fail(e, LC_GO("x509: invalid policy mappings extension"));
                if (c != NULL) {
                    if (grow((void **)&c->policy_mappings, &c->policy_mappings_n,
                             sizeof *c->policy_mappings) != 0)
                        return -2;
                    c->policy_mappings[c->policy_mappings_n - 1u] =
                        (lc_gopolicymap){ gb(issuer), gb(subject) };
                }
            }
            return 0;
        }
        case 54: { /* inhibit any policy */
            int64_t ia;
            if (!read_goint(&v, &ia))
                return fail(e, LC_GO("x509: invalid inhibit any policy extension"));
            if (c != NULL) {
                c->inhibit_any_policy = ia;
                c->inhibit_any_policy_zero = ia == 0;
            }
            return 0;
        }
        default:
            *unhandled = 1;
            return 0;
        }
    }
    if (oid_is(id, OID_AIA, sizeof OID_AIA)) {
        cs v = value;
        if (critical)
            return fail(e, LC_GO("x509: authority info access incorrectly marked critical"));
        if (!read(&v, &v, T_SEQUENCE))
            return fail(e, LC_GO("x509: invalid authority info access"));
        while (v.n > 0u) {
            cs aia, method;
            if (!read(&v, &aia, T_SEQUENCE))
                return fail(e, LC_GO("x509: invalid authority info access"));
            if (!read_oid(&aia, &method))
                return fail(e, LC_GO("x509: invalid authority info access"));
            if (!peek(&aia, 0x86u))
                continue;
            if (!read(&aia, &aia, 0x86u))
                return fail(e, LC_GO("x509: invalid authority info access"));
        }
        return 0;
    }
    *unhandled = 1;
    return 0;
}

/* parseExtension (parser.go:231-247). */
static int parse_extension(cs der, cs *id, int *critical, cs *value, lc_obuf *e)
{
    *critical = 0;
    if (!read_oid(&der, id))
        return fail(e, LC_GO("x509: malformed extension OID field"));
    if (peek(&der, T_BOOLEAN) && !read_bool(&der, critical))
        return fail(e, LC_GO("x509: malformed extension critical field"));
    if (!read(&der, value, T_OCTETS))
        return fail(e, LC_GO("x509: malformed extension value field"));
    return 0;
}

/* The extensions block (parser.go:1030-1063 in go1.26.6, :1109-1140 in go1.27.1): every extension
 * read and checked against the ones before it, and only then each processed, in order. */
static int extensions(px *x, cs block, lc_obuf *e)
{
    cs list = block;
    while (list.n > 0u) {
        cs  ext, id, value;
        int critical;
        if (!read(&list, &ext, T_SEQUENCE))
            return fail(e, LC_GO("x509: malformed extension"));
        if (parse_extension(ext, &id, &critical, &value, e) != 0)
            return -1;
        cs before = block;
        while (before.p < ext.p) {
            cs pext, pid, pvalue;
            int pcrit;
            if (!read(&before, &pext, T_SEQUENCE) || pext.p >= ext.p ||
                parse_extension(pext, &pid, &pcrit, &pvalue, NULL) != 0)
                break;
            if (pid.n == id.n && memcmp(pid.p, id.p, id.n) == 0) {
                lc_obuf s = { 0 };
                oid_string(&s, id);
                int rc = s.oom ? -2 : fail_q(e, LC_GO("x509: certificate contains duplicate extension with OID %q"),
                                             (const uint8_t *)s.p, s.n);
                free(s.p);
                return rc;
            }
        }
    }
    lc_gocert *c = x->out;
    list = block;
    while (list.n > 0u) {
        cs  ext, id, value;
        int critical, unhandled, rc;
        read(&list, &ext, T_SEQUENCE);
        parse_extension(ext, &id, &critical, &value, NULL);
        if ((rc = process_extension(x, id, critical, value, &unhandled, e)) != 0)
            return rc;
        if (c == NULL)
            continue;
        uint32_t comp[5];
        if (oid_components(id, comp, 5) == 4u && comp[0] == 2u && comp[1] == 5u && comp[2] == 29u) {
            if (comp[3] == 17u) { /* hasSANExtension, and the value alreadyInChain compares */
                c->has_san = 1;
                c->san_value = gb(value);
            } else if (comp[3] == 30u) {
                c->has_name_constraints = 1;
            }
        }
        if (critical && unhandled)
            c->unhandled_critical++;
    }
    return 0;
}

/* ---- the signature algorithm ------------------------------------------------------------------- */

/* x509.SignatureAlgorithm, Go's numbering (x509.go:224-246 in go1.27.1). */
enum {
    SA_UNKNOWN = 0, SA_MD2_RSA, SA_MD5_RSA, SA_SHA1_RSA, SA_SHA256_RSA, SA_SHA384_RSA,
    SA_SHA512_RSA, SA_DSA_SHA1, SA_DSA_SHA256, SA_ECDSA_SHA1, SA_ECDSA_SHA256, SA_ECDSA_SHA384,
    SA_ECDSA_SHA512, SA_SHA256_PSS, SA_SHA384_PSS, SA_SHA512_PSS, SA_ED25519, SA_MLDSA44,
    SA_MLDSA65, SA_MLDSA87,
};

static const uint8_t OID_RSAPSS[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a };
static const uint8_t OID_MGF1[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08 };
static const uint8_t OID_SHA256[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
static const uint8_t OID_SHA384[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 };
static const uint8_t OID_SHA512[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };

/* signatureAlgorithmDetails (x509.go:376-404 in go1.27.1), in its order: the first entry whose OID
 * matches names the algorithm. */
static const struct {
    int     algo;
    uint8_t n, der[9];
} sig_details[] = {
    { SA_MD5_RSA, 9, { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04 } },
    { SA_SHA1_RSA, 9, { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05 } },
    { SA_SHA1_RSA, 5, { 0x2b, 0x0e, 0x03, 0x02, 0x1d } },
    { SA_SHA256_RSA, 9, { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b } },
    { SA_SHA384_RSA, 9, { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c } },
    { SA_SHA512_RSA, 9, { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d } },
    /* the three RSA-PSS entries share an OID and are told apart by getSignatureAlgorithmFromAI */
    { SA_DSA_SHA1, 7, { 0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x03 } },
    { SA_DSA_SHA256, 9, { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x02 } },
    { SA_ECDSA_SHA1, 7, { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01 } },
    { SA_ECDSA_SHA256, 8, { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 } },
    { SA_ECDSA_SHA384, 8, { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03 } },
    { SA_ECDSA_SHA512, 8, { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04 } },
    { SA_ED25519, 3, { 0x2b, 0x65, 0x70 } },
    { SA_MLDSA44, 9, { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11 } },
    { SA_MLDSA65, 9, { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12 } },
    { SA_MLDSA87, 9, { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13 } },
};

/* ---- encoding/asn1, as asn1.Unmarshal reads pssParameters --------------------------------------
 *
 * getSignatureAlgorithmFromAI reads RSA-PSS's parameters with encoding/asn1 (x509.go:458-466), not
 * with cryptobyte, and encoding/asn1 has rules of its own (GOROOT/src/encoding/asn1/asn1.go):
 * high tag numbers, a SEQUENCE may carry elements after the last field, and an EXPLICIT wrapper's
 * length is looked at only to see that it is not zero — the element inside is measured against
 * what encloses the wrapper, not against the wrapper. */

typedef struct {
    int    cls, tag, compound;
    size_t len;
} a1tl;

/* parseBase128Int (asn1.go:301-334). */
static int a1_base128(const uint8_t *b, size_t n, size_t *off, int64_t *out)
{
    int64_t ret = 0;
    for (int shifted = 0; *off < n; shifted++) {
        if (shifted == 5)
            return 0;
        ret <<= 7;
        uint8_t c = b[*off];
        if (shifted == 0 && c == 0x80u)
            return 0;
        ret |= c & 0x7f;
        (*off)++;
        if ((c & 0x80u) == 0u) {
            *out = ret;
            return ret <= INT32_MAX;
        }
    }
    return 0;
}

/* parseTagAndLength (asn1.go:555-631). */
static int a1_tag_length(const uint8_t *b, size_t n, size_t *off, a1tl *t)
{
    if (*off >= n)
        return 0;
    uint8_t c = b[(*off)++];
    t->cls = c >> 6;
    t->compound = (c & 0x20u) != 0u;
    t->tag = c & 0x1f;
    if (t->tag == 0x1f) {
        int64_t v;
        if (!a1_base128(b, n, off, &v) || v < 0x1f)
            return 0;
        t->tag = (int)v;
    }
    if (*off >= n)
        return 0;
    c = b[(*off)++];
    if ((c & 0x80u) == 0u) {
        t->len = c & 0x7fu;
        return 1;
    }
    unsigned nb = c & 0x7fu;
    if (nb == 0u)
        return 0;
    size_t len = 0;
    for (unsigned i = 0; i < nb; i++) {
        if (*off >= n || len >= (1u << 23))
            return 0;
        len = len << 8 | b[(*off)++];
        if (len == 0u)
            return 0;
    }
    if (len < 0x80u)
        return 0;
    t->len = len;
    return 1;
}

enum { A1_OK, A1_ABSENT, A1_ERR };

/* parseField's framing (asn1.go:710-893) for one field: an optional EXPLICIT tag, then a universal
 * `tag` (any at all when -1) of the given constructedness; `inner` is the contents. A1_ABSENT for
 * an optional field that is not there, which leaves the offset where it was. */
static int a1_field(const uint8_t *b, size_t n, size_t *off, int explicit_tag, int optional, int tag,
                    int compound, cs *inner)
{
    size_t start = *off;
    if (*off == n)
        return optional ? A1_ABSENT : A1_ERR;
    a1tl t;
    if (!a1_tag_length(b, n, off, &t))
        return A1_ERR;
    if (explicit_tag >= 0) {
        if (*off == n)
            return A1_ERR; /* "explicit tag has no child" */
        if (t.cls == 2 && t.tag == explicit_tag && (t.len == 0u || t.compound)) {
            if (t.len == 0u)
                return A1_ERR; /* "zero length explicit tag was not an asn1.Flag" */
            if (!a1_tag_length(b, n, off, &t))
                return A1_ERR;
        } else {
            if (!optional)
                return A1_ERR;
            *off = start;
            return A1_ABSENT;
        }
    }
    if (tag >= 0 && (t.cls != 0 || t.tag != tag || t.compound != compound)) {
        if (!optional)
            return A1_ERR;
        *off = start;
        return A1_ABSENT;
    }
    if (*off + t.len < *off || *off + t.len > n)
        return A1_ERR;
    *inner = (cs){ b + *off, t.len };
    *off += t.len;
    return A1_OK;
}

/* parseObjectIdentifier's verdict (asn1.go:251-292): the contents are then the OID. */
static int a1_oid_ok(cs c)
{
    if (c.n == 0u)
        return 0;
    size_t  off = 0;
    int64_t v;
    while (off < c.n)
        if (!a1_base128(c.p, c.n, &off, &v))
            return 0;
    return 1;
}

/* An int field: parseInt64, or parseInt32 where Go's int is 32 bits (asn1.go:82-136, :944-958). */
static int a1_int(cs c, int64_t *out)
{
    if (!int_ok(c) || c.n > 8u)
        return 0;
    uint64_t v = (c.p[0] & 0x80u) ? UINT64_MAX : 0u;
    for (size_t i = 0; i < c.n; i++)
        v = v << 8 | c.p[i];
    *out = (int64_t)v;
    return GO_INT64 || (*out >= INT32_MIN && *out <= INT32_MAX);
}

/* pkix.AlgorithmIdentifier: the OID, and Parameters as the whole element when there is one. */
static int a1_algorithm_identifier(cs seq, cs *oid, cs *params)
{
    size_t off = 0;
    if (a1_field(seq.p, seq.n, &off, -1, 0, 6, 0, oid) != A1_OK || !a1_oid_ok(*oid))
        return 0;
    size_t start = off;
    cs     body;
    int    r = a1_field(seq.p, seq.n, &off, -1, 1, -1, 0, &body);
    if (r == A1_ERR)
        return 0;
    *params = r == A1_OK ? (cs){ seq.p + start, off - start } : (cs){ NULL, 0 };
    return 1; /* elements after these two are allowed */
}

/* asn1.Unmarshal of a whole element into an AlgorithmIdentifier. */
static int a1_unmarshal_ai(cs full, cs *oid, cs *params)
{
    size_t off = 0;
    cs     seq;
    return a1_field(full.p, full.n, &off, -1, 0, 16, 1, &seq) == A1_OK &&
           a1_algorithm_identifier(seq, oid, params);
}

static int null_or_absent(cs params)
{
    return params.n == 0u || (params.n == 2u && params.p[0] == 0x05u && params.p[1] == 0u);
}

/* getSignatureAlgorithmFromAI (x509.go:433-492 in go1.27.1). */
static int sig_algorithm(cs oid, cs params)
{
    for (size_t i = 0; i < sizeof sig_details / sizeof sig_details[0]; i++) {
        int a = sig_details[i].algo;
        if ((a == SA_ED25519 || a >= SA_MLDSA44) && oid_is(oid, sig_details[i].der, sig_details[i].n) &&
            params.n != 0u)
            return SA_UNKNOWN;
    }
    if (!oid_is(oid, OID_RSAPSS, sizeof OID_RSAPSS)) {
        for (size_t i = 0; i < sizeof sig_details / sizeof sig_details[0]; i++)
            if (oid_is(oid, sig_details[i].der, sig_details[i].n))
                return sig_details[i].algo;
        return SA_UNKNOWN;
    }

    /* pssParameters: Hash [0] EXPLICIT, MGF [1] EXPLICIT, SaltLength [2] EXPLICIT, TrailerField
     * [3] EXPLICIT OPTIONAL DEFAULT 1 */
    cs      seq, f, hash_oid, hash_params, mgf_oid, mgf_params, mgf_hash, mgf_hash_params;
    size_t  off = 0, in = 0;
    int64_t salt, trailer = 1;
    if (a1_field(params.p, params.n, &off, -1, 0, 16, 1, &seq) != A1_OK)
        return SA_UNKNOWN;
    if (a1_field(seq.p, seq.n, &in, 0, 0, 16, 1, &f) != A1_OK ||
        !a1_algorithm_identifier(f, &hash_oid, &hash_params))
        return SA_UNKNOWN;
    if (a1_field(seq.p, seq.n, &in, 1, 0, 16, 1, &f) != A1_OK ||
        !a1_algorithm_identifier(f, &mgf_oid, &mgf_params))
        return SA_UNKNOWN;
    if (a1_field(seq.p, seq.n, &in, 2, 0, 2, 0, &f) != A1_OK || !a1_int(f, &salt))
        return SA_UNKNOWN;
    int r = a1_field(seq.p, seq.n, &in, 3, 1, 2, 0, &f);
    if (r == A1_ERR || (r == A1_OK && !a1_int(f, &trailer)))
        return SA_UNKNOWN;
    if (!a1_unmarshal_ai(mgf_params, &mgf_hash, &mgf_hash_params))
        return SA_UNKNOWN;

    if (!null_or_absent(hash_params) || !oid_is(mgf_oid, OID_MGF1, sizeof OID_MGF1) ||
        mgf_hash.n != hash_oid.n || memcmp(mgf_hash.p, hash_oid.p, hash_oid.n) != 0 ||
        !null_or_absent(mgf_hash_params) || trailer != 1)
        return SA_UNKNOWN;
    if (oid_is(hash_oid, OID_SHA256, sizeof OID_SHA256) && salt == 32)
        return SA_SHA256_PSS;
    if (oid_is(hash_oid, OID_SHA384, sizeof OID_SHA384) && salt == 48)
        return SA_SHA384_PSS;
    if (oid_is(hash_oid, OID_SHA512, sizeof OID_SHA512) && salt == 64)
        return SA_SHA512_PSS;
    return SA_UNKNOWN;
}

/* ---- the certificate ---------------------------------------------------------------------------- */

/* parseCertificate and ParseCertificate (parser.go:886-1087 in go1.26.6, :964-1167 in go1.27.1). */
static int parse_certificate(px *x, cs der, size_t *rsa_bits, lc_obuf *e)
{
    lc_gocert *c = x->out;
    cs         input = der, raw, tbs, tbs_el, seq;
    if (!read_element(&input, &raw, T_SEQUENCE))
        return fail(e, LC_GO("x509: malformed certificate"));
    input = raw;
    if (!read(&input, &input, T_SEQUENCE))
        return fail(e, LC_GO("x509: malformed certificate"));
    if (!read_element(&input, &tbs, T_SEQUENCE))
        return fail(e, LC_GO("x509: malformed tbs certificate"));
    tbs_el = tbs;
    if (!read(&tbs, &tbs, T_SEQUENCE))
        return fail(e, LC_GO("x509: malformed tbs certificate"));

    /* ReadOptionalASN1Integer(&cert.Version, [0] EXPLICIT, 0) */
    int64_t version = 0;
    int     present;
    cs      vfield;
    if (!read_optional(&tbs, &vfield, &present, 0xa0u) ||
        (present && (!read_goint(&vfield, &version) || vfield.n != 0u)))
        return fail(e, LC_GO("x509: malformed version"));
    if (version < 0)
        return fail(e, LC_GO("x509: malformed version"));
    version++;
    if (version > 3)
        return fail(e, LC_GO("x509: invalid version"));

    int serial;
    cs  serial_mag;
    if (!read_big(&tbs, &serial, &serial_mag))
        return fail(e, LC_GO("x509: malformed serial number"));
    if (serial < 0)
        return fail(e, LC_GO("x509: negative serial number"));

    /* go1.27.1 reads the inner identifier as an element first, to keep RawSignatureAlgorithm
     * (parser.go:1016-1023): the same test and the same words. */
    cs sig_ai, outer_ai, oid, params;
    if (!read(&tbs, &sig_ai, T_SEQUENCE))
        return fail(e, LC_GO("x509: malformed signature algorithm identifier"));
    if (!read(&input, &outer_ai, T_SEQUENCE))
        return fail(e, LC_GO("x509: malformed algorithm identifier"));
    if (outer_ai.n != sig_ai.n || memcmp(outer_ai.p, sig_ai.p, sig_ai.n) != 0)
        return fail(e, LC_GO("x509: inner and outer signature algorithm identifiers don't match"));
    if (parse_ai(sig_ai, &oid, &params, e) != 0)
        return -1;
    if (c != NULL) {
        c->tbs = gb(tbs_el);
        c->version = version;
        c->serial = gb(serial_mag);
        c->sig_alg = sig_algorithm(oid, params);
    }

    int rc;
    if (!read_element(&tbs, &seq, T_SEQUENCE))
        return fail(e, LC_GO("x509: malformed issuer"));
    if (c != NULL)
        c->raw_issuer = gb(seq);
    if ((rc = parse_name(x, seq, 0, e)) != 0)
        return rc;
    if (!read(&tbs, &seq, T_SEQUENCE))
        return fail(e, LC_GO("x509: malformed validity"));
    gotime nb, na;
    if ((rc = parse_time(&seq, &nb, e)) != 0 || (rc = parse_time(&seq, &na, e)) != 0)
        return rc;
    if (c != NULL) {
        c->not_before = nb.unix;
        c->not_before_off = nb.off;
        c->not_before_utc = nb.utc;
        c->not_after = na.unix;
        c->not_after_off = na.off;
        c->not_after_utc = na.utc;
    }
    if (!read_element(&tbs, &seq, T_SEQUENCE))
        return fail(e, LC_GO("x509: malformed issuer"));
    if (c != NULL)
        c->raw_subject = gb(seq);
    if ((rc = parse_name(x, seq, 1, e)) != 0)
        return rc;

    cs spki, pk_ai, bits;
    if (!read_element(&tbs, &spki, T_SEQUENCE))
        return fail(e, LC_GO("x509: malformed spki"));
    if (c != NULL)
        c->raw_spki = gb(spki);
    if (!read(&spki, &spki, T_SEQUENCE))
        return fail(e, LC_GO("x509: malformed spki"));
    if (!read(&spki, &pk_ai, T_SEQUENCE))
        return fail(e, LC_GO("x509: malformed public key algorithm identifier"));
    if (parse_ai(pk_ai, &oid, &params, e) != 0)
        return -1;
    size_t bitlen;
    if (!read_bits(&spki, &bits, &bitlen))
        return fail(e, LC_GO("x509: malformed subjectPublicKey"));
    *rsa_bits = 0;
    int alg = pk_algorithm(x, oid);
    if (c != NULL)
        c->pk_alg = alg;
    if (alg != LC_GO_PK_UNKNOWN) {
        uint8_t *buf = malloc(bits.n ? bits.n : 1u);
        if (buf == NULL)
            return -2;
        cs key = right_align(bits, bitlen, buf);
        if (c != NULL && key.p != buf) {
            memcpy(buf, key.p, key.n);
            key.p = buf;
        }
        rc = parse_public_key(x, oid, params, key, rsa_bits, e);
        if (c != NULL && rc == 0) {
            c->key = buf;
            c->key_n = key.n;
            c->pk_present = 1;
        } else {
            free(buf);
        }
        if (rc != 0)
            return rc;
    }

    if (version > 1) {
        if (!skip_optional(&tbs, 0x81u))
            return fail(e, LC_GO("x509: malformed issuerUniqueID"));
        if (!skip_optional(&tbs, 0x82u))
            return fail(e, LC_GO("x509: malformed subjectUniqueID"));
        if (version == 3) {
            cs block;
            if (!read_optional(&tbs, &block, &present, 0xa3u))
                return fail(e, LC_GO("x509: malformed extensions"));
            if (present) {
                if (!read(&block, &block, T_SEQUENCE))
                    return fail(e, LC_GO("x509: malformed extensions"));
                if ((rc = extensions(x, block, e)) != 0)
                    return rc;
            }
        }
    }

    cs     sig;
    size_t siglen;
    if (!read_bits(&input, &sig, &siglen))
        return fail(e, LC_GO("x509: malformed signature"));
    if (c != NULL) {
        c->signature = malloc(sig.n ? sig.n : 1u);
        if (c->signature == NULL)
            return -2;
        cs aligned = right_align(sig, siglen, c->signature);
        if (aligned.p != c->signature && aligned.n != 0u)
            memcpy(c->signature, aligned.p, aligned.n);
        c->signature_n = aligned.n;
    }
    if (raw.n != der.n)
        return fail(e, LC_GO("x509: trailing data"));
    return 0;
}

int lc_x509_go_parse(const uint8_t *der, size_t len, size_t *rsa_bits, lc_obuf *err)
{
    px     x = { 0, NULL };
    size_t bits = 0;
    int    rc = parse_certificate(&x, (cs){ der, len }, &bits, err);
    if (rsa_bits != NULL)
        *rsa_bits = rc == 0 ? bits : 0u;
    if (rc == -2 && err != NULL)
        err->oom = 1;
    return rc == 0 ? 0 : -1;
}

void lc_gocert_free(lc_gocert *c)
{
    if (c == NULL)
        return;
    free(c->raw);
    free(c->signature);
    free(c->key);
    free(c->subject_cn);
    free(c->subject_o);
    free(c->ext_key_usage);
    free(c->dns_names.a);
    free(c->email_addresses.a);
    free(c->ip_addresses.a);
    for (size_t i = 0; i < c->uris_n; i++) {
        free(c->uris[i].host);
        free(c->uris[i].string);
    }
    free(c->uris);
    free(c->permitted_dns.a);
    free(c->excluded_dns.a);
    free(c->permitted_email.a);
    free(c->excluded_email.a);
    free(c->permitted_uri.a);
    free(c->excluded_uri.a);
    free(c->permitted_ip);
    free(c->excluded_ip);
    free(c->policies.a);
    free(c->policy_mappings);
    memset(c, 0, sizeof *c);
}

int lc_x509_go_parse_fields(int go127, const uint8_t *der, size_t len, lc_gocert *out, size_t *rsa_bits,
                            lc_obuf *err)
{
    size_t bits = 0;
    int    rc;
    if (out == NULL) {
        px x = { go127, NULL };
        rc = parse_certificate(&x, (cs){ der, len }, &bits, err);
    } else {
        memset(out, 0, sizeof *out);
        out->max_path_len = -1;
        out->raw = malloc(len ? len : 1u);
        if (out->raw == NULL) {
            rc = -2;
        } else {
            if (len != 0u)
                memcpy(out->raw, der, len);
            px x = { go127, out };
            rc = parse_certificate(&x, (cs){ out->raw, len }, &bits, err);
            /* Raw is the certificate's own element, which ParseCertificate insists is all of `der` */
            out->raw_n = len;
        }
        if (rc != 0)
            lc_gocert_free(out);
    }
    if (rsa_bits != NULL)
        *rsa_bits = rc == 0 ? bits : 0u;
    if (rc == -2 && err != NULL)
        err->oom = 1;
    return rc == 0 ? 0 : -1;
}

int lc_x509_go127_parse(const uint8_t *der, size_t len, lc_gocert *out, size_t *rsa_bits, lc_obuf *err)
{
    return lc_x509_go_parse_fields(1, der, len, out, rsa_bits, err);
}
