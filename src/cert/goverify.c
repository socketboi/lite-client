/* x509.Certificate.Verify of go1.27.1 — see cert/goverify.h. Each function names what it
 * transcribes; paths without a directory are in GOROOT/src/crypto/x509/. */
#include "cert/goverify.h"

#include "cert/gosig.h"
#include "cert/x509go.h"
#include "core/goquote.h"
#include "core/netip.h"
#include "tls/goerr.h"

#include <mbedtls/bignum.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ---- words -------------------------------------------------------------------------------------- */

static void put(lc_obuf *b, const char *s)
{
    lc_obuf_add(b, s, strlen(s));
}

static void putn(lc_obuf *b, const void *s, size_t n)
{
    lc_obuf_add(b, s, n);
}

static void put_int(lc_obuf *b, long long v)
{
    char num[24];
    int  n = snprintf(num, sizeof num, "%lld", v);
    lc_obuf_add(b, num, (size_t)n);
}

/* %q */
static void put_q(lc_obuf *b, const void *s, size_t n)
{
    lc_go_quote(b, s, n);
}

/* An error: the text, or none (nil). Errors are values here, copied where Go shares them. */
typedef struct {
    int     set;
    int     sig_limit; /* errSignatureLimit, which buildChains compares against */
    lc_obuf text;
} goerr;

static void err_clear(goerr *e)
{
    free(e->text.p);
    memset(e, 0, sizeof *e);
}

static void err_set(goerr *e, const char *text)
{
    err_clear(e);
    e->set = 1;
    put(&e->text, text);
}

static void err_move(goerr *dst, goerr *src)
{
    err_clear(dst);
    *dst = *src;
    memset(src, 0, sizeof *src);
}

static void err_copy(goerr *dst, const goerr *src)
{
    err_clear(dst);
    if (!src->set)
        return;
    dst->set = 1;
    dst->sig_limit = src->sig_limit;
    putn(&dst->text, src->text.p, src->text.n);
    dst->text.oom |= src->text.oom;
}

static int err_oom(const goerr *e)
{
    return e->text.oom;
}

/* ---- time --------------------------------------------------------------------------------------- */

static void civil_from_days(int64_t z, int64_t *y, int *m, int *d)
{
    z += 719468;
    int64_t  era = (z >= 0 ? z : z - 146096) / 146097;
    unsigned doe = (unsigned)(z - era * 146097);
    unsigned yoe = (doe - doe / 1460u + doe / 36524u - doe / 146096u) / 365u;
    unsigned doy = doe - (365u * yoe + yoe / 4u - yoe / 100u);
    unsigned mp = (5u * doy + 2u) / 153u;
    *d = (int)(doy - (153u * mp + 2u) / 5u + 1u);
    *m = (int)(mp < 10u ? mp + 3u : mp - 9u);
    *y = (int64_t)yoe + era * 400 + (*m <= 2);
}

/* Format(time.RFC3339) of an instant in a zone: "2006-01-02T15:04:05Z07:00". */
static void put_rfc3339(lc_obuf *b, int64_t unix, int32_t off, int utc)
{
    int64_t local = unix + (utc ? 0 : off);
    int64_t day = local >= 0 ? local / 86400 : (local - 86399) / 86400;
    int64_t secs = local - day * 86400;
    int64_t y;
    int     m, d;
    civil_from_days(day, &y, &m, &d);
    char s[64];
    int  n = snprintf(s, sizeof s, "%04lld-%02d-%02dT%02d:%02d:%02d", (long long)y, m, d,
                      (int)(secs / 3600), (int)(secs / 60 % 60), (int)(secs % 60));
    putn(b, s, (size_t)n);
    if (utc) {
        put(b, "Z");
    } else {
        int32_t a = off < 0 ? -off : off;
        n = snprintf(s, sizeof s, "%c%02d:%02d", off < 0 ? '-' : '+', (int)(a / 3600), (int)(a / 60 % 60));
        putn(b, s, (size_t)n);
    }
}

/* ---- net.IP ------------------------------------------------------------------------------------- */

static int is_v4_in_v6(const uint8_t *ip)
{
    static const uint8_t prefix[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
    return memcmp(ip, prefix, 12) == 0;
}

/* net.IP.Equal (GOROOT/src/net/ip.go): four bytes and their v4-mapped sixteen are the same. */
static int ip_equal(const uint8_t *a, size_t an, const uint8_t *b, size_t bn)
{
    if (an == bn)
        return memcmp(a, b, an) == 0;
    if (an == 4u && bn == 16u)
        return is_v4_in_v6(b) && memcmp(a, b + 12, 4) == 0;
    if (an == 16u && bn == 4u)
        return is_v4_in_v6(a) && memcmp(a + 12, b, 4) == 0;
    return 0;
}

/* net.IP.String (GOROOT/src/net/ip.go) of four or sixteen bytes: dotted for IPv4 and v4-mapped,
 * RFC 5952 for the rest — the longest run of two or more zero groups, the first of equals, as
 * "::". */
static void put_ip(lc_obuf *b, const uint8_t *ip, size_t n)
{
    char s[64];
    if (n == 4u || (n == 16u && is_v4_in_v6(ip))) {
        const uint8_t *p = n == 4u ? ip : ip + 12;
        int            k = snprintf(s, sizeof s, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
        putn(b, s, (size_t)k);
        return;
    }
    if (n != 16u) {
        /* "?" followed by the hex of an IP of another length; the parser keeps none */
        put(b, "?");
        return;
    }
    int best = -1, best_len = 0;
    for (int i = 0; i < 8;) {
        if (ip[2 * i] == 0 && ip[2 * i + 1] == 0) {
            int j = i;
            while (j < 8 && ip[2 * j] == 0 && ip[2 * j + 1] == 0)
                j++;
            if (j - i >= 2 && j - i > best_len) {
                best = i;
                best_len = j - i;
            }
            i = j;
        } else {
            i++;
        }
    }
    for (int i = 0; i < 8; i++) {
        if (i == best) {
            put(b, "::");
            i += best_len - 1;
            continue;
        }
        if (i > 0 && i != best + best_len)
            put(b, ":");
        int k = snprintf(s, sizeof s, "%x", (unsigned)(ip[2 * i] << 8 | ip[2 * i + 1]));
        putn(b, s, (size_t)k);
    }
}

/* ---- PEM, as encoding/pem.Decode reads it ------------------------------------------------------- */

/* base64.StdEncoding.Decode (GOROOT/src/encoding/base64/base64.go): '\r' and '\n' skipped, "="
 * padding required and nothing but line breaks after it, bits past the last byte ignored (the
 * encoding is not Strict). 0 with the bytes, -1 for CorruptInputError. */
static int b64_value(uint8_t c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

static int b64_decode(const uint8_t *src, size_t n, uint8_t *dst, size_t *out_n)
{
    size_t si = 0, o = 0;
    while (si < n) {
        /* decodeQuantum */
        int    dbuf[4] = { 0, 0, 0, 0 };
        size_t dlen = 4;
        int    done = 0;
        for (int j = 0; j < 4; j++) {
            if (si == n) {
                if (j == 0) {
                    *out_n = o;
                    return 0;
                }
                return -1; /* j == 1, or padding required */
            }
            uint8_t in = src[si++];
            int     v = b64_value(in);
            if (v >= 0) {
                dbuf[j] = v;
                continue;
            }
            if (in == '\n' || in == '\r') {
                j--;
                continue;
            }
            if (in != '=')
                return -1;
            if (j == 0 || j == 1)
                return -1;
            if (j == 2) {
                while (si < n && (src[si] == '\n' || src[si] == '\r'))
                    si++;
                if (si == n || src[si] != '=')
                    return -1;
                si++;
            }
            while (si < n && (src[si] == '\n' || src[si] == '\r'))
                si++;
            if (si < n)
                return -1;
            dlen = (size_t)j;
            done = 1;
            break;
        }
        unsigned val = (unsigned)dbuf[0] << 18 | (unsigned)dbuf[1] << 12 | (unsigned)dbuf[2] << 6 |
                       (unsigned)dbuf[3];
        uint8_t  bytes[3] = { (uint8_t)(val >> 16), (uint8_t)(val >> 8), (uint8_t)val };
        for (size_t k = 0; k + 1u < dlen; k++)
            dst[o++] = bytes[k];
        if (done)
            break;
    }
    *out_n = o;
    return 0;
}

/* getLine (GOROOT/src/encoding/pem/pem.go): up to '\n', without a '\r' before it, with spaces and
 * tabs trimmed from its end. */
static void get_line(const uint8_t *data, size_t n, size_t *line_n, size_t *consumed)
{
    const uint8_t *nl = memchr(data, '\n', n);
    size_t         i, j;
    if (nl == NULL) {
        i = n;
        j = n;
    } else {
        i = (size_t)(nl - data);
        j = i + 1u;
        if (i > 0u && data[i - 1u] == '\r')
            i--;
    }
    while (i > 0u && (data[i - 1u] == ' ' || data[i - 1u] == '\t'))
        i--;
    *line_n = i;
    *consumed = j;
}

static const uint8_t *find(const uint8_t *h, size_t hn, const char *needle)
{
    size_t nn = strlen(needle);
    for (size_t i = 0; i + nn <= hn; i++)
        if (memcmp(h + i, needle, nn) == 0)
            return h + i;
    return NULL;
}

static const uint8_t *find_last(const uint8_t *h, size_t hn, const char *needle)
{
    size_t nn = strlen(needle);
    if (nn > hn)
        return NULL;
    for (size_t i = hn - nn + 1u; i-- > 0u;)
        if (memcmp(h + i, needle, nn) == 0)
            return h + i;
    return NULL;
}

typedef struct {
    const uint8_t *type;
    size_t         type_n;
    int            headers;
    uint8_t       *bytes; /* heap */
    size_t         bytes_n;
} pem_block;

/* pem.Decode: 1 with a block and `*rest` after it, 0 when there is none, -2 out of memory. The
 * index arithmetic is Go's, including its `continue`s, which go on searching after the END line
 * that failed rather than after the BEGIN line. */
static int pem_decode(const uint8_t *data, size_t n, pem_block *p, size_t *rest_off)
{
    const uint8_t *rest = data;
    size_t         rest_n = n;
    long           end_trailer = 0;
    for (;;) {
        if (end_trailer < 0 || (size_t)end_trailer > rest_n)
            return 0;
        rest += end_trailer;
        rest_n -= (size_t)end_trailer;
        const uint8_t *e = find(rest, rest_n, "\n-----END ");
        if (e == NULL)
            return 0;
        long end_index = (long)(e - rest);
        end_trailer = end_index + 10;
        const uint8_t *bgn = find_last(rest, (size_t)end_index, "-----BEGIN ");
        if (bgn == NULL || (bgn > rest && bgn[-1] != '\n'))
            continue;
        long skip = (long)(bgn - rest) + 11;
        rest += skip;
        rest_n -= (size_t)skip;
        end_index -= skip;
        end_trailer -= skip;

        size_t line_n, consumed;
        get_line(rest, rest_n, &line_n, &consumed);
        const uint8_t *type = rest;
        rest += consumed;
        rest_n -= consumed;
        end_index -= (long)consumed;
        end_trailer -= (long)consumed;
        if (line_n < 5u || memcmp(type + line_n - 5u, "-----", 5) != 0)
            continue;
        size_t type_n = line_n - 5u;

        int headers = 0;
        for (;;) {
            if (rest_n == 0u)
                return 0;
            size_t ln, cons;
            get_line(rest, rest_n, &ln, &cons);
            const uint8_t *colon = memchr(rest, ':', ln);
            if (colon == NULL)
                break;
            /* Headers[TrimSpace(key)] = TrimSpace(val): a map, so it counts as having headers
             * however many lines there were */
            headers = 1;
            rest += cons;
            rest_n -= cons;
            end_index -= (long)cons;
            end_trailer -= (long)cons;
        }
        if (headers && end_index < 0)
            continue;

        if (end_trailer < 0 || (size_t)end_trailer > rest_n)
            return 0; /* rest[endTrailerIndex:] would panic; the headers loop cannot bring it here */
        const uint8_t *trailer = rest + end_trailer;
        size_t         trailer_n = rest_n - (size_t)end_trailer;
        size_t         trailer_len = type_n + 5u;
        if (trailer_n < trailer_len)
            continue;
        if (memcmp(trailer, type, type_n) != 0 || memcmp(trailer + type_n, "-----", 5) != 0)
            continue;
        size_t s_n, s_cons;
        get_line(trailer + trailer_len, trailer_n - trailer_len, &s_n, &s_cons);
        if (s_n != 0u)
            continue;

        uint8_t *bytes = NULL;
        size_t   bytes_n = 0;
        if (end_index > 0) {
            uint8_t *clean = malloc((size_t)end_index);
            if (clean == NULL)
                return -2;
            size_t cn = 0;
            for (long i = 0; i < end_index; i++)
                if (rest[i] != ' ' && rest[i] != '\t')
                    clean[cn++] = rest[i];
            bytes = malloc(cn / 4u * 3u + 3u);
            if (bytes == NULL) {
                free(clean);
                return -2;
            }
            int rc = b64_decode(clean, cn, bytes, &bytes_n);
            free(clean);
            if (rc != 0) {
                free(bytes);
                continue;
            }
        }
        /* _, rest, _ = getLine(rest[endIndex+len(pemEnd)-1:]) */
        size_t after = (size_t)end_index + 9u;
        size_t l2, c2;
        get_line(rest + after, rest_n - after, &l2, &c2);
        *rest_off = (size_t)(rest + after + c2 - data);
        p->type = type;
        p->type_n = type_n;
        p->headers = headers;
        p->bytes = bytes;
        p->bytes_n = bytes_n;
        return 1;
    }
}

/* ---- the pool ------------------------------------------------------------------------------------ */

struct lc_gopool {
    lc_gocert    **certs;
    unsigned char *borrowed; /* the certificate belongs to the caller (lc_go_verify_peer) */
    size_t         n, cap;
};

lc_gopool *lc_gopool_new(void)
{
    return calloc(1, sizeof(lc_gopool));
}

void lc_gopool_free(lc_gopool *p)
{
    if (p == NULL)
        return;
    for (size_t i = 0; i < p->n; i++) {
        if (p->borrowed[i])
            continue;
        lc_gocert_free(p->certs[i]);
        free(p->certs[i]);
    }
    free(p->certs);
    free(p->borrowed);
    free(p);
}

size_t lc_gopool_len(const lc_gopool *p)
{
    return p != NULL ? p->n : 0u;
}

const lc_gocert *lc_gopool_cert(const lc_gopool *p, size_t i)
{
    return p->certs[i];
}

/* haveSum: the same bytes, which is what equal SHA-224 sums stand for. */
static int pool_contains(const lc_gopool *p, const lc_gocert *c)
{
    if (p == NULL)
        return 0;
    for (size_t i = 0; i < p->n; i++)
        if (p->certs[i]->raw_n == c->raw_n && memcmp(p->certs[i]->raw, c->raw, c->raw_n) == 0)
            return 1;
    return 0;
}

static int pool_room(lc_gopool *p)
{
    if (p->n < p->cap)
        return 0;
    size_t         cap = p->cap != 0u ? p->cap * 2u : 16u;
    lc_gocert    **a = realloc(p->certs, cap * sizeof *a);
    if (a != NULL)
        p->certs = a;
    unsigned char *b = a != NULL ? realloc(p->borrowed, cap) : NULL;
    if (b == NULL)
        return -2;
    p->borrowed = b;
    p->cap = cap;
    return 0;
}

/* AddCert of a certificate the caller keeps. */
static int pool_add_borrowed(lc_gopool *p, const lc_gocert *c)
{
    if (pool_contains(p, c))
        return 0;
    if (pool_room(p) != 0)
        return -2;
    p->borrowed[p->n] = 1;
    p->certs[p->n++] = (lc_gocert *)(uintptr_t)c;
    return 0;
}

int lc_gopool_add(lc_gopool *p, lc_gocert *c)
{
    if (pool_contains(p, c)) {
        lc_gocert_free(c);
        return 0;
    }
    if (pool_room(p) != 0) {
        lc_gocert_free(c);
        return -2;
    }
    lc_gocert *own = malloc(sizeof *own);
    if (own == NULL) {
        lc_gocert_free(c);
        return -2;
    }
    *own = *c;
    memset(c, 0, sizeof *c);
    p->borrowed[p->n] = 0;
    p->certs[p->n++] = own;
    return 0;
}

int lc_gopool_append_pem(lc_gopool *p, const uint8_t *pem, size_t n)
{
    int    ok = 0;
    size_t off = 0;
    while (off < n) {
        pem_block b;
        size_t    next;
        int       rc = pem_decode(pem + off, n - off, &b, &next);
        if (rc == -2)
            return -2;
        if (rc == 0)
            break;
        off += next;
        if (b.headers || b.type_n != 11u || memcmp(b.type, "CERTIFICATE", 11) != 0) {
            free(b.bytes);
            continue;
        }
        lc_gocert c;
        lc_obuf   why = { 0 };
        rc = lc_x509_go127_parse(b.bytes != NULL ? b.bytes : (const uint8_t *)"", b.bytes_n, &c,
                                 NULL, &why);
        free(b.bytes);
        int oom = why.oom;
        free(why.p);
        if (rc != 0) {
            if (oom)
                return -2;
            continue;
        }
        if (lc_gopool_add(p, &c) != 0)
            return -2;
        ok = 1;
    }
    return ok;
}

/* ---- system roots (root.go, root_linux.go) ----------------------------------------------------- */

static const char *const go_cert_files[] = {
    "/etc/ssl/certs/ca-certificates.crt",                /* Debian/Ubuntu/Gentoo etc. */
    "/etc/pki/tls/certs/ca-bundle.crt",                  /* Fedora/RHEL 6 */
    "/etc/ssl/ca-bundle.pem",                            /* OpenSUSE */
    "/etc/pki/tls/cacert.pem",                           /* OpenELEC */
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", /* CentOS/RHEL 7 */
    "/etc/ssl/cert.pem",                                 /* Alpine Linux */
    NULL,
};

static const char *const go_cert_dirs[] = {
    "/etc/ssl/certs",     /* SLES10/SLES11 */
    "/etc/pki/tls/certs", /* Fedora/RHEL */
    NULL,
};

static const char *const *cert_files = go_cert_files;
static const char *const *cert_dirs = go_cert_dirs;

/* syscall.Errno.Error() for the errors a read of these files can meet (GOROOT/src/syscall/
 * zerrors_linux_*.go's table, which is not the C library's). */
static const char *go_errno(int e)
{
    switch (e) {
    case EACCES: return "permission denied";
    case EISDIR: return "is a directory";
    case ENOTDIR: return "not a directory";
    case ELOOP: return "too many levels of symbolic links";
    case EIO: return "input/output error";
    case ENAMETOOLONG: return "file name too long";
    case EMFILE: return "too many open files";
    case ENFILE: return "too many open files in system";
    case ENOMEM: return "cannot allocate memory";
    case EPERM: return "operation not permitted";
    case ENXIO: return "no such device or address";
    case ENODEV: return "no such device";
    case EINVAL: return "invalid argument";
    default: return NULL;
    }
}

/* *PathError.Error(): op + " " + path + ": " + err */
static void path_error(lc_obuf *b, const char *op, const char *path, int e)
{
    put(b, op);
    put(b, " ");
    put(b, path);
    put(b, ": ");
    const char *t = go_errno(e);
    if (t != NULL) {
        put(b, t);
    } else {
        put(b, "errno ");
        put_int(b, e);
    }
}

/* os.ReadFile: 0 with the bytes, or the errno and the operation it failed in. */
static int read_file(const char *path, uint8_t **out, size_t *out_n, const char **op)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        *op = "open";
        return errno;
    }
    size_t   cap = 4096, n = 0;
    uint8_t *buf = malloc(cap);
    if (buf == NULL) {
        close(fd);
        *op = "read";
        return ENOMEM;
    }
    for (;;) {
        if (n == cap) {
            uint8_t *nb = realloc(buf, cap * 2u);
            if (nb == NULL) {
                free(buf);
                close(fd);
                *op = "read";
                return ENOMEM;
            }
            buf = nb;
            cap *= 2u;
        }
        ssize_t r = read(fd, buf + n, cap - n);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            int e = errno;
            free(buf);
            close(fd);
            *op = "read";
            return e;
        }
        if (r == 0)
            break;
        n += (size_t)r;
    }
    close(fd);
    *out = buf;
    *out_n = n;
    return 0;
}

static int cmp_names(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* os.ReadDir: the names, sorted (byte order, as Go sorts strings), without "." and "..". */
static int read_dir(const char *dir, char ***out, size_t *out_n, const char **op)
{
    DIR *d = opendir(dir);
    if (d == NULL) {
        int e = errno;
        *op = "open"; /* os.ReadDir opens with O_DIRECTORY: a file fails there, as ENOTDIR */
        return e;
    }
    char **names = NULL;
    size_t n = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        char **nn = realloc(names, (n + 1u) * sizeof *nn);
        char  *name = nn != NULL ? strdup(de->d_name) : NULL;
        if (name == NULL) {
            if (nn != NULL)
                names = nn;
            for (size_t i = 0; i < n; i++)
                free(names[i]);
            free(names);
            closedir(d);
            *op = "readdirent";
            return ENOMEM;
        }
        names = nn;
        names[n++] = name;
    }
    closedir(d);
    qsort(names, n, sizeof *names, cmp_names);
    *out = names;
    *out_n = n;
    return 0;
}

/* isSameDirSymlink: a symbolic link whose target names no directory — another name for a file of
 * the same directory, which ReadDir would otherwise have read twice. */
static int same_dir_symlink(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0 || !S_ISLNK(st.st_mode))
        return 0;
    char    target[4096];
    ssize_t n = readlink(path, target, sizeof target - 1u);
    if (n < 0)
        return 0;
    return memchr(target, '/', (size_t)n) == NULL;
}

/* One candidate file: 0, with `*read_ok` when it was read (whatever it held), or -2. */
static int load_file_into(lc_gopool *roots, const char *path, int *read_ok, int *first_err, lc_obuf *first)
{
    uint8_t    *data;
    size_t      n;
    const char *op;
    int         e = read_file(path, &data, &n, &op);
    if (e == ENOMEM)
        return -2;
    if (e != 0) {
        if (!*first_err && e != ENOENT) {
            *first_err = 1;
            path_error(first, op, path, e);
        }
        *read_ok = 0;
        return 0;
    }
    int rc = lc_gopool_append_pem(roots, data, n);
    free(data);
    *read_ok = 1;
    return rc == -2 ? -2 : 0;
}

/* filepath.SplitList: "" is no list at all; otherwise every element between colons, empty ones
 * kept. */
static char **split_list(const char *s, size_t *n)
{
    *n = 0;
    if (s == NULL || s[0] == '\0')
        return calloc(1, sizeof(char *));
    size_t k = 1;
    for (const char *p = s; *p != '\0'; p++)
        k += *p == ':';
    char **out = calloc(k + 1u, sizeof *out);
    if (out == NULL)
        return NULL;
    const char *start = s;
    for (const char *p = s;; p++) {
        if (*p == ':' || *p == '\0') {
            out[*n] = strndup(start, (size_t)(p - start));
            if (out[*n] == NULL) {
                for (size_t i = 0; i < *n; i++)
                    free(out[i]);
                free(out);
                return NULL;
            }
            (*n)++;
            if (*p == '\0')
                break;
            start = p + 1;
        }
    }
    return out;
}

int lc_go_load_roots(const char *cert_file, const char *cert_dir, lc_gopool **out, lc_obuf *err)
{
    lc_gopool *roots = lc_gopool_new();
    if (roots == NULL)
        return -2;
    int     first_err = 0;
    lc_obuf first = { 0 };
    int     rc = 0;

    /* the files: SSL_CERT_FILE alone, or the list; stop at the first one read */
    if (cert_file != NULL && cert_file[0] != '\0') {
        int ok;
        rc = load_file_into(roots, cert_file, &ok, &first_err, &first);
    } else {
        for (size_t i = 0; cert_files[i] != NULL && rc == 0; i++) {
            int ok;
            rc = load_file_into(roots, cert_files[i], &ok, &first_err, &first);
            if (ok)
                break;
        }
    }

    /* the directories: SSL_CERT_DIR split as a path list, or the list; all of them */
    size_t nd = 0;
    char **dirs = NULL;
    if (rc == 0 && cert_dir != NULL && cert_dir[0] != '\0') {
        dirs = split_list(cert_dir, &nd);
        if (dirs == NULL)
            rc = -2;
    }
    for (size_t i = 0; rc == 0; i++) {
        const char *dir = dirs != NULL ? (i < nd ? dirs[i] : NULL) : cert_dirs[i];
        if (dir == NULL)
            break;
        char      **names = NULL;
        size_t      nn = 0;
        const char *op;
        int         e = read_dir(dir, &names, &nn, &op);
        if (e == ENOMEM) {
            rc = -2;
            break;
        }
        if (e != 0) {
            if (!first_err && e != ENOENT) {
                first_err = 1;
                path_error(&first, op, dir, e);
            }
            continue;
        }
        for (size_t j = 0; j < nn; j++) {
            size_t dl = strlen(dir), fl = strlen(names[j]);
            char  *path = malloc(dl + fl + 2u);
            if (path == NULL) {
                rc = -2;
            } else if (rc == 0) {
                /* filepath.Join: one separator, and Clean of the result */
                memcpy(path, dir, dl);
                size_t o = dl;
                if (o == 0u || path[o - 1u] != '/')
                    path[o++] = '/';
                memcpy(path + o, names[j], fl + 1u);
                if (!same_dir_symlink(path)) {
                    uint8_t    *data;
                    size_t      n;
                    const char *rop;
                    int         re = read_file(path, &data, &n, &rop);
                    if (re == ENOMEM) {
                        rc = -2;
                    } else if (re == 0) {
                        if (lc_gopool_append_pem(roots, data, n) == -2)
                            rc = -2;
                        free(data);
                    }
                }
            }
            free(path);
            free(names[j]);
        }
        free(names);
    }
    if (dirs != NULL) {
        for (size_t i = 0; i < nd; i++)
            free(dirs[i]);
        free(dirs);
    }

    if (rc == -2 || first.oom) {
        free(first.p);
        lc_gopool_free(roots);
        return -2;
    }
    if (roots->n > 0u || !first_err) {
        free(first.p);
        *out = roots;
        return 0;
    }
    lc_gopool_free(roots);
    if (err != NULL)
        putn(err, first.p, first.n);
    free(first.p);
    return -1;
}

static pthread_mutex_t  roots_mu = PTHREAD_MUTEX_INITIALIZER;
static int              roots_loaded;
static lc_gopool       *roots_pool;
static lc_obuf          roots_err;

const lc_gopool *lc_go_system_roots(lc_obuf *err)
{
    pthread_mutex_lock(&roots_mu);
    if (!roots_loaded) {
        int rc = lc_go_load_roots(getenv("SSL_CERT_FILE"), getenv("SSL_CERT_DIR"), &roots_pool,
                                  &roots_err);
        /* out of memory is this process's failure and not an answer to keep */
        if (rc != -2)
            roots_loaded = 1;
        else
            put(&roots_err, "cannot allocate memory");
    }
    const lc_gopool *p = roots_pool;
    if (p == NULL && err != NULL)
        putn(err, roots_err.p, roots_err.n);
    if (!roots_loaded) {
        free(roots_err.p);
        memset(&roots_err, 0, sizeof roots_err);
    }
    pthread_mutex_unlock(&roots_mu);
    return p;
}

void lc_go_system_roots_reset(const char *const *files, const char *const *dirs)
{
    pthread_mutex_lock(&roots_mu);
    lc_gopool_free(roots_pool);
    roots_pool = NULL;
    free(roots_err.p);
    memset(&roots_err, 0, sizeof roots_err);
    roots_loaded = 0;
    cert_files = files != NULL ? files : go_cert_files;
    cert_dirs = dirs != NULL ? dirs : go_cert_dirs;
    pthread_mutex_unlock(&roots_mu);
}

/* ---- CheckSignatureFrom (x509.go:999-1019) ------------------------------------------------------ */


enum { KU_CERT_SIGN = 1 << 5 };

static int check_signature_from(const lc_gocert *c, const lc_gocert *parent, goerr *e)
{
    if ((parent->version == 3 && !parent->basic_constraints_valid) ||
        (parent->basic_constraints_valid && !parent->is_ca)) {
        err_set(e, LC_GO("x509: invalid signature: parent certificate cannot sign this kind of certificate"));
        return -1;
    }
    if (parent->key_usage != 0 && (parent->key_usage & KU_CERT_SIGN) == 0) {
        err_set(e, LC_GO("x509: invalid signature: parent certificate cannot sign this kind of certificate"));
        return -1;
    }
    if (parent->pk_alg == LC_GO_PK_UNKNOWN) {
        err_set(e, LC_GO("x509: cannot verify signature: algorithm unimplemented"));
        return -1;
    }
    err_clear(e);
    lc_gopubkey k;
    lc_gopubkey_of(parent, &k);
    int rc = lc_go_check_signature(c->sig_alg, c->tbs.p, c->tbs.n, c->signature, c->signature_n, &k,
                                   &e->text);
    if (rc == 0) {
        err_clear(e);
        return 0;
    }
    e->set = 1;
    if (rc == -2)
        e->text.oom = 1;
    return -1;
}

/* ---- isValid (verify.go:449-514) ----------------------------------------------------------------- */

enum { LEAF, INTERMEDIATE, ROOT };

typedef struct {
    const lc_gocert **v;
    size_t            n;
} chainv;

typedef struct {
    const lc_goverify_opts *o;
    const lc_gopool        *roots, *inter;
    int64_t                 now_sec;
    int32_t                 now_nsec;
    int                     sig_checks;
    int                     oom;
} vctx;

static void expired(goerr *e, const vctx *x, const char *rel, int64_t t, int32_t off, int utc)
{
    err_clear(e);
    e->set = 1;
    put(&e->text, LC_GO("x509: certificate has expired or is not yet valid: "));
    put(&e->text, "current time ");
    put_rfc3339(&e->text, x->now_sec, 0, 1);
    put(&e->text, rel);
    put_rfc3339(&e->text, t, off, utc);
}

static int is_valid(const lc_gocert *c, int type, chainv chain, const vctx *x, goerr *e)
{
    err_clear(e);
    if (c->unhandled_critical > 0u) {
        err_set(e, LC_GO("x509: unhandled critical extension"));
        return -1;
    }
    if (chain.n > 0u) {
        const lc_gocert *child = chain.v[chain.n - 1u];
        if (child->raw_issuer.n != c->raw_subject.n ||
            memcmp(child->raw_issuer.p, c->raw_subject.p, c->raw_subject.n) != 0) {
            err_set(e, LC_GO("x509: issuer name does not match subject from issuing certificate"));
            return -1;
        }
    }
    /* now.Before(NotBefore) and now.After(NotAfter), NotBefore and NotAfter being whole seconds */
    if (x->now_sec < c->not_before) {
        expired(e, x, " is before ", c->not_before, c->not_before_off, c->not_before_utc);
        return -1;
    }
    if (x->now_sec > c->not_after || (x->now_sec == c->not_after && x->now_nsec > 0)) {
        expired(e, x, " is after ", c->not_after, c->not_after_off, c->not_after_utc);
        return -1;
    }
    if ((type == INTERMEDIATE || type == ROOT) && chain.n == 0u) {
        err_set(e, LC_GO("x509: internal error: empty chain when appending CA cert"));
        return -1;
    }
    if (type == INTERMEDIATE && (!c->basic_constraints_valid || !c->is_ca)) {
        err_set(e, LC_GO("x509: certificate is not authorized to sign other certificates"));
        return -1;
    }
    if (c->basic_constraints_valid && c->max_path_len >= 0) {
        long long num_intermediates = (long long)chain.n - 1;
        if (num_intermediates > c->max_path_len) {
            err_set(e, LC_GO("x509: too many intermediates for path length constraint"));
            return -1;
        }
    }
    return 0;
}

/* ---- buildChains (verify.go:668-812) ------------------------------------------------------------ */

typedef struct {
    chainv *a;
    size_t  n;
} chainsv;

static void chains_free(chainsv *c)
{
    for (size_t i = 0; i < c->n; i++)
        free(c->a[i].v);
    free(c->a);
    c->a = NULL;
    c->n = 0;
}

static int chains_push(chainsv *c, chainv v)
{
    chainv *a = realloc(c->a, (c->n + 1u) * sizeof *a);
    if (a == NULL) {
        free(v.v);
        return -2;
    }
    c->a = a;
    c->a[c->n++] = v;
    return 0;
}

/* appendToFreshChain */
static int fresh(chainv chain, const lc_gocert *c, chainv *out)
{
    out->v = malloc((chain.n + 1u) * sizeof *out->v);
    if (out->v == NULL)
        return -2;
    if (chain.n != 0u)
        memcpy(out->v, chain.v, chain.n * sizeof *out->v);
    out->v[chain.n] = c;
    out->n = chain.n + 1u;
    return 0;
}

static int bytes_eq(lc_gobytes a, lc_gobytes b)
{
    return a.n == b.n && (a.n == 0u || memcmp(a.p, b.p, a.n) == 0);
}

/* alreadyInChain: the same subject, key and SAN value (or neither with a SAN). */
static int already_in_chain(const lc_gocert *cand, chainv chain)
{
    for (size_t i = 0; i < chain.n; i++) {
        const lc_gocert *c = chain.v[i];
        if (!bytes_eq(cand->raw_subject, c->raw_subject) || !bytes_eq(cand->raw_spki, c->raw_spki))
            continue;
        if (!cand->has_san && !c->has_san)
            return 1;
        if (!cand->has_san || !c->has_san)
            return 0;
        if (bytes_eq(cand->san_value, c->san_value))
            return 1;
    }
    return 0;
}

/* findPotentialParents (cert_pool.go): the pool's certificates whose subject is `c`'s issuer, those
 * whose key ID matches first, then those where only one side has one, then the rest, each group in
 * the pool's order. */
static size_t potential_parents(const lc_gopool *p, const lc_gocert *c, const lc_gocert ***out)
{
    *out = NULL;
    if (p == NULL || p->n == 0u)
        return 0;
    const lc_gocert **v = malloc(p->n * sizeof *v);
    if (v == NULL)
        return (size_t)-1;
    size_t k = 0;
    for (int pass = 0; pass < 3; pass++) {
        for (size_t i = 0; i < p->n; i++) {
            const lc_gocert *cand = p->certs[i];
            if (!bytes_eq(cand->raw_subject, c->raw_issuer))
                continue;
            int kid_match = bytes_eq(cand->subject_key_id, c->authority_key_id);
            int one = (cand->subject_key_id.n == 0u && c->authority_key_id.n > 0u) ||
                      (cand->subject_key_id.n > 0u && c->authority_key_id.n == 0u);
            int group = kid_match ? 0 : one ? 1 : 2;
            if (group == pass)
                v[k++] = cand;
        }
    }
    *out = v;
    return k;
}

/* SerialNumber.String(): the decimal of the serial's magnitude. */
static void put_serial(lc_obuf *b, lc_gobytes serial)
{
    mbedtls_mpi n;
    mbedtls_mpi_init(&n);
    char   s[1024];
    size_t olen = 0;
    if (mbedtls_mpi_read_binary(&n, serial.p, serial.n) == 0 &&
        mbedtls_mpi_write_string(&n, 10, s, sizeof s, &olen) == 0)
        put(b, s);
    else
        b->oom = 1;
    mbedtls_mpi_free(&n);
}

/* UnknownAuthorityError.Error() */
static void unknown_authority(goerr *e, const goerr *hint, const lc_gocert *hint_cert)
{
    err_clear(e);
    e->set = 1;
    put(&e->text, LC_GO("x509: certificate signed by unknown authority"));
    if (hint->set) {
        lc_obuf name = { 0 };
        if (hint_cert->subject_cn != NULL && hint_cert->subject_cn_n > 0u) {
            putn(&name, hint_cert->subject_cn, hint_cert->subject_cn_n);
        } else if (hint_cert->subject_o != NULL) {
            putn(&name, hint_cert->subject_o, hint_cert->subject_o_n);
        } else {
            put(&name, "serial:");
            put_serial(&name, hint_cert->serial);
        }
        put(&e->text, " (possibly because of ");
        put_q(&e->text, hint->text.p != NULL ? hint->text.p : "", hint->text.n);
        put(&e->text, " while trying to verify candidate authority certificate ");
        put_q(&e->text, name.p != NULL ? name.p : "", name.n);
        put(&e->text, ")");
        e->text.oom |= name.oom | hint->text.oom;
        free(name.p);
    }
}

static void build_chains(vctx *x, const lc_gocert *c, chainv chain, chainsv *chains, goerr *err)
{
    goerr            hint = { 0 };
    const lc_gocert *hint_cert = NULL;
    err_clear(err);

    for (int pass = 0; pass < 2 && !x->oom; pass++) {
        const lc_gocert **cands;
        size_t            nc = potential_parents(pass == 0 ? x->roots : x->inter, c, &cands);
        if (nc == (size_t)-1) {
            x->oom = 1;
            break;
        }
        int type = pass == 0 ? ROOT : INTERMEDIATE;
        int stop = 0;
        for (size_t i = 0; i < nc && !x->oom; i++) {
            const lc_gocert *cand = cands[i];
            /* considerCandidate */
            if (++x->sig_checks > 100) {
                err_set(err, LC_GO("x509: signature check attempts limit reached while verifying certificate chain"));
                err->sig_limit = 1;
                stop = 1;
                break;
            }
            if (!cand->pk_present || already_in_chain(cand, chain))
                continue;
            goerr se = { 0 };
            if (check_signature_from(c, cand, &se) != 0) {
                if (err_oom(&se))
                    x->oom = 1;
                if (!hint.set) {
                    err_move(&hint, &se);
                    hint_cert = cand;
                }
                err_clear(&se);
                continue;
            }
            /* err = candidate.cert.isValid(...): the outer err, nil when it passes */
            if (is_valid(cand, type, chain, x, err) != 0) {
                if (!hint.set) {
                    err_copy(&hint, err);
                    hint_cert = cand;
                }
                continue;
            }
            chainv next;
            if (fresh(chain, cand, &next) != 0) {
                x->oom = 1;
                break;
            }
            if (type == ROOT) {
                if (chains_push(chains, next) != 0)
                    x->oom = 1;
            } else {
                chainsv child = { 0 };
                build_chains(x, cand, next, &child, err);
                free(next.v);
                for (size_t k = 0; k < child.n; k++)
                    if (chains_push(chains, child.a[k]) != 0)
                        x->oom = 1;
                free(child.a);
            }
            if (err->set && err->sig_limit) {
                stop = 1;
                break;
            }
        }
        free(cands);
        if (stop)
            break;
    }

    if (chains->n > 0u)
        err_clear(err);
    if (chains->n == 0u && !err->set)
        unknown_authority(err, &hint, hint_cert);
    if (err_oom(err) || hint.text.oom)
        x->oom = 1;
    err_clear(&hint);
}

/* ---- VerifyHostname (verify.go:942-983) --------------------------------------------------------- */

static uint8_t lower(uint8_t c)
{
    return c >= 'A' && c <= 'Z' ? (uint8_t)(c + 32) : c;
}

/* validHostname (verify.go:820-867) */
static int valid_hostname(const uint8_t *h, size_t n, int pattern)
{
    if (!pattern && n > 0u && h[n - 1u] == '.')
        n--;
    if (n == 0u)
        return 0;
    if (n == 1u && h[0] == '*')
        return 0;
    size_t start = 0;
    int    first = 1;
    for (size_t i = 0; i <= n; i++) {
        if (i < n && h[i] != '.')
            continue;
        const uint8_t *part = h + start;
        size_t         pn = i - start;
        if (pn == 0u)
            return 0;
        if (!(pattern && first && pn == 1u && part[0] == '*')) {
            for (size_t j = 0; j < pn; j++) {
                uint8_t c = part[j];
                if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
                    (c == '-' && j != 0u) || c == '_')
                    continue;
                return 0;
            }
        }
        first = 0;
        start = i + 1u;
    }
    return 1;
}

/* matchExactly */
static int match_exactly(const uint8_t *a, size_t an, const uint8_t *b, size_t bn)
{
    if (an == 0u || (an == 1u && a[0] == '.') || bn == 0u || (bn == 1u && b[0] == '.'))
        return 0;
    if (an != bn)
        return 0;
    for (size_t i = 0; i < an; i++)
        if (lower(a[i]) != lower(b[i]))
            return 0;
    return 1;
}

/* matchHostnames(pattern, splitHostname(host)): label by label, lower-cased, "*" matching any
 * one first label; `host` has had one trailing dot dropped already by splitHostname. */
static int match_hostnames(const uint8_t *pat, size_t pn, const uint8_t *host, size_t hn)
{
    if (hn > 0u && host[hn - 1u] == '.')
        hn--;
    if (pn == 0u)
        return 0;
    /* split both on '.' and compare part for part */
    size_t np = 1, nh = 1;
    for (size_t i = 0; i < pn; i++)
        np += pat[i] == '.';
    for (size_t i = 0; i < hn; i++)
        nh += host[i] == '.';
    if (np != nh)
        return 0;
    size_t ps = 0, hs = 0;
    for (size_t k = 0; k < np; k++) {
        size_t pe = ps, he = hs;
        while (pe < pn && pat[pe] != '.')
            pe++;
        while (he < hn && host[he] != '.')
            he++;
        if (!(k == 0u && pe - ps == 1u && pat[ps] == '*')) {
            if (pe - ps != he - hs)
                return 0;
            for (size_t i = 0; i < pe - ps; i++)
                if (lower(pat[ps + i]) != lower(host[hs + i]))
                    return 0;
        }
        ps = pe + 1u;
        hs = he + 1u;
    }
    return 1;
}

/* HostnameError.Error() (verify.go:110-144) */
static void hostname_error(goerr *e, const lc_gocert *c, const uint8_t *host, size_t hn, int is_ip)
{
    err_clear(e);
    e->set = 1;
    lc_obuf *b = &e->text;
    if (!c->has_san && c->subject_cn != NULL &&
        match_hostnames((const uint8_t *)c->subject_cn, c->subject_cn_n, host, hn)) {
        put(b, LC_GO("x509: certificate relies on legacy Common Name field, use SANs instead"));
        return;
    }
    if (is_ip) {
        if (c->ip_addresses.n == 0u) {
            put(b, "x509: cannot validate certificate for ");
            putn(b, host, hn);
            put(b, " because it doesn't contain any IP SANs");
            return;
        }
        if (c->ip_addresses.n >= 100u) {
            put(b, "x509: certificate is valid for ");
            put_int(b, (long long)c->ip_addresses.n);
            put(b, " IP SANs, but none matched ");
            putn(b, host, hn);
            return;
        }
        put(b, "x509: certificate is valid for ");
        for (size_t i = 0; i < c->ip_addresses.n; i++) {
            if (i > 0u)
                put(b, ", ");
            put_ip(b, c->ip_addresses.a[i].p, c->ip_addresses.a[i].n);
        }
    } else {
        if (c->dns_names.n >= 100u) {
            put(b, "x509: certificate is valid for ");
            put_int(b, (long long)c->dns_names.n);
            put(b, " names, but none matched ");
            putn(b, host, hn);
            return;
        }
        size_t total = 0;
        for (size_t i = 0; i < c->dns_names.n; i++)
            total += c->dns_names.a[i].n + (i > 0u ? 2u : 0u);
        if (total == 0u) {
            put(b, "x509: certificate is not valid for any names, but wanted to match ");
            putn(b, host, hn);
            return;
        }
        put(b, "x509: certificate is valid for ");
        for (size_t i = 0; i < c->dns_names.n; i++) {
            if (i > 0u)
                put(b, ", ");
            putn(b, c->dns_names.a[i].p, c->dns_names.a[i].n);
        }
    }
    put(b, ", not ");
    putn(b, host, hn);
}

static int verify_hostname(const lc_gocert *c, const char *h, size_t hn, goerr *e)
{
    const char *cand = h;
    size_t      cn = hn;
    if (hn >= 3u && h[0] == '[' && h[hn - 1u] == ']') {
        cand = h + 1;
        cn = hn - 2u;
    }
    lc_netip addr;
    if (lc_netip_parse(cand, cn, &addr, NULL) == 0) {
        const uint8_t *ip = addr.is4 ? addr.ip + 12 : addr.ip;
        size_t         ipn = addr.is4 ? 4u : 16u;
        for (size_t i = 0; i < c->ip_addresses.n; i++)
            if (ip_equal(ip, ipn, c->ip_addresses.a[i].p, c->ip_addresses.a[i].n))
                return 0;
        lc_obuf s = { 0 };
        put_ip(&s, ip, ipn);
        hostname_error(e, c, (const uint8_t *)(s.p != NULL ? s.p : ""), s.n, 1);
        e->text.oom |= s.oom;
        free(s.p);
        return -1;
    }

    const uint8_t *name = (const uint8_t *)h;
    int            valid = valid_hostname(name, hn, 0);
    for (size_t i = 0; i < c->dns_names.n; i++) {
        const uint8_t *m = c->dns_names.a[i].p;
        size_t         mn = c->dns_names.a[i].n;
        if (valid && valid_hostname(m, mn, 1)) {
            if (match_hostnames(m, mn, name, hn))
                return 0;
        } else if (match_exactly(m, mn, name, hn)) {
            return 0;
        }
    }
    hostname_error(e, c, name, hn, 0);
    return -1;
}

/* ---- checkChainForKeyUsage (verify.go:989-1036) ------------------------------------------------- */

static int chain_key_usage(chainv chain, const int *want, size_t nwant)
{
    if (chain.n == 0u)
        return 0;
    int    usages[32];
    size_t n = nwant < 32u ? nwant : 32u;
    memcpy(usages, want, n * sizeof *usages);
    size_t remaining = n;
    for (size_t i = chain.n; i-- > 0u;) {
        const lc_gocert *c = chain.v[i];
        if (c->ext_key_usage_n == 0u && c->unknown_ext_key_usage_n == 0u)
            continue;
        int any = 0;
        for (size_t k = 0; k < c->ext_key_usage_n; k++)
            if (c->ext_key_usage[k] == LC_GO_EKU_ANY)
                any = 1;
        if (any)
            continue;
        for (size_t r = 0; r < n; r++) {
            if (usages[r] == -1)
                continue;
            int found = 0;
            for (size_t k = 0; k < c->ext_key_usage_n; k++)
                if (usages[r] == c->ext_key_usage[k])
                    found = 1;
            if (found)
                continue;
            usages[r] = -1;
            if (--remaining == 0u)
                return 0;
        }
    }
    return 1;
}

/* ---- policiesValid (verify.go:1188-1407), RFC 5280 6.1 as updated by RFC 9618 ------------------ */

typedef struct pnode pnode;
struct pnode {
    lc_gobytes  valid;     /* validPolicy: the OID's DER contents */
    lc_gobytes *expected;  /* expectedPolicySet */
    size_t      nexpected;
    pnode     **parents, **children;
    size_t      nparents, nchildren;
    int         depth;
    int         alive; /* still in its stratum's map */
};

typedef struct {
    pnode **nodes; /* every node ever made, for freeing */
    size_t  n;
    int     depth;
    int     oom;
} pgraph;

static const uint8_t ANY_POLICY[] = { 0x55, 0x1d, 0x20, 0x00 }; /* 2.5.29.32.0 */

static int is_any(lc_gobytes o)
{
    return o.n == sizeof ANY_POLICY && memcmp(o.p, ANY_POLICY, sizeof ANY_POLICY) == 0;
}

static int link_add(pnode ***a, size_t *n, pnode *x)
{
    for (size_t i = 0; i < *n; i++)
        if ((*a)[i] == x)
            return 0; /* a map: once */
    pnode **v = realloc(*a, (*n + 1u) * sizeof *v);
    if (v == NULL)
        return -2;
    v[(*n)++] = x;
    *a = v;
    return 0;
}

static void link_del(pnode **a, size_t *n, const pnode *x)
{
    for (size_t i = 0; i < *n; i++) {
        if (a[i] == x) {
            a[i] = a[--*n];
            return;
        }
    }
}

/* the node of `policy` in stratum `depth`, if it is there */
static pnode *stratum_get(const pgraph *g, int depth, lc_gobytes policy)
{
    for (size_t i = 0; i < g->n; i++) {
        pnode *p = g->nodes[i];
        if (p->alive && p->depth == depth && bytes_eq(p->valid, policy))
            return p;
    }
    return NULL;
}

/* newPolicyGraphNode, then insert at the current depth (replacing what held that key) */
static pnode *pg_insert(pgraph *g, lc_gobytes valid, pnode *const *parents, size_t np)
{
    pnode  *n = calloc(1, sizeof *n);
    pnode **all = realloc(g->nodes, (g->n + 1u) * sizeof *all);
    if (n == NULL || all == NULL) {
        free(n);
        if (all != NULL)
            g->nodes = all;
        g->oom = 1;
        return NULL;
    }
    g->nodes = all;
    g->nodes[g->n++] = n;
    n->valid = valid;
    n->expected = malloc(sizeof *n->expected);
    if (n->expected == NULL) {
        g->oom = 1;
        return NULL;
    }
    n->expected[0] = valid;
    n->nexpected = 1;
    n->depth = g->depth;
    for (size_t i = 0; i < np; i++) {
        if (link_add(&parents[i]->children, &parents[i]->nchildren, n) != 0 ||
            link_add(&n->parents, &n->nparents, parents[i]) != 0)
            g->oom = 1;
    }
    pnode *old = stratum_get(g, g->depth, valid);
    if (old != NULL && old != n)
        old->alive = 0; /* the map's key now names the new node; the old one keeps its links */
    n->alive = 1;
    return n;
}

static void pg_unlink(pnode *n)
{
    for (size_t i = 0; i < n->nparents; i++)
        link_del(n->parents[i]->children, &n->parents[i]->nchildren, n);
    for (size_t i = 0; i < n->nchildren; i++)
        link_del(n->children[i]->parents, &n->children[i]->nparents, n);
    n->alive = 0;
}

static void pg_prune(pgraph *g)
{
    for (int d = g->depth - 1; d > 0; d--) {
        for (size_t i = 0; i < g->n; i++) {
            pnode *n = g->nodes[i];
            if (!n->alive || n->depth != d || n->nchildren != 0u)
                continue;
            for (size_t k = 0; k < n->nparents; k++)
                link_del(n->parents[k]->children, &n->parents[k]->nchildren, n);
            n->alive = 0;
        }
    }
}

static void pg_free(pgraph *g)
{
    for (size_t i = 0; i < g->n; i++) {
        free(g->nodes[i]->expected);
        free(g->nodes[i]->parents);
        free(g->nodes[i]->children);
        free(g->nodes[i]);
    }
    free(g->nodes);
    memset(g, 0, sizeof *g);
}

/* parentsWithExpected, through the parentIndex incrDepth built: the nodes of the previous stratum,
 * as it stood then, with `oid` in their expectedPolicySet. The index is a snapshot, so it is kept
 * as a list of (node, OID) pairs taken at incrDepth. */
typedef struct {
    pnode     *node;
    lc_gobytes oid;
} pindex;

static int policies_valid(chainv chain, const lc_goverify_opts *o, int *oom)
{
    if (chain.n == 1u)
        return 1;
    size_t    n = chain.n - 1u;
    pgraph    g = { 0 };
    int       have_graph = 1;
    long long inhibit_any = o->inhibit_any_policy ? 0 : (long long)n + 1;
    long long explicit_policy = o->require_explicit_policy ? 0 : (long long)n + 1;
    long long policy_mapping = o->inhibit_policy_mapping ? 0 : (long long)n + 1;
    int    result = 1;
    pindex *index = NULL;
    size_t  nindex = 0;

    /* the root, anyPolicy at depth 0 */
    lc_gobytes any = { ANY_POLICY, sizeof ANY_POLICY };
    if (pg_insert(&g, any, NULL, 0) == NULL)
        goto oom;

    for (size_t ii = n; ii-- > 0u;) {
        const lc_gocert *cert = chain.v[ii];
        long long        i = (long long)ii;
        int self_signed = bytes_eq(cert->raw_issuer, cert->raw_subject);

        if (cert->policies.n == 0u)
            have_graph = 0;
        if (explicit_policy == 0 && !have_graph) {
            result = 0;
            goto done;
        }

        if (have_graph) {
            /* incrDepth: the index of the stratum being left, then a new one */
            free(index);
            index = NULL;
            nindex = 0;
            for (size_t k = 0; k < g.n; k++) {
                pnode *p = g.nodes[k];
                if (!p->alive || p->depth != g.depth)
                    continue;
                for (size_t e = 0; e < p->nexpected; e++) {
                    pindex *ni = realloc(index, (nindex + 1u) * sizeof *ni);
                    if (ni == NULL)
                        goto oom;
                    index = ni;
                    index[nindex++] = (pindex){ p, p->expected[e] };
                }
            }
            g.depth++;

            int has_any = 0;
            for (size_t k = 0; k < cert->policies.n; k++) {
                lc_gobytes policy = cert->policies.a[k];
                if (is_any(policy)) {
                    has_any = 1;
                    continue;
                }
                /* (d)(1)(i): parents expecting it; (ii): else the previous anyPolicy node */
                pnode **par = NULL;
                size_t  np = 0;
                for (size_t k2 = 0; k2 < nindex; k2++) {
                    if (!bytes_eq(index[k2].oid, policy))
                        continue;
                    pnode **v = realloc(par, (np + 1u) * sizeof *v);
                    if (v == NULL) {
                        free(par);
                        goto oom;
                    }
                    par = v;
                    par[np++] = index[k2].node;
                }
                if (np == 0u) {
                    pnode *ap = stratum_get(&g, g.depth - 1, any);
                    if (ap != NULL) {
                        par = malloc(sizeof *par);
                        if (par == NULL)
                            goto oom;
                        par[np++] = ap;
                    }
                }
                if (np > 0u && pg_insert(&g, policy, par, np) == NULL) {
                    free(par);
                    goto oom;
                }
                free(par);
            }

            /* (d)(2): anyPolicy, where it may still be processed */
            if (has_any && (inhibit_any > 0 || ((long long)n - i < (long long)n && self_signed))) {
                /* missing: for each parent and each OID it expects that no leaf has yet, the
                 * parents expecting it — collected first, inserted after */
                typedef struct {
                    lc_gobytes oid;
                    pnode    **par;
                    size_t     np;
                } miss;
                miss  *m = NULL;
                size_t nm = 0;
                for (size_t k = 0; k < g.n; k++) {
                    pnode *p = g.nodes[k];
                    if (!p->alive || p->depth != g.depth - 1)
                        continue;
                    for (size_t e = 0; e < p->nexpected; e++) {
                        lc_gobytes want = p->expected[e];
                        if (stratum_get(&g, g.depth, want) != NULL)
                            continue;
                        size_t j = 0;
                        while (j < nm && !bytes_eq(m[j].oid, want))
                            j++;
                        if (j == nm) {
                            miss *v = realloc(m, (nm + 1u) * sizeof *v);
                            if (v == NULL)
                                goto miss_oom;
                            m = v;
                            m[nm++] = (miss){ want, NULL, 0 };
                        }
                        pnode **pv = realloc(m[j].par, (m[j].np + 1u) * sizeof *pv);
                        if (pv == NULL)
                            goto miss_oom;
                        m[j].par = pv;
                        m[j].par[m[j].np++] = p;
                    }
                }
                for (size_t j = 0; j < nm; j++)
                    if (pg_insert(&g, m[j].oid, m[j].par, m[j].np) == NULL)
                        goto miss_oom;
                for (size_t j = 0; j < nm; j++)
                    free(m[j].par);
                free(m);
                if (0) {
                miss_oom:
                    for (size_t j = 0; j < nm; j++)
                        free(m[j].par);
                    free(m);
                    goto oom;
                }
            }

            /* (d)(3) */
            pg_prune(&g);

            if (i != 0 && cert->policy_mappings_n > 0u) {
                /* 6.1.4 (b): issuer -> subjects, or deletions when mapping is inhibited */
                typedef struct {
                    lc_gobytes  issuer;
                    lc_gobytes *subjects;
                    size_t      n;
                } mapping;
                mapping *mp = NULL;
                size_t   nmp = 0;
                int      bad = 0;
                for (size_t k = 0; k < cert->policy_mappings_n; k++) {
                    lc_gobytes is = cert->policy_mappings[k].issuer, su = cert->policy_mappings[k].subject;
                    if (policy_mapping > 0) {
                        if (is_any(is) || is_any(su)) {
                            bad = 1;
                            break;
                        }
                        size_t j = 0;
                        while (j < nmp && !bytes_eq(mp[j].issuer, is))
                            j++;
                        if (j == nmp) {
                            mapping *v = realloc(mp, (nmp + 1u) * sizeof *v);
                            if (v == NULL)
                                goto map_oom;
                            mp = v;
                            mp[nmp++] = (mapping){ is, NULL, 0 };
                        }
                        lc_gobytes *sv = realloc(mp[j].subjects, (mp[j].n + 1u) * sizeof *sv);
                        if (sv == NULL)
                            goto map_oom;
                        mp[j].subjects = sv;
                        mp[j].subjects[mp[j].n++] = su;
                    } else {
                        pnode *leaf = stratum_get(&g, g.depth, is);
                        if (leaf != NULL)
                            pg_unlink(leaf);
                    }
                }
                if (!bad) {
                    pg_prune(&g);
                    for (size_t j = 0; j < nmp; j++) {
                        pnode *match = stratum_get(&g, g.depth, mp[j].issuer);
                        pnode *target = NULL;
                        if (match != NULL) {
                            target = match;
                        } else {
                            pnode *anyleaf = stratum_get(&g, g.depth, any);
                            if (anyleaf != NULL) {
                                target = pg_insert(&g, mp[j].issuer, &anyleaf, 1);
                                if (target == NULL)
                                    goto map_oom;
                            }
                        }
                        if (target != NULL) {
                            /* expectedPolicySet = subjectPolicies: the node takes the list */
                            free(target->expected);
                            target->expected = mp[j].subjects;
                            target->nexpected = mp[j].n;
                            mp[j].subjects = NULL;
                        }
                    }
                }
                for (size_t j = 0; j < nmp; j++)
                    free(mp[j].subjects);
                free(mp);
                if (bad) {
                    result = 0;
                    goto done;
                }
                if (0) {
                map_oom:
                    for (size_t j = 0; j < nmp; j++)
                        free(mp[j].subjects);
                    free(mp);
                    goto oom;
                }
            }
        }

        if (i != 0) {
            /* 6.1.4 (h) */
            if (!self_signed) {
                if (explicit_policy > 0)
                    explicit_policy--;
                if (policy_mapping > 0)
                    policy_mapping--;
                if (inhibit_any > 0)
                    inhibit_any--;
            }
            /* 6.1.4 (i), (j) */
            if ((cert->require_explicit_policy > 0 || cert->require_explicit_policy_zero) &&
                cert->require_explicit_policy < explicit_policy)
                explicit_policy = cert->require_explicit_policy;
            if ((cert->inhibit_policy_mapping > 0 || cert->inhibit_policy_mapping_zero) &&
                cert->inhibit_policy_mapping < policy_mapping)
                policy_mapping = cert->inhibit_policy_mapping;
            if ((cert->inhibit_any_policy > 0 || cert->inhibit_any_policy_zero) &&
                cert->inhibit_any_policy < inhibit_any)
                inhibit_any = cert->inhibit_any_policy;
        }
    }

    /* 6.1.5 (a), (b) */
    if (explicit_policy > 0)
        explicit_policy--;
    if (chain.v[0]->require_explicit_policy_zero)
        explicit_policy = 0;

    /* 6.1.5 (g): the authority-constrained set — the valid policy nodes, and the anyPolicy leaf —
     * then narrowed to the user's set unless that is {anyPolicy} alone. Only whether what is left
     * is empty matters. */
    int user_any_only = 1, authority_any = 0, user_nonempty = 0;
    for (size_t k = 0; k < o->policies_n; k++)
        if (!is_any(o->policies[k]))
            user_any_only = 0;
    if (have_graph) {
        for (int d = g.depth; d >= 0; d--) {
            for (size_t k = 0; k < g.n; k++) {
                pnode *p = g.nodes[k];
                if (!p->alive || p->depth != d || is_any(p->valid))
                    continue;
                if (!(p->nparents == 1u && is_any(p->parents[0]->valid)))
                    continue;
                if (user_any_only) {
                    user_nonempty = 1;
                } else {
                    for (size_t u = 0; u < o->policies_n; u++)
                        if (bytes_eq(o->policies[u], p->valid))
                            user_nonempty = 1;
                }
            }
        }
        if (stratum_get(&g, g.depth, any) != NULL) {
            authority_any = 1;
            if (user_any_only)
                user_nonempty = 1;
        }
    }
    /* (6)(ii): anyPolicy in the authority set brings in the whole user set, which is not empty */
    if (!user_any_only && authority_any)
        user_nonempty = 1;
    if (explicit_policy == 0 && !user_nonempty)
        result = 0;

done:
    free(index);
    pg_free(&g);
    return result;
oom:
    free(index);
    pg_free(&g);
    *oom = 1;
    return 0;
}

/* ---- name constraints (GOROOT/src/crypto/x509/constraints.go) ---------------------------------- */

/* slices.SortFunc is pdqsort (GOROOT/src/slices/zsortanyfunc.go), and it decides which of two
 * constraints that compare equal survives the pruning and is named in the error — so it is Go's,
 * over an array of pointers. */
typedef int (*cmpf)(const void *, const void *);

static void swp(const void **d, long a, long b)
{
    const void *t = d[a];
    d[a] = d[b];
    d[b] = t;
}

static void insertion_sort(const void **d, long a, long b, cmpf cmp)
{
    for (long i = a + 1; i < b; i++)
        for (long j = i; j > a && cmp(d[j], d[j - 1]) < 0; j--)
            swp(d, j, j - 1);
}

static void sift_down(const void **d, long lo, long hi, long first, cmpf cmp)
{
    long root = lo;
    for (;;) {
        long child = 2 * root + 1;
        if (child >= hi)
            break;
        if (child + 1 < hi && cmp(d[first + child], d[first + child + 1]) < 0)
            child++;
        if (!(cmp(d[first + root], d[first + child]) < 0))
            return;
        swp(d, first + root, first + child);
        root = child;
    }
}

static void heap_sort(const void **d, long a, long b, cmpf cmp)
{
    long first = a, lo = 0, hi = b - a;
    for (long i = (hi - 1) / 2; i >= 0; i--)
        sift_down(d, i, hi, first, cmp);
    for (long i = hi - 1; i >= 0; i--) {
        swp(d, first, first + i);
        sift_down(d, lo, i, first, cmp);
    }
}

static int bits_len(unsigned long x)
{
    int n = 0;
    while (x != 0u) {
        n++;
        x >>= 1;
    }
    return n;
}

/* breakPatternsCmpFunc, with the xorshift seeded by the length */
static void break_patterns(const void **d, long a, long b)
{
    long length = b - a;
    if (length >= 8) {
        uint64_t      r = (uint64_t)length;
        unsigned long modulus = 1ul << bits_len((unsigned long)length);
        for (long idx = a + (length / 4) * 2 - 1; idx <= a + (length / 4) * 2 + 1; idx++) {
            r ^= r << 13;
            r ^= r >> 7;
            r ^= r << 17;
            long other = (long)((unsigned long)r & (modulus - 1u));
            if (other >= length)
                other -= length;
            swp(d, idx, a + other);
        }
    }
}

/* order2CmpFunc: the two indexes in order, counting a swap */
static void order2(const void **d, long *a, long *b, int *swaps, cmpf cmp)
{
    if (cmp(d[*b], d[*a]) < 0) {
        (*swaps)++;
        long t = *a;
        *a = *b;
        *b = t;
    }
}

static long median(const void **d, long a, long b, long c, int *swaps, cmpf cmp)
{
    order2(d, &a, &b, swaps, cmp);
    order2(d, &b, &c, swaps, cmp);
    order2(d, &a, &b, swaps, cmp);
    return b;
}

enum { UNKNOWN_HINT, INCREASING_HINT, DECREASING_HINT };

static long choose_pivot(const void **d, long a, long b, int *hint, cmpf cmp)
{
    long l = b - a;
    int  swaps = 0;
    long i = a + l / 4 * 1, j = a + l / 4 * 2, k = a + l / 4 * 3;
    if (l >= 8) {
        if (l >= 50) {
            i = median(d, i - 1, i, i + 1, &swaps, cmp);
            j = median(d, j - 1, j, j + 1, &swaps, cmp);
            k = median(d, k - 1, k, k + 1, &swaps, cmp);
        }
        j = median(d, i, j, k, &swaps, cmp);
    }
    *hint = swaps == 0 ? INCREASING_HINT : swaps == 12 ? DECREASING_HINT : UNKNOWN_HINT;
    return j;
}

/* partialInsertionSortCmpFunc — its inner backward loop runs down to index 1, not to `a`, as Go's
 * does */
static int partial_insertion_sort(const void **d, long a, long b, cmpf cmp)
{
    long i = a + 1;
    for (int step = 0; step < 5; step++) {
        while (i < b && !(cmp(d[i], d[i - 1]) < 0))
            i++;
        if (i == b)
            return 1;
        if (b - a < 50)
            return 0;
        swp(d, i, i - 1);
        if (i - a >= 2) {
            for (long j = i - 1; j >= 1; j--) {
                if (!(cmp(d[j], d[j - 1]) < 0))
                    break;
                swp(d, j, j - 1);
            }
        }
        if (b - i >= 2) {
            for (long j = i + 1; j < b; j++) {
                if (!(cmp(d[j], d[j - 1]) < 0))
                    break;
                swp(d, j, j - 1);
            }
        }
    }
    return 0;
}

static long partition_equal(const void **d, long a, long b, long pivot, cmpf cmp)
{
    swp(d, a, pivot);
    long i = a + 1, j = b - 1;
    for (;;) {
        while (i <= j && !(cmp(d[a], d[i]) < 0))
            i++;
        while (i <= j && cmp(d[a], d[j]) < 0)
            j--;
        if (i > j)
            break;
        swp(d, i, j);
        i++;
        j--;
    }
    return i;
}

static long partition(const void **d, long a, long b, long pivot, int *already, cmpf cmp)
{
    swp(d, a, pivot);
    long i = a + 1, j = b - 1;
    while (i <= j && cmp(d[i], d[a]) < 0)
        i++;
    while (i <= j && !(cmp(d[j], d[a]) < 0))
        j--;
    if (i > j) {
        swp(d, j, a);
        *already = 1;
        return j;
    }
    swp(d, i, j);
    i++;
    j--;
    for (;;) {
        while (i <= j && cmp(d[i], d[a]) < 0)
            i++;
        while (i <= j && !(cmp(d[j], d[a]) < 0))
            j--;
        if (i > j)
            break;
        swp(d, i, j);
        i++;
        j--;
    }
    swp(d, j, a);
    *already = 0;
    return j;
}

static void pdqsort(const void **d, long a, long b, int limit, cmpf cmp)
{
    int was_balanced = 1, was_partitioned = 1;
    for (;;) {
        long length = b - a;
        if (length <= 12) {
            insertion_sort(d, a, b, cmp);
            return;
        }
        if (limit == 0) {
            heap_sort(d, a, b, cmp);
            return;
        }
        if (!was_balanced) {
            break_patterns(d, a, b);
            limit--;
        }
        int  hint;
        long pivot = choose_pivot(d, a, b, &hint, cmp);
        if (hint == DECREASING_HINT) {
            for (long i = a, j = b - 1; i < j; i++, j--)
                swp(d, i, j);
            pivot = (b - 1) - (pivot - a);
            hint = INCREASING_HINT;
        }
        if (was_balanced && was_partitioned && hint == INCREASING_HINT &&
            partial_insertion_sort(d, a, b, cmp))
            return;
        if (a > 0 && !(cmp(d[a - 1], d[pivot]) < 0)) {
            a = partition_equal(d, a, b, pivot, cmp);
            continue;
        }
        int  already;
        long mid = partition(d, a, b, pivot, &already, cmp);
        was_partitioned = already;
        long left = mid - a, right = b - mid, threshold = length / 8;
        if (left < right) {
            was_balanced = left >= threshold;
            pdqsort(d, a, mid, limit, cmp);
            a = mid + 1;
        } else {
            was_balanced = right >= threshold;
            pdqsort(d, mid + 1, b, limit, cmp);
            b = mid;
        }
    }
}

/* nameConstraintsSet.sortAndPrune: sorted, then each element that is a subset of the one kept
 * before it dropped. The new length. */
static size_t sort_and_prune(const void **d, size_t n, cmpf cmp, int (*subset)(const void *, const void *))
{
    if (n < 2u)
        return n;
    pdqsort(d, 0, (long)n, bits_len((unsigned long)n), cmp);
    size_t w = 1;
    for (size_t r = 1; r < n; r++)
        if (!subset(d[w - 1u], d[r]))
            d[w++] = d[r];
    return w;
}

/* nameConstraintsSet.search: BinarySearchFunc for the lower bound, then the element before it (or
 * the first) tested with `match`. */
static const void *set_search(const void **d, size_t n, const void *s, cmpf cmp,
                              int (*match)(const void *, const void *))
{
    if (n == 0u)
        return NULL;
    size_t i = 0, j = n;
    while (i < j) {
        size_t h = (i + j) >> 1;
        if (cmp(d[h], s) < 0)
            i = h + 1u;
        else
            j = h;
    }
    if (i < n && cmp(d[i], s) == 0)
        return d[i];
    const void *c = i == 0u ? d[0] : d[i - 1u];
    return match(c, s) ? c : NULL;
}

/* -- DNS names -- */

/* dnsCompareTable: ASCII lower-cased, and '.' below everything (the hyphen included) */
static uint8_t dns_table(uint8_t c)
{
    return c == '.' ? 0u : lower(c);
}

/* dnsCompare: from the end */
static int dns_compare(const void *av, const void *bv)
{
    const lc_gobytes *a = av, *b = bv;
    long              ia = (long)a->n - 1, ib = (long)b->n - 1;
    while (ia >= 0 && ib >= 0) {
        uint8_t x = dns_table(a->p[ia]), y = dns_table(b->p[ib]);
        if (x == y) {
            ia--;
            ib--;
            continue;
        }
        return x < y ? -1 : 1;
    }
    return ia < ib ? -1 : ib < ia ? 1 : 0;
}

/* dnsHasSuffix(a, b): whether constraint `a` covers name `b` */
static int dns_has_suffix(const void *av, const void *bv)
{
    const lc_gobytes *a = av, *b = bv;
    size_t            la = a->n, lb = b->n;
    if (la > lb)
        return 0;
    size_t off = lb - la;
    for (size_t i = la; i-- > 0u;) {
        uint8_t ar = a->p[i], br = b->p[i + off];
        if (ar == br)
            continue;
        if (br < ar) {
            uint8_t t = ar;
            ar = br;
            br = t;
        }
        if (ar >= 'A' && ar <= 'Z' && br == ar + 'a' - 'A')
            continue;
        return 0;
    }
    if (la > 0u && a->p[0] != '.' && lb > la && b->p[lb - la - 1u] != '.')
        return 0;
    return 1;
}

/* trimFirstLabel: from the first '.' on, or nothing */
static lc_gobytes trim_first_label(lc_gobytes s)
{
    const uint8_t *dot = s.n != 0u ? memchr(s.p, '.', s.n) : NULL;
    if (dot == NULL)
        return (lc_gobytes){ NULL, 0 };
    return (lc_gobytes){ dot, s.n - (size_t)(dot - s.p) };
}

static int eq_fold(lc_gobytes a, lc_gobytes b)
{
    if (a.n != b.n)
        return 0;
    for (size_t i = 0; i < a.n; i++)
        if (lower(a.p[i]) != lower(b.p[i]))
            return 0;
    return 1;
}

typedef struct {
    int                present; /* a non-nil interface: there were constraints */
    int                all;
    int                permitted;
    const lc_gobytes **set;
    size_t             n;
    /* parentConstraints: lower(trimFirstLabel(name)) -> lower(name), a later name overwriting */
    lc_gobytes *parent_key, *parent_val;
    size_t      nparent;
} dnsc;

static void dnsc_free(dnsc *c)
{
    free(c->set);
    free(c->parent_key);
    free(c->parent_val);
    memset(c, 0, sizeof *c);
}

/* newDNSConstraints */
static int dnsc_new(dnsc *c, const lc_gobytes_list *l, int permitted)
{
    memset(c, 0, sizeof *c);
    if (l->n == 0u)
        return 0;
    c->present = 1;
    for (size_t i = 0; i < l->n; i++) {
        if (l->a[i].n == 0u) {
            c->all = 1;
            return 0;
        }
    }
    c->permitted = permitted;
    c->set = malloc(l->n * sizeof *c->set);
    if (c->set == NULL)
        return -2;
    for (size_t i = 0; i < l->n; i++)
        c->set[i] = &l->a[i];
    c->n = sort_and_prune((const void **)c->set, l->n, dns_compare, dns_has_suffix);
    if (!permitted) {
        c->parent_key = malloc(c->n * sizeof *c->parent_key);
        c->parent_val = malloc(c->n * sizeof *c->parent_val);
        if (c->parent_key == NULL || c->parent_val == NULL)
            return -2;
        for (size_t i = 0; i < c->n; i++) {
            lc_gobytes name = *c->set[i];
            lc_gobytes trimmed = trim_first_label(name);
            if (trimmed.n == 0u)
                continue;
            size_t k = 0;
            while (k < c->nparent && !eq_fold(c->parent_key[k], trimmed))
                k++;
            c->parent_key[k] = trimmed;
            c->parent_val[k] = name;
            if (k == c->nparent)
                c->nparent++;
        }
    }
    return 0;
}

/* dnsConstraints.query: 1 with the constraint in `hit`, `*hit_lower` when Go lower-cased it */
static int dnsc_query(const dnsc *c, lc_gobytes s, lc_gobytes *hit, int *hit_lower)
{
    *hit_lower = 0;
    if (c->all) {
        *hit = (lc_gobytes){ (const uint8_t *)"", 0 };
        return 1;
    }
    const lc_gobytes *m = set_search((const void **)c->set, c->n, &s, dns_compare, dns_has_suffix);
    if (m != NULL) {
        *hit = *m;
        return 1;
    }
    if (!c->permitted && s.n > 0u && s.p[0] == '*') {
        lc_gobytes trimmed = trim_first_label(s);
        for (size_t k = 0; k < c->nparent; k++) {
            if (eq_fold(c->parent_key[k], trimmed)) {
                *hit = c->parent_val[k];
                *hit_lower = 1;
                return 1;
            }
        }
    }
    return 0;
}

static void put_lowered(lc_obuf *b, lc_gobytes s, int low)
{
    for (size_t k = 0; k < s.n; k++)
        lc_obuf_byte(b, low ? lower(s.p[k]) : s.p[k]);
}

/* -- IP ranges -- */

typedef struct {
    int          present;
    lc_goipnet  *nets; /* masked copies */
    const void **v4, **v6;
    size_t       n4, n6;
} ipc;

static void ipc_free(ipc *c)
{
    free(c->nets);
    free(c->v4);
    free(c->v6);
    memset(c, 0, sizeof *c);
}

/* IPNet.Contains, for an IP of the net's own length (the only kind asked here: a v4-mapped net or
 * SAN is refused at parse time) */
static int net_contains(const lc_goipnet *n, const uint8_t *ip, size_t len)
{
    if (len != n->len)
        return 0;
    for (size_t i = 0; i < len; i++)
        if ((n->ip[i] & n->mask[i]) != (ip[i] & n->mask[i]))
            return 0;
    return 1;
}

/* ipNetworkSubset */
static int ip_subset(const void *av, const void *bv)
{
    const lc_goipnet *a = av, *b = bv;
    if (!net_contains(a, b->ip, b->len))
        return 0;
    uint8_t bc[16];
    for (size_t i = 0; i < b->len; i++)
        bc[i] = (uint8_t)(b->ip[i] | (uint8_t)~b->mask[i]);
    return net_contains(a, bc, b->len);
}

/* bytes.Compare of two IPs */
static int ip_bytes_cmp(const uint8_t *a, size_t an, const uint8_t *b, size_t bn)
{
    int c = memcmp(a, b, an < bn ? an : bn);
    if (c == 0)
        c = an < bn ? -1 : an > bn ? 1 : 0;
    return c < 0 ? -1 : c > 0 ? 1 : 0;
}

/* ipNetworkCompare */
static int ip_compare(const void *av, const void *bv)
{
    const lc_goipnet *a = av, *b = bv;
    int               c = ip_bytes_cmp(a->ip, a->len, b->ip, b->len);
    return c != 0 ? c : ip_bytes_cmp(a->mask, a->len, b->mask, b->len);
}

/* ipBinarySearch: the constraint's IP against a bare IP, passed as a net of its length */
static int ip_search_cmp(const void *av, const void *bv)
{
    const lc_goipnet *a = av, *b = bv;
    return ip_bytes_cmp(a->ip, a->len, b->ip, b->len);
}

/* ipMatch */
static int ip_match(const void *av, const void *bv)
{
    const lc_goipnet *a = av, *b = bv;
    return net_contains(a, b->ip, b->len);
}

/* newIPNetConstraints */
static int ipc_new(ipc *c, const lc_goipnet *l, size_t n)
{
    memset(c, 0, sizeof *c);
    if (n == 0u)
        return 0;
    c->present = 1;
    c->nets = malloc(n * sizeof *c->nets);
    c->v4 = malloc(n * sizeof *c->v4);
    c->v6 = malloc(n * sizeof *c->v6);
    if (c->nets == NULL || c->v4 == NULL || c->v6 == NULL)
        return -2;
    for (size_t i = 0; i < n; i++) {
        c->nets[i] = l[i];
        for (size_t k = 0; k < l[i].len; k++)
            c->nets[i].ip[k] = (uint8_t)(l[i].ip[k] & l[i].mask[k]);
        if (l[i].len == 4u)
            c->v4[c->n4++] = &c->nets[i];
        else
            c->v6[c->n6++] = &c->nets[i];
    }
    c->n4 = sort_and_prune(c->v4, c->n4, ip_compare, ip_subset);
    c->n6 = sort_and_prune(c->v6, c->n6, ip_compare, ip_subset);
    return 0;
}

/* ipConstraints.query */
static const lc_goipnet *ipc_query(const ipc *c, const uint8_t *ip, size_t len)
{
    lc_goipnet t;
    memset(&t, 0, sizeof t);
    memcpy(t.ip, ip, len);
    t.len = len;
    if (len == 4u)
        return set_search(c->v4, c->n4, &t, ip_search_cmp, ip_match);
    return set_search(c->v6, c->n6, &t, ip_search_cmp, ip_match);
}

/* IPNet.String: the network and its prefix length, the mask being a prefix */
static void put_ipnet(lc_obuf *b, const lc_goipnet *n)
{
    put_ip(b, n->ip, n->len);
    int ones = 0;
    for (size_t i = 0; i < n->len; i++)
        for (int k = 7; k >= 0; k--)
            ones += (n->mask[i] >> k) & 1;
    put(b, "/");
    put_int(b, ones);
}

/* domainNameValid(s, false) (parser.go:1378-1433 in go1.27.1) */
static int domain_ok(lc_gobytes s)
{
    if (s.n == 0u)
        return 1;
    if (s.p[s.n - 1u] == '.')
        return 0;
    size_t start = 0;
    for (size_t k = 0; k <= s.n; k++) {
        if (k < s.n && (s.p[k] < 33u || s.p[k] > 126u))
            return 0;
        if (k == s.n || s.p[k] == '.') {
            if (k == start)
                return 0;
            start = k + 1u;
        }
    }
    return 1;
}

/* -- mailboxes -- */

typedef struct {
    lc_obuf    local;
    lc_gobytes domain;
} mailbox;

/* parseRFC2821Mailbox (verify.go:265-404 in go1.27.1): the local part unescaped, the domain as
 * written. 1 when it parses; `m->local` is the caller's to free either way. */
static int parse_mailbox(lc_gobytes s, mailbox *m)
{
    memset(m, 0, sizeof *m);
    const uint8_t *in = s.p;
    size_t         n = s.n, i = 0;
    if (n == 0u)
        return 0;
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
                if (d == 11u || d == 12u || (d >= 1u && d <= 9u) || (d >= 14u && d <= 127u)) {
                    lc_obuf_byte(&m->local, d);
                    i++;
                } else {
                    return 0;
                }
            } else if (c == 11u || c == 12u || c == 32u || c == 33u || c == 127u || (c >= 1u && c <= 8u) ||
                       (c >= 14u && c <= 31u) || (c >= 35u && c <= 91u) || (c >= 93u && c <= 126u)) {
                lc_obuf_byte(&m->local, c);
            } else {
                return 0;
            }
        }
    } else {
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
            lc_obuf_byte(&m->local, in[i]);
            i++;
        }
        if (m->local.n == 0u)
            return 0;
        const char *l = m->local.p;
        if (l[0] == '.' || l[m->local.n - 1u] == '.')
            return 0;
        for (size_t k = 0; k + 1u < m->local.n; k++)
            if (l[k] == '.' && l[k + 1u] == '.')
                return 0;
    }
    if (i >= n || in[i] != '@')
        return 0;
    i++;
    lc_gobytes d = { in + i, n - i };
    if (!domain_ok(d) || (d.n > 0u && memchr(d.p, '@', d.n) != NULL))
        return 0;
    m->domain = d;
    return 1;
}

typedef struct {
    int             present;
    mailbox        *full; /* the constraints that are whole addresses */
    size_t          nfull;
    lc_gobytes_list domains;
    dnsc            dns;
} emailc;

static void emailc_free(emailc *c)
{
    for (size_t i = 0; i < c->nfull; i++)
        free(c->full[i].local.p);
    free(c->full);
    free(c->domains.a);
    dnsc_free(&c->dns);
    memset(c, 0, sizeof *c);
}

/* newEmailConstraints: a whole-address constraint is matched on its local part as written and its
 * domain folded */
static int emailc_new(emailc *c, const lc_gobytes_list *l, int permitted)
{
    memset(c, 0, sizeof *c);
    if (l->n == 0u)
        return 0;
    c->present = 1;
    for (size_t i = 0; i < l->n; i++) {
        if (l->a[i].n == 0u || memchr(l->a[i].p, '@', l->a[i].n) == NULL) {
            lc_gobytes *v = realloc(c->domains.a, (c->domains.n + 1u) * sizeof *v);
            if (v == NULL)
                return -2;
            c->domains.a = v;
            c->domains.a[c->domains.n++] = l->a[i];
            continue;
        }
        mailbox m;
        if (!parse_mailbox(l->a[i], &m)) {
            free(m.local.p);
            continue;
        }
        mailbox *v = realloc(c->full, (c->nfull + 1u) * sizeof *v);
        if (v == NULL) {
            free(m.local.p);
            return -2;
        }
        c->full = v;
        c->full[c->nfull++] = m;
    }
    if (c->domains.n > 0u)
        return dnsc_new(&c->dns, &c->domains, permitted);
    return 0;
}

/* emailConstraints.query, `s` with its domain lower-cased already */
static int emailc_query(const emailc *c, const mailbox *s, lc_obuf *hit)
{
    for (size_t i = 0; i < c->nfull; i++) {
        const mailbox *f = &c->full[i];
        if (f->local.n == s->local.n && (f->local.n == 0u || memcmp(f->local.p, s->local.p, f->local.n) == 0) &&
            eq_fold(f->domain, s->domain)) {
            putn(hit, s->local.p, s->local.n);
            put(hit, "@");
            putn(hit, s->domain.p, s->domain.n);
            return 1;
        }
    }
    if (!c->dns.present)
        return 0;
    lc_gobytes h;
    int        low;
    if (!dnsc_query(&c->dns, s->domain, &h, &low))
        return 0;
    put_lowered(hit, h, low);
    return 1;
}

/* -- the chain -- */

typedef struct {
    ipc    ip_p, ip_e;
    dnsc   dns_p, dns_e, uri_p, uri_e;
    emailc email_p, email_e;
    size_t index;
} ccons;

static void ccons_free(ccons *c)
{
    ipc_free(&c->ip_p);
    ipc_free(&c->ip_e);
    dnsc_free(&c->dns_p);
    dnsc_free(&c->dns_e);
    dnsc_free(&c->uri_p);
    dnsc_free(&c->uri_e);
    emailc_free(&c->email_p);
    emailc_free(&c->email_e);
}

typedef struct {
    const lc_gouri *uri;
    lc_obuf         domain; /* the lower-cased Host, or SplitHostPort's host */
} puri;

static void not_permitted(goerr *e, const char *type, const void *p, size_t pn)
{
    err_clear(e);
    e->set = 1;
    put(&e->text, type);
    put(&e->text, " ");
    put_q(&e->text, p, pn);
    put(&e->text, " is not permitted by any constraint");
}

static void excluded(goerr *e, const char *type, const void *p, size_t pn, const void *c, size_t cn)
{
    err_clear(e);
    e->set = 1;
    put(&e->text, type);
    put(&e->text, " ");
    put_q(&e->text, p, pn);
    put(&e->text, " is excluded by constraint ");
    put_q(&e->text, c, cn);
}

/* chainConstraints.check for one certificate's set */
static int cc_check(const ccons *cc, const lc_gocert *c, const puri *uris, const mailbox *mails, size_t nm,
                    goerr *e)
{
    for (size_t i = 0; i < c->ip_addresses.n; i++) {
        const uint8_t *ip = c->ip_addresses.a[i].p;
        size_t         len = c->ip_addresses.a[i].n;
        lc_obuf        s = { 0 };
        put_ip(&s, ip, len);
        const char *sp = s.p != NULL ? s.p : "";
        if (cc->ip_p.present && ipc_query(&cc->ip_p, ip, len) == NULL) {
            not_permitted(e, "IP address", sp, s.n);
            free(s.p);
            return -1;
        }
        const lc_goipnet *hit = cc->ip_e.present ? ipc_query(&cc->ip_e, ip, len) : NULL;
        if (hit != NULL) {
            lc_obuf h = { 0 };
            put_ipnet(&h, hit);
            excluded(e, "IP address", sp, s.n, h.p != NULL ? h.p : "", h.n);
            free(h.p);
            free(s.p);
            return -1;
        }
        free(s.p);
    }
    for (size_t i = 0; i < c->dns_names.n; i++) {
        lc_gobytes d = c->dns_names.a[i];
        lc_gobytes h;
        int        low;
        if (!domain_ok(d)) {
            err_clear(e);
            e->set = 1;
            put(&e->text, "x509: cannot parse dnsName ");
            put_q(&e->text, d.p, d.n);
            return -1;
        }
        if (cc->dns_p.present && !dnsc_query(&cc->dns_p, d, &h, &low)) {
            not_permitted(e, "DNS name", d.p, d.n);
            return -1;
        }
        if (cc->dns_e.present && dnsc_query(&cc->dns_e, d, &h, &low)) {
            lc_obuf hs = { 0 };
            put_lowered(&hs, h, low);
            excluded(e, "DNS name", d.p, d.n, hs.p != NULL ? hs.p : "", hs.n);
            free(hs.p);
            return -1;
        }
    }
    for (size_t i = 0; i < c->uris_n; i++) {
        lc_gobytes      dom = { (const uint8_t *)uris[i].domain.p, uris[i].domain.n };
        const lc_gouri *u = uris[i].uri;
        lc_gobytes      h;
        int             low;
        if (!domain_ok(dom)) {
            err_clear(e);
            e->set = 1;
            put(&e->text, "x509: internal error: URI SAN ");
            put_q(&e->text, u->string, u->string_n);
            put(&e->text, " failed to parse");
            return -1;
        }
        if (cc->uri_p.present && !dnsc_query(&cc->uri_p, dom, &h, &low)) {
            not_permitted(e, "URI", u->string, u->string_n);
            return -1;
        }
        if (cc->uri_e.present && dnsc_query(&cc->uri_e, dom, &h, &low)) {
            lc_obuf hs = { 0 };
            put_lowered(&hs, h, low);
            excluded(e, "URI", u->string, u->string_n, hs.p != NULL ? hs.p : "", hs.n);
            free(hs.p);
            return -1;
        }
    }
    for (size_t i = 0; i < nm; i++) {
        const mailbox *m = &mails[i];
        lc_obuf        str = { 0 }, hit = { 0 };
        putn(&str, m->local.p, m->local.n);
        put(&str, "@");
        putn(&str, m->domain.p, m->domain.n);
        int rc = 0;
        if (!domain_ok(m->domain)) {
            err_clear(e);
            e->set = 1;
            put(&e->text, "x509: cannot parse rfc822Name ");
            put_q(&e->text, str.p, str.n);
            rc = -1;
        } else if (cc->email_p.present && !emailc_query(&cc->email_p, m, &hit)) {
            not_permitted(e, "email address", str.p, str.n);
            rc = -1;
        } else {
            free(hit.p);
            hit = (lc_obuf){ 0 };
            if (cc->email_e.present && emailc_query(&cc->email_e, m, &hit)) {
                excluded(e, "email address", str.p, str.n, hit.p != NULL ? hit.p : "", hit.n);
                rc = -1;
            }
        }
        free(hit.p);
        free(str.p);
        if (rc != 0)
            return rc;
    }
    return 0;
}

/* net.SplitHostPort's host, or its *AddrError's text (GOROOT/src/net/ipsock.go) */
static int split_host_port(const char *hp, size_t n, lc_obuf *host, lc_obuf *why)
{
    const char *miss = "missing port in address", *many = "too many colons in address";
    const char *reason = NULL;
    size_t      i = n, j = 0, k = 0;
    for (size_t x = n; x-- > 0u;) {
        if (hp[x] == ':') {
            i = x;
            break;
        }
    }
    if (i == n) {
        reason = miss;
    } else if (hp[0] == '[') {
        const char *e = memchr(hp, ']', n);
        if (e == NULL) {
            reason = "missing ']' in address";
        } else {
            size_t end = (size_t)(e - hp);
            if (end + 1u == n)
                reason = miss;
            else if (end + 1u != i)
                reason = hp[end + 1u] == ':' ? many : miss;
            else {
                putn(host, hp + 1, end - 1u);
                j = 1;
                k = end + 1u;
            }
        }
    } else if (memchr(hp, ':', i) != NULL) {
        reason = many;
    } else {
        putn(host, hp, i);
    }
    if (reason == NULL && memchr(hp + j, '[', n - j) != NULL)
        reason = "unexpected '[' in address";
    if (reason == NULL && memchr(hp + k, ']', n - k) != NULL)
        reason = "unexpected ']' in address";
    if (reason != NULL) {
        put(why, "address ");
        putn(why, hp, n);
        put(why, ": ");
        put(why, reason);
        return -1;
    }
    return 0;
}

/* parseURIs (constraints.go) */
static int parse_uris(const lc_gocert *c, puri *out, goerr *e)
{
    for (size_t i = 0; i < c->uris_n; i++) {
        const lc_gouri *u = &c->uris[i];
        puri           *p = &out[i];
        p->uri = u;
        for (size_t k = 0; k < u->host_n; k++)
            lc_obuf_byte(&p->domain, lower((uint8_t)u->host[k]));
        if (u->host_n == 0u) {
            err_clear(e);
            e->set = 1;
            put(&e->text, "URI with empty host (");
            put_q(&e->text, u->string, u->string_n);
            put(&e->text, ") cannot be matched against constraints");
            return -1;
        }
        if (memchr(p->domain.p, ':', p->domain.n) != NULL && p->domain.p[p->domain.n - 1u] != ']') {
            lc_obuf host = { 0 }, why = { 0 };
            if (split_host_port(u->host, u->host_n, &host, &why) != 0) {
                err_clear(e);
                e->set = 1;
                put(&e->text, "cannot parse URI host ");
                put_q(&e->text, u->host, u->host_n);
                put(&e->text, ": ");
                putn(&e->text, why.p, why.n);
                free(host.p);
                free(why.p);
                return -1;
            }
            free(p->domain.p);
            p->domain = host; /* SplitHostPort of the Host as written: not lower-cased */
            free(why.p);
        }
        const char *h = p->domain.p != NULL ? p->domain.p : "";
        size_t      hn = p->domain.n;
        lc_netip    ip;
        if (lc_netip_parse(h, hn, &ip, NULL) == 0 || (hn > 0u && h[0] == '[' && h[hn - 1u] == ']')) {
            err_clear(e);
            e->set = 1;
            put(&e->text, "URI with IP (");
            put_q(&e->text, u->string, u->string_n);
            put(&e->text, ") cannot be matched against constraints");
            return -1;
        }
    }
    return 0;
}

static int ccons_new(ccons *cc, const lc_gocert *c, size_t index)
{
    memset(cc, 0, sizeof *cc);
    cc->index = index;
    if (ipc_new(&cc->ip_p, c->permitted_ip, c->permitted_ip_n) != 0 ||
        ipc_new(&cc->ip_e, c->excluded_ip, c->excluded_ip_n) != 0 ||
        dnsc_new(&cc->dns_p, &c->permitted_dns, 1) != 0 || dnsc_new(&cc->dns_e, &c->excluded_dns, 0) != 0 ||
        dnsc_new(&cc->uri_p, &c->permitted_uri, 1) != 0 || dnsc_new(&cc->uri_e, &c->excluded_uri, 0) != 0 ||
        emailc_new(&cc->email_p, &c->permitted_email, 1) != 0 ||
        emailc_new(&cc->email_e, &c->excluded_email, 0) != 0)
        return -2;
    return 0;
}

/* The names of one certificate, checked against every constraint set from `from` on. */
static int check_cert(const ccons *cs, size_t from, size_t ncs, const lc_gocert *c, goerr *e)
{
    size_t   nu = c->uris_n, nm = c->email_addresses.n;
    puri    *uris = calloc(nu + 1u, sizeof *uris);
    mailbox *mails = calloc(nm + 1u, sizeof *mails);
    lc_obuf *low = calloc(nm + 1u, sizeof *low);
    int      rc = uris == NULL || mails == NULL || low == NULL ? -2 : parse_uris(c, uris, e);
    size_t   parsed = 0;
    for (size_t k = 0; rc == 0 && k < nm; k++) {
        /* parseMailboxes: each must parse, and its domain is lower-cased */
        parsed = k + 1u;
        if (!parse_mailbox(c->email_addresses.a[k], &mails[k])) {
            err_clear(e);
            e->set = 1;
            put(&e->text, "cannot parse rfc822Name ");
            put_q(&e->text, c->email_addresses.a[k].p, c->email_addresses.a[k].n);
            rc = -1;
            break;
        }
        put_lowered(&low[k], mails[k].domain, 1);
        mails[k].domain = (lc_gobytes){ (const uint8_t *)(low[k].p != NULL ? low[k].p : ""), low[k].n };
    }
    for (size_t k = from; rc == 0 && k < ncs; k++)
        rc = cc_check(&cs[k], c, uris, mails, nm, e);
    for (size_t k = 0; uris != NULL && k < nu; k++)
        free(uris[k].domain.p);
    for (size_t k = 0; k < parsed; k++) {
        free(mails[k].local.p);
        free(low[k].p);
    }
    free(uris);
    free(mails);
    free(low);
    return rc;
}

/* checkChainConstraints: 0, -1 with the error, -2 */
static int chain_constraints(chainv chain, goerr *e)
{
    ccons *cs = NULL;
    size_t ncs = 0;
    int    rc = 0;
    for (size_t i = 0; i < chain.n && rc == 0; i++) {
        if (!chain.v[i]->has_name_constraints)
            continue;
        ccons *v = realloc(cs, (ncs + 1u) * sizeof *v);
        if (v == NULL) {
            rc = -2;
            break;
        }
        cs = v;
        rc = ccons_new(&cs[ncs], chain.v[i], i);
        ncs++;
    }
    size_t cur = 0;
    for (size_t i = 0; rc == 0 && ncs > 0u && i < chain.n; i++) {
        const lc_gocert *c = chain.v[i];
        if (!c->has_san)
            continue;
        if (i >= cs[cur].index) {
            int done = 0;
            while (cs[cur].index <= i) {
                if (cur + 1u == ncs) {
                    done = 1;
                    break;
                }
                cur++;
            }
            if (done)
                break;
        }
        rc = check_cert(cs, cur, ncs, c, e);
    }
    for (size_t i = 0; i < ncs; i++)
        ccons_free(&cs[i]);
    free(cs);
    if (e->text.oom)
        rc = -2;
    return rc;
}

/* ---- Verify (verify.go:548-667) ----------------------------------------------------------------- */

void lc_gochains_free(lc_gochains *c)
{
    if (c == NULL)
        return;
    for (size_t i = 0; i < c->n; i++)
        free(c->a[i].certs);
    free(c->a);
    c->a = NULL;
    c->n = 0;
}

int lc_go_verify(const lc_gocert *leaf, const lc_goverify_opts *o, lc_gochains *out, lc_obuf *err)
{
    vctx x;
    memset(&x, 0, sizeof x);
    x.o = o;
    x.inter = o->intermediates;
    x.roots = o->roots;
    if (o->have_time) {
        x.now_sec = o->now_sec;
        x.now_nsec = o->now_nsec;
    } else {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        x.now_sec = ts.tv_sec;
        x.now_nsec = (int32_t)ts.tv_nsec;
    }
    if (x.roots == NULL) {
        lc_obuf why = { 0 };
        x.roots = lc_go_system_roots(&why);
        if (x.roots == NULL) {
            /* SystemRootsError */
            put(err, LC_GO("x509: failed to load system roots and no roots provided"));
            if (why.n > 0u) {
                put(err, "; ");
                putn(err, why.p, why.n);
            }
            free(why.p);
            return err->oom ? -2 : -1;
        }
        free(why.p);
    }

    goerr   e = { 0 }, hint = { 0 };
    chainsv cands = { 0 };
    chainv  none = { NULL, 0 };

    if (is_valid(leaf, LEAF, none, &x, &e) != 0)
        goto fail;
    if (o->dns_name != NULL && o->dns_name_n > 0u &&
        verify_hostname(leaf, o->dns_name, o->dns_name_n, &e) != 0)
        goto fail;

    if (pool_contains(x.roots, leaf)) {
        chainv one;
        if (fresh(none, leaf, &one) != 0 || chains_push(&cands, one) != 0)
            goto oom;
    } else {
        /* buildChains([]*Certificate{c}, nil, &opts): the chain starts with the leaf */
        const lc_gocert *start[1] = { leaf };
        build_chains(&x, leaf, (chainv){ start, 1 }, &cands, &e);
        if (x.oom)
            goto oom;
        if (e.set)
            goto fail;
    }

    int        any_usage = 0, serverauth = LC_GO_EKU_SERVER_AUTH;
    const int *usages = o->key_usages;
    size_t     nusages = o->key_usages_n;
    for (size_t i = 0; i < nusages; i++)
        if (usages[i] == LC_GO_EKU_ANY)
            any_usage = 1;
    if (nusages == 0u) {
        usages = &serverauth;
        nusages = 1;
    }

    /* slices.DeleteFunc: policies, then key usage, then constraints, the first constraint error
     * kept as the answer should nothing survive */
    size_t invalid_policies = 0, incompatible = 0, kept = 0;
    for (size_t i = 0; i < cands.n; i++) {
        chainv ch = cands.a[i];
        int    oom = 0, drop = 0;
        if (!policies_valid(ch, o, &oom)) {
            if (oom)
                goto oom;
            invalid_policies++;
            drop = 1;
        } else if (!any_usage && !chain_key_usage(ch, usages, nusages)) {
            incompatible++;
            drop = 1;
        } else {
            goerr ce = { 0 };
            int   crc = chain_constraints(ch, &ce);
            if (crc == -2) {
                err_clear(&ce);
                goto oom;
            }
            if (crc != 0) {
                if (!hint.set) {
                    hint.set = 1;
                    put(&hint.text, LC_GO("x509: a root or intermediate certificate is not authorized to sign for this name: "));
                    putn(&hint.text, ce.text.p, ce.text.n);
                }
                drop = 1;
            }
            err_clear(&ce);
        }
        if (drop)
            free(ch.v);
        else
            cands.a[kept++] = ch;
    }
    cands.n = kept;

    if (cands.n == 0u) {
        if (hint.set) {
            err_move(&e, &hint);
            goto fail;
        }
        err_clear(&e);
        e.set = 1;
        if (incompatible > 0u && invalid_policies == 0u) {
            put(&e.text, LC_GO("x509: certificate specifies an incompatible key usage"));
            goto fail;
        }
        put(&e.text, LC_GO("x509: no valid chains built"));
        const char *sep = ": ";
        if (incompatible > 0u) {
            put(&e.text, sep);
            put_int(&e.text, (long long)incompatible);
            put(&e.text, " candidate chains with incompatible key usage");
            sep = ", ";
        }
        if (invalid_policies > 0u) {
            put(&e.text, sep);
            put_int(&e.text, (long long)invalid_policies);
            put(&e.text, " candidate chains with invalid policies");
        }
        goto fail;
    }
    err_clear(&hint);

    if (out != NULL) {
        out->a = calloc(cands.n, sizeof *out->a);
        if (out->a == NULL)
            goto oom;
        for (size_t i = 0; i < cands.n; i++) {
            out->a[i].certs = cands.a[i].v;
            out->a[i].n = cands.a[i].n;
            cands.a[i].v = NULL;
        }
        out->n = cands.n;
    }
    chains_free(&cands);
    err_clear(&e);
    return 0;

fail:
    err_clear(&hint);
    putn(err, e.text.p, e.text.n);
    {
        int rc = e.text.oom || err->oom ? -2 : -1;
        err_clear(&e);
        chains_free(&cands);
        return rc;
    }
oom:
    err_clear(&hint);
    err_clear(&e);
    chains_free(&cands);
    return -2;
}

int lc_go_verify_peer(const lc_gocert *certs, size_t n, const char *server_name, lc_obuf *err)
{
    lc_gopool *inter = lc_gopool_new();
    if (inter == NULL)
        return -2;
    for (size_t i = 1; i < n; i++) {
        if (pool_add_borrowed(inter, &certs[i]) != 0) {
            lc_gopool_free(inter);
            return -2;
        }
    }
    lc_goverify_opts o;
    memset(&o, 0, sizeof o);
    o.dns_name = server_name;
    o.dns_name_n = server_name != NULL ? strlen(server_name) : 0u;
    o.intermediates = inter;
    int rc = lc_go_verify(&certs[0], &o, NULL, err);
    lc_gopool_free(inter);
    return rc;
}
