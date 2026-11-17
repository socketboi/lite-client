/* The node's ports as a hop address — see core/portunion.h. */

#include "core/portunion.h"

#include "core/rnd.h"

#include <stdlib.h>
#include <string.h>

/* strconv.ParseUint(s, 10, 16): decimal digits and nothing else, at least one, the value within
 * sixteen bits. */
static int parse_u16(const char *s, size_t n, uint16_t *out)
{
    uint32_t v = 0;
    if (n == 0u)
        return -1;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9')
            return -1;
        v = v * 10u + (uint32_t)(s[i] - '0');
        if (v > 65535u)
            return -1;
    }
    *out = (uint16_t)v;
    return 0;
}

void lc_hop_ports_free(lc_hop_ports *p)
{
    free(p->lo);
    free(p->hi);
    p->lo = p->hi = NULL;
    p->n = 0;
    p->total = 0;
}

int lc_hop_ports_parse(const char *s, lc_hop_ports *out)
{
    /* ParsePortUnion (vendor/hysteria/extras/utils/portunion.go:21-60): "all" and "*" are every port;
     * otherwise each comma-separated piece is a range `a-b` — exactly two halves, turned round when
     * reversed — or a single port, and any piece that is neither makes the whole string nothing. */
    size_t   pieces = 1u;
    uint16_t *lo, *hi;
    memset(out, 0, sizeof *out);
    for (const char *p = s; *p != '\0'; p++)
        pieces += *p == ',';
    lo = malloc(pieces * sizeof *lo);
    hi = malloc(pieces * sizeof *hi);
    if (lo == NULL || hi == NULL) {
        free(lo);
        free(hi);
        return -1;
    }
    unsigned n = 0;
    if (strcmp(s, "all") == 0 || strcmp(s, "*") == 0) {
        lo[0] = 0;
        hi[0] = 65535u;
        n = 1;
    } else {
        const char *p = s;
        for (;;) {
            const char *end = strchr(p, ',');
            size_t      len = end != NULL ? (size_t)(end - p) : strlen(p);
            const char *dash = memchr(p, '-', len);
            uint16_t    a = 0, b = 0;
            if (dash != NULL) {
                /* `strings.Split(portStr, "-")` must give two: a second dash is refused. */
                if (memchr(dash + 1, '-', len - (size_t)(dash - p) - 1u) != NULL ||
                    parse_u16(p, (size_t)(dash - p), &a) != 0 ||
                    parse_u16(dash + 1, len - (size_t)(dash - p) - 1u, &b) != 0)
                    goto refused;
                if (a > b) {
                    uint16_t t = a;
                    a = b;
                    b = t;
                }
            } else {
                if (parse_u16(p, len, &a) != 0)
                    goto refused;
                b = a;
            }
            lo[n] = a;
            hi[n] = b;
            n++;
            if (end == NULL)
                break;
            p = end + 1;
        }
    }

    /* Normalize (:64-86): sorted by start then end, and a range that starts at most one past the
     * last one's end is folded into it. */
    for (unsigned i = 1; i < n; i++) {
        uint16_t a = lo[i], b = hi[i];
        unsigned j = i;
        while (j > 0u && (lo[j - 1u] > a || (lo[j - 1u] == a && hi[j - 1u] > b))) {
            lo[j] = lo[j - 1u];
            hi[j] = hi[j - 1u];
            j--;
        }
        lo[j] = a;
        hi[j] = b;
    }
    unsigned m = 0;
    for (unsigned i = 0; i < n; i++) {
        if (m > 0u && (uint32_t)lo[i] <= (uint32_t)hi[m - 1u] + 1u) {
            if (hi[i] > hi[m - 1u])
                hi[m - 1u] = hi[i];
        } else {
            lo[m] = lo[i];
            hi[m] = hi[i];
            m++;
        }
    }
    out->lo = lo;
    out->hi = hi;
    out->n = m;
    out->total = 0;
    for (unsigned i = 0; i < m; i++)
        out->total += (uint32_t)hi[i] - lo[i] + 1u;
    return 0;

refused:
    free(lo);
    free(hi);
    return -1;
}

int lc_hop_ports_pick(const lc_hop_ports *p, uint16_t *out)
{
    /* An index into the expanded list, drawn as lc_hop_port draws — rand.Intn's rejection — and
     * found in the ranges it expands from. */
    uint32_t span = p->total;
    uint32_t reject = (uint32_t)(0u - span) % span;
    uint32_t r = 0;
    do {
        if (lc_rnd((uint8_t *)&r, sizeof r) != 0)
            return -1;
    } while (r < reject);
    r %= span;
    for (unsigned i = 0; i < p->n; i++) {
        uint32_t size = (uint32_t)p->hi[i] - p->lo[i] + 1u;
        if (r < size) {
            *out = (uint16_t)(p->lo[i] + r);
            return 0;
        }
        r -= size;
    }
    return -1;
}
