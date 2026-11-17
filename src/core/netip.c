/* netip.ParseAddr (GOROOT/src/net/netip/netip.go:114-341, go1.26.6), as it reads and as it
 * refuses. */
#include "core/netip.h"

#include "core/goquote.h"
#include "tls/goerr.h"

#include <string.h>

/* parseAddrError.Error (:143-149): ParseAddr(%q): msg, and " (at %q)" where it names the place
 * (`at` NULL for none). The messages are LC_GO, so that check-qgo-reasons holds each to netip. */
static int refuse(lc_obuf *err, const char *in, size_t n, const char *msg, const char *at,
                  size_t at_n)
{
    if (err == NULL)
        return -1;
    /* the first %q is the input, %s the message, a second %q the place */
    const char *f = at != NULL && at_n > 0u ? LC_GO("ParseAddr(%q): %s (at %q)")
                                            : LC_GO("ParseAddr(%q): %s");
    int quotes = 0;
    for (; *f != '\0'; f++) {
        if (f[0] == '%' && f[1] == 'q') {
            if (quotes++ == 0)
                lc_go_quote(err, (const uint8_t *)in, n);
            else
                lc_go_quote(err, (const uint8_t *)at, at_n);
            f++;
        } else if (f[0] == '%' && f[1] == 's') {
            lc_obuf_add(err, msg, strlen(msg));
            f++;
        } else {
            lc_obuf_byte(err, (uint8_t)*f);
        }
    }
    return -1;
}

/* parseIPv4Fields (:154-193): in[off:end] into four bytes. */
static int ipv4_fields(const char *in, size_t in_n, size_t off, size_t end, uint8_t fields[4],
                       lc_obuf *err)
{
    const char *s = in + off;
    size_t      n = end - off;
    unsigned    val = 0, pos = 0, dig = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] >= '0' && s[i] <= '9') {
            if (dig == 1u && val == 0u)
                return refuse(err, in, in_n, LC_GO("IPv4 field has octet with leading zero"), NULL, 0);
            val = val * 10u + (unsigned)(s[i] - '0');
            dig++;
            if (val > 255u)
                return refuse(err, in, in_n, LC_GO("IPv4 field has value >255"), NULL, 0);
        } else if (s[i] == '.') {
            if (i == 0u || i == n - 1u || s[i - 1u] == '.')
                return refuse(err, in, in_n, LC_GO("IPv4 field must have at least one digit"), s + i,
                              n - i);
            if (pos == 3u)
                return refuse(err, in, in_n, LC_GO("IPv4 address too long"), NULL, 0);
            fields[pos++] = (uint8_t)val;
            val = 0;
            dig = 0;
        } else {
            return refuse(err, in, in_n, LC_GO("unexpected character"), s + i, n - i);
        }
    }
    if (pos < 3u)
        return refuse(err, in, in_n, LC_GO("IPv4 address too short"), NULL, 0);
    fields[3] = (uint8_t)val;
    return 0;
}

/* parseIPv6 (:205-341). */
static int ipv6(const char *in, size_t in_n, lc_netip *out, lc_obuf *err)
{
    const char *s = in;
    size_t      n = in_n;
    const char *pct = memchr(in, '%', in_n);
    size_t      zone_len = 0;
    if (pct != NULL) {
        n = (size_t)(pct - in);
        zone_len = in_n - n - 1u;
        if (zone_len == 0u)
            return refuse(err, in, in_n, LC_GO("zone must be a non-empty string"), NULL, 0);
    }
    uint8_t ip[16] = { 0 };
    int     ellipsis = -1;
    if (n >= 2u && s[0] == ':' && s[1] == ':') {
        ellipsis = 0;
        s += 2;
        n -= 2u;
        if (n == 0u)
            goto done; /* IPv6Unspecified().WithZone(zone) */
    }
    int i = 0;
    while (i < 16) {
        size_t   off = 0;
        uint32_t acc = 0;
        for (; off < n; off++) {
            char c = s[off];
            if (c >= '0' && c <= '9')
                acc = (acc << 4) + (uint32_t)(c - '0');
            else if (c >= 'a' && c <= 'f')
                acc = (acc << 4) + (uint32_t)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F')
                acc = (acc << 4) + (uint32_t)(c - 'A' + 10);
            else
                break;
            if (off > 3u)
                return refuse(err, in, in_n, LC_GO("each group must have 4 or less digits"), s, n);
            if (acc > 0xffffu)
                return refuse(err, in, in_n, LC_GO("IPv6 field has value >=2^16"), s, n);
        }
        if (off == 0u)
            return refuse(err, in, in_n, LC_GO("each colon-separated field must have at least one digit"),
                          s, n);
        if (off < n && s[off] == '.') {
            if (ellipsis < 0 && i != 12)
                return refuse(err, in, in_n,
                              LC_GO("embedded IPv4 address must replace the final 2 fields of the address"),
                              s, n);
            if (i + 4 > 16)
                return refuse(err, in, in_n,
                              LC_GO("too many hex fields to fit an embedded IPv4 at the end of the address"),
                              s, n);
            size_t end = in_n;
            if (zone_len > 0u)
                end -= zone_len + 1u;
            if (ipv4_fields(in, in_n, end - n, end, ip + i, err) != 0)
                return -1;
            n = 0;
            i += 4;
            break;
        }
        ip[i] = (uint8_t)(acc >> 8);
        ip[i + 1] = (uint8_t)acc;
        i += 2;
        s += off;
        n -= off;
        if (n == 0u)
            break;
        if (s[0] != ':')
            return refuse(err, in, in_n, LC_GO("unexpected character, want colon"), s, n);
        if (n == 1u)
            return refuse(err, in, in_n, LC_GO("colon must be followed by more characters"), s, n);
        s++;
        n--;
        if (s[0] == ':') {
            if (ellipsis >= 0)
                return refuse(err, in, in_n, LC_GO("multiple :: in address"), s, n);
            ellipsis = i;
            s++;
            n--;
            if (n == 0u)
                break;
        }
    }
    if (n != 0u)
        return refuse(err, in, in_n, LC_GO("trailing garbage after address"), s, n);
    if (i < 16) {
        if (ellipsis < 0)
            return refuse(err, in, in_n, LC_GO("address string too short"), NULL, 0);
        int k = 16 - i;
        for (int j = i - 1; j >= ellipsis; j--)
            ip[j + k] = ip[j];
        memset(ip + ellipsis, 0, (size_t)k);
    } else if (ellipsis >= 0) {
        return refuse(err, in, in_n, LC_GO("the :: must expand to at least one field of zeros"), NULL, 0);
    }
done:
    memcpy(out->ip, ip, 16u);
    out->is4 = 0;
    out->zone_off = pct != NULL ? (size_t)(pct - in) + 1u : 0u;
    out->zone_len = zone_len;
    return 0;
}

int lc_netip_parse(const char *s, size_t n, lc_netip *out, lc_obuf *err)
{
    memset(out, 0, sizeof *out);
    for (size_t i = 0; i < n; i++) {
        switch (s[i]) {
        case '.': {
            out->is4 = 1;
            out->ip[10] = 0xff;
            out->ip[11] = 0xff;
            return ipv4_fields(s, n, 0, n, out->ip + 12, err);
        }
        case ':':
            return ipv6(s, n, out, err);
        case '%':
            return refuse(err, s, n, LC_GO("missing IPv6 address"), NULL, 0);
        default:
            break;
        }
    }
    return refuse(err, s, n, LC_GO("unable to parse IP"), NULL, 0);
}

int lc_net_parse_ip_ok(const char *s, size_t n)
{
    lc_netip a;
    return lc_netip_parse(s, n, &a, NULL) == 0 && a.zone_len == 0u;
}
