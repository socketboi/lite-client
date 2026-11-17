/* netip.ParseAddr, with its error texts — what net/url says of an IP-literal host that is not one
 * ("invalid host: ParseAddr(…): …") and what net.ParseIP answers for x509's URI name constraints.
 * Transcribed from GOROOT/src/net/netip/netip.go:114-341 (go1.26.6; go1.27.1's is the same). */
#ifndef LC_NETIP_H
#define LC_NETIP_H

#include "core/gotext.h"

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t ip[16]; /* IPv4 in the last four bytes when is4 */
    int     is4;
    size_t  zone_off, zone_len; /* into the input; zone_len 0 for none */
} lc_netip;

/* ParseAddr of `n` bytes. 0 with `out` filled; -1 with parseAddrError's text appended to `err`
 * when it is not NULL: ParseAddr("in"): msg, and " (at "rest")" where Go names the place. */
int lc_netip_parse(const char *s, size_t n, lc_netip *out, lc_obuf *err);

/* net.ParseIP's verdict (GOROOT/src/net/ip.go:527-540): ParseAddr, and no zone. */
int lc_net_parse_ip_ok(const char *s, size_t n);

#endif
