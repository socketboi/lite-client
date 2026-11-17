/* THE REFERENCES' RESOLVER, WHICH IS GO'S OWN AND NOT THE MACHINE'S.
 *
 * Xray and hysteria are built without cgo, so a name reaches Go's pure resolver whatever the box
 * runs: `mustUseGoResolver` is true when cgo is not available (GOROOT/src/net/conf.go:196-215), and
 * lookupOrder then decides files and DNS from /etc/nsswitch.conf alone (GOROOT/src/net/conf.go:241-470). Everything
 * it does is visible to someone: the queries it sends — one A and one AAAA per name tried, each with
 * an EDNS(0) record for 1232 bytes, in parallel, retried per server and per attempt as resolv.conf
 * says (GOROOT/src/net/dnsclient_unix.go:59-94, :297-366, :638-848) — and the address it dials first,
 * which is the answer sorted by RFC 6724 (GOROOT/src/net/addrselect.go:14-208). musl's getaddrinfo,
 * which stood in for it, asks in its own way and orders in its own way (DIVERGENCES.md G7, until
 * 2026-09-30).
 *
 * So this is that resolver, transcribed from go1.27.1: resolv.conf and nsswitch.conf read as Go reads
 * them and re-read on Go's clock, /etc/hosts with its five-second cache, the name list, the exchange
 * over UDP and then TCP, the message parsed by golang.org/x/net/dns/dnsmessage's rules (vendored at
 * GOROOT/src/vendor/golang.org/x/net/dns/dnsmessage/message.go), and the sort, down to the stable
 * merge sort `slices.SortStableFunc` runs, since RFC 6724's comparison is not a strict order and a
 * different stable sort could put the same addresses in a different order.
 *
 * Blocking: it is called on a thread of its own (net/dial.h), as Go runs its lookup on a goroutine of
 * its own. `cancel`, when not -1, is a descriptor that becomes readable when nobody waits for the
 * answer any more — Go's lookupGroupCancel (GOROOT/src/net/lookup.go:343-357) — and every wait here
 * ends on it: nothing more is sent once it fires. */
#ifndef LC_GORESOLVE_H
#define LC_GORESOLVE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

/* One address of the answer: net.IPAddr. `v4` for an address Go holds as IPv4 — four bytes from an
 * A record, or a sixteen-byte v4-mapped one from /etc/hosts, which net.IP.To4 treats the same. */
typedef struct {
    uint8_t ip[16]; /* IPv4 in the last four bytes when v4 */
    int     v4;
    char    zone[16]; /* IF_NAMESIZE on Linux: an interface name and its NUL */
} lc_goip;

typedef struct {
    lc_goip *a; /* heap; lc_goaddrs_free */
    unsigned n;
} lc_goaddrs;

void lc_goaddrs_free(lc_goaddrs *l);

/* Resolver.lookupIPAddr(ctx, "ip", name) for a name that is not an IP literal — the caller parses
 * literals first, as lookupIPAddr does (GOROOT/src/net/lookup.go:305-312). 0 with the addresses, in
 * Go's order — possibly none, where Go too answers an empty list without an error (a .onion name); -1 with `why` holding Go's error text ("lookup NAME on SERVER: no such
 * host", "... i/o timeout", ...), or with `why` "cancelled" when `cancel` fired. */
int lc_go_lookup_ip(const char *name, int cancel, lc_goaddrs *out, char *why, size_t why_cap);

/* The address with `port`, as a socket address to connect to: IPv4 for an address Go holds as IPv4,
 * IPv6 with the zone's interface index otherwise. */
socklen_t lc_goip_sockaddr(const lc_goip *a, uint16_t port, struct sockaddr_storage *ss);

/* netip.ParseAddr of `s` — whether lookupIPAddr takes it as a literal and looks nothing up
 * (GOROOT/src/net/lookup.go:310-312). 0 with the address; -1 for a name. getaddrinfo's AI_NUMERICHOST,
 * which stood in for this, also took inet_aton's shorthands — "127.1", "0x7f.1" — that Go treats as
 * names and asks the resolver for. */
int lc_goip_literal(const char *s, lc_goip *out);

/* The files that stand in for /etc/resolv.conf, /etc/nsswitch.conf and /etc/hosts. The defaults are
 * those; test/goresolve points them at its own. Not thread-safe to change while a lookup runs. */
void lc_go_resolver_paths(const char *resolv, const char *nsswitch, const char *hosts);

#endif
