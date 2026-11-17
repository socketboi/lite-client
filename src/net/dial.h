/* A dial to a node given by NAME, the way the reference dials one: Go's net.Dialer.DialContext.
 *
 * Xray hands the name to Go per dial, with no cache of its own — DialSystem has no domain strategy by
 * default (vendor/Xray-core/transport/internet/dialer.go:242-251) and DefaultSystemDialer gives
 * "host:port" to a net.Dialer with a sixteen-second Timeout
 * (vendor/Xray-core/transport/internet/system_dialer.go:138-143, :171). What Go does with it, in the
 * toolchain the reference is built with, go1.27.1 (GOROOT/src/net/dial.go:529-560, DialContext):
 *
 *   - the sixteen seconds start before the lookup and cover it (GOROOT/src/net/dial.go:529-545,
 *     dialCtx);
 *   - the lookup is shared: dials of one name while a lookup of it is in flight wait on that lookup
 *     rather than start their own, and a finished lookup is forgotten — nothing is cached
 *     (lookup.go:325-377, singleflight). A dial that gives up on a lookup nobody else waits on
 *     drops it, so the next dial starts a fresh one;
 *   - the addresses are split by the family of the first: that family is the primary list, the
 *     other the fallback (GOROOT/src/net/dial.go:553-558, ipsock.go:115-127);
 *   - each list is tried in order, one connect at a time, each given an equal share of the time
 *     left but no less than two seconds (GOROOT/src/net/dial.go:733-773, partialDeadline at
 *     :273-293);
 *   - the fallback list starts 300 ms after the primary, or at once when the primary has failed
 *     before that; the first connection up wins and the other is closed; when both fail, the
 *     primary's error is the answer (GOROOT/src/net/dial.go:659-729, fallbackDelay at :295-301).
 *
 * A literal address never comes here: Go parses it and looks nothing up (lookup.go:310-312), and
 * lc_connect_begin with its one address is already that dial.
 *
 * The lookup itself is Go's own resolver, transcribed (net/goresolve.h), on a thread of its own —
 * the goroutine Go runs its lookup on — and cancelled as Go cancels it when the last dial waiting
 * on it gives up.
 *
 * Everything the dial has in the air is behind ONE descriptor, lc_dial_fd, which the caller watches
 * for reading on its loop; that and lc_dial_wake are all a caller needs to drive it with
 * lc_dial_step. */
#ifndef LC_DIAL_H
#define LC_DIAL_H

#include <stdint.h>

#include "net/sock.h"

typedef struct lc_dial lc_dial;

/* What lc_dial_step says while the dial goes on. */
#define LC_DIAL_PENDING (-2)

/* Starts a dial to host:port whose whole budget — lookup and connects — is timeout_ms from now_ms.
 * NULL with errno set when not even that could be set up (a descriptor or memory short). */
lc_dial *lc_dial_start(const char *host, uint16_t port, uint64_t now_ms, uint32_t timeout_ms);

/* The descriptor to watch for reading. It stays the same for the whole dial. */
int lc_dial_fd(const lc_dial *d);

/* The next moment lc_dial_step must be called at even if nothing wakes the descriptor. */
uint64_t lc_dial_wake(const lc_dial *d);

/* Moves the dial on: whatever the descriptor has, and whatever timers are due at now_ms.
 * Returns a connected, non-blocking socket, which is the caller's from then on; LC_DIAL_PENDING;
 * or -1 when the dial failed, with lc_dial_why saying why. */
int lc_dial_step(lc_dial *d, uint64_t now_ms);

/* Why a failed dial failed, for a log line. */
const char *lc_dial_why(const lc_dial *d);

/* Whether it failed by running out of its time — Go's "i/o timeout" — rather than by an answer. */
int lc_dial_timed_out(const lc_dial *d);

/* Ends the dial wherever it is and frees it, closing everything it still holds. NULL is fine. */
void lc_dial_free(lc_dial *d);


/* host:port when host is an IP literal as Go reads one — netip.ParseAddr, zone and all (see
 * lc_goip_literal in net/goresolve.h) — so the network is never asked. 0 with the one address,
 * EAI_NONAME when it is a name, which is then for net/dial.h. A name is never resolved here: the
 * resolver is Go's, on the dial's own thread. */
int lc_resolve_literal(const char *host, uint16_t port, lc_resolved *out);

#endif
