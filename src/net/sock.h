/* Blocking sockets with a deadline.
 *
 * Deliberately not an event loop. The handshake is a strictly sequential conversation — send, read,
 * send — and running it on blocking sockets with a wall-clock deadline is both simpler and easier to
 * reason about than the same thing expressed as callbacks. The event loop belongs to the data path,
 * where thousands of connections are in flight; it has no business in the handshake.
 *
 * Every call carries a deadline rather than a timeout, so a handshake cannot be stretched
 * indefinitely by a peer that dribbles one byte at a time — a real behaviour of censorship
 * middleboxes, not a hypothetical one. */
#ifndef LC_SOCK_H
#define LC_SOCK_H

#include <stddef.h>
#include <stdint.h>

/* For sockaddr_storage and socklen_t in lc_resolved below. This header otherwise deals in
 * descriptors and byte counts; the one place it names a kernel type is where it holds an address. */
#include <sys/socket.h>

/* Monotonic milliseconds, for building deadlines. Monotonic because the router's clock jumps when
 * NTP first answers, which on a freshly booted device is exactly when handshakes are happening. */
uint64_t lc_now_ms(void);

/* Turns Nagle off. Both ends of a proxied connection carry framed traffic where the next thing to
 * send waits on a reply to the last, which is the pattern Nagle delays while it hopes for more
 * bytes to combine; every proxy turns it off and so does every Go program, by default.
 *
 * Set on principle rather than on evidence: it made no measurable difference in the local test bed,
 * where the round trip is too short for the delay to bite. It is on a router with a real path to the
 * node that it would. */
void lc_tcp_nodelay(int fd);

/* HOW LONG A CONNECTION WE DIALLED MAY BE QUIET BEFORE IT SAYS SOMETHING, and both numbers are the
 * reference's: `Idle: 45 * time.Second, Interval: 45 * time.Second` under a comment reading
 * "Chrome defaults" (vendor/Xray-core/transport/internet/system_dialer.go:115-121). */
#define LC_TCP_KEEPALIVE_SECS 45

/* Everything this program does to a socket it DIALLED, in one place so the blocking and
 * non-blocking dial paths cannot drift apart: Nagle off, and keepalive on the reference's cadence.
 *
 * Deliberately not what an ACCEPTED socket gets — see the comment on the definition. The reference
 * enables keepalive on what it dials and disables it on what it accepts, and those are two separate
 * decisions in two separate files upstream; they are two functions here for the same reason. */
void lc_tcp_outbound(int fd);

/* Stops a write to a departed peer from killing the process.
 *
 * Writing to a socket whose other end has gone raises SIGPIPE, and the default action for SIGPIPE
 * is termination. For a proxy that is not an edge case, it is the normal course of business: a
 * client closes a tab while its page is still arriving, and the reply lands in a socket nobody is
 * holding any more. Ignored, the same write returns EPIPE, which every caller here already handles
 * as "this connection is over".
 *
 * MSG_NOSIGNAL on each send would cover the sends and nothing else — write() takes no such flag,
 * and splice() cannot be told either. So the signal is disarmed once, for the process.
 *
 * Found on the device and not before it: under synthetic load the node had little to send back, so
 * there was rarely anything to write into a closed socket. Against real traffic from one ordinary
 * LAN client the process died in twenty seconds, with exit status 141 and nothing in any log. */
void lc_ignore_sigpipe(void);

/* Connects to host:port. host may be a name or a literal address. Returns a blocking descriptor, or
 * -1.
 *
 * The connect is bounded by the deadline, and has to be: a blocking connect() cannot be cut short,
 * so a peer that swallows SYNs would hold the caller for the kernel's whole retry schedule — about
 * two minutes, and again for every address the resolver returned — no matter how small a deadline
 * was asked for. Internally the socket is non-blocking and waited on with poll; it is put back into
 * blocking mode before it is returned, because that is what every caller and both of the read/write
 * helpers below are written against.
 *
 * Name resolution is the remaining hole: getaddrinfo is synchronous and unbounded, so a resolver
 * that stalls can overrun the deadline before the first SYN is even sent. Closing it needs
 * asynchronous resolution, which is a larger piece of work than this. */
int lc_connect(const char *host, uint16_t port, uint64_t deadline_ms);

/* WHERE THE NODE IS: the addresses host:port resolved to, in the order the resolver gave them.
 *
 * A node given as a literal address is resolved once, before the loop: that is parsing, not a
 * lookup, and Go does no more with a literal (GOROOT/src/net/lookup.go:310-312). A node given as a
 * NAME is looked up per dial, as the reference does, on a thread — see net/dial.h. Before 2026-09-29
 * a name was looked up once at start and kept for the life of the process.
 *
 * Only a literal lands here now, one address; a name's answer is Go's resolver's and lives in the dial,
 * as long as the answer is (net/dial.h, net/goresolve.h). The bound is what it was when getaddrinfo
 * filled this — musl's MAXADDRS — and a literal never comes near it. */
#define LC_RESOLVED_MAX 48u

typedef struct {
    struct sockaddr_storage addr[LC_RESOLVED_MAX];
    socklen_t               len[LC_RESOLVED_MAX];
    int                     family[LC_RESOLVED_MAX];
    int                     socktype[LC_RESOLVED_MAX];
    int                     protocol[LC_RESOLVED_MAX];
    unsigned                n;
} lc_resolved;


/* Starts a connection to the first of those addresses that will take one, without waiting for it.
 * Returns a non-blocking descriptor on which the connection is still in progress; the caller watches
 * it for writability and then asks lc_connect_done whether it succeeded.
 *
 * Nothing here can block: no resolver, no library call between the last failure and the return, so
 * errno still holds what socket() or connect() said — which the caller reads to tell a full
 * descriptor table from a node it cannot reach. */
int lc_connect_begin(const lc_resolved *r);

/* 0 when the connection is up, -1 when it failed. Call once the descriptor reports writable. */
int lc_connect_done(int fd);

/* The verdict the kernel recorded for a connection, as an errno — 0 while nothing has gone wrong.
 *
 * Separate from lc_connect_done because a log that says only "it failed" sends the next person to
 * look at it to the wrong end of the wire: a refused connection, a dropped SYN and an unreachable
 * network are three different faults with three different owners, and the socket knows which one it
 * was. Reading it CLEARS it, so ask once and keep the answer. */
int lc_socket_error(int fd);

/* Reads exactly n bytes, or fails. Returns 0 on success, -1 on error, 1 if the peer closed first —
 * distinguished because a clean close in the middle of a handshake is what REALITY looks like when
 * the server decided we are a stranger. */
int lc_read_full(int fd, uint8_t *buf, size_t n, uint64_t deadline_ms);

/* Writes all n bytes. */
int lc_write_full(int fd, const uint8_t *buf, size_t n, uint64_t deadline_ms);

void lc_close(int fd);

#endif
