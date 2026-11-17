/* The TPROXY listener.
 *
 * TPROXY is how LAN traffic reaches this client without anyone configuring a proxy: nftables marks
 * the packets and hands them to a local socket while leaving the ORIGINAL destination intact. That
 * last part is the whole trick — an accepted socket reports the address the client was trying to
 * reach, not ours, so `getsockname` is where the target comes from.
 *
 * It is also why the plane on the router uses TPROXY rather than TUN: a TUN device needs a network
 * stack in userspace, which on the measured hardware meant 2.7 MB/s and an OOM kill.
 *
 * Two requirements that fail confusingly when missed: the socket needs IP_TRANSPARENT, which needs
 * CAP_NET_ADMIN; and the kernel needs nft_tproxy and nft_socket loaded, or the nftables rule is
 * accepted and silently matches nothing. */
#ifndef LC_TPROXY_H
#define LC_TPROXY_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

/* An address as the proxy needs it: text form and port, since VLESS sends a name or a literal and
 * nothing in between. */
typedef struct {
    char     host[46]; /* INET6_ADDRSTRLEN */
    uint16_t port;
} lc_addr;

/* Opens a TPROXY listener on port. Returns the descriptor, or -1.
 * transparent=0 makes an ordinary listener, which is how the data path is tested without root. */
int lc_tproxy_listen(uint16_t port, int transparent);

/* Accepts a connection and reports where the client was actually going. Returns the descriptor, or
 * -1 when nothing is pending. */
int lc_tproxy_accept(int listen_fd, lc_addr *original_dst);

/* A UDP socket bound to `port`, non-blocking. One socket serves every client: a datagram carries
 * who sent it, so there is nothing per-client to keep open.
 *
 * With `transparent` it binds to every address rather than the loopback and asks the kernel for the
 * address each datagram was ADDRESSED to, which for a redirected packet is the place the client
 * meant to reach. Without it the socket is an ordinary one on the loopback and the destination is
 * whatever the caller configured. */
int lc_udp_listen(uint16_t port, int transparent);

/* Receives one datagram, reporting both who sent it and where it was going.
 *
 * The second is the whole point on a router: a redirected datagram has already had its destination
 * rewritten by the time an ordinary recvfrom sees it, so the only record of where the client was
 * actually trying to reach is the control message the kernel attaches. */
long lc_udp_recv(int fd, uint8_t *buf, size_t cap,
                 struct sockaddr_storage *from, socklen_t *from_len, lc_addr *original_dst);

/* A socket that can answer as the address the client was talking to.
 *
 * A reply from anywhere else is a reply from a stranger, and the client drops it — which is the
 * whole reason transparent proxying needs a socket per destination rather than one shared one. */
int lc_udp_reply_socket(const lc_addr *original_dst);

#endif
