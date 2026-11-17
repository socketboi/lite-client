#include "net/tproxy.h"

#include "core/say.h"

#include "net/sock.h"

#include "net/loop.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ⚠️ THE TWO MESSAGES BELOW GO THROUGH lc_say, AND NOT BECAUSE IT IS TIDIER. The only program that
 * calls this file runs several workers, procd hands every one of them the SAME stderr, and this
 * function is reached AFTER the fork — each worker makes its own listener, which is the whole point
 * of SO_REUSEPORT below. A line built with printf reaches that pipe in as many writes as the format
 * has pieces, and the workers' pieces interleave: measured on a live router, 20 of 44 records came
 * out shredded. core/say.h carries the evidence and the arithmetic.
 *
 * And the message is the reason it matters at all rather than a detail of style: it exists to
 * separate EPERM from ENOPROTOOPT, and torn in half it separates nothing. */

int lc_tproxy_listen(uint16_t port, int transparent)
{
    /* IPv6 socket with dual-stack, so one listener serves both families. OpenWrt ships IPv6 on by
     * default and a v4-only listener would quietly miss half the LAN. */
    int fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    /* SO_REUSEPORT is what lets several copies of this process hold the same port and have the
     * kernel spread connections between them — see the -w option in lc-tunnel. Set unconditionally
     * rather than only when workers were asked for: a single process in a REUSEPORT group of one
     * behaves exactly as it did, and making the flag conditional would mean the one-worker and
     * many-worker cases take different code through the kernel's socket lookup.
     *
     * And unconditionally is what the reference does with it, down to ignoring the result:
     *
     *     setReusePort(fd)        (vendor/Xray-core/transport/internet/system_listener.go:38)
     *
     * — no `if err :=` around it, applied to every listener it makes, and its Linux arm is the
     * plain setsockopt this one is (vendor/Xray-core/transport/internet/sockopt_linux.go:242-244). A listener that cannot have the
     * option is still a listener.
     *
     * Verified on the target kernel (6.12.94) alongside IP_TRANSPARENT, for TCP and UDP both,
     * before any of this was written — the combination is the whole premise and it is not obviously
     * allowed. */
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof on);

    int off = 0;
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof off);

    if (transparent) {
        /* Without IP_TRANSPARENT the kernel refuses to hand over connections whose destination is
         * not ours — which is every connection TPROXY exists to intercept.
         *
         * Which of the two failed is said out loud, because the reasons are different and the
         * remedies are not the same. Missing privilege gives EPERM; a kernel built without the
         * option gives ENOPROTOOPT; and the v6 option on a v6 socket serving v4 traffic is its own
         * question again. Reported as one line of "needs CAP_NET_ADMIN", as it was, this sends
         * whoever reads it looking for a privilege they already have. */
        if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &on, sizeof on) != 0) {
            lc_say(2, "IP_TRANSPARENT refused: %s", strerror(errno));
            close(fd);
            return -1;
        }
        if (setsockopt(fd, SOL_IPV6, IPV6_TRANSPARENT, &on, sizeof on) != 0) {
            lc_say(2, "IPV6_TRANSPARENT refused: %s", strerror(errno));
            close(fd);
            return -1;
        }
    }

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof addr);
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0 || listen(fd, 128) != 0) {
        close(fd);
        return -1;
    }
    if (lc_set_nonblocking(fd) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Renders an address the way VLESS wants it. A v4-mapped v6 address is written as plain IPv4:
 * sending "::ffff:1.2.3.4" upstream would be a literal no server resolves. */
static void render(const struct sockaddr_storage *ss, lc_addr *out)
{
    memset(out, 0, sizeof *out);
    if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)ss;
        out->port = ntohs(a->sin6_port);
        if (IN6_IS_ADDR_V4MAPPED(&a->sin6_addr)) {
            struct in_addr v4;
            memcpy(&v4, &a->sin6_addr.s6_addr[12], sizeof v4);
            inet_ntop(AF_INET, &v4, out->host, sizeof out->host);
        } else {
            inet_ntop(AF_INET6, &a->sin6_addr, out->host, sizeof out->host);
        }
    } else {
        const struct sockaddr_in *a = (const struct sockaddr_in *)ss;
        out->port = ntohs(a->sin_port);
        inet_ntop(AF_INET, &a->sin_addr, out->host, sizeof out->host);
    }
}

int lc_tproxy_accept(int listen_fd, lc_addr *original_dst)
{
    struct sockaddr_storage peer;
    socklen_t               peer_len = sizeof peer;
    int                     fd;

    /* Retried on a signal rather than reported as a failure. It would have been harmless either way
     * — the loop is level-triggered, so the connection is offered again — but that makes this
     * correct only for as long as nobody changes the loop, which is not a property worth relying
     * on. A router takes signals: procd sends them, and so does a network reload. */
    /* SOCK_NONBLOCK here rather than an fcntl pair afterwards. The flag is what the descriptor has
     * to end up with — loop.h: every socket in the loop must be non-blocking — and asking accept4
     * for it costs nothing, where setting it later costs a read and a write of the flags on every
     * connection the router takes. It also closes the window in between, small as it is. */
    do {
        peer_len = sizeof peer;
        fd = accept4(listen_fd, (struct sockaddr *)&peer, &peer_len,
                     SOCK_CLOEXEC | SOCK_NONBLOCK);
    } while (fd < 0 && errno == EINTR);

    if (fd < 0)
        return -1;

    /* With TPROXY the accepted socket's LOCAL address is the address the client dialled, because
     * the kernel never rewrote it. On an ordinary listener this returns our own address, which is
     * exactly why the non-transparent mode is for testing the data path and nothing else. */
    struct sockaddr_storage local;
    socklen_t               local_len = sizeof local;
    if (getsockname(fd, (struct sockaddr *)&local, &local_len) != 0) {
        close(fd);
        return -1;
    }
    render(&local, original_dst);

    lc_tcp_nodelay(fd);
    return fd;
}


/* A v4 address as a socket serving both families spells it: ten zero bytes, two of ones, then the
 * four that are the address. Written once because it is needed wherever a v4 address has to meet a
 * v6 socket, and getting one of those wrong is a bind that succeeds against nothing. */
static void map_v4(const struct in_addr *v4, struct in6_addr *out)
{
    uint8_t mapped[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0 };
    memcpy(mapped + 12, v4, sizeof *v4);
    memcpy(out, mapped, sizeof mapped);
}

int lc_udp_listen(uint16_t port, int transparent)
{
    /* One socket for both families, the way the stream listener already does it: a v6 socket with
     * V6ONLY switched off accepts v4 traffic as mapped addresses.
     *
     * It was v4-only until now, which on a network that has IPv6 means the datagrams that matter
     * most — a resolver reached over v6, which is the default on any modern LAN — never entered the
     * tunnel at all. Nothing failed; they simply went out the other way, which is the whole thing
     * this exists to prevent and the hardest kind of gap to notice from inside. */
    int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    int on = 1, off = 0;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    /* The same as the stream listener, and it matters more here: UDP has no accept, so without
     * REUSEPORT a second copy of this process could not take the port at all. The kernel hashes a
     * datagram's four-tuple to pick the socket, so one client's stream of datagrams from one source
     * port lands consistently in one worker — which is what the per-client session model needs. */
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof on);
    (void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof off);

    if (transparent) {
        /* Two options per family, and they do different jobs: TRANSPARENT lets this socket receive
         * datagrams addressed to somebody else, RECVORIGDSTADDR makes the kernel say who that
         * somebody was. Without the second the redirect works and the destination is lost.
         *
         * Both families are set on the one socket, because a mapped v4 datagram arrives with the v4
         * control message and a native v6 one with the v6 message. Asking for only one of them
         * means half the traffic arrives with nowhere to send it. */
        if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &on, sizeof on) != 0 ||
            setsockopt(fd, SOL_IP, IP_RECVORIGDSTADDR, &on, sizeof on) != 0 ||
            setsockopt(fd, SOL_IPV6, IPV6_TRANSPARENT, &on, sizeof on) != 0 ||
            setsockopt(fd, SOL_IPV6, IPV6_RECVORIGDSTADDR, &on, sizeof on) != 0) {
            close(fd);
            return -1;
        }
    }

    struct sockaddr_in6 a;
    memset(&a, 0, sizeof a);
    a.sin6_family = AF_INET6;
    a.sin6_port = htons(port);

    if (transparent) {
        a.sin6_addr = in6addr_any;
    } else {
        /* The loopback, and only the loopback. This mode sends every datagram to one configured
         * place, so a copy of it reachable from the LAN is an open forwarder for anyone on it —
         * which is why it was never bound to the wildcard and must not start being now.
         *
         * Written as the v4-mapped loopback rather than ::1 because what has to reach it is a
         * client sending to 127.0.0.1, and on a socket that serves both families that address is
         * how the v4 loopback is spelled. */
        struct in_addr v4;
        v4.s_addr = htonl(INADDR_LOOPBACK);
        map_v4(&v4, &a.sin6_addr);
    }
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0 || lc_set_nonblocking(fd) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

long lc_udp_recv(int fd, uint8_t *buf, size_t cap,
                 struct sockaddr_storage *from, socklen_t *from_len, lc_addr *original_dst)
{
    /* Room for the one control message asked for, with slack: a kernel is free to attach more than
     * was requested, and a short buffer would have it truncate rather than fail. */
    char          control[256];
    struct iovec  iov = { .iov_base = buf, .iov_len = cap };
    struct msghdr msg;

    memset(&msg, 0, sizeof msg);
    msg.msg_name = from;
    msg.msg_namelen = sizeof *from;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof control;

    ssize_t n;
    do {
        n = recvmsg(fd, &msg, 0);
    } while (n < 0 && errno == EINTR);
    if (n < 0)
        return -1;

    /* A datagram too big for the buffer is SHORTENED, as both references shorten it: they read into a
     * buffer of fixed size and never look at MSG_TRUNC — Xray into buf.Size, the flags discarded
     * (vendor/Xray-core/transport/internet/udp/hub.go:99-109), hysteria into udpBufferSize = 4096
     * with conn.Read and tproxy.ReadFromUDP (vendor/hysteria/app/internal/tproxy/udp_linux.go:13,
     * :34-43, :114-118), which return what fitted and no error.
     *
     * ⚠️ IT WAS DROPPED HERE UNTIL 2026-09-27, on the reasoning that a truncated packet is worse than a
     * lost one. That is a judgement the references did not make: they carry the first bytes, and on
     * the REALITY plane the datagram still finds or makes its session — and dials — before the xudp
     * writer drops it for size. */

    *from_len = msg.msg_namelen;

    /* Walked by hand rather than with CMSG_NXTHDR. The macro does pointer arithmetic that mixes
     * signed and unsigned, which this build's warnings refuse on a 32-bit target — and refusing it
     * is right, since the same arithmetic is where a malformed control buffer would walk off the
     * end. The bounds here are explicit: every step must stay inside what the kernel said it
     * wrote, and a header claiming a length shorter than itself ends the walk. */
    memset(original_dst, 0, sizeof *original_dst);
    size_t control_len = msg.msg_controllen;
    for (size_t off = 0; off + sizeof(struct cmsghdr) <= control_len;) {
        struct cmsghdr *c = (struct cmsghdr *)(void *)(control + off);
        size_t          this_len = c->cmsg_len;
        if (this_len < sizeof(struct cmsghdr) || off + this_len > control_len)
            break;
        off += (this_len + sizeof(size_t) - 1u) & ~(sizeof(size_t) - 1u);

        /* Either family's answer to the same question. A datagram that arrived over v4 on this
         * dual-stack socket carries the v4 message, a native v6 one carries the v6 message, and
         * only reading both keeps half the traffic from arriving with no destination. */
        if (c->cmsg_level == SOL_IP && c->cmsg_type == IP_RECVORIGDSTADDR &&
            this_len >= CMSG_LEN(sizeof(struct sockaddr_in))) {
            struct sockaddr_in d;
            memcpy(&d, CMSG_DATA(c), sizeof d);
            inet_ntop(AF_INET, &d.sin_addr, original_dst->host, sizeof original_dst->host);
            original_dst->port = ntohs(d.sin_port);
            break;
        }
        if (c->cmsg_level == SOL_IPV6 && c->cmsg_type == IPV6_RECVORIGDSTADDR &&
            this_len >= CMSG_LEN(sizeof(struct sockaddr_in6))) {
            struct sockaddr_in6 d;
            memcpy(&d, CMSG_DATA(c), sizeof d);
            /* A v4 client reaching a dual-stack socket is reported as a mapped address. Written
             * back as plain IPv4, because that is what it is and what everything downstream — the
             * reply socket, the address the node is asked to reach — expects to see. */
            if (IN6_IS_ADDR_V4MAPPED(&d.sin6_addr)) {
                struct in_addr v4;
                memcpy(&v4, (const uint8_t *)&d.sin6_addr + 12, sizeof v4);
                inet_ntop(AF_INET, &v4, original_dst->host, sizeof original_dst->host);
            } else {
                inet_ntop(AF_INET6, &d.sin6_addr, original_dst->host, sizeof original_dst->host);
            }
            original_dst->port = ntohs(d.sin6_port);
            break;
        }
    }
    return (long)n;
}

int lc_udp_reply_socket(const lc_addr *original_dst)
{
    /* Bound to the address the client was talking to, so that the answer comes from there.
     *
     * Always a v6 socket, whichever family the destination is, and that is not a detail. The client
     * this will answer was read off the dual-stack listener, so a v4 client is held as a v4-mapped
     * v6 address — and sendto refuses a v6 address on a v4 socket. Making the socket's family
     * follow the destination's therefore breaks exactly the commonest case there is: an intercepted
     * v4 datagram, answered from a v4 socket, to an address that is spelled v6.
     *
     * One family everywhere is what keeps that from being a question at each send. */
    struct sockaddr_in6 a;
    memset(&a, 0, sizeof a);
    a.sin6_family = AF_INET6;
    a.sin6_port = htons(original_dst->port);

    struct in_addr v4;
    if (inet_pton(AF_INET, original_dst->host, &v4) == 1)
        map_v4(&v4, &a.sin6_addr);
    else if (inet_pton(AF_INET6, original_dst->host, &a.sin6_addr) != 1)
        return -1;

    int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    int on = 1, off = 0;
    /* Both transparencies, because a v4-mapped bind takes the v4 path through the kernel and a
     * native v6 one does not — the same reason the listener sets both. */
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on) != 0 ||
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof off) != 0 ||
        setsockopt(fd, SOL_IP, IP_TRANSPARENT, &on, sizeof on) != 0 ||
        setsockopt(fd, SOL_IPV6, IPV6_TRANSPARENT, &on, sizeof on) != 0) {
        close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0 || lc_set_nonblocking(fd) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}
