#include "net/sock.h"

#include "net/loop.h"

#include <signal.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>




uint64_t lc_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

/* Milliseconds left until the deadline, clamped at zero. Returned as int because that is what poll
 * takes, and a deadline further away than 24 days is not a case worth carrying. */
static int left_ms(uint64_t deadline_ms)
{
    uint64_t now = lc_now_ms();
    if (now >= deadline_ms)
        return 0;
    uint64_t d = deadline_ms - now;
    return d > 0x7fffffffu ? 0x7fffffff : (int)d;
}

/* Carries one address's connect to a conclusion, or to the deadline, whichever arrives first.
 * Returns 0 when the connection is up. The descriptor must already be non-blocking.
 *
 * A blocking connect() would ignore deadline_ms for the whole SYN phase, because nothing bounds the
 * kernel's SYN retry schedule: a peer that silently drops SYNs holds the process for roughly two
 * minutes at the default tcp_syn_retries, and once per address the resolver handed back. A dropped
 * SYN is not a hypothetical here — it is the censorship signature lc-probe exists to report, so
 * sitting out the kernel's retries instead of answering at the deadline defeats the one tool whose
 * entire job is that measurement.
 *
 * POLLOUT alone does not mean success: a refused or unreachable connection reports writable too. The
 * verdict is SO_ERROR, which is what lc_connect_done reads. */
static int connect_wait(int fd, const struct addrinfo *a, uint64_t deadline_ms)
{
    if (connect(fd, a->ai_addr, a->ai_addrlen) == 0)
        return 0;
    if (errno != EINPROGRESS)
        return -1;

    for (;;) {
        int wait = left_ms(deadline_ms);
        if (wait == 0)
            return -1;

        struct pollfd p = { .fd = fd, .events = POLLOUT, .revents = 0 };
        int           r = poll(&p, 1, wait);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (r == 0)
            return -1;

        return lc_connect_done(fd);
    }
}

int lc_connect(const char *host, uint16_t port, uint64_t deadline_ms)
{
    char portstr[6];
    snprintf(portstr, sizeof portstr, "%u", (unsigned)port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *list = NULL;
    if (getaddrinfo(host, portstr, &hints, &list) != 0)
        return -1;

    int fd = -1;
    for (struct addrinfo *a = list; a != NULL; a = a->ai_next) {
        /* Once the budget is spent there is nothing left to spend on the remaining addresses, and
         * trying them anyway is how one unreachable host turns into a stall several times the
         * deadline. */
        if (left_ms(deadline_ms) == 0)
            break;
        fd = socket(a->ai_family, a->ai_socktype | SOCK_CLOEXEC, a->ai_protocol);
        if (fd < 0)
            continue;
        /* ⚠️ AND IT STAYS NON-BLOCKING, which it did not until lc_read_full and lc_write_full
         * learned that EAGAIN means retry. This used to switch back before returning, and the note
         * here said why: the helpers poll first and then expected the syscall to complete, so a
         * partial arrival read as an error would fail the handshake. That is fixed at the source
         * above rather than papered over here.
         *
         * It matters beyond tidiness. loop.h states the rule — "Every socket in the loop must be
         * non-blocking, or one slow peer stalls every other connection on the device" — and this
         * descriptor goes straight into that loop and carries a household's traffic for hours. A
         * blocking write into a full send buffer suspends the WHOLE process, single-threaded as it
         * is, and every other connection on the router waits behind it. */
        if (lc_set_nonblocking(fd) != 0 || connect_wait(fd, a, deadline_ms) != 0) {
            close(fd);
            fd = -1;
            continue;
        }
        break;
    }
    freeaddrinfo(list);

    if (fd >= 0 && left_ms(deadline_ms) == 0) {
        close(fd);
        return -1;
    }

    if (fd >= 0)
        lc_tcp_outbound(fd);
    return fd;
}

void lc_tcp_nodelay(int fd)
{
    /* Nagle off, as every proxy and every Go program does by default. This connection carries TLS
     * records and framed proxy traffic, where the next thing to send routinely waits on a reply to
     * the last — exactly the pattern Nagle delays by up to a round trip while it hopes for more
     * bytes to combine. The saving it offers is for bulk writers; this is not one. */
    int on = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
}

void lc_tcp_outbound(int fd)
{
    lc_tcp_nodelay(fd);

    /* AND KEEPALIVE, WHICH IS THE HALF THIS DID NOT HAVE AND THE REFERENCE SETS BY NAME.
     *
     * Xray's system dialer builds every outbound TCP connection with
     *
     *     // Chrome defaults
     *     keepAliveConfig := net.KeepAliveConfig{
     *         Enable:   true,
     *         Idle:     45 * time.Second,
     *         Interval: 45 * time.Second,
     *         Count:    -1,
     *     }        (vendor/Xray-core/transport/internet/system_dialer.go:115-121)
     *
     * — reached by the REALITY plane like everything else, `internet.DialSystem` from
     * vendor/Xray-core/transport/internet/tcp/dialer.go:22. The comment above it is upstream's own
     * and says what the numbers are: a browser's cadence, not a proxy's.
     *
     * What that produces on the wire is a bare ACK forty-five seconds after a connection goes
     * quiet, and every forty-five after that. This client produced none, so an idle proxied
     * connection from here and one from a stock Xray differ by a packet that needs no decryption
     * and no state to notice — the cheapest kind of distinguisher there is, and one that shows on
     * exactly the connections that live longest.
     *
     * ⚠️ ONLY ON WHAT WE DIALLED, and that asymmetry is the reference's too, in the opposite
     * direction: its LISTENER turns keepalive OFF unless an operator asks for it — `// default
     * disable keepalive` then `lc.KeepAlive = -1`
     * (vendor/Xray-core/transport/internet/system_listener.go:90-91). So an accepted socket gets
     * lc_tcp_nodelay and nothing else, which is why this is a second function rather than two more
     * lines in the first one: net/tproxy.c calls that one for every LAN connection, and putting
     * keepalive there would diverge from the reference in the other direction while looking like
     * tidying up.
     *
     * COUNT IS LEFT ALONE, because upstream leaves it alone: `Count: -1` is Go's "do not set
     * TCP_KEEPCNT", so the number of unanswered probes before the kernel gives up stays whatever
     * the system says — nine on Linux. Setting it would be a rule of our own.
     *
     * Results ignored, as everywhere else this program sets a socket option: a kernel that refuses
     * one still has a working connection, and there is nothing useful to do about it here. */
    int on = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on);
    int secs = LC_TCP_KEEPALIVE_SECS;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &secs, sizeof secs);
    (void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &secs, sizeof secs);
}


int lc_connect_begin(const lc_resolved *r)
{
    int fd = -1;
    for (unsigned i = 0; i < r->n; i++) {
        fd = socket(r->family[i], r->socktype[i] | SOCK_CLOEXEC, r->protocol[i]);
        if (fd < 0)
            continue;
        if (lc_set_nonblocking(fd) != 0) {
            close(fd);
            fd = -1;
            continue;
        }
        lc_tcp_outbound(fd);
        /* EINPROGRESS is the expected answer, not an error: it is what "started" looks like. */
        if (connect(fd, (const struct sockaddr *)&r->addr[i], r->len[i]) == 0 ||
            errno == EINPROGRESS)
            break;
        close(fd);
        fd = -1;
    }
    /* errno is left exactly as the last socket() or connect() set it. It used to be saved and put
     * back around freeaddrinfo, which is no longer here to disturb it — the caller reads it to tell
     * EMFILE and ENFILE, a local limit, from everything else, which is the node. */
    return fd;
}

int lc_socket_error(int fd)
{
    int       err = 0;
    socklen_t len = sizeof err;
    /* A getsockopt that itself fails is still a failed connection, and errno is the closest thing
     * to a reason there is — returning zero here would report the descriptor as healthy. */
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0)
        return errno != 0 ? errno : EINVAL;
    return err;
}

int lc_connect_done(int fd)
{
    return lc_socket_error(fd) == 0 ? 0 : -1;
}

int lc_read_full(int fd, uint8_t *buf, size_t n, uint64_t deadline_ms)
{
    size_t done = 0;
    while (done < n) {
        int wait = left_ms(deadline_ms);
        if (wait == 0)
            return -1;

        struct pollfd p = { .fd = fd, .events = POLLIN, .revents = 0 };
        int           r = poll(&p, 1, wait);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (r == 0)
            return -1;

        ssize_t got = recv(fd, buf + done, n - done, 0);
        if (got < 0) {
            /* ⚠️ EAGAIN IS A RETRY HERE, NOT A FAILURE, and saying so is what lets the descriptor
             * stay non-blocking for its whole life — see lc_connect and the rule in loop.h. poll
             * saying readable does not guarantee a read will produce bytes: a checksum that fails
             * after the wakeup, a second reader, or a plain spurious wakeup all leave the socket
             * empty, and the kernel is explicit that select/poll may report a descriptor ready and
             * the read then block. On a blocking descriptor that possibility is invisible because
             * the read simply waits; treating it as an error is what forced the socket back to
             * blocking, and forcing it back to blocking is what let one slow peer stall every other
             * connection on the device. The deadline still bounds the loop. */
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            return -1;
        }
        if (got == 0)
            return 1; /* peer closed: for REALITY this is a verdict, not an error */
        done += (size_t)got;
    }
    return 0;
}

int lc_write_full(int fd, const uint8_t *buf, size_t n, uint64_t deadline_ms)
{
    size_t done = 0;
    while (done < n) {
        int wait = left_ms(deadline_ms);
        if (wait == 0)
            return -1;

        struct pollfd p = { .fd = fd, .events = POLLOUT, .revents = 0 };
        int           r = poll(&p, 1, wait);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (r == 0)
            return -1;

        /* MSG_NOSIGNAL: a peer that closes mid-write would otherwise kill the process with SIGPIPE,
         * and a proxy dying because one connection went away is not acceptable. */
        ssize_t sent = send(fd, buf + done, n - done, MSG_NOSIGNAL);
        if (sent < 0) {
            /* The same retry as the read above, and needed more often: a socket reported writable
             * has room for at least one byte, not for the whole buffer, so a partial write followed
             * by EAGAIN is the ordinary case on a non-blocking descriptor rather than an oddity. */
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            return -1;
        }
        done += (size_t)sent;
    }
    return 0;
}

void lc_close(int fd)
{
    if (fd >= 0)
        close(fd);
}

void lc_ignore_sigpipe(void)
{
    /* SIG_IGN rather than a handler: there is nothing to do about it, and a handler would only turn
     * a signal nobody wants into a wake-up nobody wants either. */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = SIG_IGN;
    (void)sigaction(SIGPIPE, &sa, NULL);
}
