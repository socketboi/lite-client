/* The send queue of the Hysteria2 plane: a writer thread, a condition variable, a spin, and a
 * close that has to end.
 *
 * It had no suite of its own until 2026-09-23 — a stand checked it end to end, which proves the
 * common path and nothing about the edges, and the edges are where a thread beside the loop hurts:
 * the boundary that tells the owner to stop packing, the wake that tells it to go on, and the close,
 * which once waited for a full socket with no bound at all on the one thread every session runs on.
 *
 * Driven through the public interface only, on sockets whose fullness this file controls: an AF_UNIX
 * datagram pair stops accepting once its send buffer is taken by datagrams nobody has read, and
 * accepts again once they are read — a UDP socket's full send buffer on demand. The ECN case needs a real UDP socket and
 * uses loopback. */

#include "quic/sendq.h"

#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int failures;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

static uint64_t now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}

static void pause_ms(unsigned ms)
{
    struct timespec t = { .tv_sec = (time_t)(ms / 1000u), .tv_nsec = (long)(ms % 1000u) * 1000000L };
    nanosleep(&t, NULL);
}

/* sv[0] is the queue's socket, sv[1] the far end this file reads — or leaves unread. */
static int unix_pair(int sv[2], lc_sendq_dest *d)
{
    if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0, sv) != 0)
        return -1;
    memset(d, 0, sizeof *d);
    d->fd = sv[0];
    d->peer_len = 0; /* connected: the kernel ignores an empty name */
    d->family = AF_UNIX;
    return 0;
}

/* Until the send buffer is full of unread datagrams, so that the next send would block. */
static unsigned fill(int fd)
{
    unsigned      n = 0;
    unsigned char b = 0xee;
    while (send(fd, &b, 1, MSG_DONTWAIT) == 1)
        n++;
    return n;
}

/* Everything the far end holds, as datagrams, oldest first. */
static unsigned drain(int fd, unsigned char *first_bytes, unsigned cap, unsigned wait_ms)
{
    unsigned n = 0;
    for (;;) {
        struct pollfd p = { .fd = fd, .events = POLLIN, .revents = 0 };
        if (poll(&p, 1, (int)wait_ms) <= 0)
            return n;
        unsigned char buf[2048];
        ssize_t       got = recv(fd, buf, sizeof buf, MSG_DONTWAIT);
        if (got <= 0)
            return n;
        if (n < cap)
            first_bytes[n] = buf[0];
        n++;
    }
}

/* One entry of `count` datagrams, each two bytes: its tag, then 0xaa. */
static int put(lc_sendq *q, const lc_sendq_dest *d, uint8_t tag, unsigned count)
{
    lc_sendq_entry *en = lc_sendq_reserve(q);
    if (en == NULL)
        return -1;
    (void)d; /* where it goes is the queue's, since 2026-09-27: lc_sendq_set_dest */
    for (unsigned i = 0; i < count; i++) {
        en->buf[2u * i] = (uint8_t)(tag + i);
        en->buf[2u * i + 1u] = 0xaa;
        en->len[i] = 2u;
        en->ecn[i] = 0u;
    }
    en->n = count;
    lc_sendq_commit(q);
    return 0;
}

static unsigned in_hand(lc_sendq *q)
{
    pthread_mutex_lock(&q->lock);
    unsigned w = q->writing;
    pthread_mutex_unlock(&q->lock);
    return w;
}

static void order_is_kept(void)
{
    printf("\nentries leave in the order they were committed, datagram by datagram\n");
    int           sv[2];
    lc_sendq_dest d;
    lc_sendq      q;
    if (unix_pair(sv, &d) != 0 || lc_sendq_start(&q, &d) != 0) {
        ok(0, "a socket pair and a started queue");
        return;
    }
    /* Twenty entries through ten slots: the writer frees them as it goes, and the loop waits for
     * room the way the owner would. The eleventh entry carries three datagrams. */
    int      refused = 0;
    unsigned tag = 0;
    for (unsigned i = 0; i < 20u; i++) {
        unsigned count = i == 10u ? 3u : 1u;
        uint64_t until = now_ms() + 2000u;
        while (put(&q, &d, (uint8_t)tag, count) != 0) {
            if (now_ms() > until) {
                refused = 1;
                break;
            }
            pause_ms(1);
        }
        tag += count;
    }
    unsigned char first[64];
    unsigned      got = drain(sv[1], first, sizeof first, 1000);
    int           in_order = got == tag;
    for (unsigned i = 0; in_order && i < got; i++)
        in_order = first[i] == (unsigned char)i;
    ok(!refused, "the queue takes all twenty entries as the writer frees slots");
    ok(in_order, "and twenty-two datagrams arrive, every one in the order it was committed");
    lc_sendq_close(&q, NULL, 0u, 0u);
    close(sv[0]);
    close(sv[1]);
}

static void eight_wait_and_the_owner_is_woken(void)
{
    printf("\neight entries wait, one is in the writer's hands, and a freed entry wakes the owner\n");
    int           sv[2];
    lc_sendq_dest d;
    lc_sendq      q;
    if (unix_pair(sv, &d) != 0 || lc_sendq_start(&q, &d) != 0) {
        ok(0, "a socket pair and a started queue");
        return;
    }
    unsigned filled = fill(sv[0]);

    /* The first one goes into the writer's hands and stays there: the socket is full. */
    (void)put(&q, &d, 0x40, 1u);
    uint64_t until = now_ms() + 2000u;
    while (in_hand(&q) == 0u && now_ms() < until)
        pause_ms(1);
    ok(in_hand(&q) == 1u, "the writer takes the first entry and waits on the full socket");

    /* Then one at a time, asking after each commit, as the write loop asks at every batch boundary
     * (vendor/quic-go/connection.go:2611-2613). WouldBlock (vendor/quic-go/send_queue.go:70-72)
     * counts only what waits — Run takes the entry it writes off the channel first (:90-91). */
    unsigned committed = 1u;
    int      blocked = 0;
    for (unsigned i = 1; i < LC_SENDQ_SLOTS && !blocked; i++) {
        if (put(&q, &d, (uint8_t)(0x40 + i), 1u) != 0)
            break;
        committed++;
        blocked = lc_sendq_would_block(&q);
    }
    ok(blocked && committed == 1u + LC_SENDQ_CAP,
       "WouldBlock says yes at the eighth waiting entry, with one more in hand");
    if (!(blocked && committed == 1u + LC_SENDQ_CAP))
        printf("        blocked %d after %u committed\n", blocked, committed);

    /* The owner stops here. Reading the far end is the kernel draining the socket; the entry the
     * writer then frees is the one that has to wake the owner, and only because it stopped. */
    unsigned char first[32];
    unsigned      got = drain(sv[1], first, sizeof first, 50);
    struct pollfd p = { .fd = lc_sendq_wake_fd(&q), .events = POLLIN, .revents = 0 };
    ok(poll(&p, 1, 1500) == 1, "and the owner's wake descriptor turns readable once one is freed");
    lc_sendq_wake_drain(&q);

    /* Everything committed goes out once there is room: what the far end held before, and then
     * every entry. */
    until = now_ms() + 3000u;
    while (got < filled + committed && now_ms() < until)
        got += drain(sv[1], first, sizeof first, 100);
    ok(got == filled + committed, "and every committed entry reaches the socket once it has room");
    if (got != filled + committed)
        printf("        %u of %u + %u datagrams\n", got, filled, committed);
    lc_sendq_close(&q, NULL, 0u, 0u);
    close(sv[0]);
    close(sv[1]);
}

static void a_full_socket_cannot_hold_a_close(void)
{
    printf("\na close on a socket that stays full ends, and drops what could not leave\n");
    int           sv[2];
    lc_sendq_dest d;
    lc_sendq      q;
    if (unix_pair(sv, &d) != 0 || lc_sendq_start(&q, &d) != 0) {
        ok(0, "a socket pair and a started queue");
        return;
    }
    unsigned filled = fill(sv[0]);
    unsigned queued = 0;
    while (put(&q, &d, (uint8_t)queued, 1u) == 0)
        queued++;
    ok(queued == LC_SENDQ_SLOTS, "every slot is taken, which is when the close used to wait for empty");

    /* The old writer, told to stop, gave a full socket one interval PER DATAGRAM and went on to the
     * next: ten entries here, ten seconds. The close must now cost one interval. */
    const uint8_t last[2] = { 0xcc, 0xaa };
    uint64_t      t0 = now_ms();
    lc_sendq_close(&q, last, sizeof last, 0u);
    uint64_t took = now_ms() - t0;
    ok(took < 1600u, "the close returns within one interval of the socket staying full");
    if (took >= 1600u)
        printf("        it took %llu ms\n", (unsigned long long)took);

    unsigned char first[64];
    unsigned      got = drain(sv[1], first, sizeof first, 100);
    int           only_fill = got == filled;
    for (unsigned i = 0; only_fill && i < got && i < sizeof first; i++)
        only_fill = first[i] == 0xee;
    ok(only_fill, "and nothing it gave up on reaches the socket afterwards, the close included");
    close(sv[0]);
    close(sv[1]);
}

static void the_close_goes_last(void)
{
    printf("\nwith room on the socket, everything queued goes first and the close after it\n");
    int           sv[2];
    lc_sendq_dest d;
    lc_sendq      q;
    if (unix_pair(sv, &d) != 0 || lc_sendq_start(&q, &d) != 0) {
        ok(0, "a socket pair and a started queue");
        return;
    }
    for (unsigned i = 0; i < 5u; i++)
        (void)put(&q, &d, (uint8_t)i, 1u);
    const uint8_t last[2] = { 0xcc, 0xaa };
    lc_sendq_close(&q, last, sizeof last, 0u);

    unsigned char first[16];
    unsigned      got = drain(sv[1], first, sizeof first, 200);
    int           right = got == 6u && first[5] == 0xcc;
    for (unsigned i = 0; right && i < 5u; i++)
        right = first[i] == (unsigned char)i;
    ok(right, "five queued datagrams, then the close, in that order and nothing else");
    lc_sendq_close(&q, last, sizeof last, 0u);
    ok(drain(sv[1], first, sizeof first, 50) == 0u,
       "and a second close is a no-op, not a second close packet");
    close(sv[0]);
    close(sv[1]);
}

static void the_close_carries_its_mark(void)
{
    printf("\nthe close is marked as it was asked to be, on a real UDP socket\n");
    int rx = socket(AF_INET, SOCK_DGRAM, 0);
    int tx = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    int on = 1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t al = sizeof a;
    if (rx < 0 || tx < 0 || bind(rx, (struct sockaddr *)&a, sizeof a) != 0 ||
        getsockname(rx, (struct sockaddr *)&a, &al) != 0 ||
        setsockopt(rx, IPPROTO_IP, IP_RECVTOS, &on, sizeof on) != 0) {
        ok(0, "a loopback UDP pair that reports the TOS byte");
        return;
    }
    lc_sendq_dest d;
    memset(&d, 0, sizeof d);
    d.fd = tx;
    memcpy(&d.peer, &a, sizeof a);
    d.peer_len = sizeof a;
    d.family = AF_INET;

    lc_sendq q;
    if (lc_sendq_start(&q, &d) != 0) {
        ok(0, "a started queue");
        return;
    }
    const uint8_t last[4] = { 0x40, 1, 2, 3 };
    lc_sendq_close(&q, last, sizeof last, 2u /* ECT(0) */);

    struct pollfd p = { .fd = rx, .events = POLLIN, .revents = 0 };
    int           tos = -1;
    if (poll(&p, 1, 1000) == 1) {
        unsigned char buf[64];
        union {
            struct cmsghdr align;
            unsigned char  b[CMSG_SPACE(sizeof(int))];
        } ctl;
        struct iovec  iov = { .iov_base = buf, .iov_len = sizeof buf };
        struct msghdr m;
        memset(&m, 0, sizeof m);
        m.msg_iov = &iov;
        m.msg_iovlen = 1;
        m.msg_control = ctl.b;
        m.msg_controllen = sizeof ctl.b;
        if (recvmsg(rx, &m, 0) == (ssize_t)sizeof last) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
            for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c != NULL; c = CMSG_NXTHDR(&m, c))
#pragma GCC diagnostic pop
                if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_TOS)
                    tos = *(unsigned char *)CMSG_DATA(c);
        }
    }
    ok(tos >= 0 && (tos & 3) == 2, "the close leaves ECT(0) when the caller says so");
    close(rx);
    close(tx);
}

static void an_error_ends_the_writing(void)
{
    printf("\na send the kernel refuses for good ends the connection, as quic-go's Run does\n");
    int           sv[2];
    lc_sendq_dest d;
    lc_sendq      q;
    if (unix_pair(sv, &d) != 0 || lc_sendq_start(&q, &d) != 0) {
        ok(0, "a socket pair and a started queue");
        return;
    }
    close(sv[1]); /* ECONNREFUSED from here on */
    (void)put(&q, &d, 1, 1u);
    uint64_t until = now_ms() + 2000u;
    while (lc_sendq_error(&q) == 0 && now_ms() < until)
        pause_ms(1);
    ok(lc_sendq_error(&q) != 0, "the error is recorded for the owner to end the connection on");
    (void)put(&q, &d, 2, 1u);
    until = now_ms() + 2000u;
    while (!lc_sendq_empty(&q) && now_ms() < until)
        pause_ms(1);
    ok(lc_sendq_empty(&q), "and later entries are taken off unwritten, so nothing waits for them");
    uint64_t t0 = now_ms();
    const uint8_t last[1] = { 0xcc };
    lc_sendq_close(&q, last, sizeof last, 0u);
    ok(now_ms() - t0 < 500u, "and closing it does not try the dead socket again");
    close(sv[0]);
}

static void a_queue_never_started(void)
{
    printf("\na connection that failed to open is still closed\n");
    lc_sendq q;
    memset(&q, 0, sizeof q);
    q.wake_rd = q.wake_wr = -1;
    lc_sendq_close(&q, NULL, 0u, 0u);
    ok(lc_sendq_empty(&q) && lc_sendq_error(&q) == 0 && lc_sendq_reserve(&q) == NULL,
       "and a queue that never started answers empty, no error, no room — and closes quietly");
}

/* A hop moves the queue while it works: the write in progress finishes where it started, and
 * everything still queued goes to the new destination — udpHopPacketConn's currentConn, read at
 * WriteTo under the lock hop() takes (vendor/hysteria/extras/transport/udphop/conn.go:172-197,
 * :245-253). */
struct mover {
    lc_sendq      *q;
    lc_sendq_dest *to;
};

static void *move_it(void *arg)
{
    struct mover *m = arg;
    lc_sendq_set_dest(m->q, m->to);
    return NULL;
}

static void a_hop_moves_what_is_queued(void)
{
    printf("\na hop waits for the write in progress, and what is queued goes to the new port\n");
    int           a[2], b[2];
    lc_sendq_dest da, db;
    lc_sendq      q;
    if (unix_pair(a, &da) != 0 || unix_pair(b, &db) != 0 || lc_sendq_start(&q, &da) != 0) {
        ok(0, "two socket pairs and a started queue");
        return;
    }
    unsigned filled = fill(a[0]);
    int      put1 = put(&q, &da, 0x10, 1) == 0; /* the writer blocks on it: A is full */
    pause_ms(50);
    int put2 = put(&q, &da, 0x20, 1) == 0 && put(&q, &da, 0x30, 1) == 0;

    struct mover m = { &q, &db };
    pthread_t    t;
    int          started = pthread_create(&t, NULL, move_it, &m) == 0;
    pause_ms(50);

    /* Unblock A: read the filler, then the entry that was being written. */
    unsigned char buf[4096];
    unsigned      seen = 0;
    int           entry_on_a = 0;
    uint64_t      until = now_ms() + 3000u;
    while (now_ms() < until && !entry_on_a) {
        ssize_t r = recv(a[1], buf, sizeof buf, MSG_DONTWAIT);
        if (r > 0) {
            if (seen >= filled && buf[0] == 0x10)
                entry_on_a = 1;
            seen++;
        } else {
            pause_ms(1);
        }
    }
    if (started)
        pthread_join(t, NULL);
    unsigned char onb[8];
    unsigned      nb = drain(b[1], onb, sizeof onb, 1000);
    ok(put1 && put2 && entry_on_a, "the write in progress finishes on the old port");
    ok(nb == 2u && onb[0] == 0x20 && onb[1] == 0x30,
       "and the two still queued leave on the new one, in order");
    lc_sendq_close(&q, NULL, 0u, 0u);
    close(a[0]);
    close(a[1]);
    close(b[0]);
    close(b[1]);
}

int main(void)
{
    order_is_kept();
    a_hop_moves_what_is_queued();
    eight_wait_and_the_owner_is_woken();
    a_full_socket_cannot_hold_a_close();
    the_close_goes_last();
    the_close_carries_its_mark();
    an_error_ends_the_writing();
    a_queue_never_started();
    printf(failures == 0 ? "\nall ok\n" : "\nFAILURES\n");
    return failures == 0 ? 0 : 1;
}
