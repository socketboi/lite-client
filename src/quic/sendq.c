#include "quic/sendq.h"

#include "core/relax.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <poll.h>
#include <string.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

/* How long the writer waits for a full socket before looking again at whether it has been told to
 * stop. Not a deadline for the datagram — it keeps waiting — only the interval at which a stop is
 * noticed, so that a socket that never drains cannot hold a closing connection for ever. */
#define LC_SENDQ_POLL_MS 1000

/* ⚠️ HOW LONG THE WRITER STAYS AWAKE AFTER THE QUEUE EMPTIES, and this number is OURS, not the
 * reference's — the maintainer's decision of 2026-09-23, taken knowing that.
 *
 * The reference's writer is a goroutine, and Go's scheduler keeps the threads under it spinning for
 * work before they sleep, so a batch handed to a parked writer is picked up in microseconds. A
 * pthread parked on a condition variable is not: on the AX3000T, clocks on every gap of 50 us or
 * more between two entries this writer sent found it woken 155-172 us after the entry was committed,
 * in two gaps of three — and the owner packs a datagram in ~95 us, so the writer empties the queue
 * and parks between every pair of them. Go's spin is counted in steal attempts, not in time; this
 * waits in time, for about what that wake costs on the box it was measured on. The price is a core
 * busy between datagrams while an upload runs, and nothing when nothing is sent. See quic/sendq.h
 * for the measurements with it and without. */
#define LC_SENDQ_SPIN_NS 150000u

/* One sendmsg, and every outcome of the kernel taken the way quic-go takes it:
 *
 *   0  gone — or refused with EMSGSIZE, which quic-go treats as a lost packet and nothing more
 *      (isSendMsgSizeErr, vendor/quic-go/send_queue.go:91-99, sys_conn_df_linux.go:37-40);
 *   2  a batch the kernel refused AS a batch — EIO or EINVAL with UDP_SEGMENT, on which quic-go
 *      turns GSO off and sends the same datagrams one at a time (send_conn.go:73-93, isGSOError at
 *      sys_conn_helper_linux.go:98-107);
 *  -1  anything else, which ends the connection (vendor/quic-go/connection.go:602-606); the errno
 *      is in *err.
 *
 * A socket that would block is WAITED FOR, here, on this thread — which is what the reference's
 * writer goroutine does by sitting inside Write, and the whole reason the writer is a thread: the
 * owner goes on packing meanwhile.
 *
 * The first datagram on a connection is sent again once on EPERM, for the kernel quirk quic-go names
 * (send_conn.go:95-101, sys_conn_helper_linux.go:109-117).
 *
 * ADDRESSED ON EVERY CALL, because the socket is not connected — see dial_node in quic/conn.c. */
static int send_one(lc_sendq *q, const lc_sendq_dest *d, const uint8_t *data, size_t len,
                    uint16_t seg, unsigned ecn, int *err)
{
    struct iovec iov = { .iov_base = (void *)(uintptr_t)data, .iov_len = len };
    union {
        struct cmsghdr align;
        unsigned char  buf[CMSG_SPACE(sizeof(uint16_t)) + CMSG_SPACE(sizeof(int))];
    } control;
    memset(&control, 0, sizeof control);

    struct msghdr msg;
    memset(&msg, 0, sizeof msg);
    msg.msg_name = (void *)(uintptr_t)&d->peer;
    msg.msg_namelen = d->peer_len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.buf;
    msg.msg_controllen = sizeof control.buf;

    size_t          controllen = 0;
    struct cmsghdr *cm = NULL;
    /* Only for a buffer that is actually cut: quic-go asks for the segment size only `if len(b) >
     * int(gsoSize)` (vendor/quic-go/sys_conn_oob.go:234-240). */
#ifdef UDP_SEGMENT
    if (seg > 0u && len > seg) {
        cm = CMSG_FIRSTHDR(&msg);
        cm->cmsg_level = IPPROTO_UDP;
        cm->cmsg_type = UDP_SEGMENT;
        cm->cmsg_len = CMSG_LEN(sizeof seg);
        memcpy(CMSG_DATA(cm), &seg, sizeof seg);
        controllen += CMSG_SPACE(sizeof seg);
    }
#endif
    if (ecn != 0u) {
        /* CMSG_NXTHDR is musl's and does not survive -Wsign-conversion on 32 bits — the same macro,
         * the same reason and the same exemption as on the receive side. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
        cm = cm == NULL ? CMSG_FIRSTHDR(&msg) : CMSG_NXTHDR(&msg, cm);
#pragma GCC diagnostic pop
        if (cm != NULL) {
            int tos = (int)ecn;
            if (d->family == AF_INET6) {
                cm->cmsg_level = IPPROTO_IPV6;
                cm->cmsg_type = IPV6_TCLASS;
            } else {
                cm->cmsg_level = IPPROTO_IP;
                cm->cmsg_type = IP_TOS;
            }
            cm->cmsg_len = CMSG_LEN(sizeof tos);
            memcpy(CMSG_DATA(cm), &tos, sizeof tos);
            controllen += CMSG_SPACE(sizeof tos);
        }
    }
    /* ⚠️ THE CAST IS NOT COSMETIC. `msg_controllen` is socklen_t — 32 bits everywhere — while the
     * total is size_t: silent on mipsel, `-Werror=conversion` on aarch64. It is the sum of at most two
     * CMSG_SPACE terms over a buffer of a few dozen bytes, so the value cannot approach 2^32. */
    msg.msg_controllen = (socklen_t)controllen;
    if (controllen == 0u)
        msg.msg_control = NULL;

    for (;;) {
        if (sendmsg(d->fd, &msg, MSG_NOSIGNAL) >= 0) {
            q->wrote_first = 1;
            return 0;
        }
        int e = errno;
        if (e == EINTR)
            continue;
        if (e == EAGAIN || e == EWOULDBLOCK) {
            struct pollfd p;
            p.fd = d->fd;
            p.events = POLLOUT;
            p.revents = 0;
            int pr = poll(&p, 1, LC_SENDQ_POLL_MS);
            /* A failed socket wait is not writable readiness. Preserve the
             * failure for Run's terminal error path (quic-go/send_queue.go),
             * rather than retrying sendmsg and losing the original cause. */
            if (pr < 0 && errno != EINTR) {
                *err = errno;
                return -1;
            }
            if (pr > 0 && (p.revents & (POLLERR | POLLNVAL)) != 0) {
                *err = EBADF;
                return -1;
            }
            if (pr == 0) {
                /* Still full. Keep waiting — unless the owner is closing, in which case the node's
                 * idle timer is the backstop for whatever could not leave, as the close in
                 * quic/conn.c already accepts.
                 *
                 * ⚠️ AND IT ENDS THE WRITING, not just this datagram. This used to return "sent"
                 * and go on to the next entry, which met the same full socket and waited another
                 * second: up to ten entries of fourteen datagrams each, well over two minutes of a
                 * closing connection holding the one thread every session runs on. An error here
                 * makes the writer take the rest off unwritten, so a socket that stays full for
                 * one interval after the stop costs one interval. */
                pthread_mutex_lock(&q->lock);
                int stopping = q->stop;
                pthread_mutex_unlock(&q->lock);
                if (stopping) {
                    *err = ETIMEDOUT;
                    return -1;
                }
            }
            continue;
        }
        if (e == EPERM && !q->wrote_first) {
            q->wrote_first = 1;
            continue;
        }
        q->wrote_first = 1;
        if (e == EMSGSIZE)
            return 0;
        if (controllen > 0u && seg > 0u && len > seg && (e == EIO || e == EINVAL))
            return 2;
        *err = e;
        return -1;
    }
}

/* One entry: a batch in one call when it is one, otherwise its datagrams in order. */
static int send_entry(lc_sendq *q, const lc_sendq_dest *d, lc_sendq_entry *en, int *err)
{
    pthread_mutex_lock(&q->lock);
    int batching = !q->gso_failed;
    pthread_mutex_unlock(&q->lock);

    if (en->seg > 0u && en->n > 1u && batching) {
        size_t total = 0;
        for (unsigned i = 0; i < en->n; i++)
            total += en->len[i];
        int rv = send_one(q, d, en->buf, total, en->seg, en->ecn[0], err);
        if (rv != 2)
            return rv;
        /* For the rest of the connection, as quic-go's gotGSOError is (send_conn.go:76-80): set
         * here, read by the owner so that it stops building batches, and this batch goes out below
         * one datagram at a time. */
        pthread_mutex_lock(&q->lock);
        q->gso_failed = 1;
        pthread_mutex_unlock(&q->lock);
    }

    size_t off = 0;
    for (unsigned i = 0; i < en->n; i++) {
        int rv = send_one(q, d, en->buf + off, en->len[i], 0u, en->ecn[i], err);
        if (rv < 0)
            return -1;
        off += en->len[i];
    }
    return 0;
}

static void wake(lc_sendq *q)
{
    uint8_t one = 1;
    /* Non-blocking, and a full pipe is fine: the owner only needs to know that SOMETHING was freed,
     * and a pipe full of bytes already says so. */
    while (write(q->wake_wr, &one, 1) < 0 && errno == EINTR) {
    }
}

static uint64_t mono_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec;
}


/* Waits awake, up to LC_SENDQ_SPIN_NS, for a commit after `seen`. Reads only `kick`, which is written
 * atomically, so the loop touches neither the lock nor anything the owner writes under it; the clock
 * is read once per sixty-four looks, not every time. */
static void await_awake(lc_sendq *q, unsigned seen)
{
    uint64_t start = mono_ns();
    for (;;) {
        for (unsigned i = 0; i < 64u; i++) {
            if (__atomic_load_n(&q->kick, __ATOMIC_ACQUIRE) != seen)
                return;
            lc_cpu_relax();
        }
        if (mono_ns() - start >= LC_SENDQ_SPIN_NS)
            return;
    }
}

static void *writer(void *arg)
{
    lc_sendq *q = arg;

    for (;;) {
        pthread_mutex_lock(&q->lock);
        if (q->count == 0u && !q->stop) {
            /* Awake first, asleep only if nothing came — see LC_SENDQ_SPIN_NS. A stop arriving now
             * is noticed below, at most that long later. */
            unsigned seen = __atomic_load_n(&q->kick, __ATOMIC_ACQUIRE);
            pthread_mutex_unlock(&q->lock);
            await_awake(q, seen);
            pthread_mutex_lock(&q->lock);
        }
        while (q->count == 0u && !q->stop)
            pthread_cond_wait(&q->cv, &q->lock);
        if (q->count == 0u) {
            /* Told to stop and nothing left: everything queued has gone, which is the order
             * send_queue.go:82-90 keeps. */
            pthread_mutex_unlock(&q->lock);
            break;
        }
        lc_sendq_entry *en = &q->e[q->head];
        int             dead = q->err != 0;
        /* A hop waiting for the write before this one moves the queue now, before this one — see
         * lc_sendq_set_dest. Where this entry goes is fixed here, as WriteTo reads currentConn. */
        if (q->moving) {
            q->cur = q->next;
            q->moving = 0;
            pthread_cond_broadcast(&q->cv);
        }
        lc_sendq_dest dest = q->cur;
        /* Taken off before it is written, as Run takes it off the channel: from here it no longer
         * counts as waiting. */
        q->writing = 1u;
        pthread_mutex_unlock(&q->lock);

        /* After an error nothing more is written — the reference's Run has returned by then and its
         * Send drops what it is given (send_queue.go:60-61) — but entries are still taken off, so
         * that nobody draining this queue waits for ever. */
        if (!dead) {
            int e = 0;
            if (send_entry(q, &dest, en, &e) < 0) {
                pthread_mutex_lock(&q->lock);
                if (q->err == 0)
                    q->err = e != 0 ? e : EIO;
                pthread_mutex_unlock(&q->lock);
            }
        }

        pthread_mutex_lock(&q->lock);
        q->head = (q->head + 1u) % LC_SENDQ_SLOTS;
        q->count--;
        q->writing = 0u;
        int woken = q->blocked;
        q->blocked = 0;
        pthread_cond_broadcast(&q->cv);
        pthread_mutex_unlock(&q->lock);
        if (woken)
            wake(q);
    }
    return NULL;
}

static int nonblock_cloexec(int fd)
{
    int fl = fcntl(fd, F_GETFL);
    int fd_fl = fcntl(fd, F_GETFD);
    return fl < 0 || fd_fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) != 0 ||
                   fcntl(fd, F_SETFD, fd_fl | FD_CLOEXEC) != 0
               ? -1
               : 0;
}

int lc_sendq_start(lc_sendq *q, const lc_sendq_dest *first)
{
    int fds[2];

    q->head = q->count = q->writing = 0u;
    q->stop = q->err = q->gso_failed = q->wrote_first = q->blocked = 0;
    __atomic_store_n(&q->kick, 0u, __ATOMIC_RELAXED);
    q->started = 0;
    q->wake_rd = q->wake_wr = -1;

    if (pipe(fds) != 0)
        return -1;
    if (nonblock_cloexec(fds[0]) != 0 || nonblock_cloexec(fds[1]) != 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    q->wake_rd = fds[0];
    q->wake_wr = fds[1];

    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->cv, NULL);
    q->cur = *first;
    q->moving = 0;

    /* A small stack, as the reader's is: this thread holds a msghdr and a control buffer and
     * nothing else. The entries it sends live in the queue, not on its stack. */
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    (void)pthread_attr_setstacksize(&attr, 32u * 1024u);
    int rv = pthread_create(&q->thread, &attr, writer, q);
    pthread_attr_destroy(&attr);
    if (rv != 0) {
        pthread_cond_destroy(&q->cv);
        pthread_mutex_destroy(&q->lock);
        close(q->wake_rd);
        close(q->wake_wr);
        q->wake_rd = q->wake_wr = -1;
        return -1;
    }
    q->started = 1;
    return 0;
}

void lc_sendq_set_dest(lc_sendq *q, const lc_sendq_dest *d)
{
    if (!q->started) {
        q->cur = *d;
        return;
    }
    /* Asked for, then waited for: a write in progress finishes where it began, and the writer
     * moves the queue before the next one; with nothing being written it moves at once. Go's
     * RWMutex gives hop() its Lock ahead of any WriteTo that comes after it, which is why the move
     * is the writer's to make and not a race for a lock. */
    pthread_mutex_lock(&q->lock);
    q->next = *d;
    q->moving = 1;
    while (q->moving && q->writing)
        pthread_cond_wait(&q->cv, &q->lock);
    if (q->moving) {
        q->cur = q->next;
        q->moving = 0;
    }
    pthread_mutex_unlock(&q->lock);
}

void lc_sendq_close(lc_sendq *q, const uint8_t *last, size_t len, unsigned ecn)
{
    if (!q->started)
        return;
    pthread_mutex_lock(&q->lock);
    q->stop = 1;
    pthread_cond_broadcast(&q->cv);
    pthread_mutex_unlock(&q->lock);
    pthread_join(q->thread, NULL);
    if (q->moving) {
        q->cur = q->next;
        q->moving = 0;
    }

    /* The writer is gone and everything it held has been written or given up on. `stop` is still
     * set, so send_one gives a full socket one interval and no more; after an error — the writer's,
     * or a stop that already timed out — nothing more is tried at all. */
    if (last != NULL && len > 0u && q->err == 0) {
        int e = 0;
        (void)send_one(q, &q->cur, last, len, 0u, ecn, &e);
    }

    pthread_cond_destroy(&q->cv);
    pthread_mutex_destroy(&q->lock);
    close(q->wake_rd);
    close(q->wake_wr);
    q->wake_rd = q->wake_wr = -1;
    q->started = 0;
}

/* The four questions below are answered for a queue that was never started too — as "empty, all free,
 * no error" — because a connection that failed to open is still closed, and its close asks them. */
int lc_sendq_would_block(lc_sendq *q)
{
    if (!q->started)
        return 0;
    pthread_mutex_lock(&q->lock);
    int full = q->count - q->writing >= LC_SENDQ_CAP;
    if (full)
        q->blocked = 1;
    pthread_mutex_unlock(&q->lock);
    return full;
}

int lc_sendq_empty(lc_sendq *q)
{
    if (!q->started)
        return 1;
    pthread_mutex_lock(&q->lock);
    int e = q->count == 0u;
    pthread_mutex_unlock(&q->lock);
    return e;
}

/* The slot at head+count. Stable across a concurrent pop: the writer advances head and lowers count
 * together, so head+count names the same slot before and after, and the writer only ever touches
 * slots in [head, head+count). */
lc_sendq_entry *lc_sendq_reserve(lc_sendq *q)
{
    if (!q->started)
        return NULL;
    pthread_mutex_lock(&q->lock);
    unsigned c = q->count, h = q->head;
    pthread_mutex_unlock(&q->lock);
    if (c >= LC_SENDQ_SLOTS)
        return NULL;
    lc_sendq_entry *en = &q->e[(h + c) % LC_SENDQ_SLOTS];
    en->n = 0u;
    en->seg = 0u;
    return en;
}

void lc_sendq_commit(lc_sendq *q)
{
    pthread_mutex_lock(&q->lock);
    q->count++;
    __atomic_store_n(&q->kick, __atomic_load_n(&q->kick, __ATOMIC_RELAXED) + 1u, __ATOMIC_RELEASE);
    pthread_cond_signal(&q->cv);
    pthread_mutex_unlock(&q->lock);
}

int lc_sendq_error(lc_sendq *q)
{
    if (!q->started)
        return 0;
    pthread_mutex_lock(&q->lock);
    int e = q->err;
    pthread_mutex_unlock(&q->lock);
    return e;
}

int lc_sendq_gso_failed(lc_sendq *q)
{
    if (!q->started)
        return 0;
    pthread_mutex_lock(&q->lock);
    int f = q->gso_failed;
    pthread_mutex_unlock(&q->lock);
    return f;
}

int lc_sendq_wake_fd(const lc_sendq *q)
{
    return q->wake_rd;
}

void lc_sendq_wake_drain(lc_sendq *q)
{
    uint8_t buf[64];
    while (read(q->wake_rd, buf, sizeof buf) > 0) {
    }
}
