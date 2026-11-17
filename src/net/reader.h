/* A THREAD BESIDE THE LOOP, and it does exactly one thing: it blocks in a read.
 *
 * It was the only one until 2026-09-21. The Hysteria2 connection now has a second, the writer of its
 * send queue (quic/sendq.h), which blocks in sendmsg the way this one blocks in read and owns as
 * little. Neither decides anything; both hand bytes across one lock.
 *
 * WHY IT EXISTS, measured rather than supposed — see CONCURRENCY.md for the numbers and the stands
 * that produced them. On a 300 KB upload the reference takes 11 reads averaging 27 279 bytes; this
 * client took 41 averaging 9 539, and 34 of those were exactly one READ_CHUNK. That is not a
 * constant to raise: the read-vector ladder here is `allocStrategy.Adjust` verbatim and the copy
 * loop is `copyInternal` verbatim. It is a feedback loop that a single thread cannot leave — read,
 * frame, write, return to epoll, find little waiting because nothing was reading while we wrote,
 * read small, shrink the ladder, return sooner. The reference never makes that trip: a goroutine is
 * sitting in ReadMultiBuffer, woken by the first byte, and has accumulated more by the time it looks.
 *
 * WHAT IT IS NOT. It is not a worker pool and it is not a second event loop. It never touches
 * ngtcp2, the record layer, Vision, the session table, a timer or a socket towards the node. It owns
 * an epoll of its own with client-side descriptors in it, and the only memory it writes is the
 * uplink queue of the session that descriptor belongs to, under that session's own lock. Everything
 * that decides anything stays where it was, on the loop thread, single-threaded.
 *
 * THE MEMORY IT COSTS IS A MUTEX. The bytes go into the queue the session already has — the same
 * `to_up` the loop thread has always read into — so nothing is staged twice and no buffer is added.
 * On a client whose resident size on a live router is 2 296 kB that mattered more than elegance.
 *
 * TEARDOWN, which is the only place a bug here would be fatal — and where one was, for a day. A
 * session may be closed by the loop while the reader is inside it, or while the reader holds a ready
 * event for it that it has not reached yet. lc_reader_del is therefore synchronous: it removes the
 * descriptor from the reader's epoll, goes through the stage's lock, and then waits until the reader
 * has finished the batch of events it was working through. That last step is the one that was
 * missing: this paragraph used to say that an `active` flag kept a stale event out, and the flag
 * lives in the very memory that is freed — see lc_reader_del for what that did on a router. After it
 * returns, the session is the loop's alone and may be freed. */
#ifndef LC_NET_READER_H
#define LC_NET_READER_H

#include <pthread.h>
#include <stddef.h>

/* One descriptor the reader watches, and where it puts what it takes.
 *
 * The fields the two threads share are `len`, `eof` and `err`, and every one of them is touched only
 * with `lock` held — by the reader when it fills, by the loop when it drains. `buf` and `cap` are
 * written once at registration and never again. */
typedef struct {
    pthread_mutex_t lock;
    int             fd;     /* the client's descriptor; -1 when this stage is not registered */
    unsigned char  *buf;    /* the session's own uplink queue, not a copy of it */
    size_t          cap;
    size_t         *len;    /* how much of `buf` is filled: the queue's own field */
    size_t         *off;    /* how much of it the loop has already handed on */
    int             eof;    /* the client closed its side */
    int             err;    /* errno from the read that failed, or 0 */
    int             active; /* cleared by lc_reader_del before the session goes */
    int             full;   /* the queue had no room; the loop re-arms after it drains */
} lc_reader_stage;

/* Starts the thread. `wake` is a descriptor the reader writes one byte to whenever a stage gains
 * bytes, an end or an error — the loop watches it like any other. Returns -1 and starts nothing if
 * the thread or its epoll cannot be made; there is no second path, and a client that cannot read is
 * a client that must not pretend to run. */
int lc_reader_start(int wake);

/* Stops the thread and waits for it. Every stage must already have been removed. */
void lc_reader_stop(void);

/* Registers a descriptor. The stage is initialised here, including its lock, and belongs to the
 * reader from this moment until lc_reader_del returns. */
int lc_reader_add(lc_reader_stage *st, int fd, unsigned char *buf, size_t cap, size_t *len,
                  size_t *off);

/* Removes it, synchronously — see the note above on teardown. Safe on a stage that was never added
 * or has already been removed. */
void lc_reader_del(lc_reader_stage *st);

/* Says the queue has room again, after the loop has drained it. Cheap and idempotent: it does
 * nothing unless the reader had stopped for want of room. */
void lc_reader_rearm(lc_reader_stage *st);

#endif
