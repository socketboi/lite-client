/* The event loop.
 *
 * One thread, epoll, no callbacks into user code that can re-enter the loop. On a router that has
 * to hold a few hundred connections in 8 MB of RSS this is not a stylistic choice: a thread per
 * connection costs a stack each, and a callback that can close the very connection it was invoked
 * for is the shortest path to a use-after-free.
 *
 * The loop therefore owns nothing. It reports which descriptors are ready and the caller decides
 * what to do — including deleting a connection, which happens between events rather than inside
 * one.
 *
 * ⚠️ AND THERE IS NOTHING IN vendor/ THIS COULD BE COMPARED AGAINST, which is why COVERAGE.md
 * lists this file and net/loop.c among the uncited and why that is a boundary rather than a debt.
 * The reference is a Go program: it has no event loop because the runtime is one. Where this file
 * says epoll, Xray and quic-go say `go func()`, and a scheduler nobody wrote does the rest. There
 * is no line to cite, no function to compare, and a reverse pass that generates requirements from
 * the reference's shape will attribute the runtime's behaviour to us — which the sieve of
 * 2026-08-29 did, spending a batch on it.
 *
 * Written down once, in the two files a reader would open first, so the next audit starts from the
 * architecture rather than from a list of absent functions. (A second such boundary stood beside it,
 * a check on the machine's memory before every growth; that check is gone since 29.09 — L1 —
 * because the reference has none.) */
#ifndef LC_LOOP_H
#define LC_LOOP_H

#include <stddef.h>
#include <stdint.h>

#define LC_EV_READ 0x1u
#define LC_EV_WRITE 0x2u
#define LC_EV_ERROR 0x4u /* reported, never requested: hangup or error on the descriptor */
/* Requested, never reported, and only when a descriptor is ADDED: of all the loops waiting on this
 * one descriptor, wake ONE (EPOLLEXCLUSIVE). For a listener several workers share, the one woken is
 * one that is waiting — an idle one — and nobody else wakes to find nothing. Read only; the kernel
 * refuses it together with EPOLLRDHUP, which a listener has no use for anyway. See lc-tunnel,
 * before `supervise`, and test/loop/test_share.c. */
#define LC_EV_EXCLUSIVE 0x8u

typedef struct {
    int   fd;
    void *data;     /* whatever the caller attached */
    unsigned events; /* what happened */
} lc_event;

typedef struct lc_loop lc_loop;

lc_loop *lc_loop_new(unsigned max_events);
void     lc_loop_free(lc_loop *l);

/* Registers or updates a descriptor. `data` is handed back with every event for it. */
int lc_loop_add(lc_loop *l, int fd, unsigned events, void *data);
int lc_loop_mod(lc_loop *l, int fd, unsigned events, void *data);
int lc_loop_del(lc_loop *l, int fd);

/* Waits up to timeout_ms and fills `out` with what is ready. Returns how many, or -1.
 * A timeout is not an error: it returns zero, which is how periodic work gets done. */
int lc_loop_wait(lc_loop *l, lc_event *out, unsigned max_out, int timeout_ms);

/* Puts a descriptor into non-blocking mode. Every socket in the loop must be non-blocking, or one
 * slow peer stalls every other connection on the device.
 *
 * ⚠️ AND THE RULE NOW HOLDS WITH NO EXCEPTION, which it did not. There used to be an lc_set_blocking
 * beside this, for the one caller that borrowed non-blocking mode to bound a SYN by a deadline and
 * then handed the descriptor back BLOCKING — the socket to the node, the one that carries a
 * household's traffic for hours. The reason given was that lc_read_full and lc_write_full poll and
 * then expect the syscall to complete; they now treat EAGAIN as the retry it is, so the descriptor
 * stays non-blocking for its whole life and the sentence above is true of every socket rather than
 * most of them. lc_set_blocking is gone with its last caller: a function that puts a socket back
 * into the mode this rule forbids should not be within reach. */
int lc_set_nonblocking(int fd);

/* ---- what an event and a read result mean -----------------------------------
 *
 * The decision "read now, or is this over" separated from the machinery that obtains either, so it
 * can be stated once and checked without a socket, a peer or a protocol.
 *
 * The rule it encodes, in one line: THE ERROR FLAGS ARE INFORMATIVE, THE SYSCALL IS THE TRUTH.
 * Bytes that arrived before a connection broke are still in the kernel's buffer, and epoll reports
 * the data and the error together — a peer that answers and then resets is exactly that shape. So
 * an error is never itself a reason to stop reading; read() reports the two in their real order. */

/* Whether there is something to read despite whatever else the event says. */
int lc_ev_should_read(unsigned events);

typedef enum {
    LC_READ_DATA = 0, /* bytes arrived */
    LC_READ_EOF,      /* the peer has finished writing */
    LC_READ_RETRY,    /* nothing this moment: EAGAIN, or a signal */
    LC_READ_DEAD,     /* the descriptor is finished */
} lc_read_outcome;

/* Classifies what a read returned. `got` is the syscall's return, `err` its errno. */
lc_read_outcome lc_read_classify(long got, int err);

/* Whether the session behind this descriptor is over, given the flags that woke us and what the
 * read said.
 *
 * The one case worth naming: a retry when the event carried an error. Nothing more is coming — an
 * error flag is reported whether or not it was asked for, so a caller that treated this as "come
 * back later" would be woken again immediately, forever, with nothing to read. That is the same
 * shape as the descriptor-exhaustion spin, in a different place. */
int lc_ev_finished(unsigned events, lc_read_outcome r);

#endif
