#include "net/reader.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

/* The reader's own epoll, its thread, and the descriptor it pokes the loop with. All three are
 * process-wide because there is one reader: a second would be a second answer to a question that has
 * one. */
static int       r_ep = -1;
static int       r_wake = -1;
static int       r_ctl = -1;    /* write end of the control pipe: a stop request, or a nudge */
static int       r_ctl_rd = -1; /* its read end, the one entry in the epoll that is not a stage */
static pthread_t r_thread;
static int       r_running;

/* HOW FAR THE READER HAS GOT, which is what lc_reader_del waits on — see there for why a lock on the
 * stage is not enough. `r_batches` counts the batches of events the reader has finished with, one
 * per return from epoll_wait; `r_gone` says it will never finish another, so that nobody waits for
 * a thread that has left; `r_stopping` tells a stop request apart from a nudge on the same pipe. */
static pthread_mutex_t r_seq_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  r_seq_cv = PTHREAD_COND_INITIALIZER;
static unsigned long   r_batches;
static int             r_gone;
static int             r_stopping;

/* One byte towards the loop. Nothing is read back here — the loop drains its own end, and a wake
 * that is already pending needs no second byte, which is why a full pipe is not an error. */
static void poke(void)
{
    unsigned char one = 1;

    while (write(r_wake, &one, 1) < 0 && errno == EINTR) {
    }
}

/* One byte towards the reader, for the same reason and with the same indifference to a full pipe:
 * a byte already waiting wakes it just as well. */
static void nudge(void)
{
    unsigned char one = 1;

    while (write(r_ctl, &one, 1) < 0 && errno == EINTR) {
    }
}

/* One ready descriptor, taken as far as the queue allows.
 *
 * THE READ IS AS LARGE AS THE ROOM, not one READ_CHUNK at a time, and that is the whole point of the
 * thread: the reference's reader is bounded by its buffer ladder and by nothing else, and the ladder
 * only ever collapsed here because the loop kept arriving before anything had accumulated. */
static void drain(lc_reader_stage *st)
{
    pthread_mutex_lock(&st->lock);

    if (!st->active) {
        pthread_mutex_unlock(&st->lock);
        return;
    }

    /* The queue's own compaction rule, and it belongs under this lock like everything else that
     * reads those two fields: a queue whose whole content has been handed on starts again at zero. */
    if (*st->off > 0 && *st->off == *st->len) {
        *st->len = 0;
        *st->off = 0;
    }

    size_t room = st->cap - *st->len;

    if (room == 0) {
        /* Nothing to do until the loop drains it. The descriptor stays in the epoll but is disarmed,
         * so a level-triggered readiness does not spin this thread. */
        st->full = 1;
        struct epoll_event ev;
        memset(&ev, 0, sizeof ev);
        ev.data.ptr = st;
        (void)epoll_ctl(r_ep, EPOLL_CTL_MOD, st->fd, &ev);
        pthread_mutex_unlock(&st->lock);
        return;
    }

    ssize_t got = read(st->fd, st->buf + *st->len, room);

    if (got > 0) {
        *st->len += (size_t)got;
    } else if (got == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
        if (got == 0)
            st->eof = 1;
        else
            st->err = errno;
        /* AND THE DESCRIPTOR LEAVES THE EPOLL NOW, because there is nothing more it can say. An end
         * of stream stays readable for as long as the descriptor is open, and a reset stays in error,
         * so left in a level-triggered epoll it was reported again on every wait until the loop got
         * round to closing the session — a spin, and one that filled every batch with events for the
         * very sessions that were being closed, which is where the use-after-free described at
         * lc_reader_del lived. The removal there then finds nothing, as a re-arm by
         * lc_reader_rearm would, and both ignore the answer. */
        (void)epoll_ctl(r_ep, EPOLL_CTL_DEL, st->fd, NULL);
    } else {
        /* Nothing was there after all: a readiness that another wakeup already consumed. Not an
         * event for the loop. */
        pthread_mutex_unlock(&st->lock);
        return;
    }

    pthread_mutex_unlock(&st->lock);
    poke();
}

static void *reader_main(void *unused)
{
    (void)unused;

    for (;;) {
        struct epoll_event evs[16];
        int                n = epoll_wait(r_ep, evs, 16, -1);
        int                stop = 0;

        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        for (int i = 0; i < n; i++) {
            if (evs[i].data.ptr == NULL) {
                /* The control pipe: emptied, and then either a stop request — every stage is already
                 * gone by the time one arrives, because lc_reader_stop says so — or a nudge from
                 * lc_reader_del, which asks for nothing but that this batch be finished. */
                unsigned char sink[64];
                while (read(r_ctl_rd, sink, sizeof sink) > 0) {
                }
                pthread_mutex_lock(&r_seq_lock);
                stop = r_stopping;
                pthread_mutex_unlock(&r_seq_lock);
                continue;
            }
            drain((lc_reader_stage *)evs[i].data.ptr);
        }

        /* This batch is finished: no pointer it carried is looked at again. */
        pthread_mutex_lock(&r_seq_lock);
        r_batches++;
        pthread_cond_broadcast(&r_seq_cv);
        pthread_mutex_unlock(&r_seq_lock);

        if (stop)
            break;
    }

    pthread_mutex_lock(&r_seq_lock);
    r_gone = 1;
    pthread_cond_broadcast(&r_seq_cv);
    pthread_mutex_unlock(&r_seq_lock);
    return NULL;
}

int lc_reader_start(int wake)
{
    if (r_running)
        return 0;

    r_ep = epoll_create1(EPOLL_CLOEXEC);
    if (r_ep < 0)
        return -1;

    /* Non-blocking at the read end, because the reader empties it with a loop that has to stop when
     * it is empty; the write end, because a nudge into a full pipe is a nudge already delivered. */
    int fds[2];
    if (pipe(fds) != 0 || fcntl(fds[0], F_SETFL, O_NONBLOCK) != 0 ||
        fcntl(fds[1], F_SETFL, O_NONBLOCK) != 0) {
        close(r_ep);
        r_ep = -1;
        return -1;
    }
    r_ctl_rd = fds[0];
    r_ctl = fds[1];

    struct epoll_event ev;
    memset(&ev, 0, sizeof ev);
    ev.events = EPOLLIN;
    ev.data.ptr = NULL; /* the one entry that is not a stage */
    if (epoll_ctl(r_ep, EPOLL_CTL_ADD, fds[0], &ev) != 0) {
        close(fds[0]);
        close(fds[1]);
        close(r_ep);
        r_ep = -1;
        r_ctl = r_ctl_rd = -1;
        return -1;
    }

    r_wake = wake;
    r_batches = 0;
    r_gone = 0;
    r_stopping = 0;

    /* A stack of its own size, because the default is a megabyte of address space per thread and
     * this one calls read() and nothing else. The client's resident size is measured in a couple of
     * megabytes on the box it ships to. */
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    (void)pthread_attr_setstacksize(&attr, 32u * 1024u);

    int rv = pthread_create(&r_thread, &attr, reader_main, NULL);
    pthread_attr_destroy(&attr);

    if (rv != 0) {
        close(fds[0]);
        close(fds[1]);
        close(r_ep);
        r_ep = -1;
        r_ctl = r_ctl_rd = -1;
        return -1;
    }

    r_running = 1;
    return 0;
}

void lc_reader_stop(void)
{
    if (!r_running)
        return;

    pthread_mutex_lock(&r_seq_lock);
    r_stopping = 1;
    pthread_mutex_unlock(&r_seq_lock);
    nudge();

    (void)pthread_join(r_thread, NULL);
    close(r_ctl);
    close(r_ctl_rd);
    close(r_ep);
    r_ep = -1;
    r_ctl = r_ctl_rd = -1;
    r_running = 0;
}

int lc_reader_add(lc_reader_stage *st, int fd, unsigned char *buf, size_t cap, size_t *len,
                  size_t *off)
{
    if (!r_running)
        return -1;

    memset(st, 0, sizeof *st);
    if (pthread_mutex_init(&st->lock, NULL) != 0)
        return -1;

    st->fd = fd;
    st->buf = buf;
    st->cap = cap;
    st->len = len;
    st->off = off;
    st->active = 1;

    struct epoll_event ev;
    memset(&ev, 0, sizeof ev);
    ev.events = EPOLLIN;
    ev.data.ptr = st;

    if (epoll_ctl(r_ep, EPOLL_CTL_ADD, fd, &ev) != 0) {
        st->active = 0;
        pthread_mutex_destroy(&st->lock);
        st->fd = -1;
        return -1;
    }

    return 0;
}

void lc_reader_del(lc_reader_stage *st)
{
    if (st->fd < 0 || !st->active)
        return;

    /* Out of the epoll first, so that no wait BEGUN from now on can report it... */
    (void)epoll_ctl(r_ep, EPOLL_CTL_DEL, st->fd, NULL);

    /* ...then through the lock, which cannot be taken while the reader is inside this stage, and
     * with `active` cleared so that a readiness already in the reader's hands finds nothing to do... */
    pthread_mutex_lock(&st->lock);
    st->active = 0;
    pthread_mutex_unlock(&st->lock);

    /* ...AND THEN PAST THE END OF THE READER'S BATCH, which is the step this function did not have.
     *
     * The two steps above were described as enough, and they are not. epoll_wait hands the reader up
     * to sixteen events at once, and one of them can name this stage when the removal above happens:
     * the kernel copied it out before the descriptor left. The reader then gets to it after this
     * function has returned — after the session holding the stage has been freed — and `drain`
     * takes a lock that is no longer there. `active` does not help, because it lives in the same
     * freed memory: reading it is the use-after-free, not the protection against one.
     *
     * Seen as it was, on the router: SIGSEGV in libc called from reader_main, the return address
     * the instruction after pthread_mutex_lock(&st->lock) and before the load of st->active at
     * offset 52; three times in one afternoon, the first in the service itself, which procd
     * restarted without anybody learning of it.
     *
     * So this waits for the reader to finish whatever batch it is in the middle of, and nudges it,
     * so that a reader asleep in epoll_wait finishes an empty one rather than none. A batch finished
     * after the removal cannot have been handed out before it and still be unread; one handed out
     * after it cannot name this stage. When this returns, the stage is the loop's alone. */
    pthread_mutex_lock(&r_seq_lock);
    unsigned long seen = r_batches;
    int           gone = r_gone;
    pthread_mutex_unlock(&r_seq_lock);

    if (!gone) {
        nudge();
        pthread_mutex_lock(&r_seq_lock);
        while (r_batches == seen && !r_gone)
            pthread_cond_wait(&r_seq_cv, &r_seq_lock);
        pthread_mutex_unlock(&r_seq_lock);
    }

    pthread_mutex_destroy(&st->lock);
    st->fd = -1;
}

void lc_reader_rearm(lc_reader_stage *st)
{
    if (st->fd < 0 || !st->active)
        return;

    pthread_mutex_lock(&st->lock);

    if (st->full) {
        st->full = 0;
        struct epoll_event ev;
        memset(&ev, 0, sizeof ev);
        ev.events = EPOLLIN;
        ev.data.ptr = st;
        (void)epoll_ctl(r_ep, EPOLL_CTL_MOD, st->fd, &ev);
    }

    pthread_mutex_unlock(&st->lock);
}
