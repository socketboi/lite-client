#include "net/loop.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

/* Linux 4.5; a libc older than its headers may not name it. */
#ifndef EPOLLEXCLUSIVE
#define EPOLLEXCLUSIVE (1u << 28)
#endif

struct lc_loop {
    int                 fd;
    struct epoll_event *events;
    unsigned            max_events;
};

lc_loop *lc_loop_new(unsigned max_events)
{
    if (max_events == 0)
        return NULL;

    lc_loop *l = calloc(1, sizeof *l);
    if (l == NULL)
        return NULL;

    /* EPOLL_CLOEXEC so a descriptor never leaks into a child. Nothing forks here today, but a
     * crash handler that execs one is the obvious future addition. */
    l->fd = epoll_create1(EPOLL_CLOEXEC);
    if (l->fd < 0) {
        free(l);
        return NULL;
    }
    l->events = calloc(max_events, sizeof *l->events);
    if (l->events == NULL) {
        close(l->fd);
        free(l);
        return NULL;
    }
    l->max_events = max_events;
    return l;
}

void lc_loop_free(lc_loop *l)
{
    if (l == NULL)
        return;
    close(l->fd);
    free(l->events);
    free(l);
}

static uint32_t to_epoll(unsigned events)
{
    uint32_t e = 0;
    if (events & LC_EV_READ)
        e |= EPOLLIN;
    if (events & LC_EV_WRITE)
        e |= EPOLLOUT;
    if (events & LC_EV_EXCLUSIVE)
        e |= EPOLLEXCLUSIVE;
    /* Level-triggered on purpose. Edge-triggered is faster and demands that every handler drain a
     * socket completely on every wake-up; one handler that returns early silently stalls that
     * connection forever, and it will be the rare one that is hard to reproduce. */
    return e;
}

static unsigned from_epoll(uint32_t e)
{
    unsigned events = 0;
    if (e & EPOLLIN)
        events |= LC_EV_READ;
    if (e & EPOLLOUT)
        events |= LC_EV_WRITE;

    /* A peer that has stopped writing is something to READ, not an error: what it left behind is an
     * end-of-stream, and the way to collect it is a read that returns zero.
     *
     * Counted as an error, as it was, it tore the connection down instead — which made every
     * half-close a truncated reply, and made the whole lan_eof and up_shut arrangement below
     * unreachable, since a read only ever returns zero after exactly this event. An HTTP client
     * that shuts down its write side after the request is doing the ordinary thing, and it was
     * getting its answer cut off. */
    if (e & EPOLLRDHUP)
        events |= LC_EV_READ;

    /* These two are different: the descriptor itself is finished, in both directions. */
    if (e & (EPOLLERR | EPOLLHUP))
        events |= LC_EV_ERROR;
    return events;
}

static int ctl(lc_loop *l, int op, int fd, unsigned events, void *data)
{
    struct epoll_event ev;
    memset(&ev, 0, sizeof ev);
    ev.events = to_epoll(events);
    ev.data.ptr = data;

    /* Asked for only alongside reading, and that pairing matters. This is level-triggered: a peer
     * that has stopped writing keeps reporting it for as long as it is in the mask, so a caller
     * that has finished reading and stopped asking would be woken again and again with nothing to
     * do. Tied to LC_EV_READ, it stops the moment the caller stops caring.
     *
     * Not with LC_EV_EXCLUSIVE: the kernel accepts EPOLLEXCLUSIVE only beside EPOLLIN, EPOLLOUT,
     * EPOLLERR, EPOLLHUP, EPOLLWAKEUP and EPOLLET, and refuses the whole registration with EINVAL
     * otherwise. Exclusive is for a shared listener, and a listener has no peer to stop writing. */
    if ((events & LC_EV_READ) && !(events & LC_EV_EXCLUSIVE))
        ev.events |= EPOLLRDHUP;

    return epoll_ctl(l->fd, op, fd, &ev) == 0 ? 0 : -1;
}

int lc_loop_add(lc_loop *l, int fd, unsigned events, void *data)
{
    return ctl(l, EPOLL_CTL_ADD, fd, events, data);
}

int lc_loop_mod(lc_loop *l, int fd, unsigned events, void *data)
{
    return ctl(l, EPOLL_CTL_MOD, fd, events, data);
}

int lc_loop_del(lc_loop *l, int fd)
{
    return epoll_ctl(l->fd, EPOLL_CTL_DEL, fd, NULL) == 0 ? 0 : -1;
}

int lc_loop_wait(lc_loop *l, lc_event *out, unsigned max_out, int timeout_ms)
{
    unsigned want = max_out < l->max_events ? max_out : l->max_events;
    int      n = epoll_wait(l->fd, l->events, (int)want, timeout_ms);
    if (n < 0) {
        /* A signal is not a failure — it is how a timer or a shutdown request arrives. */
        return errno == EINTR ? 0 : -1;
    }
    for (int i = 0; i < n; i++) {
        out[i].fd = -1; /* the caller identifies connections by `data`, not by descriptor */
        out[i].data = l->events[i].data.ptr;
        out[i].events = from_epoll(l->events[i].events);
    }
    return n;
}

int lc_set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 ? 0 : -1;
}

/* ---- what an event and a read result mean ------------------------------------ */

int lc_ev_should_read(unsigned events)
{
    return (events & LC_EV_READ) != 0;
}

lc_read_outcome lc_read_classify(long got, int err)
{
    if (got > 0)
        return LC_READ_DATA;
    if (got == 0)
        return LC_READ_EOF;
    if (err == EAGAIN || err == EWOULDBLOCK || err == EINTR)
        return LC_READ_RETRY;
    return LC_READ_DEAD;
}

int lc_ev_finished(unsigned events, lc_read_outcome r)
{
    switch (r) {
    case LC_READ_DATA:
        return 0;
    case LC_READ_EOF:
    case LC_READ_DEAD:
        return 1;
    case LC_READ_RETRY:
    default:
        /* Nothing now — and if the event carried an error, nothing ever. See the header. */
        return (events & LC_EV_ERROR) != 0;
    }
}
