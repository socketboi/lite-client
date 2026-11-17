/* The reader thread's one fatal promise: once lc_reader_del returns, the reader never touches that
 * stage again, so the session holding it may be freed.
 *
 * It was broken, and not by a mistake in the code so much as in the argument the code was written
 * to: the removal went through the stage's lock and cleared an `active` flag, and that was said to
 * keep out an event the reader already held. It could not, because the flag lives in the memory
 * being freed. A batch from epoll_wait can hold an event for a stage at the moment it is removed, and
 * the reader reaches it after the session is gone. On a router that was a SIGSEGV inside
 * pthread_mutex_lock called from reader_main — see lc_reader_del in src/net/reader.c.
 *
 * Checked here the way the router found it, only much faster: every stage and the queue it fills
 * live in a mapping of their own, and the mapping is taken away the moment lc_reader_del returns.
 * A reader that looks at a removed stage faults on the spot rather than reading whatever the
 * allocator put there next, and the fault is reported as a failure instead of a crash. The clients
 * all close their end straight away, because an end of stream is exactly what kept the reader
 * holding events for sessions that were being closed. */

#include "net/reader.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

static int failures;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

/* A fault is the finding, not the end of the suite: said, and then the exit a failed check gives. */
static void on_fault(int sig)
{
    static const char msg[] =
        "  FAIL  the reader touched a stage after lc_reader_del had returned (a fault in freed memory)\n";
    (void)sig;
    (void)!write(1, msg, sizeof msg - 1);
    _exit(1);
}

/* What a session gives the reader: the stage and the queue, in one mapping of their own. */
typedef struct {
    lc_reader_stage st;
    size_t          len, off;
    unsigned char   buf[4096];
} slot;

static slot *slot_new(void)
{
    void *p = mmap(NULL, sizeof(slot), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p == MAP_FAILED ? NULL : p;
}

/* The helper that stops the reader where the race is: it holds two stages' locks, lets go of the first
 * when told, and of the second twenty milliseconds after that. */
typedef struct {
    pthread_mutex_t *y, *x;
    pthread_mutex_t  m;
    pthread_cond_t   cv;
    int              step;
} holder;

static void holder_step(holder *h, int step)
{
    pthread_mutex_lock(&h->m);
    h->step = step;
    pthread_cond_broadcast(&h->cv);
    pthread_mutex_unlock(&h->m);
}

static void holder_wait(holder *h, int step)
{
    pthread_mutex_lock(&h->m);
    while (h->step < step)
        pthread_cond_wait(&h->cv, &h->m);
    pthread_mutex_unlock(&h->m);
}

static void *hold(void *arg)
{
    holder *h = arg;
    pthread_mutex_lock(h->y);
    pthread_mutex_lock(h->x);
    holder_step(h, 1);
    holder_wait(h, 2);
    pthread_mutex_unlock(h->y);
    usleep(20000);
    pthread_mutex_unlock(h->x);
    return NULL;
}

static int wait_wake(int fd, int ms)
{
    struct pollfd p = { .fd = fd, .events = POLLIN };
    if (poll(&p, 1, ms) != 1)
        return 0;
    unsigned char sink[256];
    while (read(fd, sink, sizeof sink) > 0) {
    }
    return 1;
}

int main(void)
{
    printf("\nthe reader thread and the sessions it reads for\n");

    signal(SIGSEGV, on_fault);
    signal(SIGBUS, on_fault);
    signal(SIGPIPE, SIG_IGN);

    int wake[2];
    if (pipe(wake) != 0 || fcntl(wake[0], F_SETFL, O_NONBLOCK) != 0 ||
        fcntl(wake[1], F_SETFL, O_NONBLOCK) != 0) {
        ok(0, "a pipe to be woken through");
        return 1;
    }
    ok(lc_reader_start(wake[1]) == 0, "the reader starts");

    /* What it is for, first: bytes a client sends end up in the session's queue, and so does the
     * client's end. */
    {
        int   sv[2];
        slot *s = slot_new();
        int   made = s != NULL && socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0 &&
                   fcntl(sv[0], F_SETFL, O_NONBLOCK) == 0;
        ok(made, "a client and a session to read for");
        if (made) {
            ok(lc_reader_add(&s->st, sv[0], s->buf, sizeof s->buf, &s->len, &s->off) == 0,
               "the session is handed to the reader");
            (void)!write(sv[1], "hello", 5);
            int woke = wait_wake(wake[0], 2000);
            pthread_mutex_lock(&s->st.lock);
            int got = s->len == 5 && memcmp(s->buf, "hello", 5) == 0;
            pthread_mutex_unlock(&s->st.lock);
            ok(woke && got, "what the client sent is in the queue, and the loop was woken for it");

            close(sv[1]);
            int eof = 0;
            for (int i = 0; i < 200 && !eof; i++) {
                (void)wait_wake(wake[0], 10);
                pthread_mutex_lock(&s->st.lock);
                eof = s->st.eof;
                pthread_mutex_unlock(&s->st.lock);
            }
            ok(eof, "and so is the client's end");

            lc_reader_del(&s->st);
            ok(s->st.fd == -1, "the session is taken back");
            close(sv[0]);
            munmap(s, sizeof *s);
        }
    }

    /* A FULL QUEUE, AND THE WAKE-UP OUT OF IT — the one path test/hystand cannot see. With the
     * loop's re-arm after it makes room taken out, every scenario there still passes, because the
     * loop re-arms from a second place as well; so the rule is pinned here, where nothing else
     * re-arms. A queue of sixteen bytes and a client that sends forty-eight: the reader takes
     * sixteen, finds no room and disarms. The test then does what the loop does — hands everything
     * on, the queue back to zero under the lock — and the reader must stay put until it is
     * re-armed, and read the next sixteen when it is. */
    {
        int   sv[2];
        slot *s = slot_new();
        int   made = s != NULL && socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0 &&
                   fcntl(sv[0], F_SETFL, O_NONBLOCK) == 0;
        ok(made, "a client and a session with a queue of sixteen bytes");
        if (made) {
            ok(lc_reader_add(&s->st, sv[0], s->buf, 16u, &s->len, &s->off) == 0,
               "the session is handed to the reader");
            unsigned char said[48];
            for (unsigned i = 0; i < sizeof said; i++)
                said[i] = (unsigned char)i;
            (void)!write(sv[1], said, sizeof said);

            int full = 0;
            for (int i = 0; i < 200 && !full; i++) {
                (void)wait_wake(wake[0], 10);
                pthread_mutex_lock(&s->st.lock);
                full = s->len == 16u && s->st.full;
                pthread_mutex_unlock(&s->st.lock);
            }
            ok(full, "the reader fills the queue and stops");

            pthread_mutex_lock(&s->st.lock);
            s->off = s->len = 0;
            pthread_mutex_unlock(&s->st.lock);
            usleep(100000);
            pthread_mutex_lock(&s->st.lock);
            int stayed = s->len == 0u;
            pthread_mutex_unlock(&s->st.lock);
            ok(stayed, "room alone does not start it again");

            lc_reader_rearm(&s->st);
            int more = 0;
            for (int i = 0; i < 200 && !more; i++) {
                (void)wait_wake(wake[0], 10);
                pthread_mutex_lock(&s->st.lock);
                more = s->len == 16u && s->buf[0] == 16u && s->buf[15] == 31u;
                pthread_mutex_unlock(&s->st.lock);
            }
            ok(more, "lc_reader_rearm does, and the next sixteen bytes follow in order");

            lc_reader_del(&s->st);
            close(sv[0]);
            close(sv[1]);
            munmap(s, sizeof *s);
        }
    }

    /* The promise. Eight sessions at a time, and each one's client says something in the instant
     * before the session is removed — so that the reader wakes with an event for it in hand just as
     * lc_reader_del runs, which is the whole of the race. Every other round the clients have also
     * already gone, because an end of stream is what kept the reader busy with closing sessions on
     * the router. A reader that reached a removed stage faults above.
     *
     * ⚠️ THIS LOOP IS NOT THE CONTROL FOR THE WAIT, and the first version of this suite had nothing
     * else. Against the original reader it faults every run. But with the other half of the fix in
     * place — drain taking a finished descriptor out of the epoll — the race gets rare enough that
     * removing only the wait in lc_reader_del failed this loop once in five runs, with or without the
     * byte written just before each removal. The section after it is the control: it fails that
     * mutation every time. */
    enum { AT_ONCE = 8, ROUNDS = 4000 };
    int made_all = 1;
    for (int r = 0; r < ROUNDS && made_all; r++) {
        slot *s[AT_ONCE];
        int   fd[AT_ONCE], peer[AT_ONCE];
        for (int i = 0; i < AT_ONCE; i++) {
            int sv[2];
            s[i] = slot_new();
            if (s[i] == NULL || socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0 ||
                fcntl(sv[0], F_SETFL, O_NONBLOCK) != 0 ||
                lc_reader_add(&s[i]->st, sv[0], s[i]->buf, sizeof s[i]->buf, &s[i]->len,
                              &s[i]->off) != 0) {
                made_all = 0;
                break;
            }
            fd[i] = sv[0];
            peer[i] = sv[1];
            if (r % 2 == 1) {
                (void)!write(sv[1], "x", 1);
                close(sv[1]);
                peer[i] = -1;
            }
        }
        if (!made_all)
            break;
        for (int i = 0; i < AT_ONCE; i++) {
            if (peer[i] >= 0)
                (void)!write(peer[i], "x", 1);
            lc_reader_del(&s[i]->st);
            munmap(s[i], sizeof *s[i]);
            close(fd[i]);
            if (peer[i] >= 0)
                close(peer[i]);
        }
        unsigned char sink[256];
        while (read(wake[0], sink, sizeof sink) > 0) {
        }
    }
    ok(made_all, "thirty-two thousand sessions made, removed as their clients spoke or had gone");
    ok(1, "and none of them was touched by the reader after lc_reader_del returned");

    /* THE SAME RACE, MADE CERTAIN rather than likely, because the loop above catches a removal that
     * does not wait only now and then — the window is the few microseconds between epoll_wait
     * returning and drain taking a lock. Here the reader is stopped inside that window on purpose:
     * a helper holds the lock of the FIRST stage in its batch, so the reader sits in drain with
     * events for the others in hand, and the others are removed and unmapped right then. A removal
     * that does not wait for the batch returns at once and the reader faults the moment the helper
     * lets go; one that waits returns only after that, and nothing faults. */
    int staged_all = 1;
    for (int r = 0; r < 20 && staged_all; r++) {
        enum { OTHERS = 6 };
        slot *hold_y = slot_new(), *hold_x = slot_new(), *a[OTHERS];
        int   y[2], x[2], av[OTHERS][2];
        staged_all = hold_y != NULL && hold_x != NULL && socketpair(AF_UNIX, SOCK_STREAM, 0, y) == 0 &&
                     socketpair(AF_UNIX, SOCK_STREAM, 0, x) == 0 &&
                     fcntl(y[0], F_SETFL, O_NONBLOCK) == 0 && fcntl(x[0], F_SETFL, O_NONBLOCK) == 0 &&
                     lc_reader_add(&hold_y->st, y[0], hold_y->buf, sizeof hold_y->buf, &hold_y->len,
                                   &hold_y->off) == 0 &&
                     lc_reader_add(&hold_x->st, x[0], hold_x->buf, sizeof hold_x->buf, &hold_x->len,
                                   &hold_x->off) == 0;
        for (int i = 0; i < OTHERS && staged_all; i++) {
            a[i] = slot_new();
            staged_all = a[i] != NULL && socketpair(AF_UNIX, SOCK_STREAM, 0, av[i]) == 0 &&
                         fcntl(av[i][0], F_SETFL, O_NONBLOCK) == 0 &&
                         lc_reader_add(&a[i]->st, av[i][0], a[i]->buf, sizeof a[i]->buf,
                                       &a[i]->len, &a[i]->off) == 0;
        }
        if (!staged_all)
            break;

        holder h = { .y = &hold_y->st.lock, .x = &hold_x->st.lock };
        pthread_mutex_init(&h.m, NULL);
        pthread_cond_init(&h.cv, NULL);
        pthread_t ht;
        if (pthread_create(&ht, NULL, hold, &h) != 0) {
            staged_all = 0;
            break;
        }
        holder_wait(&h, 1);

        /* The reader into Y's lock, alone in its batch; then X and the others ready together behind
         * it, X first; then Y let go, so that the next batch is X and the others and stops at X. */
        (void)!write(y[1], "y", 1);
        usleep(2000);
        (void)!write(x[1], "x", 1);
        for (int i = 0; i < OTHERS; i++)
            (void)!write(av[i][1], "a", 1);
        holder_step(&h, 2);
        usleep(2000);

        for (int i = 0; i < OTHERS; i++) {
            lc_reader_del(&a[i]->st);
            munmap(a[i], sizeof *a[i]);
            close(av[i][0]);
            close(av[i][1]);
        }

        pthread_join(ht, NULL);
        pthread_mutex_destroy(&h.m);
        pthread_cond_destroy(&h.cv);
        lc_reader_del(&hold_x->st);
        lc_reader_del(&hold_y->st);
        munmap(hold_x, sizeof *hold_x);
        munmap(hold_y, sizeof *hold_y);
        close(x[0]);
        close(x[1]);
        close(y[0]);
        close(y[1]);
        unsigned char sink[256];
        while (read(wake[0], sink, sizeof sink) > 0) {
        }
    }
    ok(staged_all, "twenty times, a reader held inside a batch while the rest of it was removed");
    ok(1, "and it never reached what was removed");

    /* A reader with nothing to do is asleep in epoll_wait, and a removal waits for it to finish a
     * batch: it has to be woken for that, or the loop thread would wait for ever. Reaching this line
     * says it was, every time above; this says it once more with the reader idle for certain. */
    {
        int   sv[2];
        slot *s = slot_new();
        if (s != NULL && socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0 &&
            lc_reader_add(&s->st, sv[0], s->buf, sizeof s->buf, &s->len, &s->off) == 0) {
            usleep(50000);
            lc_reader_del(&s->st);
            ok(s->st.fd == -1, "a removal returns while the reader sleeps with nothing to read");
            close(sv[0]);
            close(sv[1]);
            munmap(s, sizeof *s);
        } else {
            ok(0, "a session for the idle removal");
        }
    }

    lc_reader_stop();
    ok(1, "the reader stops");

    printf("\n%s\n", failures == 0 ? "the reader keeps its promise" : "the reader does NOT keep its promise");
    return failures == 0 ? 0 : 1;
}
