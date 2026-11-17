/* One listener shared by several workers, each waiting on it with LC_EV_EXCLUSIVE: a connection goes
 * to a worker that is WAITING — an idle one — and wakes no one else.
 *
 * WHY THIS EXISTS. lc-tunnel's workers used to hold a listener each, grouped by SO_REUSEPORT, and the
 * kernel hashed every connection to one of them regardless of how busy it was. Measured on the
 * MT7621 (2026-09-24, four workers): two downloads opened together landed in the same worker 4 times
 * in 20, and that worker then carried both on one core while three sat idle — 26-28 Mbit/s where two
 * workers gave 45-48. The reference has no such lottery: Go runs each connection's goroutine on
 * whichever processor is free. Sharing the listener and waking one WAITING worker is the same rule
 * in processes: a worker busy with a connection is not waiting, so the next one goes elsewhere.
 *
 * The flag is also what keeps the shared listener from being the thundering herd the per-worker
 * sockets were introduced to avoid: without it every idle worker wakes for every connection, and all
 * but one find nothing.
 *
 * HOW. Three children, one loop each, the same non-blocking listener added with LC_EV_EXCLUSIVE. A
 * child that accepts writes its number down the connection and then stays busy for a while, as a
 * worker carrying a download does. Three connections arrive a little apart: each must reach a
 * different child, and no child may be woken for a connection it then fails to accept. */

#include "net/loop.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHILDREN 3
#define BUSY_MS 400
#define APART_MS 40

static int failures;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

static void sleep_ms(long ms)
{
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
    }
}

/* A child: waits on the shared listener, accepts, answers with its number, stays busy. Exits with
 * the number of wakeups that found nothing to accept. */
static int child(int listen_fd, unsigned char id)
{
    lc_loop *loop = lc_loop_new(4);
    if (loop == NULL || lc_loop_add(loop, listen_fd, LC_EV_READ | LC_EV_EXCLUSIVE, NULL) != 0)
        return 100;
    int empty = 0;
    for (;;) {
        lc_event ev[4];
        int      n = lc_loop_wait(loop, ev, 4, 1500);
        if (n <= 0)
            break; /* quiet for a while: the test is over */
        int c = accept(listen_fd, NULL, NULL);
        if (c < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                empty++;
            continue;
        }
        if (write(c, &id, 1) != 1) {
            /* the parent sees a missing number and says so */
        }
        close(c);
        sleep_ms(BUSY_MS);
    }
    lc_loop_free(loop);
    return empty;
}

int main(void)
{
    printf("\none listener shared by workers, one waiting worker woken per connection\n");

    int l = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t al = sizeof a;
    if (l < 0 || bind(l, (struct sockaddr *)&a, sizeof a) != 0 || listen(l, 16) != 0 ||
        getsockname(l, (struct sockaddr *)&a, &al) != 0) {
        ok(0, "a listener on the loopback");
        return 1;
    }

    pid_t kids[CHILDREN];
    for (int i = 0; i < CHILDREN; i++) {
        kids[i] = fork();
        if (kids[i] == 0)
            _exit(child(l, (unsigned char)('A' + i)));
    }
    close(l);
    sleep_ms(200); /* every child in its wait before the first connection */

    unsigned char got[CHILDREN] = { 0 };
    for (int i = 0; i < CHILDREN; i++) {
        int c = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (c >= 0 && connect(c, (struct sockaddr *)&a, sizeof a) == 0) {
            struct timeval tv = { 2, 0 };
            (void)setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            if (read(c, &got[i], 1) != 1)
                got[i] = '?';
        }
        if (c >= 0)
            close(c);
        sleep_ms(APART_MS);
    }

    int empty = 0, crashed = 0;
    for (int i = 0; i < CHILDREN; i++) {
        int st = 0;
        if (waitpid(kids[i], &st, 0) != kids[i] || !WIFEXITED(st) || WEXITSTATUS(st) >= 100)
            crashed++;
        else
            empty += WEXITSTATUS(st);
    }

    char seen[CHILDREN + 1];
    memcpy(seen, got, CHILDREN);
    seen[CHILDREN] = '\0';
    int distinct = got[0] != got[1] && got[0] != got[2] && got[1] != got[2] && got[0] >= 'A' &&
                   got[1] >= 'A' && got[2] >= 'A';
    char what[160];
    snprintf(what, sizeof what,
             "three connections %d ms apart went to three different workers (%s), none to a busy one",
             APART_MS, seen);
    ok(distinct, what);
    snprintf(what, sizeof what, "no worker was woken for a connection it could not accept (%d were)",
             empty);
    ok(empty == 0, what);
    ok(crashed == 0, "every worker could register the listener exclusively and ended cleanly");

    printf("\n%s\n", failures == 0 ? "shared listener: one idle worker per connection" : "FAILED");
    return failures == 0 ? 0 : 1;
}
