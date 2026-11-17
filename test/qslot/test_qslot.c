/* The stream table of src/quic/conn.c, and the one thing about it no other suite reaches: that a
 * handle made for a slot finds that slot again — after the slot has been released and taken by the
 * next stream too.
 *
 * WHY IT EXISTS. On 2026-09-27 the table went from one array to chunks, a slot learnt its own index,
 * and slot_release wiped the index with the rest. Every reused slot then called itself slot 0, its
 * handle named a control stream, and the second connection through the tunnel ended before a byte
 * moved. `make check` was green; only test/hystand's twenty short connections said so. This asks
 * the same question without a node. */

#include <poll.h>
static int qslot_poll(struct pollfd *fds, nfds_t count, int timeout);
#define poll qslot_poll
#include "quic/conn.c"
#undef poll

#include <stdio.h>
#include <fcntl.h>

static int failures;
static int poll_error;
static int qslot_poll(struct pollfd *fds, nfds_t count, int timeout)
{
    if (poll_error) { errno = poll_error; return -1; }
    return poll(fds, count, timeout);
}

static void ok(int cond, const char *what)
{
    printf("  %s  %s\n", cond ? "ok  " : "FAIL", what);
    if (!cond)
        failures++;
}

static void failed_poll_preserves_cause_and_wake(void)
{
    int pipes[2];
    if (pipe(pipes) != 0) { ok(0, "poll-error pipe created"); return; }
    int flags = fcntl(pipes[0], F_GETFL);
    if (flags < 0 || fcntl(pipes[0], F_SETFL, flags | O_NONBLOCK) != 0) {
        ok(0, "poll-error pipe is nonblocking"); close(pipes[0]); close(pipes[1]); return;
    }
    const int errors[] = {EINTR, ENOMEM};
    for (unsigned i = 0; i < sizeof errors / sizeof errors[0]; i++) {
        lc_qconn connection;
        memset(&connection, 0, sizeof connection);
        connection.fd = connection.prev_fd = -1;
        connection.sq.started = 1;
        connection.sq.wake_rd = pipes[0];
        uint8_t byte = 42, received = 0;
        ok(write(pipes[1], &byte, 1) == 1, "queue wake is pending before failed poll");
        poll_error = errors[i];
        int rc = lc_qconn_step(&connection, 0);
        poll_error = 0;
        ok(rc == (errors[i] == EINTR ? 1 : -1), "poll interruption and terminal failure remain distinct");
        if (errors[i] != EINTR)
            ok(strstr(connection.err, strerror(errors[i])) != NULL, "poll diagnostic preserves the original failure");
        ok(read(pipes[0], &received, 1) == 1 && received == byte, "failed poll does not consume a queue wake");
    }
    close(pipes[0]); close(pipes[1]);
}

int main(void)
{
    failed_poll_preserves_cause_and_wake();
    static lc_qconn c;
    lc_qstream     *s[80];
    unsigned        i;
    int             found = 1;

    printf("the stream table: a handle finds its slot, reused or not\n");

    /* More than one chunk's worth, so that a slot past the first chunk is reused too. */
    for (i = 0; i < 80u; i++) {
        s[i] = slot_take(&c);
        if (s[i] == NULL)
            break;
        s[i]->state = LC_QSLOT_OPEN;
        found &= by_handle(&c, HANDLE_OF(&c, s[i])) == s[i];
    }
    ok(i == 80u && found, "eighty fresh slots, each found by its own handle");

    slot_release(s[3]);
    slot_release(s[70]);
    lc_qstream *a = slot_take(&c);
    a->state = LC_QSLOT_OPEN;
    lc_qstream *b = slot_take(&c);
    b->state = LC_QSLOT_OPEN;
    ok(a == s[3] && b == s[70], "released slots are taken again, first free first");
    ok(by_handle(&c, HANDLE_OF(&c, a)) == a && by_handle(&c, HANDLE_OF(&c, b)) == b,
       "and each reused slot is found by the handle made for it");
    ok(a->idx == 3u && b->idx == 70u, "because a slot keeps its index through the release");

    for (i = 0; i < LC_QSTREAM_CHUNKS; i++)
        free(c.st_chunk[i]);

    printf("\n%s\n", failures == 0 ? "all good" : "THE STREAM TABLE IS WRONG");
    return failures == 0 ? 0 : 1;
}
