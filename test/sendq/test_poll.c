/* Deterministic wait failures, without a real socket or scheduling sleeps. */
#include "quic/sendq.h"
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

static int injected_poll(struct pollfd *fds, nfds_t count, int timeout);
static ssize_t injected_sendmsg(int fd, const struct msghdr *msg, int flags);
#define poll injected_poll
#define sendmsg injected_sendmsg
#include "../../src/quic/sendq.c"
#undef poll
#undef sendmsg

static int wait_error, send_calls, poll_calls, failures;
static int injected_poll(struct pollfd *fds, nfds_t count, int timeout)
{
    if (count != 1u || fds[0].fd != 73 || timeout != LC_SENDQ_POLL_MS) {
        failures++;
        errno = EINVAL;
        return -1;
    }
    poll_calls++;
    if (wait_error == 0)
        return 0;
    errno = wait_error;
    return -1;
}
static ssize_t injected_sendmsg(int fd, const struct msghdr *msg, int flags)
{
    (void)flags;
    if (fd != 73 || msg->msg_iovlen != 1u || msg->msg_iov[0].iov_len != 1u)
        failures++;
    send_calls++;
    if (send_calls == 1) {
        errno = EAGAIN;
        return -1;
    }
    if (wait_error != 0 && wait_error != EINTR) {
        /* Bound the broken implementation instead of hanging the fixture. */
        errno = EIO;
        return -1;
    }
    return 1;
}
static void check(int error, int stopping)
{
    wait_error = error;
    send_calls = poll_calls = 0;
    lc_sendq q;
    memset(&q, 0, sizeof q);
    if (pthread_mutex_init(&q.lock, NULL) != 0) { failures++; return; }
    q.stop = stopping;
    lc_sendq_dest destination;
    memset(&destination, 0, sizeof destination);
    destination.fd = 73;
    destination.family = AF_UNIX;
    uint8_t byte = 42;
    int actual_error = 0;
    int result = send_one(&q, &destination, &byte, 1u, 0u, 0u, &actual_error);
    int fatal = error != 0 && error != EINTR;
    int expected_error = fatal ? error : stopping && error == 0 ? ETIMEDOUT : 0;
    int expected_sends = expected_error ? 1 : 2;
    int correct = poll_calls == 1 && send_calls == expected_sends &&
                  actual_error == expected_error && result == (expected_error ? -1 : 0);
    printf("  %s poll errno=%d stopping=%d result=%d error=%d sends=%d\n",
           correct ? "ok" : "FAIL", error, stopping, result, actual_error, send_calls);
    if (!correct) failures++;
    pthread_mutex_destroy(&q.lock);
}
int main(void)
{
    check(ENOMEM, 0);
    check(EINVAL, 0);
    check(EBADF, 1);
    check(EINTR, 0);
    check(0, 0);
    check(0, 1);
    return failures ? 1 : 0;
}
