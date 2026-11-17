/* The one place that turns a message into bytes on a descriptor, and the arithmetic in it.
 *
 * ⚠️ THIS SUITE EXISTS BECAUSE CENTRALISING WITHOUT TESTING JUST CONCENTRATES THE RISK. The clamp in
 * lc_vsay was written three times in one day, in three files, in two different shapes — all correct,
 * each needing its own reading to know that. Pulling them into one function is only an improvement
 * if that one function is pinned; otherwise it is the same danger with fewer eyes on it, and the
 * danger is specific: a clamp that is wrong here is a write past the end of a stack buffer.
 *
 * ⚠️ AND "ONE write() PER LINE" IS CHECKED AS SUCH, not inferred from the bytes. A pipe shows the
 * same stream whether it arrived in one write or five, which is exactly how the fault this was
 * written for stayed invisible — the tunnel's log looked correct everywhere except where it mattered.
 * A datagram socket keeps the boundaries: one write is one datagram, so counting datagrams counts
 * writes, and this can assert what no reading of a pipe ever could. */

#include "core/say.h"

#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int failures;

static void expect(int cond, const char *what)
{
    printf(cond ? "  ok    %s\n" : "  FAIL  %s\n", what);
    if (!cond)
        failures++;
}

/* Runs `fn` with a datagram socket as its descriptor and reports what arrived: the bytes of the
 * first message, its length, and how many messages there were in all. */
static void capture(void (*fn)(int fd), unsigned char *buf, size_t cap, size_t *len, int *messages)
{
    int sv[2];
    *len = 0;
    *messages = -1;
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0)
        return;

    *messages = 0;
    fn(sv[1]);
    close(sv[1]);

    for (;;) {
        struct pollfd p;
        p.fd = sv[0];
        p.events = POLLIN;
        p.revents = 0;
        if (poll(&p, 1, 500) != 1)
            break;

        static unsigned char one[LC_SAY_MAX * 4u];
        ssize_t              got = recv(sv[0], one, sizeof one, 0);
        if (got <= 0)
            break;
        if (*messages == 0) {
            *len = (size_t)got < cap ? (size_t)got : cap;
            memcpy(buf, one, *len);
        }
        (*messages)++;
    }
    close(sv[0]);
}

/* The shape a caller with its own va_list has — a logging callback, or note() with its stamp. */
static void say_with_prefix(int fd, const char *prefix, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    lc_vsay(fd, prefix, fmt, ap);
    va_end(ap);
}

static void case_short(int fd)
{
    lc_say(fd, "answer %d for %s", 42, "everything");
}

static void case_prefix(int fd)
{
    say_with_prefix(fd, "[w1 12.345] ", "opened %s:%u", "example.com", 443u);
}

/* A body far longer than the buffer, so the cut is forced. */
static void case_long_body(int fd)
{
    static char big[LC_SAY_MAX * 3u];
    memset(big, 'A', sizeof big - 1u);
    big[sizeof big - 1u] = '\0';
    lc_say(fd, "%s", big);
}

/* A prefix that on its own is longer than the buffer. Nothing may run past the end even when the
 * caller's own text never gets the room to be formatted at all. */
static void case_long_prefix(int fd)
{
    static char big[LC_SAY_MAX * 2u];
    memset(big, 'P', sizeof big - 1u);
    big[sizeof big - 1u] = '\0';
    say_with_prefix(fd, big, "%s", "tail");
}

/* Two calls, to show the boundary is per call rather than per buffer-full. */
static void case_two(int fd)
{
    lc_say(fd, "first");
    lc_say(fd, "second");
}

int main(void)
{
    printf("\none line, built whole, out in one write\n");

    unsigned char buf[LC_SAY_MAX * 2u];
    size_t        len = 0;
    int           messages = 0;

    capture(case_short, buf, sizeof buf, &len, &messages);
    if (messages < 0) {
        expect(0, "a datagram socket to say things down");
        return 1;
    }
    expect(messages == 1,
           "one call is one write, which a datagram socket proves and a pipe cannot");
    expect(len == strlen("answer 42 for everything\n") &&
               memcmp(buf, "answer 42 for everything\n", len) == 0,
           "and the bytes are the message, a newline, and nothing else");

    capture(case_prefix, buf, sizeof buf, &len, &messages);
    expect(messages == 1 && len == strlen("[w1 12.345] opened example.com:443\n") &&
               memcmp(buf, "[w1 12.345] opened example.com:443\n", len) == 0,
           "a prefix goes in front of the message and shares its single write");

    capture(case_long_body, buf, sizeof buf, &len, &messages);
    expect(messages == 1, "a message too long for the buffer is still ONE write");
    expect(len == LC_SAY_MAX, "cut to the buffer exactly, not to some byte near it");
    expect(len >= 4 && memcmp(buf + len - 4, "...\n", 4) == 0,
           "and it SAYS it was cut, because a sentence that stops early reads like one that ended");

    capture(case_long_prefix, buf, sizeof buf, &len, &messages);
    expect(messages == 1 && len == LC_SAY_MAX,
           "a prefix longer than the buffer is clamped rather than trusted");
    expect(len >= 4 && memcmp(buf + len - 4, "...\n", 4) == 0,
           "and that case is marked as cut too");

    capture(case_two, buf, sizeof buf, &len, &messages);
    expect(messages == 2, "two calls are two writes, never one merged with the next");

    printf("\n%s\n", failures == 0 ? "all ok" : "FAILURES");
    return failures == 0 ? 0 : 1;
}
