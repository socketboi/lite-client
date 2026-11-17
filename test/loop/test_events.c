/* What an event and a read result mean, checked without a socket.
 *
 * These two decisions used to live inside the event loop, where the only way to exercise them was a
 * real peer misbehaving at exactly the right moment. One of them was wrong: an error was acted on
 * before reading, so a server that answered and then reset had its answer thrown away — data lost
 * with no error reported anywhere, on the commonest abrupt close there is.
 *
 * The rule below is the fix, stated once and checked here: the flags are informative, the syscall
 * is the truth. */

#include "net/loop.h"

#include <errno.h>
#include <stdio.h>

static int failures;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

int main(void)
{
    printf("\nevent and read semantics\n");

    /* The case that was wrong: data and an error arriving together. */
    ok(lc_ev_should_read(LC_EV_READ | LC_EV_ERROR),
       "an error alongside readable data does not stop the read");
    ok(lc_ev_should_read(LC_EV_READ), "nor does its absence");
    ok(!lc_ev_should_read(LC_EV_ERROR), "an error with nothing to read is not a read");
    ok(!lc_ev_should_read(LC_EV_WRITE), "and neither is writability");

    ok(lc_read_classify(64, 0) == LC_READ_DATA, "a positive return is data");
    ok(lc_read_classify(0, 0) == LC_READ_EOF, "zero is the peer having finished writing");
    ok(lc_read_classify(-1, EAGAIN) == LC_READ_RETRY, "EAGAIN is not a failure");
    ok(lc_read_classify(-1, EINTR) == LC_READ_RETRY, "nor is a signal");
    ok(lc_read_classify(-1, ECONNRESET) == LC_READ_DEAD, "a reset is");
    ok(lc_read_classify(-1, EBADF) == LC_READ_DEAD, "and so is anything else");

    /* The composite, which is what the loop actually asks. */
    ok(!lc_ev_finished(LC_EV_READ | LC_EV_ERROR, LC_READ_DATA),
       "data with an error pending is delivered, not discarded");
    ok(lc_ev_finished(LC_EV_READ | LC_EV_ERROR, LC_READ_DEAD),
       "and the reset that follows it ends the session");
    ok(lc_ev_finished(LC_EV_READ, LC_READ_EOF), "an end of stream ends it");
    ok(!lc_ev_finished(LC_EV_READ, LC_READ_RETRY), "nothing to read right now is not the end");

    /* The anti-spin rule. Level-triggered epoll reports an error whether or not it was asked for,
     * so treating "nothing right now, but the descriptor is in error" as "come back later" is a
     * wake-up with nothing to do in it, repeated as fast as the processor allows — the same shape
     * as the descriptor-exhaustion spin, in a different place. */
    ok(lc_ev_finished(LC_EV_READ | LC_EV_ERROR, LC_READ_RETRY),
       "but nothing to read WITH an error pending is, or the loop spins forever");

    printf("\n%s\n", failures == 0 ? "the semantics hold" : "the semantics are WRONG");
    return failures == 0 ? 0 : 1;
}
