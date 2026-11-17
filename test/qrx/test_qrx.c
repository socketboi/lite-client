/* The receive buffer, and the one rule that makes an eight-megabyte promise affordable.
 *
 * The window this client advertises is the reference client's — eight megabytes on a stream, twenty
 * across the connection — and a window is not a preference: the node may send that much before we
 * acknowledge any of it, so the buffer has to be able to reach the window or the connection dies on
 * bytes it invited. Two hundred and fifty-six streams times eight megabytes is two gigabytes on a
 * machine with a hundred and eighteen, and no rule anywhere has to be broken to get there — it is
 * enough that streams take turns being large and never give anything back.
 *
 * So the assertions below are about giving it back, and the shape of them matters. Emptying is the
 * release, not closing and not a timer: a stream that has drained has proved nothing about the next
 * burst, and one that has NOT drained is exactly the stream whose room is in use. A test that only
 * checked "grows when fed" would pass on the version that keeps every byte of capacity it ever
 * touched, which is the version this is about. */

#include "quic/rxbuf.c"

#include <stdio.h>
#include <string.h>

static int failures;

static void expect(int cond, const char *what)
{
    if (cond) {
        printf("  ok    %s\n", what);
        return;
    }
    printf("  FAIL  %s\n", what);
    failures++;
}

static uint8_t junk[LC_QTCP_RX_MIN * 40];

static void fill(void)
{
    for (size_t i = 0; i < sizeof junk; i++)
        junk[i] = (uint8_t)(i * 31u + 7u);
}

int main(void)
{
    fill();
    printf("the receive buffer\n");

    lc_qrx r;
    expect(lc_qrx_open(&r) == 0, "opens at the floor and no larger");
    expect(r.cap == LC_QTCP_RX_MIN && r.len == 0, "with nothing in it");

    lc_qrx_put(&r, junk, 100);
    expect(r.len == 100 && r.cap == LC_QTCP_RX_MIN, "a hundred bytes fit without growing anything");
    expect(memcmp(r.buf, junk, 100) == 0, "and are the bytes that were put there");
    expect(!r.over, "nothing was lost");

    /* More than the floor: it has to grow, because the window said these could arrive. */
    lc_qrx_put(&r, junk, LC_QTCP_RX_MIN * 3);
    expect(!r.over, "three floors' worth arrives whole, because growth is what the window promised");
    expect(r.len == 100 + LC_QTCP_RX_MIN * 3, "all of it is held");
    expect(r.cap >= r.len, "in a buffer at least that large");
    size_t grown = r.cap;
    expect(grown > LC_QTCP_RX_MIN, "which is larger than the floor it started at");
    expect(memcmp(r.buf + 100, junk, LC_QTCP_RX_MIN * 3) == 0, "and the bytes are in order");

    /* Draining part of it is not draining it. This is the case that separates "release when empty"
     * from "release whenever the buffer looks calm": a stream in the middle of a burst is the one
     * whose room is being used, and taking it away would mean growing again on the next packet. */
    lc_qrx_take(&r, 100);
    expect(r.len == LC_QTCP_RX_MIN * 3, "taking the first hundred leaves the rest");
    expect(memcmp(r.buf + r.off, junk, LC_QTCP_RX_MIN * 3) == 0,
           "in order, starting at the read offset");

    /* ⚠️ THIS ASSERTION USED TO SAY THE OPPOSITE, and what it pinned was a quadratic drain.
     *
     * It read `memcmp(r.buf, junk, ...)` — "moved to the front, in order" — which was true only
     * because lc_qrx_take memmoved the whole remainder on every call. A caller takes what its
     * onward queue has room for (about 19 KB on the tunnel), so a buffer holding half a megabyte
     * was copied about thirteen times over to deliver itself once, and the cost grew with the
     * window: measured on an AX3000T, the reference's own 8 MiB window gave 49-67 Mbit/s at 64 % of
     * a core where 1 MiB gave 70-82 at 42 %. Raising the window made the client SLOWER, which is
     * how the memmove was found at all.
     *
     * So the test now requires the remainder NOT to move. Written as an assertion about `off`
     * rather than only about the bytes, because "the bytes are in order" stays true under the old
     * behaviour too — it is the absence of the copy that is the fix. */
    expect(r.off == 100, "and the remainder did not move: a take is two integers, not a memmove");
    expect(r.cap == grown, "and a buffer that still holds bytes keeps its room");

    /* And emptying it is. */
    lc_qrx_take(&r, r.len);
    expect(r.len == 0, "taking the rest empties it");
    expect(r.cap == LC_QTCP_RX_MIN,
           "and an empty buffer gives its room back, which is what bounds two hundred of these");

    /* Having given it back, it grows again on demand: the release is not a cap. */
    lc_qrx_put(&r, junk, LC_QTCP_RX_MIN * 2);
    expect(!r.over && r.len == LC_QTCP_RX_MIN * 2, "and grows again when the next burst arrives");
    lc_qrx_take(&r, r.len);
    expect(r.cap == LC_QTCP_RX_MIN, "and gives it back again");

    /* Taking more than is there is a caller error, and doing nothing is the safe answer: the
     * alternative is a length that has gone below zero and a memmove of it. */
    lc_qrx_put(&r, junk, 10);
    lc_qrx_take(&r, 11);
    expect(r.len == 10, "taking more than is held does nothing at all");
    lc_qrx_take(&r, 0);
    expect(r.len == 10, "and taking nothing is not an accident either");
    lc_qrx_take(&r, 10);

    lc_qrx_close(&r);
    expect(r.buf == NULL && r.cap == 0, "closing leaves nothing behind");

    printf("\na lent buffer\n");

    /* The authentication exchange lends the connection's own array. It must never be grown — that
     * would realloc memory this module did not allocate — and never freed. What does not fit is
     * `over`, and for that exchange `over` is how a node that refuses the password is recognised:
     * it answers with the web page it masquerades as, which is tens of kilobytes. */
    uint8_t lent[64];
    lc_qrx_borrow(&r, lent, sizeof lent);
    expect(r.buf == lent && r.cap == sizeof lent && !r.owns, "is the array it was given");

    /* A RUN THAT DOES NOT FIT IS REFUSED WHOLE, and this used to be the opposite: it filled to the
     * brim, set `over`, and the remainder was thrown away — leaving the caller a byte stream with a
     * hole in it and no error on the path that reads it. Whatever is held has to be a faithful
     * PREFIX of the stream, so that ending it is the only thing left to get wrong. */
    lc_qrx_put(&r, junk, 200);
    expect(r.len == 0, "a run larger than the buffer is not taken in part");
    expect(r.over, "and says so, which is what ends the stream");
    expect(r.over == LC_QRX_OVER_CEILING,
           "naming the ceiling as what refused it: a lent buffer is never grown, so neither the reserve nor realloc was asked");
    expect(r.buf == lent, "without having moved anywhere");

    /* And a smaller one still goes in: `over` is about the run that would not fit, not a latch that
     * makes the buffer useless. Reset first, because the reader of `over` ends the stream on it. */
    r.over = 0;
    lc_qrx_put(&r, junk, sizeof lent);
    expect(r.len == sizeof lent && !r.over, "exactly filling it is not overflowing it");
    lc_qrx_put(&r, junk, 1);
    expect(r.len == sizeof lent && r.over, "and one byte past a full buffer is refused, not wrapped");

    lc_qrx_take(&r, r.len);
    expect(r.buf == lent && r.cap == sizeof lent,
           "and emptying a lent buffer returns nothing, because the room is not ours to return");

    lc_qrx_close(&r);
    expect(r.buf == NULL, "closing a lent buffer forgets it rather than freeing it");

    printf("\n%s\n", failures == 0 ? "all good" : "SOMETHING IS WRONG");
    return failures == 0 ? 0 : 1;
}
