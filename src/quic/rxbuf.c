#include "quic/rxbuf.h"

#include <stdlib.h>
#include <string.h>

int lc_qrx_open(lc_qrx *r)
{
    memset(r, 0, sizeof *r);
    r->buf = malloc(LC_QTCP_RX_MIN);
    if (r->buf == NULL)
        return -1;
    r->cap = LC_QTCP_RX_MIN;
    r->owns = 1;
    return 0;
}

void lc_qrx_borrow(lc_qrx *r, uint8_t *buf, size_t cap)
{
    memset(r, 0, sizeof *r);
    r->buf = buf;
    r->cap = cap;
}

void lc_qrx_close(lc_qrx *r)
{
    if (r->owns)
        free(r->buf);
    memset(r, 0, sizeof *r);
}

/* Doubling rather than fitting exactly, so that a stream receiving a megabyte in small pieces
 * reallocates a handful of times instead of a hundred; capped at the window, which is all the node
 * is ever allowed to have in flight on this stream.
 *
 * One refusal is possible, realloc's, and nothing asks the machine first — quic-go's frame queue
 * takes what the flow control allowed, and so does this (L1 is gone, 29.09). On a refusal the buffer
 * keeps the size it had and the run that would not fit is refused whole, which is `over`.
 * Growth is an improvement on a fixed allocation, never a requirement of it — but a run that cannot
 * be held is not something this layer can paper over, and lc_qrx_put says why.
 *
 * Returns LC_QRX_OVER_ALLOC when it said no, 0 otherwise. */
static int grow(lc_qrx *r, size_t need)
{
    size_t want = r->cap;
    while (want < need && want < LC_QTCP_STREAM_WINDOW)
        want *= 2u;
    if (want > LC_QTCP_STREAM_WINDOW)
        want = LC_QTCP_STREAM_WINDOW;
    if (want <= r->cap)
        return 0;

    uint8_t *bigger = realloc(r->buf, want);
    if (bigger == NULL)
        return LC_QRX_OVER_ALLOC;
    r->buf = bigger;
    r->cap = want;
    return 0;
}

void lc_qrx_put(lc_qrx *r, const uint8_t *data, size_t len)
{
    if (r->buf == NULL || len == 0)
        return;

    /* Grown here rather than taken at open: this is the moment the stream proves it needs the room,
     * and the only moment at which the machine's state is worth asking about. */
    int refused = 0;
    if (r->owns && r->len + len > r->cap && r->cap < LC_QTCP_STREAM_WINDOW)
        refused = grow(r, r->len + len);

    /* ALL OF IT OR NONE OF IT. This used to copy what fit and set `over` for the remainder, and the
     * remainder was then thrown away: the caller went on reading a byte stream with a hole in the
     * middle of it and no error anywhere. For TLS inside the tunnel that is a decrypt failure the
     * user reads as a broken site; for plain HTTP it is silently wrong content.
     *
     * The reference has no such branch to copy. quic-go pushes received stream data onto an
     * unbounded queue and lets flow control be the only limiter — `UpdateHighestReceived(...)` then
     * `frameQueue.Push(frame.Data, frame.Offset, frame.PutBack)`
     * (vendor/quic-go/receive_stream.go:449-467), both propagating errors — so there is no state in
     * which it accepts a STREAM frame,
     * counts it against the window, and then drops part of it. What we have and it does not is a
     * router that can run out of memory, so the case has to exist here; what it must not do is
     * pretend it did not happen.
     *
     * Refusing the whole run keeps the buffer a faithful prefix of the stream. The caller sees
     * `over` and ends the stream, so the hole is never delivered — see recv_stream_data_cb. */
    if (r->len + len > r->cap) {
        r->over = refused != 0 ? refused : LC_QRX_OVER_CEILING;
        return;
    }

    /* Room exists, but perhaps not at the tail: the read offset may have walked forward and left
     * the space behind it. Compact THEN, not on every take — this is the one place the remainder
     * has to move, and it moves at most once per fill instead of once per taken piece. */
    if (r->off + r->len + len > r->cap) {
        memmove(r->buf, r->buf + r->off, r->len);
        r->off = 0;
    }
    memcpy(r->buf + r->off + r->len, data, len);
    r->len += len;
}

void lc_qrx_take(lc_qrx *r, size_t n)
{
    if (n == 0 || n > r->len)
        return;

    /* Two integers. What is left does not move — see the note on `off` in rxbuf.h for what this
     * replaced and what it was costing. */
    r->off += n;
    r->len -= n;

    if (r->len == 0u)
        r->off = 0u;

    if (r->len > 0 || !r->owns || r->cap <= LC_QTCP_RX_MIN)
        return;

    /* Empty, and ours, and larger than the floor: give the room back.
     *
     * This is what keeps a promise of eight megabytes per stream from becoming an obligation of
     * eight megabytes TIMES the number of streams. Flow control bounds what is in the buffers at
     * one moment; nothing bounds what they were once grown to, because a buffer that has been
     * drained looks exactly like one that never filled. Held onto, capacity accumulates over
     * streams that were never large together, and the ceiling stops being the connection window and
     * becomes the machine.
     *
     * Released here rather than on a timer or at close, because empty is the only moment at which
     * this costs nothing: there is nothing to copy, so it is a free and a malloc of the floor and
     * no memmove at all. A stream that is genuinely fast is not empty — the next arrival is already
     * waiting when we take — so it keeps what it has grown and does not thrash. A stream that has
     * gone quiet gives it back, which is what it should do.
     *
     * A refusal here is nothing: failing to shrink leaves a buffer that is merely larger than
     * needed, which is the condition this is improving, so the old one is kept and the next empty
     * tries again. */
    uint8_t *smaller = malloc(LC_QTCP_RX_MIN);
    if (smaller == NULL)
        return;
    free(r->buf);
    r->buf = smaller;
    r->cap = LC_QTCP_RX_MIN;
}
