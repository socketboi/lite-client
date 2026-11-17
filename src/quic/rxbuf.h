/* One stream's receive buffer, and the promise it has to be able to keep.
 *
 * A receive window is not a preference. Advertising eight megabytes on a stream tells the node it
 * may send that much before we acknowledge any of it, and the node is entitled to do exactly that.
 * If the bytes arrive and there is nowhere to put them they are not delayed, they are LOST — and a
 * QUIC stream has no way to un-receive them, so the connection ends. The window and what this
 * buffer can grow to are therefore the same number by necessity, not by choice; see
 * LC_QTCP_STREAM_WINDOW in quic/params.h.
 *
 * Which raises the question this file exists to answer: what stops a thousand connections —
 * a stock node's MAX_STREAMS, now that the stream table no longer stops at 256 — from each holding
 * eight megabytes?
 *
 * Two things, and only the second one is here.
 *
 * The first is flow control, and it works because the window is returned by TAKING, not by
 * receiving. lc_qconn_tcp_take is what calls ngtcp2_conn_extend_max_offset, so a stream whose
 * local end has stalled stops being read, stops extending, and the node stops sending to it. What
 * has arrived and is not yet taken can never exceed the window on one stream, nor
 * LC_QTCP_CONN_WINDOW across all of them at once. That is a bound on bytes IN the buffers.
 *
 * It is not a bound on the buffers. A stream that received a megabyte, was drained, and now holds
 * nothing still owns the megabyte it was given — capacity is not the same thing as content, and
 * growth that is never given back accumulates across streams that were never large at the same
 * moment. Two hundred and fifty-six of those is two gigabytes of obligation on a machine with a
 * hundred and eighteen megabytes, arrived at without any single rule being broken. That is why
 * lc_qrx_take gives the room back the moment the buffer is empty: capacity is retained exactly
 * while it is being used, and the sum across every stream is then bounded by what the node is
 * allowed to have in flight, plus one floor per stream.
 *
 * Separate from conn.c for the reason txbuf.c is separate: this is arithmetic on a struct, and a
 * struct can be asked questions without the whole vendored QUIC stack. test/qrx asks. */

#ifndef LC_QRXBUF_H
#define LC_QRXBUF_H

#include "quic/params.h"

#include <stddef.h>
#include <stdint.h>

/* What a stream costs before it has proved it needs more, and what it goes back to when it has
 * stopped proving it. Sized so that the great majority of a browser's connections — a redirect, a
 * small JSON answer, a cached 304 — never grow at all. */
#define LC_QTCP_RX_MIN (8u * 1024u)

typedef struct {
    uint8_t *buf;
    size_t   cap, len;
    /* Where the unread bytes START, so that taking them does not have to move what is left.
     *
     * ⚠️ THIS FIELD IS A MEASURED FIX AND ITS ABSENCE COST MORE THAN THE WINDOW EVER BOUGHT.
     * lc_qrx_take used to do `memmove(buf, buf + n, len)` on every call — the whole remainder
     * shifted to the front each time a caller took a piece. A caller takes what its onward queue
     * has room for, which on the tunnel is LAN_QUEUE_SIZE, about 19 KB; so draining a buffer
     * holding half a megabyte cost twenty-six takes, each moving what was left, and roughly
     * thirteen bytes copied for every byte delivered. Quadratic in what the buffer holds, and the
     * bigger the window the worse it got — which is why raising the window from 1 MiB to 2, 4 and
     * finally the reference's 8 MiB bought NOTHING and then went backwards: measured on an AX3000T,
     * 8 MiB gave 49-67 Mbit/s at 64 % of a core where 1 MiB gave 70-82 at 42 %. More promise, more
     * memmove, less throughput and more heat.
     *
     * With an offset a take is two integer updates. The remainder moves at most once per fill
     * rather than once per take, and only when the tail has no room left. */
    size_t off;
    /* Whether this buffer is ours to resize. The authentication exchange lends the connection's own
     * fixed array instead, and a lent buffer must be neither grown nor freed. */
    int owns;
    /* Bytes arrived that did not fit. The node was entitled to send them, so this is not a dropped
     * packet to be retried — it is a connection that no longer carries what it thinks it does, and
     * the caller ends it. Nonzero is the whole question for most readers; the value says what
     * refused the room (LC_QRX_OVER_*), which is the question the line reporting it has to answer. */
    int over;
} lc_qrx;

/* What `over` holds. realloc said no, or the buffer is already as large as it may be — the lent one,
 * or a stream at LC_QTCP_STREAM_WINDOW. */
enum { LC_QRX_OVER_ALLOC = 1, LC_QRX_OVER_CEILING = 2 };

/* Allocates the floor. Returns 0, or -1 with the buffer left empty and unusable. */
int lc_qrx_open(lc_qrx *r);

/* Lends `buf` instead: never grown, never freed, never returned to the floor. */
void lc_qrx_borrow(lc_qrx *r, uint8_t *buf, size_t cap);

void lc_qrx_close(lc_qrx *r);

/* Appends what fits, growing towards LC_QTCP_STREAM_WINDOW if the machine allows it. Anything that
 * still does not fit sets `over`. */
void lc_qrx_put(lc_qrx *r, const uint8_t *data, size_t len);

/* Consumes `n` bytes from the front. An emptied buffer gives its room back — that release is the
 * whole reason a stream may promise eight megabytes on a router. */
void lc_qrx_take(lc_qrx *r, size_t n);

#endif
