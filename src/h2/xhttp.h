/* XHTTP in its stream-one shape: one HTTP/2 request that is the whole tunnel.
 *
 * The request body carries what the client sends and the response body carries what comes back, so
 * a proxied connection is one POST that never finishes. Xray picks this shape by itself whenever
 * the transport sits on REALITY, which is the only way this client would use it.
 *
 * Everything here was measured against the reference rather than read off the RFC — the stand in
 * build/xhttp, with GODEBUG=http2debug=2 on Xray's own client. Three details would have been wrong
 * otherwise, and each would have produced a working tunnel that no other client resembles:
 *
 *   - the padding is not a header of its own. It is a whole URL in `referer`, with the padding in
 *     its query string, which is the most ordinary-looking thing on the request;
 *   - the path carries a trailing slash the configuration does not mention;
 *   - HEADERS does not end the stream. The request body is the upload channel, so the stream stays
 *     open for as long as the connection does. */
#ifndef LC_XHTTP_H
#define LC_XHTTP_H

#include <stddef.h>
#include <stdint.h>

/* What the reference announces, and therefore what this does. They are not tuning: they are the
 * numbers on the wire, and a client that announced its own would be answering a question no other
 * client answers that way.
 *
 * Both come from `setConfigDefaults` (vendor/x-net/http2/config.go:100), each from its own
 * `if server { … } else { … }` — the connection credit from the first:
 *
 *     104     if server {
 *     105         setDefault(&conf.MaxUploadBufferPerConnection, initialWindowSize, math.MaxInt32, 1<<20)
 *     106     } else {
 *     107         setDefault(&conf.MaxUploadBufferPerConnection, initialWindowSize, math.MaxInt32,
 *     107                    transportDefaultConnFlow)          // = 1 << 30 (vendor/x-net/http2/transport.go:44)
 *     108     }
 *
 * ⚠️ WE ARE THE CLIENT, SO THE BRANCH IS `else`. On 2026-08-19 the connection credit was changed
 * from a gigabyte to a megabyte, citing line 105 — and 105 is the SERVER. To the transport the two
 * are indistinguishable (neither ever becomes the binding limit) and to anyone reading the first
 * three frames of a connection they are completely distinguishable — which is precisely where a
 * client is identified. So the change improved nothing and put a number on the wire that no real
 * client of this library writes.
 *
 * Caught by the sieve, in the run where one finding out of ninety-eight was real, and it turned out
 * to be our own, from the day before.
 *
 * The stream credit comes from the second `if server { … } else { … }`
 * (vendor/x-net/http2/config.go:109-113), right below the first, and again from its `else` — line
 * 112, `transportDefaultStreamFlow`, which is `4 << 20` (vendor/x-net/http2/transport.go:49). That
 * one was right the whole time. */
#define LC_XHTTP_STREAM_WINDOW 4194304u
#define LC_XHTTP_CONN_CREDIT 1073741824u

/* The padding range Xray draws from when none is configured. */
#define LC_XHTTP_PAD_MIN 100u
#define LC_XHTTP_PAD_MAX 1000u

/* Room the opening burst can need: preface, SETTINGS, WINDOW_UPDATE and a HEADERS frame whose
 * largest part is the padded referer. */
#define LC_XHTTP_OPEN_MAX 2048u

typedef struct {
    /* The one stream. Client-initiated streams are odd and this client opens exactly one. */
    uint32_t stream;

    /* What the peer will still accept from us, counted separately for the stream and for the
     * connection. Running out of either stops the upload, and a client that tracks only one of them
     * stalls at whichever it forgot. */
    int64_t send_stream;
    int64_t send_conn;

    /* The last INITIAL_WINDOW_SIZE the peer announced, so a second SETTINGS moves the window by
     * the difference from it rather than from the default. */
    uint32_t peer_initial_window;

    /* What we have taken delivery of and not yet given credit back for. Credit is returned in
     * lumps rather than per frame: one WINDOW_UPDATE per DATA frame is a packet of overhead for
     * every packet of payload. */
    uint32_t owed_stream;
    uint32_t owed_conn;

    int got_response; /* the HEADERS of the answer have been seen */
    int ended;        /* the peer closed the stream */
} lc_xhttp;

/* Writes everything that goes out before the first byte of payload: the connection preface, our
 * SETTINGS, the connection window, and the request. Returns the length, or -1.
 *
 * `host` is the name the request is addressed to, which for REALITY is the server name the
 * handshake used. `path` is the configured path; the trailing slash is added here if it is missing,
 * because that is what the reference sends and the difference is visible to the server. */
long lc_xhttp_open(lc_xhttp *x, const char *host, const char *path, uint8_t *out, size_t cap);

/* Frames `len` bytes of the client's traffic for the upload direction. Writes only the nine-byte
 * header — the payload follows it untouched, because copying a proxy's traffic twice is the cost
 * this whole layer exists to avoid. `*carried` says how much of `len` the windows allowed, which
 * may be nothing at all.
 *
 * Returns the header length, or 0 when nothing can be sent right now. */
size_t lc_xhttp_data(lc_xhttp *x, size_t len, uint8_t *out, size_t cap, size_t *carried);

/* What one turn of the reader produced. */
typedef struct {
    const uint8_t *body;     /* response payload, pointing into the caller's buffer */
    size_t         body_len;
    size_t         consumed; /* bytes of input this took */

    /* Frames this client owes an answer to, already written and ready to go out. */
    uint8_t reply[64];
    size_t  reply_len;
} lc_xhttp_event;

/* Reads as much as one whole frame from the head of `in`.
 *
 * Returns 1 when a frame was dealt with, 0 when there is not enough for a whole one yet, and -1
 * when the peer said something this connection cannot continue after. */
int lc_xhttp_read(lc_xhttp *x, const uint8_t *in, size_t len, lc_xhttp_event *ev);

/* Credit to hand back for `n` bytes the caller has finished with, written into `out`. Returns the
 * length, which is zero when not enough has accumulated to be worth a frame. */
size_t lc_xhttp_credit(lc_xhttp *x, uint32_t n, uint8_t *out, size_t cap);

#endif
