/* HTTP/2 framing — as much of RFC 9113 as XHTTP's stream-one mode actually uses.
 *
 * Four frame types and a preface, not a protocol implementation. That is not a shortcut taken to
 * save effort: stream-one opens exactly one stream, sends one request on it, and reads one response
 * back, so priority, push, ping, RST_STREAM, GOAWAY and CONTINUATION describe a conversation this
 * client never has. What is here is what appears on the wire between a client that opens one stream
 * and a server that answers it.
 *
 * The things that would bite if left out are in: flow control, because a server that has given a
 * window of 65 535 bytes stops at 65 535 bytes and waits, and a client that never sends
 * WINDOW_UPDATE waits with it, forever, with no error anywhere. */
#ifndef LC_H2_FRAME_H
#define LC_H2_FRAME_H

#include <stddef.h>
#include <stdint.h>

/* The nine bytes every frame starts with: three of length, one of type, one of flags, four of
 * stream id whose top bit is reserved and zero. */
#define LC_H2_HEADER 9u

/* TWO LIMITS, NOT ONE, and conflating them is a protocol error waiting for the first peer that
 * takes us at our word.
 *
 * What we may SEND is what the PEER allows, and until its SETTINGS say otherwise that is the
 * protocol's own floor of sixteen kilobytes (RFC 9113 section 6.5.2). What we ACCEPT is what WE
 * advertise, and that is what Go's client advertises for a Transport that sets no MaxReadFrameSize —
 * which both of Xray's do, the REALITY spider's and splithttp's
 * (vendor/Xray-core/transport/internet/reality/reality.go:211-218,
 * vendor/Xray-core/transport/internet/splithttp/dialer.go:254-260).
 *
 * UNDER GO 1.27 THAT IS A MEGABYTE, and it was sixteen kilobytes until the reference moved to it.
 * Both Transports are x/net's, and under Go 1.27 x/net hands them to the client inside net/http
 * (vendor/x-net/http2/transport_wrap.go:73-84): a MaxReadFrameSize of zero is passed on as zero,
 * mergeHTTP2Config keeps it (GOROOT/src/net/http/http2.go:499-548), and setDefault replaces a
 * value out of [minMaxFrameSize, maxFrameSize] with defaultMaxReadFrameSize, 1 << 20
 * (GOROOT/src/net/http/internal/http2/config.go:44-48, :64,
 * GOROOT/src/net/http/internal/http2/http2.go:82) — the value the SETTINGS frame then carries
 * (GOROOT/src/net/http/internal/http2/transport.go:679). Xray v26.9.9 sent 1048576 on the stand
 * (tools/vendorcap/spiderredir, 2026-09-27). Under Go 1.26 x/net's own config clipped the zero up to
 * minMaxFrameSize instead, so 16384 went out, and this said so until then.
 *
 * The two were one constant, which was consistent only because this client advertised nothing: it
 * accepted sixteen kilobytes and sent no more. Raising the single number to match the reference
 * would have raised the SEND cap with it, and a megabyte DATA frame at a peer that allowed sixteen
 * kilobytes is a connection error — the one kind of bug that shows up only against a peer that
 * bothers to check. The two are no longer equal. */
#define LC_H2_MAX_FRAME 16384u
#define LC_H2_MAX_READ_FRAME 1048576u

/* And what a peer's header block may weigh before we stop reading it. `maxHeaderListSize()` returns
 * `10 << 20` when nothing configured it (vendor/x-net/http2/transport.go:91-93), and Go's client
 * sends it whenever it is non-zero, which by that default is always. */
#define LC_H2_MAX_HEADER_LIST (10u << 20)

typedef enum {
    LC_H2_DATA = 0x0,
    LC_H2_HEADERS = 0x1,
    LC_H2_RST_STREAM = 0x3,
    LC_H2_SETTINGS = 0x4,
    LC_H2_PING = 0x6,
    LC_H2_GOAWAY = 0x7,
    LC_H2_WINDOW_UPDATE = 0x8,
} lc_h2_type;

/* Flags, only the ones this client sets or reads. */
#define LC_H2_END_STREAM 0x01u
#define LC_H2_END_HEADERS 0x04u
#define LC_H2_ACK 0x01u
#define LC_H2_PADDED 0x08u

typedef struct {
    uint32_t len;
    uint8_t  type;
    uint8_t  flags;
    uint32_t stream;
} lc_h2_hd;

/* The twenty-four bytes a client sends before anything else, so a server reading a plain HTTP
 * request cannot mistake this for one. Returns its length, which is constant. */
size_t lc_h2_preface(uint8_t *out, size_t cap);

/* Writes a frame header. Returns LC_H2_HEADER, or 0 if it did not fit. */
size_t lc_h2_put_header(uint8_t *out, size_t cap, uint32_t len, uint8_t type, uint8_t flags,
                        uint32_t stream);

/* Reads one. Returns 0, or -1 when there are fewer than nine bytes or the frame declares more
 * payload than was ever offered. */
int lc_h2_get_header(const uint8_t *in, size_t len, lc_h2_hd *out);

/* Our SETTINGS: no dynamic table, no push, and the window we can hold. Returns the length written.
 *
 * Sent once, immediately after the preface, and never changed — a client that renegotiates mid
 * connection has a reason to, and this one does not. */
size_t lc_h2_settings(uint8_t *out, size_t cap, uint32_t initial_window);

/* An empty SETTINGS with ACK set, which is the whole of the answer a peer's SETTINGS requires. */
size_t lc_h2_settings_ack(uint8_t *out, size_t cap);

/* A HEADERS frame wrapping an already-encoded block. `end_stream` says the request has no body,
 * which for stream-one it always has. */
size_t lc_h2_headers(uint8_t *out, size_t cap, uint32_t stream, const uint8_t *block, size_t len,
                     int end_stream);

/* A DATA frame header. The payload is written by the caller straight after it, because on this path
 * it is the client's own traffic and copying it twice is the thing being avoided. */
size_t lc_h2_data_header(uint8_t *out, size_t cap, uint32_t stream, size_t len, int end_stream);

/* Credit, in bytes, for one stream or — with stream zero — for the whole connection. Both are
 * needed: they are counted separately, and running out of either one stops everything. */
size_t lc_h2_window_update(uint8_t *out, size_t cap, uint32_t stream, uint32_t increment);

/* The body a DATA frame carries, its padding cut off: a PADDED frame starts with the padding's
 * length and ends with that many bytes (RFC 9113 section 6.1). -1 for one whose padding does not
 * fit in it, which is a connection error to x/net and a frame with no body to anyone. */
int lc_h2_data_body(const lc_h2_hd *hd, const uint8_t *payload, const uint8_t **body,
                    size_t *body_len);

#endif
