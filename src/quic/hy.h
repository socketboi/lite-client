/* Hysteria2's proxy framing: what goes on a stream once the node has let us in.
 *
 * Two messages and a datagram, all of them small and none of them negotiable — the definitions are
 * core/internal/protocol/proxy.go, which is vendored beside this so the numbers can be checked
 * rather than remembered.
 *
 * The address is a string, "host:port", not a packed structure. That is a deliberate part of the
 * protocol rather than an accident of Go: it is what lets the node resolve names for us, which is
 * the whole point of routing DNS through the tunnel rather than around it. */
#ifndef LC_HY_H
#define LC_HY_H

#include "quic/pad.h"

#include <stddef.h>
#include <stdint.h>

/* Limits the node enforces on what it reads, so writing past them is writing a message that will be
 * refused. Ours are the same numbers for the same reason: a length field is an invitation.
 *
 * ⚠️ AND THEY NAMED NO LINE UNTIL NOW, WHICH IS THE HEADER'S PARTICULAR BLINDNESS: nothing here is
 * code, so no finding is ever made about it, and every one of these is a wire limit. The file's own
 * opening says the definitions are in proxy.go "so the numbers can be checked rather than
 * remembered" — this is that promise kept at each number rather than once in prose.
 *
 *     MaxAddressLength = 2048
 *     MaxMessageLength = 2048
 *     MaxPaddingLength = 4096
 *              (vendor/hysteria/core/internal/protocol/proxy.go:19-21) */
#define LC_HY_ADDR_MAX 2048u
#define LC_HY_MSG_MAX 2048u
#define LC_HY_PADDING_MAX 4096u

/* Room a request needs in the worst case: the frame type, the longest address, and the longest
 * padding, each behind its own length. */
#define LC_HY_TCP_REQ_MAX (8u + 8u + LC_HY_ADDR_MAX + 8u + LC_PAD_TCP_REQ_MAX)

/* Writes the request that asks the node to open a TCP connection to `addr` ("host:port").
 * Returns the number of bytes written, or -1. */
long lc_hy_tcp_request(const char *addr, uint8_t *out, size_t cap);

/* What the node said about that request. `message` is its explanation when it refused; it is the
 * node's text and is only ever shown, never acted on. */
typedef struct {
    int  ok;
    char message[128];
} lc_hy_tcp_reply;

/* Reads the reply from the head of `in`.
 *
 * Returns the number of bytes it consumed — after which the stream carries nothing but the
 * connection's own bytes — or 0 when more is needed, or -1 when it is not a reply at all. */
long lc_hy_tcp_response(const uint8_t *in, size_t len, lc_hy_tcp_reply *out);

/* ---- UDP, which rides QUIC's unreliable datagrams ----------------------------------------------
 *
 * A datagram is not a stream: there is no retransmission, no ordering, and no flow control, which
 * is exactly what a UDP packet wants. What that costs is a header, because one QUIC connection
 * carries every UDP flow at once and each datagram has to say which one it belongs to and where it
 * is going. */

/* The largest UDP packet that survives this, reassembled. Upstream's number — `MaxUDPSize = 4096`
 * (vendor/hysteria/core/internal/protocol/proxy.go:24) — and a packet larger than this is one the
 * node will not put back together either. */
#define LC_HY_UDP_MAX 4096u

/* And what one datagram may carry before it has to be split: `MaxDatagramFrameSize = 1200`
 * (vendor/hysteria/core/internal/protocol/proxy.go:23). Both sides use this same figure, and the
 * reason it has to be a figure rather than something negotiated is that the reference deliberately
 * does NOT announce it — `MaxDatagramFrameSize: protocol.MaxDatagramFrameSize` immediately followed
 * by `OmitMaxDatagramFrameSize: true` (vendor/hysteria/core/client/client.go:92-93). See the
 * note in src/quic/shim.c about the transport parameter that is never sent. */
#define LC_HY_DATAGRAM_MAX 1200u

typedef struct {
    uint32_t session;
    uint16_t packet;    /* which packet these fragments belong to; zero when there is one fragment */
    uint8_t  frag;      /* this fragment's number */
    uint8_t  frag_count;/* how many there are; one means the packet arrived whole */
    char     addr[LC_HY_ADDR_MAX + 1];

    /* Into the caller's buffer, not a copy. */
    const uint8_t *data;
    size_t         len;
} lc_hy_udp;

/* Bytes the header takes for a given address, which is what decides how much payload fits. */
size_t lc_hy_udp_header_len(const char *addr);

/* Writes one datagram. Returns its length, or -1 if it does not fit `cap`. */
long lc_hy_udp_put(const lc_hy_udp *msg, uint8_t *out, size_t cap);

/* Reads one. `out->data` points into `in`, which must outlive it. Returns 0 or -1. */
int lc_hy_udp_parse(const uint8_t *in, size_t len, lc_hy_udp *out);

#endif
