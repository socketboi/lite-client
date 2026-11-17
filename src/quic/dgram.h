/* How large a proxied UDP payload may be, and the two wrappers that decide it.
 *
 * Split out of conn.c for the reason quic/txbuf.c was: conn.c cannot be loaded by a test without the
 * whole vendored QUIC stack, so arithmetic living there is arithmetic nothing ever asks. This module
 * is that arithmetic and nothing else — no ngtcp2, no connection, no socket — so test/qdgram can put
 * the reference's own numbers to it directly.
 *
 * ⚠️ AND THAT IS NOT A TIDINESS ARGUMENT. The numbers below were a single guessed constant of sixty
 * bytes standing in for both wrappers, it was wrong by fifty-seven on one of them, and it was wrong
 * for months while a comment beside it said the fault had been fixed. Nothing could contradict the
 * comment, because there was nothing to run. See conn.c's lc_qconn_udp_send for the full account.
 */
#ifndef LC_QDGRAM_H
#define LC_QDGRAM_H

#include "quic/hy.h"

#include <stddef.h>
#include <stdint.h>

/* THE TWO WRAPPERS AROUND A DATAGRAM, EACH THE SIZE THE REFERENCE GIVES IT.
 *
 * A payload is bounded twice over and by different things: by the DATAGRAM FRAME the node agreed to
 * accept, and by the QUIC PACKET that frame has to fit inside. quic-go takes the smaller of the two
 * and hysteria fragments against it — `min(f.MaxDataLen(maxDatagramFrameSize, version),
 * maxPayloadSizeEstimate)` (vendor/quic-go/connection.go:3084-3093). Two numbers, not one.
 *
 * FRAME. `DatagramFrame.MaxDataLen` is one byte of frame type, one for the length varint, and one
 * more once the answer stops fitting in a single varint byte
 * (vendor/quic-go/internal/wire/datagram_frame.go:61-76, with DataLenPresent true as
 * vendor/quic-go/connection.go:3084 sets it). Three for
 * anything worth sending; lc_qudp_frame_fit spells the edge out rather than assuming it.
 *
 * PACKET. `estimateMaxPayloadSize` is `mtu - 1 (type byte) - 20 (maximum connection id length) -
 * 16 (tag size)` (vendor/quic-go/connection.go:3199-3204). Thirty-seven, and deliberately loose at
 * the connection id: ours is eight, so the real short header is twenty-nine, and the reference's own
 * comment calls the estimate "not very sophisticated". Loose in this direction is the cheap way to
 * be wrong — a datagram that turns out not to fit is refused by ngtcp2 with
 * NGTCP2_ERR_INVALID_ARGUMENT and dropped with a log line, which is exactly what
 * DatagramTooLargeError does on the other side. */
#define LC_QUDP_FRAME_OVERHEAD  3u
#define LC_QUDP_PACKET_OVERHEAD 37u

/* What fits when the node has said nothing at all: it assumes a silent client accepts a
 * LC_HY_DATAGRAM_MAX frame (AssumePeerMaxDatagramFrameSize), and the frame header comes out of that.
 * This is the case the reference never reaches — it always has a negotiated number to use — and it
 * is also the bound lc-hydns checks a query against, having no connection to ask. */
#define LC_QUDP_PAYLOAD (LC_HY_DATAGRAM_MAX - LC_QUDP_FRAME_OVERHEAD)

/* The largest UDP payload this client will ever put on the wire, which is quic-go's
 * MaxPacketBufferSize (vendor/quic-go/internal/protocol/protocol.go:107-111). It is a CEILING and
 * not the size packets come out at: a connection starts at NGTCP2_INITIAL_UDP_PAYLOAD_SIZE = 1280
 * and Path MTU Discovery raises it towards this number, taking the minimum with what the node
 * advertised, exactly as the reference does. Named here because two places have to agree about it:
 * the ngtcp2 setting in lc_qconn_open, and the send queue slot below. */
#define LC_QUDP_TX_MTU 1452u

/* One slot of the send queue, and it has to hold the LARGEST payload that can ever be handed to it
 * rather than the fallback above. lc_qudp_fit is computed per send from the negotiated limits and
 * can exceed LC_QUDP_PAYLOAD; a slot sized to the fallback would turn every datagram in between into
 * a refusal from lc_hy_udp_put — a drop on our own floor that reads in the log like the node's
 * doing. At this MTU the packet wrapper is the binding half, so that is what the ceiling works out
 * to. */
#define LC_QUDP_SLOT (LC_QUDP_TX_MTU - LC_QUDP_PACKET_OVERHEAD)

/* How much payload a DATAGRAM frame of `frame_max` bytes can carry. Zero when not even the header
 * fits, which is the refusal MaxDataLen gives. */
size_t lc_qudp_frame_fit(uint64_t frame_max);

/* The whole of what the reference computes before it fragments: the smaller of the two wrappers,
 * the fallback for a peer that advertised nothing, and the clamp that keeps the answer inside the
 * queue slot it will be copied into. `peer_frame_max` is the node's advertised
 * max_datagram_frame_size, zero when it sent none; `mtu` is the UDP payload the path takes, zero
 * when there is no connection to ask yet. */
size_t lc_qudp_fit(uint64_t peer_frame_max, size_t mtu);

#endif
