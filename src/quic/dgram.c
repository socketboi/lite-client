#include "quic/dgram.h"

/* The reference's own answer, copied rather than approximated.
 *
 * `DatagramFrame.MaxDataLen` reserves one byte of frame type and one for the length varint, then
 * takes one more back once the answer it arrived at no longer fits in a single varint byte, which is
 * at sixty-four (vendor/quic-go/internal/wire/datagram_frame.go:61-76). DataLenPresent is true
 * because vendor/quic-go/connection.go:3084 constructs the frame that way.
 *
 * Worth spelling out rather than writing `frame_max - 3`: the two-byte case is unreachable against
 * any node worth talking to, and a constant that happens to be right for every reachable input is
 * exactly the kind that stops being right silently when the input changes. That is the fault this
 * whole module was extracted over. */
size_t lc_qudp_frame_fit(uint64_t frame_max)
{
    if (frame_max < 2u)
        return 0;
    uint64_t fit = frame_max - 2u;
    if (fit >= 64u) /* quicvarint.Len(fit) != 1 */
        fit--;
    return (size_t)fit;
}

size_t lc_qudp_fit(uint64_t peer_frame_max, size_t mtu)
{
    size_t fit = 0;

    /* The peer's number bounds a FRAME, so the frame header comes off it. Zero means it advertised
     * nothing at all, which is not the same as advertising something too small to use — that second
     * case comes back from lc_qudp_frame_fit as a zero of its own and is left to the fallback, the
     * way MaxDataLen's zero leaves quic-go with nothing it can send. */
    if (peer_frame_max > 0u) {
        size_t peer = lc_qudp_frame_fit(peer_frame_max);
        if (peer > 0u)
            fit = peer;
    }

    /* The path's number bounds a PACKET, so the packet header and the tag come off it instead. */
    if (mtu > LC_QUDP_PACKET_OVERHEAD) {
        size_t path = mtu - LC_QUDP_PACKET_OVERHEAD;
        fit = (fit == 0u || path < fit) ? path : fit;
    }

    if (fit == 0u)
        fit = LC_QUDP_PAYLOAD;
    if (fit > LC_QUDP_SLOT)
        fit = LC_QUDP_SLOT;
    return fit;
}
