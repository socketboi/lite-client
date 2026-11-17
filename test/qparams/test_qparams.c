/* What this client tells the node about itself, checked against what the reference client tells it.
 *
 * These numbers are read twice by two different parties and for two different reasons, and both
 * readings are silent when they go wrong. The node reads the windows and obeys them: too small a
 * window is not an error anywhere, it is a download that runs at window-over-round-trip and no
 * faster — 64 KiB against a 66 ms round trip was 6.4 Mbit/s on a 47 Mbit/s line, and nothing in
 * any log said why. Anybody on the path reads all of them: the client's transport parameters ride
 * in the ClientHello, and an Initial packet is protected with keys derived from a connection id
 * sent in the clear, so a value nobody else sends is a mark — the same argument shim.c makes about
 * max_datagram_frame_size, applied to the rest of the block.
 *
 * So the assertions are against the reference client's own constants, quoted with where they live,
 * rather than against whatever this file happened to contain when it was written. A test that says
 * "the window is what conn.c sets" would have passed every day the window was wrong.
 *
 * The four values that deliberately differ are asserted as differing, with the reason. That is the
 * part of this test that stops being true first: if one of them is ever brought into line, this
 * fails and says so, rather than quietly disagreeing with the comment that explains it. */

#include "quic/params.c"

#include <stdio.h>

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

/* vendor/hysteria/core/client/config.go:15 — defaultStreamReceiveWindow = 8388608 */
#define HY_STREAM_WINDOW 8388608u
/* vendor/hysteria/core/client/config.go:16 — defaultConnReceiveWindow = stream * 5 / 2 */
#define HY_CONN_WINDOW (HY_STREAM_WINDOW * 5u / 2u)
/* :48-49 — the floor that knob accepts, which is what makes a smaller window a CONFIGURATION of the
 * reference client rather than a value nobody sends. */
#define HY_STREAM_WINDOW_MIN 16384u
/* vendor/hysteria/core/client/config.go:17 — defaultMaxIdleTimeout = 30 * time.Second */
#define HY_IDLE_SECONDS 30u

int main(void)
{
    ngtcp2_transport_params p;
    lc_qparams(&p, 0);

    printf("transport parameters, against hysteria's client\n");

    /* THE REFERENCE'S OWN DEFAULT AGAIN SINCE 2026-09-07, and this paragraph said the opposite
     * until then: "eight megabytes is a promise this hardware refuses to keep, and the refusal
     * arrives as a reset download rather than a slow one." It was describing a client whose
     * receive buffer compacted itself on every take, where draining cost more the larger the
     * window grew — the promise was unreachable for that reason and not because the hardware could
     * not back it. src/quic/params.h carries the measurements; the block further down holds all
     * four numbers to the reference's literals. Two comments in one file disagreeing about the
     * same constant is what this one is here to stop happening again.
     *
     * What these first assertions still add is the SHAPE — one number in all three, the same 5/2
     * ratio for the connection — and that it stays inside what the reference's own knob accepts,
     * because outside it would be a mark on the path. */
    expect(p.initial_max_stream_data_bidi_local == LC_QTCP_STREAM_WINDOW,
           "a stream window this machine can actually back");
    expect(p.initial_max_stream_data_bidi_local >= HY_STREAM_WINDOW_MIN &&
               p.initial_max_stream_data_bidi_local <= HY_STREAM_WINDOW,
           "and one InitialStreamReceiveWindow would accept, so it is a setting and not a mark");
    /* quic-go fills all three from one number: vendor/quic-go/connection.go:329-331. Two of them
     * carry no traffic on this client, and that is the point — they are read, not used. */
    expect(p.initial_max_stream_data_bidi_remote == LC_QTCP_STREAM_WINDOW,
           "and so may a stream the node opens, which it never does");
    expect(p.initial_max_stream_data_uni == LC_QTCP_STREAM_WINDOW,
           "and so may a unidirectional one, which carries only HTTP/3 control");
    expect(p.initial_max_stream_data_bidi_local == p.initial_max_stream_data_bidi_remote &&
               p.initial_max_stream_data_uni == p.initial_max_stream_data_bidi_local,
           "all three agree, because one number fills all three where this is copied from");
    expect(p.initial_max_data == LC_QTCP_CONN_WINDOW,
           "the connection window across every stream at once");
    expect(p.initial_max_data == p.initial_max_stream_data_bidi_local * 5u / 2u,
           "and it keeps the reference's ratio: two and a half stream windows");
    expect(p.initial_max_data > p.initial_max_stream_data_bidi_local,
           "and more than one stream's worth, or a single download would stall on the connection");

    expect(p.max_idle_timeout == HY_IDLE_SECONDS * NGTCP2_SECONDS,
           "thirty seconds of silence before either side may give up");

    /* Held to the number rather than to the constant, so that raising the buffer ceiling without
     * raising the promise — or the reverse — is a failure and not a slow download nobody explains.
     * The window IS the buffer ceiling: rx_grow stops there. */
    expect(LC_QTCP_STREAM_WINDOW == p.initial_max_stream_data_bidi_local,
           "the ceiling a receive buffer may grow to is the window we promised");
    expect(LC_QTCP_CONN_WINDOW == p.initial_max_data,
           "and the connection ceiling is the one we promised across all of them");

    /* ⚠️ THE FOUR THAT USED TO DIFFER FROM THE REFERENCE, HELD TO ITS LITERAL NUMBERS.
     *
     * These were the only QUIC-layer values where this client and the reference disagreed — the
     * qlog comparison in src/quic/params.h found the parameter SET identical, the ORDER identical
     * and six values equal, with just these four lower. They are equal now, and the assertions are
     * written as bare literals rather than against our own constants on purpose: comparing
     * LC_QTCP_STREAM_WINDOW with itself passes whatever it is set to, which is how a fingerprint
     * quietly drifts. 8 388 608 is defaultStreamReceiveWindow
     * (vendor/hysteria/core/client/config.go:15) and 20 971 520 is defaultConnReceiveWindow, its
     * five halves (:16).
     *
     * Lowering either of them again is a decision about what a censor sees, so it should cost a
     * failing test and an argument, not a quiet edit. */
    expect(p.initial_max_stream_data_bidi_local == 8388608u &&
               p.initial_max_stream_data_bidi_remote == 8388608u &&
               p.initial_max_stream_data_uni == 8388608u,
           "all three stream windows are the reference's own 8 388 608, to the byte");
    expect(p.initial_max_data == 20971520u,
           "and the connection window is its 20 971 520, five halves of the stream window");

    /* DATAGRAM is offered to ngtcp2 and withheld from the wire; shim.c is where the second half of
     * that happens, and it can only withhold what is set here. */
    expect(p.max_datagram_frame_size == LC_HY_DATAGRAM_MAX,
           "datagrams are enabled on the connection, and shim.c keeps the parameter off the wire");

    printf("\nthe four that used to differ, now taken from the reference\n");

    /* This block was headed "where this client deliberately differs" and asserted the differences,
     * which made the suite the thing keeping them. Each is now the number quic-go puts on the wire
     * with hysteria overriding none of them.
     *
     * Unidirectional is DefaultMaxIncomingUniStreams = 100
     * (vendor/quic-go/internal/protocol/params.go:37), which hysteria does not override.
     *
     * Bidirectional is ZERO, and this assertion said 100 for as long as the reasoning stopped one
     * layer too high. hysteria does not dial quic-go — it dials through an http3.Transport, whose
     * init sets `t.QUICConfig.MaxIncomingStreams = -1 // don't allow any bidirectional streams`
     * (vendor/quic-go/http3/transport.go:156-157) into the very config the dial then uses
     * (:384), and populateConfig folds -1 to 0 (vendor/quic-go/config.go:94-95). The default of
     * 100 is real and no hysteria client ever reaches it.
     *
     * Zero here does NOT mean the parameter is absent from the hello: ngtcp2 declines to encode a
     * zero (vendor/ngtcp2/lib/ngtcp2_transport_params.c:330-333) while quic-go writes it
     * unconditionally, so src/quic/qtls.c synthesises `08 01 00` in place. The check for that is
     * below, and it is the half that matters on the wire. */
    expect(p.initial_max_streams_bidi == 0, "no bidirectional streams, as http3.Transport forces");
    expect(p.initial_max_streams_uni == 100, "a hundred unidirectional, the same default");
    /* MaxActiveConnectionIDs = 4 (params.go:127), passed as ActiveConnectionIDLimit
     * (vendor/quic-go/connection.go:477). Seven came from ngtcp2's example client. */
    expect(p.active_connection_id_limit == 4, "four connection ids, from MaxActiveConnectionIDs");
    /* MaxPacketBufferSize = 1452 (internal/protocol/protocol.go:111) as MaxUDPPayloadSize (quic-go/connection.go:338).
     * Unset meant ngtcp2's 65527 — legal, and the largest number in the set. */
    expect(p.max_udp_payload_size == 1452, "1452, from MaxPacketBufferSize");
    /* MaxAckDelayInclGranularity = 25 ms + 1 ms (params.go:144-148), sent by quic-go/connection.go:336. */
    expect(p.max_ack_delay == 26 * NGTCP2_MILLISECONDS,
           "26 ms — the reference's own 25 plus a millisecond of granularity");

    /* THE FLOOR UNDER THE PEER'S IDLE TIMEOUT, which is the one value here that is READ rather than
     * sent. quic-go clamps a received max_idle_timeout to five seconds
     * (vendor/quic-go/internal/wire/transport_parameters.go:325-326); ngtcp2 has no such floor, and
     * a hysteria node may advertise four seconds legitimately
     * (vendor/hysteria/core/server/config.go:74-75). Asked of lc_qtp_floor_idle directly: the caller
     * needs a connection and finished keys, and building those would test them instead. */
    printf("\nthe floor under a peer's idle timeout\n");
    {
        uint8_t                 blob[1024], out[1280];
        ngtcp2_transport_params peer;

        /* Absent — the encoder omits a zero, and an absent parameter is left alone, because the
         * reference clamps inside `case maxIdleTimeoutParameterID:` and never reaches an omission. */
        lc_qparams(&peer, 0);
        peer.max_idle_timeout = 0;
        ngtcp2_ssize n = ngtcp2_transport_params_encode(blob, sizeof blob, &peer);
        expect(n > 0 && lc_qtp_floor_idle(blob, (size_t)n, out, sizeof out) == 0,
               "a peer that names no idle timeout is handed on untouched");

        /* Above the floor — nothing to do, and the blob must not be rewritten for nothing. */
        lc_qparams(&peer, 0);
        peer.max_idle_timeout = 30 * NGTCP2_SECONDS;
        n = ngtcp2_transport_params_encode(blob, sizeof blob, &peer);
        expect(n > 0 && lc_qtp_floor_idle(blob, (size_t)n, out, sizeof out) == 0,
               "thirty seconds is above the floor and is left as it arrived");

        /* Four seconds — what a node's own config permits, and what the reference raises. */
        lc_qparams(&peer, 0);
        peer.max_idle_timeout = 4 * NGTCP2_SECONDS;
        n = ngtcp2_transport_params_encode(blob, sizeof blob, &peer);
        ngtcp2_ssize m = n > 0 ? lc_qtp_floor_idle(blob, (size_t)n, out, sizeof out) : -1;
        ngtcp2_transport_params got;
        expect(m > 0 && ngtcp2_transport_params_decode(&got, out, (size_t)m) == 0 &&
                   got.max_idle_timeout == 5 * NGTCP2_SECONDS,
               "four seconds is raised to five, as MinRemoteIdleTimeout requires");

        /* PRESENT AND ZERO, which the decoded struct cannot tell from absent — the contract on
         * ngtcp2_transport_params_decode assigns defaults to what is missing. The reference reaches
         * its `case` for this one and raises it like any other small value, so presence is read off
         * the wire here. Hand-built because ngtcp2's encoder will not write a zero. */
        static const uint8_t present_zero[] = { 0x01u, 0x01u, 0x00u };
        m = lc_qtp_floor_idle(present_zero, sizeof present_zero, out, sizeof out);
        expect(m > 0 && ngtcp2_transport_params_decode(&got, out, (size_t)m) == 0 &&
                   got.max_idle_timeout == 5 * NGTCP2_SECONDS,
               "a zero that was actually sent is raised too, which absent is not");
    }

    printf("\n%s\n", failures == 0 ? "all good" : "SOMETHING IS WRONG");
    return failures == 0 ? 0 : 1;
}
