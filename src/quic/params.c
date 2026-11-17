#include "quic/params.h"

#include "quic/hy.h"
#include "quic/varint.h"


void lc_qparams(ngtcp2_transport_params *p, int chrome)
{
    ngtcp2_transport_params_default(p);

    /* A hundred unidirectional, and ZERO bidirectional, because that is what the reference puts on
     * the wire — and the two numbers get there by different routes, which is why the second one was
     * wrong for as long as it was reasoned about rather than traced.
     *
     * Unidirectional: hysteria does not set MaxIncomingUniStreams, so quic-go's
     * DefaultMaxIncomingUniStreams = 100 survives (vendor/quic-go/internal/protocol/params.go:37,
     * applied in populateConfig, vendor/quic-go/config.go:97-102).
     *
     * Bidirectional: hysteria does not set MaxIncomingStreams either — and it never reaches the
     * default of 100, because hysteria does not dial quic-go directly. It hands its quic.Config to
     * an http3.Transport (vendor/hysteria/core/client/client.go:106-115), and that transport's init
     * writes into the config it was given:
     *
     *   if t.QUICConfig.MaxIncomingStreams == 0 {
     *       t.QUICConfig.MaxIncomingStreams = -1 // don't allow any bidirectional streams
     *   }                                        (vendor/quic-go/http3/transport.go:156-157)
     *
     * and the dial uses that same mutated config (`dial(ctx, hostname, tlsConf, t.QUICConfig)`,
     * vendor/quic-go/http3/transport.go:384). populateConfig then folds -1 to 0 (vendor/quic-go/config.go:94-95), and
     * the client's parameters take it verbatim. So every real hysteria client says `08 01 00`.
     *
     * The comment that stood here argued from "hysteria overrides nothing, therefore quic-go's
     * default" and stopped one layer above the layer that decides. It also argued that advertising
     * a limit is not accepting a stream, which is true and is not the point: the number is read off
     * the wire before anything is opened, and ours read 100 where every client of this stack reads
     * 0.
     *
     * Zero is not merely a different value here — it is a value ngtcp2 will not encode at all
     * (`if (params->initial_max_streams_bidi) {`, vendor/ngtcp2/lib/ngtcp2_transport_params.c:330),
     * while quic-go writes the parameter unconditionally. Setting it to 0 alone would therefore
     * DELETE 0x08 from the hello rather than correct it, which is a louder difference than the one
     * being fixed. The entry is written explicitly in src/quic/qtls.c instead; see the note there. */
    p->initial_max_streams_uni = 100;
    p->initial_max_streams_bidi = 0;

    /* Four, from MaxActiveConnectionIDs (vendor/quic-go/internal/protocol/params.go:127), which is
     * what quic-go passes as ActiveConnectionIDLimit (vendor/quic-go/connection.go:477). Seven was what ngtcp2's
     * example client asks for — a reasonable number chosen from the wrong reference.
     * DefaultActiveConnectionIDLimit (vendor/quic-go/internal/protocol/protocol.go:137) is a
     * different two: the READER'S fallback for a peer that sent nothing
     * (vendor/quic-go/internal/wire/transport_parameters.go:126), the same 2 RFC 9000 names, and
     * ngtcp2 reads an absent value the same way — no divergence has anywhere to live. */
    p->active_connection_id_limit = 4;

    /* 1452 = MaxPacketBufferSize (vendor/quic-go/internal/protocol/protocol.go:111), passed as
     * MaxUDPPayloadSize (vendor/quic-go/connection.go:470, the client constructor). Unset here meant ngtcp2's default of 65527, which is
     * legal, is what nothing else sends, and is the largest single number in the parameter set —
     * the easiest kind of value to notice. */
    p->max_udp_payload_size = 1452;

    /* 26 ms, and the odd number is the reference's own arithmetic: MaxAckDelayInclGranularity is
     * MaxAckDelay (25 ms) plus TimerGranularity (1 ms),
     * vendor/quic-go/internal/protocol/params.go:144-148, and vendor/quic-go/connection.go:469 (the client
     * constructor) sends that sum rather than the round number beside it. ngtcp2 defaults to a flat 25.
     * The same 25 under its own name, DefaultMaxAckDelay (vendor/quic-go/internal/protocol/protocol.go:143), plays
     * two reader-side parts this client already lines up with: the fallback for a peer that sent no
     * max_ack_delay, and the omit-if-equal threshold that keeps the parameter OFF the wire when it
     * would say 25 (vendor/quic-go/internal/wire/transport_parameters.go:124, :400) — ours says 26, so ours is sent,
     * which the hello suite pins. */
    p->max_ack_delay = 26 * NGTCP2_MILLISECONDS;

    /* Thirty seconds of silence before either side may give up, which is what the reference client
     * asks for — `defaultMaxIdleTimeout = 30 * time.Second`
     * (vendor/hysteria/core/client/config.go:17), applied at
     * vendor/hysteria/core/client/config.go:67. It is not what
     * keeps a tunnel alive — see the keep-alive in conn.c — but it is what the number on the wire
     * says, and the two are read together by anything comparing this client to that one. */
    p->max_idle_timeout = LC_QCONN_IDLE_TIMEOUT;

    /* WHAT IS DONE WITH THE PEER'S IDLE TIMEOUT, NOT OURS — named here because nothing else in this
     * tree cites it and the constants ledger (lcdefaults) flagged the silence. quic-go refuses to
     * take the remote's word below five seconds: `p.MaxIdleTimeout = max(protocol.MinRemoteIdleTimeout,
     * ...)` (vendor/quic-go/internal/wire/transport_parameters.go:326, constant at
     * vendor/quic-go/internal/protocol/params.go:91) — a server advertising one second cannot force
     * the reference client onto a keep-alive treadmill. ngtcp2 applies RFC 9000's plain minimum of
     * the two sides with no such floor, and this client does not add one: the divergence is not on
     * the wire — it is how a RECEIVED value is interpreted.
     *
     * ⚠️ THE CONDITION THIS PARAGRAPH SET FOR CLOSING IT IS SATISFIABLE, AND CLOSING IT STILL BUYS
     * NOTHING. The condition was "a node config that actually puts a sub-five value on the wire",
     * cited to hysteria's 4s floor — but that citation named the CLIENT config, and what reaches us
     * is set by the server: `must be between 4s and 120s`
     * (vendor/hysteria/core/server/config.go:74-75, default 30s at :22). A legitimately configured
     * node can therefore advertise four seconds, and this is reachable rather than marginal.
     *
     * ⚠️ AND IT IS CLOSED NOW — lc_qtp_floor_idle, at the bottom of this file. What kept it open was
     * an argument from consequence: both clients keep alive every ten seconds — ours in conn.c
     * (`ngtcp2_conn_set_keep_alive_timeout(c->conn, 10 * NGTCP2_SECONDS)`), the reference at
     * `defaultKeepAlivePeriod = 10 * time.Second` (vendor/hysteria/core/client/config.go:18) — so
     * against a node
     * that tolerates four seconds the connection dies AT THE NODE either way and the floor only
     * decides whether we stop waiting after four or after five. That is still true, and it stopped
     * being the question — the rule here is that the protocols are the reference's, not that each
     * divergence earns its keep separately.
     *
     * The other half of the old argument was a cost that turned out not to exist. It said a
     * re-encode drops everything ngtcp2 does not model. It does — and those parameters were never
     * going to reach ngtcp2 anyway, since its own decoder ignores them
     * (vendor/ngtcp2/lib/ngtcp2_transport_params.c:761). The re-encode also happens ONLY when the
     * clamp fires, so an ordinary handshake is byte for byte the path it was before.
     *
     * ⚠️ AND ngtcp2 DOES HAVE A SETTER FOR DECODED PARAMETERS, which that argument said it did not:
     * `ngtcp2_conn_set_remote_transport_params` (vendor/ngtcp2/lib/ngtcp2_conn.c:11657). It is
     * declared in vendor/ngtcp2/lib/ngtcp2_conn.h and nowhere public. Using it would skip the
     * re-encode — and would reach into the library's own internals, which is a different thing from
     * the crypto backend interface shim.c includes and justifies. The public round trip is chosen
     * knowing the private shortcut exists. What that reading did settle is the lifetime question:
     * the setter copies (`ngtcp2_transport_params_copy_new`), so the buffer handed in may be a
     * local. */

    /* All three, the way quic-go fills them from one number (vendor/quic-go/connection.go:329-331).
     * bidi_remote and uni are not windows this client's traffic ever uses — the node opens no bidi
     * streams and the unidirectional ones carry HTTP/3 control and QPACK, which are tiny. They are
     * set because they are read: three values that agree is what the reference client looks like,
     * and one of them holding a different number is a mark on a client whose whole purpose is not to
     * have one. */
    /* Two quic-go numbers a reader may look for here and rightly not find. DefaultInitialMaxData
     * (vendor/quic-go/internal/protocol/params.go:22) is quic-go's own config fallback, and hysteria overrides it
     * before dialling (vendor/hysteria/core/client/config.go:47-62) — the reference client never
     * puts it on the wire, so neither do we. WindowUpdateThreshold
     * (vendor/quic-go/internal/protocol/params.go:31) is the RECEIVER'S cadence — re-advertise the window once a
     * quarter of it is consumed — and that lives inside ngtcp2 here, with ngtcp2's own policy.
     *
     * ⚠️ AND THAT POLICY IS THE SAME QUARTER, WHICH THIS PARAGRAPH GOT WRONG FOR AS LONG AS IT
     * STOOD. It said the two stacks "genuinely differ" here and named this as the place to start on
     * the throughput gap. They do not differ. quic-go advertises when the remaining window has
     * fallen to (1 - 0.25) of its size — `bytesRemaining <= ByteCount(float64(receiveWindowSize) *
     * (1 - WindowUpdateThreshold))` (vendor/quic-go/flow_controller_base.go:38,
     * constant 0.25 at vendor/quic-go/internal/protocol/params.go:31) — and ngtcp2 sends when the
     * unannounced increment has reached a quarter of the window: `return strm->rx.window < 4 * inc`
     * (vendor/ngtcp2/lib/ngtcp2_conn.c:3251-3256, and conn_should_send_max_data at :3263-3267 for
     * the connection). One fraction, two spellings.
     *
     * ⚠️ THE OTHER HALF, WHICH LOOKED LIKE A REAL DIVERGENCE AND IS NOT EITHER: quic-go AUTO-TUNES
     * a receive window, doubling it when an epoch is consumed faster than four times the fraction
     * of an RTT (maybeAdjustWindowSize, vendor/quic-go/flow_controller_base.go:55-75).
     * BOTH STACKS HAVE THAT — ngtcp2's is `max_window` and `max_stream_window`, "enabled if nonzero
     * value is specified in this field" (vendor/ngtcp2/lib/includes/ngtcp2/ngtcp2.h:1940-1966) —
     * and in BOTH it is off here. Ours because those settings are left at zero; the reference's
     * because hysteria closes the door itself: with nothing configured it sets
     * `MaxStreamReceiveWindow = defaultStreamReceiveWindow`
     * (vendor/hysteria/core/client/config.go:51-53), the same eight megabytes as the initial one,
     * so `min(2*size, maxSize)` can never exceed what it started with. Two windows that never grow,
     * for two different reasons, to the same number.
     *
     * ⚠️ THAT HOLDS WITHOUT THE PARROT ONLY, and "for two different reasons" is one reason now.
     * Parroting Chrome, the reference starts at Chrome's smaller windows under the same ceilings
     * (below), and there its windows DO grow. So this client sets ngtcp2's ceilings to hysteria's —
     * 8 and 20 MB, the numbers above — and grows as quic-go grows (patches/ngtcp2/0016, which puts
     * quic-go's rule in place of ngtcp2's own; see conn.c where the settings are made). Without the
     * parrot the ceilings equal the windows and nothing moves, as before. The buffer keeps the
     * promise either way: quic/rxbuf.h grows to LC_QTCP_STREAM_WINDOW, which is the ceiling.
     *
     * So the receiver's flow control is closed as an explanation, on citations rather than on a
     * measurement that happened not to show it — and the measurement agreed anyway: zero
     * STREAM_DATA_BLOCKED from the node against a window five times the bandwidth-delay product.
     * What remains of the gap is the sending stack itself — ngtcp2's recovery and pacer against
     * quic-go's — which is the layer this client accepts by construction, since the alternative is
     * to ship Go. Anyone picking the gap back up should start there and not here. */
    p->initial_max_stream_data_bidi_local = LC_QTCP_STREAM_WINDOW;
    p->initial_max_stream_data_bidi_remote = LC_QTCP_STREAM_WINDOW;
    p->initial_max_stream_data_uni = LC_QTCP_STREAM_WINDOW;
    p->initial_max_data = LC_QTCP_CONN_WINDOW;

    /* Hysteria2 carries proxied UDP in QUIC datagrams, so the extension has to be offered or the
     * server has nowhere to put them.
     *
     * Set on the connection and deliberately NOT sent: ngtcp2 measures every DATAGRAM frame that
     * arrives against this value, and hysteria's client keeps the parameter off the wire. The whole
     * of that argument is in src/quic/shim.c, where it is left out of the encoding. */
    p->max_datagram_frame_size = LC_HY_DATAGRAM_MAX;

    if (!chrome)
        return;

    /* ⚠️ WHILE PARROTING CHROME, NEARLY EVERY NUMBER ABOVE IS SOMETHING ELSE, and the reasoning
     * above is the reasoning for a client that has turned the parrot off.
     *
     * populateConfig overwrites hysteria's choices with Chrome's (vendor/quic-go/config.go:109-125):
     * windows of 6291456 per stream and 15728640 for the connection, a hundred bidirectional
     * streams where http3 had asked for none and 103 unidirectional ones, thirty seconds of idle
     * time — which hysteria already asked for. chromeParrotTransportParameters then moves four
     * values to what their ABSENCE means, because marshalChrome does not send them: max_ack_delay
     * to the 25 ms default, ack_delay_exponent to 3, disable_active_migration off,
     * active_connection_id_limit to 2 — and states a 1472-byte max_udp_payload_size and a
     * DATAGRAM frame of 65536, which it both sends and accepts (vendor/quic-go/chrome_parrot.go:
     * 31-39). The encoding is write_params_chrome in src/quic/qtls.c.
     *
     * The two windows are only where Chrome STARTS: the ceilings stay hysteria's, raised to the
     * starting windows if they were below them — `maxStreamReceiveWindow =
     * max(maxStreamReceiveWindow, initialStreamReceiveWindow)` (vendor/quic-go/config.go:122-124) —
     * which leaves 8 and 20 MB above 6291456 and 15728640, and auto-tuning carries the windows up to
     * them (patches/ngtcp2/0016). */
    p->initial_max_streams_bidi = 100;
    p->initial_max_streams_uni = 103;
    p->initial_max_stream_data_bidi_local = LC_QCHROME_STREAM_WINDOW;
    p->initial_max_stream_data_bidi_remote = LC_QCHROME_STREAM_WINDOW;
    p->initial_max_stream_data_uni = LC_QCHROME_STREAM_WINDOW;
    p->initial_max_data = LC_QCHROME_CONN_WINDOW;
    p->max_udp_payload_size = 1472;
    p->max_ack_delay = NGTCP2_DEFAULT_MAX_ACK_DELAY;
    p->ack_delay_exponent = NGTCP2_DEFAULT_ACK_DELAY_EXPONENT;
    p->disable_active_migration = 0;
    p->active_connection_id_limit = NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT;
    p->max_datagram_frame_size = 65536;
}

/* ---- the floor the reference puts under a peer's idle timeout ---------------- */

/* quic-go refuses to take the remote's word below five seconds — `p.MaxIdleTimeout =
 * max(protocol.MinRemoteIdleTimeout, time.Duration(val)*time.Millisecond)`
 * (vendor/quic-go/internal/wire/transport_parameters.go:325-326, constant at
 * vendor/quic-go/internal/protocol/params.go:91) — and ngtcp2 applies RFC 9000's plain minimum of
 * the two sides with no such floor. A hysteria node may advertise four seconds legitimately: its
 * SERVER config accepts `must be between 4s and 120s` (vendor/hysteria/core/server/config.go:74-75,
 * default 30s at :22), so this is reachable rather than theoretical.
 *
 * ⚠️ THE CLAMP SITS INSIDE THE REFERENCE'S `case`, so it runs only when the parameter is PRESENT. A
 * peer that omits it is left alone; a peer that sends a zero is raised to five seconds like any
 * other small value. The decoded struct cannot tell those apart — "if an optional parameter is
 * missing, the default value is assigned", the contract on ngtcp2_transport_params_decode — so
 * presence is read off the wire bytes rather than inferred from the struct. */
#define LC_MIN_REMOTE_IDLE (5 * NGTCP2_SECONDS)
#define TP_MAX_IDLE_TIMEOUT 0x01u

static int tp_has_idle_timeout(const uint8_t *p, size_t len)
{
    size_t off = 0;
    while (off < len) {
        uint64_t id = 0, vlen = 0;
        if (lc_varint_get(p, len, &off, &id) != 0 || lc_varint_get(p, len, &off, &vlen) != 0)
            return 0;
        if (vlen > (uint64_t)(len - off))
            return 0;
        if (id == TP_MAX_IDLE_TIMEOUT)
            return 1;
        off += (size_t)vlen;
    }
    return 0;
}

ngtcp2_ssize lc_qtp_floor_idle(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap)
{
    ngtcp2_transport_params tp;

    /* The blob is handed on UNTOUCHED unless the floor applies, which is why this answers "nothing
     * to do" rather than always rewriting. Re-encoding drops anything ngtcp2 does not model — it
     * ignores unknown parameters when decoding (vendor/ngtcp2/lib/ngtcp2_transport_params.c:761)
     * and has nowhere to keep them — which costs nothing, since they never reached ngtcp2 either
     * way; but doing it only when the clamp fires leaves the ordinary handshake the path it was. */
    if (!tp_has_idle_timeout(in, in_len))
        return 0;
    if (ngtcp2_transport_params_decode(&tp, in, in_len) != 0)
        return 0; /* ngtcp2 refuses it a moment later, in its own words */
    if (tp.max_idle_timeout >= LC_MIN_REMOTE_IDLE)
        return 0;

    tp.max_idle_timeout = LC_MIN_REMOTE_IDLE;
    ngtcp2_ssize n = ngtcp2_transport_params_encode(out, out_cap, &tp);
    /* No second path on failure, deliberately. Falling back to the unclamped blob would mean the
     * floor silently does not apply against exactly the peer odd enough to be unencodable here — a
     * rule that holds except when it matters. A peer whose parameters this build cannot re-state is
     * one it does not understand, and the handshake stops. */
    return n > 0 ? n : -1;
}
