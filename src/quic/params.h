/* What this client advertises to the node, and nothing else.
 *
 * A separate file for the same reason the reference client keeps these in core/client/config.go
 * rather than beside the code that opens a connection: they are a statement about what we are, they
 * are read by the party on the other end, and they can be checked without a socket. test/qparams
 * checks them against the numbers that client sends.
 *
 * Everything here is visible to anyone on the path. The client's transport parameters ride in the
 * ClientHello, and an Initial packet is protected with keys derived from a connection id sent in the
 * clear — so this file is the same kind of thing as src/fp/hello.c, and a value nobody else sends is
 * a mark, exactly as argued in src/quic/shim.c about max_datagram_frame_size. */
#ifndef LC_QPARAMS_H
#define LC_QPARAMS_H

#include <ngtcp2/ngtcp2.h>

/* What a proxied connection may have in flight towards us: the receive window advertised for that
 * stream, and the size its buffer may reach.
 *
 * A window is a speed limit divided by the round trip, and that is not a subtlety — it is the whole
 * of what a single download gets. This was 64 KiB, and over a 66 ms round trip that
 * is 7.9 Mbit/s and nothing above it, no matter how fast the path is. Measured on the router
 * against a 47 Mbit/s line: 6.4 Mbit/s on one connection, three connections at once 18.2 — linear
 * in the number of connections, which is what a per-stream ceiling looks like from outside. The same
 * build with this number raised carried 33 Mbit/s on one connection and 68 on three, with the client
 * at 20 % of one core. Nothing else changed.
 *
 * The number is the reference client's, not one of ours: `defaultStreamReceiveWindow = 8388608`
 * (vendor/hysteria/core/client/config.go:15), and quic-go puts it on the wire in all three of
 * initial_max_stream_data_{bidi_local,bidi_remote,uni} (vendor/quic-go/connection.go:329). Two
 * reasons to take it rather than pick a middle number. It is what anybody comparing this client to
 * that one reads out of the ClientHello. And it is not a memory decision to make twice: the window
 * is a PROMISE, and the buffer behind it starts at LC_QTCP_RX_MIN and grows only for the stream that
 * actually receives that much — which for a browser is a small minority of them.
 *
 * What bounds memory takes two rules, and stating only the first one is how a promise this size
 * turns into two gigabytes. The first is flow control: the window is returned by TAKING, so a
 * stream whose local end has stalled stops being read and the node stops sending to it — what has
 * arrived and is not yet taken cannot exceed this on one stream, nor LC_QTCP_CONN_WINDOW across all
 * of them at once. That bounds what is IN the buffers and says nothing about the buffers, which is
 * the second rule and lives in quic/rxbuf.h: a buffer gives its room back the moment it is empty,
 * so capacity is held exactly while it is used and cannot accumulate across streams that were never
 * large at the same time. With both, the whole of what this can hold is what the node is allowed to
 * have in flight plus one floor per stream. That is the arrangement the Go client has too: memory
 * follows the bytes that arrive rather than the promise that invited them — and, as there, nothing
 * above it asks the machine first (the reserve that did, L1, is gone since 29.09). */
/* AND IT CAME BACK DOWN, BECAUSE THE PROMISE WAS ONE THIS MACHINE REFUSES TO KEEP.
 *
 * Everything above is still true and none of it is undone: 64 KiB was a ceiling on one download and
 * raising it is what took a connection from 6.4 to 33 Mbit/s. What was wrong was the SIZE of the
 * raise, and the fault it caused is not a slow download but a dead one.
 *
 * The chain, measured end to end on 2026-08-18 rather than reasoned about. A download through the
 * tunnel on the router stops after 400–700 KB, every time, with no error in the client's log at all.
 * The node says what happened: `TCP error … "stream 4 canceled by remote with error code 258"` —
 * 258 is 0x102, this client's own cancel, the LC_QTCP_LOST path. Behind it: the router cannot move
 * bytes out of the stream as fast as the node puts them in (ChaCha20 on this processor is 64 Mbit/s
 * for both directions), so the receive buffer grows — 8 KiB doubling towards this window — and
 * the memory reserve of the time (L1, gone since 29.09) refuses a step. `avail - want > total/100*10` on a box with 118 768 KB total and
 * ~18 500 KB available refuses any single step above roughly 6 700 KB and in practice much earlier,
 * so the buffer stalls a long way short of eight megabytes. Then lc_qrx_put marks `over`, and the
 * stream is reset.
 *
 * So the window has to be a size the buffer can actually reach on THIS machine. Half a megabyte is
 * one doubling below where the headroom rule starts refusing, and it costs nothing that can be
 * measured: against the 66 ms round trip to the node it is 62 Mbit/s on a single stream, above the
 * 43 Mbit/s line and at the ChaCha20 ceiling of 64. The eight-megabyte figure buys throughput this
 * hardware cannot reach and pays for it with reset downloads.
 *
 * The round trip is worth re-measuring rather than inherited: 75.7 ms from the lab router to the
 * node on 2026-08-25, not 66, which puts a single stream at 55 Mbit/s instead of 62. The conclusion
 * is unchanged — still above the 43 Mbit/s line — but the margin is thinner than the sentence above
 * suggests, and a slower path is where this number stops being free. It is the first figure to
 * check if a household ever reports a single download capped well under its line.
 *
 * ON THE FINGERPRINT, WHICH IS THE REASON THE REFERENCE'S NUMBER WAS TAKEN IN THE FIRST PLACE. The
 * header of this file is right that transport parameters are readable on the path. But this is not
 * a value nobody else sends: hysteria exposes it as `QUICConfig.InitialStreamReceiveWindow` with a
 * documented floor of 16384 (vendor/hysteria/core/client/config.go:46-50), so a smaller window is a
 * configuration the reference client supports and its users on small hardware set. What would be a
 * mark is a number outside what that knob accepts, and this is not one.
 *
 * AND THAT PARAGRAPH IS NOW A MEASUREMENT RATHER THAN AN ARGUMENT, which matters because the thing
 * it argues about — what an observer actually sees — had never been looked at. Measured 2026-08-25
 * by standing up a server built from vendor/quic-go with qlog switched on, so that the parameters
 * of both clients were recorded by the reference's own tracer, and connecting first the reference
 * hysteria client and then this one to it. What came back:
 *
 *   - the SET of parameters is identical, and so is their ORDER. Nothing we send is absent from the
 *     reference's list, nothing of the reference's is missing from ours, and nothing is reordered.
 *     That was not obvious and had been assumed the other way: two different QUIC libraries, ngtcp2
 *     here and quic-go there, could easily have disagreed about which optional parameters to omit —
 *     `internal/wire/transport_parameters.go:362-485` states the reference's order and its rule for
 *     leaving defaults out — and they do not.
 *   - six values agree exactly: max_idle_timeout 30000, max_udp_payload_size 1452,
 *     ack_delay_exponent 3, max_ack_delay 26, active_connection_id_limit 4,
 *     initial_max_streams_uni 100. disable_active_migration is false on both.
 *   - FOUR values differed at the time of that measurement, and they were the four this file
 *     chooses: initial_max_data 1 310 720 against 20 971 520, and the three
 *     initial_max_stream_data_* at 524 288 against 8 388 608.
 *
 * ✅ AND THOSE FOUR AGREE NOW TOO, so the sentence that stood here — "the entire visible difference
 * between this client and the reference at the QUIC layer is the window" — describes a difference
 * that no longer exists. Not because the argument for a smaller window was wrong, but because the
 * thing that made the reference's own number harmful was a memmove in our receive buffer rather
 * than the number; the measurements are below, at LC_QTCP_STREAM_WINDOW. Set, order and every
 * value now match. There is nothing left at this layer for a comparison to find.
 *
 * The stand is worth rebuilding rather than trusting this paragraph if the numbers here are ever
 * touched; the recipe is a Go program of forty lines against vendor/quic-go with
 * `Tracer: qlog.DefaultConnectionTracer`, and hysteria itself wires no tracer at all, so its own
 * server cannot be asked this question.
 *
 * The alternative was to keep the promise and stop cancelling — but the bytes are already delivered
 * to recv_stream_data_cb and already counted against the window by the time we find we cannot hold
 * them, so there is nothing to refuse and nothing to slow: the only choices left are a hole in the
 * stream or a reset. The place to be honest is the promise. */

/* ⚠️ AND IT IS NO LONGER ONE NUMBER FOR EVERY BOX, BECAUSE THE ARGUMENT ABOVE IS ABOUT A MACHINE.
 *
 * Everything above stands and none of it is undone. What it did not say is that all of its evidence
 * came from ONE device: "118 768 KB total", "~18 500 KB available", "ChaCha20 on this processor is
 * 64 Mbit/s", "a 43 Mbit/s line" — the Xiaomi 4A. The conclusion was right there and was then
 * applied everywhere, and the file itself named the symptom that would show it up: "the first
 * figure to check if a household ever reports a single download capped well under its line".
 *
 * That is exactly what happened, measured on an AX3000T (aarch64, 239 MB, 61 ms to the node,
 * a line above 100 Mbit/s) on 2026-09-07, one download of 20 MB through the Hysteria2 plane to the
 * same test node, three to six runs per window, CPU of our own process alongside:
 *
 *     window   single stream, Mbit/s        CPU of one core
 *     512 KiB  40 45 42                     29 %
 *     1 MiB    58 82 76 76 82 82            41 %
 *     2 MiB    44 91 75 73 65 79            46 %
 *     4 MiB    55 68 62                     61 %
 *     8 MiB    41.7, then 0, then 0         56 %   ← the dead downloads, on THIS box too
 *
 * Three things are in that table. The window was the ceiling: 512 KiB against 61 ms is 68.8 Mbit/s
 * in theory and 42 in practice, and one doubling nearly doubles the result. It stops paying almost
 * at once: 2 MiB is not better than 1 MiB and 4 MiB is worse for the processor. And the reference's
 * own 8 MiB still kills downloads on a box with twice the Xiaomi's memory, so "more RAM, take the
 * reference's number" would have been wrong — the failure is the buffer never reaching the promise,
 * and it arrives long before eight megabytes on anything we ship to.
 *
 * The proof that the client was not the thing in the way: three downloads at once through the SAME
 * client and the same 512 KiB gave 28.1 + 28.1 + 28.1 = 84.3 Mbit/s at a third of one core. Linear
 * in the number of streams is what a per-stream ceiling looks like from outside, which is the same
 * shape this file already reports for 64 KiB. Not the CPU, not the language, not the thread count.
 *
 * ✅ AND THE ANSWER TURNED OUT TO BE THE REFERENCE'S OWN NUMBER, ONCE THE REAL FAULT WAS FOUND.
 *
 * The step by RAM that stood here — 512 KiB below 192 MB, 1 MiB above — is gone, and so is every
 * argument for advertising less than the reference. What made eight megabytes harmful was never the
 * eight megabytes: lc_qrx_take compacted the whole receive buffer on every take, so the cost of
 * holding bytes grew with the window and ate the gain (see the note on `off` in quic/rxbuf.h).
 * Remove the memmove and the reference's value is both safe and best, measured on both boxes:
 *
 *     AX3000T (aarch64, 239 MB)   1 MiB  66 85 83 84 78 Mbit/s at 42 %
 *                                 8 MiB  93 128 122 109 129   at 52 %, RSS 2 416 KB
 *     reference hysteria client          92 128 115 114 125   at 69 %, RSS 38 664 KB
 *     Xiaomi 4A (mipsel, 118 MB)  8 MiB  39 27 27 28 27       at 57 %, RSS 2 412 KB
 *                                        zero memory warnings, zero resets
 *
 * The Xiaomi is the box the old dead-download story came from, and it is the one that settles it:
 * with the same eight megabytes that once killed downloads there, it now runs faster than the
 * 17-20 Mbit/s it used to manage at 84-87 % of a core, holds 2.4 MB, and refuses nothing. The
 * buffer never has to grow large any more because it drains in constant time instead of quadratic.
 *
 * So the four transport parameters that were the ONLY QUIC-layer difference from the reference are
 * now identical to it. Nothing here is a configuration of our own: initial_max_stream_data_* is
 * defaultStreamReceiveWindow (vendor/hysteria/core/client/config.go:15) and initial_max_data is
 * defaultConnReceiveWindow, its five halves (:16). A reader comparing the two clients' hellos now
 * finds nothing to compare. */
#define LC_QTCP_STREAM_WINDOW (8u * 1024u * 1024u)

/* The most the node may have in flight to us across EVERY stream at once, and so the real ceiling on
 * what this client can be made to hold.
 *
 * Stated on its own rather than derived from the connection count. Derived — which is what
 * `window * (LC_QTCP_MAX + 1)` was — it grew with the count, so raising how many connections we
 * carry silently raised how much the node was invited to send. A limit that moves with the thing it
 * limits is not one.
 *
 * ✅ THE RATIO AND THE BASE ARE BOTH THE REFERENCE'S, so this is 20 971 520 —
 * defaultConnReceiveWindow itself, and defaultStreamReceiveWindow * 5 / 2 exactly as the reference
 * writes it (vendor/hysteria/core/client/config.go:16). Nothing here is chosen by us any more: the
 * ratio is copied and the base is copied, and a reader comparing the two clients' transport
 * parameters finds the same four numbers on both sides.
 *
 * ⚠️ AND THIS PARAGRAPH HAS NOW BEEN STALE TWICE, WHICH IS THE POINT WORTH KEEPING. Until
 * 2026-08-29 it claimed the value was "the same number the reference client states" and named
 * twenty megabytes, while the line beneath it read 1.25 MiB — the stream window had come down and
 * the prose had not. It was then rewritten the other way, "THE RATIO IS THE REFERENCE'S, THE BASE
 * IS NOT … so this is 1.25 MiB and not 20", and on 2026-09-07 the stream window went back up to the
 * reference's 8 MiB (see the measurements at LC_QTCP_STREAM_WINDOW: the memmove in lc_qrx_take was
 * what made the reference's own number harmful, not the number), so the prose was false again —
 * in the opposite direction, and about the same constant.
 *
 * Both times it was the sieve and not a reader that asked, because every number in this file is
 * also an argument, and an argument does not stop compiling when it stops being true. Nothing
 * derives this value from the connection count either — `window * (LC_QTCP_MAX + 1)` grew with the
 * count, so raising how many connections we carry silently raised how much the node was invited to
 * send, and a limit that moves with the thing it limits is not one.
 *
 * Speed is still not what chooses it: what the constant costs is what a node which wanted to could
 * make this process hold before the window closed on it — now twenty megabytes rather than 1.25,
 * and that ceiling is the reference's to defend, not ours. The floor that keeps it from being
 * reserved rather than merely promised is in quic/rxbuf.h. */
#define LC_QTCP_CONN_WINDOW (LC_QTCP_STREAM_WINDOW * 5u / 2u)

/* The two clocks hysteria's client sets on quic-go: `defaultMaxIdleTimeout = 30 * time.Second` and
 * `defaultKeepAlivePeriod = 10 * time.Second` (vendor/hysteria/core/client/config.go:17-18). The first
 * is the max_idle_timeout this client states; the second is where the keep-alive interval starts,
 * before the negotiated idle time and the PTO have their say — see keep_alive_interval in quic/conn.c. */
#define LC_QCONN_IDLE_TIMEOUT (30u * NGTCP2_SECONDS)
#define LC_QCONN_KEEP_ALIVE_PERIOD (10u * NGTCP2_SECONDS)

/* THE NUMBERS A CLIENT PARROTING CHROME STATES, pinned by the fork whatever hysteria asked for:
 * "Chrome pins these, so anything the caller asked for is overridden" (vendor/quic-go/config.go:
 * 109-125, constants at vendor/quic-go/chrome_parrot.go:12-26). Six megabytes a stream and fifteen
 * a connection to START with — the ceilings stay hysteria's eight and twenty (config.go:123-124),
 * which is what lets the reference's window grow under the parrot where it cannot without it. */
#define LC_QCHROME_STREAM_WINDOW 6291456u
#define LC_QCHROME_CONN_WINDOW 15728640u

/* Fills `p` from scratch: ngtcp2's defaults first, then every value this client states — Chrome's
 * when `chrome` is set. */
void lc_qparams(ngtcp2_transport_params *p, int chrome);

/* Puts the reference's five-second floor under a peer's max_idle_timeout, if it needs one.
 *
 * Returns the length written to `out` when the peer asked for less than five seconds, 0 when its
 * parameters should be handed on exactly as they arrived, and -1 when they cannot be re-stated —
 * which stops the handshake rather than quietly skipping the floor.
 *
 * A function over bytes so it can be asked directly: the caller needs an ngtcp2_conn and a
 * completed key exchange, and a test that built those would be testing them. */
ngtcp2_ssize lc_qtp_floor_idle(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap);

#endif
