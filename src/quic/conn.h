/* One QUIC connection, driven by hand.
 *
 * ngtcp2 does not own a socket, a thread or a clock: it turns packets into events and events back
 * into packets, and everything around that is the caller's. This is that everything — the socket,
 * the loop that feeds it, and the timer it asks for.
 *
 * The crypto underneath is ours (src/quic/qcrypto.c and qtls.c), which is the whole reason this
 * exists as a separate thing rather than as ngtcp2's example client: the alternative was linking
 * OpenSSL, and OpenSSL is 4.4 MB against 5.3 MB of free flash on the target. */
#ifndef LC_QCONN_H
#define LC_QCONN_H

#include "quic/h3.h"
#include "quic/hy.h"
#include "quic/obfs.h"
#include "quic/gecko.h"
#include "quic/dgram.h"
#include "quic/params.h"
#include "quic/reasm.h"
#include "quic/rxbuf.h"
#include "quic/hop.h"
#include "quic/qcrypto.h"
#include "quic/rxopen.h"
#include "quic/sendq.h"
#include "quic/shim.h"
#include "quic/txbuf.h"
#include "quic/udptab.h"

#include <ngtcp2/ngtcp2_crypto.h>

#include <netinet/in.h>
#include <stdint.h>

/* How many proxied connections one QUIC connection carries at once.
 *
 * This used to be forty-eight, and forty-eight used to be a memory budget: each connection took its
 * whole receive window at open, so the count WAS the ceiling. Measured on a router, one desktop
 * browsing normally hit it fourteen times in a single session — every one of those a connection
 * refused to a browser that had done nothing wrong. Sixteen, the first number, was worse.
 *
 * Upstream has no such limit at all, and looking at why says what was wrong here rather than what
 * number to use instead. hysteria's client advertises eight megabytes per stream and twenty per
 * connection — `defaultStreamReceiveWindow = 8388608` and `defaultConnReceiveWindow =
 * defaultStreamReceiveWindow * 5 / 2` (vendor/hysteria/core/client/config.go:15-16) — and carries
 * as many connections as are asked of it. It can,
 * because there a window is a promise and memory follows the bytes that actually arrive. Here the
 * window was a malloc. It is not one any more, and since 2026-09-07 the numbers are not ours
 * either: quic/params.h states those same 8 388 608 and 20 971 520.
 *
 * ⚠️ THIS PARAGRAPH HAS BEEN WRONG IN BOTH DIRECTIONS, WHICH IS WHY IT KEEPS ITS HISTORY. Until
 * 2026-09-01 it claimed the reference's numbers while params.h stated a quarter of them; the
 * correction that replaced it — "512 KiB per stream and 1.25 MiB per connection … the choice is
 * still open" — outlived the choice by six days. A file that argues about a constant it does not
 * define is exposed to exactly this, so the rule for the next reader is to believe quic/params.h
 * and treat anything here as commentary.
 *
 * The cost that was stated as the reason not to raise it is worth keeping, because the measurement
 * that settled it went the other way. The objection ran: a node may then make this process hold
 * twenty megabytes per QUIC connection, which a four-worker router with forty megabytes available
 * cannot afford, so the allocator starts refusing growth — and a refusal at that point is a
 * stream reset, since the bytes are already counted against the window by the time we find we
 * cannot hold them. What it missed is that the promise is not the reservation: the buffer grows to
 * what actually arrives and gives the room back the moment it drains (quic/rxbuf.h), so what a
 * stream holds is set by how fast it is read, not by what was advertised. Measured on the smallest
 * box we ship to — Xiaomi 4A, 118 MB — the reference's eight megabytes cost 2 412 KB of RSS with
 * zero memory warnings and zero resets, against 17-20 Mbit/s at 84-87 % of a core before. The
 * thing that had made the reference's number harmful was a memmove in lc_qrx_take, not the number.
 *
 * So the difference an observer could see at the QUIC layer — four window values in transport
 * parameters, in the clear, on every connection — is gone, and choosing the window from available
 * memory at startup is no longer an option anybody needs to measure.
 *
 * So this is now an array bound and nothing more. What actually limits memory is two things that
 * bound it directly: LC_QTCP_CONN_WINDOW, which is the most the node may have in flight to us
 * across every stream at once, and the machine's own memory, which the kernel hands out and takes
 * back as it does for the reference. Both are true limits; a count never was one.
 *
 * ⚠️ AND AS AN ARRAY BOUND IT STILL REFUSED THE 257TH CONNECTION, until 2026-09-27, where the reference
 * refuses none: hysteria opens a stream per request with `c.conn.OpenStream()` and no count of its own
 * (vendor/hysteria/core/client/client.go:185-190), and the limit is the node's MAX_STREAMS — 1024 on
 * a stock server (vendor/hysteria/core/server/config.go:23). The table now grows a chunk at a time
 * (LC_QSTREAM_CHUNK) up to what a handle can index, and the node's limit is the one that bites, as
 * lc_qconn_tcp_open asks it through ngtcp2_conn_get_streams_bidi_left2 first. */
#define LC_QTCP_MAX 65531

/* ONE WRITE AT A TIME, AND WHAT IS LEFT OF IT — the seam that gives a reference client its shape.
 *
 * hysteria relays a forwarded TCP connection with plain io.Copy, whose buffer is 32 KB when neither
 * side offers WriteTo or ReadFrom (vendor/hysteria/app/internal/forwarding/tcp.go:54-58). quic-go's
 * stream then holds exactly ONE of those writes: `s.dataForWriting = p`, and the writing goroutine
 * blocks on s.writeChan until the packer has drained it to at most MaxPacketBufferSize, which is
 * then copied into s.nextFrame so that Write can return (vendor/quic-go/send_stream.go:249-322 and
 * :342-351; the constant is 1452, vendor/quic-go/internal/protocol/protocol.go:111).
 *
 * So the stream runs dry once per 32 KB of payload — 32768 bytes is 23.5 packets' worth of stream
 * data — and the remainder of about 750 bytes goes out as a short datagram before the next 32 KB
 * has been read off the socket. ONE SHORT DATAGRAM PER 32 KB, whatever the path does: predicted
 * 1 536 for the stand's 48 MB uplink and 768 for half of it, measured 1 585-1 628 over five runs
 * and 790. The arithmetic is in test/hystand/loss.sh.
 *
 * THIS CLIENT HAD NO SUCH SEAM. The uplink sat in one continuous queue, so its packets were fuller
 * and fewer — better engineering, and a DIFFERENT SHAPE: a profiler counting datagram sizes
 * separates the two on that alone, and being the same on the wire is what this client is for. So
 * the seam is reproduced, with no new state: a write is clamped so it cannot cross the next
 * multiple of LC_QTX_WRITE in the stream, and only AT such a multiple is a new one refused until
 * what is unsent has fallen to LC_QTX_CARRY. lc_qconn_tcp_send says why it is anchored to the
 * stream rather than to whatever a single call happens to offer, and what reading the rule the
 * other way cost.
 *
 * ⚠️ IT IS NOT FREE — about 3.7 % more datagrams for the same bytes, paid in packet rate on a
 * router — and the decision to pay it was the product's, not this file's. On the stand it cost
 * nothing at all: 244-526 Mbit/s after against 176-482 before, faster than the reference either
 * way. It also overshoots by half, 2 456 middle-sized datagrams against 1 641, and those extra
 * ones are not the seam but this client running dry between seams. test/hystand/loss.sh has both
 * tables. */
#define LC_QTX_WRITE 32768u
#define LC_QTX_CARRY 1452u

/* How many datagrams one send may carry.
 *
 * ⚠️ WHAT STOOD HERE CITED A CONSTANT THAT DOES NOT EXIST. It said "quic-go's own ceiling is 20 —
 * `maxPacketsPerBatch`, the bound it applies to the same UDP_SEGMENT batch (send_conn.go)". There is
 * no such identifier in the pinned revision; the `batchSize = 8` that is there belongs to the READ
 * side, the recvmmsg batch (sys_conn_helper_linux.go:24), and has nothing to do with sending.
 *
 * The real bound is a buffer size and a loop condition: the GSO path fills a large packet buffer of
 * MaxLargePacketBufferSize = 20 * 1024 bytes and appends another packet only while
 * `buf.Len()+maxSize <= buf.Cap()` (vendor/quic-go/connection.go:2632-2675,
 * internal/protocol/protocol.go:113-114, buffer_pool.go:77-92). At the 1441-byte packet this client
 * and the reference both settle on, that is FOURTEEN datagrams per syscall.
 *
 * Eight was ours, chosen for the buffer it costs per connection. The shape measurement says what it
 * cost on the wire: with batches of eight, eight in ten of our datagrams arrived in the same batch
 * as the one before, against nine in ten of the reference's, and the gap at the ninetieth percentile
 * was 126 microseconds against its 26 — the inter-batch pause, not the pace. Fourteen to match, at
 * 2056 bytes a slot: 29 KB per connection against 16, on a process whose RSS under load is 2.5 MB.
 *
 * AND FOURTEEN DID NOT CLOSE IT, which is worth writing down because it rules two things out. With
 * batches of fourteen the commonest run became exactly fourteen, as intended, and the density moved
 * from 80 % to 81 %; doubling the path's delay, which doubles the window, left it at 78 %. So the
 * remaining difference is not the congestion controller (its phases match the reference's), not the
 * pacer's arithmetic (the reference's own bucket), and not the size of a batch.
 *
 * WHAT STOOD HERE NEXT WAS REASONED, AND ON 19 SEPTEMBER IT WAS MEASURED. It said the remainder is
 * how much this loop has ready when it writes — one thread reading from the LAN, feeding the queue
 * and writing, against a goroutine for each in the reference. The counters at tx_stop_paced say it
 * on the path the density was measured on, 25 ms each way: of 19 095 passes of the write loop,
 * 13 660 ended with nothing left to write and 5 435 ended on the pace, two datagrams to a pass.
 * Seven passes in ten run dry. The loop is starved there, and the sentence stands.
 *
 * ⚠️ AND ON A PATH WITH NO DELAY IT IS THE OTHER WAY ROUND, which is why the first reading of these
 * counters said the opposite. Through test/hystand/run.sh, where nothing is ever in flight for long,
 * 51 141 of 51 626 passes ended on the pace and 485 ran dry — 0.47 datagrams to a pass. Both numbers
 * are real and they are different regimes: with no window outstanding the bucket decides everything,
 * with one outstanding the feed does. The density figure belongs to the second, so that is the one
 * to quote here, and a counter read on run.sh answers a different question than it was asked.
 *
 * WHAT THE RELAY SEES OF THE SAME THING, and it is not the shape one would guess from "starved": our
 * commonest run is 297 batches of exactly fourteen, the reference's are runs of two, four and three
 * — it writes small groups almost continuously while this client writes full batches with pauses
 * between them, and the pauses are the whole difference (ninetieth-percentile gap 129 µs against
 * its 40).
 *
 * ⚠️ AND THE PACING GATE IS NOT THE DIFFERENCE, checked so that it is not checked again: the
 * reference asks the same question on every wakeup this loop asks on — HasPacingBudget(now), the
 * budget accrued since the last send against one datagram
 * (vendor/quic-go/internal/ackhandler/sent_packet_handler.go:1094-1096). Its MinPacingDelay floor
 * lives in TimeUntilSend, which sets the timer and not what a wakeup from somewhere else may do,
 * exactly as it does here.
 *
 * HALF OF IT IS NOW CLOSED, and by feeding the loop rather than by changing what it does. The
 * reference's uplink is io.Copy in a goroutine — read, write, read again, never going anywhere
 * else — while the read here happened once per event and then went round the whole turn, so a turn
 * moved 8 KB, which is 5.7 datagrams against a batch of fourteen. The read now rounds like io.Copy
 * does, handing each bufferful to the stream before taking the next — HY_READ_ROUNDS in
 * cmd/lc-tunnel/main.c at the time, since replaced by the reader thread of net/reader.c, which
 * reads as much as there is room for. Measured on the same path the same day: density 81 % to
 * 86 % against the reference's 93, passes of this loop 19 095 down to 11 987, and full batches of
 * fourteen 297 up to 884 with runs of twenty-four appearing for the first time.
 *
 * WHAT IS LEFT IS THE CONCURRENCY ITSELF, and it shows in the shape rather than in the total: the
 * reference's commonest runs are two, four and three datagrams, ours are fourteen and twenty-four.
 * It writes small groups continuously because its bytes arrive continuously; this client fills a
 * batch, writes it, and goes to fetch more. Feeding it twice as much per turn was tried and made
 * that worse, not better — eight rounds instead of four gave bigger bursts with longer gaps between
 * them, 85 % and a ninetieth percentile of 168 µs against 144. So the remainder is not a constant
 * either, and closing it meant the loop reading while it writes — which is what the reader thread
 * (net/reader.c) and the writer thread (quic/sendq.c) now do. CONCURRENCY.md has the numbers:
 * 94-95 % against the reference's 96-97 % once the pacer was charged once. */
#define LC_GSO_BATCH 14u
/* One entry of the send queue holds a whole batch, so the two sizes are one number. See quic/sendq.h,
 * which also holds the frames of one Gecko packet in a single entry. */
#if LC_GSO_BATCH != LC_SENDQ_DGRAMS
#error "a send queue entry must hold exactly one GSO batch"
#endif

/* Every stream this connection can hold at once: four slots for HTTP/3 — two of them used, the
 * control stream and the request (see `st` in lc_qconn) — plus the proxied connections. */
#define LC_QSTREAM_MAX (4 + LC_QTCP_MAX)

/* The table is allocated in chunks of this many slots as streams are opened, and a chunk never moves
 * once made — see slot_take. */
#define LC_QSTREAM_CHUNK 64u
#define LC_QSTREAM_CHUNKS ((LC_QSTREAM_MAX + LC_QSTREAM_CHUNK - 1u) / LC_QSTREAM_CHUNK)

/* What a connection costs at open is LC_QTCP_RX_MIN, not the window — see quic/rxbuf.h, which owns
 * that number and the rule that returns a stream to it. The two windows live in quic/params.h,
 * where the rest of what this client states about itself lives. */

/* And the other way: the MOST we hold for a connection whose bytes ngtcp2 has not taken yet, because
 * congestion control or the node's own window says not now. Small on purpose — when this fills, the
 * answer is to stop reading from the local socket, which costs nothing and is what backpressure is
 * supposed to feel like. */
/* ⚠️ AND IT IS WHAT BOUNDS AN UPLOAD, WHICH IT WAS NOT UNTIL 2026-08-30.
 *
 * The queue holds bytes until they are ACKNOWLEDGED — ngtcp2 points into them for retransmits — so
 * the most that can be outstanding on one stream is this number, and the rate is that over the
 * round trip. A flat buffer could not reach it: giving room back meant sliding the rest down over
 * the region ngtcp2 was pointing into, so both growing and reclaiming had to wait for the buffer to
 * be idle, and on an uploading stream that moment never comes. It froze at whatever the first write
 * needed — READ_CHUNK, 8 KB.
 *
 * ⚠️ AND THE MEASURED NUMBER HAS TWO CANDIDATE CAUSES, OF WHICH THAT IS ONE. The 0.6 Mbit/s upload
 * was read off the router against a stand abroad on 2026-08-27 at a 175 ms round trip — about
 * 13 KB in flight — beside REALITY's 18.2 up on the same box in the same hour. A frozen 8 KB queue
 * fits it, and so does a congestion window stuck near its initial ten packets, which is what the
 * note of the day concluded. Nobody separated them: that needs the same upload at a second round
 * trip, and the only other node available does not run this plane. quic/txbuf.h carries the full
 * account.
 *
 * quic/txbuf.c is a list of immovable blocks now, so the front is released while the back is still
 * in flight and the window stays full instead of draining to empty. Raising this constant therefore
 * DOES change the rate, and raises the budget line below by the same factor.
 *
 * ⚠️ AND ON 2026-09-07 IT WAS RAISED SIXTEENFOLD WITHOUT THIS LINE BEING EDITED, because it is
 * written as the receive window and the receive window went back to the reference's eight megabytes
 * (quic/params.h). The clause that stood here — "which is the reason it has not been raised" — was
 * false from that commit onward, and the budget table below was wrong with it. A constant defined
 * as another constant carries that one's arguments too, and they are not reread when it moves.
 *
 * ✅ THE ALIAS IS THE REFERENCE'S OWN SYMMETRY AND NOT A COUPLING OF CONVENIENCE, which is why it
 * stays. hysteria writes the same 8388608 on both sides — client defaultStreamReceiveWindow
 * (vendor/hysteria/core/client/config.go:15) and server defaultStreamReceiveWindow
 * (vendor/hysteria/core/server/config.go:20) — with the same five halves on the connection under
 * each (:16 and :21). So what this queue may hold is exactly what the node permits to be
 * outstanding: the two bounds are equal by construction, where before ours was a guess a quarter of
 * the way under the peer's. The server refuses a configured value below sixteen kilobytes outright
 * (:54-55), so it cannot quietly advertise less than this assumes.
 *
 * ⚠️ WHAT IT MAY COST IS NOT WHAT IT RESERVES, and that is what makes the raise affordable rather
 * than the arithmetic below. Blocks are allocated as an upload proves it needs them, so a
 * connection that writes a request and reads a reply holds one
 * LC_QTCP_TX_MIN block and nothing else.
 *
 * MEASURED END TO END SINCE, which this said it was not, and why: when it was written the router's
 * Hysteria2 credentials no longer authenticated against the node. The upload has since been
 * measured on the Xiaomi 4A — 2.45-2.56 MB/s with the writer thread (CONCURRENCY.md, 2026-09-21) —
 * and one way on the stand against the reference server, 242-326 Mbit/s against the reference
 * client's 210-257 (test/hystand/loss.sh). The accounting is tested in test/qtx, and the case that
 * fails on a return to the flat buffer is named there. The derivation stands on this tree's own
 * code and on ngtcp2's documented contract. */
#define LC_QTCP_SENDBUF LC_QTCP_STREAM_WINDOW

/* The most this client may hold for sending across EVERY stream at once, and so the real ceiling on
 * what an upload can cost it.
 *
 * ⚠️ STATED ON ITS OWN, NOT DERIVED FROM THE STREAM COUNT, and that is the whole reason this
 * constant exists. The send side's budget read `LC_QTCP_MAX x LC_QTCP_SENDBUF` — a limit that grew
 * with the number of connections carried, so raising how many we serve silently raised how much
 * memory an upload could take. The RECEIVE side already fixed exactly this and says so at
 * LC_QTCP_CONN_WINDOW: "a limit that moves with the thing it limits is not one." The send side was
 * left repeating it, which is the same asymmetry this tree caught once before when the receive half
 * had been taught to grow and the send half had not.
 *
 * The ratio is the receive side's, because the question is the same one: how many streams may be
 * near their own ceiling at once before the box is the thing that gives way.
 *
 * What makes it affordable is quic/txbuf.c. While the send buffer was one block per stream, this
 * number was memory RESERVED; now blocks are allocated as an upload proves it needs them, so it is
 * memory the client MAY take, and only for the streams
 * that actually upload. A connection that writes one request and reads a reply — the ordinary case
 * — still holds one block of LC_QTCP_TX_MIN and nothing more. */
#define LC_QTCP_SENDBUF_CONN (LC_QTCP_SENDBUF * 5u / 2u)

/* And what it costs before then. Every proxied connection begins by writing one TCPRequest and
 * nothing else, so the first block is exactly big enough for that; connections that go on to upload
 * add blocks of LC_QTCP_TX_BLK as they prove they need them, up to LC_QTCP_SENDBUF. A connection
 * that never says more than a request never allocates a second block, which is the ordinary case.
 *
 * This was the sendbuf itself until the review that found it: the receive side had been taught to
 * grow and the send side had not, while the comment two blocks down claimed both had. Sixteen
 * kilobytes times however many connections are carried is the same mistake the count-as-budget was,
 * left standing in the half nobody re-read. */
#define LC_QTCP_TX_MIN LC_HY_TCP_REQ_MAX

/* How much a send queue allocates at a time once it is past that first request. Four kilobytes
 * makes a full queue four blocks at LC_QTCP_SENDBUF, which is few enough that walking the list
 * costs nothing and many enough that a block is released — and its room handed back — several
 * times per round trip rather than once. It is the granularity of RECLAIM, not of sending: ngtcp2
 * is offered every run the queue holds, so a packet is never cut short at a block boundary. */
#define LC_QTCP_TX_BLK (4u * 1024u)

/* Where a slot is in its life. Two booleans stood here — `open` and `closing` — and every reader
 * had to know which combinations were meant to exist: not-open-but-closing never was, and nothing
 * said so. One field with three values says it once.
 *
 *   FREE ──slot_take──▶ OPEN ──lc_qconn_tcp_close──▶ CLOSING ──end-of-stream sent──▶ FREE
 *
 * CLOSING is not a formality: the owner has let go, but the bytes it queued and the end-of-stream
 * that follows them are still ngtcp2's to deliver, and the slot cannot be reused until they have
 * gone. A handle stops working the moment the slot leaves OPEN. */
typedef enum {
    LC_QSLOT_FREE = 0,
    LC_QSLOT_OPEN,
    LC_QSLOT_CLOSING
} lc_qslot_state;

/* And what is owed to the peer on the sending side, which is a different question from whether the
 * slot is still ours: a stream can be OPEN with its end-of-stream already sent. */
typedef enum {
    LC_QTX_NONE = 0,    /* nothing said about the end of this direction */
    LC_QTX_FIN_PENDING, /* we owe the peer an end-of-stream */
    LC_QTX_FIN_SENT     /* ngtcp2 has it and will deliver it */
} lc_qtx_state;

/* One stream, whichever kind. The HTTP/3 exchange and the proxied connections share this because
 * ngtcp2 does not distinguish them: data arrives by stream id, and something has to know which
 * buffer that id belongs to. */
typedef struct {
    int64_t        id;
    lc_qslot_state state;

    /* Which use of this slot this is. Part of every handle, so that one issued for a stream that
     * has ended cannot address the one that took its place. */
    unsigned gen;
    /* Its place in the table, which a handle carries: the table is in chunks, so it cannot be worked
     * out from the address (see HANDLE_OF). Set by slot_take. */
    unsigned idx;

    /* Outbound. `tx` points either into the connection's small arena, for the HTTP/3 streams whose
     * contents are written once and never grow, or at a buffer this stream owns. */
    /* Who may touch which part of this, and why it is not simply a buffer and a length, is the whole
     * subject of txbuf.h. Short version: what ngtcp2 has accepted and not had acknowledged, it is
     * still pointing at. */
    lc_qtx       tx;
    lc_qtx_state tx_fin;
    /* Where the current write of LC_QTX_WRITE began, as an absolute stream offset: the reference's
     * seam, counted on the stream rather than on whatever one call offers. Set on the first payload
     * write, which is after the request block this queue was handed, so the units start where the
     * reference's io.Copy starts. See lc_qconn_tcp_send. */
    uint64_t     tx_seam;
    /* Passed over for the rest of the current flush, because ngtcp2 refused it for a reason that
     * belongs to this stream: its window is full, or its write side is closed. Not a connection
     * failure, and treating it as one ended the whole tunnel every time a proxied request
     * finished. Cleared at the start of every flush. */
    int      tx_skip;

    /* Inbound. The buffer and the rule about how large it may be, and for how long, are in
     * quic/rxbuf.h — that rule is what makes the advertised window affordable. */
    lc_qrx rx;
    int    rx_fin;

    /* Proxying only: until the node's reply has been read, the bytes on this stream are that reply
     * and not the connection's. */
    int  reply_read;
    int  refused;
    /* The reply could not be read as one — see LC_QTCP_CLOSED. */
    int  reply_bad;
    /* Set when a run of bytes the node was entitled to send could not be held: the machine refused
     * the memory. Kept apart from `refused`, which is the NODE saying no — attributing a local
     * limit to the far end is how an operator ends up looking at the wrong end of the wire. */
    int  lost;
    /* Set by stream_close_cb: ngtcp2 is done with this stream and will not call about it again. A
     * slot let go AFTER that has nobody left to release it — see lc_qconn_tcp_close. */
    int  nc_closed;
    /* Whether the buffers belong to this stream or to the connection's arena. Kept apart from the
     * slot's own state on purpose: a slot can be taken and given back many times, and what it does
     * with rx/tx on the way out depends entirely on where they came from. */
    int  owned;
    char why[128];
} lc_qstream;

/* The largest datagram this connection will read. A QUIC packet from our node fits the path MTU
 * by construction — see the note at the receive loop in conn.c — so this bounds a stack frame
 * rather than the protocol. */
#define LC_QCONN_PACKET_MAX 2048u

/* LC_QUDP_FRAGS and the state a half-arrived packet occupies live in quic/reasm.h, with the rules
 * that govern them. They are there rather than here so that a test can reach them: what happens to
 * fragments after the parser has passed them is the worst-fed logic in this client, and for as long
 * as it sat in conn.c nothing could ask it anything. */

/* What one datagram may carry, and the two wrappers that decide it, live in quic/dgram.h —
 * LC_QUDP_FRAME_OVERHEAD, LC_QUDP_PACKET_OVERHEAD, LC_QUDP_PAYLOAD, LC_QUDP_TX_MTU and
 * LC_QUDP_SLOT, with lc_qudp_fit doing the arithmetic. They are there rather than here so that a
 * test can reach them: the version of those numbers that was wrong by fifty-seven bytes was
 * unreachable from any suite for as long as it lived in conn.c. */


/* Datagrams waiting to go out. A datagram that will not fit here is dropped rather than queued,
 * which is what UDP means: the alternative is holding packets long enough that delivering them is
 * worse than not. */
/* Datagrams waiting to go out, and the number is the reference client's.
 *
 * It was sixteen, chosen without evidence, and the evidence arrived the day a counter was put on the
 * drop: a browser speaking HTTP/3 through this tunnel lost 196 datagrams in thirty-six minutes,
 * every one of them here rather than on the path. quic-go's own send queue is maxDatagramSendQueueLen
 * = 32 (vendor/quic-go/datagram_queue.go:13). Thirty-two costs eighteen more kilobytes.
 *
 * AND WHAT HAPPENS WHEN IT IS FULL IS NOT DROPPING, which is what stood here and was read out of
 * first principles rather than out of the reference. quic-go says it in the comment on Add: "Once
 * that limit is reached, Add blocks until the queue size has reduced" (same file, :44-47) — the
 * goroutine reading that session's socket stops reading, and the burst waits in the kernel's
 * receive buffer instead of being thrown away. The argument for dropping — that a datagram held
 * long enough to arrive late is one its sender has given up on — is sound about holding it HERE,
 * for as long as it takes, and says nothing about a wait bounded by a socket buffer: the shared
 * listener runs on the system default, so on the target device that is about a hundred and thirty
 * datagrams, or a seventh of a second at the rate where this begins to matter.
 *
 * The gate that does it lives in the loop, in lc-tunnel's main.c, because only the loop can stop
 * reading a descriptor. Dropping remains the last resort for a datagram already in hand.
 *
 * Whether thirty-two is enough is not asserted here. The counter that produced this number is still
 * in the summary line, and it is what says so. */
#define LC_QUDP_QUEUE 32

/* What all of this can cost at once, spelled out because on a router it is the whole question.
 *
 * Received TCP: LC_QTCP_CONN_WINDOW, whatever the number of streams  = 20 480 KB
 * Sent TCP:     LC_QTCP_SENDBUF_CONN, whatever the number of streams  = 20 480 KB
 * Proxied UDP:  LC_HY_UDP_MAX for each session holding half a packet  =  4 KB each
 * Send queue:   LC_QUDP_QUEUE x LC_QUDP_SLOT  = 32 x 1243 B          =     39 KB
 *                                      per connection  = 40 999 KB + 4 KB a session reassembling
 *
 * That queue line read "20 KB" until 2026-09-01 and had been wrong twice over: it was computed when
 * the queue was sixteen slots, and it was never updated when the queue doubled to thirty-two on the
 * reference's number. A budget that is not recomputed when its own factors change is a budget only
 * in the sense that it is written down.
 *
 * ⚠️ AND THE ROUTER CAN PAY THAT FOUR TIMES, WHICH THIS TABLE DID NOT SAY UNTIL 2026-08-30. Every
 * line above is one CONNECTION, and lc-tunnel forks a worker per core when it is asked to — four on
 * the MT7621 this ships to, each with its own connection and its own buffers.
 *
 * "When it is asked to" is the part this said as though it were automatic, and on THIS plane it is
 * not: the shipped `option workers ''` (package/files/lite-client.config:165) leaves the count to
 * lc-tunnel, which runs one worker on the Hysteria2 plane unless -w says otherwise — one per CPU is
 * the REALITY default only (main.c, just before `supervise`). And since 2026-09-24 the packaged
 * init REFUSES any other value on this plane (its `workers` check, before -w is passed): every
 * worker would be its own session with the same password, and a server that
 * keeps one session per subscription closes the rest. So the four-fold figure below is
 * reachable only by running lc-tunnel by hand with -w — not what a box pays, and not what the
 * packaged service can be told to pay —
 * which matters, because a worst case quoted as the normal case is the kind that gets budgeted
 * against and then argued from. The worst case of that hand-run is therefore about
 * 164 MB, not 41, and that is the number any question of the form "can we afford a bigger
 * window" has to be asked against.
 *
 * ⚠️ AND THAT NUMBER IS LARGER THAN THE ROUTER, WHICH IS THE POINT RATHER THAN A CONTRADICTION.
 * Measured on that router 2026-08-30 while it was serving the household: 118 MB total, 31.5 MB
 * MemAvailable, and the five processes together resident in 15 MB. Against the windows of that
 * date the worst case came to 10.7 MB and the paragraph here called it "about a third of what the
 * box has spare — affordable", and added that doubling either window "puts it past half". Both
 * windows then went up sixteenfold, so on the same arithmetic the ceiling is now 164 MB on a box
 * with 118, and the honest reading is that this table stopped being a budget the moment the client
 * stopped reserving. It is a promise: what a node which wanted to could make four workers hold
 * before their windows closed on it, not what they take.
 *
 * What bounds it in fact is two things that are measured rather than derived. Buffers follow the
 * bytes that arrive and give the room back on drain (quic/rxbuf.h) or on acknowledgement
 * (quic/txbuf.c). Under one download saturating the line the resident set was 2 416 KB on the AX3000T and
 * 2 412 KB on the 118 MB Xiaomi, with zero memory warnings and zero stream resets — four decimal
 * orders below the ceiling in this table. The reference client, holding the identical windows, was
 * resident in 38 664 KB on the same run.
 *
 * So the question "can we afford a bigger window" is not answered from this arithmetic any more,
 * and the line that used to answer it is retired rather than updated: what to watch is
 * the allocator refusing growth, because a refusal there is a stream reset — the bytes are
 * already counted against the window by the time we find we cannot hold them.
 *
 * ⚠️ It is also, one level up, the very shape the two lines above were rewritten to avoid: a limit
 * multiplied by however many of something we happen to run. The difference is that the worker count
 * is fixed at start from the core count rather than growing with load, so it is a multiplier that
 * can be written down honestly — but only if it IS written down, which is what this paragraph is
 * for.
 *
 * The first line is the one that changed shape. It no longer multiplies by the number of streams,
 * because the node cannot send more than the connection window no matter how many it opens — the
 * count and the memory came apart, which is the whole point of the change.
 *
 * And its NUMBER has now been wrong three times, which is why it is derived in words as well as
 * written: it is LC_QTCP_STREAM_WINDOW × 5/2 and nothing else. It read 4 096 KB while the window
 * was eight megabytes — where 20 480 KB was the truth — then 4 096 KB again after the window came
 * down to half a megabyte, where 1 280 KB was; it was corrected to 1 280 KB, and on 2026-09-07 the
 * window went back to the reference's eight megabytes and left it wrong in the first direction
 * again. Three times out of three the constant moved and the table did not. A budget table nobody
 * recomputes is a budget nobody has; when either window moves, this line moves with it or it is
 * worse than absent.
 *
 * The second line still multiplies, and is a worst case that does not happen: a send buffer fills
 * only for a connection uploading faster than the node drains, and it starts at LC_QTCP_TX_MIN —
 * the size of one request, which until the review that caught it was this whole sixteen kilobytes.
 *
 * The third line read 2 048 KB for a long time, on the arithmetic 32 x 64 KB. LC_HY_UDP_MAX is four
 * kilobytes and not sixty-four, so the truth is a sixteenth of what was written — and it survived a
 * rewrite of this very block, because the line was carried across instead of checked. It made the
 * UDP path look like the expensive half when it is the cheapest thing here.
 *
 * Every buffer here is taken as bytes arrive and given back when the connection closes; measured
 * resident use on a router with a household's worth open is under two megabytes.
 *
 * Nothing sits above it any more: a reserve that refused growth and new connections while the
 * machine had less than a tenth of itself available was taken out on the maintainer's word, 29.09 (L1),
 * because the reference has none. On a box that is short, the kernel decides, for both. */

/* Where a reassembled packet goes. A callback rather than a queue: a datagram that cannot be handed
 * on this instant is a datagram to drop, and a queue would only be a way of dropping it later. */
/* Asked when the write loop finds ngtcp2 with nothing left to put in a packet, and answered with
 * nonzero if the callback put bytes on a stream.
 *
 * WHY THE WRITE LOOP ASKS AT ALL, instead of returning to the event loop as it did. The reference's
 * writer is a goroutine blocked inside Stream.Write; the moment the packer takes the last frame it
 * holds, `signalWrite` releases that goroutine, it hands over the next buffer, and the send loop
 * carries on in the same cycle (vendor/quic-go/send_stream.go:307-322, 492). Nothing schedules it —
 * it was already waiting. Here the same bytes are staged by the reader thread and handed to the
 * stream by the tunnel, which used to happen exactly once per turn of the event loop: ngtcp2 ran
 * out, the loop returned to poll, and the next feed waited for whatever woke it.
 *
 * What that cost, read off a live router carrying Hysteria2 on 2026-09-20: of 6063 passes of the
 * write loop during a 20 MB upload, 1870 ended with nothing left to write. That is the counter
 * tx_stop_dry, and it is the one number three earlier attempts at "feed it more" never moved,
 * because all three were about how much the READER stages — which was never the bottleneck. The
 * hand-off was.
 *
 * The callback may not close a session or touch the event loop: it runs inside lc_qconn_step, from
 * inside the write loop, with a packet possibly half-built. Staging bytes on a stream is all it is
 * allowed to do, and all it needs to do. */
typedef int (*lc_qrefill_fn)(void *user);


/* One packet of a UDP session, whole, for the client. 0 when it went — or was dropped, as a UDP
 * packet may be — and 1 when the client's socket was full: the callee keeps the packet and waits for
 * the socket, as the reference's writer waits in conn.Write, and the session holds what arrives next
 * until lc_qconn_udp_resume (see LC_QUDP_CHAN). It may not open or close a session: it runs inside
 * lc_qconn_step. */
typedef int (*lc_qudp_fn)(void *user, int session, const char *addr, const uint8_t *data,
                          size_t len);

typedef struct {
    int fd;

    /* The socket the PREVIOUS hop used, kept open and still read from.
     *
     * Not an optimisation — it is the difference between hopping and losing a window of packets
     * every time we hop. When the source port changes, the node goes on sending to the old one
     * until a packet from the new one reaches it and it updates where this client is; everything
     * already in flight, plus everything sent during that round trip, arrives at the port we just
     * left. Closing it at once throws all of that away.
     *
     * The reference keeps exactly one generation for exactly this reason, and says so at
     * vendor/hysteria/extras/transport/udphop/conn.go:186-192: "We need to keep receiving packets
     * from the previous connection, because otherwise there will be packet loss due to the time gap
     * between we hop to a new port and the server acknowledges this change. So we do the following:
     * Close prevConn, move currentConn to prevConn, set newConn as currentConn, start recvLoop on
     * newConn." One generation and no more: by the second hop the node has long since moved on, and
     * an unbounded chain would be a growing set of open sockets on a device with few to spare.
     *
     * Sending always uses `fd`. This one only ever receives. -1 when there has been no hop yet. */
    int prev_fd;
    /* AF_INET or AF_INET6, so the ECN control message names the right level. */
    int family;
    /* The application error code CONNECTION_CLOSE carries. 0x100 ordinarily, 0x101 when the
     * node refused our authentication — hysteria keeps the two apart and so does this. */
    uint64_t close_code;
    /* The TLS alert ngtcp2 was handed when our own TLS refused the node, or 0. Kept because the
     * close is written later and somewhere else: storing the alert on the connection is only half
     * of what the reference does, and this is the other half. */
    uint8_t  tls_alert;
    /* The ngtcp2 error that ended the connection, when one did, or 0.
     *
     * ⚠️ THE OTHER HALF OF THE SAME SHAPE, AND IT WAS MISSING. The reference splits every failure of
     * ngtcp2_conn_read_pkt in two — a crypto failure becomes a TLS alert, anything else becomes the
     * library error itself:
     *
     *     if (rv == NGTCP2_ERR_CRYPTO) {
     *       ngtcp2_ccerr_set_tls_alert(&c->last_error, ngtcp2_conn_get_tls_alert2(c->conn), NULL, 0);
     *     } else {
     *       ngtcp2_ccerr_set_liberr(&c->last_error, rv, NULL, 0);
     *     }        (vendor/ngtcp2/examples/simpleclient.c:383-389)
     *
     * This client kept only the first branch, so a PROTOCOL_VIOLATION, a FLOW_CONTROL_ERROR or a
     * FRAME_ENCODING_ERROR left as an APPLICATION close (frame 0x1d) carrying hysteria's "nothing
     * went wrong" 0x100, where every other client on this stack sends a TRANSPORT close (frame
     * 0x1c) with the real code. Both the frame type and the number are on the wire, in the clear to
     * anything that parses QUIC. Found by the sieve, 2026-09-06. */
    int      lib_err;

    ngtcp2_conn *conn;
    lc_qshim     shim;

    /* Applied to every datagram in both directions, or a no-op when the node does not use it. */
    lc_obfs obfs;
    /* Beside it rather than inside it, because the two are layers and not variants: Gecko frames
     * the packet and Salamander scrambles each frame. Off, it costs one comparison per datagram. */
    lc_gecko gecko;

    struct sockaddr_storage local_addr, remote_addr;
    socklen_t               local_len, remote_len;
    /* Where datagrams are addressed NOW: remote_addr with the port the last hop moved to. The socket
     * is not connected — see dial_node — so every send names this, and remote_addr stays what ngtcp2
     * was given as the path, which a hop does not change. */
    struct sockaddr_storage peer_addr;

    /* When a packet from the node was last ACCEPTED BY ngtcp2 — which is to say, decrypted with keys
     * only the node has. See lc_qconn_silent_ms.
     *
     * Not "last unscrambled with our key", which is what stood here and what the receive loop used
     * to mean. Salamander is XOR with no authenticator, so it unscrambles anything; the sentence
     * described a check that does not exist. */
    uint64_t last_rx_ms;

    /* Datagrams that reached this socket and that ngtcp2 threw away — a wrong obfuscation key, a
     * scanner, a stray packet from some other flow. It is the one number that tells a path which
     * dropped the node's packets apart from an obfuscation that stopped agreeing with the node's:
     * two faults identical from every other angle.
     *
     * It used to count datagrams that failed to unscramble, and that number was structurally almost
     * always zero — see lc_obfs_unwrap, which fails on length and on nothing else. The diagnosis the
     * comment promised was never once available. */
    uint64_t rx_foreign;

    /* Every datagram taken off the socket, ours or not. The tunnel compares it across a step to
     * learn whether the step brought anything that its sessions have not been offered yet. */
    uint64_t rx_datagrams;

    /* WHY THE WRITE LOOP STOPPED, counted, because the two reasons mean opposite things and the
     * shape measurement cannot tell them apart from outside.
     *
     * `tx_stop_paced` is the reference's own answer: the token bucket said the budget is spent, the
     * connection's timer carries the moment it refills, and a gap on the wire after that is the
     * pace working.
     *
     * ⚠️ EXCEPT THAT THE REFERENCE DOES NOT LEAVE EMPTY-HANDED THERE, AND THIS LOOP DOES. When its
     * send mode comes back pacing-limited, quic-go parks the deadline and then sends ONE MORE
     * packet — an acknowledgement on its own:
     *
     *     case ackhandler.SendPacingLimited:
     *         ...
     *         c.pacingDeadline = deadline
     *         // Allow sending of an ACK if we're pacing limit.
     *         ...
     *         return c.maybeSendAckOnlyPacket(now)
     *                              (vendor/quic-go/connection.go:2496-2505)
     *
     * Measured through the impairing relay on 2026-09-20, same transfer, both clients: datagrams
     * under 300 bytes were 15.6 % of what the reference put on the wire and 4.8 % of ours — 7 507
     * against 1 868. The difference, 5 639, is the same order as this counter on that run (3 451
     * stops on the pace), and it is the whole of the shape gap that three separate changes to the
     * FEED never moved: the reference's "runs of two and three datagrams" are an ACK riding beside
     * full packets, not a short burst of data, and its back-to-back density is higher because those
     * small packets fill the moments when neither client is allowed to send data.
     *
     * IMPLEMENTED, AND IT DID NOT CLOSE THE GAP. ngtcp2 turned out to have the writer already —
     * `conn_write_ack_pkt`, reached from the branch its OWN pacer guards, which patch 0009 made
     * unreachable by moving pacing out of the library. Patch 0010 exposes it; the loop calls it
     * here and charges the bucket for what goes out, as the reference does.
     *
     * Measured the same way, after: small datagrams went from 4.8 % of what this client sends to
     * 6.9 %, against the reference's 17.7 %, and the back-to-back density did not move — 82 %,
     * inside the noise of the 83-86 % it has been. So the branch was real and faithful, and it is
     * a quarter of the difference at most.
     *
     * WHAT THAT LEAVES, ASKED OF VENDOR AND ANSWERED BY IT. Both clients queue an acknowledgement
     * on the same rule (patch 0003 is quic-go's, two ack-eliciting packets), so the gap is not
     * WHETHER but WHEN — and the answer is that NOTHING wakes the reference's send loop, because it
     * never gets far from the top of the run loop. Its send cycle writes one batch, asks whether a
     * packet has arrived meanwhile and returns if one has; the run loop reads up to thirty-two and
     * calls triggerSending again, which asks the pacer FIRST and, finding it out of budget, sends
     * the acknowledgement those thirty-two have just made due (vendor/quic-go/connection.go:
     * 2486-2505, 2622-2628, 2683-2689). This loop instead wrote until the bucket ran out, by which
     * time the acknowledgement had always found a data packet to ride in. The rule is now here too:
     * see rx_waiting in conn.c and tx_stop_yield below.
     *
     * AND IT DID NOT MOVE THE WIRE EITHER. Measured 2026-09-20 over five runs of the clean stand,
     * two without the rule and three with (the table is in test/hystand/loss.sh): back-to-back
     * density 87, 88 % without against 86, 90, 87 % with; small datagrams 3.2, 2.1 % against 1.4,
     * 2.7, 1.8 %; round-trip throughput no worse. The reference across those same five runs sat at
     * 93, 94, 93, 93, 94 % — IT is the steady one, and what swings is this client.
     *
     * ⚠️ AND THE PARAGRAPH THAT STOOD HERE NEXT WAS WRONG, and a one-way measurement is what showed
     * it. It said the remainder was NOT about acknowledgements at all — that the reference simply
     * sent more datagrams, each smaller (41 764-44 223 against 36 339-38 532, a mean of 1253-1293
     * bytes against 1373-1417, 9-10 % under 300 bytes against 2 %), and was denser back-to-back for
     * that reason. Every transfer the stand made was symmetric then, so both clients were also
     * acknowledging a return stream, and that mixture is exactly what those numbers could not take
     * apart. With the far end made a sink (SINK=1 in test/hystand/loss.sh), the reference sends
     * 39 239 datagrams against our 38 513, at a mean of 1380 bytes against 1369, with 0.9 % under 300
     * bytes against 0.2 %. So its extra small datagrams WERE acknowledgements, and "more, smaller"
     * was theirs too.
     *
     * What survives the one-way measurement is the density itself — 97 % against 90 — and its
     * shape: our datagrams arrive in runs of exactly fourteen, one GSO batch at a time, where the
     * reference's arrive in long runs of no particular length. loss.sh lists what that has been
     * tested against and ruled out.
     *
     * The 32 KB seam found on the way is real and holds: hysteria relays with io.Copy's 32 KB buffer
     * and quic-go's stream holds one such write at a time, so every 32 KB of payload ends in a short
     * datagram — predicted 1 536 for this stand's uplink and 768 for half of it, measured 1 585-1 628
     * and 790. It is reproduced here (LC_QTX_WRITE); it is simply not the density.
     *
     * `tx_stop_dry` is ours alone, and since 2026-09-20 it means something narrower than it says:
     * ngtcp2 had nothing left to put in a packet AND the tunnel had nothing to add when asked. The
     * loop asks now rather than returning to the poll — see lc_qrefill_fn in conn.h and hy_refill
     * in cmd/lc-tunnel/main.c — so this counts only the passes where both were empty, and it fell
     * by three quarters when the ask was added. What follows such a pass is the work between two
     * writes rather than any decision about when to write.
     *
     * The note at LC_GSO_BATCH says the remaining density difference against the reference is "how
     * much this loop has ready when it writes". That sentence was reasoned; these two counters are
     * what measured it, and the answer turned out to depend on the path — seven passes in ten run
     * dry through the impairing relay, one in a hundred through a path with no delay at all. So
     * read them together with the path they were read on, and read the ratio rather than either
     * number: they are counted for every pass, including the ones that write nothing. */
    uint64_t tx_stop_paced;
    uint64_t tx_stop_dry;
    /* The third way a pass ends, and leaving it uncounted made the other two a lie: the socket
     * would not take the packet, so the batch was held and the pass returned. It is rare on a stand
     * and it is not rare on a router with a full send buffer — which is exactly the box whose
     * summary somebody reads. Without it, "passes" was the sum of two of three, and datagrams per
     * pass was divided by a denominator that skipped precisely the passes that carried least.
     *
     * ⚠️ SINCE THE SEND QUEUE IT COUNTS A FULL QUEUE, not a socket that said EAGAIN: eight entries
     * waiting, which is quic-go's WouldBlock (see quic/sendq.h). The summary line still says "the
     * socket full" because a full queue is what a slow socket looks like from this thread — the
     * writer is sitting on it — and the line is read by a script on the routers that this tree
     * does not have. On the Xiaomi it reads 9-15 per twenty megabytes up. */
    uint64_t tx_stop_blocked;
    /* The fourth way a pass ends, and the only one that is not a refusal: a packet has gone out,
     * another has arrived, and the reference would go and read it rather than write more. See
     * rx_waiting in conn.c. High here is not a fault — it is this loop staying as close to the top
     * of its loop as the reference's does, which is where a bare acknowledgement gets its chance.
     *
     * ⚠️ AND IT READS 658, 679, 700 ON THREE RUNS OF THE CLEAN STAND — about one pass in fifteen —
     * WHILE NOTHING ELSE MOVED. Not the wire (see tx_stop_paced above) and not the other three
     * counters either: against two runs without the rule, passes went 11 963 · 9 697 to 11 436 ·
     * 9 084 · 10 181, stops on the pace 7 701 · 7 037 to 8 779 · 4 507 · 7 285, and dry passes
     * 4 262 · 2 660 to 1 957 · 3 898 · 2 238. Every one of those swings further between two runs of
     * the same binary than between the two binaries, so the honest reading is that the rule is the
     * reference's, costs nothing measurable and buys nothing measurable here. It is kept because it
     * is what the reference does, not because a number improved.
     *
     * ⚠️ AND THAT SENTENCE STOOD FOR ABOUT AN HOUR. The hand-off added later the same day —
     * lc_qrefill_fn, the write loop asking the tunnel for a top-up instead of returning to the
     * poll — did move numbers, and it moved this one with them: yields read 1 724 · 1 528 on the
     * stand and 982 · 945 on a live router, because a loop that stays in the write path longer
     * meets more arriving packets. The rule is still kept for the reason above; it is simply no
     * longer inert. */
    uint64_t tx_stop_yield;
    /* Datagrams written, so the two above can be read per packet rather than per wakeup. */
    uint64_t tx_packets;

    /* Whether to move at all, the range to move across when the node allows one, and when the next
     * move is due. With hop_on and no range, only our own port changes — which needs nothing from
     * the node and is enough to be a different flow. See lc_qconn_hop. */
    unsigned            hop_min_ms, hop_max_ms;
    const lc_hop_ports *hop_ports; /* the caller's, NULL when the port is a single one */
    uint64_t            hop_at;

    /* Parrot Chrome's QUIC stack, as hysteria's client does unless DisableChromeParrot is set
     * (vendor/hysteria/core/client/client.go:95-103). Decided before the connection opens, because
     * it decides the first packet: the hello, the transport parameters, the connection IDs.
     *
     * `plain` is the switch and `chrome` its reading. The switch is the one that is ZERO BY DEFAULT,
     * so that a connection nobody configured is the reference's default one — which since hysteria
     * 2.11 is the parrot. `chrome` is set from it in lc_qconn_open. */
    int plain;
    int chrome;

    /* Kept because a hop has to dial the same host again, and the caller's string may be gone by
     * then — this connection outlives the call that opened it. */
    char     node_host[256];
    uint16_t node_port;

    int handshake_done;
    int closed;
    /* Ends without a CONNECTION_CLOSE: an idle timeout, or a handshake given up on by the clock.
     * That is how quic-go ends a connection for a timeout: the handshake and idle timeouts reach
     * destroyImpl with an error whose `immediate` is set, and handleCloseError then sends nothing
     * (vendor/quic-go/connection.go:706-716, :2323-2325). The node learns of it the way it learns
     * of a path that died. Set by whoever gives up — the idle expiry in conn.c, the handshake clock
     * in lc-tunnel — before lc_qconn_close. */
    int silent;
    /* The connection ended in a failure of this client's own — out of memory, a callback of ours
     * that failed, a buffer of ours too small — which the reference cannot have: where this client
     * fails, Go has ended the process, and the node hears nothing. So lc_qconn_close says nothing
     * either. See own_failure in conn.c; the TLS half of it is lc_qtls_own. */
    int own_fail;
    /* A write pass run from lc_qconn_tcp_read, or from lc_qconn_tcp_open for a STREAMS_BLOCKED,
     * failed: the next lc_qconn_step says so. */
    int read_flush_failed;

    /* Four slots for the HTTP/3 exchange, two of them used: the control stream carrying SETTINGS
     * and the request stream. Like quic-go's client, this one opens no QPACK streams — see
     * lc_qconn_auth_send. The rest are for proxied connections. Named because a handle encodes an
     * index into this array in a fixed number of bits, and conn.c checks the two against each
     * other at compile time. */
    lc_qstream *st_chunk[LC_QSTREAM_CHUNKS]; /* made as needed, LC_QSTREAM_CHUNK slots each */
    unsigned   st_count;

    /* Where the round-robin over those streams left off. Starting from zero every time would let
     * one busy connection have the link to itself while another waits behind it. */
    unsigned st_turn;

    /* The HTTP/3 streams write from here rather than owning buffers: the control stream carries
     * eight bytes, once, and the request stream an authentication request that is mostly padding.
     * A buffer per stream, each large enough for the request, would spend one of them on eight
     * bytes. */
    uint8_t txbuf[LC_H3_AUTH_REQ_MAX + 32u];
    size_t  txused;

    /* And read into here, for the same reason. */
    int64_t auth_id;
    uint8_t auth_rx[4096];

    /* The goroutine that writes SETTINGS — see qconn_control_goroutine in conn.c: the thread, whether
     * one was started (and so is to be joined), and whether it has run, which it says through
     * __atomic because it is written there and read here. */
    pthread_t ctrl_g;
    uint8_t   ctrl_pending, ctrl_g_live, ctrl_g_join, ctrl_opened;
    int       ctrl_ready;

    /* UDP, all of it taken on demand: a connection that only carries TCP never pays for any of it,
     * and on this target that is most of them. The sessions have no ceiling — see quic/udptab.h —
     * and a session's id is the handle the caller holds. */
    lc_qudptab udp;
    uint8_t   *dq; /* LC_QUDP_QUEUE slots of LC_QUDP_SLOT bytes, waiting to be written */
    uint16_t   dq_len[LC_QUDP_QUEUE];
    unsigned   dq_head, dq_count;
    lc_qudp_fn on_udp;
    void      *on_udp_user;

    /* Asked when ngtcp2 has nothing left; see lc_qrefill_fn. */
    lc_qrefill_fn on_dry;
    void         *on_dry_user;


    /* ONE SEND FOR MANY DATAGRAMS, WHICH IS WHAT THE REFERENCE DOES AND WHAT THIS COSTS.
     *
     * quic-go attaches UDP_SEGMENT as a control message and hands the kernel one buffer holding
     * several equal-sized datagrams, which the NIC or the kernel then cuts apart
     * (vendor/quic-go/sys_conn_helper_linux.go:83-96, applied in WritePacket,
     * vendor/quic-go/sys_conn_oob.go:228-239). Only QUIC_GO_DISABLE_GSO turns it off and hysteria
     * never sets it, so every hysteria client on the wire sends this way.
     *
     * ⚠️ AND IT IS 19% OF THE PROCESSOR ON THIS TARGET, measured 2026-09-06 on the Xiaomi 4A rather
     * than argued: uploading at 21.6 Mbit/s the client made 4498 `send` calls in two seconds and
     * spent 305 ms of 1580 ms of CPU inside them. The note in conn.c had this down as "not the
     * problem" on a measurement taken at 10-12 Mbit/s, where the same arithmetic gives 1240 calls a
     * second and the cost disappears — and it named the condition that would overturn it, "a link
     * where this plane is asked for tens of megabits rather than ten". That link is now measured.
     *
     * WHAT THE BATCH REQUIRES is that every datagram in it be the same size except the last. After
     * the handshake ours are: Salamander adds a constant eight bytes and Gecko fires only on
     * long-header packets. So the steady state batches and the handshake does not, which is also
     * where the packet rate is. A datagram of a different size flushes what is waiting and starts a
     * new batch — see gso_flush. */
    int      gso_ok;    /* the kernel took UDP_SEGMENT on this socket */
    int      ecn_ok;    /* 1-RTT datagrams are marked: the OOB path, on a kernel quic-go marks on */
    uint16_t gso_seg;   /* the size every datagram in the batch has */
    unsigned gso_ecn;   /* the marking they all carry, since a batch takes one cmsg */
    unsigned gso_count;
    size_t   gso_len;
    uint8_t  gso_buf[LC_GSO_BATCH * (LC_GECKO_BUFFER + LC_OBFS_SALT)];

    /* WHERE EVERY DATAGRAM GOES TO LEAVE: the reference's send queue, eight entries and a writer
     * thread of its own. See quic/sendq.h for why, and for the measurement that found it missing.
     *
     * It replaced held_buf, which kept the datagrams a full socket would not take and was drained
     * by this thread on the next writable event. That was already the reference's answer to
     * EAGAIN — send late rather than never — but it put the waiting and the packing on the same
     * thread. The writer now waits for the socket itself, as quic-go's writer goroutine does inside
     * Write, and the first-send EPERM retry moved there with it. */
    lc_sendq sq;
    /* The threads that open the node's packets ahead of ngtcp2, and the two batches they open —
     * see quic/rxopen.h. */
    lc_rxopen *rx;
    /* Entries the write path has committed to it, ever; see entry_commit in conn.c. */
    unsigned tx_commits;

    /* What ended it, when something did. Kept because a QUIC connection can fail for reasons that
     * never reach a socket error — a transport parameter the peer would not accept, a timeout it
     * declared — and the only place those appear is here. */
    char err[192];
} lc_qconn;

/* A monotonic millisecond clock. Exposed because every wait in this client has to be against a
 * deadline: lc_qconn_step returns as soon as ngtcp2 has a timer due, so counting turns of it and
 * multiplying by the timeout measures nothing at all. */
uint64_t lc_qconn_now_ms(void);

/* How long since a packet from the node last unscrambled with our key.
 *
 * The connection's own answer to "is this path still there" is max_idle_timeout, thirty seconds,
 * and thirty seconds is the whole of what a person experiences when it goes: measured twice on a
 * router, every stream stalls for that entire window and then everything opens in under a second
 * on the connection that replaces it. Reconnecting is cheap; noticing was the expensive part.
 *
 * NOTHING IS DECIDED FROM THIS. Three rules once were — silence at six seconds, then twenty, then
 * eight with a packet outstanding — and all three were this tree's invention; the reference
 * reconnects when QUIC declares the connection gone and at no other moment. What the number is for
 * now is the summary line, where it is the one fact that tells a node which has gone quiet apart
 * from a path on which our packets are being dropped, and a person reading a night of syslog cannot
 * recover it afterwards. */
uint64_t lc_qconn_silent_ms(const lc_qconn *c);

/* How long the connection has been idle by QUIC's rule rather than by the last packet in: the clock
 * restarts on a packet received and on the first ack-eliciting packet sent after it (RFC 9000 10.1).
 * That is quic-go's idleTimeoutStartTime (vendor/quic-go/connection.go:931-937), which its handshake
 * idle timeout is measured from, and ngtcp2 keeps the same point as its idle_ts
 * (vendor/ngtcp2/lib/ngtcp2_conn.c:2158-2166). This is the number the handshake gives up on;
 * lc_qconn_silent_ms stays the one the log reports. */
uint64_t lc_qconn_idle_ms(lc_qconn *c);

/* Opens the socket and starts the handshake. Returns 0 when the first packet has gone out, which is
 * not the same as connected — that is what lc_qconn_step reports.
 *
 * `pin` is the SHA-256 of the node's leaf certificate, LC_QTLS_PIN bytes, or NULL.
 *
 * A match IS proof that the node is the node — but only because two checks stand behind it, and the
 * note at the top of qtls.h sets out why neither is worth anything alone: the pin names WHICH key
 * the peer must hold, CertificateVerify proves it HAS it. The pin alone would rule out a node whose
 * certificate changed and rule out nobody replaying it, a certificate being public; that was the
 * state this comment used to describe. It now stands alongside REALITY's reality_verified rather
 * than below it. Given no pin, nothing is proved and lc_qconn_pinned says so.
 *
 * `c` MUST BE ZEROED BEFORE THE FIRST OPEN, and this is a real requirement rather than hygiene.
 *
 * The function wipes the struct — a reopen must not inherit a previous connection's streams — but
 * three groups of settings are meant to survive it, because they are armed BEFORE opening: the hop
 * interval and range (lc_qconn_hop_on) and Gecko's three numbers. So it reads them out of the
 * struct first and writes them back after. On a struct that was never initialised those reads take
 * whatever the stack held.
 *
 * Not theoretical, and not a crash: found on a router. lc-hy, lc-hydns and lc-hyfetch each declared
 * `lc_qconn c;` on the stack, and a non-zero `gecko.on` in that garbage turned frame splitting on
 * against a node running none. The node answers such packets by dropping them, so the tools failed
 * with "the handshake did not complete" — every time, under every password, every SNI, with
 * obfuscation and without — while lc-tunnel, whose struct is `static` and therefore zero, held a
 * working connection to the same node from the same box at the same moment. The three tools now
 * initialise; this paragraph is here so the fourth caller does not have to find it the same way. */
/* How long between hops, in milliseconds, and the floor under it. Both are the reference's.
 *
 * Thirty seconds is defaultHopInterval (vendor/hysteria/extras/transport/udphop/conn.go:19), applied
 * by normalized() when the operator sets no interval at all. Five seconds is the floor the same
 * function refuses to go below (:114-116, "hop interval must be at least 5 seconds").
 *
 * There is no jitter constant any more. A wander of ±5 s used to live here, on the argument that a
 * fixed period is itself a signature; upstream produces no such wander unless minHopInterval and
 * maxHopInterval are set to different values by hand, so a client that always wanders is as
 * recognisable as one that never does — see arm_hop. */
#define LC_QCONN_HOP_MS 30000u
#define LC_QCONN_HOP_MIN_MS 5000u

int lc_qconn_open(lc_qconn *c, const char *host, uint16_t port, const char *sni,
                  const char *obfs_password, const uint8_t *pin);

/* Whether the node matched the pin it was opened with. Always 0 when no pin was given. */
int lc_qconn_pinned(const lc_qconn *c);

/* PORT HOPPING, which is upstream's answer to exactly the fault this client kept hitting.
 *
 * Measured on a live router: the path swallows UDP to one port for six seconds at a time — the loop
 * awake, nothing arriving, not one datagram failing to unscramble — while ICMP over the same route
 * runs at zero loss with six milliseconds of jitter. That is a shaper acting on a UDP flow, and no
 * amount of care inside the client answers it, because the packets never arrive.
 *
 * Hysteria's own client answers it by moving: `server: host:20000-50000` makes it pick a fresh
 * destination port every half minute or so: the address is resolved by `udphop.ResolveUDPHopAddr`
 * (vendor/hysteria/app/cmd/client.go:258), the interval is read from the config beside it
 * (vendor/hysteria/app/cmd/client.go:279), and the hopping connection is built only when the
 * address parsed as a range (vendor/hysteria/app/cmd/client.go:285-287). The trick that makes this
 * cheap is that QUIC is never told — `UDPHopPacketConn` presents one stable address upwards and
 * swaps the real destination underneath, so no path validation and no migration happen. This does
 * the same: ngtcp2 keeps the path it was given, and the socket beneath it is replaced.
 *
 * The node needs one firewall rule and no configuration: it keeps listening on its single port, and
 * the range is redirected to it.
 */

/* The node's ports and how often to move among them. Called before lc_qconn_open, because the first
 * dial already takes a port from them. `ports` is the caller's and must outlive the connection.
 *
 * THE PORTS ARE THE WHOLE SWITCH. NULL is a node addressed by one port and there is no hopping at
 * all — not a separate setting, just the absence of a hop address, which is how the reference
 * decides it: hysteria's client asks the address form, `ServerAddr.Network() == "udphop"`
 * (vendor/hysteria/app/cmd/client.go:285), with no enable beside it.
 *
 * `min_secs` of zero takes the reference's own default, thirty seconds, the way an unset interval
 * does upstream; `max_secs` of zero is the minimum again, and a span draws a fresh interval for every
 * move. With a hop address the node needs a firewall redirect from its ports to the one it listens
 * on. */
void lc_qconn_hop_on(lc_qconn *c, unsigned min_secs, unsigned max_secs, const lc_hop_ports *ports);

/* Ask for Gecko, the shape obfuscation that wraps Salamander. Called before lc_qconn_open, for the
 * same reason hopping is: it changes the first packet of the handshake. Sizes of zero take the
 * reference client's defaults. quic/gecko.h says what a node running it does to a client that does
 * not, and the short answer is nothing at all, silently. */
void lc_qconn_gecko_on(lc_qconn *c, unsigned min_packet, unsigned max_packet);

/* Do NOT parrot Chrome — hysteria's quic.disableChromeParrot (vendor/hysteria/app/cmd/client.go:172,
 * passed on at :470). Without this call a connection parrots, as the reference does by default.
 * Called before lc_qconn_open, for the same reason as the two above. */
void lc_qconn_chrome_off(lc_qconn *c);

/* The node port actually in use. Not the same as what the caller asked for once a range is in play:
 * the first dial already takes a port from it, so a line printing the caller's number names a port
 * nothing is talking to. */
uint16_t lc_qconn_port(const lc_qconn *c);

/* Whether a hop is due. Answered false when no range was given, which is the ordinary case. */
int lc_qconn_hop_due(const lc_qconn *c);

/* Move to another port from the range. Asked only when lc_qconn_hop_due says so, which is the same
 * question as "is there a range" — upstream has no other, because without one the hopping conn is
 * never built. The descriptor changes, so the caller must take the old one out of its event loop
 * and put the new one in — which is why this is the caller's to invoke rather than something the
 * connection does behind its back. Returns -1 and leaves the old socket in place if the new one
 * cannot be made, or if the system could not provide the randomness to choose a port. */
int lc_qconn_hop(lc_qconn *c);

/* Which cipher suite the node chose, as a name for the log. Valid once the handshake is done.
 *
 * Worth a line because the client offers three and does not decide: the node does. On hardware
 * without AES instructions the difference between the answers is twelvefold, and until this existed
 * the only way to tell which one was in use was to watch the share of the processor and infer. */
const char *lc_qconn_suite(const lc_qconn *c);

/* Waits up to timeout_ms, then does whatever the connection needs: reads what arrived, hands it to
 * ngtcp2, honours any timer that has come due, and writes whatever ngtcp2 wants sent.
 *
 * Returns 1 while the connection is alive, 0 when it has closed cleanly, -1 on failure. */
int lc_qconn_step(lc_qconn *c, int timeout_ms);

/* How long something else may sleep before this connection needs attention, never more than `cap`.
 *
 * For a caller that owns its own event loop and cannot let lc_qconn_step do the waiting. QUIC's
 * timers are not optional the way a plain socket's are: a retransmission that is never sent because
 * nothing woke up is a connection that stalls and then times out, with no error anywhere. */
int lc_qconn_timeout(const lc_qconn *c, int cap);

/* The descriptor to watch for readability. One socket carries every stream and session on this
 * connection, so a loop watches it once and asks lc_qconn_step to sort out who the bytes were for. */
int lc_qconn_fd(const lc_qconn *c);

/* Readable whenever the send queue has freed an entry. A loop watches it and calls lc_qconn_step when
 * it fires: a write pass that stopped on a full queue goes on from there, which is the reference's
 * run loop waking on sendQueueAvailable (vendor/quic-go/connection.go:677). The socket itself never
 * needs watching for writability now — the writer thread waits on it. Negative before the
 * connection is open. */
int lc_qconn_wake_fd(const lc_qconn *c);

/* AND THE SOCKET THE LAST HOP LEFT BEHIND, which a loop has to watch as well. Negative when there
 * is none, which is every connection that has not hopped.
 *
 * A hop does not close the socket it leaves — everything the node had already sent to that port is
 * still on its way, and the node keeps sending there until our first packet from the new one
 * arrives. Upstream keeps that socket for a whole interval and reads it with a goroutine of its own
 * (vendor/hysteria/extras/transport/udphop/conn.go:186-197, 215). lc_qconn_step polls both, so
 * nothing is ever lost — but a loop that watches only the current one is not WOKEN by the old one,
 * and those packets then wait for whatever else stirs the loop next. That was the state this
 * existed to fix and only half fixed: the socket was kept and nobody listened at the door.
 *
 * The descriptor is closed by the hop AFTER next, so a loop must drop it before calling
 * lc_qconn_hop, and before lc_qconn_close. */
int lc_qconn_prev_fd(const lc_qconn *c);

/* The source port in use at this moment. Asked of the kernel every time, because a hop replaces the
 * socket without telling anything else — see the source. Zero when there is no socket. */
uint16_t lc_qconn_source_port(const lc_qconn *c);

/* Authenticates: opens the HTTP/3 streams, sends the one request Hysteria2 wants, and pumps until
 * the answer arrives or the time runs out. Returns 0 when the node accepted us — which it says with
 * status 233 rather than 200, so that an ordinary web client poking at the same port learns
 * nothing.
 *
 * `rx_rate` is what we say we can receive at, in BYTES per second, and it is the whole of Brutal as
 * far as downloads are concerned. State one and the node sends to us at exactly that rate, treating
 * loss as somebody else's problem — which is what Hysteria is for, and which is decided entirely at
 * the node. Say zero, meaning "I do not know", and it falls back to congestion control that slows
 * down when the path does; that is also what the reference client says when nobody has told it a
 * number, so it is the honest default rather than a worse one.
 *
 * Bytes, not bits, and the trap is upstream's: hysteria's own configuration is written "100 mbps"
 * (vendor/hysteria/app/internal/utils/bpsconv.go:18-19) and stored as 12 500 000. Its units are
 * DECIMAL — `Kilobyte = Byte * 1000` and so on (:10-16) — and the conversion divides by eight:
 * `case "m", "mb", "mbps": return v * Megabyte / 8`
 * (vendor/hysteria/app/internal/utils/bpsconv.go:44-45), so a hundred megabits is 12 500 000 bytes and
 * not 13 107 200.
 * A caller that passed bits here would ask for eight times what it meant, and the node would
 * cheerfully oblige. */
/* Authentication in two halves, for a caller that cannot afford to wait.
 *
 * lc_qconn_auth_send opens the HTTP/3 streams and queues the request; lc_qconn_auth_poll answers 1
 * when the node has said yes, 0 while the answer has not arrived, and -1 when it said no or said
 * something that is not an answer. Between the two the caller drives lc_qconn_step as usual and
 * keeps serving everything else. lc_qconn_auth_seen is how much of an answer has arrived, for the
 * message a caller writes when it gives up. */
int    lc_qconn_auth_send(lc_qconn *c, const char *password, uint64_t rx_rate);
int    lc_qconn_auth_poll(lc_qconn *c, lc_h3_auth_result *result);
size_t lc_qconn_auth_seen(const lc_qconn *c);

/* The same exchange with a loop of its own, for the one-shot probes. */
int lc_qconn_authenticate(lc_qconn *c, const char *password, uint64_t rx_rate,
                          lc_h3_auth_result *result, int timeout_ms);

/* ---- proxied TCP connections ----------------------------------------------------------------
 *
 * One QUIC stream each, and nothing about them blocks: every call here either does its work now or
 * says how little of it it could do. That is not a style preference — the tunnel that will drive
 * this has one thread and one epoll loop for every connection it carries, and a call that waited
 * would be waiting on behalf of all of them. */

/* Asks the node to connect to `addr`, which is "host:port" — a name, not an address, when a name is
 * what we were given, because resolving it at the node is the difference between a DNS query that
 * goes through the tunnel and one that does not.
 *
 * Returns a handle, or -1 when there is no room or the node allows no more streams. The connection
 * is not open yet: the node answers on the same stream, and lc_qconn_tcp_state reports that. */
int lc_qconn_tcp_open(lc_qconn *c, const char *addr);

typedef enum {
    LC_QTCP_OPENING,     /* the request has gone; the node has not answered */
    LC_QTCP_ESTABLISHED, /* it answered yes, and what follows is the connection itself */
    LC_QTCP_REFUSED,     /* it answered no, and said why */
    /* Bytes the node sent could not be held — the machine was out of memory — so what is in the
     * buffer is a prefix of the stream and not the stream. Distinct from GONE because nothing about
     * the connection is wrong, and distinct from REFUSED because the node did nothing: the caller
     * must end this one session and may carry on with every other. */
    LC_QTCP_LOST,
    /* The stream ended — FIN or RESET_STREAM — before the node's answer was whole, or the answer is
     * not one. To the reference that is ReadTCPResponse failing, which wrapIfConnectionClosed makes
     * ClosedError: the request fails AND the client lets go of this connection, so the next request
     * dials a new one (vendor/hysteria/core/client/client.go:216-220, :251-262,
     * vendor/hysteria/core/client/reconnect.go:80-88). `why` says which. */
    LC_QTCP_CLOSED,
    LC_QTCP_GONE         /* the stream ended after the answer, or the handle is not one of ours */
} lc_qtcp_state;

/* `why` is set for LC_QTCP_REFUSED, where it is the node's own words, for LC_QTCP_CLOSED, and for
 * LC_QTCP_LOST, where it is this end's account of what refused the room — with the reserve's numbers when it was the
 * reserve. NULL otherwise. */
lc_qtcp_state lc_qconn_tcp_state(lc_qconn *c, int h, const char **why);

/* What has arrived and not been taken yet, in place. Nothing is copied and nothing is consumed
 * until lc_qconn_tcp_take says so.
 *
 * lc_qconn_tcp_read is the reference's Read of |n| of those bytes: it re-opens this stream's receive
 * window by that much — so a caller that stops reading is a caller the node stops sending to, all
 * the way back — and, when that makes a window update due, sends it at once, as quic-go wakes its
 * sender from Read (vendor/quic-go/receive_stream.go:113-135). lc_qconn_tcp_take then lets go of
 * bytes already read. */
const uint8_t *lc_qconn_tcp_peek(lc_qconn *c, int h, size_t *len);
void           lc_qconn_tcp_read(lc_qconn *c, int h, size_t n);
void           lc_qconn_tcp_take(lc_qconn *c, int h, size_t n);

/* Whether the node has finished: no more bytes will arrive after what peek is showing. */
int lc_qconn_tcp_eof(lc_qconn *c, int h);

/* Bytes towards the node. Returns how many were taken, which may be fewer than offered and may be
 * none — the send buffer is a small fixed thing, and when it is full the answer is to stop reading
 * from wherever these bytes came from. */
size_t lc_qconn_tcp_send(lc_qconn *c, int h, const uint8_t *data, size_t len);

/* Done with it. What is already buffered still goes out, and the end-of-stream follows it; the
 * handle stops being valid at once.
 *
 * There is deliberately no way to close only our half. Hysteria2 does not have one: the node runs
 * both directions of a proxied connection in one copy and tears the whole thing down as soon as
 * EITHER ends: two goroutines copying opposite ways into one channel, and `return <-errChan`
 * blocks for the FIRST of them (vendor/hysteria/core/server/copy.go:68-80). So an end-of-stream
 * sent to say "I have finished asking" is
 * read as "I have finished" — the reply is never sent, and the connection ends looking like the
 * far side had nothing to say. Anything above this that wants to relay a local half-close has to
 * decide not to. */
void lc_qconn_tcp_close(lc_qconn *c, int h);

/* ---- proxied UDP -------------------------------------------------------------------------------
 *
 * A session is what one local socket's worth of UDP is called on the wire: it can send to any
 * number of destinations and hear back from them, and the address travels with every packet rather
 * than being fixed when it opens. Nothing about it is reliable, in either direction, on purpose.
 *
 * There is no way to close a session at the node: the protocol has no message for it, and the node
 * forgets a session that has gone quiet on its own timer. Closing one here only stops us holding
 * its buffers.
 *
 * lc_qconn_udp_open returns the new session's id — the number on the wire, from one upwards as the
 * reference numbers them (vendor/hysteria/core/client/udp.go:97-100, :153-154) — and that is the
 * handle every call below takes and the one lc_qudp_fn is given; -1 when there is no memory, or no
 * id left an int can hold (see lc_qudptab_open). */
int  lc_qconn_udp_open(lc_qconn *c);
void lc_qconn_udp_close(lc_qconn *c, int session);

/* Sends one packet to `addr` ("host:port"), splitting it across datagrams if it is too big for one.
 * Returns 0 when every piece was queued, -1 when it was dropped — which for UDP is an outcome, not
 * a failure, and the caller is told only so that it can count them — and 1 when header and data
 * together are over LC_HY_UDP_MAX, which the reference drops in silence and answers as sent. */
int lc_qconn_udp_send(lc_qconn *c, int session, const char *addr, const uint8_t *data, size_t len);

/* Where packets coming back are delivered, from inside lc_qconn_step. */
void lc_qconn_udp_handler(lc_qconn *c, lc_qudp_fn fn, void *user);

/* The client's socket took the packet that was waiting: what the session held meanwhile is
 * delivered now, in the order it came, until the socket is full again or nothing is left. */
void lc_qconn_udp_resume(lc_qconn *c, int session);

/* Who tops the streams up when the write loop runs out, from inside lc_qconn_step. */
void lc_qconn_refill_handler(lc_qconn *c, lc_qrefill_fn fn, void *user);

void lc_qconn_close(lc_qconn *c);


#endif
