#include "quic/conn.h"

#include "core/rnd.h"
#include "core/say.h"
#include "net/goresolve.h"
#include "net/loop.h"
#include "net/sock.h"
#include "quic/hop.h"
#include "quic/pad.h"
/* For naming the suite the node chose: the id is turned into an algorithm by the same call the
 * record layer uses, and the algorithm into a name by the one function that spells them. */
#include "tls/aead.h"
#include "tls/suite.h"
#include "tls/alert.h"

/* The controller's pacer is asked before every packet — see flush. The header lives in the patched
 * ngtcp2 tree (patch 0009), which the QUIC include path already covers. */
#include <ngtcp2_hybbr.h>

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

/* NOT IN NGTCP2'S PUBLIC HEADER, AND NOT IN NGTCP2 EITHER: patches/ngtcp2/0010 adds it, as four
 * lines of guard around a writer the library already had and kept to itself. The send loop needs it
 * at the one moment the pace forbids data — an acknowledgement may still go, which is what the
 * reference does there and what this client lost when patch 0009 moved pacing out of the library.
 *
 * Declared here rather than in a header for the same reason as ngtcp2_conn_get_idle_expiry further
 * down: ngtcp2 is linked as objects built from the pinned revision with these patches applied, so
 * the symbol is this build's own and a header would only be a second place to keep it in step. */
ngtcp2_ssize ngtcp2_conn_write_ack_pkt_1rtt(ngtcp2_conn *conn, ngtcp2_pkt_info *pi, uint8_t *dest,
                                            size_t destlen, ngtcp2_tstamp ts);

/* ngtcp2 counts in nanoseconds off a monotonic clock, and insists it be monotonic for the same
 * reason the rest of this client does: the router's clock jumps when NTP first answers, which on a
 * freshly booted device is exactly when connections are being made. */
static ngtcp2_tstamp now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ngtcp2_tstamp)ts.tv_sec * NGTCP2_SECONDS + (ngtcp2_tstamp)ts.tv_nsec;
}

uint64_t lc_qconn_now_ms(void)
{
    return now_ns() / NGTCP2_MILLISECONDS;
}

uint64_t lc_qconn_silent_ms(const lc_qconn *c)
{
    uint64_t now = lc_qconn_now_ms();

    /* Before the first packet there is nothing to be silent since, and a clock that went backwards
     * is not evidence of anything. Both answer zero, which is what a number nobody can act on
     * should read as in a log line. */
    if (c->last_rx_ms == 0 || now < c->last_rx_ms)
        return 0;
    return now - c->last_rx_ms;
}

/* Text the peer chose, on its way to somebody's terminal.
 *
 * This connection hands the user two such strings, and both are the peer's to write: the
 * CONNECTION_CLOSE reason that say() formats into c->err, and the refusal message of a Hysteria2
 * reply, which the node puts on the wire and reply_if_ready() copies into s->why. Both are shown
 * before anything has established who the peer is — the pin decides that, and the pin is optional,
 * so without one the peer is whoever answered. Left raw, a carriage return rewrites the line above,
 * a newline forges log lines of the node's own (these tools' stdout IS the log — lc-tunnel sets
 * line buffering for that), and a CSI sequence clears the screen. Anything outside printable ASCII
 * becomes a dot: the message stays readable and stops being a channel.
 *
 * One function for both, called where each buffer is filled rather than at the format string, which
 * is what the note beside say() already claimed — "so no future caller has to remember". It was
 * true of c->err only, and s->why, the buffer that carries a string the node composed in full,
 * reached the terminal untouched. */
static void printable(char *s)
{
    for (; *s != '\0'; s++)
        if (*s < 0x20 || *s > 0x7e)
            *s = '.';
}

static void say(lc_qconn *c, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(c->err, sizeof c->err, fmt, ap);
    va_end(ap);
    printable(c->err);
}

/* ngtcp2 hands us one line at a time and expects us to end it. Through lc_vsay, which ends it and
 * puts it on the descriptor in one write: the tunnel runs several workers on one stderr, and this
 * used to be a vfprintf followed by a fputc — two writes at least, and as many as the format has
 * pieces, every one of them a chance for another worker's line to land in the middle.
 *
 * ⚠️ THIS IS THE PATH WHERE TORN OUTPUT COSTS MOST, which is why it is worth doing even though the
 * trace is off by default. A QUIC connection that fails says nothing on a socket — no alert, no
 * reset — so this is the only account of what happened, and it is read exactly when something is
 * already wrong. Anyone who turns it on is not in a position to also guess which half of a line
 * belongs to which worker.
 *
 * ⚠️ AND THE LENGTH IS lc_vsay's, WHICH IS WHY IT IS 2048 RATHER THAN THE 512 THIS FIRST GOT. The
 * old vfprintf had no ceiling at all, so any cap here is a cap this rewrite introduced — into the
 * one trace whose entire value is that it is complete. A line long enough to reach even this one is
 * cut with "..." rather than quietly, for the same reason. */
static void log_printf(void *user_data, const char *fmt, ...)
{
    (void)user_data;
    va_list ap;
    va_start(ap, fmt);
    lc_vsay(2, NULL, fmt, ap);
    va_end(ap);
}

static void rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *ctx)
{
    (void)ctx;
    (void)lc_rnd(dest, destlen);
}

/* A failure of this client's own ends the connection as the reference's process ends there: Go
 * has no counterpart to it — memory runs out and the runtime ends the program, crypto/rand fails and
 * it is fatal — so its node hears nothing and learns of it when its idle timer runs out. Returns -1
 * for the caller to pass on. */
static int own_failure(lc_qconn *c)
{
    c->own_fail = 1;
    return -1;
}

/* What ngtcp2 answered to a write, as the end of the connection: ours when the library ran out of
 * memory, a callback of ours failed (the AEAD, header protection, a random number), or it was called
 * wrongly. */
static int write_refused(lc_qconn *c, ngtcp2_ssize rv)
{
    if (rv == NGTCP2_ERR_NOMEM || rv == NGTCP2_ERR_CALLBACK_FAILURE || rv == NGTCP2_ERR_CRYPTO ||
        rv == NGTCP2_ERR_INVALID_ARGUMENT)
        return own_failure(c);
    return -1;
}

/* Connection identifiers are how a peer recognises this connection after its address changes, so
 * they have to be unguessable — a predictable one lets anyone on the path claim to be us. */
static int get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                    ngtcp2_stateless_reset_token *token,
                                    size_t cidlen, void *user_data)
{
    (void)conn;
    (void)user_data;
    if (lc_rnd(cid->data, cidlen) != 0 ||
        lc_rnd(token->data, sizeof token->data) != 0)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    cid->datalen = cidlen;
    return 0;
}

static int recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                               uint64_t offset, const uint8_t *data, size_t datalen,
                               void *user_data, void *stream_user_data);
static int stream_close_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                           uint64_t app_error_code, void *user_data, void *stream_user_data);
static void slot_release(lc_qstream *s);
static lc_qstream *slot_of(lc_qconn *c, int64_t id);

/* Slot `i` of the stream table, which is kept in chunks — see LC_QSTREAM_CHUNK. */
static inline lc_qstream *st_at(const lc_qconn *c, unsigned i)
{
    return &c->st_chunk[i / LC_QSTREAM_CHUNK][i % LC_QSTREAM_CHUNK];
}
static int  qconn_control_turn(lc_qconn *c);
static void qconn_control_join(lc_qconn *c);
static int  qconn_open_control(lc_qconn *c);
static int  recv_datagram_cb(ngtcp2_conn *conn, uint32_t flags, const uint8_t *data, size_t datalen,
                             void *user_data);
static int  emit(lc_qconn *c, const uint8_t *pkt, size_t len, unsigned ecn);
/* Both belong to the port-hopping half at the bottom of this file; declared here because opening a
 * connection uses them and sits above them. */
static int  dial_node(lc_qconn *c, const char *host, uint16_t port, int *out_fd,
                      struct sockaddr_storage *out_addr, socklen_t *out_len);
static void arm_hop(lc_qconn *c);

/* IS THERE A RANGE TO MOVE WITHIN — which is the whole of "is hopping on", and is asked in exactly
 * one spelling because it was asked in three: the first dial asked it to choose a port, asked it
 * again to arm the timer, and lc_qconn_hop_due asked it a third time. Three writings of one rule are
 * three rules, and this one decides whether the node's port moves at all.
 *
 * The bounds are the switch because that is where the reference keeps it: hysteria's client hops
 * when the server address is a range, `ServerAddr.Network() == "udphop"`
 * (vendor/hysteria/app/cmd/client.go:285), and has no enable beside it to consult. */
static int hopping(const lc_qconn *c)
{
    return c->hop_ports != NULL;
}

/* WHETHER THE REFERENCE WOULD TAKE THE OOB PATH ON THIS CONNECTION — which is what decides ECN, the
 * received TOS and GSO, all three.
 *
 * quic-go takes it only for a conn that is an OOBCapablePacketConn — in practice a *net.UDPConn — and
 * otherwise falls to basicConn, "PacketConn is not a net.UDPConn. Disabling optimizations possible on
 * UDP connections", whose capabilities are DF and nothing else (vendor/quic-go/sys_conn.go:53-81,
 * :123). Two things hand it such a conn. A hopping client's udpHopPacketConn, which passes
 * SyscallConn and the buffer setters through but not the OOB calls
 * (vendor/hysteria/extras/transport/udphop/conn.go:227-345). And an obfuscated one: Salamander and Gecko both go through obfs.WrapPacketConn*
 * (vendor/hysteria/app/cmd/client.go:339-351), whose wrapper passes SyscallConn and the two buffer
 * setters through so that DF survives, and nothing more (vendor/hysteria/extras/obfs/conn.go:32-71,
 * :123-133).
 *
 * ⚠️ THIS ASKED ONLY ABOUT HOPPING. So a client with Salamander or Gecko on and a single port
 * marked every 1-RTT datagram ECT(0), put ECN counts in its ACKs and sent GSO batches, where the
 * reference with the same configuration sends Not-ECT, counts nothing and writes one datagram a call.
 * Two bits of the IP header, readable without touching QUIC. */
static int oob_conn(const lc_qconn *c)
{
    return !hopping(c) && !c->obfs.on && !c->gecko.on;
}

static int handshake_completed_cb(ngtcp2_conn *conn, void *user_data)
{
    (void)conn;
    ((lc_qconn *)user_data)->handshake_done = 1;
    return 0;
}

/* Everything ngtcp2 wants to send right now, in as many datagrams as it takes.
 *
 * Written with a stream id of -1, which means "no stream data, only whatever the connection itself
 * owes" — acknowledgements, the handshake, keep-alives. Stream data goes out the same way once
 * there is any. */
/* One finished packet onto the wire. Returns 0 when it went, 1 when the kernel would not take it
 * this moment, -1 when the connection is finished. Three outcomes rather than two because the
 * middle one is ordinary and the last one is not. */
/* The ECN codepoint for one datagram, applied the way the reference applies it.
 *
 * quic-go marks every 1-RTT datagram ECT(0) and leaves everything else unmarked:
 *
 *     func (h *sentPacketHandler) ECNMode(isShortHeaderPacket bool) protocol.ECN {
 *         if !h.enableECN { return protocol.ECNUnsupported }
 *         if !isShortHeaderPacket { return protocol.ECNNon }
 *         return h.ecnTracker.Mode()
 *     }                       (vendor/quic-go/internal/ackhandler/sent_packet_handler.go:1004-1012)
 *
 * with Mode() the tracker's verdict: ECT(0) on the first ten 1-RTT packets, nothing until an
 * acknowledgement shows the marks arrived, ECT(0) on every one after that
 * (vendor/quic-go/internal/ackhandler/ecn.go:82-139). Two bits of the IPv4 TOS or IPv6 traffic
 * class byte, readable by any middlebox without parsing QUIC at all: a genuine hysteria client on
 * Linux is ECT(0) on every data packet of a path that carries the marks, and this one was Not-ECT
 * on all of them.
 *
 * ngtcp2 chooses the mark — patches/ngtcp2/0030 is quic-go's tracker in it, deciding per datagram
 * by its first packet as isShortHeaderPacket does — and this applies it. The datagram's own first
 * byte is checked here as well, bit 7 set being a long header: a Gecko fragment of one is cut here,
 * after ngtcp2, and must go unmarked like the packet it came from. */
static int gso_flush(lc_qconn *c);

/* EVERY DATAGRAM LEAVES THROUGH THE SEND QUEUE NOW, and the kernel's answers are taken there — see
 * quic/sendq.c for the sendmsg and every outcome of it, quic/sendq.h for why it is a thread of its
 * own. What this file still owns is deciding what goes into an entry; where it goes is the queue's,
 * read when it is written — see lc_sendq_set_dest. */
static void cur_dest(const lc_qconn *c, lc_sendq_dest *d)
{
    d->fd = c->fd;
    memcpy(&d->peer, &c->peer_addr, sizeof d->peer);
    d->peer_len = c->remote_len;
    d->family = c->family;
}

/* An entry to fill. NULL only if the queue is full, which the write loop rules out by asking for room
 * before it packs anything — so reaching it is a fault in that check, and it says so. */
static lc_sendq_entry *entry_open(lc_qconn *c)
{
    lc_sendq_entry *en = lc_sendq_reserve(&c->sq);
    if (en == NULL) {
        say(c, "the send queue had no room for a datagram the write loop had made room for");
        return NULL;
    }
    return en;
}

/* Makes a filled entry the writer's, and counts it: the write loop asks whether the queue is full
 * after every commit, and this count is how it knows one happened. */
static void entry_commit(lc_qconn *c)
{
    c->tx_commits++;
    lc_sendq_commit(&c->sq);
}

int lc_qconn_wake_fd(const lc_qconn *c)
{
    return c->sq.started ? lc_sendq_wake_fd(&c->sq) : -1;
}

static int emit_one(lc_qconn *c, const uint8_t *pkt, size_t len, unsigned ecn)
{
    /* Scrambled on the way out, and this is the last thing that touches the datagram: whatever
     * ngtcp2 produced is a QUIC packet, and a server running Salamander will not recognise one that
     * arrives unscrambled — it will not answer and it will not say why. */
    /* Large enough for the biggest frame anything upstream of here can hand over, which is not
     * 1600.
     *
     * The option parser accepts `-g MIN-MAX` up to LC_GECKO_BUFFER = 2048, deliberately and with a
     * comment saying why: that is geckoBufferSize, the reference's own ceiling
     * (vendor/hysteria/extras/obfs/gecko.go:22 and :45), and refusing 1201..2048 would make nodes
     * the reference supports unconfigurable here. lc_gecko_split then pads frames toward that
     * maximum, and lc_obfs_wrap refuses anything whose length plus the salt exceeds the output
     * buffer (src/quic/obfs.c:48). At 1600 that meant every frame over 1592 bytes failed to
     * scramble, emit_one returned -1 and the connection was torn down — so `-g 512-2048`, a range
     * this program advertises as supported, could not bring a tunnel up at all.
     *
     * Sized from the constants rather than from a round number, so it cannot drift from either. */
    uint8_t masked[LC_GECKO_BUFFER + LC_OBFS_SALT];
    long    n = lc_obfs_wrap(&c->obfs, pkt, len, masked, sizeof masked);
    if (n < 0) {
        say(c, "cannot obfuscate a %zu-byte packet", len);
        return own_failure(c);
    }

    /* ONE SYSCALL PER PACKET WHERE THE REFERENCE SENDS BATCHES — a divergence that WAS here,
     * undocumented until 2026-09-01 and closed by the batching a few lines down. The paragraphs
     * that follow are kept because they are the answer to "is this plane slow because of the send
     * path", which is the first place anyone looks, and that answer did not change when the
     * divergence did.
     *
     * ⚠️ READ THE TENSE. This said "This sends one datagram per send(2)" as a statement about the
     * present for as long as it took to implement the batch, and a reader who takes it as current
     * concludes the code below does not exist.
     *
     * quic-go sets UDP_SEGMENT and hands the kernel one buffer holding many equal-sized datagrams:
     * it probes support with getsockopt at startup (vendor/quic-go/sys_conn_helper_linux.go:70-81),
     * attaches the segment size as a cmsg (:83-95), and WritePacket passes it whenever gsoSize > 0
     * (sys_conn_oob.go:228-239). Only QUIC_GO_DISABLE_GSO turns it off, and hysteria does not set
     * it — so neither does this, and the probe, the cmsg and the batch are all below.
     *
     * IT APPLIES HERE, which is the part that had to be checked before it could be written. GSO
     * needs every segment but the last to be the same size, and after the handshake ours are:
     * Salamander adds a constant eight bytes (quic/obfs.c), and Gecko — the one that pads to random
     * lengths — fires only on LONG-HEADER packets, so the steady-state stream it batches passes
     * through whole (quic/gecko.h). That is why the condition below excludes long headers rather
     * than trying to hold them.
     *
     * AND IT WAS NEVER WHAT MADE THIS PLANE SLOWER, on the evidence already in this tree — the batch
     * below is there because the reference has one, not because it was owed a speed-up. At the
     * 10-12.7 Mbit/s measured from the router against a stand abroad, ~1280-byte datagrams come to
     * roughly 1240 packets a second — a syscall rate no router struggles with. The stronger argument
     * is the receive side's own result: batching arrivals into recvmmsg cut time in the kernel
     * THIRTEENFOLD and the throughput gap did not move. That measurement disproved
     * the syscall-cost hypothesis where it could be tested, and the send side is the same hypothesis
     * with fewer packets in it.
     *
     * WHAT WOULD CHANGE THE ANSWER: a link where this plane is asked for tens of megabits rather
     * than ten, or a packet rate raised by something other than throughput.
     *
     * ⚠️ WHAT IS LEFT AS THE SUSPECT IS THE AEAD, and this paragraph said the opposite for a day.
     *
     * Every byte on this plane is ChaCha20 at the 64 Mbit/s this processor manages
     * (quic/params.h), while REALITY under Vision hands bulk bytes to the kernel and never touches
     * them. What stood here argued that the difference does not exist in the direction that matters:
     * direct copy is two decisions, only the upstream one is ours, and the DOWNSTREAM hand-off is
     * the node's to announce — with tls/record.h reporting that on a live router it "often never
     * came". So both planes were said to be paying an AEAD on downloads.
     *
     * Measured on the live router 2026-09-02, off its own summary line: `direct 719434386 bytes down
     * (spliced, 89% of what came down)`. The announcement comes, and for the overwhelming majority
     * of downstream bytes. So the asymmetry is real — REALITY's bulk download costs this process
     * nothing and this plane's costs it a ChaCha20 pass — and that is the standing candidate.
     *
     * ✅ AND ON 2026-09-07 THE PROCESSOR WAS FINALLY WATCHED, so the candidate has an answer and it
     * is not the one the paragraph was heading towards. Profiled on the Xiaomi under four
     * downloads on this plane:
     *
     *     recv 6 %   obfs 19-20 %   ngtcp2_conn_read_pkt 54-55 %, of which AEAD 32 %   writev ~0 %
     *
     * So the AEAD really is about a third of what this process spends, and the asymmetry with
     * REALITY is real as stated. What it is NOT is the ceiling. On the AX3000T the same plane
     * carried 122-129 Mbit/s at 52 % of ONE core with the second core idle, so a third of half a
     * core is not what stops it, and buying that third back would buy nothing — the same verdict
     * the recvmmsg result reached about syscalls, arrived at from the other side. Rewriting ChaCha
     * for NEON was costed on exactly this and dropped: mbedTLS's chacha20.c and poly1305.c are
     * plain C here where Go ships assembly, and it still does not matter, because nothing is
     * waiting on the cipher.
     *
     * The share belongs partly to the far end rather than to us (see the note at the summary line
     * in lc-tunnel's main.c), so a node that splits records differently would move it. What this
     * divergence was NOT is the reason — that much the recvmmsg result settles.
     *
     * Unmarked datagrams keep the plain send: a cmsg per packet costs a little and buys nothing
     * when the value is the socket default anyway.
     *
     * ⚠️ THE HEADER BYTE IS `pkt[0]`, NOT `masked[0]`, AND FOR A YEAR IT WAS THE SECOND.
     *
     * `masked` is what lc_obfs_wrap produced, and under Salamander its first eight bytes are the
     * per-packet salt — drawn fresh for every datagram (lc_obfs_wrap, quic/obfs.c).
     * So `masked[0] & 0x80` was a coin toss, not a header test, and the branch it guards decides
     * whether the datagram carries ECT(0).
     *
     * What that put on the wire: ngtcp2 marked every 1-RTT packet once the handshake was done, so
     * the coin decided instead, and roughly half of all data packets left Not-ECT and half ECT(0).
     * The reference marks every one its tracker says to (vendor/quic-go/internal/ackhandler/
     * sent_packet_handler.go:1004-1012) — and the ECN bits sit in the IPv4 TOS byte, which any
     * middlebox reads without touching QUIC. A random half-and-half is a signature that matches
     * neither the reference nor a client with ECN off. Secondarily it desynchronised the ECN
     * validation, which counted as marked the packets this branch sent unmarked.
     *
     * Only under Salamander: with no obfuscation `masked[0] == pkt[0]` and the test was right,
     * which is why it read as correct everywhere it was looked at.
     *
     * ⚠️ AND NOTHING IS MARKED AT ALL WHEN THE PORT MOVES. A hopping client gives quic-go a conn it
     * cannot take the OOB path with, so upstream marks nothing in either direction — the reasoning
     * and the citations are with the socket options in prep_socket. Marking here while a real
     * hopping client marks nothing would put our ECN bits on the wire alone. */
    /* BATCHED WHERE THE SHAPE ALLOWS IT, WHICH IS THE STEADY STATE AND NOTHING ELSE.
     *
     * Long-header packets are excluded because they are the handshake: Gecko cuts them into frames
     * of deliberately unequal length, and a batch requires every datagram but the last to be the
     * same size. They are also a handful per connection, so there is nothing to win there — the
     * packet rate lives after the handshake, which is exactly what does batch.
     *
     * Hopping is excluded for the reason the socket options are: a hopping client hands quic-go a
     * conn it cannot take the OOB path with, so upstream sends those one at a time and so do we.
     *
     * A datagram larger than one slot cannot be held at all — it goes out on its own rather than
     * being refused, because refusing here would end a connection over a packet the kernel would
     * have taken. */
    /* The marking this datagram actually carries: only a short header, and only on the OOB path. */
    unsigned mark = oob_conn(c) && (pkt[0] & 0x80u) == 0u ? ecn : 0u;

    if (c->gso_ok && oob_conn(c) && (pkt[0] & 0x80u) == 0u &&
        (size_t)n <= sizeof c->gso_buf / LC_GSO_BATCH) {
        /* A SHORTER DATAGRAM ENDS THE BATCH RATHER THAN BREAKING IT, which is what the kernel's own
         * rule allows and what this missed at first.
         *
         * UDP_SEGMENT cuts the buffer into pieces of the given size and lets the LAST one be
         * shorter — that is how a run of full packets followed by a partial one travels in a single
         * call. Flushing on any change of length instead treated the ordinary end of a write as an
         * error condition: measured on the router, batches averaged 3.4 datagrams of a possible 8,
         * because a full packet is followed by a short one far more often than eight full ones come
         * in a row.
         *
         * A LONGER one still cannot join: it would have to become the new segment size, and the
         * datagrams already waiting would then be cut wrongly. */
        int fits = c->gso_count == 0u ||
                   (mark == c->gso_ecn && (uint16_t)n <= c->gso_seg);
        if (!fits && gso_flush(c) < 0)
            return -1;
        if (c->gso_count == 0u) {
            c->gso_seg = (uint16_t)n;
            c->gso_ecn = mark;
        }
        int last = (uint16_t)n < c->gso_seg;
        memcpy(c->gso_buf + c->gso_len, masked, (size_t)n);
        c->gso_len += (size_t)n;
        c->gso_count++;
        /* The short one is the last one by definition: anything after it would be cut at the wrong
         * offset, since the kernel measures every piece but the final one against gso_seg. */
        if (last || c->gso_count >= LC_GSO_BATCH)
            return gso_flush(c);
        return 0;
    }

    /* Anything that does not batch also ENDS a batch: datagrams leave in the order ngtcp2 produced
     * them, and holding a short-header packet behind a handshake one would reorder them. */
    if (c->gso_count > 0u && gso_flush(c) < 0)
        return -1;

    lc_sendq_entry *en = entry_open(c);
    if (en == NULL)
        return -1;
    memcpy(en->buf, masked, (size_t)n);
    en->len[0] = (uint16_t)n;
    en->ecn[0] = (uint8_t)mark;
    en->n = 1u;
    entry_commit(c);
    return 0;
}

/* Hands the kernel everything in the batch, as one call carrying many datagrams.
 *
 * Returns 0 when the batch is in the send queue, -1 when the connection is over. It no longer waits
 * for anything: the writer thread does that — see quic/sendq.h.
 *
 * ⚠️ A BATCH REFUSED WITH EAGAIN WAS DROPPED HERE, with a paragraph calling holding it "a second copy
 * of the bytes outside ngtcp2's loss recovery". That is the fault txbuf.h describes for stream data
 * handed to ngtcp2 by pointer, and it is not this: a written packet is ngtcp2's to account for, and
 * the one choice left is whether it reaches the wire late or never. quic-go's answer is late — its
 * write blocks — and dropping it put a loss burst on every full socket buffer.
 *
 * ONE cmsg PER BATCH IS WHY THE MARKING IS PART OF THE KEY. UDP_SEGMENT and IP_TOS are attached to
 * the call, not to a datagram, so a batch can only carry packets that agree about both. emit_one
 * flushes when either changes; here they are simply used. */
static int gso_flush(lc_qconn *c)
{
    if (c->gso_count == 0u)
        return 0;

    size_t   len = c->gso_len;
    unsigned count = c->gso_count;
    uint16_t seg = c->gso_seg;
    unsigned ecn = c->gso_ecn;
    c->gso_count = 0u;
    c->gso_len = 0u;
    c->gso_seg = 0u;

    lc_sendq_entry *en = entry_open(c);
    if (en == NULL)
        return -1;
    memcpy(en->buf, c->gso_buf, len);
    /* Every datagram but the last is `seg` bytes — that is what a batch is — so the lengths are
     * recovered here rather than kept twice. The writer needs them only if the kernel refuses the
     * batch AS a batch and it has to go one datagram at a time. */
    unsigned i = 0;
    for (size_t off = 0; off < len; off += seg) {
        size_t piece = len - off < seg ? len - off : seg;
        en->len[i] = (uint16_t)piece;
        en->ecn[i] = (uint8_t)ecn;
        i++;
    }
    en->n = i;
    /* A single datagram gets no segment size: the option would describe a cut that does not happen. */
    en->seg = count > 1u ? seg : 0u;
    entry_commit(c);
    return 0;
}

static int emit(lc_qconn *c, const uint8_t *pkt, size_t len, unsigned ecn)
{
    /* Gecko first, because it wraps Salamander rather than the other way round: the packet is cut
     * into frames here and each frame is scrambled on its own below. Only the handshake is cut —
     * see lc_gecko_applies — so on an established connection this is one comparison and nothing
     * else. */
    if (lc_gecko_applies(&c->gecko, pkt, len)) {
        lc_gecko_out frames;
        if (lc_gecko_split(&c->gecko, pkt, len, &frames) != 0) {
            say(c, "cannot fragment a %zu-byte packet", len);
            return own_failure(c);
        }
        /* EVERY FRAME, AND ALL IN ONE ENTRY. They travel in order behind whatever is already queued,
         * so the packet reaches the wire whole, late if it must, as the reference's blocked write
         * delivers it. One entry rather than one per frame because a packet can be cut into up to
         * LC_GECKO_MAX_CHUNKS, and the write loop reserves room for a packet as two entries — the
         * batch it may have to flush and the packet itself. Each frame keeps its own marking, which
         * is why an entry carries one per datagram. */
        if (c->gso_count > 0u && gso_flush(c) < 0)
            return -1;
        lc_sendq_entry *en = entry_open(c);
        if (en == NULL)
            return -1;
        size_t off = 0;
        for (unsigned i = 0; i < frames.count; i++) {
            long n = lc_obfs_wrap(&c->obfs, frames.frame[i], frames.len[i], en->buf + off,
                                  LC_SENDQ_DGRAM_MAX);
            if (n < 0) {
                say(c, "cannot obfuscate a %u-byte frame", (unsigned)frames.len[i]);
                return own_failure(c);
            }
            en->len[i] = (uint16_t)n;
            en->ecn[i] =
                (uint8_t)(oob_conn(c) && (frames.frame[i][0] & 0x80u) == 0u ? ecn : 0u);
            off += (size_t)n;
        }
        en->n = frames.count;
        entry_commit(c);
        return 0;
    }

    return emit_one(c, pkt, len, ecn);
}

/* What follows every acceptance by ngtcp2 of everything on offer: an end-of-stream that was owed
 * has now been handed over.
 *
 * It used to empty the buffer here as well, on the reasoning that ngtcp2 keeps what it has not had
 * acknowledged. It does keep it — by pointer, into this buffer. See txbuf.h. Emptying the buffer
 * told the next writer the room was free while a retransmit could still read it.
 *
 * One function because it was written out in two places inside flush and the two had to agree; the
 * one that fell behind would have left a stream owing an end-of-stream forever, which from the
 * outside looks like a download that never finishes. */
static void stream_tx_taken(lc_qstream *s)
{
    if (s->tx_fin == LC_QTX_FIN_PENDING)
        s->tx_fin = LC_QTX_FIN_SENT;
}

/* Gives up on the bytes that were never offered to ngtcp2, for a stream whose write side it says is
 * closed, and settles the end-of-stream that will now never be sent as one.
 *
 * This used to be the same "empty the buffer" as the success path, and dropping it entirely would
 * leave a shut stream offering the same bytes to every flush for the life of the connection. */
static void stream_tx_abandon(lc_qstream *s)
{
    lc_qtx_abandon(&s->tx);
    if (s->tx_fin == LC_QTX_FIN_PENDING)
        s->tx_fin = LC_QTX_FIN_SENT;
}

/* ngtcp2 reporting that a run of this stream's bytes will never need sending again. */
static int acked_stream_data_cb(ngtcp2_conn *conn, int64_t stream_id, uint64_t offset,
                                uint64_t datalen, void *user_data, void *stream_user_data)
{
    (void)conn;
    (void)stream_user_data;

    lc_qstream *s = slot_of((lc_qconn *)user_data, stream_id);
    if (s != NULL)
        lc_qtx_ack(&s->tx, offset + datalen);
    return 0;
}

/* The path this connection sends on. Built in one place because it appeared in three, each spelled
 * slightly differently, and a path that disagrees with the socket is a packet ngtcp2 refuses. */
static ngtcp2_path qconn_path(lc_qconn *c)
{
    ngtcp2_path path = {
        .local = { .addr = (struct sockaddr *)&c->local_addr, .addrlen = c->local_len },
        .remote = { .addr = (struct sockaddr *)&c->remote_addr, .addrlen = c->remote_len },
        .user_data = NULL,
    };
    return path;
}

/* HOW MANY DATAGRAMS ARE READ BEFORE THIS CLIENT WRITES — thirty-two, quic-go's own bound, and the
 * third number to stand here.
 *
 * quic-go's reader goroutine queues every datagram on the connection (vendor/quic-go/connection.go:
 * 1978-2004), and the connection's loop takes at most `maxPacketsToProcess = 32` of them off that
 * queue before it sends anything (:1021-1056) — "so we eventually get a chance to send out an ACK
 * when receiving a lot of packets". Its acknowledgement POLICY decides what the ACK says and whether
 * one is owed: two ack-eliciting packets queue one, a 25 ms alarm covers a single packet, and the
 * reordering rules are patches/ngtcp2/0003. Its CADENCE is the batch: however many packets arrived
 * while the loop was busy, up to thirty-two, answered by the writes that follow them. This loop
 * reads the same queue — the kernel's — and does the same: a turn reads up to thirty-two datagrams,
 * and the write path runs after them, or earlier if the socket runs dry.
 *
 * ⚠️ TWO STOOD HERE, TAKEN FROM THE WRONG CONSTANT. `packetsBeforeAck = 2`
 * (vendor/quic-go/internal/ackhandler/received_packet_tracker.go:79) is when quic-go QUEUES an
 * acknowledgement; it is not when one leaves. Writing after every second datagram answered twice as
 * often as the reference does under load, and cost what was measured on the AX3000T, 2026-09-09,
 * six alternating pairs each against an unchanged build: every 2 — 107.6 Mbit/s against 118.1,
 * 9 % slower; every 10 — 124.8 against 105.9, 18 % faster. The capture of the reference that
 * showed about one answer per 10.8 datagrams was the batch showing through, not noise.
 *
 * ⚠️ AND BEFORE THAT, ONE WRITE PER TURN, WHICH WAS NO BOUND AT ALL. flush() stood once at the end of
 * lc_qconn_step, a step drained everything recvmmsg had, and the AX3000T measured 20 017 packets in
 * against 517 out — one answer per 38.7 arrivals, with the peer's sender waiting on us. Thirty-two is
 * the reference's ceiling on exactly that.
 *
 * ⚠️ AND WHAT A TURN COMES OUT AT IS NOT THE REFERENCE'S — DIVERGES: G6. Counted 2026-09-27 on the
 * qstand stand, 32 MB from quic-go's server at 0, 10 and 30 ms of delay: the reference's client sent
 * one acknowledgement-only packet per ~16 datagrams, this one per ~30, and a histogram of these turns
 * at 10 ms found 531 ending on the bound against ~400 on a dry socket. The router reads the same:
 * ~2 500 datagrams out for ~76 800 in over 100 MB on the MT7621. The reference's turn ends early
 * because its queue is fed by a reader goroutine as it reads (handlePacket, vendor/quic-go/
 * connection.go:1978-2004) and emptied by a run loop that leaves the clients to an io.Copy goroutine
 * on another core. Ours is the kernel's queue, which holds everything that has arrived, read by the
 * one thread that also feeds the clients.
 *
 * A reader thread with the reference's ring of 256 was built and measured the same day, and is not
 * in the tree: on the stand it raised the acknowledgements by 15-25 %, a fraction of the gap; on the
 * MT7621, where this thread is the bottleneck, the ring overflowed — 94 700-99 800 datagrams in for
 * the same 100 MB, the node resending what was dropped, against 76 800 and no kernel drops without
 * it — for 40 % more CPU and 5 % more speed. The kernel's queue loses nothing.
 *
 * ⚠️ AND ON THE ROUTERS THE PICTURE ABOVE IS THE STAND'S, NOT THEIRS — measured 2026-09-30 with the
 * reference client itself on the boxes, the LAN stand, 100 MB, datagrams in against datagrams out.
 * With the processor the limit, the reference answers every 28-31 datagrams on the AX3000T and every
 * 28-29 on the MT7621, and this client every 27-30: the same. It is below the limit that the two
 * part, and the other way round from the stand: shaped to 50 and 100 Mbit/s on the AX3000T, the
 * reference answers every 3.3-3.6 and 9.6-9.8, this client every 2.2-2.3 and 4.0-4.5, for about
 * 12 % more processor. A model of the reference's queue, run on the arrival stamps with the loop
 * held for what each packet cost, was tried the same day: 12-18 on the stand and 3.2 on the
 * AX3000T at 100 Mbit/s, further from the reference, and is not in the tree. */
#define LC_QRX_PER_TURN 32u

/* THE KEEP-ALIVE INTERVAL, WHICH IS TEN SECONDS ONLY WHEN THE NODE ALLOWS TWENTY OF IDLE.
 *
 * quic-go fixes it once the peer's parameters are in: `c.keepAliveInterval =
 * min(c.config.KeepAlivePeriod, c.idleTimeout/2)`, where idleTimeout is the smaller of its own and the
 * peer's max_idle_timeout (vendor/quic-go/connection.go:2452-2460) — and schedules each ping no sooner
 * than one and a half PTOs, `max(c.keepAliveInterval, c.rttStats.PTO(true)*3/2)` (:879-885). Ten
 * seconds stood here whatever the node said, so against a node configured with an idle timeout under
 * twenty seconds — hysteria allows four — the reference pings at half of it and this let the
 * connection lapse. Recomputed on each turn because the PTO moves; the rest is fixed by then. */
static void keep_alive_interval(lc_qconn *c)
{
    if (!ngtcp2_conn_get_handshake_completed(c->conn))
        return;
    ngtcp2_duration                idle = LC_QCONN_IDLE_TIMEOUT;
    const ngtcp2_transport_params *rp = ngtcp2_conn_get_remote_transport_params(c->conn);
    if (rp != NULL && rp->max_idle_timeout > 0 && rp->max_idle_timeout < idle)
        idle = rp->max_idle_timeout;
    ngtcp2_duration period = LC_QCONN_KEEP_ALIVE_PERIOD < idle / 2 ? LC_QCONN_KEEP_ALIVE_PERIOD : idle / 2;
    ngtcp2_duration floor = ngtcp2_conn_get_pto(c->conn) * 3 / 2;
    ngtcp2_conn_set_keep_alive_timeout(c->conn, period > floor ? period : floor);
}

/* Added to ngtcp2 by patches/ngtcp2/0003 and declared in its internal lib/ngtcp2_conn.h, for the same
 * reason ngtcp2_conn_get_idle_expiry is declared below: the one prototype, not the whole header. */
void ngtcp2_conn_set_app_stream_data_pending(ngtcp2_conn *conn, int pending);

/* Whether a datagram from the node is already waiting to be read.
 *
 * The reference's send loop asks this after every batch it hands the kernel and stops writing when
 * the answer is yes — "Prioritize receiving of packets over sending out more packets", written
 * twice, once in each of its two send paths (vendor/quic-go/connection.go:2622-2628 and 2668-2674).
 * It then marks the next send as due immediately, so nothing is delayed by having yielded.
 *
 * quic-go can read a flag, because another goroutine fills its receive queue. Here the queue is the
 * socket itself, so the question costs one poll with no timeout — once per batch of up to
 * LC_GSO_BATCH datagrams, against a sendmsg and fourteen packets' worth of encryption on the same
 * path. */
static int rx_waiting(const lc_qconn *c)
{
    if (c->fd < 0)
        return 0;

    struct pollfd p;
    p.fd = c->fd;
    p.events = POLLIN;
    p.revents = 0;
    return poll(&p, 1, 0) > 0 && (p.revents & POLLIN) != 0;
}

static int flush_pass(lc_qconn *c);
static void qconn_control_release(lc_qconn *c);

/* A write pass of the run loop, and after it whatever became runnable while it ran — see
 * qconn_control_release. */
static int flush(lc_qconn *c)
{
    int rc = flush_pass(c);
    if (rc == 0)
        qconn_control_release(c);
    return rc;
}

static int flush_pass(lc_qconn *c)
{
    uint8_t         buf[1500];
    keep_alive_interval(c);
    ngtcp2_path_storage ps;
    ngtcp2_path_storage_zero(&ps);

    /* WHAT THE WRITER HAS LEARNT SINCE THE LAST PASS, read first. An error it met ends the
     * connection, as quic-go's send queue error goes to destroyImpl (vendor/quic-go/connection.go:
     * 602-606), and in the same silence the direct sendmsg used to end it in. A batch it had to send
     * one datagram at a time means no more batches are built (send_conn.go:76-80). */
    int send_err = lc_sendq_error(&c->sq);
    if (send_err != 0) {
        say(c, "cannot send: %s", strerror(send_err));
        c->silent = 1;
        return -1;
    }
    if (c->gso_ok && lc_sendq_gso_failed(&c->sq))
        c->gso_ok = 0;

    /* THE PACE, AND WHO ACCOUNTS FOR IT. Until the port this loop wrote for as long as ngtcp2 had
     * anything to give and the window allowed, with no pacing at all. Then it paced ngtcp2's way —
     * write a batch, then hold the next one back by that batch's worth of time — and the relay in
     * test/hystand/loss.sh, which reports the shape both clients arrive in, said that was still not
     * the reference's shape: nine of ten of its datagrams arrive in the same batch as the one
     * before, against eight of ten here, and its ninetieth-percentile gap was 18 microseconds
     * against our 127.
     *
     * ⚠️ THOSE TWO NUMBERS ARE THE STATE THAT ARGUED FOR THE PORT, NOT THE STATE NOW. The port did
     * not move them (80 % to 80 %); what moved them was feeding the loop — 86 % against the
     * reference's 91-93 as of 2026-09-19, measured over three runs. The whole ladder of what was
     * tried and what each step bought is at LC_GSO_BATCH in conn.h; this paragraph is kept because
     * it says why the bucket is asked per packet, which is still true and is still the reference's
     * shape.
     *
     * So the bucket is asked the way the reference's loop asks it: before every packet, send while
     * there is budget, and stop when there is not (core/internal/congestion/common/pacer.go:31-77, consulted by quic-go's
     * send loop). The bucket is the one ported inside the controller, filled at the rate the
     * controller sets and bounded by its maxBurstSize, so nothing here decides a number — this only
     * decides WHEN to ask. ngtcp2's own pacing is left unused: `ngtcp2_conn_update_pkt_tx_time` is
     * never called, so its next-send time stays unset and it never holds anything back itself. */
    ngtcp2_hybbr *pacer = ngtcp2_conn_hybbr(c->conn);

    /* Whether this pass has put anything on the wire yet, which decides whether it may yield to the
     * reader: the reference checks its receive queue only AFTER a packet has gone out, so every
     * send cycle carries at least one packet however busy the socket is. See rx_waiting. */
    int wrote_one = 0;

    /* Whether the streams have already been topped up since the last packet went out; see the
     * refill below and lc_qrefill_fn in conn.h. */
    int topped_up = 0;

    /* The commit count the send queue was last asked at; see the check at the top of the loop. */
    unsigned asked_at = c->tx_commits;

    /* Whatever was passed over last time is offered again: a window opens and a stream that could
     * not be written a moment ago can be now. */
    for (unsigned i = 0; i < c->st_count; i++)
        st_at(c, i)->tx_skip = 0;

    for (;;) {
        /* A FULL SEND QUEUE ENDS THE PASS, and it is asked where quic-go asks it: before
         * triggerSending, and after every Send (vendor/quic-go/connection.go:730-744, 2611-2613,
         * 2664-2666) — here, at every batch boundary and after anything was committed. Not in the
         * middle of a batch otherwise: that batch is still in gso_buf, as the reference's is in its
         * packet buffer until Send, and the queue has nothing to say about it.
         *
         * "After anything was committed" is the case the reference's order does not have. It
         * decides whether the NEXT packet joins before packing it (`nextECN == ecn`,
         * vendor/quic-go/connection.go:2663-2672); this learns a packet's marking and length only
         * once ngtcp2 has written it, so a packet that cannot join is already packed when the batch
         * before it goes, and it opens a batch of its own. That batch is flushed if the queue is now full, and it
         * leaves right behind the eight, where the reference's next packet would have been queued.
         *
         * Which is also the bound LC_SENDQ_SLOTS is sized to: a check that passes leaves at most
         * seven waiting, one packet commits at most two entries (the batch it closes and itself),
         * and the next iteration asks again — so nine waiting and one being written, never more.
         *
         * Asking arms the wake: the entry the writer frees next makes lc_qconn_wake_fd readable,
         * and nothing else ever does, which is the reference's run loop selecting on Available()
         * only while it is blocked (vendor/quic-go/connection.go:664,
         * vendor/quic-go/connection.go:729-736, vendor/quic-go/connection.go:746-753). */
        if (c->gso_count == 0u || c->tx_commits != asked_at) {
            asked_at = c->tx_commits;
            if (lc_sendq_would_block(&c->sq)) {
                c->tx_stop_blocked++;
                return gso_flush(c) < 0 ? -1 : 0;
            }
        }

        /* One codepoint per datagram, and every writer that fills this packet shares it: the
         * pkt_info is handed to ngtcp2 only once the handshake is complete, for the reason spelled
         * out at the stream writer. Reset each packet because ngtcp2 asserts it arrives as NOT_ECT —
         * and kept for the whole packet, with the same clock, because a packet built across several
         * calls must be given the same conn, path, pi, buffer and timestamp on each
         * (ngtcp2_conn_writev_stream's contract for NGTCP2_ERR_WRITE_MORE). */
        ngtcp2_pkt_info tx_pi;
        memset(&tx_pi, 0, sizeof tx_pi);
        int             marking = c->ecn_ok && ngtcp2_conn_get_handshake_completed(c->conn);
        ngtcp2_tstamp   ts = now_ns();

        /* The bucket, before the packet rather than after the batch: what the reference's send loop
         * asks, and what keeps a burst the size its budget allows instead of the size the window
         * allows. Out of budget ends this wakeup; the connection's timer carries the moment the
         * bucket will have a datagram's worth again. */
        if (pacer != NULL && !ngtcp2_hybbr_pacer_can_send(pacer, ts)) {
            c->tx_stop_paced++;

            /* AND ONE ACKNOWLEDGEMENT MAY STILL GO, which is what the reference does here and what
             * this loop used to leave on the floor. quic-go parks its pacing deadline and then calls
             * maybeSendAckOnlyPacket (vendor/quic-go/connection.go:2496-2505); ngtcp2 does the same
             * thing in the branch its own pacer guards — and patch 0009 moved the pacing decision
             * out here, so that branch became unreachable and the acknowledgement went with it.
             *
             * The relay measured what it cost: small datagrams were 15.6 % of the reference's
             * traffic against 4.8 % of ours, and that difference is the whole back-to-back density
             * gap. See patches/ngtcp2/0010 and tx_stop_paced in conn.h.
             *
             * Charged to the bucket, because the reference charges it: hysteria's BBR does
             * pacer.SentPacket first thing in OnPacketSent, whether or not the packet was
             * ack-eliciting (core/internal/congestion/bbr/bbr_sender.go:444-451). */
            uint8_t        ackbuf[LC_GECKO_BUFFER];
            ngtcp2_pkt_info ack_pi;
            ngtcp2_ssize   acklen;

            memset(&ack_pi, 0, sizeof ack_pi);
            /* With a pkt_info only where ECN is on at all, as the rest of the loop: patch 0030 marks
             * an ACK-only packet as quic-go does, and quic-go has no tracker to ask on a connection
             * without ECN (vendor/quic-go/internal/ackhandler/sent_packet_handler.go:180-182). */
            acklen = ngtcp2_conn_write_ack_pkt_1rtt(c->conn, c->ecn_ok ? &ack_pi : NULL, ackbuf,
                                                    sizeof ackbuf, ts);
            if (acklen > 0) {
                c->tx_packets++;
                ngtcp2_hybbr_pacer_sent(pacer, ts, (uint64_t)acklen);
                if (emit(c, ackbuf, (size_t)acklen, ack_pi.ecn) < 0)
                    return -1;
            } else if (acklen < 0) {
                say(c, "ngtcp2 refused to write an acknowledgement: %s",
                    ngtcp2_strerror((int)acklen));
                return write_refused(c, acklen);
            }

            return gso_flush(c) < 0 ? -1 : 0;
        }

        /* AND THE READER GOES FIRST once a packet has gone out and something is waiting. This is
         * the reference's own rule, and it is the answer to the question tx_stop_paced used to end
         * on: what wakes its send loop often enough to put three times as many bare acknowledgements
         * on the wire. Nothing wakes it — it never gets far from the top. Its send cycle writes one
         * batch, sees a received packet waiting and returns; the run loop reads up to thirty-two
         * packets and calls triggerSending again, which asks the pacer FIRST and, when the answer is
         * no, sends the acknowledgement those packets have just made due
         * (vendor/quic-go/connection.go:2486-2505, 2622-2628, 2683-2689).
         *
         * This loop instead wrote until the bucket ran out, and by then the acknowledgement had
         * ridden out in a data packet — cheaper per byte, and a different shape on the wire.
         *
         * Asked at a batch boundary only: gso_count is zero exactly when the kernel has everything
         * written so far, which is where the reference asks it too. */
        if (wrote_one && c->gso_count == 0u && rx_waiting(c)) {
            c->tx_stop_yield++;
            return 0;
        }

        /* Whether stream data will follow in this packet, told to ngtcp2 before its first write:
         * quic-go puts a pending ACK into any packet that carries data (patches/ngtcp2/0003), and
         * that first write may be the DATAGRAM, before ngtcp2 has seen any stream. */
        int streams_pending = 0;
        for (unsigned i = 0; i < c->st_count && !streams_pending; i++) {
            const lc_qstream *s = st_at(c, i);
            streams_pending = s->state != LC_QSLOT_FREE && !s->tx_skip &&
                              (lc_qtx_pending(&s->tx) > 0 || s->tx_fin == LC_QTX_FIN_PENDING);
        }
        ngtcp2_conn_set_app_stream_data_pending(c->conn, streams_pending);

        /* A PACKET IS FILLED THE WAY QUIC-GO FILLS ONE: an ACK, at most ONE datagram, then stream
         * frames from the active streams in turn, for as long as a frame still fits
         * (vendor/quic-go/packet_packer.go:725-785 — `datagramQueue.Peek()` once, then
         * `framer.Append`; vendor/quic-go/framer.go:177-223, `for range numActiveStreams` until less
         * than MinStreamFrameSize is left). The turn is by urgency and then round-robin among
         * incremental streams, and every stream quic-go opens is urgency 3 and incremental
         * (vendor/quic-go/send_stream.go:105) — hysteria sets no priority — so for this client it is
         * one round-robin, as it was.
         *
         * INSIDE the packet it is quic-go's since patches/ngtcp2/0022: the DATAGRAM is given its room
         * right after the ACK, before any control frame (vendor/quic-go/packet_packer.go:736-761), and
         * the payload is laid out as appendPacketPayload lays it out — the ACK, the padding, every
         * other frame that is not STREAM in an order drawn afresh for each packet, then the STREAM
         * frames, the last without its Length (vendor/quic-go/packet_packer.go:1055-1092).
         *
         * LOST STREAM DATA GOES FIRST, and it is not this loop that sends it. Since f1cdf4e0 the
         * framer sends every stream's retransmissions before any stream's new data
         * (vendor/quic-go/framer.go:140-176). ngtcp2 did that already — its queue of streams with
         * lost data is drained into each packet before the stream handed to it here is asked for —
         * and this said, until 2026-09-26, that it retransmitted "on that stream's own turn", which
         * it never did. What did differ was the order among those streams: patches/ngtcp2/0017
         * queues them first in, first out, and 0019 declares the losses oldest first, as quic-go
         * does, so that they go back in its order. Within one stream each lost frame goes back to the
         * end of the stream's own queue, whole, and is resent on its own, cut only where it does not
         * fit (patches/ngtcp2/0023, as vendor/quic-go/send_stream.go:508-532 and :897-941): ngtcp2
         * resent by offset and as one frame where lost ranges met.
         *
         * ⚠️ WHAT STOOD HERE PUT ONE THING IN EACH PACKET — every queued datagram first, each alone,
         * then one stream's bytes per packet — so a download beside a DNS lookup, or two uploads at
         * once, went out as more and smaller packets than the reference sends for the same load.
         * Packet sizes are what a path sees through any obfuscation. ngtcp2 coalesces on request:
         * NGTCP2_WRITE_DATAGRAM_FLAG_MORE and NGTCP2_WRITE_STREAM_FLAG_MORE answer
         * NGTCP2_ERR_WRITE_MORE while there is room, and a call with no stream finishes the packet. */
        if (c->dq_count > 0) {
            ngtcp2_vec dv = { .base = c->dq + (size_t)c->dq_head * LC_QUDP_SLOT,
                              .len = c->dq_len[c->dq_head] };

            int          taken = 0;
            ngtcp2_ssize dwritten = ngtcp2_conn_writev_datagram(
                c->conn, &ps.path, marking ? &tx_pi : NULL, buf, sizeof buf, &taken,
                NGTCP2_WRITE_DATAGRAM_FLAG_MORE, 0, &dv, 1, ts);

            /* Two refusals are about this datagram and not the connection: one says the node never
             * agreed to receive any, the other that this one is larger than it agreed to. Neither
             * is fixed by trying again, and a queue that keeps retrying is a queue that never
             * sends anything else either. */
            if (dwritten == NGTCP2_ERR_INVALID_STATE || dwritten == NGTCP2_ERR_INVALID_ARGUMENT) {
                say(c, "the node will not take a %u-byte datagram: %s",
                    (unsigned)c->dq_len[c->dq_head], ngtcp2_strerror((int)dwritten));
                c->dq_head = (c->dq_head + 1u) % LC_QUDP_QUEUE;
                c->dq_count--;
                continue;
            }
            if (dwritten < 0 && dwritten != NGTCP2_ERR_WRITE_MORE) {
                say(c, "ngtcp2 refused to write a datagram: %s", ngtcp2_strerror((int)dwritten));
                return write_refused(c, dwritten);
            }
            if (taken) {
                c->dq_head = (c->dq_head + 1u) % LC_QUDP_QUEUE;
                c->dq_count--;
            }
            if (dwritten == 0)
                return gso_flush(c) < 0 ? -1 : 0; /* no room in this packet and none to be had now */
            if (dwritten > 0) {
                /* Not charged to the bucket here: ngtcp2 already did, see the stream writer below. */
                if (emit(c, buf, (size_t)dwritten, tx_pi.ecn) < 0)
                    return -1;
                continue;
            }
            /* NGTCP2_ERR_WRITE_MORE: the packet has room — for streams only, since quic-go takes one
             * datagram per packet and a second would be a packet shape it cannot produce. The
             * datagram is in it, or it did not fit beside the ACK and waits at the head of the queue
             * for a later packet, as quic-go's does (patches/ngtcp2/0022; `taken` says which). The
             * one it drops instead — too large even for an empty packet — is one lc_qudp_fit never
             * lets this queue hold. */
        }

        /* The streams, in turn from where the last packet left off: a scan from zero would give a
         * busy download the link to itself while everything opened after it waited behind. A stream
         * whose bytes all went in has nothing left to offer this packet; one that filled it goes to
         * the back, as quic-go's streamQueue puts it. */
        ngtcp2_ssize written = 0;
        int          done = 0;
        unsigned     start = c->st_turn;
        for (unsigned n = 0; n < c->st_count && !done; n++) {
            unsigned    i = (start + n) % c->st_count;
            lc_qstream *s = st_at(c, i);
            if (s->state == LC_QSLOT_FREE || s->tx_skip)
                continue;
            if (lc_qtx_pending(&s->tx) == 0 && s->tx_fin != LC_QTX_FIN_PENDING)
                continue;

            /* Every contiguous run of unsent bytes, not just the first: the queue is a list of
             * blocks now, and handing over one run at a time would end each packet wherever a block
             * happened to end. */
            ngtcp2_vec vec[LC_QTX_VECS];
            size_t     veccnt = 0;
            uint8_t   *at;
            size_t     len;
            for (unsigned v = 0; v < LC_QTX_VECS && lc_qtx_run(&s->tx, v, &at, &len); v++) {
                vec[v].base = at;
                vec[v].len = len;
                veccnt++;
            }
            uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
            if (s->tx_fin == LC_QTX_FIN_PENDING)
                flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
            c->st_turn = (i + 1u) % c->st_count;

            /* Minus one, not zero, is ngtcp2's way of saying it wrote no stream data at all — a
             * packet of acknowledgements, or a stream it could not fit. Zero means it did write
             * stream data and there happened to be none of it, which is what sending a bare
             * end-of-stream looks like, so the two cases cannot share a test. */
            ngtcp2_ssize accepted = -1;
            /* WITHHELD UNTIL THE HANDSHAKE IS DONE. Upstream ngtcp2 marked whatever packet it was
             * writing when given a pkt_info, long headers included
             * (vendor/ngtcp2/lib/ngtcp2_conn.c:2822, :4563), which would have put ECT(0) on our
             * Initial where quic-go puts Not-ECT (`if !isShortHeaderPacket { return
             * protocol.ECNNon }`, vendor/quic-go/internal/ackhandler/sent_packet_handler.go:
             * 1008-1010). Patch 0030 now chooses the mark per datagram as quic-go does, so a long
             * header makes its datagram Not-ECT either way; and before the handshake is done a
             * client has no 1-RTT packet to mark, so the gate changes nothing on the wire. It
             * stays because it is where quic-go's tracker starts too: the first datagram that can
             * be marked is the first one holding only a 1-RTT packet
             * (vendor/quic-go/internal/ackhandler/ecn.go:122-134). */
            ngtcp2_ssize w = ngtcp2_conn_writev_stream(c->conn, &ps.path, marking ? &tx_pi : NULL,
                                                       buf, sizeof buf, &accepted, flags, s->id,
                                                       veccnt > 0 ? vec : NULL, veccnt, ts);
            if (accepted >= 0) {
                lc_qtx_sent(&s->tx, (size_t)accepted);
                if (lc_qtx_pending(&s->tx) == 0)
                    stream_tx_taken(s);
                /* A connection whose owner has let it go, whose last bytes and end-of-stream are now
                 * ngtcp2's to deliver. Nothing here is needed to do that — except the bytes
                 * themselves, which ngtcp2 holds by pointer and will read again if a packet is lost.
                 * Freeing them here was a use-after-free that only a retransmit could reach. What is
                 * still in flight is released instead by stream_close_cb, which ngtcp2 calls once it
                 * has stopped referring to this stream at all. */
                if (s->state == LC_QSLOT_CLOSING && s->tx_fin == LC_QTX_FIN_SENT &&
                    !lc_qtx_inflight(&s->tx))
                    slot_release(s);
            }
            /* Three refusals are about one stream rather than the connection, and all three used to
             * end the tunnel. "Blocked" is flow control doing its job: the peer's window for this
             * stream is full and will open again, so the bytes stay put. "Shut" and "not found" mean
             * the write side is closed or the stream is gone entirely, so these bytes will never go
             * — which is what a finished proxied request looks like from here. None of the three
             * ends a packet being built: the next stream may still go into it.
             *
             * The slot is not released here. Whoever owns the stream releases it on its own path,
             * and doing it from inside the writer as well left the table and ngtcp2 disagreeing
             * about which ids exist — which is the "not found" this same branch now has to absorb. */
            if (w == NGTCP2_ERR_STREAM_DATA_BLOCKED || w == NGTCP2_ERR_STREAM_SHUT_WR ||
                w == NGTCP2_ERR_STREAM_NOT_FOUND) {
                s->tx_skip = 1;
                if (w != NGTCP2_ERR_STREAM_DATA_BLOCKED)
                    stream_tx_abandon(s);
                continue;
            }
            if (w == NGTCP2_ERR_WRITE_MORE)
                continue;
            if (w < 0) {
                say(c, "ngtcp2 refused to write: %s", ngtcp2_strerror((int)w));
                return write_refused(c, w);
            }
            written = w;
            done = 1;
        }

        /* No stream left to offer: finish the packet being built, or let ngtcp2 write the one it has
         * of its own — acknowledgements, control frames, a retransmission. */
        if (!done) {
            ngtcp2_ssize accepted = -1;
            written = ngtcp2_conn_writev_stream(c->conn, &ps.path, marking ? &tx_pi : NULL, buf,
                                                sizeof buf, &accepted, NGTCP2_WRITE_STREAM_FLAG_NONE,
                                                -1, NULL, 0, ts);
            if (written < 0) {
                say(c, "ngtcp2 refused to write: %s", ngtcp2_strerror((int)written));
                return write_refused(c, written);
            }
        }

        /* Nothing more to write. ASK FOR MORE BEFORE GIVING UP, which is what the reference's
         * writer does without being asked: see lc_qrefill_fn in conn.h.
         *
         * Once between packets, and only once: the flag is cleared every time something actually
         * goes out, so a top-up that produces a packet earns another, and one that produces nothing
         * ends the pass. That is what makes this terminate — a stream blocked by its flow control
         * accepts the bytes and still writes none, and the second ask would be the same ask. */
        if (written == 0 && !topped_up && c->on_dry != NULL && c->on_dry(c->on_dry_user)) {
            topped_up = 1;
            continue;
        }

        /* Nothing more to write is where the batch goes out: ngtcp2 has emptied itself, so whatever
         * is held here is the tail of this wakeup and has nobody behind it to fill the slot. Held
         * any longer it would wait for the next packet from the far end, which is a round trip. */
        if (written == 0) {
            c->tx_stop_dry++;
            return gso_flush(c) < 0 ? -1 : 0;
        }

        topped_up = 0;

        c->tx_packets++;
        wrote_one = 1;
        /* ⚠️ NOT CHARGED TO THE BUCKET HERE, AND FOR TWO DAYS IT WAS CHARGED TWICE. The reference
         * charges every packet once, in OnPacketSent (core/internal/congestion/bbr/bbr_sender.go:
         * 444-451), and the port does the same in ngtcp2_cc_hybbr_on_pkt_sent — which ngtcp2 calls
         * for every ack-eliciting packet from inside the write that produced it
         * (vendor/ngtcp2/lib/ngtcp2_conn.c:1920-1927). A second charge here, added on 19 September
         * with the per-packet ask, made every data packet cost the bucket twice its size: the pace
         * this client actually kept was HALF the rate its controller set.
         *
         * Measured on the one-way stand before the fix, against the reference with counters in a
         * copy of quic-go: 8 655 of our 10 141 write passes ended on the pacer, where the reference's
         * triggerSending found SendPacingLimited 19 times in 3 162 (and 220 more mid-batch). That is
         * the whole of the "pause, hole in the acks, pause" loop loss.sh describes: a sender paced at
         * half speed stops, and the stop comes back as a gap in the acknowledgements.
         *
         * The one packet ngtcp2 does NOT report is an acknowledgement on its own, and that one is
         * charged where it is written — the paced branch at the top of this loop. */
        if (emit(c, buf, (size_t)written, tx_pi.ecn) < 0)
            return -1;
    }
}

int lc_qconn_open(lc_qconn *c, const char *host, uint16_t port, const char *sni,
                  const char *obfs_password, const uint8_t *pin)
{
    /* WHAT SURVIVES THE WIPE, and why anything does.
     *
     * This memset is right: a connection is built from nothing, and carrying state across from the
     * one before it is how a reconnect inherits a fault. But hopping is asked for BEFORE opening —
     * it has to be, since the first dial already depends on it — so a plain wipe erased the setting
     * between being given and being used. The symptom was a `-j 20` that parsed, printed no
     * complaint, and moved nothing: the port sat still for forty-eight seconds while the option was
     * in the command line the whole time.
     *
     * Restored explicitly rather than moved out of the wipe's way, so that adding a field here is a
     * decision instead of an accident. */
    unsigned            hop_min_ms = c->hop_min_ms, hop_max_ms = c->hop_max_ms;
    const lc_hop_ports *hop_ports = c->hop_ports;
    /* Gecko is asked for before opening for the same reason hopping is, and would be erased by the
     * same wipe. Only the three settings are carried across, not the reassembly table: half a
     * packet held from the connection before this one belongs to a msgID nobody will complete, and
     * the table is seventy-six kilobytes that would be copied twice to keep it. */
    int      gecko_on = c->gecko.on;
    unsigned gecko_min = c->gecko.min_packet, gecko_max = c->gecko.max_packet;
    /* And the parrot, for the same reason again: it decides the first packet. */
    int plain = c->plain;

    memset(c, 0, sizeof *c);
    /* THE DESCRIPTORS ARE INVALIDATED FIRST, before anything below can return early.
     *
     * memset leaves them zero, and zero is standard input — a perfectly good descriptor that this
     * connection does not own. These three lines used to sit after the Gecko check, so a caller who
     * gave unusable packet sizes got -1 from here with c->fd still reading 0, and the tidy-up that
     * follows a failed open closes what it is given. Closing standard input on a router is not a
     * crash: the process keeps running with descriptor 0 free, and the next socket it opens becomes
     * 0, so a later close of "no descriptor" reaches a live connection instead. */
    c->fd = -1;
    c->prev_fd = -1;
    c->auth_id = -1;
    c->hop_min_ms = hop_min_ms;
    c->hop_max_ms = hop_max_ms;
    c->hop_ports = hop_ports;
    c->plain = plain;
    c->chrome = !plain;
    if (lc_gecko_init(&c->gecko, gecko_on, gecko_min, gecko_max) != 0) {
        say(c, "the gecko packet sizes are not usable");
        return -1;
    }

    if (lc_obfs_init(&c->obfs, obfs_password) != 0) {
        say(c, "the obfuscation password is not usable (four to %u bytes)",
            (unsigned)sizeof c->obfs.password);
        return -1;
    }

    /* THE PORT MAY BE A RANGE, asked for with lc_qconn_hop_on before this call. When it is, the
     * first dial takes a port from the range like every later one, and lc_qconn_hop moves on about
     * every half minute — see the note in the header for why this exists at all. The choosing lives
     * in lc_hop_port, which both callers share and test/hop pins; whether there IS a range is asked
     * here, because it is the caller's question and only this caller has another port to fall to. */
    snprintf(c->node_host, sizeof c->node_host, "%s", host);
    if (hopping(c) && lc_hop_ports_pick(c->hop_ports, &port) != 0) {
        say(c, "the system could not provide randomness for the node port");
        return -1;
    }
    c->node_port = port;
    if (hopping(c))
        arm_hop(c);
    if (dial_node(c, host, port, &c->fd, &c->remote_addr, &c->remote_len) != 0)
        return -1;
    /* The writer, before the first datagram — the flush at the end of this function sends the
     * ClientHello. ⛔ No synchronous path beside it: a connection whose writer cannot start does
     * not open. See quic/sendq.h. */
    lc_sendq_dest first;
    cur_dest(c, &first);
    if (lc_sendq_start(&c->sq, &first) != 0) {
        say(c, "cannot start the thread that writes to the node");
        goto fail;
    }
    /* And the threads that open the node's packets ahead of ngtcp2 — see quic/rxopen.h. None on a
     * single core, where the loop opens them itself through the same code; like the writer, a
     * connection whose threads cannot start does not open. */
    if (lc_rxopen_new(&c->rx, &c->obfs) != 0) {
        say(c, "cannot start the threads that open the node's packets");
        goto fail;
    }

    c->local_len = sizeof c->local_addr;
    if (getsockname(c->fd, (struct sockaddr *)&c->local_addr, &c->local_len) != 0) {
        say(c, "cannot set the socket up");
        goto fail;
    }
    ngtcp2_cid dcid, scid;

    /* BOTH LENGTHS TRAVEL IN THE CLEAR, and both were ours rather than the reference's.
     *
     * A long header carries them as plain bytes right after the version: DCID length, DCID, SCID
     * length, SCID. Nothing protects them — they are what a receiver needs before it can derive the
     * Initial keys — so they are readable in the first packet of every connection by anybody on the
     * path, and two constants where the imitated client has a distribution and a different constant
     * is as cheap a discriminator as exists.
     *
     * The destination identifier: quic-go draws its LENGTH as well as its bytes.
     * GenerateConnectionIDForInitial takes one random byte and computes
     * `MinConnectionIDLenInitial + int(r[0])%(maxConnectionIDLen-MinConnectionIDLenInitial+1)`
     * (vendor/quic-go/internal/protocol/connection_id.go:60-70) — eight plus r%13, so a length
     * spread over 8..20. Ours said "only its length is fixed by the protocol" and used the minimum,
     * eight, every time. The protocol fixes a MINIMUM of eight and nothing else.
     *
     * The remainder is reproduced as the reference computes it, bias included: 256 is not a multiple
     * of thirteen, so lengths 8..16 come up very slightly more often than 17..20. Correcting that
     * would be a distribution no quic-go client has.
     *
     * The source identifier: four, because hysteria builds `quic.Transport{Conn: pktConn}` with
     * neither ConnectionIDLength nor ConnectionIDGenerator
     * (vendor/hysteria/core/client/client.go:96), and a Transport left unset takes
     * protocol.DefaultConnectionIDLength — which is 4 (vendor/quic-go/transport.go:433-438,
     * vendor/quic-go/internal/protocol/params.go:124). Ours was eight.
     *
     * Measured against the reference on a local stand before and after: its first Initial carried
     * DCID length 0x0c and SCID length 0x04, ours 0x08 and 0x08.
     *
     * ⚠️ BOTH OF THOSE ARE hysteria 2.10, AND 2.12 SAYS OTHERWISE. A client parroting Chrome — the
     * default from 2.11 — sets ZeroLengthConnectionIDGenerator on its Transport
     * (vendor/hysteria/core/client/client.go:97-103), so the source identifier is EMPTY, and dials
     * with GenerateChromeConnectionIDForInitial (vendor/quic-go/transport.go:296-300), a
     * destination identifier of exactly eight (vendor/quic-go/internal/protocol/connection_id.go:71-80)
     * — the draw above belongs to a client that has turned the parrot off. */
    uint8_t len_draw = 0;
    if (c->chrome) {
        /* The parrot's two, which the paragraph above ends on: eight bytes drawn with no length
         * draw ahead of them (GenerateChromeConnectionIDForInitial,
         * vendor/quic-go/internal/protocol/connection_id.go:71-80, chosen at
         * vendor/quic-go/transport.go:296-300), and an empty source identifier. ngtcp2 takes a
         * zero-length one as RFC 9000 allows and then issues no NEW_CONNECTION_ID, as quic-go
         * issues none for a generator of length zero. */
        dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
        scid.datalen = 0;
    } else {
        if (lc_rnd(&len_draw, 1) != 0) {
            say(c, "no randomness for the connection identifiers");
            goto fail;
        }
        dcid.datalen = (size_t)NGTCP2_MIN_INITIAL_DCIDLEN + len_draw % 13u;
        scid.datalen = 4;
    }
    if (lc_rnd(dcid.data, dcid.datalen) != 0 || lc_rnd(scid.data, scid.datalen) != 0) {
        say(c, "no randomness for the connection identifiers");
        goto fail;
    }

    ngtcp2_callbacks callbacks = {
        .client_initial = ngtcp2_crypto_client_initial_cb,
        .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
        .recv_stream_data = recv_stream_data_cb,
        .acked_stream_data_offset = acked_stream_data_cb,
        .stream_close = stream_close_cb,
        .handshake_completed = handshake_completed_cb,
        .encrypt = ngtcp2_crypto_encrypt_cb,
        .decrypt = ngtcp2_crypto_decrypt_cb,
        .hp_mask = ngtcp2_crypto_hp_mask_cb,
        .recv_retry = ngtcp2_crypto_recv_retry_cb,
        .rand = rand_cb,
        .get_new_connection_id2 = get_new_connection_id_cb,
        /* Not optional plumbing: the peer INITIATES a key update after its first hundred packets
         * — `FirstKeyUpdateInterval uint64 = 100`, then every hundred thousand
         * (vendor/quic-go/internal/handshake/updatable_aead.go:31-32, KeyUpdateInterval at
         * vendor/quic-go/internal/protocol/params.go:151). Every connection that carries real
         * traffic crosses a key phase flip within seconds, and this callback is why that flip is
         * survived rather than read as garbage. ngtcp2's stock implementation does the whole dance;
         * there is nothing of ours in it to test, but there is something to refuse to remove.
         *
         * AND WE INITIATE THEM AS THE REFERENCE DOES, since 2026-09-27: the rule is not the
         * server's but updatableAEAD's, which quic-go builds for a client and a server alike
         * (vendor/quic-go/internal/handshake/crypto_setup.go:73, :116, :168), so a hysteria client
         * flips on the same counts — patches/ngtcp2/0026 carries them into ngtcp2, which on its own
         * rotates only at the AEAD limit (ngtcp2_conn.c:8731-8735).
         *
         * ⚠️ WHAT STOOD HERE WAS "A KNOWN, DECIDED GAP … LEFT AS IT IS", argued from the key phase
         * bit sitting under header protection (vendor/quic-go/internal/handshake/header_protector.go:75,
         * :129), so that only our own node could tell. True, and not a reason: nobody had decided
         * it but this comment, and a gap only the node can see is still a gap. */
        .update_key = ngtcp2_crypto_update_key_cb,
        .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
        .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
        .get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb,
        .version_negotiation = ngtcp2_crypto_version_negotiation_cb,
        .recv_datagram = recv_datagram_cb,
    };

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = now_ns();
    /* ngtcp2's own account of every frame it sends and receives, behind an environment variable.
     * A QUIC connection that fails says nothing on a socket — there is no alert and no reset — so
     * without this the only symptom is silence. */
    if (getenv("LC_QUIC_LOG") != NULL)
        settings.log_printf = log_printf;

    /* THE TWO SENDER CADENCES ARE THE REFERENCE'S, said here so the constants ledger stops counting
     * them as unexamined. The pace is hysteria's own bucket, which never waits less than
     * MinPacingDelay (patches/ngtcp2/0009 and the write loop below; ngtcp2's pacer is left unused),
     * and the twentieth pure ACK in a row carries a PING, MaxNonAckElicitingAcks
     * (vendor/quic-go/internal/protocol/params.go:71; NGTCP2_MAX_NON_ACK_ELICITING_ACKS, see
     * write_single_frame_pkt and conn_write_pkt in the patched ngtcp2).
     *
     * ⚠️ "TWO SENDER CADENCES THAT STAY NGTCP2'S … this client sets neither knob because ngtcp2
     * exposes neither" stood here until 2026-09-27, long after both had been ported. */

    /* AND THE REST OF THE LEDGER, READ ONE BY ONE RATHER THAN LEFT UNNAMED.
     *
     * lcdefaults.sh lists the reference's behaviour constants that nothing here cites, on the rule
     * that an uncited constant is a place where a divergence is invisible to BOTH passes of the
     * sieve — the forward one walks our references, the reverse one walks functions we reference,
     * and a number nobody mentioned appears in neither. Seventeen were listed. They are not all the
     * same kind of silence, and the difference is the whole point, so each was opened:
     *
     * FOUR ARE A ROLE WE DO NOT PLAY. Max0RTTQueueLen, Max0RTTQueues, MaxAcceptQueueSize and
     * MinUnknownVersionPacketSize (vendor/quic-go/internal/protocol/params.go:163,
     * vendor/quic-go/internal/protocol/params.go:157,
     * vendor/quic-go/internal/protocol/params.go:54,
     * vendor/quic-go/internal/protocol/protocol.go:121) are used only from quic-go's server.go —
     * queues of connections waiting to be accepted, 0-RTT buffered for connections not yet made,
     * and the size at which an unknown version earns a Version Negotiation reply. A client reaches
     * none of that code, and the same goes for MinStatelessResetSize
     * (vendor/quic-go/internal/protocol/protocol.go:124), which sizes a reset the transport SENDS,
     * and for MaxPostHandshakeCryptoFrameSize (vendor/quic-go/internal/protocol/params.go:107),
     * which chops CRYPTO frames sent AFTER the handshake — quic-go reaches it through
     * GetSessionTicket (vendor/quic-go/connection.go:984-991), and a TLS 1.3 client has nothing of
     * its own to put on that stream: it receives NewSessionTicket, it does not send one.
     *
     * SIX ARE BOOKKEEPING WITH NO WIRE SHAPE. MaxByteCount is a type's ceiling
     * (vendor/quic-go/internal/protocol/protocol.go:99); MaxConnUnprocessedPackets is a receive
     * queue depth (vendor/quic-go/internal/protocol/params.go:43); MaxStreamFrameSorterGaps and
     * MinStreamFrameBufferSize guard the reassembler against a peer sending many tiny frames
     * (vendor/quic-go/internal/protocol/params.go:75,
     * vendor/quic-go/internal/protocol/params.go:80); MaxOutstandingSentPackets and
     * MaxTrackedSentPackets are soft limits inside loss recovery
     * (vendor/quic-go/internal/protocol/params.go:62,
     * vendor/quic-go/internal/protocol/params.go:67). Different numbers here change when a stack
     * gives up under abuse, not what a watcher sees.
     *
     * AND THE FEW THAT DO TOUCH A CLIENT, none of them ours to set. Written flat rather than as an
     * indented list because lcquote.pl reads a deeper-indented comment line as quoted reference
     * code, and prose dressed as a quotation is noise in the one check that reads quotations.
     *
     * MinCoalescedPacketSize (vendor/quic-go/internal/protocol/params.go:84) is the one with a
     * shape: packet_packer.go:390 stops coalescing when fewer than 128 bytes remain, so the
     * reference's handshake datagrams carry a particular arrangement of long-header packets, and
     * lengths in a long header are in the clear. ngtcp2 coalesces by its own rule and exposes no
     * knob for this, so the arrangement is ngtcp2's — worth knowing it is a SHAPE and not a
     * constant, if a datagram-layout distinguisher is ever looked for. ⚠️ And from hysteria 2.11
     * the reference does not coalesce at all while it parrots Chrome, its default: noCoalescing
     * sends every encryption level in a datagram of its own (vendor/quic-go/packet_packer.go:185-191,
     * :391-393, :427-429).
     *
     * MaxNumAckRanges (vendor/quic-go/internal/protocol/params.go:115) bounds the ranges in an ACK
     * frame, and ACK frames travel encrypted: the only party who could compare is the peer, which
     * is our own node. MaxConnIDLen (vendor/quic-go/internal/protocol/protocol.go:149) is the 20
     * that bounds the 8..20 draw already reproduced where the identifiers are made, above.
     * MinReceivedStatelessResetSize (vendor/quic-go/internal/protocol/protocol.go:128) is how a
     * client RECOGNISES a stateless reset it is sent; ngtcp2 implements the same RFC 9000 test, and
     * a client that fails it hangs rather than emitting anything.
     *
     * MinInitialPacketSize (vendor/quic-go/internal/protocol/protocol.go:117) is the RFC floor of
     * 1200 and not a choice; what a client actually puts on the wire is InitialPacketSize, which is
     * 1280 and is reproduced a few lines below with its own measurement. */
    /* THE CEILING, THE SIZE WE START AT, AND THE SEARCH BETWEEN THEM — THREE NUMBERS, NOT ONE.
     *
     * quic-go has all three and keeps them apart. It sends InitialPacketSize = 1280 until Path MTU
     * Discovery has something larger to offer (vendor/quic-go/internal/protocol/params.go:5-6,
     * vendor/quic-go/connection.go:2900-2916); the largest it will ever send is
     * min(MaxPacketBufferSize = 1452, the node's advertised max_udp_payload_size)
     * (vendor/quic-go/internal/protocol/protocol.go:107-111, quic-go/connection.go:2474-2483); and between
     * the two it searches, halving the interval with a probe packet every five smoothed RTTs
     * (vendor/quic-go/mtu_discoverer.go:14-23, :138-165). hysteria overrides none of them, and on
     * Linux it leaves discovery on (vendor/hysteria/core/internal/pmtud/avail.go:6).
     *
     * ngtcp2 had two of the three and tied them together: the ceiling doubled as the padding target
     * and as the hard maximum its own PMTUD would probe, and its PMTUD walked a fixed table of
     * sizes rather than searching. That is why this client used to set the ceiling to 1280 with
     * shaping off and switch discovery off entirely — the comment that stood here worked the trade
     * out and took the deal, because the alternative was a probe of 1232 bytes, below the 1280 we
     * already send, at a fixed place in every connection.
     *
     * patches/ngtcp2/0008 unties them: a path starts at NGTCP2_INITIAL_UDP_PAYLOAD_SIZE = 1280 for
     * a client, the padding target is the size the path is known to take rather than a constant,
     * and PMTUD is quic-go's search. So the ceiling here is quic-go's 1452, and ngtcp2 takes the
     * minimum with the node's advertised size the same way quic-go does.
     *
     * MEASURED, and that is the point of changing it: the reference's steady-state datagrams on a
     * 1500-byte path are 1366 and ours were 1280 — six per cent more packets for the same bytes,
     * and a difference anyone can read off a capture without decrypting a thing. */
    settings.max_tx_udp_payload_size = LC_QUDP_TX_MTU;

    /* Discovery on, which is the reference's default on Linux. It costs one probe packet five
     * smoothed RTTs after the handshake is confirmed, and another each time one is answered, until
     * the interval is twenty bytes wide; a probe that is lost costs nothing but the search
     * narrowing, because ngtcp2 keeps PMTUD probes out of congestion control
     * (ngtcp2_rtb.c:190-194). The DF bit those probes need is already set on the socket, for the
     * same reason and against the same reference — see the block above oob_conn. */
    settings.no_pmtud = 0;

    /* A HUNDRED MILLISECONDS, WHICH IS THE REFERENCE'S OWN INITIAL RTT.
     *
     * ngtcp2's default is 333 ms (NGTCP2_DEFAULT_INITIAL_RTT, ngtcp2.h:439) and it seeds recovery
     * with it — `cstat->smoothed_rtt = initial_rtt; cstat->rttvar = initial_rtt / 2`
     * (ngtcp2_conn.c:910-911); the first probe timeout was smoothed_rtt + 4*rttvar = 3 *
     * initial_rtt, 999 ms. quic-go's number is DefaultInitialRTT = 100 ms
     * (vendor/quic-go/internal/utils/rtt_stats.go:18), which NewRTTStats puts in its smoothed,
     * latest and min RTT (:32-38), and hysteria does not override it. Retransmission timing is
     * measurable by anyone who can drop or delay the server's first flight, and before the first
     * sample the pacer and the receive-window autotuning read this number too (patches/ngtcp2/0016,
     * 0018).
     *
     * The probe timeout before the first sample and the number of probes are patches/ngtcp2/0004:
     * quic-go's flat 2 * DefaultInitialRTT = 200 ms (rtt_stats.go:69-72), where ngtcp2's formula
     * over this initial RTT gives 300 ms, and its two probes per timeout, one while nothing is in
     * flight and the server's address is not validated
     * (vendor/quic-go/internal/ackhandler/sent_packet_handler.go:949-982). This said until
     * 2026-09-26 that both were still ngtcp2's, ten days after 0004 had made them quic-go's.
     *
     * THE ESTIMATE FROM THE FIRST SAMPLE ON is quic-go's too, patches/ngtcp2/0020: latestRTT after
     * the ACK Delay is taken off, the delay capped at max_ack_delay and never a reason to drop a
     * sample, the smoothing in whole microseconds through float32 (UpdateRTT, rtt_stats.go:80-116),
     * and a Retry taken for a sample of at least 5 ms
     * (vendor/quic-go/internal/ackhandler/sent_packet_handler.go:1172-1176). Upstream ngtcp2 did
     * each of these its own way, and loss detection, which waits 9/8 of the larger of latest and
     * smoothed, read the difference. */
    settings.initial_rtt = 100 * NGTCP2_MILLISECONDS;

    /* BBR, because that is what the client we are imitating sends with.
     *
     * Hysteria is known for Brutal, which sends at a fixed rate and treats loss as somebody else's
     * problem — but its client only uses that when the person running it has stated an upload
     * speed. Left unstated, which is the usual case, its congestion control falls through to BBR
     * (UseConfigured in core/internal/congestion/utils.go). ngtcp2's default is Cubic, which backs
     * off differently and would make this client the one connection on the node that slows down
     * where the others do not.
     *
     * ⚠️ THAT CHOICE HAS TWO INPUTS AND ONLY ONE OF THEM IS THE PERSON RUNNING THE CLIENT, which
     * this paragraph left out until 2026-08-30. The reference computes `actualTx = authResp.Rx` and
     * then CLAMPS it to its own configured send rate: `if actualTx == 0 || actualTx > MaxTx {
     * actualTx = MaxTx }`, taking Brutal only if something survives
     * (vendor/hysteria/core/client/client.go:155-165). MaxTx is `bandwidth.up`, zero unless written
     * (vendor/hysteria/app/cmd/client.go:479-484), so a client with no send rate lands on BBR
     * whatever the node states — and this client has none to configure.
     *
     * ⚠️ UNTIL 2026-09-22 THIS SAID "a NODE that states a bandwidth puts the reference on Brutal
     * whatever the client was configured with" and called the match a matter of node configuration
     * that would end the day a node is given a rate. It read the assignment and missed the clamp.
     * The match holds on every node. (The ones measured state no rate anyway: a node writes the
     * `bandwidth:` block only when it is given one.)
     *
     * What Brutal governs for a user is the DOWNLOAD, and that is not decided here at all: the node
     * uses Brutal to send to us when we state a receive rate, which is a number in the
     * authentication request and nothing more. See lc_qconn_authenticate.
     *
     * AND WHICH BBR, WHICH IS NOT THE SAME QUESTION. `UseBBR` does not ask quic-go for its
     * congestion control: it REPLACES it, with the port of Chromium's BBRv1 that hysteria
     * carries in core/internal/congestion/bbr (core/internal/congestion/utils.go:37-43). ngtcp2's own is BBRv2 — a
     * different state machine, different gains, a different sampler — so `NGTCP2_CC_ALGO_BBR`
     * here meant this client sent to a rhythm no reference client has. The port is patch 0009
     * and lib/ngtcp2_hybbr.c; this names it.
     *
     * ⚠️ Its seed moved in hysteria 2.12: the address-based guess is now capped at the size QUIC
     * itself starts at (seedPacketSize, vendor/hysteria/core/internal/congestion/utils.go:45-59),
     * which changes nothing at quic-go's own 1280 and makes it 1250 for a client parroting Chrome
     * (chromeInitialPacketSize, vendor/quic-go/chrome_parrot.go:19). */
    settings.cc_algo = NGTCP2_CC_ALGO_HYBBR;

    /* And the packet layout of a client parroting Chrome: the first Initial numbered 1, 1250-byte
     * datagrams, Chrome's packet number lengths, one encryption level per datagram, the CRYPTO
     * of an Initial chaos protected — patches/ngtcp2/0014. */
    settings.chrome_parrot = (uint8_t)(c->chrome != 0);

    /* The ceilings the receive windows may grow to: hysteria's MaxStreamReceiveWindow and
     * MaxConnectionReceiveWindow, which it leaves at its defaults (vendor/hysteria/core/client/
     * config.go:51-55, :61-65) and passes to quic-go (vendor/hysteria/core/client/client.go:84-87). The
     * growth itself is quic-go's, patches/ngtcp2/0016. Without the parrot the windows start at these
     * same numbers and never move; parroting Chrome they start at Chrome's and grow to them — see
     * lc_qparams. */
    settings.max_stream_window = LC_QTCP_STREAM_WINDOW;
    settings.max_window = LC_QTCP_CONN_WINDOW;

    /* Everything this client states about itself, in one place and checkable without a socket:
     * src/quic/params.c, and test/qparams against the numbers the reference client sends. */
    ngtcp2_transport_params params;
    lc_qparams(&params, c->chrome);

    ngtcp2_path path = qconn_path(c);

    /* ⚠️ THIS CALL RESHAPES OUR FIRST PACKET — AND SO DOES THE REFERENCE'S, DIFFERENTLY.
     *
     * Upstream ngtcp2 sets a flag on every client connection it creates, with no setting either way
     * (vendor/ngtcp2/lib/ngtcp2_conn.c:1651, from its own commit 89c29fd8, "Crumble Client Initial
     * CRYPTO (aka chaos protection)", released in v1.15.0 — not a fork's patch, as this said):
     * conn_crumble_initial_crypto cuts the ClientHello into up to eleven random CRYPTO pieces, splits
     * the server name, and interleaves random PING and PADDING frames before permuting the lot
     * (ngtcp2_conn.c:2393-2484).
     *
     * quic-go scrambles too, and this said it did not ("one CRYPTO frame with the SNI whole"). Its
     * client holds back the second half of the server name — [sni + len/2, sni + len) — sends the
     * ClientHello around that hole in offset order and the held-back piece last
     * (vendor/quic-go/crypto_stream.go:174-283, cut found in sni.go), unless
     * QUIC_GO_DISABLE_CLIENTHELLO_SCRAMBLING is set, which hysteria never sets. Its Initial payload
     * is the ACK, then PADDING, then the CRYPTO frames shuffled (packet_packer.go:1055-1078), with no
     * PING.
     *
     * ⚠️ THAT WAS THE REFERENCE UP TO hysteria 2.10, AND IT IS NOT THE REFERENCE NOW. From 2.11 the
     * client parrots Chrome unless told not to (DisableChromeParrot,
     * vendor/hysteria/core/client/client.go:95), and a parroting client does not scramble at all —
     * newInitialCryptoStream turns it off (vendor/quic-go/crypto_stream.go:144-163) because the
     * packer applies Chromium's chaos protection instead: CRYPTO cut at random points, two to ten
     * PINGs, padding in runs, the lot
     * shuffled (vendor/quic-go/packet_packer_chaos.go:94-165), and a ClientHello longer than one
     * Initial sent head and tail first (chromeCryptoSplit, :38-78).
     *
     * Both layouts are ngtcp2's now, by patch, and upstream's crumbling runs in neither:
     * patches/ngtcp2/0005 is the scrambling of a client that does not parrot, 0014 Chrome's chaos
     * protection for one that does (settings.chrome_parrot, above), and test/ngpatch holds the first
     * Initial of the parrot to quic-go's. This said until 2026-09-26 that neither was done.
     *
     * PACKET NUMBERS ARE LEFT OUT ON QUIC-GO'S SCHEDULE, patches/ngtcp2/0021. Both stacks skip one
     * now and then, so that a peer acknowledging a packet it never got gives itself away. quic-go
     * skips first at 3 plus a draw below 512, then each time at the number after next plus 3 plus a
     * draw below twice a period that doubles from 512 to 128 Ki
     * (vendor/quic-go/internal/ackhandler/packet_number_generator.go:51-84, SkipPacketInitialPeriod
     * in vendor/quic-go/internal/protocol/params.go:45-50); upstream ngtcp2 put the next skip
     * (r + 1) * 2^k + 3 on, for a random byte r and a k growing from 0 without a ceiling. Only the
     * node sees the numbers, inside the encryption, but it sees all of them. */
    int rv = ngtcp2_conn_client_new(&c->conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1,
                                    &callbacks, &settings, &params, NULL, c);
    if (rv != 0) {
        say(c, "ngtcp2 refused the connection: %s", ngtcp2_strerror(rv));
        goto fail;
    }

    /* AND NOT BBR YET. Until its authentication is answered the reference runs on quic-go's own
     * controller, NewReno with quic-go's pacer, and installs BBR only then (patches/ngtcp2/0018;
     * the switch is in lc_qconn_auth_poll). */
    {
        ngtcp2_hybbr *cc = ngtcp2_conn_hybbr(c->conn);
        if (cc != NULL)
            ngtcp2_hybbr_start_reno(cc, cc->cstat);
    }

    /* A keep-alive at all, because without one a tunnel that goes quiet dies. Not theoretical: with
     * nothing sending, the connection reached its idle timeout and closed, and the first request
     * after each of those gaps was lost while it was being remade. A client with one connection
     * carrying everything cannot let it lapse the way a client with a connection per request can.
     *
     * TEN SECONDS, which is the reference's own: defaultKeepAlivePeriod in core/client/config.go.
     *
     * It was three, deliberately, and the argument for three was detection speed: the only evidence
     * a QUIC client has of a live path is a packet arriving, and on an idle connection the only
     * thing that makes one arrive is this — so at ten, silence cannot be called before ten, while at
     * three it can be called at six. The comment that stood here weighed the cadence being visible
     * from outside against those six seconds and chose the six, saying so honestly.
     *
     * The weighing has been redone and it comes out the other way, on the plainest of the two
     * grounds: a cadence is not a small thing to differ in. Every client of this protocol pings
     * every ten seconds, because defaultKeepAlivePeriod is ten
     * (vendor/hysteria/core/client/config.go:18) and nothing overrides it — so pinging every three
     * is a client that can be picked out of a packet trace without decrypting anything.
     *
     * The OTHER ground the old comment gave has since been withdrawn. It said detecting a dead node
     * six seconds sooner was worth the visibility, and the machinery that used that speed threw
     * away working connections tens of times an hour; three successive silence thresholds were
     * written to tame it and all three were removed, because upstream has no such rule at any
     * number — `closeErr = <-copyErrChan`, two io.Copy goroutines and one channel with no timer
     * anywhere in it (vendor/hysteria/app/internal/redirect/tcp_linux.go:69-79), and the whole
     * account is at the half-close rule in cmd/lc-tunnel/main.c. Until 2026-09-07 this sent the
     * reader to a header called revive, in this directory, that went out with the machinery it
     * documented — a pointer into a deleted file reads as a citation and answers nothing, which is
     * worse than no pointer because the search is spent before that is learned.
     *
     * Nothing downstream of this value depends on it any more: the keep-alive is what it is for its
     * own sake, which is to keep an idle connection from lapsing, and is measured on the wire at
     * 10.1 s between packets on an idle tunnel. */
    ngtcp2_conn_set_keep_alive_timeout(c->conn, LC_QCONN_KEEP_ALIVE_PERIOD);
    c->last_rx_ms = lc_qconn_now_ms();

    /* The shim is what ngtcp2 knows as its TLS. Binding it also arms the handshake: ngtcp2 asks for
     * the local transport parameters on its way to the first packet, and that request is what
     * builds and sends the ClientHello. */
    if (lc_qshim_init(&c->shim, c->conn, sni, pin, c->chrome ? LC_QTLS_CHROME : 0u) != 0) {
        say(c, "cannot bind the tls shim");
        goto fail;
    }

    if (flush(c) != 0)
        goto fail;
    return 0;

fail:
    lc_qconn_close(c);
    return -1;
}

/* Which source port the socket is on NOW, asked of the kernel rather than of c->local_addr.
 *
 * That field is filled once, at open, and a hop deliberately does not refresh it: ngtcp2 is never
 * told the socket moved, so the path it holds — local address included — must keep saying what it
 * said when the path was validated. Reading the port from there would therefore report the first
 * dial for ever, which is the same bug node_port had and which was found only because somebody
 * compared a log line with ss(8). */
uint16_t lc_qconn_source_port(const lc_qconn *c)
{
    struct sockaddr_storage sa;
    socklen_t               len = sizeof sa;
    if (c->fd < 0 || getsockname(c->fd, (struct sockaddr *)&sa, &len) != 0)
        return 0;
    if (sa.ss_family == AF_INET6)
        return (uint16_t)ntohs(((struct sockaddr_in6 *)&sa)->sin6_port);
    return (uint16_t)ntohs(((struct sockaddr_in *)&sa)->sin_port);
}

int lc_qconn_fd(const lc_qconn *c)
{
    return c->fd;
}

int lc_qconn_prev_fd(const lc_qconn *c)
{
    return c->prev_fd;
}

int lc_qconn_pinned(const lc_qconn *c)
{
    return c->shim.tls.peer_pinned;
}

/* One socket to the node, unconnected, buffered and non-blocking. Separated out because a port hop
 * needs exactly this again, and two copies of it would drift. */
/* One socket buffer, asked for the way the reference asks for it.
 *
 * Three steps, and the third is the one that matters on a router: read what the socket already has
 * and stop if it is enough; set it; read again, and if the kernel's cap held the request down, ask
 * again with SO_*BUFFORCE, which ignores net.core.*mem_max and needs CAP_NET_ADMIN. That is
 * setReceiveBuffer in vendor/quic-go/sys_conn_buffers.go:37-55, line for line, including the order:
 * the force is a fallback, never the first ask, so a client without the capability behaves exactly
 * as it did before and one with it gets what the reference gets.
 *
 * The comparison is against `want` and not twice it, which looks wrong and is what the reference
 * does: Linux reports back double what it was given, so `got >= want` is satisfied at half the
 * request. Keeping that is the point — a client that demanded the full doubled figure would force
 * buffers on machines where quic-go is content, and the whole value of this file is that a byte
 * we spend is a byte the reference spends. */
static void ask_buffer(int fd, int opt, int force_opt, int want)
{
    int       got = 0;
    socklen_t len = sizeof got;
    if (getsockopt(fd, SOL_SOCKET, opt, &got, &len) == 0 && got >= want)
        return;

    (void)setsockopt(fd, SOL_SOCKET, opt, &want, sizeof want);

    got = 0;
    len = sizeof got;
    if (getsockopt(fd, SOL_SOCKET, opt, &got, &len) == 0 && got >= want)
        return;

    (void)force_opt;
#ifdef SO_RCVBUFFORCE
    (void)setsockopt(fd, SOL_SOCKET, force_opt, &want, sizeof want);
#endif
}

/* What every socket to the node wants, whichever of the two made it. `first_socket` is the dial's;
 * every hop's is not — they differ in DF alone, see below. */
static int prep_socket(lc_qconn *c, int fd, int first_socket)
{
    /* A RECEIVE BUFFER BIG ENOUGH THAT A BURST DOES NOT BECOME SILENCE — see the long note at the
     * only other place this used to live. Asked for, not required: SO_RCVBUF is clamped by
     * net.core.rmem_max, and asking above the cap costs nothing but the syscall.
     *
     * EIGHT MEGABYTES BECAUSE THAT IS WHAT THE REFERENCE ASKS, not because a burst was measured
     * needing it. One figure serves both directions, `desiredBufferSize = 8 << 20`
     * (vendor/quic-go/sys_conn_buffers_nonopenbsd.go:5 — OpenBSD alone gets two), and quic-go asks
     * for it on every socket it opens, the receive side at vendor/quic-go/sys_conn_buffers.go:46 and
     * the send side generated from it. This said two megabytes, a number with no reference behind
     * it — the kind this file exists to stop.
     *
     * Nothing changes on the router this was written for: net.core.rmem_max there is exactly
     * 2 097 152, so both figures come back as two megabytes, and the socket's own drop counter in
     * /proc/net/udp read zero through every transfer measured — the buffer has never been the
     * limit on that box. What changes is a box whose cap is generous, where the reference would
     * have four times the room this asked for — and on the router too, now that the cap is asked
     * to stand aside the way the reference asks it. See ask_buffer just above. */
    int want = 8 * 1024 * 1024;
#ifdef SO_RCVBUFFORCE
    ask_buffer(fd, SO_RCVBUF, SO_RCVBUFFORCE, want);
#else
    ask_buffer(fd, SO_RCVBUF, SO_RCVBUF, want);
#endif
#ifdef SO_SNDBUFFORCE
    ask_buffer(fd, SO_SNDBUF, SO_SNDBUFFORCE, want);
#else
    ask_buffer(fd, SO_SNDBUF, SO_SNDBUF, want);
#endif

    /* THE ARRIVING CODEPOINT HAS TO COME BACK TO ngtcp2, or marking is worse than not marking.
     *
     * ECN is validated by the peer echoing counts of what it received. ngtcp2 compares those
     * against what it believes it sent, and a client that marks its packets while reporting
     * Not-ECT on everything it receives fails its own validation and gives up on ECN — which is a
     * connection that starts marking and then stops, a shape no ordinary client has.
     *
     * quic-go asks for the same two options and gates its whole ECN support on them
     * (vendor/quic-go/sys_conn_oob.go:73-74, with enableECN taken from the resulting capability at
     * :132). Not required: a kernel that refuses leaves us reading Not-ECT, which is where this
     * client was before.  */
    /* DON'T FRAGMENT, on both families, which the reference sets and this socket did not.
     *
     * quic-go pins it unconditionally at socket setup:
     *
     *     errDFIPv4 = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER,
     *                                    unix.IP_PMTUDISC_PROBE)
     *     errDFIPv6 = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER,
     *                                    unix.IPV6_PMTUDISC_PROBE)
     *                                     (vendor/quic-go/sys_conn_df_linux.go:16-20)
     *
     * and tolerates either failing — it logs which ones took and carries on (:24-32), which is why
     * the returns are discarded here too rather than made fatal.
     *
     * PROBE rather than DO: it sets the DF bit and, as the comment beside it says, makes the kernel
     * answer EMSGSIZE instead of fragmenting, WITHOUT letting the kernel's own path-MTU cache
     * shrink what we may send. That matters for a client that decides its own datagram size: left
     * at the host default, a stale cache entry for the route silently caps our packets somewhere
     * below the 1280 this client pins, and the only symptom is a connection that works slowly or
     * not at all on one network and is fine on the next.
     *
     * A QUIC datagram that gets fragmented at the IP layer is also a datagram no QUIC client
     * produces: the protocol sizes its packets so it never happens, and fragments on port 443 are
     * their own signal.
     *
     * Both families are set on the one socket regardless of which it is, exactly as the reference
     * does: the wrong one simply fails and is ignored. */
    /* ⚠️ AND NONE OF IT WHEN THE PORT MOVES, because upstream configures none of it there.
     *
     * A hopping client hands quic-go a `udpHopPacketConn`, not a `*net.UDPConn`, and wrapConn sorts
     * on exactly that: the buffers are asked for either way (vendor/quic-go/sys_conn.go:53-54, which is why they
     * stay above), `setDF` runs when the conn offers `SyscallConn` (:56-74), and the OOB path — the
     * one that turns ECN on — is taken only for an `OOBCapablePacketConn` (:75-80). The hop conn
     * offers SyscallConn, handing over its CURRENT socket's
     * (vendor/hysteria/extras/transport/udphop/conn.go:337-345), and is not OOB-capable. So
     * upstream sets DF (PROBE) on the first socket only — hop() carries the buffer sizes and
     * deadlines over to each new socket, not DF (:172-225) — and falls to `basicConn`, saying so in
     * a log line ("PacketConn is not a net.UDPConn…"), with no ECN in either direction.
     *
     * We used to set both on every socket, hop or not, and the ECN half of that is READABLE BY
     * ANYONE: two bits in the IPv4 TOS byte, marked on every 1-RTT packet where a real hopping
     * client marks none. See the send gate in emit_one, which is the other half of this.
     *
     * DF IS THE OTHER HALF, AND IT IS NOT "NONE": setDF reaches the socket the hop conn holds when
     * quic-go sets up, which is the first one, and no socket after it (lc_hop_sets_df holds the
     * rule and says where). This used to set it on none when hopping — the first socket of a
     * hopping connection was an open divergence, written down while hopping was off by the maintainer's
     * decision, and closed 2026-09-25 on "finish it to the ideal". Every later socket takes the
     * kernel's default and the IP fragment it may produce; a fragment on 443 is a signal, as the
     * paragraph above says, and it is upstream's own to own. */
    if (lc_hop_sets_df(hopping(c), first_socket)) {
#ifdef IP_MTU_DISCOVER
        {
            int df4 = IP_PMTUDISC_PROBE;
            (void)setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &df4, sizeof df4);
        }
#endif
#ifdef IPV6_MTU_DISCOVER
        {
            int df6 = IPV6_PMTUDISC_PROBE;
            (void)setsockopt(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &df6, sizeof df6);
        }
#endif
    }
    /* The received codepoint is the OOB path's too (vendor/quic-go/sys_conn_oob.go), so it is asked
     * for only where that path would be taken — see oob_conn. */
    /* WHEN EACH DATAGRAM ARRIVED, asked of the kernel, because the reference knows it and this
     * loop otherwise cannot. quic-go reads the socket in a goroutine that does nothing else and
     * stamps a datagram the moment the read returns (vendor/quic-go/sys_conn.go:107,
     * sys_conn_oob.go:169); every acknowledgement is then processed with that stamp — loss
     * detection and hysteria's BBR included. This loop reads when it gets round to it, which on
     * the one-way stand was 118 us after arrival on average and over a millisecond 86 times in
     * 4 591. The kernel's own receive time is what a reader that is always waiting would have
     * seen. Asked on every socket, whatever the obfuscation — the reference stamps both paths.
     * Refused by an old kernel, it is simply absent, and ngtcp2 falls back to the time of
     * processing: see ngtcp2_conn_read_pkt_rx in patches/ngtcp2/0011. */
    {
        int on = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPNS, &on, sizeof on);
    }
    if (oob_conn(c)) {
        int on = 1;
        (void)setsockopt(fd, IPPROTO_IP, IP_RECVTOS, &on, sizeof on);
#ifdef IPV6_RECVTCLASS
        (void)setsockopt(fd, IPPROTO_IPV6, IPV6_RECVTCLASS, &on, sizeof on);
#endif
    }

    /* WHETHER THE KERNEL WILL TAKE A BATCH, ASKED THE WAY THE REFERENCE ASKS IT.
     *
     * quic-go does not assume UDP_SEGMENT exists: on a kernel whose major version is 5 or later,
     * and unless QUIC_GO_DISABLE_GSO is set, it READS the option and treats GSO as absent if the
     * read fails (isGSOEnabled, vendor/quic-go/sys_conn_helper_linux.go:66-81). It never sets it.
     * The same question here, asked the same way — the option arrived in Linux 4.18, OpenWrt
     * carries kernels older than that on targets this program is built for, and a client that
     * assumed it would get EINVAL on every send with no way to tell why. The environment switch has
     * no counterpart: nothing sets it on a router.
     *
     * ⚠️ IT USED TO SET THE OPTION TO ZERO AND READ IT BACK, WITH NO KERNEL GATE, and the comment
     * here said that was quic-go's way. It is not, and on a 4.18-4.x kernel the two answer
     * differently: the option exists there, so ours batched where the reference sends one datagram
     * a call. The size still travels per-send as a control message, because it is a property of
     * the batch rather than of the socket.
     *
     * And ECN marking, on that path, only on a kernel quic-go marks on: `return kernelVersionMajor
     * >= 5 && !isECNDisabledUsingEnv()` (vendor/quic-go/sys_conn_helper_linux.go:119-121). The
     * major number is parsed from uname's release the way its kernelVersion does (:123-153), once,
     * for both. */
    int kernel_major = 0;
    {
        struct utsname u;
        if (uname(&u) == 0)
            for (const char *p = u.release; *p >= '0' && *p <= '9'; p++)
                kernel_major = kernel_major * 10 + (*p - '0');
    }
    c->ecn_ok = oob_conn(c) && kernel_major >= 5;

    c->gso_ok = 0;
#ifdef UDP_SEGMENT
    if (oob_conn(c) && kernel_major >= 5) {
        int       seg = 0;
        socklen_t sl = sizeof seg;
        if (getsockopt(fd, IPPROTO_UDP, UDP_SEGMENT, &seg, &sl) == 0)
            c->gso_ok = 1;
    }
#endif
    c->gso_count = 0;
    c->gso_len = 0;
    c->gso_seg = 0;

    if (lc_set_nonblocking(fd) != 0) {
        say(c, "cannot set the socket up");
        return -1;
    }
    return 0;
}

/* A socket bound to nothing in particular, the way `net.ListenUDP("udp", nil)` makes one: any address,
 * a port the kernel picks, and NOT connected. */
static int open_socket(lc_qconn *c, int family, int first_socket)
{
    int fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    struct sockaddr_storage any;
    memset(&any, 0, sizeof any);
    any.ss_family = (sa_family_t)family;
    socklen_t any_len = family == AF_INET6 ? (socklen_t)sizeof(struct sockaddr_in6)
                                           : (socklen_t)sizeof(struct sockaddr_in);
    c->family = family;
    if (bind(fd, (struct sockaddr *)&any, any_len) != 0 || prep_socket(c, fd, first_socket) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* ONE ADDRESS, CHOSEN AS GO CHOOSES IT, AND A SOCKET THAT IS NOT CONNECTED TO IT.
 *
 * The address. hysteria resolves the server with `net.ResolveUDPAddr("udp", hostPort)`, or for a port
 * range `net.ResolveIPAddr("ip", host)` (vendor/hysteria/app/cmd/client.go:255-259,
 * vendor/hysteria/extras/transport/udphop/addr.go:46-54), and both hand back ONE address: the first
 * IPv4 one in the resolver's answer, or the first of any kind when there is none — Go's
 * `addrList.forResolve` takes `first(isIPv4)` unless the name itself is an IPv6 literal. What stood
 * here walked the whole answer in the resolver's own order and kept the first family `connect`
 * accepted, which for a name with both kinds of address is IPv6 wherever the host has a route — a
 * different address, and a different family on the wire, from the reference's.
 *
 * The socket. The reference's is `ListenUDP("udp", nil)` (vendor/hysteria/app/cmd/client.go:291-294,
 * via app/internal/sockopts/sockopts.go:42-63), which binds and never connects. What stood here
 * connected, "a filter worth having for free", and the filter was not free:
 *
 *   - a connected UDP socket is told of ICMP errors. A port-unreachable from the node — or from
 *     anything that can forge one on the path — comes back as ECONNREFUSED from the next receive, and
 *     that ended the connection and every stream on it at once. The reference's unconnected socket is
 *     never told, and the connection lives until its idle timeout or the node's next packet;
 *   - the kernel drops datagrams from any other address, where quic-go's client handles a packet by
 *     its connection ID wherever it came from (vendor/quic-go/transport.go:582-607; the address is
 *     looked at only by a server, vendor/quic-go/connection.go:1284-1287).
 *
 * The socket's family is the address's. Go's is AF_INET6 dual-stack even for an IPv4 node; the
 * datagrams that leave are the same IPv4 datagrams either way.
 *
 * AND RESOLVED ONCE, BY GO'S RESOLVER. The reference resolves the server when it reads its
 * configuration — fillServerAddr (vendor/hysteria/app/cmd/client.go:248-270) — and every connection
 * after that, reconnections included, goes to that one address: the core client is handed a net.Addr,
 * not a name. So the first address this process resolves is kept for its life, and a name is asked
 * of the resolver the references use, Go's own (net/goresolve.h). Until 2026-09-30 every connection
 * asked getaddrinfo again: more queries on the path than the reference makes, in libc's shape, and
 * possibly another address after a reconnect. */
static struct {
    char    host[256];
    int     have;
    lc_goip ip;
} node_resolved;

static int dial_node(lc_qconn *c, const char *host, uint16_t port, int *out_fd,
                     struct sockaddr_storage *out_addr, socklen_t *out_len)
{
    lc_goip pick;
    if (lc_goip_literal(host, &pick) != 0) {
        if (node_resolved.have && strcmp(node_resolved.host, host) == 0) {
            pick = node_resolved.ip;
        } else {
            lc_goaddrs l;
            char       why[200];
            if (lc_go_lookup_ip(host, -1, &l, why, sizeof why) != 0 || l.n == 0u) {
                /* An empty answer is errNoSuitableAddress to ResolveUDPAddr as to a dial. */
                say(c, "cannot resolve %s: %s", host, l.n == 0u ? "no suitable address found" : why);
                lc_goaddrs_free(&l);
                return -1;
            }
            /* forResolve: the first IPv4 address, or the first of any kind when there is none. */
            pick = l.a[0];
            for (unsigned i = 0; i < l.n; i++) {
                if (l.a[i].v4) {
                    pick = l.a[i];
                    break;
                }
            }
            lc_goaddrs_free(&l);
            snprintf(node_resolved.host, sizeof node_resolved.host, "%s", host);
            node_resolved.ip = pick;
            node_resolved.have = 1;
        }
    }
    *out_len = lc_goip_sockaddr(&pick, port, out_addr);
    int family = out_addr->ss_family;

    int fd = open_socket(c, family, 1);
    if (fd < 0) {
        say(c, "cannot open a socket towards %s:%u", host, (unsigned)port);
        return -1;
    }
    c->peer_addr = *out_addr;
    *out_fd = fd;
    return 0;
}

/* The same node at a different port, WITHOUT going back to the resolver.
 *
 * Two things are wrong with re-resolving on every hop. It blocks: getaddrinfo has no non-blocking
 * form, and it runs here inside the event loop rather than at startup, so a slow or dead resolver
 * stops the tunnel for as long as it takes. And it can answer differently — a name behind several
 * addresses hands out another one — which would point an ESTABLISHED connection at a host that never
 * had it, silently, because the whole design of the hop is that ngtcp2 is not told. Neither risk buys
 * anything: the address was resolved at open and the only thing meant to change is the port — which is
 * also the reference's shape, where every entry of the hop address is the one resolved IP with a port
 * from the range (vendor/hysteria/extras/transport/udphop/addr.go:34-44). */
static void addr_with_port(struct sockaddr_storage *ss, uint16_t port)
{
    if (ss->ss_family == AF_INET)
        ((struct sockaddr_in *)ss)->sin_port = htons(port);
    else if (ss->ss_family == AF_INET6)
        ((struct sockaddr_in6 *)ss)->sin6_port = htons(port);
}

/* A fresh unconnected socket, as each hop takes one from `ListenUDPFunc`
 * (vendor/hysteria/extras/transport/udphop/conn.go:178-185), and the address it will send to. */
static int redial_node(lc_qconn *c, uint16_t port, int *out_fd, struct sockaddr_storage *out_to)
{
    *out_to = c->remote_addr;
    addr_with_port(out_to, port);

    int fd = open_socket(c, (int)out_to->ss_family, 0);
    if (fd < 0)
        return -1;
    *out_fd = fd;
    return 0;
}

/* When the next hop falls due. A flat interval, because that is what the reference uses.
 *
 * nextHopInterval (vendor/hysteria/extras/transport/udphop/conn.go:165-170) returns Min unchanged
 * when Min == Max, and picks uniformly in [Min, Max] only when they differ — and they differ only
 * if the operator set minHopInterval and maxHopInterval by hand
 * (vendor/hysteria/app/cmd/client.go:127-131). With a single hopInterval, or none at all,
 * normalized() sets Min == Max, so the reference hops on a level schedule.
 *
 * What stood here added a sixth of the interval either way, unconditionally, reasoning that a fixed
 * period is itself a mark. The reasoning is not absurd and it is not the reference's, and this
 * client's whole purpose is to be indistinguishable from the reference — a spread nobody upstream
 * produces is as much of a signature as a period, and one that no amount of matching elsewhere
 * repairs. The configuration here exposes one interval, so Min == Max always, so there is no
 * spread. */
static void arm_hop(lc_qconn *c)
{
    /* nextHopInterval: Min when the two agree, otherwise Min plus a uniform draw over the span,
     * both ends included (vendor/hysteria/extras/transport/udphop/conn.go:165-170) — in
     * milliseconds here, nanoseconds there. */
    uint32_t extra = 0;
    if (c->hop_max_ms > c->hop_min_ms &&
        lc_pad_draw(0, c->hop_max_ms - c->hop_min_ms + 1u, &extra) != 0)
        extra = 0;
    c->hop_at = lc_qconn_now_ms() + c->hop_min_ms + extra;
}

void lc_qconn_hop_on(lc_qconn *c, unsigned min_secs, unsigned max_secs, const lc_hop_ports *ports)
{
    /* normalized() (vendor/hysteria/extras/transport/udphop/conn.go:107-121): neither set is the
     * default thirty seconds; one alone stands for both, as hopInterval does
     * (vendor/hysteria/app/cmd/client.go:360-377); a minimum above the maximum is refused, and so is
     * one under five seconds. */
    c->hop_min_ms = min_secs > 0 ? min_secs * 1000u : LC_QCONN_HOP_MS;
    c->hop_max_ms = max_secs > 0 ? max_secs * 1000u : c->hop_min_ms;

    /* Five seconds is the floor the reference refuses to go below: normalized()
     * (vendor/hysteria/extras/transport/udphop/conn.go:114-116) returns an error for "hop interval
     * must be at least 5 seconds", so a client configured faster than that does not start at all.
     * Clamping rather than refusing, because the value arrives from UCI on a router where a failed
     * start is a household with no
     * internet and no explanation — but the number is the reference's, not one chosen here. */
    /* REFUSED, NOT CLAMPED — the comment above already knew what the reference does and this code
     * did the other thing.
     *
     * udphop refuses outright: `if c.Min < 5*time.Second { return HopIntervalConfig{},
     * errors.New("hop interval must be at least 5 seconds") }`
     * (vendor/hysteria/extras/transport/udphop/conn.go:117-119), so a client configured faster
     * than that does not start. Clamping instead ran the tunnel at an interval nobody asked for
     * and said nothing, which is the shape of fault this project spends its time removing: the
     * operator reads one number in the config and the wire carries another.
     *
     * The operational worry that produced the clamp — a failed start is a household with no
     * internet — is answered where it belongs, at the argument, which refuses with LC_EXIT_CONFIG
     * and a line naming the minimum. A service that will not start for a stated reason is a
     * different thing from one that starts and misbehaves quietly. */
    if (c->hop_min_ms < LC_QCONN_HOP_MIN_MS || c->hop_max_ms < c->hop_min_ms) {
        say(c, "a hop interval under %u seconds, or a minimum over the maximum, is refused, as the "
               "reference refuses it",
            (unsigned)(LC_QCONN_HOP_MIN_MS / 1000u));
        c->hop_ports = NULL;
        return;
    }

    /* THE RANGE IS THE WHOLE SWITCH, and there is no second state beside it.
     *
     * ⚠️ WHAT STOOD HERE WAS AN ARMING STEP THIS PROJECT INVENTED: the interval doubled as an on/off
     * — hop_ms of zero meant "not armed" — and the caller had to ask whether to arm at all before
     * calling. The reference has none of that: hysteria decides on the address form alone
     * (vendor/hysteria/app/cmd/client.go:285). An extra state is an extra way to be
     * half-configured, and it produced exactly that: a connection armed to move with nowhere to
     * move to.
     *
     * So the bounds are the only thing that decides, everywhere — lc_qconn_hop_due asks them, the
     * first dial asks them, and the interval is only ever an interval.
     *
     * A range that is not one is not stored, which is what the reference does with a bad one:
     * `ParsePortUnion` returning nil is an `InvalidPortError` out of ResolveUDPHopAddr, so the
     * address never becomes a hop address at all
     * (vendor/hysteria/extras/transport/udphop/addr.go:60-62).
     *
     * ⚠️ THAT PATH IS ON ONE LINE ON PURPOSE. It was wrapped after the last slash, and a wrapped
     * path is not a path: the citation audit matches `vendor/…:N-M` within a line, falls back to
     * the bare basename, and `addr.go` exists twice under vendor — so the reference was dropped as
     * ambiguous and this claim went unchecked, silently, which is the very failure that script's
     * header warns about.
     *
     * ⚠️ THE CITATION HERE USED TO BE `vendor/hysteria/extras/transport/udphop/conn.go:107-121`,
     * normalized(). Those lines are real and quoted correctly, and they refuse a malformed pair —
     * of INTERVALS. They say nothing about
     * ports, so they were evidence for the neighbouring rule rather than this one. */
    c->hop_ports = ports != NULL && ports->n > 0u ? ports : NULL;
}

uint16_t lc_qconn_port(const lc_qconn *c)
{
    return c->node_port;
}

int lc_qconn_hop_due(const lc_qconn *c)
{
    /* On time, whatever is queued: the hop waits for the write in progress and for nothing else, and
     * what is still queued goes to the new port — lc_sendq_set_dest, the reference's write lock
     * (vendor/hysteria/extras/transport/udphop/conn.go:172-174, :245-253). ⚠️ UNTIL 2026-09-27 this
     * waited for the whole queue to drain, so a busy connection hopped late. */
    return hopping(c) && !c->closed && c->conn != NULL && lc_qconn_now_ms() >= c->hop_at;
}

int lc_qconn_hop(lc_qconn *c)
{
    /* A PORT FROM THE RANGE, CHOSEN AFRESH EVERY TIME — in lc_hop_port, which the first dial calls
     * too, so the rule has one writing. No question about whether a range exists is asked here, and
     * there is no "is hopping on" to ask either: lc_qconn_hop_due answers exactly that question,
     * out of the same bounds, and upstream has nothing else to ask because without ports the
     * hopping conn is never built at all.
     *
     * A source that cannot deliver randomness ends the hop the same way a refused socket does — the
     * old one is untouched and still carrying the connection, and the next interval tries again.
     *
     * ⚠️ WHAT STOOD HERE kept `c->node_port` when no range was configured, so that only the source
     * port moved, under a heading saying both ends were "worth having" and an argument that a
     * shaper acts on a flow of four numbers rather than on a port. Reasoning from first principles
     * towards behaviour the reference does not have is the one difference this client cannot
     * afford — and the branch was unreachable besides.
     *
     * Said carefully, because "the reference does not do this" is true of the ADDRESS FORM and not
     * of the port count: an address that is not a udphop address takes the else branch and gets one
     * socket that is never replaced (vendor/hysteria/app/cmd/client.go:285-293), and that is the
     * case the removed branch imitated. A hop address holding a SINGLE port is a different thing —
     * upstream hops it, `rand.Intn(1)` picks the only entry, and the destination stays put while
     * the socket underneath is replaced. `20000-20000` reaches exactly that here, legally. */
    uint16_t port = 0;
    if (lc_hop_ports_pick(c->hop_ports, &port) != 0) {
        arm_hop(c);
        return -1;
    }

    int                     fd = -1;
    struct sockaddr_storage to;
    if (redial_node(c, port, &fd, &to) != 0) {
        /* The old socket is untouched and still works; the reference skips the hop the same way,
         * "Could be temporary, just skip this hop" (vendor/hysteria/extras/transport/udphop/conn.go:
         * 178-185). Opening a socket asks nothing of the node, so a port the node's redirect does not
         * cover is not what lands here. */
        arm_hop(c);
        return -1;
    }

    /* Close the generation BEFORE last, keep the last, adopt the new — the reference's own sequence
     * (vendor/hysteria/extras/transport/udphop/conn.go:186-197). What this replaced was a plain
     * close(c->fd), which dropped every packet the node had already sent to the port we were
     * leaving, once per hop. At the default thirty seconds that was a loss burst twice a minute,
     * and each one costs a round trip of retransmission on a link that is already the
     * bottleneck. */
    int old_fd = c->fd;
    c->fd = fd;
    c->peer_addr = to;
    /* The writer moves first — after the write in progress, if there is one, and before anything
     * else queued (lc_sendq_set_dest) — and only then is the generation before last closed, so no
     * write can be on it. */
    lc_sendq_dest now_dest;
    cur_dest(c, &now_dest);
    lc_sendq_set_dest(&c->sq, &now_dest);
    if (c->prev_fd >= 0)
        close(c->prev_fd);
    c->prev_fd = old_fd;
    /* Said out loud, because the tunnel prints it and something has to be true after the first hop:
     * without this line lc_qconn_port kept answering with the port of the very first dial, so a
     * connection whose far end had moved four times still reported where it started. */
    c->node_port = port;
    /* ngtcp2 is NOT told, and that is the whole design: it keeps the path it was given, and the
     * socket underneath is what moved. Telling it would start path validation and a migration for
     * something that, from the protocol's side, has not happened. Upstream does the same by hiding
     * the hop inside a PacketConn. */
    arm_hop(c);
    return 0;
}

const char *lc_qconn_suite(const lc_qconn *c)
{
    /* Three suites are offered now, and which one the node chose decides what this costs to run.
     * Re-measured on the target router (MT7621) on 2026-09-19 with test/bench built at the flags the
     * binary ships — which is a correction, and a large one: AES-128-GCM costs 534 ms per megabyte
     * for the pair of directions (443 until 2026-09-21, when the bench's open was found to stop at
     * a failed tag and never decrypt — see src/tls/aead.h) against ChaCha20-Poly1305's 91, and this line used to say 1077
     * against 91, from the same bench before it was fixed to stop measuring its own -O1 build.
     * The difference is visible from outside only as a share of the processor, which is a thing to
     * infer rather than read — so the connection says it instead.
     *
     * Named through lc_aead_alg_name so that the two planes cannot spell a cipher differently: the
     * suite id is turned into an algorithm by the same function the record layer uses. */
    lc_aead_alg alg;
    lc_hash     hash;
    size_t      key_len;

    if (lc_tls_suite_params(c->shim.tls.suite, &alg, &hash, &key_len) != 0)
        return "an unknown suite";

    return lc_aead_alg_name(alg);
}

/* Not in ngtcp2's public header, only in lib/ngtcp2_conn.h:911 — and the one place that knows idle_ts.
 * The library is linked here as objects from the pinned revision (docs/BUILD.md "Pinned revisions",
 * check-vendor holds the pin), so the symbol is this build's own; declared here rather than by
 * reaching into lib/ for the whole internal header. */
ngtcp2_tstamp ngtcp2_conn_get_idle_expiry(const ngtcp2_conn *conn);


uint64_t lc_qconn_idle_ms(lc_qconn *c)
{
    if (c->closed || c->conn == NULL)
        return 0;
    /* ngtcp2 does not hand out idle_ts, only idle_ts plus the timeout it applies: the local
     * max_idle_timeout until the handshake completes, raised to three PTOs if that is longer
     * (ngtcp2_conn_get_idle_expiry, vendor/ngtcp2/lib/ngtcp2_conn.c:14034-14066). The same sum,
     * taken back off. */
    ngtcp2_tstamp expiry = ngtcp2_conn_get_idle_expiry(c->conn);
    if (expiry == UINT64_MAX)
        return 0;
    ngtcp2_duration span = LC_QCONN_IDLE_TIMEOUT;
    const ngtcp2_transport_params *rp = ngtcp2_conn_get_remote_transport_params(c->conn);
    if (ngtcp2_conn_get_handshake_completed(c->conn) && rp != NULL && rp->max_idle_timeout > 0 &&
        rp->max_idle_timeout < span)
        span = rp->max_idle_timeout;
    ngtcp2_duration pto3 = 3u * ngtcp2_conn_get_pto(c->conn);
    if (pto3 > span)
        span = pto3;
    ngtcp2_tstamp now = now_ns();
    if (expiry < span || now <= expiry - span)
        return 0;
    return (now - (expiry - span)) / NGTCP2_MILLISECONDS;
}

/* Whichever comes first: the caller's own patience, or the timer ngtcp2 asked for. Waiting past the
 * timer is how a connection quietly stops retransmitting and then times out. */
int lc_qconn_timeout(const lc_qconn *c, int cap)
{
    if (c->closed || c->conn == NULL)
        return cap;

    ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(c->conn);

    /* And the pacer's own next moment, because it is this loop that paces now: ngtcp2's timer knows
     * about loss detection and keep-alive, and nothing about a bucket that has run dry. Without
     * this the connection would sleep until some other timer happened to fire and the pace would
     * come out as whatever that interval was. */
    {
        ngtcp2_hybbr *pacer = ngtcp2_conn_hybbr(c->conn);
        if (pacer != NULL) {
            ngtcp2_tstamp next = ngtcp2_hybbr_pacer_next(pacer);
            if (next != 0 && next < expiry) {
                expiry = next;
            }
        }
    }

    /* AND THE HOP'S MOMENT, which is a timer of its own in the reference — hopLoop's, running from the
     * socket's creation (vendor/hysteria/extras/transport/udphop/conn.go:148-163) — so the port moves
     * on time on a connection with nothing to say. ⚠️ UNTIL 2026-09-27 nothing woke the loop for it,
     * and an idle connection hopped only when some other timer or packet came along. */
    if (hopping(c)) {
        uint64_t now_ms = lc_qconn_now_ms();
        uint64_t hop_in = c->hop_at <= now_ms ? 0u : c->hop_at - now_ms;
        if (cap < 0 || hop_in < (uint64_t)cap)
            cap = (int)hop_in;
    }

    if (expiry == UINT64_MAX)
        return cap;

    /* Compared in sixty-four bits and narrowed only once it is known to fit. ngtcp2's expiry is a
     * nanosecond timestamp and the difference is unsigned: a timer far enough out — an idle timeout
     * measured in days is legal — divides down to more milliseconds than an int holds, and the
     * conversion would land on a negative number. A negative timeout to poll means "wait forever",
     * so the failure of this line is a connection that stops waking up at all. */
    ngtcp2_tstamp now = now_ns();
    uint64_t      until = expiry <= now ? 0 : (expiry - now) / NGTCP2_MILLISECONDS;

    /* AND A WAIT SHORTER THAN A MILLISECOND IS STILL A WAIT, which matters since the pace is
     * applied (see flush): an interval of six hundred microseconds divides to zero here, poll
     * returns at once, ngtcp2 refuses to write because the pacing time has not come, and the loop
     * spins through that interval instead of sleeping through it — on a router, at the packet rate
     * this plane runs at, that is a core spent on waiting.
     *
     * Rounded up to one millisecond rather than to zero, and that number is the reference's: its
     * pacer never asks to be woken sooner either, because `TimeUntilSend` floors the delay at
     * MinPacingDelay = 1 ms (vendor/quic-go/internal/protocol/params.go:120, core/internal/congestion/common/pacer.go:64-77).
     * So the granularity this gives the pace is the granularity the reference gives it. */
    if (until == 0 && expiry > now) {
      until = 1;
    }

    if (cap < 0)
        cap = 0;
    return until < (uint64_t)cap ? (int)until : cap;
}

static int feed_batch(lc_qconn *c, lc_rxbatch *b, const ngtcp2_path *path, ngtcp2_pkt_info *pi,
                      unsigned *carry);

int lc_qconn_step(lc_qconn *c, int timeout_ms)
{
    if (c->closed)
        return 0;
    if (c->read_flush_failed)
        return -1;

    /* The question quic-go's run loop asks first, each time round: more control frames queued than
     * the last pass could send, past maxControlFrames, end the connection with INTERNAL_ERROR
     * (vendor/quic-go/connection.go:616-619, vendor/quic-go/framer.go:119-122). Only a node that
     * means to — a flood of reordered NEW_CONNECTION_ID, each answered with a RETIRE — gets there. */
    int crv = c->conn != NULL ? ngtcp2_conn_qgo_check_control_frames(c->conn) : 0;
    if (crv != 0) {
        c->lib_err = crv;
        say(c, "more control frames queued than quic-go allows");
        return -1;
    }

    timeout_ms = lc_qconn_timeout(c, timeout_ms);

    /* Both generations, because the point of keeping the previous socket is to read from it. And
     * the send queue's wake, so that a caller sleeping here after a write pass stopped on a full
     * queue is woken the moment an entry frees rather than at its next timeout. The socket is not
     * watched for writability at all any more: the writer thread waits on it. */
    struct pollfd p[3];
    nfds_t        np = 0;
    int           wake = lc_qconn_wake_fd(c);
    p[np].fd = c->fd;
    p[np].events = POLLIN;
    p[np++].revents = 0;
    if (c->prev_fd >= 0) {
        p[np].fd = c->prev_fd;
        p[np].events = POLLIN;
        p[np++].revents = 0;
    }
    if (wake >= 0) {
        p[np].fd = wake;
        p[np].events = POLLIN;
        p[np++].revents = 0;
    }
    int r = poll(p, np, timeout_ms);
    if (r < 0) {
        /* A signal is not an event and not a failure. Returning here rather than falling through
         * means the caller comes back with a fresh timeout instead of this turn running the timers
         * and the writer for nothing — which under a signal that arrives often is a busy loop
         * doing protocol work at whatever rate the signals arrive. */
        if (errno == EINTR)
            return 1;
        say(c, "poll failed: %s", strerror(errno));
        return -1;
    }
    /* Only consume wakes after a successful wait. Draining an empty pipe sets
     * errno=EAGAIN and must not replace EINTR or the original wait failure. */
    if (wake >= 0)
        lc_sendq_wake_drain(&c->sq);

    if (r > 0) {
        /* READ IN BATCHES, BECAUSE ONE DATAGRAM PER SYSTEM CALL WAS THE WHOLE OF THE DIFFERENCE.
         *
         * Measured 2026-09-01 against hysteria's own client on a loopback stand, both moving the
         * same 64 MiB: ours made 49 524 `recvmsg`, the reference made 6 190 `recvmmsg` — about
         * eight datagrams a call — and spent 98% of its kernel time there just as we did. Nothing
         * else in the profile came close, and the receive window — the obvious suspect, 512 KiB
         * at that date against the reference's 8 MiB — had already been ruled out by experiment:
         * raising it to the reference's value bought 14%, not the fourfold gap. (The window has
         * since become the reference's own; quic/params.h holds the measurements that settled it.)
         *
         * AND OPENED AHEAD, ON THE OTHER CORES (quic/rxopen.h). Datagrams are read eight to a
         * `recvmmsg` into a batch of thirty-two — the number the reference's loop reads before it
         * writes — and while the threads take one batch's Salamander, header protection and AEAD
         * off, this thread feeds ngtcp2 the batch before. ngtcp2 still opens every packet through
         * its callbacks, which answer from what the threads computed only for exactly the inputs
         * it was computed from; on a single core there are no threads and the same code opens each
         * batch here, just before it is fed.
         *
         * The buffers are sized to what a QUIC packet from our node can be, not to what a UDP
         * datagram may be: this connection tells the peer its packets must fit
         * max_tx_udp_payload_size, and the path MTU is under fifteen hundred. Anything larger did
         * not come from our node, and recv truncating it produces a packet ngtcp2 refuses — which
         * is the same outcome as reading it whole and refusing it. */
        ngtcp2_path     path = qconn_path(c);
        ngtcp2_pkt_info pi = { 0 };

        /* Drained in turn, current generation first. The previous socket is read for as long as it
         * exists because packets the node addressed to the port we have just left are still
         * arriving on it — that is the entire reason it is still open. Which socket a packet came
         * in on tells us nothing worth acting on: the reference does not check either, and says so
         * at ReadFrom (vendor/hysteria/extras/transport/udphop/conn.go:234-235), "Currently we do
         * not check whether the packet is from the server or not". What decides is whether it
         * unscrambles and whether ngtcp2 accepts it,
         * both of which happen below and neither of which cares about the descriptor. */
        for (unsigned gen = 0; gen < 2u; gen++) {
            int rfd = gen == 0 ? c->fd : c->prev_fd;
            if (rfd < 0)
                continue;
            /* Datagrams read since the write path last ran: the reference writes after at most
             * thirty-two. See LC_QRX_PER_TURN. */
            unsigned    since_answer = 0;
            lc_rxbatch *cur = lc_rxopen_batch(c->rx, 0), *ahead = lc_rxopen_batch(c->rx, 1);
            int         read_err = 0;
            unsigned    n = lc_rxopen_fill(cur, rfd, &read_err);
            if (n > 0u)
                lc_rxopen_start(c->rx, cur, c->conn);
            while (n > 0u) {
                /* The next batch is read before this one is fed, and handed to the threads before
                 * it is fed, so that the two overlap. The keys it is opened with are the ones in
                 * force now; a key update inside this batch leaves the next one's answers
                 * unmatched, and the callbacks compute those themselves. */
                unsigned next_n = read_err != 0 ? 0u : lc_rxopen_fill(ahead, rfd, &read_err);
                lc_rxopen_finish(c->rx);
                if (next_n > 0u)
                    lc_rxopen_start(c->rx, ahead, c->conn);
                int rc = feed_batch(c, cur, &path, &pi, &since_answer);
                if (rc != 1) {
                    /* Nothing may be left in the threads' hands when the step returns. */
                    lc_rxopen_finish(c->rx);
                    return rc;
                }
                lc_rxbatch *t = cur;
                cur = ahead;
                ahead = t;
                n = next_n;
            }
            if (read_err != 0) {
                /* Ends the connection the way the reference's does: a read error closes the
                 * transport, whose connections are destroyed without a CONNECTION_CLOSE
                 * (vendor/quic-go/transport.go:547-571). With the socket unconnected, an ICMP
                 * error from the path no longer lands here at all — see dial_node. It is
                 * reported after everything read before it was processed, as it always was. */
                say(c, "cannot receive: %s", strerror(read_err));
                c->silent = 1;
                return -1;
            }
        }
    }

    /* Timers before writing: an expiry that has come due may itself be what produces the packet. */
    int rv = ngtcp2_conn_handle_expiry(c->conn, now_ns());
    if (rv != 0) {
        /* The idle timeout is quic-go's ErrIdleTimeout, and it leaves in silence — see `silent`
         * in quic/conn.h. Any other expiry is ngtcp2 refusing, and says so. */
        if (rv == NGTCP2_ERR_IDLE_CLOSE)
            c->silent = 1;
        say(c, "the connection expired: %s", ngtcp2_strerror(rv));
        return -1;
    }

    /* SETTINGS, if its goroutine has run since the last turn — see qconn_control_goroutine. */
    if (qconn_control_turn(c) != 0)
        return -1;
    return flush(c) != 0 ? -1 : 1;
}

/* One batch, opened by quic/rxopen.c, fed to ngtcp2 in the order it was read. Returns 1 to go on,
 * 0 when the peer closed the connection, -1 on a failure that ends it (said). */
static int feed_batch(lc_qconn *c, lc_rxbatch *b, const ngtcp2_path *path, ngtcp2_pkt_info *pi,
                      unsigned *carry)
{
    /* Datagrams read since the write path last ran, carried from one batch to the next. */
    unsigned since_answer = *carry;
    int      rc = 1;
    for (unsigned slot = 0; slot < b->n; slot++) {
        lc_rxslot     *s = &b->slot[slot];
        struct msghdr *rmsgp = &s->hdr;
        c->rx_datagrams++;
        pi->ecn = 0;
        ngtcp2_tstamp rx_ts = 0; /* unknown until a stamp says otherwise */
        {
            /* CMSG_NXTHDR IS THE LIBRARY'S, AND ON 32-BIT IT DOES NOT SURVIVE -Wsign-conversion.
             *
             * musl's macro compares the walked length against msg_controllen, one signed and one
             * not, and the cross build for the router — where long is 32 bits — refuses it:
             * `unsigned conversion from long int to long unsigned int changes value from -4 to
             * 4294967292`. The host build never sees it, so this compiled clean here and could
             * not compile at all for the device it is written for.
             *
             * Silenced around the macro alone rather than for the file or the build. The
             * conversion is inside a header this tree does not own; widening the exemption would
             * cover our own arithmetic too, and every other sign-conversion warning in this file
             * has been a real defect. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
            for (struct cmsghdr *cm = CMSG_FIRSTHDR(rmsgp); cm != NULL;
                 cm = CMSG_NXTHDR(rmsgp, cm)) {
#pragma GCC diagnostic pop
                int got = -1;
                if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_TIMESTAMPNS &&
                    cm->cmsg_len >= CMSG_LEN(sizeof(struct timespec))) {
                    struct timespec at;
                    memcpy(&at, CMSG_DATA(cm), sizeof at);
                    int64_t mono = (int64_t)at.tv_sec * 1000000000 + (int64_t)at.tv_nsec -
                                   s->wall_minus_mono;
                    if (mono > 0)
                        rx_ts = (ngtcp2_tstamp)mono;
                    continue;
                }
                if (cm->cmsg_level == IPPROTO_IP && cm->cmsg_type == IP_TOS) {
                    /* IP_TOS arrives as one byte on Linux and as an int elsewhere; both are
                     * read rather than assuming, because guessing wrong reads a neighbouring
                     * byte of the control buffer as the codepoint. */
                    if (cm->cmsg_len >= CMSG_LEN(sizeof(int)))
                        memcpy(&got, CMSG_DATA(cm), sizeof got);
                    else if (cm->cmsg_len >= CMSG_LEN(1u))
                        got = *(const unsigned char *)CMSG_DATA(cm);
                }
#ifdef IPV6_TCLASS
                else if (cm->cmsg_level == IPPROTO_IPV6 && cm->cmsg_type == IPV6_TCLASS) {
                    if (cm->cmsg_len >= CMSG_LEN(sizeof(int)))
                        memcpy(&got, CMSG_DATA(cm), sizeof got);
                }
#endif
                if (got >= 0)
                    pi->ecn = (uint8_t)(got & 0x03);
            }
        }

        /* Unscrambled before ngtcp2 ever sees it — by the opener, see quic/rxopen.c. A datagram
         * that does not unscramble is one from something that is not our server — scanners find an
         * open UDP port and try things — and is dropped rather than handed on. */
        uint8_t *plain = s->plain;
        long     plain_len = s->plain_len;
        if (plain_len < 0) {
            /* COUNTED, because the alternative reading of a silent connection is this one.
             *
             * The tunnel decides the node has gone quiet when nothing has unscrambled for six
             * seconds — and a datagram that arrives and fails here is indistinguishable from a
             * datagram that never arrived, by every measure the tunnel has. Two very different
             * faults look identical: a path that dropped the packets, and an obfuscation that
             * stopped agreeing with the node's. Measured on a router, the silence is real and
             * the loop was awake for it; which of these two it was cannot be answered without
             * this number. Scanners knocking on the port land here too, and that is itself
             * worth knowing when the count is small and steady rather than a burst. */
            c->rx_foreign++;
            continue;
        }

        /* And put back together, if this is a piece rather than a packet.
         *
         * The order is the mirror of emit: Salamander came off above, and what is underneath is
         * either a Gecko frame or a QUIC packet. Which one is decided the way the reference
         * decides it — by the top bit — and a short header goes straight through, so an
         * established connection pays one comparison. A frame that completes nothing is not a
         * fault and not a foreign datagram: the rest of it is still on its way, so the loop
         * takes the next datagram without touching either counter. A reassembled packet is not
         * the one the opener saw, and goes to ngtcp2 without a hint. */
        uint8_t assembled[LC_QCONN_PACKET_MAX];
        int     hinted = 1;
        if (c->gecko.on && plain_len > 0 && (plain[0] & 0x80u) != 0u) {
            long whole = lc_gecko_take(&c->gecko, plain, (size_t)plain_len, lc_qconn_now_ms(),
                                       assembled, sizeof assembled);
            if (whole == 0)
                continue;
            if (whole < 0) {
                /* Counted with the rest of what did not come from our node, which is what it
                 * is: with Gecko on, a long-header datagram that is not a frame of ours cannot
                 * have been produced by the node. */
                c->rx_foreign++;
                continue;
            }
            memcpy(plain, assembled, (size_t)whole);
            plain_len = whole;
            hinted = 0;
        }

        /* Read first, stamped after — because unscrambling proves nothing at all.
         *
         * This used to stamp here, on the reasoning that a packet which unscrambled with our key
         * came from our node. Salamander cannot support that reasoning: it is XOR with a key
         * derived from the password and a salt the sender chooses and sends in the clear, so a
         * datagram encrypted with SOMEBODY ELSE'S password unscrambles perfectly, into rubbish.
         * Checked against the upstream it copies — extras/obfs/salamander.go rejects only a
         * datagram of eight bytes or fewer — and that is the protocol as designed, not a
         * shortcoming here: the real client leans on QUIC's own AEAD below it, exactly as this
         * does. lc_obfs_unwrap therefore fails on length and on nothing else, and the number it
         * refuses is not "wrong key" but "too short to hold a salt".
         *
         * So a stream of rubbish from anything that can reach this socket kept last_rx_ms
         * current: ngtcp2 discards an undecryptable packet and returns 0, silently. At the time
         * that mattered because a silence rule read last_rx_ms and would never have fired; that
         * rule is gone, and the stamp still has to be honest — lc_qconn_silent_ms is what the
         * log reports and what a person reads to tell a quiet node from a blocked one, and a
         * blocked node is the case with a party on the path who would very much like the two to
         * look the same.
         *
         * What ngtcp2 accepted is the only proof there is, since only our keys can produce it —
         * and a zero return is not that. ngtcp2 answers zero for a packet it could not decrypt
         * as readily as for one it processed: NGTCP2_ERR_DISCARD_PKT is turned into `return 0`
         * one line after it is raised. The number that distinguishes them is pkt_recv, which is
         * documented as "excluding discarded ones" and incremented only where a packet has been
         * read whole. Its counterpart pkt_discarded is what this loop has wanted all along. */
        ngtcp2_conn_info before;
        ngtcp2_conn_get_conn_info2(c->conn, &before);

        /* With the time it arrived, which is what the reference's acknowledgement handling
         * runs on — see the socket options in prep_socket and patches/ngtcp2/0011 — and with
         * what the opener computed, for the callbacks to answer from when it matches. */
        lc_qcrypto_hint(hinted ? &s->hint : NULL);
        int rv = ngtcp2_conn_read_pkt_rx(c->conn, path, pi, plain, (size_t)plain_len, rx_ts,
                                         now_ns());
        lc_qcrypto_hint(NULL);
        if (rv == 0) {
            ngtcp2_conn_info after;
            ngtcp2_conn_get_conn_info2(c->conn, &after);
            if (after.pkt_recv > before.pkt_recv)
                c->last_rx_ms = lc_qconn_now_ms();
            else if (after.pkt_discarded > before.pkt_discarded)
                c->rx_foreign++;
        }
        if (rv != 0) {
            /* OUR OWN TLS FIRST, WHEN IT HAS SOMETHING TO SAY.
             *
             * ngtcp2 reports every refusal from the crypto callback as NGTCP2_ERR_CRYPTO, so
             * the reason a handshake ended — a pin that did not match, a signature scheme this
             * build cannot verify, a message at the wrong level — arrived here as one word and
             * left as "no reason recorded". qtls.c now records which of them it was, and this
             * is the only place that can lift it out: the shim has no channel back and ngtcp2
             * has no room for it.
             *
             * Read here and used at the bottom: the branches in between describe what the PEER
             * said, and those keep their own words. */
            const char *why = lc_qtls_error(&c->shim.tls);

            /* A closed connection is an outcome, not a fault: the peer said so in a packet we
             * just read, and there is nothing left to do but agree. */
            if (rv == NGTCP2_ERR_DRAINING || rv == NGTCP2_ERR_CLOSING) {
                /* The peer said WHY, and it is the only account of the failure that exists:
                 * everything went out obfuscated and encrypted, so a capture shows nothing.
                 * Dropping it left every refusal — a TLS alert, a transport parameter the node
                 * would not take, an idle timeout — reading identically as "the node closed the
                 * connection", which is the sentence that tells the operator least. A TLS alert
                 * arrives as 0x0100 + the alert number, so the code is worth printing raw. */
                const ngtcp2_ccerr *cc = ngtcp2_conn_get_ccerr(c->conn);
                if (cc != NULL)
                    say(c, "the node closed the connection: code 0x%llx%s%.*s",
                        (unsigned long long)cc->error_code, cc->reasonlen > 0 ? ", " : "",
                        (int)cc->reasonlen, cc->reason != NULL ? (const char *)cc->reason : "");
                c->closed = 1;
                rc = 0;
                goto out;
            }
            /* OURS WINS, and it has to be said here rather than above: say() overwrites, so a
             * reason recorded before this line is a reason this line erases. The first attempt
             * at this put the lift above the branches, which read better and printed
             * "ERR_CRYPTO" exactly as before.
             *
             * ngtcp2's word for it is the same for every refusal our TLS makes, so when qtls
             * has a sentence it is strictly the more useful of the two. */
            if (why[0] != '\0')
                say(c, "%s", why);
            else
                say(c, "the node's packet was refused: %s", ngtcp2_strerror(rv));
            /* AND THE ALERT IS CARRIED TO THE CLOSE, which is where it becomes visible.
             *
             * The shim hands ngtcp2 the alert number when our TLS refuses; ngtcp2 stores it
             * and nothing in the library ever reads it back. The reference client is what
             * turns it into a close:
             *
             *     if (rv == NGTCP2_ERR_CRYPTO) {
             *       ngtcp2_ccerr_set_tls_alert(&c->last_error,
             *                                  ngtcp2_conn_get_tls_alert2(c->conn), NULL, 0);
             *     } else {
             *       ngtcp2_ccerr_set_liberr(&c->last_error, rv, NULL, 0);
             *     }        (vendor/ngtcp2/examples/simpleclient.c:383-389)
             *
             * Without this half the alert is set and then dropped, and lc_qconn_close writes
             * an APPLICATION close with 0x100 for a failure that was not an application's.
             *
             * ⚠️ AND THE `else` WAS MISSING UNTIL 2026-09-06, which is the same fault in the
             * other direction: only the crypto half was carried, so every TRANSPORT failure —
             * PROTOCOL_VIOLATION, FLOW_CONTROL_ERROR, FRAME_ENCODING_ERROR,
             * TRANSPORT_PARAMETER_ERROR — left as an application close with 0x100. The frame
             * type differs (0x1d against 0x1c) and so does the code, both readable on the path.
             * The two branches are one decision and are written as one. */
            /* A refusal that named no alert of its own is internal_error: quicError, which every
             * TLS failure on the reference's QUIC path goes through, gives that to any error
             * that carries none (GOROOT/src/crypto/tls/quic.go:358-373, go1.25.14). Zero is not
             * an answer — it is close_notify, and it used to fall through to an APPLICATION
             * close with 0x100, which says nothing went wrong. */
            if (rv == NGTCP2_ERR_CRYPTO) {
                c->tls_alert = ngtcp2_conn_get_tls_alert2(c->conn);
                if (c->tls_alert == 0u)
                    c->tls_alert = LC_ALERT_INTERNAL_ERROR;
            } else {
                c->lib_err = (int)rv;
                if (rv == NGTCP2_ERR_NOMEM || rv == NGTCP2_ERR_CALLBACK_FAILURE)
                    c->own_fail = 1;
            }
            if (lc_qtls_own(&c->shim.tls))
                c->own_fail = 1;
            rc = -1;
            goto out;
        }

        /* Thirty-two read, and the reference's loop would now stop reading and send: what is
         * owed goes out here, and reading resumes after it. A socket that runs dry first is
         * answered by the flush at the end of the step. */
        if (++since_answer >= LC_QRX_PER_TURN) {
            since_answer = 0;
            if (flush(c) != 0) {
                rc = -1;
                goto out;
            }
        }
    }
out:
    *carry = since_answer;
    return rc;
}

void lc_qconn_close(lc_qconn *c)
{
    qconn_control_join(c); /* before anything it touches goes */
    /* Said out loud rather than walked away from. A client that just stops sending leaves the node
     * holding the session until its idle timer runs out — half a minute of state per connection,
     * and a line in its log about a client that vanished. Hysteria's own client closes with the
     * HTTP/3 code for "nothing went wrong", which is 0x100, so this does too: the alternative is
     * being the one connection on the node that ends differently from all the others.
     *
     * One packet, one attempt. If it is lost, the timer the peer already has is the backstop.
     *
     * Built here, while the connection still exists, and written only after the send queue has
     * closed — see lc_sendq_close below for why that order is the reference's. */
    uint8_t       close_pkt[1500 + LC_OBFS_SALT];
    long          close_len = 0;
    unsigned      close_ecn = 0u;
    /* NOT A WORD AFTER A FAILURE OF OUR OWN, which is where the reference has ended the process —
     * see own_failure. Until 2026-09-30 such a failure went out as a CONNECTION_CLOSE the reference
     * never sends: under the Chrome parrot CRYPTO_ERROR with internal_error and no reason, and
     * without it the same code or 0x100, "nothing went wrong". */
    if (c->conn != NULL && !c->closed && !c->silent && !c->own_fail && c->fd >= 0) {
        ngtcp2_ccerr ccerr;
        /* 0x100 unless something set it otherwise; a refused authentication sets 0x101. Both come
         * from vendor/hysteria/core/client/client.go:22-23. */
        /* A CRYPTO FAILURE IS A TRANSPORT ERROR, NOT AN APPLICATION ONE. `ngtcp2_ccerr_set_tls_alert`
         * builds NGTCP2_CRYPTO_ERROR | alert (ngtcp2_conn.c:12878-12881), so a pin that did not match
         * leaves as 0x012a and an unverifiable signature scheme as 0x012f — what any other client
         * would send. Everything else keeps 0x100, which is hysteria's own "nothing went wrong". */
        /* Three states, in the order the reference decides them: a crypto failure names its alert,
         * any OTHER library failure names itself as a transport error, and only a close this client
         * chose to make — the ordinary one, or the 0x101 of a refused authentication — is an
         * application close. Before the middle branch existed a transport failure took the last one
         * and went out as 0x100, which said "the application closed, nothing went wrong" about a
         * connection ngtcp2 had just refused. */
        if (c->tls_alert != 0u && c->chrome && lc_qtls_go_error(&c->shim.tls)[0] != '\0') {
            /* UNDER THE CHROME PARROT A TLS FAILURE IS NOT A CRYPTO ERROR. quic-go knows the
             * standard library's AlertError and not uTLS's, which is what the parrot runs; so
             * wrapError turns the failure into INTERNAL_ERROR with err.Error() as the reason
             * (vendor/quic-go/internal/handshake/crypto_setup.go:700-705) — a pin that does not
             * match leaves as 0x1 "no certificate matches the pinned hash", not as 0x12a. The words
             * are uTLS's, kept by quic/qtls.c beside the alert (tls/goerr.h). A refusal with no
             * words of the reference's is a failure of ours, and never reaches here: see own_fail. */
            const char *go = lc_qtls_go_error(&c->shim.tls);
            ngtcp2_ccerr_set_transport_error(&ccerr, NGTCP2_INTERNAL_ERROR, (const uint8_t *)go,
                                             strlen(go));
        } else if (c->tls_alert != 0u)
            ngtcp2_ccerr_set_tls_alert(&ccerr, c->tls_alert, NULL, 0);
        else if (c->lib_err != 0) {
            /* A transport error closes as quic-go closes on it: its code, the type of the frame it
             * happened on, and its own words as the reason (vendor/quic-go/packet_packer.go:202-208)
             * — recorded by the patched ngtcp2 where the check failed (patches/ngtcp2/0033). Only an
             * error with no counterpart in quic-go falls back to the code ngtcp2 infers. */
            if (!ngtcp2_conn_get_qgo_ccerr(c->conn, &ccerr))
                ngtcp2_ccerr_set_liberr(&ccerr, c->lib_err, NULL, 0);
        }
        else
            ngtcp2_ccerr_set_application_error(
                &ccerr, c->close_code != 0u ? c->close_code : 0x100u, NULL, 0);

        uint8_t             buf[1500];
        ngtcp2_path_storage ps;
        ngtcp2_path_storage_zero(&ps);

        /* Marked as the reference marks it: sendConnectionClose asks ECNMode like every other
         * packet (vendor/quic-go/connection.go:2895), so the close is ECT(0) exactly when a data
         * packet would be — pkt_info handed over on the same condition as in the write loop, and
         * the same rule as emit_one on which socket may carry the mark at all. This went out
         * unmarked always. */
        ngtcp2_pkt_info pi;
        memset(&pi, 0, sizeof pi);
        int marking = c->ecn_ok && ngtcp2_conn_get_handshake_completed(c->conn);

        ngtcp2_ssize n = ngtcp2_conn_write_connection_close(
            c->conn, &ps.path, marking ? &pi : NULL, buf, sizeof buf, &ccerr, now_ns());
        if (n > 0 && lc_gecko_applies(&c->gecko, buf, (size_t)n)) {
            /* THROUGH GECKO WHEN IT CUTS THIS PACKET, as the reference's close goes: it is written
             * to the same wrapped connection every packet is, and Gecko's WriteTo fragments any long
             * header (vendor/hysteria/extras/obfs/gecko.go:99-108) — which a close during the
             * handshake is. Queued as a packet like any other, so it leaves behind what is already
             * queued, as lc_sendq_close would send it. ⚠️ UNTIL 2026-09-27 it went out whole, one
             * salted datagram, where the reference sends Gecko frames. */
            if (emit(c, buf, (size_t)n, 0u) != 0)
                say(c, "cannot fragment the close");
        } else if (n > 0) {
            /* Sized from the packet it wraps rather than from a round number. Sixteen hundred was
             * enough here and it is the same figure that was NOT enough in emit_one, where the
             * frame can be a Gecko one — a number that happens to work beside one that did not is
             * worth removing. A short-header close is never cut by Gecko: one packet and the salt.
             */
            close_len = lc_obfs_wrap(&c->obfs, buf, (size_t)n, close_pkt, sizeof close_pkt);
            close_ecn = oob_conn(c) && (buf[0] & 0x80u) == 0u ? pi.ecn : 0u;
        }
    }

    for (unsigned i = 0; i < c->st_count; i++)
        slot_release(st_at(c, i));
    c->st_count = 0;
    for (unsigned k = 0; k < LC_QSTREAM_CHUNKS; k++) {
        free(c->st_chunk[k]);
        c->st_chunk[k] = NULL;
    }

    lc_qudptab_free(&c->udp);
    free(c->dq);
    c->dq = NULL;
    c->dq_count = 0;

    if (c->conn != NULL) {
        ngtcp2_conn_del(c->conn);
        c->conn = NULL;
    }
    lc_qshim_free(&c->shim);
    /* Everything queued goes out, then the close packet, then the sockets close — the reference's
     * order: `c.sendQueue.Close()` drains and stops the writer (vendor/quic-go/connection.go:761,
     * send_queue.go:82-90), and sendConnectionClose then writes the close itself
     * (vendor/quic-go/connection.go:2897). It also
     * has to happen BEFORE the close below: a datagram addressed to a descriptor must not be written
     * after that number has been handed to somebody else.
     *
     * ⚠️ THE CLOSE USED TO BE QUEUED, and with the queue full that meant draining it first — a wait for
     * empty with no bound, taken BEFORE the writer was told to stop, while the writer only gives up
     * on a full socket once it has been. A socket that stayed full held the one thread every session
     * runs on for good, with no crash for procd to notice. */
    lc_sendq_close(&c->sq, close_len > 0 ? close_pkt : NULL, close_len > 0 ? (size_t)close_len : 0u,
                   close_ecn);
    /* Idle by now: every step finishes the batch in the threads' hands before it returns. */
    lc_rxopen_free(c->rx);
    c->rx = NULL;
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
    /* And the generation behind it, when a hop has happened. The reference closes both in Close()
     * for the same reason (vendor/hysteria/extras/transport/udphop/conn.go:262-263, "Close prevConn
     * and currentConn"). Leaking it
     * would be a descriptor per connection on a device with a few hundred. */
    if (c->prev_fd >= 0) {
        close(c->prev_fd);
        c->prev_fd = -1;
    }

    /* And said in the structure, not only in the descriptors. Every entry point here is guarded by
     * some combination of `closed` and `conn != NULL`, and this function cleared the second without
     * ever setting the first — so a closed connection still answered "not closed" to anything that
     * asked that question alone. Nothing reachable does today, which is exactly why it would have
     * been a quiet fault the day something did. */
    c->closed = 1;
}

/* ---- the stream table ------------------------------------------------------- */

/* How a handle is put together: sixteen bits of slot index, the rest a generation. Declared here
 * rather than beside HANDLE_OF because the generation is kept by the table below, and the two have
 * to agree about how much of it fits.
 *
 * Sixteen since 2026-09-27, when the table stopped refusing the 257th stream (see LC_QTCP_MAX): the
 * nine before held 4 + 256 slots and no more. The bits come out of the generation, which is what
 * the assertion below is for — it is the reason raising the table stops the build instead of
 * producing handles that address the wrong slot. */
#define HANDLE_INDEX_BITS 16
#define HANDLE_GEN_MASK ((1u << (31 - HANDLE_INDEX_BITS)) - 1u)

/* The two things a handle silently assumes, said out loud so that changing either one stops the
 * build rather than producing handles that address the wrong slot or come out negative.
 *
 * A handle is a signed int on purpose — it is what the public interface hands back, and -1 is how
 * "no room" is said — so everything has to fit in thirty-one bits with the index at the bottom and
 * one value (zero) reserved for "not a handle". */
_Static_assert(LC_QSTREAM_MAX <= (1u << HANDLE_INDEX_BITS) - 1u,
               "the stream table outgrew the index bits in a handle");
_Static_assert((HANDLE_GEN_MASK << HANDLE_INDEX_BITS) <= (unsigned)INT_MAX,
               "generation and index together do not fit in a positive int");

static lc_qstream *slot_of(lc_qconn *c, int64_t id)
{
    for (unsigned i = 0; i < c->st_count; i++)
        if (st_at(c, i)->state != LC_QSLOT_FREE && st_at(c, i)->id == id)
            return st_at(c, i);
    return NULL;
}

/* Takes a slot and puts a stream in it. The buffers are the caller's business: the HTTP/3 streams
 * point into the connection's arena, a proxied connection owns what it was given. */
static lc_qstream *slot_take(lc_qconn *c)
{
    lc_qstream *s = NULL;
    for (unsigned i = 0; i < c->st_count && s == NULL; i++)
        if (st_at(c, i)->state == LC_QSLOT_FREE)
            s = st_at(c, i);

    if (s == NULL) {
        if (c->st_count >= LC_QSTREAM_MAX)
            return NULL;
        /* A chunk at a time, and never moved: a slot's address stays what it was for as long as the
         * connection lives, which the callers that hold one across another slot_take rely on. */
        unsigned k = c->st_count / LC_QSTREAM_CHUNK;
        if (c->st_chunk[k] == NULL) {
            c->st_chunk[k] = calloc(LC_QSTREAM_CHUNK, sizeof *c->st_chunk[k]);
            if (c->st_chunk[k] == NULL)
                return NULL;
        }
        s = st_at(c, c->st_count);
        s->idx = c->st_count++;
    }

    /* The generation survives the wipe and moves on: that is the whole point of it. Every reuse of
     * a slot is a different stream, and a handle to the previous one has to stop working.
     *
     * Kept inside what a handle can hold. A handle is a signed int with sixteen bits spent on the
     * index, so the generation has fifteen; left to grow it would eventually push into the
     * sign bit and make every handle from that slot negative, which by_handle reads as "not one of
     * ours" — a stream that stops working after enough churn and no reason visible anywhere.
     * Wrapping instead is safe: nobody holds a handle across thirty-two thousand reuses of one slot, and
     * a handle does not outlive the turn of the loop that was given it. */
    unsigned gen = (s->gen + 1u) & HANDLE_GEN_MASK;
    unsigned idx = s->idx;
    memset(s, 0, sizeof *s);
    s->gen = gen;
    s->idx = idx;
    return s;
}

static void slot_release(lc_qstream *s)
{
    if (s->owned) {
        lc_qrx_close(&s->rx);
    }
    /* Unconditionally, because the queue knows which of its blocks it owns and the arena's are
     * marked as not its to free. The old flat buffer needed the caller to remember. */
    lc_qtx_free(&s->tx);
    /* The generation AND the index survive the wipe: the index is where the slot is, and a handle
     * is made from it (HANDLE_OF). ⚠️ UNTIL THE STAND CAUGHT IT, 2026-09-27, only the generation did —
     * the table had just gone from one array to chunks — so every reused slot said it was slot 0,
     * its handle named a control stream, and the second connection through the tunnel ended before
     * a byte moved. `make check` was green; test/hystand's twenty short connections were not. */
    unsigned gen = s->gen;
    unsigned idx = s->idx;
    memset(s, 0, sizeof *s);
    s->gen = gen;
    s->idx = idx;
}

/* Claims room in the shared arena for one of the HTTP/3 streams and hands back where to write. The
 * length is settled afterwards by arena_commit, because the one caller that needs the most room —
 * the authentication request — cannot know how much of it it will use until the padding has been
 * drawn and coded. */
/* Returns the stream rather than only where to write, and arena_commit takes it back.
 *
 * It used to return the buffer alone, and the commit wrote to `st[st_count - 1]` — the slot most
 * recently ADDED to the table, which is the one slot_take returns only while no slot has ever been
 * released. The first reuse of a freed slot would have sent the length to somebody else's stream:
 * a live connection told it had bytes to send that were never put there. Nothing reaches it today,
 * because the four streams that use the arena are opened once at the start of a connection — which
 * is exactly the kind of "cannot happen yet" that stops being true without anyone noticing. */
static lc_qstream *arena_open(lc_qconn *c, int64_t id, size_t most, lc_qtx_state fin, uint8_t **at)
{
    if (most > sizeof c->txbuf - c->txused)
        return NULL;
    lc_qstream *s = slot_take(c);
    if (s == NULL)
        return NULL;
    s->state = LC_QSLOT_OPEN;
    s->id = id;
    /* Borrowed, not owned: this region belongs to the connection's arena, and freeing it with
     * the stream would be a free of memory nobody malloc'd. */
    if (lc_qtx_adopt(&s->tx, c->txbuf + c->txused, most, 0) != 0) {
        slot_release(s);
        return NULL;
    }
    s->tx.cap = most;
    s->tx_fin = fin;
    *at = c->txbuf + c->txused;
    return s;
}

static void arena_commit(lc_qconn *c, lc_qstream *s, size_t len)
{
    lc_qtx_commit(&s->tx, len);
    c->txused += len;
}

static int arena_queue(lc_qconn *c, int64_t id, const uint8_t *data, size_t len, lc_qtx_state fin)
{
    uint8_t    *at = NULL;
    lc_qstream *s = arena_open(c, id, len, fin, &at);
    if (s == NULL)
        return -1;
    memcpy(at, data, len);
    arena_commit(c, s, len);
    return 0;
}

/* The sending side is quic/txbuf.c, and there is no growing left to do here: the queue allocates a
 * block when it needs one and frees it when its bytes are acknowledged, so room comes back at the
 * front while the back is still in flight. tx_grow stood here until 2026-08-30 and could not — it
 * had to wait for the whole buffer to be idle, which on an uploading stream never happened. The
 * derivation it carried is kept where the code is, at the top of quic/txbuf.h. */

static int recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                               uint64_t offset, const uint8_t *data, size_t datalen,
                               void *user_data, void *stream_user_data)
{
    (void)offset;
    (void)stream_user_data;
    lc_qconn *c = user_data;

    /* A stream we know nothing about is read and dropped. The server's own control and QPACK
     * streams arrive here: with a dynamic table of zero there is nothing on them this client needs,
     * and saying so is cheaper than pretending to parse them.
     *
     * DROPPED, BUT STILL CREDITED BACK — and it was not, which turned "nothing this client needs"
     * into a window that shrank and never grew.
     *
     * ngtcp2 leaves connection-level flow control to the application: `ngtcp2_conn_extend_max_offset
     * extends max data offset by |datalen|. This function only extends connection-level flow
     * control window.` (vendor/ngtcp2/lib/includes/ngtcp2/ngtcp2.h:5578-5582). Bytes handed to this
     * callback have been counted against conn->rx.max_offset already; returning without crediting
     * them consumes the window permanently.
     *
     * This client advertises initial_max_data = 20 MB and initial_max_streams_uni = 100
     * (src/quic/params.c), so a node that opens unidirectional streams and writes 20 MB of anything
     * at all across them exhausts the connection window for the life of the connection. Every
     * proxied stream then stalls, with no error anywhere: flow control exhaustion is silence, not a
     * failure. It costs the peer nothing to do and needs no protocol violation.
     *
     * The reference has no equivalent because quic-go credits its own window internally; there is
     * no reference line to copy here, only ngtcp2's contract to honour. Credited for BOTH the
     * unknown-stream case and the known-stream-without-a-buffer case below, because the bytes are
     * equally gone in both. */
    lc_qstream *s = slot_of(c, stream_id);
    if (s == NULL) {
        if (datalen > 0)
            ngtcp2_conn_extend_max_offset(conn, datalen);
        return 0;
    }

    /* The three HTTP/3 streams we open are ours to write and have no receive buffer at all. The
     * peer cannot send on them — they are unidirectional in our direction — so this never fires;
     * it is here so that what follows is about a buffer that exists rather than about a null
     * pointer whose capacity happens to be zero.
     *
     * Everything else about holding these bytes — how far the buffer may grow, when it gives the
     * room back, and what happens to bytes that do not fit — is quic/rxbuf.c. That last one is
     * `over`, and it is acted on below. For the authentication stream it means something else
     * entirely — the node answered with a web page — and is handled where that answer is read, in
     * lc_qconn_authenticate. */
    if (s->rx.buf == NULL) {
        if (datalen > 0)
            ngtcp2_conn_extend_max_offset(conn, datalen);
        return 0;
    }

    lc_qrx_put(&s->rx, data, datalen);

    /* WHAT COULD NOT BE HELD ENDS THIS STREAM, AND ONLY THIS STREAM.
     *
     * The comment above used to say `over` "ends the connection". It did not: the only reader of
     * `over` in the whole tree was the authentication stream, and every proxied stream ran on
     * without looking — lc_qconn_tcp_peek handed the caller its buffer with no error channel at
     * all, so a run the machine had no memory for became a hole delivered as if it were data.
     *
     * The loss was doubly permanent, because lc_qconn_tcp_take extends the window only for bytes
     * actually taken: what was dropped was never credited back either, so the stream's window shrank
     * for good. Credited here for exactly that reason — the bytes are gone, and ngtcp2 leaves
     * connection-level flow control to the application (ngtcp2.h:5578-5582).
     *
     * Only the stream is ended, not the connection. The node did nothing wrong, every other session
     * on this tunnel is unaffected, and a device under memory pressure is helped least by having its
     * one working connection torn down. The node is told to stop sending on it — H3_INTERNAL_ERROR
     * (0x102, nghttp3.h:386), which is the honest code: the fault is at this end.
     *
     * `owns` is the gate rather than the stream id: only a stream with a buffer of its own can reach
     * `over` this way. The authentication stream borrows a fixed one (lc_qrx_borrow) whose `over`
     * means the node sent more than an answer, which is a different event with its own reader. */
    if (s->rx.over && s->rx.owns && !s->lost) {
        s->lost = 1;
        /* What refused the room, said now: the line that reports the loss is printed later, from the
         * caller's poll. */
        if (s->rx.over == LC_QRX_OVER_ALLOC) {
            snprintf(s->why, sizeof s->why, "the allocator had no memory to grow the buffer");
        } else {
            snprintf(s->why, sizeof s->why, "more arrived than the buffer's ceiling holds");
        }
        if (datalen > 0)
            ngtcp2_conn_extend_max_offset(conn, datalen);
        (void)ngtcp2_conn_shutdown_stream(conn, 0, stream_id, 0x102u);
    }

    if ((flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0)
        s->rx_fin = 1;
    return 0;
}

/* The peer is finished with a stream, one way or another. Ours stays in the table until its owner
 * lets it go: a closed stream with bytes still in it is one the caller has not read yet, and
 * dropping them here would lose the tail of every download that ends promptly. */
static int stream_close_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                           uint64_t app_error_code, void *user_data, void *stream_user_data)
{
    (void)conn;
    (void)flags;
    (void)app_error_code;
    (void)stream_user_data;

    lc_qstream *s = slot_of((lc_qconn *)user_data, stream_id);
    if (s == NULL)
        return 0;
    s->rx_fin = 1;
    s->nc_closed = 1;
    /* And here, and only here, is the send buffer certainly nobody's but ours: "after stream_close
     * is called for a particular stream, conn does not touch data for the closed stream again".
     * A slot whose owner let it go while bytes were still unacknowledged has been waiting for this
     * — without it the slot would sit occupied for the life of the connection. */
    if (s->state == LC_QSLOT_CLOSING)
        slot_release(s);
    return 0;
}

/* The request, sent and not waited for.
 *
 * This was one blocking function: it opened the streams, wrote the request and then span its own
 * loop for up to ten seconds waiting for the answer. Inside a client with one thread and one event
 * loop that is ten seconds in which nothing else is served — no session, no datagram, no timer —
 * and it happens on exactly the path where something has already gone wrong. The reference has no
 * such problem to solve: there every proxied connection is its own goroutine, so a client blocking
 * on its own handshake blocks nothing but itself. Getting that property here means not blocking.
 *
 * So the two halves are named apart: this one queues, and lc_qconn_auth_poll asks. */
/* The control stream, opened when its goroutine has run: see qconn_control_goroutine. */
static int qconn_open_control(lc_qconn *c)
{
    /* Enough for the control stream's opening bytes, which are a stream type and a SETTINGS frame
     * with one entry in it — eight bytes. */
    uint8_t buf[32];

    c->ctrl_opened = 1;

    /* ONE UNIDIRECTIONAL STREAM, WHICH IS ALL THE REFERENCE OPENS.
     *
     * There were three: the control stream and a pair carrying nothing but a QPACK type byte, with
     * "required to exist, never used" beside them. The first half of that is wrong and the whole
     * reference says so — quic-go's HTTP/3 client calls OpenUniStream in exactly one place,
     * openControlStream (vendor/quic-go/http3/conn.go:82-92). It knows the QPACK stream types and
     * ACCEPTS them from a peer (vendor/quic-go/http3/conn.go:182-191), which is what "required" was read off; it never
     * opens them itself, because it uses the static table only and so has nothing to put on them.
     *
     * RFC 9204 permits either. What decides it here is that the node is a quic-go server and every
     * other client it meets is a quic-go client, so two extra streams in the first flight — two more
     * STREAM frames, two stream ids consumed, a different count of unidirectional streams before the
     * request — is a difference visible without decrypting anything beyond the handshake, on every
     * connection this client makes.
     *
     * Nothing is lost by not opening them: they carried one byte each and were never written to
     * again. Nothing breaks at the node either, by construction — its own client does the same. */
    int64_t ctrl = -1;
    if (ngtcp2_conn_open_uni_stream(c->conn, &ctrl, NULL) != 0) {
        say(c, "the node allowed no unidirectional stream");
        return -1;
    }

    size_t n = lc_h3_control_preface(buf, sizeof buf);
    if (n == 0 || arena_queue(c, ctrl, buf, n, 0) != 0) {
        say(c, "cannot build the control stream preface");
        return -1;
    }
    return 0;
}

/* THE GOROUTINE THAT WRITES SETTINGS, AS A THREAD OF ITS OWN.
 *
 * The reference writes SETTINGS from a goroutine — `go func() { … openControlStream(…) }()` in
 * newClientConn (vendor/quic-go/http3/client.go:120-134) — and the request on the caller's, which
 * goes straight on to RoundTrip. Which of the two reaches quic-go's run loop first is the scheduler's
 * doing: a new goroutine waits in its P's runnext until the goroutine that made it blocks, and the
 * caller blocks once its request is queued, waiting for the answer. Then the goroutine runs, queues
 * SETTINGS and wakes the run loop, which by then has usually sent the request. On the qstand server
 * (QSTAND_SERVE, 20 connections) the request came first every time and SETTINGS followed alone,
 * 0.06–3.83 ms later, 0.71 on average.
 *
 * So the same shape here: when the request is queued the "goroutine" becomes runnable — a thread
 * starts — and when it runs it marks SETTINGS as queued and wakes the loop through the send queue's
 * pipe, which is the run loop's wake; the loop opens the control stream at its next turn
 * (lc_qconn_step). The delay is the time a thread takes to start and a loop to wake, not a number
  * put here; until 2026-10-01 SETTINGS went out in the very next packet after the request
 * (DIVERGENCES.md G1). Measured then on the same stand, 20 connections each: SETTINGS alone after the
 * request every time in both clients, 0.04–0.42 ms after it here (0.15 on average) and 0.00–1.50
 * in the reference (0.58; 0.71 and 0.96 in two runs before) — its run loop's pass is longer than
 * this one's, which is the rest of the gap (tools/vendorcap/qstand/g1.sh). */
static void *qconn_control_goroutine(void *arg)
{
    lc_qconn *c = arg;
    __atomic_store_n(&c->ctrl_ready, 1, __ATOMIC_RELEASE);
    uint8_t one = 1;
    /* the loop may be gone to sleep on it; a full pipe means it is awake already */
    if (c->sq.wake_wr >= 0 && write(c->sq.wake_wr, &one, 1) < 0) {
        /* nothing to do: a failed wake is a turn the loop takes anyway at its next timer */
    }
    return NULL;
}

/* The loop's side: SETTINGS queued once the goroutine has run, and only once. */
static int qconn_control_turn(lc_qconn *c)
{
    if (c->ctrl_opened || !c->ctrl_g_live || !__atomic_load_n(&c->ctrl_ready, __ATOMIC_ACQUIRE))
        return 0;
    return qconn_open_control(c);
}

/* WHEN THE GOROUTINE RUNS: after the run loop's pass that sent the request.
 *
 * `go func()` puts the new goroutine in its P's runnext; the request's Write then readies the run
 * loop, which takes runnext and pushes the SETTINGS goroutine to the back of the queue. So when the
 * caller blocks on the answer the run loop runs first and sends the request, and the goroutine runs
 * after it — which is why the stand never saw SETTINGS first or in the request's packet. Here the
 * loop is the run loop: the thread starts once a pass has handed the whole request to ngtcp2. A
 * thread that cannot be started is a goroutine that has run at once. */
static void qconn_control_release(lc_qconn *c)
{
    if (!c->ctrl_pending || c->auth_id < 0)
        return;
    const lc_qstream *auth = slot_of(c, c->auth_id);
    if (auth == NULL || lc_qtx_pending(&auth->tx) != 0 || auth->tx_fin == LC_QTX_FIN_PENDING)
        return;
    c->ctrl_pending = 0;
    c->ctrl_g_live = 1;
    if (pthread_create(&c->ctrl_g, NULL, qconn_control_goroutine, c) == 0)
        c->ctrl_g_join = 1;
    else
        __atomic_store_n(&c->ctrl_ready, 1, __ATOMIC_RELEASE);
}

/* Joined before anything it touches goes: the send queue's pipe. */
static void qconn_control_join(lc_qconn *c)
{
    if (c->ctrl_g_join) {
        pthread_join(c->ctrl_g, NULL);
        c->ctrl_g_join = 0;
    }
}

int lc_qconn_auth_send(lc_qconn *c, const char *password, uint64_t rx_rate)
{
    if (ngtcp2_conn_open_bidi_stream(c->conn, &c->auth_id, NULL) != 0) {
        say(c, "the node allowed no request stream");
        return -1;
    }

    uint8_t    *at = NULL;
    lc_qstream *areq = arena_open(c, c->auth_id, LC_H3_AUTH_REQ_MAX, LC_QTX_FIN_PENDING, &at);
    long        req = areq == NULL ? -1 : lc_h3_auth_request("hysteria", password, rx_rate, at,
                                                             LC_H3_AUTH_REQ_MAX);
    if (req < 0) {
        if (areq != NULL)
            slot_release(areq);
        say(c, "cannot build the authentication request");
        return -1;
    }
    arena_commit(c, areq, (size_t)req);

    /* The one stream in this exchange that is read as well as written. */
    lc_qstream *auth = slot_of(c, c->auth_id);
    lc_qrx_borrow(&auth->rx, c->auth_rx, sizeof c->auth_rx);

    /* The SETTINGS goroutine exists from here, waiting its turn — see qconn_control_release. */
    __atomic_store_n(&c->ctrl_ready, 0, __ATOMIC_RELAXED);
    c->ctrl_opened = 0;
    c->ctrl_g_live = 0;
    c->ctrl_pending = 1;
    return 0;
}

int lc_qconn_auth_poll(lc_qconn *c, lc_h3_auth_result *result)
{
    lc_qstream *auth = c->auth_id < 0 ? NULL : slot_of(c, c->auth_id);
    if (auth == NULL)
        return -1;

    /* A node that refuses a password does not say so. It hands the request to whatever it
     * masquerades as — hysteria's own word for it — and answers with that site's page, at which
     * point the only difference between "wrong password" and "this is a web server" is that we
     * happen to know what we asked. Tens of kilobytes arriving on this stream is that answer. */
    /* Both of these end the connection the way a refusal does, with closeErrCodeProtocolError: every
     * error from RoundTrip and every status that is not 233 closes with 0x101
     * (vendor/hysteria/core/client/client.go:133-146). They returned before the code was set below,
     * so a node whose masquerade answered with a large page, or with something that did not parse,
     * saw this client leave with 0x100 — an ordinary close. */
    if (auth->rx.over) {
        c->close_code = 0x101u;
        say(c, "the node answered with a web page instead: it did not accept the password");
        return -1;
    }

    int got = lc_h3_auth_response(auth->rx.buf + auth->rx.off, auth->rx.len, result);
    if (got < 0) {
        c->close_code = 0x101u;
        say(c, "the node's answer does not parse as HTTP/3");
        return -1;
    }
    if (got == 0) {
        /* The stream ended — the node's FIN, or its RESET closing the stream — with no whole answer
         * on it: RoundTrip returns an error, and every error from it closes with 0x101
         * (vendor/hysteria/core/client/client.go:132-139). ⚠️ Until 2026-09-27 this kept answering
         * "more is needed", and with no clock on the answer the requests waiting for the connection
         * waited while keep-alives held it open. */
        if (auth->rx_fin) {
            c->close_code = 0x101u;
            say(c, "the node ended the authentication stream without answering it");
            return -1;
        }
        return 0;
    }

    if (result->status == 233) {
        /* A NEW BBR, AS THE REFERENCE INSTALLS ONE HERE. Until this answer hysteria's connection
         * runs on quic-go's own controller; on it, with no send rate of its own to state, it calls
         * UseConfigured (vendor/hysteria/core/client/client.go:147-166), which hands quic-go a
         * sender built from nothing — bbr.NewBbrSender, seeded as at the start
         * (vendor/hysteria/core/internal/congestion/utils.go:37-43) — and quic-go swaps it in with
         * only the RTT statistics carried over (SetCongestionControl,
         * vendor/quic-go/internal/ackhandler/sent_packet_handler.go:1231-1240). Nothing the
         * handshake taught the old one — its bandwidth samples, its round count, its pacing
         * budget — survives, and the data after authentication starts from STARTUP.
         *
         * ngtcp2_cc_hybbr_reset is that: the sender re-initialised with the seed it was given
         * (patches/ngtcp2/0014), the RTT kept in conn_stat. Packets sent before it are unknown to
         * the new sampler and are passed over when acknowledged, as the reference's are.
         *
         * And what it replaces is the reference's too: quic-go's NewReno and its pacer, which this
         * connection has run since its first packet (ngtcp2_hybbr_start_reno at the open; it is
         * cubicSender with `true, // use Reno`,
         * vendor/quic-go/internal/ackhandler/sent_packet_handler.go:153-160 — not Cubic, which
         * this paragraph called it until the port). The reset leaves that mode. */
        ngtcp2_hybbr *cc = ngtcp2_conn_hybbr(c->conn);
        if (cc != NULL)
            ngtcp2_cc_hybbr_reset(&cc->cc, cc->cstat, now_ns());

        /* AND THE STREAM IS CANCELLED, which the reference does on every ACCEPTED authentication —
         * and this client did on none.
         *
         * ⚠️ "Accepted", not "every": `_ = resp.Body.Close()`
         * (vendor/hysteria/core/client/client.go:168) sits after the refusal returns, so a
         * rejected client never reaches it (`if resp.StatusCode != protocol.StatusAuthOK { … return
         * nil, coreErrs.AuthError{…} }`, :141-146). The word used to be "every", which is why this branch reads as a gap when
         * it is a match: the sieve raised exactly that, and the answer is in the early return.
         *
         * hysteria closes the response body the moment it has read the answer — `_ = resp.Body.Close()`
         * (vendor/hysteria/core/client/client.go:168) — and in http3 that is not a local tidy-up:
         * Body.Close calls `r.body.str.CancelRead(quic.StreamErrorCode(ErrCodeRequestCanceled))`
         * (vendor/quic-go/http3/body.go:134-135), which puts a STOP_SENDING frame with HTTP/3's
         * ErrCodeRequestCanceled = 0x10c on the wire.
         *
         * So every real hysteria connection carries one STOP_SENDING on the authentication stream,
         * immediately after the response, and ours carried none — a frame present in every
         * reference connection and absent from every one of ours, inside the first round trip after
         * the handshake.
         *
         * The return value is ignored deliberately: the answer is already in hand, and a node that
         * will not take the frame has not changed what it said. */
        (void)ngtcp2_conn_shutdown_stream_read(c->conn, 0, c->auth_id, 0x10cu);
        return 1;
    }

    /* Worth spelling out, because the node will not: a wrong password is answered with whatever the
     * masquerade is configured to serve, so what arrives here is an ordinary web response and its
     * status is the only thing that distinguishes it. */
    /* AND THE CONNECTION IS MARKED AS A PROTOCOL ERROR ON THE WAY OUT.
     *
     * hysteria keeps two codes and uses them apart: closeErrCodeOK = 0x100 for an ordinary close
     * (vendor/hysteria/core/client/client.go:22, used at :241) and closeErrCodeProtocolError =
     * 0x101 for a refusal — `if resp.StatusCode != protocol.StatusAuthOK { _ =
     * conn.CloseWithError(closeErrCodeProtocolError, "") }` (:23, :141-142). This client sent
     * 0x100 for both, so a node watching its own logs saw every rejected client leave the way a
     * satisfied one does — and the code is in the CONNECTION_CLOSE frame, which is on the wire. */
    c->close_code = 0x101u;
    say(c, "the node did not accept us: it answered with HTTP status %d", result->status);
    return -1;
}

/* And the blocking form, for the one-shot probes.
 *
 * lc-hy, lc-hyfetch and lc-hydns do one exchange and exit; there is nothing else for them to serve
 * while they wait, so a loop of their own is the honest shape. The tunnel does NOT use this — see
 * the two halves above and hy_connect, which has other sessions to keep moving. */
int lc_qconn_authenticate(lc_qconn *c, const char *password, uint64_t rx_rate,
                          lc_h3_auth_result *result, int timeout_ms)
{
    /* A negative timeout would become an enormous unsigned deadline below and turn "give up after
     * a while" into "wait for as long as the node likes". */
    if (timeout_ms < 0 || lc_qconn_auth_send(c, password, rx_rate) != 0)
        return -1;

    /* Against the clock, not against a count of turns. lc_qconn_step returns the moment ngtcp2 has
     * a timer due — which, just after handing it a request to write, is immediately — so a hundred
     * "50 ms" turns can go by in under a millisecond. Counted that way this loop gave up before the
     * node three hops away had finished hearing the question. */
    uint64_t deadline = lc_qconn_now_ms() + (uint64_t)timeout_ms;
    while (lc_qconn_now_ms() < deadline) {
        int rv = lc_qconn_step(c, 50);
        if (rv < 0)
            return -1;
        if (rv == 0) {
            say(c, "the node closed the connection during authentication");
            return -1;
        }
        int done = lc_qconn_auth_poll(c, result);
        if (done != 0)
            return done == 1 ? 0 : -1;
    }

    say(c, "the node did not answer within the time allowed (%zu bytes read on stream %lld)",
        lc_qconn_auth_seen(c), (long long)c->auth_id);
    return -1;
}

/* How many bytes of an answer have arrived, for a caller that wants to say so when it gives up. */
size_t lc_qconn_auth_seen(const lc_qconn *c)
{
    const lc_qstream *auth = c->auth_id < 0 ? NULL : slot_of((lc_qconn *)c, c->auth_id);
    return auth == NULL ? 0u : auth->rx.len;
}

/* ---- proxied TCP connections ------------------------------------------------ */

/* A handle is a slot index and the slot's generation, together.
 *
 * The index alone would be enough to find the slot and not enough to know it is still the same
 * stream: slots are reused, and a caller holding a handle to a connection that has ended would
 * address whatever took its place — a live stream belonging to someone else. Nothing does that
 * today, but only because the one caller is careful, and that is a property of the caller rather
 * than of this. The generation makes a stale handle answer "gone", which is what it is.
 *
 * HANDLE_INDEX_BITS for the index and the rest for the generation; the number itself and why it is
 * what it is are stated once, where it is defined. Repeating it here is what went wrong: this said
 * eight, and four times the streams, from before LC_QTCP_MAX stopped being a memory budget — by
 * which time the constant was nine and the room it left was 511 slots against 260, not fourfold.
 * A stale copy of a number is worse than no copy, because it reads as a second confirmation.
 *
 * Zero is never a valid handle, so a zeroed field cannot address one. */
#define HANDLE_OF(c, s) \
    ((int)((((s)->gen) << HANDLE_INDEX_BITS) | ((s)->idx + 1u)))

static lc_qstream *by_handle(lc_qconn *c, int h)
{
    if (h <= 0)
        return NULL;

    unsigned i = ((unsigned)h & ((1u << HANDLE_INDEX_BITS) - 1u)) - 1u;
    unsigned gen = (unsigned)h >> HANDLE_INDEX_BITS;
    if (i >= c->st_count)
        return NULL;

    lc_qstream *s = st_at(c, i);
    return s->state == LC_QSLOT_OPEN && s->gen == gen ? s : NULL;
}

int lc_qconn_tcp_open(lc_qconn *c, const char *addr)
{
    if (c->closed || c->conn == NULL)
        return -1;

    /* Asked before opening, because ngtcp2 refusing a stream and the node refusing a connection are
     * different failures and only one of them is worth retrying later. */
    if (ngtcp2_conn_get_streams_bidi_left2(c->conn) == 0) {
        /* And says so to the node, once per limit, as quic-go's OpenStream does before it returns
         * StreamLimitReachedError (vendor/quic-go/streams_map_outgoing.go:65-79, :144-160); ngtcp2
         * never writes the frame by itself — patches/ngtcp2/0025. Sent at once, as queueing a
         * control frame wakes quic-go's sender; a failed pass is reported by the next step, as one
         * run from lc_qconn_tcp_read is. */
        if (ngtcp2_conn_lc_streams_blocked_bidi(c->conn) == 0 && flush(c) != 0)
            c->read_flush_failed = 1;
        say(c, "the node allows no more streams just now");
        return -1;
    }

    lc_qrx  rx;
    uint8_t *tx = malloc(LC_QTCP_TX_MIN);
    if (lc_qrx_open(&rx) != 0 || tx == NULL) {
        lc_qrx_close(&rx);
        free(tx);
        say(c, "out of memory for a connection");
        return -1;
    }

    lc_qstream *s = slot_take(c);
    if (s == NULL) {
        lc_qrx_close(&rx);
        free(tx);
        say(c, "already carrying %u streams, or no memory for more", (unsigned)c->st_count);
        return -1;
    }

    int64_t id = -1;
    if (ngtcp2_conn_open_bidi_stream(c->conn, &id, NULL) != 0) {
        lc_qrx_close(&rx);
        free(tx);
        /* slot_release, not memset: a bare wipe takes the generation with it, and the generation is
         * the whole of what makes a stale handle answer "gone". Zeroed here, the next use of this
         * slot starts again at generation one — and a handle issued for its previous life at that
         * generation would address the new stream as if it were its own. */
        slot_release(s);
        say(c, "the node allowed no stream for this connection");
        return -1;
    }

    s->state = LC_QSLOT_OPEN;
    s->owned = 1;
    s->id = id;
    s->rx = rx;
    /* Owned: this one was malloc'd here and the queue frees it with the stream. */
    if (lc_qtx_adopt(&s->tx, tx, LC_QTCP_TX_MIN, 1) != 0) {
        free(tx);
        ngtcp2_conn_shutdown_stream(c->conn, 0, id, 0);
        slot_release(s);
        return -1;
    }
    s->tx.cap = LC_QTCP_SENDBUF;
    s->tx.blk = LC_QTCP_TX_BLK;

    /* The request goes in the send queue ahead of the connection's own first bytes, which is why
     * that first block has to be at least this large — see LC_HY_TCP_REQ_MAX. */
    long n = lc_hy_tcp_request(addr, tx, LC_QTCP_TX_MIN);
    if (n < 0) {
        ngtcp2_conn_shutdown_stream(c->conn, 0, id, 0);
        slot_release(s);
        say(c, "cannot build a request for %s", addr);
        return -1;
    }
    lc_qtx_commit(&s->tx, (size_t)n);
    return HANDLE_OF(c, s);
}

/* Reads the node's reply off the front of the stream once all of it is there. Everything after it
 * is the proxied connection's own bytes and is left where it is. */
static void reply_if_ready(lc_qstream *s)
{
    /* Not on a lost stream: its buffer is a prefix and not the stream, and `why` already carries the
     * account of the loss, which a reply parsed from that prefix would overwrite. */
    if (s->reply_read || s->lost)
        return;

    lc_hy_tcp_reply reply;
    long            n = lc_hy_tcp_response(s->rx.buf + s->rx.off, s->rx.len, &reply);
    if (n == 0)
        return; /* not all here yet */

    s->reply_read = 1;
    if (n < 0) {
        /* ReadTCPResponse failing, not the node saying no: see LC_QTCP_CLOSED. */
        s->reply_bad = 1;
        snprintf(s->why, sizeof s->why, "the node's answer is not a Hysteria2 reply");
        return;
    }

    s->refused = !reply.ok;
    if (s->refused) {
        snprintf(s->why, sizeof s->why, "%s",
                 reply.message[0] != '\0' ? reply.message : "the node refused, without saying why");
        /* The node wrote this string, so it is filtered exactly like the CONNECTION_CLOSE reason —
         * see printable(). "ok" followed by a newline and a line of the node's own invention is a
         * forged log entry, and lc-hyfetch and lc-tunnel print this verbatim. */
        printable(s->why);
    }

    /* What is left is the connection. Moved to the front rather than tracked behind an offset:
     * this happens once per connection and costs one copy of whatever arrived in the same packet
     * as the reply, which is at most a packet's worth. */
    lc_qrx_take(&s->rx, (size_t)n);
}

lc_qtcp_state lc_qconn_tcp_state(lc_qconn *c, int h, const char **why)
{
    if (why != NULL)
        *why = NULL;

    lc_qstream *s = by_handle(c, h);
    if (s == NULL)
        return LC_QTCP_GONE;

    /* Asked before anything else, because nothing below it is trustworthy once a run has been lost:
     * what is in the buffer is a prefix of the stream, and that includes the node's reply if the
     * loss happened before it was read. */
    if (s->lost) {
        if (why != NULL)
            *why = s->why;
        return LC_QTCP_LOST;
    }

    reply_if_ready(s);
    if (!s->reply_read) {
        if (!s->rx_fin)
            return LC_QTCP_OPENING;
        /* The stream ended before the reply was whole — io.ReadFull meeting EOF, or a reset, inside
         * ReadTCPResponse. */
        if (why != NULL)
            *why = "the node ended the stream before its answer";
        return LC_QTCP_CLOSED;
    }
    if (s->reply_bad) {
        if (why != NULL)
            *why = s->why;
        return LC_QTCP_CLOSED;
    }

    if (s->refused) {
        if (why != NULL)
            *why = s->why;
        return LC_QTCP_REFUSED;
    }
    return LC_QTCP_ESTABLISHED;
}

const uint8_t *lc_qconn_tcp_peek(lc_qconn *c, int h, size_t *len)
{
    *len = 0;
    lc_qstream *s = by_handle(c, h);
    if (s == NULL)
        return NULL;
    reply_if_ready(s);
    /* `lost` here as well as in the state: a caller that peeks without asking the state first would
     * otherwise be handed the prefix, which is the very thing this exists to stop. */
    if (!s->reply_read || s->refused || s->lost)
        return NULL;
    *len = s->rx.len;
    /* buf + off, not buf: the unread bytes start at the offset now that taking them no longer
     * compacts the buffer. Every reader of this structure has to add it — see rxbuf.h. */
    return s->rx.buf + s->rx.off;
}

void lc_qconn_tcp_read(lc_qconn *c, int h, size_t n)
{
    lc_qstream *s = by_handle(c, h);
    if (s == NULL || n == 0 || n > s->rx.len)
        return;

    /* The node gets to send that much again: extending the window is what reading means at the
     * protocol level, and a caller that stops reading stops the sender — the only backpressure a
     * QUIC stream has.
     *
     * AND THE UPDATE LEAVES NOW, NOT AT THE NEXT WRITE PASS. quic-go's Read queues it and wakes the
     * sender (onHasStreamControlFrame and onHasConnectionData, vendor/quic-go/connection.go:3034,
     * :3046-3049); here the reads of a burst came one after another before the next write pass, and
     * until 2026-09-26 every update they made due went out as one — on a path with almost no delay
     * the node saw them a whole window apart where the reference's came a quarter apart. What is
     * left is when the reads come, which is the Go scheduler's doing (DIVERGES: G5, see
     * hy_copy_down in lc-tunnel). */
    ngtcp2_conn_extend_max_stream_offset(c->conn, s->id, n);
    ngtcp2_conn_extend_max_offset(c->conn, n);
    if (ngtcp2_conn_lc_window_update_due(c->conn, s->id) && flush(c) != 0)
        c->read_flush_failed = 1;
}

void lc_qconn_tcp_take(lc_qconn *c, int h, size_t n)
{
    lc_qstream *s = by_handle(c, h);
    if (s == NULL || n == 0 || n > s->rx.len)
        return;
    lc_qrx_take(&s->rx, n);
}

int lc_qconn_tcp_eof(lc_qconn *c, int h)
{
    lc_qstream *s = by_handle(c, h);
    return s == NULL || s->rx_fin;
}

size_t lc_qconn_tcp_send(lc_qconn *c, int h, const uint8_t *data, size_t len)
{
    lc_qstream *s = by_handle(c, h);
    if (s == NULL || s->tx_fin != LC_QTX_NONE)
        return 0;

    /* The room at the front is what has been ACKNOWLEDGED, not what ngtcp2 has taken. Taken and
     * unacknowledged is still being pointed at, and sliding it down here is how a retransmit came
     * to carry whatever the connection uploaded next. */
    /* Blocks are allocated as they are needed and freed as they are acknowledged, so there is no
     * growing to do here and no moment to wait for. Taking less than was offered is not a failure:
     * a caller that gets less stops reading from its socket, which is what backpressure is.
     *
     * ⚠️ TWO CEILINGS, AND THE SECOND IS THE ONE THAT BOUNDS THE MACHINE. The stream's own is in
     * s->tx.cap; this is the connection's, and it is what LC_QTCP_SENDBUF_CONN exists to state.
     * Without it the cost would again be per-stream times however many streams are carried, which
     * is the shape the receive side threw out and the send side had kept.
     *
     * Summed rather than counted. A running total kept in step by hand drifts the first time a path
     * frees a block without telling it, and a drifted budget is worse than none: it strangles a
     * healthy connection or stops bounding anything. The walk is over the streams open — as many as the
     * node allows, 1024 on a stock server — once per write of up to READ_CHUNK. */
    /* THE REFERENCE'S SEAM, BEFORE THIS CONNECTION'S OWN CEILING — see LC_QTX_WRITE in conn.h for
     * where it comes from and what it costs.
     *
     * ⚠️ IT IS COUNTED ON THE STREAM, AND IT DOES NOT CLAMP THE WRITE. Both halves of that were
     * learned by measuring, and both are worth stating because each wrong form looked right.
     *
     * Counting on the call — "take at most 32 KB, then wait for the queue to run dry" — is the
     * reference's rule read literally, and it OVERSHOT BY HALF: 2 583 middle-sized datagrams against
     * the reference's 1 652, because the caller here can never offer 32 KB. The staging queue is
     * UP_QUEUE_SIZE, 18 693 bytes, sized for this device's memory and not for io.Copy, so the seam
     * fell at every 18 KB instead of every 32 — and overshooting is as recognisable as undershooting.
     *
     * Clamping each write to the next multiple instead — which does put the seam at 32 KB — COST AN
     * ORDER OF MAGNITUDE OF SPEED: 201, 20.9, 14.4 Mbit/s against 245, 451, 482, with gaps over 5 ms
     * going from 37 to 935 in the same report. 16 MB in units of 32 KB is 512 units, and 512 round
     * trips of 25 ms is 12.8 seconds, which is what the stand measured. The clamp left a fraction of
     * a unit in the staging queue, so the next write was a few bytes, the queue could not be refilled
     * behind it, and the upload advanced one unit per round trip. Do not put it back.
     *
     * What is here instead: writes are passed through whole, and a new one is refused only once
     * LC_QTX_WRITE bytes have been accepted since the stream last ran dry. Same seam, same period,
     * no short writes — which is also what quic-go does when a second Write arrives before the packer
     * has popped s.nextFrame and is appended to it (vendor/quic-go/send_stream.go:272-284).
     *
     * Absolute offsets from the queue itself: everything below `sent` has gone to ngtcp2 and
     * `unsent` is what has not, so the only state kept here is where the current unit began. */
    size_t   unsent = lc_qtx_pending(&s->tx);
    uint64_t written = s->tx.sent + unsent;

    if (s->tx_seam == 0)
        s->tx_seam = written;

    if (written - s->tx_seam >= LC_QTX_WRITE) {
        if (unsent > LC_QTX_CARRY)
            return 0;
        s->tx_seam = written;
    }

    size_t held = 0;
    for (unsigned i = 0; i < c->st_count; i++)
        if (st_at(c, i)->state != LC_QSLOT_FREE)
            held += st_at(c, i)->tx.queued;
    size_t budget = LC_QTCP_SENDBUF_CONN > held ? LC_QTCP_SENDBUF_CONN - held : 0;
    if (len > budget)
        len = budget;

    return lc_qtx_push(&s->tx, data, len);
}

/* ---- proxied UDP ------------------------------------------------------------ */

/* Starts a fresh packet in a session's reassembly buffer, discarding whatever was half-built.
 *
 * Upstream's defragmenter does the same and says why in as many words: it holds one packet at a
 * time, and a fragment of another one throws away what came before. Holding several would mean
 * deciding which to give up on when they stop arriving, and packets that stop arriving are the
 * normal case here. */
/* One message of a session, as the reference's goroutine takes one out of its channel: fed to the
 * packet being put together, and a packet that is whole handed to the client. 1 when the client's
 * socket was full and the writer now waits with that packet. */
static int udp_deliver(lc_qconn *c, lc_qudp *u, const lc_hy_udp *msg)
{
    /* The first piece of a split packet is what the session's reassembly buffer is taken for — see
     * lc_qudp. Without the memory it is dropped, as a UDP packet may be. */
    if (msg->frag_count > 1u && u->r.buf == NULL) {
        u->r.buf = malloc(LC_HY_UDP_MAX);
        if (u->r.buf == NULL)
            return 0;
    }

    /* What is left of this function used to be forty lines of bitmap and offsets. It is in
     * quic/reasm.c now, with the reference lines it follows, because conn.c cannot be loaded by a
     * test and that logic is the worst-fed in the client: every byte of it comes from the node, in
     * whatever order and whatever number of copies the path produced. */
    uint8_t        whole[LC_HY_UDP_MAX];
    const uint8_t *whole_p = NULL;
    long           n = lc_qreasm_feed(&u->r, msg, whole, sizeof whole, &whole_p);
    if (n <= 0)
        return 0; /* held for more, or dropped; neither is a connection failure */

    return c->on_udp(c->on_udp_user, (int)u->id, msg->addr, whole_p, (size_t)n) == 1;
}

/* A message for a session whose writer is waiting: into the channel behind it, as the reference's
 * feed puts it there, and dropped when the channel is full (vendor/hysteria/core/client/udp.go:
 * 125-141). The ring is taken the first time a writer waits. */
static void udp_hold(lc_qudp *u, const uint8_t *data, size_t len)
{
    if (u->hq_n == LC_QUDP_CHAN || len > UINT16_MAX)
        return;
    if (u->hq == NULL) {
        u->hq = calloc(LC_QUDP_CHAN, sizeof *u->hq);
        u->hq_len = calloc(LC_QUDP_CHAN, sizeof *u->hq_len);
        if (u->hq == NULL || u->hq_len == NULL) {
            free(u->hq);
            free(u->hq_len);
            u->hq = NULL;
            u->hq_len = NULL;
            return;
        }
    }
    uint8_t *copy = malloc(len);
    if (copy == NULL)
        return;
    memcpy(copy, data, len);
    unsigned at = (u->hq_head + u->hq_n) % LC_QUDP_CHAN;
    u->hq[at] = copy;
    u->hq_len[at] = (uint16_t)len;
    u->hq_n++;
}

static int recv_datagram_cb(ngtcp2_conn *conn, uint32_t flags, const uint8_t *data, size_t datalen,
                            void *user_data)
{
    (void)conn;
    (void)flags;
    lc_qconn *c = user_data;

    if (c->on_udp == NULL)
        return 0;

    lc_hy_udp msg;
    if (lc_hy_udp_parse(data, datalen, &msg) != 0)
        return 0; /* not something this protocol produces; dropped, as a UDP packet may be */

    lc_qudp *u = lc_qudptab_find(&c->udp, msg.session);
    if (u == NULL)
        return 0; /* a session we have forgotten, or never had */

    /* The writer is waiting for the client's socket: the message goes into the channel behind it,
     * or is dropped when the channel is full, as feed drops it — see lc_qudp. */
    if (u->held) {
        udp_hold(u, data, datalen);
        return 0;
    }

    if (udp_deliver(c, u, &msg))
        u->held = 1;
    return 0;
}

void lc_qconn_udp_resume(lc_qconn *c, int session)
{
    lc_qudp *u = lc_qudptab_find(&c->udp, (uint32_t)session);
    if (u == NULL)
        return;

    u->held = 0;
    while (u->hq_n > 0u) {
        unsigned  i = u->hq_head;
        uint8_t  *d = u->hq[i];
        size_t    len = u->hq_len[i];
        lc_hy_udp msg;
        int       blocked = 0;

        u->hq[i] = NULL;
        u->hq_head = (i + 1u) % LC_QUDP_CHAN;
        u->hq_n--;
        if (lc_hy_udp_parse(d, len, &msg) == 0)
            blocked = udp_deliver(c, u, &msg);
        free(d);
        if (blocked) {
            u->held = 1;
            return;
        }
    }
}

void lc_qconn_udp_handler(lc_qconn *c, lc_qudp_fn fn, void *user)
{
    c->on_udp = fn;
    c->on_udp_user = user;
}

void lc_qconn_refill_handler(lc_qconn *c, lc_qrefill_fn fn, void *user)
{
    c->on_dry = fn;
    c->on_dry_user = user;
}

int lc_qconn_udp_open(lc_qconn *c)
{
    if (c->dq == NULL) {
        c->dq = malloc((size_t)LC_QUDP_QUEUE * LC_QUDP_SLOT);
        if (c->dq == NULL) {
            say(c, "out of memory for the datagram queue");
            return -1;
        }
    }

    lc_qudp *u = lc_qudptab_open(&c->udp);
    if (u == NULL) {
        say(c, "no memory or no session number left for a session");
        return -1;
    }
    return (int)u->id;
}

void lc_qconn_udp_close(lc_qconn *c, int session)
{
    if (session > 0)
        lc_qudptab_close(&c->udp, (uint32_t)session);
}

/* Queues one datagram. Returns 0, or -1 when there is no room — the caller turns that into a drop. */
static int datagram_queue(lc_qconn *c, const lc_hy_udp *msg)
{
    if (c->dq_count >= LC_QUDP_QUEUE)
        return -1;
    unsigned at = (c->dq_head + c->dq_count) % LC_QUDP_QUEUE;
    long     n = lc_hy_udp_put(msg, c->dq + (size_t)at * LC_QUDP_SLOT, LC_QUDP_SLOT);
    if (n < 0)
        return -1;
    c->dq_len[at] = (uint16_t)n;
    c->dq_count++;
    return 0;
}


int lc_qconn_udp_send(lc_qconn *c, int session, const char *addr, const uint8_t *data, size_t len)
{
    lc_qudp *u = session > 0 ? lc_qudptab_find(&c->udp, (uint32_t)session) : NULL;
    if (u == NULL || c->dq == NULL)
        return -1;

    size_t header = lc_hy_udp_header_len(addr);
    if (header >= LC_QUDP_SLOT)
        return -1;
    /* THE HEADER COUNTS TOWARDS THE CEILING, AND GOING OVER IT IS A SILENT DROP, NOT A FAILURE: the
     * reference serialises into a SendBuf of MaxUDPSize, 4096, and Serialize refuses a buffer shorter
     * than m.Size(), which is header plus data (vendor/hysteria/core/internal/protocol/proxy.go:24,
     * :174-176, :178-182) — which SendMessage answers with `// Message larger than buffer, silent drop`
     * and nil
     * (vendor/hysteria/core/client/client.go:334-340), before any fragmenting. ⚠️ Until 2026-09-27
     * only the data counted here, so a payload a header short of 4096 went out in fragments the
     * reference never sends. */
    if (header + len > LC_HY_UDP_MAX)
        return 1;

    lc_hy_udp msg = { .session = u->id, .packet = 0, .frag = 0, .frag_count = 1, .data = data,
                      .len = len };
    /* Truncation is an error, not a shorter address. snprintf reports what it WANTED to write, so a
     * destination longer than the field came back positive and was sent as its own first hundred and
     * some characters — a name the node then resolves to somewhere else entirely, or fails to
     * resolve while the log says we asked for the right place. The header length was already
     * computed from the untruncated string one line above, which is the other half of the same
     * fault: the two would have disagreed about the size of the message. */
    int wrote = snprintf(msg.addr, sizeof msg.addr, "%s", addr);
    if (wrote < 0 || (size_t)wrote >= sizeof msg.addr)
        return -1;

    /* WHAT FITS IS ASKED, NOT ASSUMED.
     *
     * LC_QUDP_PAYLOAD is a constant — what LC_HY_DATAGRAM_MAX leaves once the frame header is off —
     * and the reference does not work that way. udpConn.Send tries the whole packet first and learns the
     * limit from the refusal: quic-go answers DatagramTooLargeError carrying MaxDatagramPayloadSize,
     * computed as min(what the peer's advertised max_datagram_frame_size leaves for a payload, the
     * current packet-size estimate) — vendor/quic-go/connection.go:3084-3093 — and only then does
     * hysteria fragment, against that number (vendor/hysteria/core/client/udp.go:60-71).
     *
     * Both halves of that minimum are knowable here, and they are wrapped in DIFFERENT things: the
     * peer's limit bounds a FRAME and comes from its transport parameters, the path's bounds a
     * PACKET and comes from ngtcp2. So each gets its own overhead — LC_QUDP_FRAME_OVERHEAD and
     * LC_QUDP_PACKET_OVERHEAD, both sized in quic/dgram.h from the reference's own arithmetic, and
     * the minimum itself is lc_qudp_fit in quic/dgram.c — put there so test/qdgram can ask it the
     * reference's numbers, which is the check that was missing while this was wrong.
     *
     * ⚠️ AND THE 57-BYTE WINDOW BELOW WAS NEVER ACTUALLY CLOSED, though the paragraph that used to
     * stand here said it was. The fix it describes was real: `fit` had STARTED at LC_QUDP_PAYLOAD
     * and taken the minimum with the negotiated numbers, so the constant acted as a ceiling while
     * the comment beside it called it a floor. But the same sixty-byte reserve was then subtracted
     * from the negotiated frame size too, so against a node advertising 1200 the peer half came out
     * at 1140 — the very number the ceiling had been giving — while the reference gets 1197. The
     * window the paragraph identified, 57 bytes wide and squarely where ordinary DNS answers and
     * tunnelled QUIC payloads sit, survived the fix that was written to close it and went on cutting
     * those datagrams in two. Fifty-seven is sixty less three, which is the whole story: one guessed
     * constant was doing the work of two measured ones.
     *
     * The path half was over-reserved by twenty-three the same way (sixty against the reference's
     * thirty-seven), and that one only ever cost capacity.
     *
     * `mtu` is the size the PATH is known to take, not the ceiling this client is configured with:
     * ngtcp2_conn_get_path_max_tx_udp_payload_size2 is the minimum of the two, which is 1280 until
     * Path MTU Discovery raises it and up to 1452 after. The reference sizes its datagrams off the
     * same moving number — `estimateMaxPayloadSize(c.mtuDiscoverer.CurrentSize())`
     * (vendor/quic-go/connection.go:2167-2174). Asking for the configured ceiling instead, as this
     * did while PMTUD was switched off, would promise a datagram the path has not been shown to
     * carry.
     *
     * The fallback answers only the case the reference never reaches: a peer that advertised nothing
     * and no connection to ask. The clamp is what keeps the answer inside the queue slot it will be
     * copied into, so that a generous negotiation cannot turn into a refusal on our own floor. */
    uint64_t peer_frame_max = 0;
    size_t   mtu = 0;
    if (c->conn != NULL) {
        const ngtcp2_transport_params *rp = ngtcp2_conn_get_remote_transport_params2(c->conn);
        if (rp != NULL)
            peer_frame_max = rp->max_datagram_frame_size;
        mtu = ngtcp2_conn_get_path_max_tx_udp_payload_size2(c->conn);
    }
    size_t fit = lc_qudp_fit(peer_frame_max, mtu);
    if (header >= fit)
        return -1;

    /* One datagram if it fits, which is the case for anything a name server or a game sends. */
    if (header + len <= fit)
        return datagram_queue(c, &msg);

    /* Otherwise split, with a packet number so that the node knows which pieces belong together.
     * Never zero: zero is what an unfragmented packet carries, and reusing it would make a
     * fragmented packet indistinguishable from a whole one that lost its way. */
    size_t room = fit - header;
    size_t count = (len + room - 1u) / room;
    if (count > LC_QUDP_FRAGS)
        return -1;

    /* Drawn, not counted. udpConn.Send picks `uint16(rand.Intn(0xFFFF)) + 1`
     * (vendor/hysteria/core/client/udp.go:64-66) every time it has to fragment — a fresh number in
     * 1..65535, never zero. This counted upwards instead, which produces the same "never zero" and a
     * different thing on the wire: a sequence anyone watching can continue. The number rides in the
     * clear inside every fragment, so a counter says how many packets this client has ever had to
     * split, and two captures an hour apart say how busy it was in between. */
    /* And drawn as rand.Intn draws: exactly uniform, by rejection (Int31n, GOROOT/src/math/rand/rand.go),
     * which lc_pad_draw is — a plain modulo of 32 bits, as stood here until 2026-09-27, is not. */
    uint32_t pid = 0;
    if (lc_pad_draw(0, 0xFFFFu, &pid) != 0)
        return -1;
    msg.packet = (uint16_t)pid + 1u;
    msg.frag_count = (uint8_t)count;

    /* Room for every piece is checked before any of them is queued: half a packet on the wire is
     * bytes spent on something the node will never put together. */
    if (c->dq_count + count > LC_QUDP_QUEUE)
        return -1;

    for (size_t i = 0; i < count; i++) {
        size_t off = i * room;
        size_t take = len - off < room ? len - off : room;
        msg.frag = (uint8_t)i;
        msg.data = data + off;
        msg.len = take;
        if (datagram_queue(c, &msg) != 0)
            return -1;
    }
    return 0;
}

void lc_qconn_tcp_close(lc_qconn *c, int h)
{
    lc_qstream *s = by_handle(c, h);
    if (s == NULL)
        return;

    /* Ended by saying so, not by going quiet. A stream simply forgotten holds a slot at the node
     * and the window that goes with it until the whole connection times out.
     *
     * The slot stays until the end-of-stream has actually been handed to ngtcp2 — see flush —
     * because there may still be buffered bytes in front of it and they are the ones the far side
     * has been waiting for. Nothing more can be read from it in the meantime: the handle is not
     * valid from here on. */
    s->state = LC_QSLOT_CLOSING;
    if (s->tx_fin == LC_QTX_NONE)
        s->tx_fin = LC_QTX_FIN_PENDING;

    /* AND THE READ SIDE, SAID OUT LOUD, which is the half this used to leave open.
     *
     * The reference does not call quic-go's Close() alone. It wraps every stream in QStream, whose
     * Close() is two statements — `s.Stream.CancelRead(0)` and then `s.Stream.Close()`
     * (vendor/hysteria/core/internal/utils/qstream.go:43-46) — and the comment above the type says
     * why in as many words: "quic.Stream's Close() only closes the write side of the stream, not the
     * read side. And if there is unread data, the stream is not really considered closed until
     * either the data is drained or CancelRead() is called."
     *
     * The same is true here. A FIN says we will send no more; it says nothing about what the node
     * may still send, so a stream closed while a reply was on its way stayed half-open at the node,
     * holding its slot and its flow-control window until the whole connection ended. On a tunnel
     * that opens a stream per connection and closes them constantly, that is a slow leak of exactly
     * the resource the node counts.
     *
     * Zero is the code the reference passes, and it is not the connection close code: hysteria uses
     * 0x100 for CloseWithError on the whole connection (vendor/hysteria/core/client/client.go:22)
     * and plain 0 here.
     * Sending 0x100 on a stream would be a third thing, which nothing upstream does. */
    if (c->conn != NULL && !c->closed && !s->nc_closed)
        (void)ngtcp2_conn_shutdown_stream_read(c->conn, 0, s->id, 0);

    /* Except when there is no connection left to say it on — or when ngtcp2 has already closed the
     * stream, which is the same thing for this one stream.
     *
     * ⚠️ THE SECOND HALF IS A LEAK THAT RAN FOR WEEKS, found 2026-09-22 on the 118 MB Xiaomi 4A. A
     * stream whose data could not be held (`lost`, recv_stream_data_cb) is shut down in both
     * directions at once, and the node answers within a round trip — so stream_close_cb could come
     * BEFORE the session noticed the loss and let the slot go here. It found the slot still OPEN and
     * left it, as it should; but it is the last call ngtcp2 makes about that stream, and the flush
     * path only releases a slot whose FIN it managed to send, which on a reset stream it never does.
     * The slot, and a receive buffer that had just reached four megabytes, stayed for the life of
     * the connection. /proc/PID/maps on the box read three anonymous 4 100 kB regions with no session
     * open, each one a stream the memory reserve had refused; every one of them shrank what the next
     * stream could grow into, so after the first refusal the others followed — downloads cut at
     * 0.4–15 MB of 50, one after another. quic-go has no such state: its stream is completed and
     * dropped by whichever of the two events comes second (receive_stream.go, CancelRead and
     * isNewlyCompleted), and this is that. */
    if (c->conn == NULL || c->closed || s->nc_closed)
        slot_release(s);
}

/* Ask for Gecko. Called before lc_qconn_open, like hopping and for the same reason: what it changes
 * begins with the first packet of the handshake. */
void lc_qconn_gecko_on(lc_qconn *c, unsigned min_packet, unsigned max_packet)
{
    (void)lc_gecko_init(&c->gecko, 1, min_packet, max_packet);
}

void lc_qconn_chrome_off(lc_qconn *c)
{
    c->plain = 1;
}
