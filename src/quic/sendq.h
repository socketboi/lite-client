#ifndef LC_SENDQ_H
#define LC_SENDQ_H

#include "quic/gecko.h"
#include "quic/obfs.h"

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

/* The send queue, which is the other half of the reference's connection algorithm.
 *
 * quic-go does not write datagrams from the goroutine that packs them. Send puts a batch on a
 * channel of eight and returns — "guaranteed to not block" (vendor/quic-go/send_queue.go:47-64,
 * sendQueueCapacity = 8 at :35) — and a goroutine of its own takes batches off that channel and
 * writes them (Run, :78-108). So while one batch is inside sendmsg, the next is already being
 * packed, and when the write returns the next batch is waiting: several leave the kernel with
 * nothing between them.
 *
 * WHY IT WAS LOOKED FOR, 2026-09-21 on the one-way stand (test/hystand/loss.sh, SINK=1). This
 * client packed and sent on one thread, one after the other: a sendmsg of fourteen datagrams took
 * 33 microseconds on average, and the next fourteen were encrypted and framed only after it. Our
 * datagrams arrived in runs of exactly fourteen, 90 % of them back to back, the reference's in runs
 * of 48 and 100, 97 %.
 *
 * ⚠️ AND WHAT IT DID NOT DO: move that. With the queue in, the stand still reads 89-90 % against the
 * old binary's 86-91 in interleaved runs, because there a batch takes 218 us to pack and 32-36 to
 * send — the writer waits for the packer, and there is nothing to overlap. The packing was blamed on
 * the AEAD for an hour; clocks on the whole iteration found two thirds of it in lc_qtx_run walking
 * the blocks in flight from the head, fixed in quic/txbuf.c, after which a batch packs in 54 us and
 * the runs of fourteen are gone. loss.sh has the numbers. Do not read this queue as the fix for the
 * density; it is not one on any machine measured.
 *
 * WHAT IT DID DO, on the router, where both sides run ChaCha20 in plain code and a sendmsg is the
 * kernel's whole UDP path on a slow core: upload went up. Xiaomi 4A (MT7621) against the live node,
 * one binary at a time — the node allows one session per account, so two side by side keep
 * replacing each other — three pairs of blocks of four 5 MB uploads, alternated:
 *
 *                  MB/s per block          CPU ticks per 20 MB
 *   one thread     2.17  2.33  2.11        819   814   838
 *   with queue     2.45  2.46  2.56        1005  940   955
 *
 * +13 % on every pair, for +17 % CPU per byte spread over two threads: the send path runs on the
 * second core while the first packs, which is the reference's arrangement doing what it is for.
 * Downloads, where this queue carries acknowledgements only, read 4.5-4.7 MB/s either way.
 *
 * ⚠️ AND WHAT IS LEFT OF THE DENSITY GAP IS THIS THREAD WAKING UP, measured 2026-09-23. Uploads through
 * the stand's relay on the AX3000T, against the live node, Salamander on — so no GSO and no ECN on
 * either side (oob_conn in quic/conn.c), one sendmsg per datagram for both: 66-71 % of our datagrams
 * arrive back to back against the reference's 73-76 %, at the same speed. Clocks on every gap of
 * 50 us or more between two entries this writer sent, about 9 000 such gaps in 36 000:
 *
 *   within one pass        6 100-6 700   the writer woke 155-172 us after the entry was committed;
 *                                        the owner took ~95 us per datagram, and datagrams sent
 *                                        back to back leave 13-14 us apart
 *   after a pass yielded   ~2 200        108-117 us of it waking
 *   after a full queue     ~650          141-163 us
 *
 * The owner packs slower than this thread sends, so this thread empties the queue, parks on the
 * condition variable and has to be woken for the next datagram — and a parked thread on that box
 * takes 150 us to run again. The reference's writer is a goroutine: readied onto its sender's own
 * processor, run the moment the sender blocks, or taken by a scheduler thread that is still spinning
 * for work. Three answers were measured and none is in the tree:
 *
 *   - the OWNER SENDS when the writer is idle: on the one-way stand 92-93 % against 94-95 % before —
 *     worse, because it serialises packing and sending again, the thing this queue exists to undo;
 *   - the owner sends what is left BEFORE IT BLOCKS, Go's runnext: the owner was asleep in the loop
 *     for only 282-366 of those ~9 000 gaps, so it could reach three or four in a hundred;
 *   - the reference's AEAD instead of mbedTLS's (src/tls/aead.h, the end): a packet costs 10.6 us
 *     instead of 18, and the share moved from 66-70 % to 67-71 %.
 *
 * What closes it is this thread staying awake for a while after the queue empties, as Go's
 * scheduler threads do before they sleep — a core kept busy between datagrams for a duration this
 * client chooses. ⛔ THE MAINTAINER TOOK THAT ON 2026-09-23, knowing the duration is ours: 150 us, about
 * what the wake costs on the AX3000T (LC_SENDQ_SPIN_NS in quic/sendq.c). Measured the same day,
 * one client at a time, three rounds each:
 *
 *                              back to back          CPU during the upload
 *   AX3000T  asleep            68 · 70 · 70 %         57-70 %
 *            awake 150 us      74 · 72 · 73 %         64-76 %
 *            reference         74 · 75 · 74 %         61-74 %
 *   stand    asleep            94 · 94 · 95 %
 *            awake 150 us      95 · 95 · 95 %  (the reference 96 · 96 · 96)
 *   MT7621   asleep / awake    same speed; 7-21 % more CPU awake; the share back to back is 0-1 %
 *                              for both through a relay on that CPU, so the shape there could not
 *                              be told apart
 *
 * Speed did not move anywhere. On the AX3000T the gap to the reference went from 4-6 points to 1-2.
 *
 * So this is that queue, and it is written to the reference's rules:
 *
 *   - eight entries WAITING, and an entry is what the reference's is: one write's worth of
 *     datagrams — a GSO batch, or a lone datagram, or here also the frames of one Gecko packet,
 *     which the reference sends through the same queue one Write at a time. The one being written
 *     is not among the eight: Run takes it off the channel before it calls Write (`e := <-h.queue`,
 *     send_queue.go:90-91), so a full queue is eight waiting plus one in the writer's hands, and
 *     WouldBlock counts only the eight (:70-72);
 *   - the owner asks whether it is full at every batch boundary, which is where quic-go asks —
 *     before triggerSending (vendor/quic-go/connection.go:730-744) and after every Send
 *     (vendor/quic-go/connection.go:2611-2613 and vendor/quic-go/connection.go:2679-2681) — and
 *     stops when it is;
 *   - the owner is woken by a freed entry ONLY when it stopped on a full queue. quic-go's run loop
 *     selects on Available() only after WouldBlock said yes (vendor/quic-go/connection.go:664,
 *     vendor/quic-go/connection.go:729-736) and sets it back to nil otherwise
 *     (vendor/quic-go/connection.go:746-753); a writer that woke it after every write would add a
 *     send cycle per batch that the reference does not have;
 *   - the writer waits for the socket when the kernel would block, as a goroutine inside Write
 *     does, so a datagram is sent late rather than not at all;
 *   - a message-size error is a lost packet and nothing more (isSendMsgSizeErr,
 *     vendor/quic-go/send_queue.go:91-99), and any other error ends the connection
 *     (vendor/quic-go/connection.go:602-606);
 *   - a batch the kernel refuses AS a batch is sent again one datagram at a time and batching is
 *     off from then on (vendor/quic-go/send_conn.go:73-93) — the writer does the resend, the owner
 *     reads the flag;
 *   - closing sends everything queued first (vendor/quic-go/send_queue.go:82-90) and only then the
 *     CONNECTION_CLOSE, which the reference writes itself rather than queueing
 *     (vendor/quic-go/connection.go:761, then vendor/quic-go/connection.go:2897) — see
 *     lc_sendq_close.
 *
 * ⛔ WHILE THE QUEUE RUNS THERE IS NO SYNCHRONOUS PATH BESIDE IT. A connection whose writer cannot
 * start does not open; every datagram, the handshake's included, goes through the queue, because a
 * send that bypassed it could overtake what is already waiting and put packets on the wire out of
 * order. The one datagram that does not is the close, and it is written after the writer has
 * finished, when there is nothing left to overtake. */

/* sendQueueCapacity (vendor/quic-go/send_queue.go:35): how many entries may WAIT. */
#define LC_SENDQ_CAP 8u

/* The slots behind them: the eight, the one the writer is sending, and one more that only the
 * handshake can need. A packet that cannot join a batch (a long header) arriving behind a batch
 * that is still open needs two entries at once — the batch it closes and itself — and the
 * reference never meets that case, because its packer builds a batch only from short-header
 * packets and sends coalesced handshake datagrams on their own path
 * (vendor/quic-go/connection.go:2572-2590).
 * A packet whose marking changes mid-batch needs the same two. The slot is room, not queue:
 * WouldBlock is still answered against LC_SENDQ_CAP, and the bound is argued at the check in
 * quic/conn.c's write loop. */
#define LC_SENDQ_SLOTS (LC_SENDQ_CAP + 2u)

/* How many datagrams one entry can hold: a full GSO batch (LC_GSO_BATCH, asserted equal in
 * quic/conn.c) or all the frames of one Gecko packet, whichever is more. */
#define LC_SENDQ_DGRAMS 14u
#define LC_SENDQ_DGRAM_MAX (LC_GECKO_BUFFER + LC_OBFS_SALT)

/* Where the datagrams go: the socket and the node's address. One for the queue, read when an entry is
 * WRITTEN and not when it was queued — see lc_sendq_set_dest. */
typedef struct {
    int                     fd;
    struct sockaddr_storage peer;
    socklen_t               peer_len;
    int                     family;
} lc_sendq_dest;

typedef struct {
    uint8_t       buf[LC_SENDQ_DGRAMS * LC_SENDQ_DGRAM_MAX];
    uint16_t      len[LC_SENDQ_DGRAMS]; /* each datagram, in order, contiguous in buf */
    unsigned      n;
    uint16_t      seg;                  /* nonzero: a GSO batch of datagrams this long */
    /* Per datagram, because the frames of one Gecko packet each carry their own — a batch's are
     * all the same, since a batch takes one cmsg, and the writer uses the first. */
    uint8_t       ecn[LC_SENDQ_DGRAMS];
} lc_sendq_entry;

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t  cv;     /* the writer waits for work on it */
    pthread_t       thread;
    int             started;

    lc_sendq_entry  e[LC_SENDQ_SLOTS];
    /* `count` is every slot in use, the one being written included; `writing` is 1 while the
     * writer has one in hand. What waits is count - writing, and that is what WouldBlock asks. */
    unsigned        head, count, writing;

    /* Where datagrams go now, and where they go once the write in progress is over — the hop
     * conn's currentConn and a hop waiting on its lock (see lc_sendq_set_dest). Under `lock`. */
    lc_sendq_dest   cur, next;
    int             moving;

    int             stop;
    int             err;          /* the first error that ended the connection, 0 if none */
    int             gso_failed;   /* set once, by the writer: stop building batches */
    int             wrote_first;  /* EPERM on the first send is retried once, send_conn.go:95-101 */

    /* Set by the owner when it stops on a full queue, cleared by the writer when it frees the entry
     * that ends that: then, and only then, one byte goes down the pipe. */
    int             blocked;

    /* Bumped by every commit, and the one field touched without the lock: the writer reads it while
     * it waits awake (LC_SENDQ_SPIN_NS in quic/sendq.c), so both sides use __atomic on it. */
    unsigned        kick;
    int             wake_rd, wake_wr;
} lc_sendq;

/* Starts the writer, sending to `first`. -1 if it cannot: no pipe, no thread. */
int lc_sendq_start(lc_sendq *q, const lc_sendq_dest *first);

/* Sends from now on to `d` — a port hop. Waits for a write in progress and for nothing else: every
 * entry still queued goes to the new destination, as every packet quic-go has yet to write goes
 * through udpHopPacketConn's currentConn at the moment it is written, and hop() takes the lock a
 * WriteTo in progress holds (vendor/hysteria/extras/transport/udphop/conn.go:172-197, :245-253).
 * ⚠️ UNTIL 2026-09-27 each entry carried the destination it was queued with, and the hop waited
 * for the whole queue to drain. */
void lc_sendq_set_dest(lc_sendq *q, const lc_sendq_dest *d);

/* Closes the queue the way quic-go closes a connection: first the queue, which sends everything
 * already in it and stops its writer (`c.sendQueue.Close() // close the send queue before sending
 * the CONNECTION_CLOSE`, vendor/quic-go/connection.go:761; Run drains before it returns,
 * vendor/quic-go/send_queue.go:82-90), and only then `last`, written by the closer itself and not
 * through the queue (sendConnectionClose ends in `c.conn.Write`,
 * vendor/quic-go/connection.go:2897), to the destination the queue holds now. `last` may be NULL:
 * a silent close sends nothing of its own.
 *
 * BOUNDED, where the reference is not: its closing goroutine waits in Write for as long as the socket
 * stays full, and so would ours — but ours is the thread every session of the process runs on. Once
 * told to stop, a socket that stays full for LC_SENDQ_POLL_MS ends the writing: what was still queued
 * is dropped, and so is `last`, with the node's idle timer as the backstop the close already accepts.
 * Idempotent. */
void lc_sendq_close(lc_sendq *q, const uint8_t *last, size_t len, unsigned ecn);

/* WouldBlock: eight entries waiting. When it answers yes it also arms the wake, in the same breath,
 * so that the entry freed next is the one that wakes the owner — the owner stops the moment it
 * has asked, as quic-go's run loop does. */
int lc_sendq_would_block(lc_sendq *q);

/* Nothing queued and nothing being written. */
int lc_sendq_empty(lc_sendq *q);

/* The next entry to fill, cleared, or NULL when the queue is full. The owner fills it and then
 * makes it visible with lc_sendq_commit; the writer never looks at it before that. */
lc_sendq_entry *lc_sendq_reserve(lc_sendq *q);
void            lc_sendq_commit(lc_sendq *q);

/* The first error that ended the connection, or 0; and whether batching has been turned off. */
int lc_sendq_error(lc_sendq *q);
int lc_sendq_gso_failed(lc_sendq *q);

/* Readable once an owner that stopped on a full queue can go on, and at no other time. The owner
 * empties it with lc_sendq_wake_drain. */
int  lc_sendq_wake_fd(const lc_sendq *q);
void lc_sendq_wake_drain(lc_sendq *q);

#endif
