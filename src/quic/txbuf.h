/* One stream's send queue, and the rule about who may touch which part of it.
 *
 * ngtcp2 does not copy stream data. ngtcp2_conn_writev_stream keeps the POINTER: its retransmit
 * queue holds ngtcp2_vec, and ngtcp2_vec_copy is a memcpy of those descriptors rather than of the
 * bytes they name, so a packet lost on the way is rebuilt by reading this memory again — possibly
 * long after the write returned. The library says it in as many words — "The caller must keep the
 * portion of data covered by |*pdatalen| bytes in tact until
 * :member:`ngtcp2_callbacks.acked_stream_data_offset` indicates that they are acknowledged by a
 * remote endpoint or the stream is closed" (vendor/ngtcp2/lib/includes/ngtcp2/ngtcp2.h:5247-5250).
 *
 * This file exists because that rule was got wrong, and got wrong invisibly. The tunnel treated
 * "ngtcp2 accepted these bytes" as "the room is free again" and wrote the next batch over them. On
 * a link with no loss nothing happens: the bytes were already serialised into a datagram and sent,
 * and the retransmit queue is never consulted. The symptom needs a lost packet — and then it is a
 * transfer that completes and delivers the wrong bytes, with no error anywhere.
 *
 * ⚠️ AND THE FIRST ANSWER TO THAT RULE WAS A FLAT BUFFER, WHICH OBEYED IT BY STANDING STILL.
 *
 * A single block cannot give room back without moving what is left — a memmove over the region
 * ngtcp2 is pointing into — so both growing and reclaiming had to wait for the buffer to be nobody
 * else's. On a stream that is UPLOADING that moment never comes: from the first write onwards
 * something is always in flight. The buffer therefore filled once, sat full until every byte of it
 * was acknowledged, and only then took more. Stop-and-wait, on a plane where the whole point is to
 * keep the pipe full.
 *
 * ⚠️ WHAT THAT COSTS IS MEASURED, AND THIS QUEUE IS ONLY ONE OF TWO EXPLANATIONS FOR THE NUMBER.
 * Read off the MT7621 router against a stand abroad on 2026-08-27, same box and same hour as its
 * neighbour: Hysteria2 carried 9.8 Mbit/s down and 0.6 UP, where REALITY over TCP on the same box
 * did 18.2 up. At the 175 ms round trip of that measurement 0.6 Mbit/s is about 13 KB in flight.
 *
 * The note written that day called it a congestion window stuck near its initial ten packets, about
 * 14 KB, and the arithmetic alone does not rule that out. But two things point at this queue rather
 * than at the network, and the second of them is a mechanism rather than a coincidence.
 *
 * The first is the size. The plane's own summary read `chunks out 756 (average 7632)` — READ_CHUNK
 * less a header. That is a number from this program, not from the path.
 *
 * The second is the rate, and it closes the loop. The tunnel steps the connection immediately after
 * it moves bytes and only then: `if (moved && hy.up) lc_qconn_step(...)` in cmd/lc-tunnel, there
 * since 2026-08-13 and so already in place when the measurement was taken. A full queue takes
 * nothing, so `moved` is zero, so no step is made and the loop sleeps until ngtcp2's timer — which
 * is exactly the 9.5 turns a second the summary showed. The buffer was putting the loop to sleep on
 * itself: full, therefore idle, therefore drained only once per timer.
 *
 * Removing the freeze removes both. What it does NOT do is prove the number moves, and that stays
 * unclaimed here: the upload has not been re-run since, and the second round trip that would have
 * separated the two explanations was never obtained, because the only other node available does not
 * run this plane.
 *
 * So the memory is now a LIST OF BLOCKS that never move. New bytes go into the last block or into a
 * new one; ngtcp2 is handed as many vectors as the unsent run spans; a block is freed when the
 * acknowledgement passes its END, which is exactly the moment the contract above releases it. Room
 * comes back at the FRONT while the back is still in flight, which is the whole of the fix.
 *
 * ⚠️ AND IT IS WHAT MADE THE CEILING AFFORDABLE, which matters more than the stop-and-wait it
 * ended. While the send buffer was one block per stream, a per-stream ceiling was memory RESERVED,
 * so the budget had to read LC_QTCP_MAX times that ceiling and the ceiling had to stay small. With
 * blocks taken as an upload proves it needs them, the ceiling
 * became memory the client MAY take, and only on streams that actually upload. quic/conn.h now
 * states a connection-wide ceiling on its own instead of multiplying by the stream count, which is
 * the shape the RECEIVE side had already been given and the send side had kept missing.
 *
 * The three regions, in stream offsets rather than indices, because that is what ngtcp2 speaks:
 *
 *     [.., acked)     confirmed; blocks lying entirely below it are freed
 *     [acked, sent)   IN FLIGHT — ngtcp2 is pointing at these. Not to be moved, overwritten,
 *                     reallocated or freed until it says otherwise
 *     [sent, end)     never offered yet; ours entirely
 *
 * It is separate from conn.c for the reason revive.c is separate: the decision was three lines
 * spread through a file that no test can load without the whole vendored QUIC stack, so nothing
 * asked it anything. Here it is arithmetic on a struct, and test/qtx asks.
 *
 * ⚠️ AND THERE IS NO REFERENCE TO CITE FOR ANY OF IT, WHICH IS A BOUNDARY RATHER THAN A HOLE —
 * checked against quic-go on 2026-08-30 rather than assumed, because a file with no pair invites
 * both the sieve and the next reader to call the absence a divergence.
 *
 * The reference has no send buffer at all. `sendStream.dataForWriting` is the CALLER'S slice, held
 * only for as long as Write() blocks the goroutine that made the call, and the bytes are COPIED out
 * of it into stream frames — `copy(f.Data, s.dataForWriting)`
 * (vendor/quic-go/send_stream.go:536-543) — which the sent-packet handler then keeps for retransmission (StreamFrames in
 * vendor/quic-go/internal/ackhandler/packet.go:18). So the caller's memory is free the moment Write
 * returns, and nothing in that design has to stay still.
 *
 * Two properties of ours make it necessary, and neither has an opposite number over there. ngtcp2
 * does NOT copy — the contract quoted at the top of this file is the whole difference — so the
 * bytes must outlive the call that handed them over. And there is no goroutine to block: where the
 * reference parks an upload in a blocked Write, this program has an event loop that must take the
 * bytes off a socket now and hold them. The same boundary is already written down for net/loop.h,
 * which has no counterpart because the reference's event loop is its runtime. */

#ifndef LC_QTXBUF_H
#define LC_QTXBUF_H

#include <stddef.h>
#include <stdint.h>

/* One immovable run of bytes. `off` is the stream offset of buf[0]; `len` is how much of `cap` has
 * been written. `owned` is zero for memory this queue did not allocate — the connection-wide arena
 * hands out regions of its own, and freeing one of those would be a double free. */
typedef struct lc_qtx_blk {
    struct lc_qtx_blk *next;
    uint64_t           off;
    size_t             cap;
    size_t             len;
    uint8_t           *buf;
    int                owned;
} lc_qtx_blk;

typedef struct {
    lc_qtx_blk *head, *tail;
    uint64_t    sent;    /* absolute: everything below this has been handed to ngtcp2 */
    uint64_t    acked;   /* absolute: everything below this is released */
    size_t      queued;  /* bytes held across every block, freed ones excluded */
    size_t      cap;     /* the most `queued` may reach */
    size_t      blk;     /* size of a block this queue allocates for itself */
    /* Where lc_qtx_run starts: no block before this one has a byte left to offer. NULL means the
     * head. Only ever moved forward by lc_qtx_run, and put back to the head by whatever frees
     * blocks — see lc_qtx_run for what it cost to walk from the head every time. */
    lc_qtx_blk *from;
} lc_qtx;

/* Whether ngtcp2 may still read this queue. True from the moment it accepts a byte until that byte
 * is acknowledged — the window in which none of it is ours to touch. */
int lc_qtx_inflight(const lc_qtx *t);

/* How much has been written and not yet offered. Zero means there is nothing to send. */
size_t lc_qtx_pending(const lc_qtx *t);

/* The unsent bytes as contiguous runs, `i` counting from zero. Returns 0 when `i` is past the last
 * run. A caller filling an ngtcp2_vec array walks it until it returns 0 or the array is full —
 * offering fewer vectors than exist is always safe, since the rest is offered on the next turn. */
int lc_qtx_run(lc_qtx *t, unsigned i, uint8_t **at, size_t *len);

/* How many runs a caller offers at once. Four covers a full queue at any block size the tree uses,
 * and offering fewer is safe — but offering ONE is not merely slower. ngtcp2 fills a packet from
 * the vectors it is given, so a single run would end every packet at a block boundary, and our
 * block size would become a rhythm in the packet lengths on the wire. That is a property of this
 * program's memory layout, and nothing about the reference has it. */
#define LC_QTX_VECS 4u

/* ngtcp2 accepted `n` bytes from the pending region. */
void lc_qtx_sent(lc_qtx *t, size_t n);

/* ngtcp2 reports that this stream's bytes up to `end` — an absolute stream offset — will never need
 * sending again. Sequential and without overlap per stream, so only the far end matters. Bytes past
 * what was handed over are ignored: a bare end-of-stream is acknowledged at the offset after the
 * last byte, and the end-of-stream is not a byte in here. Frees whatever blocks that releases. */
void lc_qtx_ack(lc_qtx *t, uint64_t end);

/* Room for new bytes. Unlike the flat buffer this replaced, it does not go to zero because
 * something is in flight: blocks below `acked` are already gone. */
size_t lc_qtx_room(const lc_qtx *t);

/* Copies up to `n` bytes in, allocating blocks as needed, and returns how many it took — less than
 * `n` when the ceiling or the allocator says so, which is the backpressure this queue exists to
 * apply. */
size_t lc_qtx_push(lc_qtx *t, const uint8_t *data, size_t n);

/* Takes over memory the caller already has as this queue's first block. `owned` says whether the
 * queue may free it. For the two callers that build a message in place: the arena, which lends a
 * region it owns itself, and the Hysteria2 request, which allocates one and hands it over. */
int lc_qtx_adopt(lc_qtx *t, uint8_t *buf, size_t cap, int owned);

/* Says how much of an adopted block was actually written. */
void lc_qtx_commit(lc_qtx *t, size_t len);

/* Gives up the bytes that were never offered, for a stream ngtcp2 says is closed for writing. Only
 * the tail past `sent`: what it accepted is still its to look at, closed or not, until the stream
 * is gone entirely. */
void lc_qtx_abandon(lc_qtx *t);

/* Releases every block this queue owns. Called where the stream is finished with — after which
 * ngtcp2 is not pointing at any of it, because the stream is gone. */
void lc_qtx_free(lc_qtx *t);

#endif /* LC_QTXBUF_H */
