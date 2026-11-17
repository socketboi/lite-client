#include "quic/txbuf.h"


#include <stdlib.h>
#include <string.h>

/* ⚠️ THIS FILE HAS NO COUNTERPART IN vendor/, AND THAT IS A BOUNDARY RATHER THAN A DEBT — said here
 * because the coverage report once listed it as the largest protocol file nothing had ever cited,
 * and a reader who goes looking for its reference will not find one either.
 *
 * The whole file exists to satisfy a contract that only ngtcp2 has. ngtcp2 does not copy stream
 * data: `ngtcp2_conn_writev_stream` keeps the caller's POINTER, and the caller must keep those bytes
 * intact until the acked_stream_data_offset callback says they arrived
 * (vendor/ngtcp2/lib/includes/ngtcp2/ngtcp2.h:5247-5250, quoted at length in txbuf.h). A queue that
 * hands out addresses and reclaims them by acknowledgement is what that sentence requires.
 *
 * The reference stack does the opposite and therefore needs nothing of the kind. quic-go COPIES the
 * caller's bytes into the frame's own buffer — `copy(f.Data, s.dataForWriting)`
 * (vendor/quic-go/send_stream.go:534-548) — and keeps the frames themselves for retransmission in
 * `retransmissionQueue []*wire.StreamFrame` (vendor/quic-go/send_stream.go:35). By the time Write
 * returns, the caller's memory is free. There is no ownership question to get wrong, so there is no
 * code answering it, so there is nothing here to compare against.
 *
 * What that means for the sieve, which is why this paragraph is worth its lines: a pass looking for
 * a reference function to hold this file to will find only the two above, and they are the CONTRACT
 * and its absence — not an implementation. The thing that checks this file is test/qtx, which holds
 * the accounting to the rule (nothing reclaimed before its ack, nothing handed out twice), and the
 * case that fails on a return to a flat buffer is named there.
 *
 * The two citations are here rather than only in the header on purpose: pairs are built per FILE,
 * and a .c with none is a file the forward pass never opens. */

/* One past the last byte a block holds. */
static uint64_t blk_end(const lc_qtx_blk *b)
{
    return b->off + (uint64_t)b->len;
}

/* Where the next byte written would land. With blocks present it follows the last one; with none it
 * is wherever the stream got to, which after the front has been freed is `acked`. */
static uint64_t next_off(const lc_qtx *t)
{
    return t->tail != NULL ? blk_end(t->tail) : t->acked;
}

int lc_qtx_inflight(const lc_qtx *t)
{
    return t->sent > t->acked;
}

size_t lc_qtx_pending(const lc_qtx *t)
{
    if (t->tail == NULL)
        return 0;
    uint64_t end = blk_end(t->tail);
    return end > t->sent ? (size_t)(end - t->sent) : 0;
}

/* ⚠️ FROM `from`, NOT FROM THE HEAD, and the head is where this used to start on every call.
 *
 * The head is the oldest block ngtcp2 may still read, so everything between it and the first unsent
 * byte is the data in flight — about two megabytes on a 25 ms path at 300 Mbit/s, which at four
 * kilobytes a block is several hundred blocks, each a separate allocation. The write loop asks for
 * up to four runs per packet, and each ask walked all of them again. Timed on the one-way stand
 * (2026-09-21): 10.6 us per packet in this walk, against 3.7 for ngtcp2 to build and encrypt the
 * packet itself — two thirds of what a packet cost to pack, spent finding where the unsent bytes
 * begin. A pointer that remembers it makes the walk start where the answer is.
 *
 * And on the router, where it matters more: Xiaomi 4A (MT7621) against the live node, one binary at
 * a time, three pairs of blocks of four 5 MB uploads, alternated — 2.55 · 2.20 · 2.63 MB/s before,
 * 2.75 · 2.77 · 2.78 after, with the process's CPU per 20 MB going 982 · 1021 · 931 ticks to
 * 909 · 893 · 895. Faster on every pair, and cheaper per byte.
 *
 * It never passes the last block, so a queue with everything offered keeps its place instead of
 * falling back to the head, and it is only ever moved past a block whose every byte is below
 * `sent` — which only grows — so a block it has passed never has anything to offer again. */
int lc_qtx_run(lc_qtx *t, unsigned i, uint8_t **at, size_t *len)
{
    lc_qtx_blk *b = t->from != NULL ? t->from : t->head;
    while (b != NULL && b->next != NULL && blk_end(b) <= t->sent)
        b = b->next;
    t->from = b;

    unsigned n = 0;
    for (; b != NULL; b = b->next) {
        uint64_t end = blk_end(b);
        if (end <= t->sent)
            continue; /* handed over in full already */
        uint64_t from = t->sent > b->off ? t->sent : b->off;
        if (n == i) {
            *at = b->buf + (size_t)(from - b->off);
            *len = (size_t)(end - from);
            return 1;
        }
        n++;
    }
    return 0;
}

void lc_qtx_sent(lc_qtx *t, size_t n)
{
    size_t room = lc_qtx_pending(t);
    t->sent += n < room ? (uint64_t)n : (uint64_t)room;
}

void lc_qtx_ack(lc_qtx *t, uint64_t end)
{
    /* Never past what was handed over: a bare end-of-stream is acknowledged at the offset after the
     * last byte, and the end-of-stream is not a byte in here. */
    if (end > t->sent)
        end = t->sent;
    if (end <= t->acked)
        return;
    t->acked = end;

    /* ⚠️ AND THIS IS WHERE THE ROOM COMES BACK, WITH NOTHING MOVED AND NOTHING WAITED FOR. A block
     * whose last byte is below `acked` is released by the contract quoted in the header — ngtcp2
     * will never read it again — so it is freed while every block after it may still be in flight.
     * The flat buffer this replaced could not do that: giving room back meant sliding the rest
     * down, over the very region ngtcp2 was pointing into, so it had to wait for the whole buffer
     * to be idle and on an uploading stream it never was. */
    while (t->head != NULL && blk_end(t->head) <= t->acked) {
        lc_qtx_blk *gone = t->head;
        t->head = gone->next;
        if (t->head == NULL)
            t->tail = NULL;
        /* The place lc_qtx_run keeps may be this very block: every byte of it is below `sent`. */
        if (t->from == gone)
            t->from = NULL;
        t->queued -= gone->len;
        if (gone->owned)
            free(gone->buf);
        free(gone);
    }
}

size_t lc_qtx_room(const lc_qtx *t)
{
    return t->cap > t->queued ? t->cap - t->queued : 0;
}

size_t lc_qtx_push(lc_qtx *t, const uint8_t *data, size_t n)
{
    size_t room = lc_qtx_room(t);
    if (n > room)
        n = room;

    size_t done = 0;
    while (done < n) {
        if (t->tail == NULL || t->tail->len == t->tail->cap) {
            /* A queue told nothing about its block size takes nothing. Refusing is the honest
             * answer: the caller is told it took less, which is backpressure, and a made-up size
             * would put the router's memory on a number nobody chose. */
            if (t->blk == 0)
                break;
            lc_qtx_blk *b = malloc(sizeof *b);
            if (b == NULL)
                break;
            b->buf = malloc(t->blk);
            if (b->buf == NULL) {
                free(b);
                break;
            }
            b->next = NULL;
            b->off = next_off(t);
            b->cap = t->blk;
            b->len = 0;
            b->owned = 1;
            if (t->tail != NULL)
                t->tail->next = b;
            else
                t->head = b;
            t->tail = b;
        }
        size_t take = t->tail->cap - t->tail->len;
        if (take > n - done)
            take = n - done;
        memcpy(t->tail->buf + t->tail->len, data + done, take);
        t->tail->len += take;
        t->queued += take;
        done += take;
    }
    return done;
}

int lc_qtx_adopt(lc_qtx *t, uint8_t *buf, size_t cap, int owned)
{
    lc_qtx_blk *b = malloc(sizeof *b);
    if (b == NULL)
        return -1;
    b->next = NULL;
    b->off = next_off(t);
    b->buf = buf;
    b->cap = cap;
    b->len = 0;
    b->owned = owned;
    if (t->tail != NULL)
        t->tail->next = b;
    else
        t->head = b;
    t->tail = b;
    return 0;
}

void lc_qtx_commit(lc_qtx *t, size_t len)
{
    if (t->tail == NULL)
        return;
    if (len > t->tail->cap)
        len = t->tail->cap;
    t->queued += len - t->tail->len;
    t->tail->len = len;
}

void lc_qtx_abandon(lc_qtx *t)
{
    lc_qtx_blk *b = t->head;
    lc_qtx_blk *keep_tail = NULL;
    while (b != NULL && blk_end(b) <= t->sent) {
        keep_tail = b;
        b = b->next;
    }
    /* `b` is the first block holding anything never offered. Its front may still be in flight, in
     * which case only its tail goes. */
    if (b != NULL && b->off < t->sent) {
        size_t keep = (size_t)(t->sent - b->off);
        t->queued -= b->len - keep;
        b->len = keep;
        keep_tail = b;
        b = b->next;
    }
    while (b != NULL) {
        lc_qtx_blk *gone = b;
        b = b->next;
        t->queued -= gone->len;
        if (gone->owned)
            free(gone->buf);
        free(gone);
    }
    if (keep_tail != NULL)
        keep_tail->next = NULL;
    else
        t->head = NULL;
    t->tail = keep_tail;
    /* Back to the head: the place lc_qtx_run kept may have been one of the blocks just freed. */
    t->from = NULL;
}

void lc_qtx_free(lc_qtx *t)
{
    lc_qtx_blk *b = t->head;
    while (b != NULL) {
        lc_qtx_blk *gone = b;
        b = b->next;
        if (gone->owned)
            free(gone->buf);
        free(gone);
    }
    t->head = NULL;
    t->tail = NULL;
    t->from = NULL;
    t->queued = 0;
}
