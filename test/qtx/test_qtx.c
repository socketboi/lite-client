/* The send queue's three regions, and the one of them that is not ours.
 *
 * ngtcp2 keeps stream data by pointer until it is acknowledged. The tunnel used to hand bytes over
 * and immediately call the room free, which on a link with no loss is invisible — the bytes were
 * already in a datagram and gone — and on a link with loss is a retransmit carrying whatever was
 * written next. A transfer that completes and delivers the wrong bytes, with no error anywhere.
 *
 * conn.c cannot be loaded by a test without the whole vendored QUIC stack, so for as long as this
 * lived there, nothing asked it anything: every one of the 472 checks passed with the rule broken.
 * Which is why it lives in txbuf.c now, and why these cases are about the accounting rather than
 * about ngtcp2 — the same split, and for the same reason, as revive.c.
 *
 * ⚠️ AND THE CASE THIS FILE EXISTS FOR NOW IS THE ONE THE FLAT BUFFER COULD NOT PASS: room coming
 * back while bytes are still in flight. Obeying the rule by standing still is easy and is what the
 * first version did — it waited for the whole buffer to be idle, and on an uploading stream that
 * moment never came, so the queue filled once per round trip and sat full. The list of blocks obeys
 * the same rule by never moving anything, which lets the front be released while the back is still
 * ngtcp2's. The cases below are written so that a return to the flat buffer fails them. */

#include "quic/txbuf.c"

#include <stdio.h>
#include <string.h>

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

/* Everything the queue holds that has not been offered yet, concatenated across blocks. */
static size_t drain_runs(lc_qtx *t, uint8_t *out, size_t cap)
{
    size_t   n = 0;
    uint8_t *at;
    size_t   len;
    for (unsigned i = 0; lc_qtx_run(t, i, &at, &len); i++) {
        if (n + len > cap)
            return n;
        memcpy(out + n, at, len);
        n += len;
    }
    return n;
}

int main(void)
{
    printf("the send queue keeps what is in flight\n");

    /* ⚠️ THE FIX ITSELF. Four blocks of eight bytes: fill the ceiling, hand it all to ngtcp2, then
     * acknowledge only the FIRST block. The flat buffer gave back nothing here — it needed the
     * whole buffer idle — and this queue gives back exactly one block while the other three are
     * still being pointed at. */
    {
        lc_qtx t;
        memset(&t, 0, sizeof t);
        t.cap = 32;
        t.blk = 8;

        expect(lc_qtx_push(&t, (const uint8_t *)"AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD", 32) == 32,
               "the ceiling is taken in one push, across as many blocks as it needs");
        expect(lc_qtx_room(&t) == 0, "and then there is no room");
        lc_qtx_sent(&t, 32);
        expect(lc_qtx_inflight(&t) && lc_qtx_pending(&t) == 0,
               "all of it is in flight and none of it is pending");

        lc_qtx_ack(&t, 8);
        expect(lc_qtx_inflight(&t), "one block acknowledged leaves the rest in flight");
        expect(lc_qtx_room(&t) == 8,
               "and the room comes back anyway, which the flat buffer could not do");

        uint8_t *at;
        size_t   len;
        expect(lc_qtx_run(&t, 0, &at, &len) == 0, "nothing is pending after everything was sent");
        expect(t.head != NULL && t.head->off == 8 && t.head->buf[0] == 'B',
               "the block now at the front still holds its own bytes, unmoved");

        expect(lc_qtx_push(&t, (const uint8_t *)"EEEEEEEE", 8) == 8,
               "the freed room takes new bytes while the rest is in flight");
        expect(lc_qtx_pending(&t) == 8, "which are pending and nothing else is");
        lc_qtx_free(&t);
    }

    printf("\nacknowledgement, and what it may and may not release\n");
    {
        lc_qtx t;
        memset(&t, 0, sizeof t);
        t.cap = 32;
        t.blk = 8;
        (void)lc_qtx_push(&t, (const uint8_t *)"AAAAAAAABBBBBBBB", 16);
        lc_qtx_sent(&t, 16);

        /* A partial acknowledgement inside a block releases nothing: the rest of that block is
         * still under ngtcp2's pointer. Block granularity is the price of never moving anything. */
        lc_qtx_ack(&t, 4);
        expect(t.head != NULL && t.head->off == 0 && lc_qtx_room(&t) == 16,
               "an acknowledgement inside a block frees no block");

        lc_qtx_ack(&t, 16);
        expect(t.head == NULL && t.tail == NULL && lc_qtx_room(&t) == 32,
               "and one that passes the last block frees them all");
        expect(!lc_qtx_inflight(&t), "with nothing left in flight");

        lc_qtx_ack(&t, 999);
        expect(t.acked == 16, "an acknowledgement past what was sent is clamped to what was sent");

        (void)lc_qtx_push(&t, (const uint8_t *)"CCCC", 4);
        expect(t.head != NULL && t.head->off == 16,
               "a block allocated after the front was freed carries on from the right offset");
        lc_qtx_free(&t);
    }

    printf("\nwhat is offered to ngtcp2\n");
    {
        lc_qtx t;
        memset(&t, 0, sizeof t);
        t.cap = 32;
        t.blk = 8;
        (void)lc_qtx_push(&t, (const uint8_t *)"0123456789abcdefghij", 20);

        uint8_t got[32];
        size_t  n = drain_runs(&t, got, sizeof got);
        expect(n == 20 && memcmp(got, "0123456789abcdefghij", 20) == 0,
               "the runs concatenate to exactly what was pushed, in order");

        uint8_t *at;
        size_t   len;
        expect(lc_qtx_run(&t, 0, &at, &len) && len == 8,
               "the first run is one block, not the whole queue");
        expect(lc_qtx_run(&t, 2, &at, &len) && len == 4,
               "and the last is the part of a block that was written");
        expect(lc_qtx_run(&t, 3, &at, &len) == 0, "past the end there is no run");

        lc_qtx_sent(&t, 12);
        n = drain_runs(&t, got, sizeof got);
        expect(n == 8 && memcmp(got, "cdefghij", 8) == 0,
               "after a partial accept the runs resume where ngtcp2 stopped");
        lc_qtx_free(&t);
    }

    printf("\nthe ceiling, and taking less than was offered\n");
    {
        lc_qtx t;
        memset(&t, 0, sizeof t);
        t.cap = 12;
        t.blk = 8;
        expect(lc_qtx_push(&t, (const uint8_t *)"AAAAAAAABBBBBBBB", 16) == 12,
               "a push past the ceiling takes what fits and says so");
        expect(lc_qtx_room(&t) == 0 && lc_qtx_pending(&t) == 12,
               "the queue holds exactly the ceiling");
        lc_qtx_free(&t);

        /* A queue never told its block size takes nothing rather than inventing one. */
        lc_qtx u;
        memset(&u, 0, sizeof u);
        u.cap = 32;
        expect(lc_qtx_push(&u, (const uint8_t *)"AAAA", 4) == 0,
               "a queue with no block size takes nothing rather than choosing one");
        lc_qtx_free(&u);
    }

    printf("\nadopted memory, abandoning, and freeing\n");
    {
        /* The arena lends a region it owns itself; freeing it here would be a free of memory this
         * queue never allocated. The bytes must still be there afterwards. */
        uint8_t lent[16];
        memset(lent, 'z', sizeof lent);
        lc_qtx t;
        memset(&t, 0, sizeof t);
        t.cap = 64;
        t.blk = 8;
        expect(lc_qtx_adopt(&t, lent, sizeof lent, 0) == 0, "a borrowed block is adopted");
        memcpy(lent, "hello", 5);
        lc_qtx_commit(&t, 5);
        expect(lc_qtx_pending(&t) == 5, "and what was written into it is pending");
        lc_qtx_free(&t);
        expect(memcmp(lent, "hello", 5) == 0, "freeing the queue leaves borrowed memory alone");
    }
    {
        lc_qtx t;
        memset(&t, 0, sizeof t);
        t.cap = 32;
        t.blk = 8;
        (void)lc_qtx_push(&t, (const uint8_t *)"AAAAAAAABBBBBBBBCCCC", 20);
        lc_qtx_sent(&t, 12);

        /* Abandon drops only what was never offered. The four bytes of the second block that
         * ngtcp2 took are still its to look at, closed or not. */
        lc_qtx_abandon(&t);
        expect(lc_qtx_pending(&t) == 0, "abandoning leaves nothing pending");
        expect(t.tail != NULL && t.tail->off + t.tail->len == 12,
               "and keeps exactly the bytes that were handed over");
        expect(t.queued == 12, "with the accounting to match");
        lc_qtx_free(&t);
        expect(t.head == NULL && t.queued == 0, "freeing empties the queue");
    }

    /* THE PLACE lc_qtx_run KEEPS, which is a pointer into the list and therefore a pointer that can
     * be left dangling. It exists because walking from the head cost two thirds of the packing time
     * on a long path; every case below is one where a block it may point at is freed or cut. */
    {
        lc_qtx t;
        memset(&t, 0, sizeof t);
        t.cap = 64;
        t.blk = 8;
        (void)lc_qtx_push(&t, (const uint8_t *)"0000000011111111222222223333333344444444", 40);
        lc_qtx_sent(&t, 36);
        uint8_t *at;
        size_t   len;
        expect(lc_qtx_run(&t, 0, &at, &len) == 1 && len == 4 && memcmp(at, "4444", 4) == 0,
               "the first run starts where the unsent bytes do, deep in the list");
        expect(t.from == t.tail, "and the place is kept on the block that holds them");
        (void)lc_qtx_push(&t, (const uint8_t *)"55555555", 8);
        expect(lc_qtx_run(&t, 1, &at, &len) == 1 && len == 8 && memcmp(at, "55555555", 8) == 0,
               "a block written after it is reached from there");

        lc_qtx_sent(&t, 12);
        expect(lc_qtx_run(&t, 0, &at, &len) == 0, "with everything offered there is no run");
        expect(t.from == t.tail, "and the place stays on the last block rather than going back");

        /* Everything acknowledged: every block goes, the one the place is on included. */
        lc_qtx_ack(&t, 48);
        expect(t.head == NULL && t.from == NULL,
               "freeing the block the place is on puts the place back at the head");
        (void)lc_qtx_push(&t, (const uint8_t *)"66666666", 8);
        expect(lc_qtx_run(&t, 0, &at, &len) == 1 && len == 8 && memcmp(at, "66666666", 8) == 0,
               "and the next bytes are found");
        lc_qtx_free(&t);
        expect(t.from == NULL, "freeing the queue forgets the place too");
    }
    {
        lc_qtx t;
        memset(&t, 0, sizeof t);
        t.cap = 32;
        t.blk = 8;
        (void)lc_qtx_push(&t, (const uint8_t *)"AAAAAAAABBBBBBBBCCCCCCCC", 24);
        lc_qtx_sent(&t, 20);
        uint8_t *at;
        size_t   len;
        (void)lc_qtx_run(&t, 0, &at, &len);
        expect(t.from == t.tail, "the place is on the block being offered");
        lc_qtx_abandon(&t);
        expect(t.from == NULL, "abandoning, which cuts that very block, puts the place back");
        expect(lc_qtx_run(&t, 0, &at, &len) == 0 && t.from == t.tail,
               "and a walk from the head finds it again with nothing left to offer");
        lc_qtx_free(&t);
    }

    printf("\n%s\n", failures == 0 ? "all ok" : "FAILURES");
    return failures == 0 ? 0 : 1;
}
