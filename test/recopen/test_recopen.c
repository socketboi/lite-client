/* The node's records opened ahead (tls/recopen.c) and the answers the loop takes from them.
 *
 * The one claim that matters: whatever the threads opened, the loop gets from lc_recopen_take exactly
 * what lc_record_unprotect with its own key would have given it — the same plaintext, the same
 * length, the same inner type, the same sequence number afterwards — and when an answer is not
 * theirs to give, nothing at all, so that the loop's own call gives it. Each record here is sealed
 * as the node seals it, with lc_record_protect, and every one is opened a second time by a key of
 * the test's own, which is what every answer is held to byte for byte.
 *
 * What must not be answered: a record whose tag is broken, a key that has moved since the records
 * were handed out, a sequence number the loop has moved, room of another size, a record nobody
 * handed out; and a TLS 1.2 key, a record that is not application data and a record not yet whole
 * are not handed out at all. Then many rounds, with and without letting the threads go first. */

#include "tls/recopen.h"

#include "core/rnd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int failures;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

static void let_threads_go_first(void)
{
    struct timespec t = { 0, 30 * 1000 * 1000 };
    nanosleep(&t, NULL);
}

/* `n` records sealed one after another with `w` into `buf`: sizes from `sizes`, inner types from
 * `types`, a little padding on some. Returns the length written. */
static size_t seal_all(lc_record_key *w, uint8_t *buf, size_t cap, unsigned n, const size_t *sizes,
                       const uint8_t *types)
{
    static uint8_t pt[LC_REC_MAX_PLAINTEXT];
    size_t         at = 0;
    for (unsigned i = 0; i < n; i++) {
        for (size_t j = 0; j < sizes[i]; j++)
            pt[j] = (uint8_t)(j * 13u + i + (size_t)w->seq);
        size_t pad = i % 3u == 1u ? 7u : 0u;
        if (sizes[i] + 1u + pad > LC_REC_MAX_PLAINTEXT)
            pad = 0;
        size_t got = 0;
        if (lc_record_protect(w, types[i], pt, sizes[i], pad, buf + at, cap - at, &got) != 0)
            return 0;
        at += got;
    }
    return at;
}

/* One record the loop's way: from the pool when it answers, else with the loop's own key — and a
 * third key, the test's, opens it too; the two must agree in everything. `from_pool` says which it
 * was. */
static int deliver_one(lc_recopen *r, lc_record_key *loop, lc_record_key *ref, const uint8_t *rec,
                       size_t rec_len, int *from_pool)
{
    static uint8_t a[LC_RECOPEN_CAP], b[LC_RECOPEN_CAP];
    size_t         al = 0, bl = 0;
    uint8_t        at = 0, bt = 0;
    memset(a, 0xaa, sizeof a);
    memset(b, 0xaa, sizeof b);
    uint64_t seq_before = loop->seq;
    int      ra = 0;
    *from_pool = lc_recopen_take(r, loop, rec, rec_len, a, sizeof a, &al, &at);
    if (!*from_pool)
        ra = lc_record_unprotect(loop, rec, rec_len, a, sizeof a, &al, &at);
    int rb = lc_record_unprotect(ref, rec, rec_len, b, sizeof b, &bl, &bt);
    if (ra != rb)
        return 0;
    if (ra != 0)
        return loop->seq == seq_before && ref->seq == seq_before;
    return al == bl && at == bt && memcmp(a, b, al) == 0 && loop->seq == ref->seq &&
           loop->seq == seq_before + 1u;
}

static void random_bytes(uint8_t *p, size_t n)
{
    if (lc_rnd(p, n) != 0)
        memset(p, 0x5a, n);
}

static void one_suite(lc_aead_alg alg, const char *name)
{
    char       what[200];
    uint8_t    key[32], key2[32], iv[LC_AEAD_NONCE];
    lc_recopen *r = NULL;
    random_bytes(key, sizeof key);
    random_bytes(key2, sizeof key2);
    random_bytes(iv, sizeof iv);
    ok(lc_recopen_new(&r) == 0 && r != NULL, "a pool with threads");
    if (r == NULL)
        return;

    static uint8_t      buf[LC_RECOPEN_SLOTS * LC_REC_MAX_WIRE + 64u];
    static lc_record_key w, loop, ref;
    size_t              sizes[LC_RECOPEN_SLOTS];
    uint8_t             types[LC_RECOPEN_SLOTS];

    /* Every record answered, when the threads are let go first: every size from nothing to the
     * largest, every inner type the node sends. */
    {
        lc_record_key_init(&w, alg, key, iv);
        lc_record_key_init(&loop, alg, key, iv);
        lc_record_key_init(&ref, alg, key, iv);
        const uint8_t kinds[3] = { LC_REC_APPLICATION_DATA, LC_REC_HANDSHAKE, LC_REC_ALERT };
        unsigned      total = 0, answered = 0, agree = 0;
        for (unsigned round = 0; round < 12u; round++) {
            unsigned n = 2u + round % (LC_RECOPEN_SLOTS - 1u);
            for (unsigned i = 0; i < n; i++) {
                sizes[i] = (size_t)((round * 977u + i * 3331u) % (LC_REC_MAX_PLAINTEXT - 1u));
                if (i == 0u && round % 4u == 0u)
                    sizes[i] = 0;
                if (i == 1u && round % 4u == 1u)
                    sizes[i] = LC_REC_MAX_PLAINTEXT - 1u;
                types[i] = kinds[(round + i) % 3u];
            }
            size_t len = seal_all(&w, buf, sizeof buf, n, sizes, types);
            unsigned handed = lc_recopen_start(r, &loop, buf, len);
            let_threads_go_first();
            size_t at = 0;
            for (unsigned i = 0; i < n; i++) {
                size_t whole = LC_REC_HEADER + ((size_t)buf[at + 3u] << 8 | buf[at + 4u]);
                int    from = 0;
                agree += (unsigned)deliver_one(r, &loop, &ref, buf + at, whole, &from);
                answered += (unsigned)from;
                total++;
                at += whole;
            }
            lc_recopen_finish(r);
            if (handed != n)
                agree = 0;
        }
        snprintf(what, sizeof what, "%s: %u records, every answer the loop's own call's (%u from "
                                    "the threads)", name, total, answered);
        ok(agree == total && answered == total, what);
        lc_record_key_free(&w);
        lc_record_key_free(&loop);
        lc_record_key_free(&ref);
    }

    /* A broken tag: not answered, and the loop's own call refuses it with bad_record_mac. */
    {
        lc_record_key_init(&w, alg, key, iv);
        lc_record_key_init(&loop, alg, key, iv);
        lc_record_key_init(&ref, alg, key, iv);
        for (unsigned i = 0; i < 4u; i++) {
            sizes[i] = 900u + i;
            types[i] = LC_REC_APPLICATION_DATA;
        }
        size_t len = seal_all(&w, buf, sizeof buf, 4, sizes, types);
        size_t first = LC_REC_HEADER + ((size_t)buf[3] << 8 | buf[4]);
        buf[first + 20u] ^= 0x01u; /* in the second record's body */
        lc_recopen_start(r, &loop, buf, len);
        let_threads_go_first();
        int from0 = 0, from1 = 1, agree0, agree1;
        agree0 = deliver_one(r, &loop, &ref, buf, first, &from0);
        size_t second = LC_REC_HEADER + ((size_t)buf[first + 3u] << 8 | buf[first + 4u]);
        agree1 = deliver_one(r, &loop, &ref, buf + first, second, &from1);
        lc_recopen_finish(r);
        snprintf(what, sizeof what, "%s: a tag that does not verify is not answered, and the loop "
                                    "refuses it itself", name);
        ok(agree0 && from0 && agree1 && !from1, what);
        lc_record_key_free(&w);
        lc_record_key_free(&loop);
        lc_record_key_free(&ref);
    }

    /* The key moved after the records were handed out — a KeyUpdate among them: the records after
     * it were opened by the threads with the old key, and none of those answers is given. */
    {
        lc_record_key_init(&w, alg, key, iv);
        lc_record_key_init(&loop, alg, key, iv);
        for (unsigned i = 0; i < 3u; i++) {
            sizes[i] = 500u;
            types[i] = LC_REC_APPLICATION_DATA;
        }
        size_t len = seal_all(&w, buf, sizeof buf, 3, sizes, types);
        lc_recopen_start(r, &loop, buf, len);
        let_threads_go_first();
        static uint8_t o[LC_RECOPEN_CAP];
        size_t         ol = 0;
        uint8_t        ot = 0;
        int first = lc_recopen_take(r, &loop, buf, LC_REC_HEADER + 500u + 1u + LC_AEAD_TAG, o,
                                    sizeof o, &ol, &ot);
        lc_record_key_free(&loop);
        lc_record_key_init(&loop, alg, key2, iv);
        loop.seq = 1;
        size_t at = LC_REC_HEADER + 500u + 1u + LC_AEAD_TAG;
        size_t len1 = LC_REC_HEADER + ((size_t)buf[at + 3u] << 8 | buf[at + 4u]);
        int    second = lc_recopen_take(r, &loop, buf + at, len1, o, sizeof o, &ol, &ot);
        uint64_t seq_after = loop.seq;
        lc_recopen_finish(r);
        snprintf(what, sizeof what, "%s: a key that moved after the records were handed out gets no "
                                    "answer", name);
        ok(first && !second && seq_after == 1u, what);
        lc_record_key_free(&w);
        lc_record_key_free(&loop);
    }

    /* The loop's sequence number is not the one the record was opened with. */
    {
        lc_record_key_init(&w, alg, key, iv);
        lc_record_key_init(&loop, alg, key, iv);
        sizes[0] = sizes[1] = 300u;
        types[0] = types[1] = LC_REC_APPLICATION_DATA;
        size_t len = seal_all(&w, buf, sizeof buf, 2, sizes, types);
        lc_recopen_start(r, &loop, buf, len);
        let_threads_go_first();
        loop.seq = 7;
        static uint8_t o[LC_RECOPEN_CAP];
        size_t         ol = 0;
        uint8_t        ot = 0;
        int got = lc_recopen_take(r, &loop, buf, LC_REC_HEADER + 300u + 1u + LC_AEAD_TAG, o,
                                  sizeof o, &ol, &ot);
        lc_recopen_finish(r);
        snprintf(what, sizeof what, "%s: a sequence number the loop has moved gets no answer", name);
        ok(!got && loop.seq == 7u, what);
        lc_record_key_free(&w);
        lc_record_key_free(&loop);
    }

    /* Room of another size: lc_record_unprotect decides by it, so the answer would not be its. */
    {
        lc_record_key_init(&w, alg, key, iv);
        lc_record_key_init(&loop, alg, key, iv);
        sizes[0] = sizes[1] = 300u;
        types[0] = types[1] = LC_REC_APPLICATION_DATA;
        size_t len = seal_all(&w, buf, sizeof buf, 2, sizes, types);
        lc_recopen_start(r, &loop, buf, len);
        let_threads_go_first();
        static uint8_t o[LC_RECOPEN_CAP];
        size_t         ol = 0;
        uint8_t        ot = 0;
        int got = lc_recopen_take(r, &loop, buf, LC_REC_HEADER + 300u + 1u + LC_AEAD_TAG, o,
                                  sizeof o - 1u, &ol, &ot);
        int other = lc_recopen_take(r, &loop, buf + 1, 10, o, sizeof o, &ol, &ot);
        lc_recopen_finish(r);
        snprintf(what, sizeof what, "%s: room of another size, or a record nobody handed out, gets "
                                    "no answer", name);
        ok(!got && !other && loop.seq == 0u, what);
        lc_record_key_free(&w);
        lc_record_key_free(&loop);
    }

    /* What is handed out: application data only, whole records only, never with a TLS 1.2 key, and
     * nothing for a single record. */
    {
        lc_record_key_init(&w, alg, key, iv);
        lc_record_key_init(&loop, alg, key, iv);
        for (unsigned i = 0; i < 4u; i++) {
            sizes[i] = 200u;
            types[i] = LC_REC_APPLICATION_DATA;
        }
        size_t len = seal_all(&w, buf, sizeof buf, 4, sizes, types);
        size_t one = LC_REC_HEADER + 200u + 1u + LC_AEAD_TAG;
        unsigned partial = lc_recopen_start(r, &loop, buf, len - 1u);
        lc_recopen_finish(r);
        size_t third = 0;
        for (unsigned i = 0; i < 2u; i++)
            third += LC_REC_HEADER + ((size_t)buf[third + 3u] << 8 | buf[third + 4u]);
        buf[third] = LC_REC_CHANGE_CIPHER_SPEC;
        unsigned ccs = lc_recopen_start(r, &loop, buf, len);
        lc_recopen_finish(r);
        unsigned single = lc_recopen_start(r, &loop, buf, one);
        lc_recopen_finish(r);
        static lc_record_key k12;
        memset(&k12, 0, sizeof k12);
        k12.tls12 = 1;
        k12.key_len = 16; /* never so from lc_record_key_init12 — the test gives it bytes anyway */
        unsigned tls12 = lc_recopen_start(r, &k12, buf, len);
        lc_recopen_finish(r);
        snprintf(what, sizeof what, "%s: handed out — 3 of 4 when the last is short (%u), 2 before a "
                                    "ChangeCipherSpec (%u), none for one record (%u) or TLS 1.2 (%u)",
                 name, partial, ccs, single, tls12);
        ok(partial == 3u && ccs == 2u && single == 0u && tls12 == 0u, what);
        lc_record_key_free(&w);
        lc_record_key_free(&loop);
    }

    /* Many rounds, the loop not waiting: whatever the threads reached and whatever they did not, the
     * loop's records are the reference's. */
    {
        lc_record_key_init(&w, alg, key, iv);
        lc_record_key_init(&loop, alg, key, iv);
        lc_record_key_init(&ref, alg, key, iv);
        unsigned total = 0, answered = 0, agree = 0;
        for (unsigned round = 0; round < 300u; round++) {
            unsigned n = 2u + (round * 7u) % (LC_RECOPEN_SLOTS - 1u);
            for (unsigned i = 0; i < n; i++) {
                sizes[i] = (size_t)((round * 131u + i * 5003u) % 16000u);
                types[i] = LC_REC_APPLICATION_DATA;
            }
            size_t len = seal_all(&w, buf, sizeof buf, n, sizes, types);
            lc_recopen_start(r, &loop, buf, len);
            size_t at = 0;
            /* Sometimes the loop stops part-way, as it does when the client's queue is full. */
            unsigned upto = round % 5u == 0u ? n / 2u : n;
            for (unsigned i = 0; i < upto; i++) {
                size_t whole = LC_REC_HEADER + ((size_t)buf[at + 3u] << 8 | buf[at + 4u]);
                int    from = 0;
                agree += (unsigned)deliver_one(r, &loop, &ref, buf + at, whole, &from);
                answered += (unsigned)from;
                total++;
                at += whole;
            }
            lc_recopen_finish(r);
            /* What was not delivered is delivered next round, from where it stands, as the loop
             * would after moving it to the front. */
            if (upto < n) {
                size_t rest = len - at;
                memmove(buf, buf + at, rest);
                lc_recopen_start(r, &loop, buf, rest);
                size_t a2 = 0;
                for (unsigned i = upto; i < n; i++) {
                    size_t whole = LC_REC_HEADER + ((size_t)buf[a2 + 3u] << 8 | buf[a2 + 4u]);
                    int    from = 0;
                    agree += (unsigned)deliver_one(r, &loop, &ref, buf + a2, whole, &from);
                    answered += (unsigned)from;
                    total++;
                    a2 += whole;
                }
                lc_recopen_finish(r);
            }
        }
        snprintf(what, sizeof what, "%s: %u records in 300 rounds, the loop not waiting, every one the "
                                    "reference's (%u from the threads)", name, total, answered);
        ok(agree == total && answered > 0u, what);
        lc_record_key_free(&w);
        lc_record_key_free(&loop);
        lc_record_key_free(&ref);
    }

    lc_recopen_free(r);
}

int main(void)
{
    printf("the node's records opened ahead, and the answers the loop takes from them\n");
    one_suite(LC_AEAD_AES_128_GCM, "AES-128-GCM");
    one_suite(LC_AEAD_AES_256_GCM, "AES-256-GCM");
    one_suite(LC_AEAD_CHACHA20_POLY1305, "ChaCha20-Poly1305");
    if (failures) {
        printf("%d FAILED\n", failures);
        return 1;
    }
    printf("all good\n");
    return 0;
}
