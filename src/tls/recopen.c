/* The node's records opened ahead — see tls/recopen.h. DIVERGES: O3. */
#include "tls/recopen.h"

#include "core/relax.h"
#include "core/wipe.h"

#include <linux/futex.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

typedef struct {
    /* What the loop handed out: set before the job is published, read only after. */
    const uint8_t *rec;
    size_t         rec_len;
    uint64_t       seq;

    /* What the thread made of it, readable once `done` is set. */
    int      rc;
    size_t   plain_len;
    uint8_t  inner;
    int      claimed; /* by a thread — under the pool's lock */
    int      done;    /* atomically; a futex word */
    int      waiting; /* atomically: the loop sleeps on `done` */
    uint8_t  plain[LC_RECOPEN_CAP];
} slot;

/* The key the job's records are opened with, as the loop's key has it. */
typedef struct {
    lc_aead_alg alg;
    size_t      key_len;
    uint8_t     key[32];
    uint8_t     iv[LC_AEAD_NONCE];
} key_id;

struct lc_recopen {
    unsigned        nthreads;
    pthread_t       th[LC_RECOPEN_THREADS_MAX];
    pthread_mutex_t lock;
    pthread_cond_t  cv;
    int             stop;

    /* The job. Under the lock: job, n, next, id, and each slot's `claimed`. */
    unsigned job;     /* bumped for every job handed out */
    unsigned n;       /* records in it */
    unsigned next;    /* the first no thread has claimed — and that the loop has not taken back */
    key_id   id;
    int      active;  /* the loop's own: between start and finish */
    slot     s[LC_RECOPEN_SLOTS];
};

static int same_key(const key_id *a, const key_id *b)
{
    return a->alg == b->alg && a->key_len == b->key_len &&
           memcmp(a->key, b->key, a->key_len) == 0 && memcmp(a->iv, b->iv, sizeof a->iv) == 0;
}

static void id_of(const lc_record_key *k, key_id *id)
{
    memset(id, 0, sizeof *id);
    id->alg = k->alg;
    id->key_len = k->key_len;
    memcpy(id->key, k->key, k->key_len);
    memcpy(id->iv, k->iv, sizeof id->iv);
}

/* The loop waits for a record a thread is opening: a few turns awake, which is all it takes when
 * the thread is nearly done, then asleep on the slot until the thread wakes it. Spinning for longer
 * was measured on the MT7621 (2026-09-29): the same speed, three quarters more processor, since the
 * wait is up to a record's opening and on MIPS a spin is the core's whole attention. */
static void wait_done(slot *s)
{
    for (unsigned i = 0; i < 100u; i++) {
        if (__atomic_load_n(&s->done, __ATOMIC_ACQUIRE))
            return;
        lc_cpu_relax();
    }
    __atomic_store_n(&s->waiting, 1, __ATOMIC_SEQ_CST);
    while (!__atomic_load_n(&s->done, __ATOMIC_SEQ_CST))
        syscall(SYS_futex, &s->done, FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0);
    __atomic_store_n(&s->waiting, 0, __ATOMIC_RELAXED);
}

/* The thread's half: the answer published, and the loop woken only if it went to sleep for it. */
static void set_done(slot *s)
{
    __atomic_store_n(&s->done, 1, __ATOMIC_SEQ_CST);
    if (__atomic_load_n(&s->waiting, __ATOMIC_SEQ_CST))
        syscall(SYS_futex, &s->done, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
}

static void *opener(void *arg)
{
    lc_recopen   *r = arg;
    unsigned      seen = 0;
    lc_record_key mine;
    key_id        mine_id, job_id;
    int           have = 0;

    memset(&mine, 0, sizeof mine);
    memset(&mine_id, 0, sizeof mine_id);
    for (;;) {
        pthread_mutex_lock(&r->lock);
        while (r->job == seen && !r->stop)
            pthread_cond_wait(&r->cv, &r->lock);
        if (r->stop) {
            pthread_mutex_unlock(&r->lock);
            break;
        }
        seen = r->job;
        while (r->next < r->n) {
            slot *s = &r->s[r->next++];
            s->claimed = 1;
            job_id = r->id;
            pthread_mutex_unlock(&r->lock);

            if (!have || !same_key(&mine_id, &job_id)) {
                if (have)
                    lc_record_key_free(&mine);
                have = lc_record_key_init(&mine, job_id.alg, job_id.key, job_id.iv) == 0;
                mine_id = job_id;
            }
            if (have) {
                mine.seq = s->seq;
                s->rc = lc_record_unprotect(&mine, s->rec, s->rec_len, s->plain, sizeof s->plain,
                                            &s->plain_len, &s->inner);
            } else {
                s->rc = -1;
            }
            set_done(s);
            pthread_mutex_lock(&r->lock);
        }
        pthread_mutex_unlock(&r->lock);
    }
    if (have)
        lc_record_key_free(&mine);
    lc_wipe(&mine_id, sizeof mine_id);
    lc_wipe(&job_id, sizeof job_id);
    return NULL;
}

static unsigned threads_for_box(void)
{
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpus <= 1)
        return 0;
    return (unsigned)cpus - 1u < LC_RECOPEN_THREADS_MAX ? (unsigned)cpus - 1u
                                                        : LC_RECOPEN_THREADS_MAX;
}

int lc_recopen_new(lc_recopen **out)
{
    *out = NULL;
    unsigned want = threads_for_box();
    if (want == 0u)
        return 0;
    lc_recopen *r = calloc(1, sizeof *r);
    if (r == NULL)
        return -1;
    if (pthread_mutex_init(&r->lock, NULL) != 0) {
        free(r);
        return -1;
    }
    if (pthread_cond_init(&r->cv, NULL) != 0) {
        pthread_mutex_destroy(&r->lock);
        free(r);
        return -1;
    }
    pthread_attr_t attr;
    if (pthread_attr_init(&attr) != 0) {
        lc_recopen_free(r);
        return -1;
    }
    /* Small stacks: an opener's frame is its key and a few hundred bytes, the records and what they
     * open to are in the pool. */
    pthread_attr_setstacksize(&attr, 64u * 1024u);
    for (unsigned i = 0; i < want; i++) {
        if (pthread_create(&r->th[i], &attr, opener, r) != 0) {
            pthread_attr_destroy(&attr);
            lc_recopen_free(r);
            return -1;
        }
        r->nthreads++;
    }
    pthread_attr_destroy(&attr);
    *out = r;
    return 0;
}

void lc_recopen_free(lc_recopen *r)
{
    if (r == NULL)
        return;
    lc_recopen_finish(r);
    pthread_mutex_lock(&r->lock);
    r->stop = 1;
    pthread_cond_broadcast(&r->cv);
    pthread_mutex_unlock(&r->lock);
    for (unsigned i = 0; i < r->nthreads; i++)
        pthread_join(r->th[i], NULL);
    pthread_cond_destroy(&r->cv);
    pthread_mutex_destroy(&r->lock);
    lc_wipe(&r->id, sizeof r->id);
    free(r);
}

unsigned lc_recopen_start(lc_recopen *r, const lc_record_key *k, const uint8_t *buf, size_t len)
{
    if (r == NULL || r->active || k->tls12 || k->key_len == 0u)
        return 0;
    unsigned n = 0;
    size_t   at = 0;
    while (n < LC_RECOPEN_SLOTS && len - at >= LC_REC_HEADER) {
        const uint8_t *h = buf + at;
        if (h[0] != LC_REC_APPLICATION_DATA)
            break;
        size_t whole = LC_REC_HEADER + ((size_t)h[3] << 8 | h[4]);
        if (len - at < whole)
            break;
        r->s[n].rec = h;
        r->s[n].rec_len = whole;
        r->s[n].seq = k->seq + n;
        r->s[n].plain_len = 0;
        r->s[n].claimed = 0;
        r->s[n].done = 0;
        r->s[n].waiting = 0;
        n++;
        at += whole;
    }
    /* One record is the loop's to open as it always was: there is nothing beside it to overlap. */
    if (n < 2u)
        return 0;
    pthread_mutex_lock(&r->lock);
    id_of(k, &r->id);
    r->n = n;
    r->next = 0;
    r->job++;
    pthread_cond_broadcast(&r->cv);
    pthread_mutex_unlock(&r->lock);
    r->active = 1;
    return n;
}

int lc_recopen_take(lc_recopen *r, lc_record_key *k, const uint8_t *rec, size_t rec_len,
                    uint8_t *out, size_t out_cap, size_t *out_len, uint8_t *inner_type)
{
    if (r == NULL || !r->active)
        return 0;
    unsigned i = 0;
    while (i < r->n && r->s[i].rec != rec)
        i++;
    if (i == r->n)
        return 0;

    /* Not claimed yet: the loop takes it back and opens it itself, rather than wait for a thread
     * that has not reached it. Everything before it has been delivered, so the claim moves past it. */
    pthread_mutex_lock(&r->lock);
    if (i >= r->next) {
        r->next = i + 1u;
        pthread_mutex_unlock(&r->lock);
        return 0;
    }
    pthread_mutex_unlock(&r->lock);

    /* Claimed: being opened, or opened. The wait is at most one record's opening. */
    slot *s = &r->s[i];
    wait_done(s);

    key_id now;
    id_of(k, &now);
    int ok = s->rc == 0 && s->rec_len == rec_len && s->seq == k->seq && !k->tls12 &&
             out_cap == LC_RECOPEN_CAP && s->plain_len <= out_cap && same_key(&now, &r->id);
    lc_wipe(&now, sizeof now);
    if (!ok) {
        if (s->rc == 0)
            lc_wipe(s->plain, s->plain_len);
        s->plain_len = 0;
        return 0;
    }
    memcpy(out, s->plain, s->plain_len);
    *out_len = s->plain_len;
    *inner_type = s->inner;
    k->seq++;
    lc_wipe(s->plain, s->plain_len);
    s->plain_len = 0;
    return 1;
}

void lc_recopen_finish(lc_recopen *r)
{
    if (r == NULL || !r->active)
        return;
    pthread_mutex_lock(&r->lock);
    r->next = r->n;
    pthread_mutex_unlock(&r->lock);
    /* Past this lock no slot is claimed any more; the ones that were are waited for, and once each
     * is done no thread reads the loop's buffer for it. */
    for (unsigned i = 0; i < r->n; i++) {
        slot *s = &r->s[i];
        if (!s->claimed)
            continue;
        wait_done(s);
        if (s->rc == 0)
            lc_wipe(s->plain, s->plain_len);
        s->plain_len = 0;
        s->rec = NULL;
    }
    pthread_mutex_lock(&r->lock);
    r->n = 0;
    r->next = 0;
    pthread_mutex_unlock(&r->lock);
    r->active = 0;
}
