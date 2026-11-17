/* The node's packets opened ahead — see quic/rxopen.h. */
#include "quic/rxopen.h"

#include "core/relax.h"
#include "core/wipe.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ngtcp2's NGTCP2_MAX_PKT_NUM (vendor/ngtcp2/lib/ngtcp2_pkt.h), which conn_recv_pkt discards a
 * packet above. Private to the library, so named again here. */
#define MAX_PKT_NUM ((int64_t)((1ll << 62) - 1))

/* HOW MANY THREADS: one fewer than the processors online, at most seven. Measured 2026-09-29 on the
 * MT7621 (four logical processors), a Hysteria2 download from a LAN node with Salamander and
 * ChaCha20, where the processor and not a path is the ceiling — seconds and CPU seconds per 100 MB:
 *
 *     no thread      17.3 s   18.3 s
 *     one            12.4 s   21.1 s
 *     two            11.9 s   25.6 s
 *     three          11.5 s   28.4 s
 *
 * The first thread buys most of it; each further one about 4 % for a fifth more CPU. All of them
 * are taken, as the reference's scheduler takes every core it is given.
 *
 * AND THEY SLEEP AS SOON AS THEY RUN OUT. Staying awake for the next batch was measured and buys
 * nothing — 11.7 s with no wait, 11.5 with 50 us, 11.6 with 200 us, the CPU rising with the wait —
 * because the next batch is handed out as the loop starts feeding the one before, a few
 * milliseconds of work, and a thread woken then is in time for it. */
#define LC_RXOPEN_THREADS_MAX 7u

/* ---- the keys ------------------------------------------------------------------------------- */

static int same_key(lc_aead_alg a, const uint8_t *ka, size_t la, lc_aead_alg b, const uint8_t *kb,
                    size_t lb)
{
    return a == b && la == lb && memcmp(ka, kb, la) == 0;
}

void lc_rxkeys_take(lc_rxkeys *k, ngtcp2_conn *conn)
{
    ngtcp2_rx1rtt_keys r;
    k->valid = 0;
    if (conn == NULL || ngtcp2_conn_get_rx1rtt_keys(conn, &r) != 0 || r.ivlen != LC_AEAD_NONCE)
        return;
    const lc_qaead *a = r.aead_ctx->native_handle;
    const lc_qhp   *h = r.hp_ctx->native_handle;
    if (a == NULL || h == NULL)
        return;

    /* Remade from the key bytes, and only when they changed — a key update, once in a long while. */
    if (!k->have_aead || !same_key(k->aead.alg, k->aead.key, k->aead.key_len, a->alg, a->key,
                                   a->key_len)) {
        if (k->have_aead)
            lc_qaead_free(&k->aead);
        k->have_aead = lc_qaead_init(&k->aead, a->alg, a->key) == 0;
        if (!k->have_aead)
            return;
    }
    if (!k->have_hp ||
        !same_key(k->hp.alg, k->hp.key, k->hp.key_len, h->alg, h->key, h->key_len)) {
        if (k->have_hp)
            lc_qhp_free(&k->hp);
        k->have_hp = lc_qhp_init(&k->hp, h->alg, h->key) == 0;
        if (!k->have_hp)
            return;
    }
    memcpy(k->iv, r.iv, LC_AEAD_NONCE);
    k->key_phase = r.key_phase;
    k->max_pkt_num = r.max_pkt_num;
    k->dcidlen = r.dcidlen;
    k->valid = 1;
}

void lc_rxkeys_free(lc_rxkeys *k)
{
    if (k->have_aead)
        lc_qaead_free(&k->aead);
    if (k->have_hp)
        lc_qhp_free(&k->hp);
    lc_wipe(k, sizeof *k);
}

/* ---- one datagram --------------------------------------------------------------------------- */

/* ngtcp2_pkt_adjust_pkt_num (vendor/ngtcp2/lib/ngtcp2_pkt.c), which conn_recv_pkt decodes a
 * truncated packet number with, against the largest received. */
static int64_t adjust_pkt_num(int64_t max_pkt_num, int64_t pkt_num, size_t pkt_numlen)
{
    uint64_t expected = (uint64_t)max_pkt_num + 1u;
    uint64_t win = 1ull << (pkt_numlen * 8u);
    uint64_t hwin = win / 2u;
    uint64_t mask = win - 1u;
    uint64_t cand = (expected & ~mask) | (uint64_t)pkt_num;

    if (cand + hwin <= expected)
        return (int64_t)(cand + win);
    if (cand > expected + hwin && cand >= win)
        return (int64_t)(cand - win);
    return (int64_t)cand;
}

/* What conn_recv_pkt does to a short-header packet before it reaches the frames, done ahead: the
 * header's protection off as decrypt_hp takes it (the sample four bytes past the packet number,
 * five bytes of mask, the first byte's low five bits and the packet number's bytes), the key chosen
 * as it chooses one when the Key Phase bit has not changed, the packet number decoded against the
 * largest received, the nonce as ngtcp2_crypto_create_nonce makes it, and the AEAD opened over the
 * unprotected header (vendor/ngtcp2/lib/ngtcp2_conn.c, conn_recv_pkt, decrypt_hp, decrypt_pkt).
 * Whatever is not the ordinary case — a long header, a changed key phase, a packet too short to
 * sample — is left to ngtcp2 alone: no hint, and the callbacks compute as ever. */
void lc_rxopen_slot(const lc_obfs *obfs, lc_rxkeys *k, lc_rxslot *s)
{
    lc_qhint *h = &s->hint;
    h->have_mask = 0;
    h->have_open = 0;
    s->plain_len = lc_obfs_unwrap(obfs, s->raw, s->raw_len, s->plain, sizeof s->plain);
    if (s->plain_len <= 0 || !k->valid)
        return;

    const uint8_t *p = s->plain;
    size_t         n = (size_t)s->plain_len;
    if ((p[0] & 0x80u) != 0u)
        return;
    size_t pn_off = 1u + k->dcidlen;
    if (pn_off + 4u + 16u > n)
        return;

    const uint8_t *sample = p + pn_off + 4u;
    if (lc_qhp_mask(&k->hp, sample, h->mask) != 0)
        return;
    h->sample = sample;
    h->hp_alg = k->hp.alg;
    h->hp_key = k->hp.key;
    h->hp_key_len = k->hp.key_len;
    h->have_mask = 1;

    uint8_t first = (uint8_t)(p[0] ^ (h->mask[0] & 0x1fu));
    size_t  pn_len = (size_t)(first & 0x03u) + 1u;
    if (((first & 0x04u) != 0u) != (k->key_phase != 0) || pn_off + pn_len > sizeof h->aad)
        return;
    memcpy(h->aad, p, pn_off);
    h->aad[0] = first;
    int64_t truncated = 0;
    for (size_t i = 0; i < pn_len; i++) {
        h->aad[pn_off + i] = (uint8_t)(p[pn_off + i] ^ h->mask[1u + i]);
        truncated = truncated << 8 | h->aad[pn_off + i];
    }
    h->aad_len = pn_off + pn_len;
    int64_t pkt_num = adjust_pkt_num(k->max_pkt_num, truncated, pn_len);
    if (pkt_num > MAX_PKT_NUM)
        return;

    size_t hd_len = pn_off + pn_len;
    if (n - hd_len < LC_AEAD_TAG)
        return;
    memcpy(h->nonce, k->iv, LC_AEAD_NONCE);
    for (unsigned i = 0; i < 8u; i++)
        h->nonce[LC_AEAD_NONCE - 1u - i] ^= (uint8_t)((uint64_t)pkt_num >> (8u * i));
    h->ct = p + hd_len;
    h->ct_len = n - hd_len;
    h->alg = k->aead.alg;
    h->key = k->aead.key;
    h->key_len = k->aead.key_len;
    size_t written = 0;
    h->opened = lc_aead_open(&k->aead.aead, h->nonce, h->aad, h->aad_len, h->ct, h->ct_len,
                             s->opened, sizeof s->opened, &written) == 0;
    h->plain = s->opened;
    h->have_open = 1;
}

/* ---- reading a batch ------------------------------------------------------------------------ */

unsigned lc_rxopen_fill(lc_rxbatch *b, int fd, int *err)
{
    *err = 0;
    b->n = 0;
    while (b->n < LC_RXOPEN_BATCH) {
        struct mmsghdr m[LC_QRX_BATCH];
        unsigned       want = LC_RXOPEN_BATCH - b->n < LC_QRX_BATCH ? LC_RXOPEN_BATCH - b->n
                                                                  : LC_QRX_BATCH;
        memset(m, 0, sizeof m);
        for (unsigned i = 0; i < want; i++) {
            lc_rxslot *s = &b->slot[b->n + i];
            s->iov.iov_base = s->raw;
            s->iov.iov_len = sizeof s->raw;
            m[i].msg_hdr.msg_iov = &s->iov;
            m[i].msg_hdr.msg_iovlen = 1;
            m[i].msg_hdr.msg_control = s->ctl.buf;
            m[i].msg_hdr.msg_controllen = sizeof s->ctl.buf;
        }
        int got = recvmmsg(fd, m, want, 0, NULL);
        /* The kernel stamps arrivals on the wall clock and ngtcp2 counts on the monotonic one; the
         * distance between the two is taken once per read, right after it. */
        struct timespec wall, mono;
        clock_gettime(CLOCK_REALTIME, &wall);
        clock_gettime(CLOCK_MONOTONIC, &mono);
        int64_t wmm = ((int64_t)wall.tv_sec - (int64_t)mono.tv_sec) * 1000000000 +
                      ((int64_t)wall.tv_nsec - (int64_t)mono.tv_nsec);
        if (got < 0) {
            if (errno == EINTR)
                continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                *err = errno;
            break;
        }
        if (got == 0)
            break;
        for (int i = 0; i < got; i++) {
            lc_rxslot *s = &b->slot[b->n + (unsigned)i];
            s->hdr = m[i].msg_hdr;
            s->raw_len = m[i].msg_len;
            s->wall_minus_mono = wmm;
        }
        b->n += (unsigned)got;
        if ((unsigned)got < want)
            break;
    }
    return b->n;
}

/* ---- the threads ---------------------------------------------------------------------------- */

struct lc_rxopen {
    const lc_obfs  *obfs;
    lc_rxbatch      batch[2];
    unsigned        nthreads;
    pthread_t       th[LC_RXOPEN_THREADS_MAX];
    pthread_mutex_t lock;
    pthread_cond_t  cv;
    unsigned        job;  /* bumped for every batch handed out */
    lc_rxbatch     *cur;  /* the batch in hand, NULL for none */
    unsigned        next; /* its next slot to take — under the lock */
    unsigned        done; /* its slots opened — atomically */
    int             stop;
};

/* Takes slots of the batch in hand until none is left; the lock is held on entry and on return. */
static void take_slots(lc_rxopen *r)
{
    while (r->cur != NULL && r->next < r->cur->n) {
        lc_rxbatch *b = r->cur;
        unsigned    i = r->next++;
        pthread_mutex_unlock(&r->lock);
        lc_rxopen_slot(r->obfs, &b->keys, &b->slot[i]);
        __atomic_add_fetch(&r->done, 1u, __ATOMIC_RELEASE);
        pthread_mutex_lock(&r->lock);
    }
}

static void *opener(void *arg)
{
    lc_rxopen *r = arg;
    unsigned   seen = 0;
    for (;;) {
        pthread_mutex_lock(&r->lock);
        while (r->job == seen && !r->stop)
            pthread_cond_wait(&r->cv, &r->lock);
        if (r->stop) {
            pthread_mutex_unlock(&r->lock);
            return NULL;
        }
        seen = r->job;
        take_slots(r);
        pthread_mutex_unlock(&r->lock);
    }
}

static unsigned threads_for_box(void)
{
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpus <= 1)
        return 0;
    return (unsigned)cpus - 1u < LC_RXOPEN_THREADS_MAX ? (unsigned)cpus - 1u : LC_RXOPEN_THREADS_MAX;
}

int lc_rxopen_new(lc_rxopen **out, const lc_obfs *obfs)
{
    *out = NULL;
    lc_rxopen *r = calloc(1, sizeof *r);
    if (r == NULL)
        return -1;
    r->obfs = obfs;
    if (pthread_mutex_init(&r->lock, NULL) != 0) {
        free(r);
        return -1;
    }
    if (pthread_cond_init(&r->cv, NULL) != 0) {
        pthread_mutex_destroy(&r->lock);
        free(r);
        return -1;
    }
    unsigned want = threads_for_box();
    pthread_attr_t attr;
    if (pthread_attr_init(&attr) != 0) {
        lc_rxopen_free(r);
        return -1;
    }
    /* Small stacks: an opener's frame is a few hundred bytes, the batches are on the heap. */
    pthread_attr_setstacksize(&attr, 64u * 1024u);
    for (unsigned i = 0; i < want; i++) {
        if (pthread_create(&r->th[i], &attr, opener, r) != 0) {
            pthread_attr_destroy(&attr);
            lc_rxopen_free(r);
            return -1;
        }
        r->nthreads++;
    }
    pthread_attr_destroy(&attr);
    *out = r;
    return 0;
}

void lc_rxopen_free(lc_rxopen *r)
{
    if (r == NULL)
        return;
    pthread_mutex_lock(&r->lock);
    r->stop = 1;
    pthread_cond_broadcast(&r->cv);
    pthread_mutex_unlock(&r->lock);
    for (unsigned i = 0; i < r->nthreads; i++)
        pthread_join(r->th[i], NULL);
    pthread_cond_destroy(&r->cv);
    pthread_mutex_destroy(&r->lock);
    lc_rxkeys_free(&r->batch[0].keys);
    lc_rxkeys_free(&r->batch[1].keys);
    free(r);
}

lc_rxbatch *lc_rxopen_batch(lc_rxopen *r, unsigned i)
{
    return &r->batch[i & 1u];
}

void lc_rxopen_start(lc_rxopen *r, lc_rxbatch *b, ngtcp2_conn *conn)
{
    lc_rxkeys_take(&b->keys, conn);
    lc_rxopen_hand(r, b);
}

void lc_rxopen_hand(lc_rxopen *r, lc_rxbatch *b)
{
    pthread_mutex_lock(&r->lock);
    r->cur = b;
    r->next = 0;
    __atomic_store_n(&r->done, 0u, __ATOMIC_RELAXED);
    r->job++;
    /* No more sleepers need waking than there are datagrams to open. Keep the
     * full pool for larger batches and the stop broadcast in lc_rxopen_free.
     * Workers that have not parked yet observe job under the same mutex.
     * Slot ownership, completion and ordered delivery do not change. DIVERGES: O2. */
    if (r->nthreads > 0u && b->n >= r->nthreads) {
        pthread_cond_broadcast(&r->cv);
    } else {
        for (unsigned i = 0; i < b->n && i < r->nthreads; i++)
            pthread_cond_signal(&r->cv);
    }
    pthread_mutex_unlock(&r->lock);
}

void lc_rxopen_finish(lc_rxopen *r)
{
    pthread_mutex_lock(&r->lock);
    lc_rxbatch *b = r->cur;
    if (b == NULL) {
        pthread_mutex_unlock(&r->lock);
        return;
    }
    take_slots(r);
    pthread_mutex_unlock(&r->lock);
    /* What the threads still hold is in progress; the release on each count pairs with this
     * acquire, so every slot they wrote is visible once the count is whole. */
    while (__atomic_load_n(&r->done, __ATOMIC_ACQUIRE) < b->n)
        lc_cpu_relax();
    pthread_mutex_lock(&r->lock);
    r->cur = NULL;
    pthread_mutex_unlock(&r->lock);
}
