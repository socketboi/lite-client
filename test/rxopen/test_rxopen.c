/* The node's packets opened ahead (quic/rxopen.c) and the callbacks that answer from it
 * (lc_qhint, quic/qcrypto.c).
 *
 * The one claim that matters: whatever the threads computed, ngtcp2 gets from hp_mask and decrypt
 * exactly what they would have computed themselves — the same mask, the same plaintext, the same
 * refusal with the same wiped output — for a packet opened as expected, one whose tag is broken,
 * one opened ahead with a key the connection has since replaced, one whose packet number was
 * decoded differently, one never hinted at all, and one whose sample, header protection key,
 * ciphertext or header is not what the hint was made from. Each packet here is built as the node
 * builds it: payload sealed over the header, the header's protection applied from the sample,
 * Salamander over the lot. Then the callbacks are asked twice, with the hint and without, and the
 * two answers compared byte for byte; and the counters say whether the hint was the one answering.
 *
 * And the threads: many batches opened by the pool, each slot compared with the same datagram
 * opened on this thread alone. */

#include "quic/rxopen.h"

#include "core/rnd.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Observe only the caller's dispatch, without replacing real thread execution.
 * A fixed four-core fixture keeps empty/single/small/full batches reproducible. */
static _Thread_local int four_core_fixture;
static _Thread_local int observe_dispatch;
static _Thread_local unsigned signals, broadcasts;
static _Thread_local int observe_startup;
static _Thread_local unsigned fail_create_at, create_calls, started, joined;

long __real_sysconf(int name);
long __wrap_sysconf(int name)
{
    return four_core_fixture && name == _SC_NPROCESSORS_ONLN ? 4 : __real_sysconf(name);
}

int __real_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*entry)(void *), void *arg);
int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*entry)(void *), void *arg)
{
    if (observe_startup && create_calls++ == fail_create_at)
        return EAGAIN;
    int error = __real_pthread_create(thread, attr, entry, arg);
    if (observe_startup && error == 0)
        started++;
    return error;
}

int __real_pthread_join(pthread_t thread, void **result);
int __wrap_pthread_join(pthread_t thread, void **result)
{
    int error = __real_pthread_join(thread, result);
    if (observe_startup && error == 0)
        joined++;
    return error;
}

int __real_pthread_cond_signal(pthread_cond_t *cond);
int __wrap_pthread_cond_signal(pthread_cond_t *cond)
{
    if (observe_dispatch)
        signals++;
    return __real_pthread_cond_signal(cond);
}

int __real_pthread_cond_broadcast(pthread_cond_t *cond);
int __wrap_pthread_cond_broadcast(pthread_cond_t *cond)
{
    if (observe_dispatch)
        broadcasts++;
    return __real_pthread_cond_broadcast(cond);
}

static int failures;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

static void startup_failure_suite(void)
{
    lc_obfs obfs;
    memset(&obfs, 0, sizeof obfs);
    for (unsigned fail_at = 0; fail_at < 3u; fail_at++) {
        lc_rxopen *pool = NULL;
        four_core_fixture = 1;
        observe_startup = 1;
        fail_create_at = fail_at;
        create_calls = started = joined = 0u;
        signals = broadcasts = 0u;
        observe_dispatch = 1;
        int error = lc_rxopen_new(&pool, &obfs);
        observe_dispatch = 0;
        observe_startup = 0;
        four_core_fixture = 0;
        char what[160];
        snprintf(what, sizeof what,
                 "worker %u creation failure returns no pool and joins all %u started workers",
                 fail_at + 1u, fail_at);
        ok(error == -1 && pool == NULL && create_calls == fail_at + 1u &&
               started == fail_at && joined == started && broadcasts == 1u && signals == 0u,
           what);
        lc_rxopen_free(pool);

        /* Failed construction must not leave process-wide state that prevents
         * a subsequent pool from opening and shutting down normally. */
        four_core_fixture = 1;
        int made = lc_rxopen_new(&pool, &obfs) == 0;
        four_core_fixture = 0;
        lc_rxopen_free(pool);
        ok(made, "a new opener pool works after failed construction");
    }
}

/* A short-header packet as the node sends it: first byte 0x40 | key phase | pn length - 1, the
 * DCID, the packet number's low bytes, the payload sealed with nonce = iv XOR pn over that header,
 * then header protection from the sample four bytes past the packet number. */
static size_t build_packet(lc_qaead *aead, lc_qhp *hp, const uint8_t iv[LC_AEAD_NONCE], int phase,
                           const uint8_t *dcid, size_t dcidlen, int64_t pkt_num, size_t pn_len,
                           size_t payload_len, uint8_t *out)
{
    size_t off = 0;
    out[off++] = (uint8_t)(0x40u | (phase ? 0x04u : 0u) | (uint8_t)(pn_len - 1u));
    memcpy(out + off, dcid, dcidlen);
    off += dcidlen;
    size_t pn_off = off;
    for (size_t i = 0; i < pn_len; i++)
        out[off++] = (uint8_t)((uint64_t)pkt_num >> (8u * (pn_len - 1u - i)));
    uint8_t payload[1500];
    for (size_t i = 0; i < payload_len; i++)
        payload[i] = (uint8_t)(i * 7u + (size_t)pkt_num);
    uint8_t nonce[LC_AEAD_NONCE];
    memcpy(nonce, iv, sizeof nonce);
    for (unsigned i = 0; i < 8u; i++)
        nonce[LC_AEAD_NONCE - 1u - i] ^= (uint8_t)((uint64_t)pkt_num >> (8u * i));
    size_t written = 0;
    if (lc_aead_seal(&aead->aead, nonce, out, off, payload, payload_len, out + off,
                     payload_len + LC_AEAD_TAG, &written) != 0)
        return 0;
    size_t len = off + written;
    uint8_t mask[5];
    if (lc_qhp_mask(hp, out + pn_off + 4u, mask) != 0)
        return 0;
    out[0] ^= (uint8_t)(mask[0] & 0x1fu);
    for (size_t i = 0; i < pn_len; i++)
        out[pn_off + i] ^= mask[1u + i];
    return len;
}

/* What ngtcp2's conn_recv_pkt hands the two callbacks for this packet, computed its way: the
 * sample's place, the mask, the unprotected header as aad, the nonce from `max_pkt_num`. Then both
 * callbacks are called with `h` set and with no hint, and every output compared. Returns 1 when the
 * two agree; *used says whether the decrypt answered from the hint. */
static int callbacks_agree(lc_qaead *conn_aead, lc_qhp *conn_hp, const uint8_t iv[LC_AEAD_NONCE],
                           size_t dcidlen, int64_t max_pkt_num, const uint8_t *pkt, size_t len,
                           const lc_qhint *h, int *used)
{
    ngtcp2_crypto_cipher_ctx hp_ctx = { .native_handle = conn_hp };
    ngtcp2_crypto_aead_ctx   aead_ctx = { .native_handle = conn_aead };
    size_t                   pn_off = 1u + dcidlen;
    const uint8_t           *sample = pkt + pn_off + 4u;

    uint8_t m1[16] = { 0 }, m2[16] = { 0 };
    lc_qcrypto_hint(h);
    int r1 = ngtcp2_crypto_hp_mask(m1, NULL, &hp_ctx, sample);
    lc_qcrypto_hint(NULL);
    int r2 = ngtcp2_crypto_hp_mask(m2, NULL, &hp_ctx, sample);
    if (r1 != r2 || memcmp(m1, m2, 5) != 0)
        return 0;

    uint8_t hdr[64];
    memcpy(hdr, pkt, pn_off);
    hdr[0] = (uint8_t)(pkt[0] ^ (m2[0] & 0x1fu));
    size_t  pn_len = (size_t)(hdr[0] & 0x03u) + 1u;
    int64_t truncated = 0;
    for (size_t i = 0; i < pn_len; i++) {
        hdr[pn_off + i] = (uint8_t)(pkt[pn_off + i] ^ m2[1u + i]);
        truncated = truncated << 8 | hdr[pn_off + i];
    }
    /* ngtcp2_pkt_adjust_pkt_num */
    uint64_t expected = (uint64_t)max_pkt_num + 1u, win = 1ull << (pn_len * 8u), hwin = win / 2u;
    uint64_t cand = (expected & ~(win - 1u)) | (uint64_t)truncated;
    if (cand + hwin <= expected)
        cand += win;
    else if (cand > expected + hwin && cand >= win)
        cand -= win;
    uint8_t nonce[LC_AEAD_NONCE];
    memcpy(nonce, iv, sizeof nonce);
    for (unsigned i = 0; i < 8u; i++)
        nonce[LC_AEAD_NONCE - 1u - i] ^= (uint8_t)(cand >> (8u * i));

    const uint8_t *ct = pkt + pn_off + pn_len;
    size_t         ct_len = len - pn_off - pn_len;
    static uint8_t d1[2048], d2[2048];
    memset(d1, 0xaa, sizeof d1);
    memset(d2, 0xaa, sizeof d2);
    unsigned long long a0, m0, a1, mm1;
    lc_qcrypto_hint_counts(&a0, &m0);
    lc_qcrypto_hint(h);
    int e1 = ngtcp2_crypto_decrypt(d1, NULL, &aead_ctx, ct, ct_len, nonce, LC_AEAD_NONCE, hdr,
                                   pn_off + pn_len);
    lc_qcrypto_hint(NULL);
    lc_qcrypto_hint_counts(&a1, &mm1);
    int e2 = ngtcp2_crypto_decrypt(d2, NULL, &aead_ctx, ct, ct_len, nonce, LC_AEAD_NONCE, hdr,
                                   pn_off + pn_len);
    *used = a1 > a0;
    return e1 == e2 && memcmp(d1, d2, sizeof d1) == 0;
}

/* The mask asked for with the hint set and without it: 1 when the two agree. Given inputs the hint
 * was not made from, agreeing means the hint did not answer — its mask is not this one. */
static int mask_unhinted(lc_qhp *hp, const lc_qhint *h, const uint8_t *sample)
{
    ngtcp2_crypto_cipher_ctx ctx = { .native_handle = hp };
    uint8_t                  m1[16] = { 0 }, m2[16] = { 0 };
    lc_qcrypto_hint(h);
    int r1 = ngtcp2_crypto_hp_mask(m1, NULL, &ctx, sample);
    lc_qcrypto_hint(NULL);
    int r2 = ngtcp2_crypto_hp_mask(m2, NULL, &ctx, sample);
    return r1 == 0 && r2 == 0 && memcmp(m1, m2, sizeof m1) == 0;
}

/* The same for decrypt, and here the counters also say the hint did not answer. */
static int decrypt_unhinted(lc_qaead *a, const lc_qhint *h, const uint8_t *ct, size_t ct_len,
                            const uint8_t *nonce, const uint8_t *aad, size_t aad_len)
{
    ngtcp2_crypto_aead_ctx ctx = { .native_handle = a };
    static uint8_t         d1[2048], d2[2048];
    memset(d1, 0xaa, sizeof d1);
    memset(d2, 0xaa, sizeof d2);
    unsigned long long a0, m0, a1, m1;
    lc_qcrypto_hint_counts(&a0, &m0);
    lc_qcrypto_hint(h);
    int e1 = ngtcp2_crypto_decrypt(d1, NULL, &ctx, ct, ct_len, nonce, LC_AEAD_NONCE, aad, aad_len);
    lc_qcrypto_hint(NULL);
    lc_qcrypto_hint_counts(&a1, &m1);
    int e2 = ngtcp2_crypto_decrypt(d2, NULL, &ctx, ct, ct_len, nonce, LC_AEAD_NONCE, aad, aad_len);
    return a1 == a0 && e1 == e2 && memcmp(d1, d2, sizeof d1) == 0;
}

static void random_key(uint8_t *k, size_t n)
{
    if (lc_rnd(k, n) != 0)
        memset(k, 0x5a, n);
}

static void one_suite(lc_aead_alg alg, const char *name)
{
    uint8_t key[32], hpkey[32], key2[32], iv[LC_AEAD_NONCE], dcid[8];
    random_key(key, sizeof key);
    random_key(hpkey, sizeof hpkey);
    random_key(key2, sizeof key2);
    random_key(iv, sizeof iv);
    random_key(dcid, sizeof dcid);

    /* The connection's contexts, as ngtcp2 holds them, and the opener's, made from the same bytes. */
    static lc_qaead conn_aead, conn_aead2;
    static lc_qhp   conn_hp;
    lc_qaead_init(&conn_aead, alg, key);
    lc_qaead_init(&conn_aead2, alg, key2);
    lc_qhp_init(&conn_hp, alg, hpkey);

    static lc_obfs obfs;
    lc_obfs_init(&obfs, "stand-obfs-0123456789");

    static lc_rxkeys k;
    memset(&k, 0, sizeof k);
    k.have_aead = lc_qaead_init(&k.aead, alg, key) == 0;
    k.have_hp = lc_qhp_init(&k.hp, alg, hpkey) == 0;
    memcpy(k.iv, iv, sizeof iv);
    k.key_phase = 1;
    k.dcidlen = 0; /* the parrot's SCID: no DCID on a short header */
    k.valid = k.have_aead && k.have_hp;

    unsigned agree = 0, total = 0, answered = 0, short_ones = 0, short_hinted = 0;
    char     what[160];

    /* Expected: every packet number length, near and far from the largest received, every size —
     * and with the largest just short of 2^8, 2^16 and 2^24, so that the numbers after it cross
     * the window their truncated form is decoded in, and must be widened as ngtcp2 widens them. */
    static const int64_t largest[] = { 70000, 250, 65530, 16777210 };
    for (size_t li = 0; li < sizeof largest / sizeof largest[0]; li++) {
        k.max_pkt_num = largest[li];
        for (size_t pn_len = 1; pn_len <= 4u; pn_len++) {
            for (int64_t d = -3; d <= 40; d += 7) {
                for (size_t pl = 1; pl <= 1400u; pl += 233u) {
                    static lc_rxslot s;
                    uint8_t          pkt[2048];
                    size_t           len = build_packet(&conn_aead, &conn_hp, iv, 1, dcid, 0,
                                                        k.max_pkt_num + d, pn_len, pl, pkt);
                    long wl = lc_obfs_wrap(&obfs, pkt, len, s.raw, sizeof s.raw);
                    if (len == 0 || wl < 0) {
                        total++;
                        continue;
                    }
                    s.raw_len = (size_t)wl;
                    lc_rxopen_slot(&obfs, &k, &s);
                    int used = 0;
                    if (len < 1u + 4u + 16u) {
                        /* Too short to sample: decrypt_hp refuses it before either callback is
                         * called, and the opener leaves it alone. */
                        short_ones++;
                        if (s.hint.have_mask || s.hint.have_open)
                            short_hinted++;
                        continue;
                    }
                    total++;
                    if (s.plain_len == (long)len && memcmp(s.plain, pkt, len) == 0 &&
                        callbacks_agree(&conn_aead, &conn_hp, iv, 0, k.max_pkt_num, s.plain, len,
                                        &s.hint, &used))
                        agree++;
                    answered += (unsigned)used;
                }
            }
        }
    }
    snprintf(what, sizeof what, "%s: %u packets, the callbacks' answers with the hint are theirs "
                                "without it (%u answered from it)",
             name, total, answered);
    ok(agree == total && answered == total, what);
    snprintf(what, sizeof what, "%s: %u packets too short to sample get no hint", name, short_ones);
    ok(short_ones > 0u && short_hinted == 0u, what);

    /* A broken tag: the hint says so, and the callback refuses exactly as it would itself. */
    {
        static lc_rxslot s;
        uint8_t          pkt[2048];
        size_t len = build_packet(&conn_aead, &conn_hp, iv, 1, dcid, 0, k.max_pkt_num + 1, 2, 600,
                                  pkt);
        pkt[len - 1u] ^= 0x01u;
        long wl = lc_obfs_wrap(&obfs, pkt, len, s.raw, sizeof s.raw);
        s.raw_len = (size_t)wl;
        lc_rxopen_slot(&obfs, &k, &s);
        int used = 0;
        int same = callbacks_agree(&conn_aead, &conn_hp, iv, 0, k.max_pkt_num, s.plain, len,
                                   &s.hint, &used);
        snprintf(what, sizeof what, "%s: a tag that does not verify — refused from the hint, "
                                    "output wiped as lc_aead_open wipes it",
                 name);
        ok(same && used && !s.hint.opened, what);
    }

    /* Opened ahead with a key the connection has since replaced: the callback is given the new
     * key, so the hint must not answer — and what it computes is what it always computed. */
    {
        static lc_rxslot s;
        uint8_t          pkt[2048];
        size_t len = build_packet(&conn_aead, &conn_hp, iv, 1, dcid, 0, k.max_pkt_num + 1, 2, 600,
                                  pkt);
        long wl = lc_obfs_wrap(&obfs, pkt, len, s.raw, sizeof s.raw);
        s.raw_len = (size_t)wl;
        lc_rxopen_slot(&obfs, &k, &s);
        int used = 1;
        int same = callbacks_agree(&conn_aead2, &conn_hp, iv, 0, k.max_pkt_num, s.plain, len,
                                   &s.hint, &used);
        snprintf(what, sizeof what, "%s: a hint made with another key is not used", name);
        ok(same && !used, what);
    }

    /* A packet number the opener decoded against a stale largest, differently from ngtcp2: the
     * nonce differs, and the hint must not answer. */
    {
        static lc_rxslot s;
        uint8_t          pkt[2048];
        size_t len = build_packet(&conn_aead, &conn_hp, iv, 1, dcid, 0, k.max_pkt_num + 100, 1,
                                  600, pkt);
        long wl = lc_obfs_wrap(&obfs, pkt, len, s.raw, sizeof s.raw);
        s.raw_len = (size_t)wl;
        lc_rxopen_slot(&obfs, &k, &s);
        int used = 1;
        int same = callbacks_agree(&conn_aead, &conn_hp, iv, 0, k.max_pkt_num + 300, s.plain, len,
                                   &s.hint, &used);
        snprintf(what, sizeof what, "%s: a packet number decoded otherwise is not answered from "
                                    "the hint",
                 name);
        ok(same && !used, what);
    }

    /* The Key Phase bit flipped: ngtcp2 would reach for another key, so the opener leaves it. */
    {
        static lc_rxslot s;
        uint8_t          pkt[2048];
        size_t len = build_packet(&conn_aead, &conn_hp, iv, 0, dcid, 0, k.max_pkt_num + 1, 2, 600,
                                  pkt);
        long wl = lc_obfs_wrap(&obfs, pkt, len, s.raw, sizeof s.raw);
        s.raw_len = (size_t)wl;
        lc_rxopen_slot(&obfs, &k, &s);
        snprintf(what, sizeof what, "%s: a changed key phase is left to ngtcp2 (mask only)", name);
        ok(s.hint.have_mask && !s.hint.have_open, what);
    }

    /* A long header — a handshake packet — is not opened ahead at all. */
    {
        static lc_rxslot s;
        uint8_t          pkt[64] = { 0xc0u };
        long             wl = lc_obfs_wrap(&obfs, pkt, sizeof pkt, s.raw, sizeof s.raw);
        s.raw_len = (size_t)wl;
        lc_rxopen_slot(&obfs, &k, &s);
        snprintf(what, sizeof what, "%s: a long header gets no hint", name);
        ok(s.plain_len == (long)sizeof pkt && !s.hint.have_mask && !s.hint.have_open, what);
    }

    /* Each input the callbacks compare, changed alone on a packet the hint answers whole: the
     * sample read from another place, another header protection key, the ciphertext from another
     * buffer, another header. None of them is answered from the hint. */
    {
        static lc_rxslot s;
        static lc_qhp    conn_hp2;
        uint8_t          pkt[2048], hpkey2[32];
        random_key(hpkey2, sizeof hpkey2);
        lc_qhp_init(&conn_hp2, alg, hpkey2);
        size_t len = build_packet(&conn_aead, &conn_hp, iv, 1, dcid, 0, k.max_pkt_num + 1, 2, 600,
                                  pkt);
        long wl = lc_obfs_wrap(&obfs, pkt, len, s.raw, sizeof s.raw);
        s.raw_len = (size_t)wl;
        lc_rxopen_slot(&obfs, &k, &s);
        const lc_qhint *h = &s.hint;

        uint8_t sample[16];
        memcpy(sample, h->sample, sizeof sample);
        sample[0] ^= 0x01u;
        snprintf(what, sizeof what, "%s: a sample read from elsewhere is not answered from the hint",
                 name);
        ok(h->have_open && h->opened && mask_unhinted(&conn_hp, h, sample), what);
        snprintf(what, sizeof what, "%s: another header protection key is not answered from it",
                 name);
        ok(mask_unhinted(&conn_hp2, h, h->sample), what);

        static uint8_t ct[2048];
        memcpy(ct, h->ct, h->ct_len);
        ct[0] ^= 0x01u;
        snprintf(what, sizeof what, "%s: a ciphertext from another buffer is not answered from it",
                 name);
        ok(decrypt_unhinted(&conn_aead, h, ct, h->ct_len, h->nonce, h->aad, h->aad_len), what);

        uint8_t aad[sizeof h->aad];
        memcpy(aad, h->aad, h->aad_len);
        aad[h->aad_len - 1u] ^= 0x01u;
        snprintf(what, sizeof what, "%s: another header is not answered from it", name);
        ok(decrypt_unhinted(&conn_aead, h, h->ct, h->ct_len, h->nonce, aad, h->aad_len), what);
        lc_qhp_free(&conn_hp2);
    }

    /* The threads: batches opened by the pool, each slot as this thread opens it alone. */
    {
        lc_rxopen *r = NULL;
        four_core_fixture = 1;
        int        made = lc_rxopen_new(&r, &obfs) == 0;
        four_core_fixture = 0;
        unsigned   batches = 0, bad = 0, excess_wakes = 0;
        static lc_rxslot alone;
        for (unsigned round = 0; made && round < 200u; round++) {
            lc_rxbatch *b = lc_rxopen_batch(r, round);
            b->n = round % (LC_RXOPEN_BATCH + 1u);
            for (unsigned i = 0; i < b->n; i++) {
                uint8_t pkt[2048];
                size_t  len = build_packet(&conn_aead, &conn_hp, iv, 1, dcid, 0,
                                           k.max_pkt_num + 1 + (int64_t)i, 2,
                                           100u + (size_t)((round * 31u + i * 17u) % 1300u), pkt);
                if (i == 7u)
                    pkt[len - 2u] ^= 0x80u; /* one tag broken in every batch */
                long wl = lc_obfs_wrap(&obfs, pkt, len, b->slot[i].raw, sizeof b->slot[i].raw);
                b->slot[i].raw_len = (size_t)wl;
            }
            /* lc_rxopen_start takes the keys from a connection; here there is none, so the test's
             * keys are put in place of that and the batch handed out with no connection. */
            lc_rxkeys_free(&b->keys);
            b->keys.have_aead = lc_qaead_init(&b->keys.aead, alg, key) == 0;
            b->keys.have_hp = lc_qhp_init(&b->keys.hp, alg, hpkey) == 0;
            memcpy(b->keys.iv, iv, sizeof iv);
            b->keys.key_phase = 1;
            b->keys.max_pkt_num = k.max_pkt_num;
            b->keys.dcidlen = 0;
            b->keys.valid = 1;
            signals = broadcasts = 0u;
            observe_dispatch = 1;
            lc_rxopen_hand(r, b);
            observe_dispatch = 0;
            if (b->n < 3u ? (broadcasts != 0u || signals != b->n)
                          : (broadcasts != 1u || signals != 0u))
                excess_wakes++;
            lc_rxopen_finish(r);
            batches++;
            for (unsigned i = 0; i < b->n; i++) {
                memcpy(alone.raw, b->slot[i].raw, b->slot[i].raw_len);
                alone.raw_len = b->slot[i].raw_len;
                lc_rxopen_slot(&obfs, &k, &alone);
                const lc_qhint *x = &b->slot[i].hint, *y = &alone.hint;
                if (b->slot[i].plain_len != alone.plain_len ||
                    memcmp(b->slot[i].plain, alone.plain, (size_t)alone.plain_len) != 0 ||
                    x->have_open != y->have_open || x->opened != y->opened ||
                    memcmp(x->mask, y->mask, sizeof x->mask) != 0 ||
                    memcmp(x->nonce, y->nonce, sizeof x->nonce) != 0 ||
                    (x->opened && memcmp(b->slot[i].opened, alone.opened, x->ct_len - LC_AEAD_TAG) != 0))
                    bad++;
            }
        }
        snprintf(what, sizeof what, "%s: %u batches opened by the threads, every slot as opened "
                                    "alone (%u differ)",
                 name, batches, bad);
        ok(made && batches == 200u && bad == 0u, what);
        signals = broadcasts = 0u;
        observe_dispatch = 1;
        lc_rxopen_free(r);
        observe_dispatch = 0;
        ok(made && broadcasts == 1u && signals == 0u, "stop wakes the complete opener pool");
        ok(made && excess_wakes == 0u,
           "empty batches wake nobody; small batches wake only their work; full batches use all workers");
    }

    lc_rxkeys_free(&k);
    lc_qaead_free(&conn_aead);
    lc_qaead_free(&conn_aead2);
    lc_qhp_free(&conn_hp);
}

int main(void)
{
    printf("the node's packets opened ahead, and the callbacks that answer from it\n");
    startup_failure_suite();
    one_suite(LC_AEAD_CHACHA20_POLY1305, "ChaCha20-Poly1305");
    one_suite(LC_AEAD_AES_128_GCM, "AES-128-GCM");
    one_suite(LC_AEAD_AES_256_GCM, "AES-256-GCM");
    if (failures) {
        printf("%d FAILED\n", failures);
        return 1;
    }
    printf("all good\n");
    return 0;
}
