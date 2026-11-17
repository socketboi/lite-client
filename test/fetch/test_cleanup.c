/* White-box observations, with production feed/wait/step/take/completion drivers below.
 * The direct local predicate checks supplement rather than replace scheduler coverage. */
#include "core/gozip.h"
#include <pthread.h>
static int observed_cond_broadcast(pthread_cond_t *cond);
static int observed_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);
static int observed_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr);
static int observed_cond_destroy(pthread_cond_t *cond);
static int observed_mutex_unlock(pthread_mutex_t *mutex);
static int paused_gzip_read(lc_gozip *z, size_t cap, const uint8_t **out, size_t *n, int *err);
#define lc_gozip_read paused_gzip_read
#define lc_redirect paused_redirect
#define lc_spider_sink_commit observed_sink_commit
#define pthread_cond_broadcast observed_cond_broadcast
#define pthread_cond_wait observed_cond_wait
#define pthread_cond_init observed_cond_init
#define pthread_cond_destroy observed_cond_destroy
#define pthread_mutex_unlock observed_mutex_unlock
#include "../../src/reality/fetch.c"
#undef pthread_mutex_unlock
#undef pthread_cond_broadcast
#undef pthread_cond_wait
#undef pthread_cond_init
#undef pthread_cond_destroy
#undef lc_redirect
#undef lc_spider_sink_commit
#undef lc_gozip_read
#include <stdio.h>
#include <stdatomic.h>
#include <zlib.h>

int lc_redirect(const lc_url *first, int stripped, const lc_url *base, const char *location,
                size_t ln, lc_url *next, lc_redir *r);
static pthread_mutex_t prep_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t prep_changed = PTHREAD_COND_INITIALIZER;
static int prep_pause, prep_entered, prep_release;
static int harvest_pause, harvest_entered, harvest_release;
static int gzip_pause, gzip_entered, gzip_release;
static atomic_uint harvest_commits;
static _Atomic(pthread_cond_t *) watched_request_cond;
static _Atomic(pthread_cond_t *) watched_do_cond;
static _Atomic(pthread_mutex_t *) watched_wait_mutex;
static atomic_uint request_notifications;
static atomic_uint do_notifications;
static atomic_uint failed_cond_at, cond_initializations, cond_destructions;
static pthread_mutex_t wait_watch_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wait_watch_changed = PTHREAD_COND_INITIALIZER;
static int wait_watch_seen;

static int observed_cond_broadcast(pthread_cond_t *cond)
{
    if (cond == atomic_load(&watched_request_cond))
        atomic_fetch_add(&request_notifications, 1u);
    if (cond == atomic_load(&watched_do_cond))
        atomic_fetch_add(&do_notifications, 1u);
    return pthread_cond_broadcast(cond);
}

static int observed_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
    if (mutex == atomic_load(&watched_wait_mutex)) {
        if (cond != atomic_load(&watched_request_cond)) {
            fprintf(stderr, "FAIL: request task waits on its own notification channel\n");
            exit(1);
        }
        pthread_mutex_lock(&wait_watch_lock);
        wait_watch_seen = 1;
        pthread_cond_broadcast(&wait_watch_changed);
        pthread_mutex_unlock(&wait_watch_lock);
    }
    return pthread_cond_wait(cond, mutex);
}

static int observed_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr)
{
    if (atomic_load(&failed_cond_at) != 0u &&
        atomic_fetch_add(&cond_initializations, 1u) + 1u == atomic_load(&failed_cond_at))
        return EAGAIN;
    return pthread_cond_init(cond, attr);
}

static int observed_cond_destroy(pthread_cond_t *cond)
{
    if (atomic_load(&failed_cond_at) != 0u)
        atomic_fetch_add(&cond_destructions, 1u);
    return pthread_cond_destroy(cond);
}

/* This checkpoint stands inside the private decoder, not inside its pipe Read.
 * No timing delay or production callback is added. */
static int paused_gzip_read(lc_gozip *z, size_t cap, const uint8_t **out, size_t *n, int *err)
{
    pthread_mutex_lock(&prep_lock);
    if (gzip_pause) {
        gzip_entered = 1;
        pthread_cond_broadcast(&prep_changed);
        while (!gzip_release)
            pthread_cond_wait(&prep_changed, &prep_lock);
    }
    pthread_mutex_unlock(&prep_lock);
    return lc_gozip_read(z, cap, out, n, err);
}

void lc_spider_sink_commit(lc_spider_sink *sink);

/* Count the actual commit call returning, not a later random draw from the path set.
 * These fixtures do not inject sink OOM; this is not an allocation-success metric. */
void observed_sink_commit(lc_spider_sink *sink)
{
    pthread_mutex_lock(&prep_lock);
    if (harvest_pause) {
        harvest_entered = 1;
        pthread_cond_broadcast(&prep_changed);
        while (!harvest_release)
            pthread_cond_wait(&prep_changed, &prep_lock);
    }
    pthread_mutex_unlock(&prep_lock);
    lc_spider_sink_commit(sink);
    atomic_fetch_add(&harvest_commits, 1u);
}

/* A test checkpoint, not a protocol delay: the producer decides exactly when to release Do. */
int paused_redirect(const lc_url *first, int stripped, const lc_url *base, const char *location,
                    size_t ln, lc_url *next, lc_redir *r)
{
    pthread_mutex_lock(&prep_lock);
    if (prep_pause) {
        prep_entered = 1;
        pthread_cond_broadcast(&prep_changed);
        while (!prep_release)
            pthread_cond_wait(&prep_changed, &prep_lock);
    }
    pthread_mutex_unlock(&prep_lock);
    return lc_redirect(first, stripped, base, location, ln, next, r);
}

static void require(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
    printf("  ok    %s\n", message);
}

static lc_spider_fetch *boundary_fetch;
static pthread_t boundary_owner;
static pthread_mutex_t boundary_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t boundary_changed = PTHREAD_COND_INITIALIZER;
static int boundary_seen, boundary_done, boundary_stop, boundary_reset;

static int observed_mutex_unlock(pthread_mutex_t *mutex)
{
    int boundary = boundary_fetch != NULL && mutex == &boundary_fetch->lock &&
                   pthread_equal(pthread_self(), boundary_owner) && !boundary_seen &&
                   boundary_fetch->ccs->streams->resp &&
                   boundary_fetch->ccs->streams->pb_len == 0u &&
                   boundary_fetch->ccs->rr < boundary_fetch->ccs->rw;
    int rc = pthread_mutex_unlock(mutex);
    if (boundary) {
        struct timespec deadline;
        require(clock_gettime(CLOCK_REALTIME, &deadline) == 0, "frame boundary clock");
        deadline.tv_sec += 3;
        pthread_mutex_lock(&boundary_lock);
        boundary_seen = 1;
        pthread_cond_broadcast(&boundary_changed);
        while (!boundary_done)
            require(pthread_cond_timedwait(&boundary_changed, &boundary_lock, &deadline) == 0,
                    "consumer runs before buffered DATA without another feed");
        pthread_mutex_unlock(&boundary_lock);
    }
    return rc;
}

static void *boundary_consumer(void *arg)
{
    lc_spider_fetch *f = arg;
    pthread_mutex_lock(&boundary_lock);
    while (!boundary_seen)
        pthread_cond_wait(&boundary_changed, &boundary_lock);
    pthread_mutex_unlock(&boundary_lock);
    if (boundary_stop)
        lc_spider_fetch_stop(f);
    else {
        require(lc_spider_fetch_step(f, 0) == 1 && lc_spider_fetch_step(f, 0) >= 0,
                "Do handles redirect and closes the still-empty body");
        require(f->ccs->streams->p_break, "Body.Close precedes coalesced DATA in this interleaving");
        if (boundary_reset)
            require(lc_spider_fetch_request_step(f) == 1 && f->cuts == 1u,
                    "request task queues its real reset before the readLoop resumes");
    }
    pthread_mutex_lock(&boundary_lock);
    boundary_done = 1;
    pthread_cond_broadcast(&boundary_changed);
    pthread_mutex_unlock(&boundary_lock);
    return NULL;
}

static void test_write_buffer_ownership(void)
{
    for (unsigned barrier = 0; barrier < 2u; barrier++) {
        lc_browser browser;
        require(lc_browser_chrome_anchored(&browser, LC_BROWSER_NAV) == 0,
                "write ownership browser");
        lc_spider_fetch *f = lc_spider_fetch_new("write-owner.example", &browser);
        require(f != NULL, "write ownership fetch");
        if (barrier)
            require(lc_spider_fetch_write_barrier(f) == 0, "write ownership barrier");
        require(f->cuts == 1u && f->out_len > 0u, "one whole opening Write");
        size_t opening_len = f->out_len;
        uint8_t *opening = f->out, *write = NULL;
        uint8_t expected[128];
        require(opening_len <= sizeof expected, "opening fits the byte fixture");
        memcpy(expected, opening, opening_len);
        require(lc_spider_fetch_take(f, &write) == (long)opening_len && write == opening &&
                    memcmp(write, expected, opening_len) == 0 && f->out == NULL &&
                    f->cuts == 0u && f->out_len == 0u && f->out_cap == 0u,
                "last Write transfers owned storage without a copy");
        const uint8_t first[] = {0, 1, 2}, second[] = {3, 4, 5, 6, 7};
        put_write(f, NULL, first, sizeof first);
        put_write(f, NULL, second, sizeof second);
        require(memcmp(write, expected, opening_len) == 0 && f->out != write,
                "later queued Writes cannot overwrite the detached opening");
        if (barrier) {
            uint8_t *blocked = (uint8_t *)f;
            require(lc_spider_fetch_take(f, &blocked) == 0 && blocked == NULL &&
                        f->cuts == 2u && f->ccs->opening_write_id != 0u,
                    "ownership transfer does not complete the opening Write");
            require(lc_spider_fetch_write_complete(f, 1) == 0,
                    "actual opening completion releases its owner");
        }
        free(write);
        uint8_t *queued = f->out;
        require(lc_spider_fetch_take(f, &write) == (long)sizeof first &&
                    write != queued && memcmp(write, first, sizeof first) == 0 &&
                    f->cuts == 1u && f->out == queued &&
                    memcmp(f->out, second, sizeof second) == 0,
                "prefix Write keeps later queued bytes and boundaries intact");
        if (barrier)
            require(lc_spider_fetch_write_complete(f, 1) == 0,
                    "prefix Write completes separately");
        free(write);
        require(lc_spider_fetch_take(f, &write) == (long)sizeof second && write == queued &&
                    memcmp(write, second, sizeof second) == 0,
                "last remaining Write transfers after prefix removal");
        if (barrier)
            require(lc_spider_fetch_write_complete(f, 0) == 0 && f->closed,
                    "failed detached Write still closes the connection");
        lc_spider_fetch_free(f);
        require(memcmp(write, second, sizeof second) == 0,
                "detached Write remains caller-owned after fetch destruction");
        free(write);
    }
}

static void input_frame(lc_spider_fetch *f, uint8_t type, uint8_t flags, uint32_t stream,
                        const uint8_t *payload, size_t n)
{
    uint8_t input[6000];
    require(n + LC_H2_HEADER <= sizeof input, "fixture frame fits");
    (void)lc_h2_put_header(input, sizeof input, (uint32_t)n, type, flags, stream);
    if (n != 0u)
        memcpy(input + LC_H2_HEADER, payload, n);
    require(lc_spider_fetch_feed(f, input, LC_H2_HEADER + n) == 0,
            "public feed accepts the fixture frame");
}

static lc_spider_fetch *driver_fixture_mode(uint8_t **request, int split)
{
    lc_browser b;
    require(lc_browser_chrome_anchored(&b, LC_BROWSER_NAV) == 0, "driver browser");
    lc_spider_fetch *f = lc_spider_fetch_new("cleanup-driver.example", &b);
    require(f != NULL && lc_spider_fetch_write_barrier(f) == 0, "completion driver fixture");
    if (split)
        require(lc_spider_fetch_request_tasks(f) == 0, "split tasks enabled before publication");
    uint8_t *bytes = NULL;
    require(lc_spider_fetch_take(f, &bytes) > 0 && lc_spider_fetch_write_complete(f, 1) == 0,
            "driver completes the opening Write");
    free(bytes);
    input_frame(f, LC_H2_SETTINGS, 0, 0, NULL, 0);
    require(lc_spider_fetch_take(f, &bytes) == 9 && lc_spider_fetch_write_complete(f, 1) == 0,
            "driver completes SETTINGS ACK");
    free(bytes);
    if (split)
        require(lc_spider_fetch_read_step(f) == 1 && lc_spider_fetch_read_ready(f),
                "loop owner resumes initial SETTINGS after its own ACK Flush");
    require(lc_spider_fetch_step(f, 0) == 1, "Do submits its initial request");
    if (split)
        require(lc_spider_fetch_request_step(f) == 1,
                "request task admits the initial stream before encoding");
    if (split)
        require(f->cuts == 0u && lc_spider_fetch_request_wait(f) == 1 &&
                    lc_spider_fetch_request_step(f) == 1,
                "only the separately ready request task writes initial HEADERS");
    require(lc_spider_fetch_take(f, request) > 9,
            "driver holds the actual request Write");
    return f;
}

static lc_spider_fetch *driver_fixture(uint8_t **request)
{
    return driver_fixture_mode(request, 0);
}

/* Force one permitted interleaving only in the fixture. The production parser
 * neither waits for Do nor chooses a winner between HEADERS and following DATA. */
static void test_coalesced_frame_consumer(void)
{
    for (int stop = 0; stop < 2; stop++) {
        uint8_t *write = NULL;
        lc_spider_fetch *f = driver_fixture_mode(&write, 1);
        require(lc_spider_fetch_write_complete(f, 1) == 0, "coalesced fixture request completes");
        free(write);
        const lc_hpack_field fields[] = {
            {":status", "302"}, {"location", "/next"}, {"content-length", "5000"}
        };
        uint8_t headers[128], input[5200];
        long hn = lc_hpack_encode(fields, 3u, headers, sizeof headers);
        require(hn > 0, "coalesced redirect encodes");
        size_t n = lc_h2_put_header(input, sizeof input, (uint32_t)hn, LC_H2_HEADERS,
                                   LC_H2_END_HEADERS, f->ccs->streams->id);
        memcpy(input + n, headers, (size_t)hn);
        n += (size_t)hn;
        n += lc_h2_put_header(input + n, sizeof input - n, 5000u, LC_H2_DATA, 0,
                              f->ccs->streams->id);
        memset(input + n, 'x', 5000u);
        n += 5000u;
        boundary_owner = pthread_self();
        boundary_seen = boundary_done = 0;
        boundary_stop = stop;
        boundary_reset = 0;
        boundary_fetch = f;
        pthread_t consumer;
        require(pthread_create(&consumer, NULL, boundary_consumer, f) == 0,
                "coalesced consumer starts");
        require(lc_spider_fetch_feed(f, input, n) == 0 && boundary_seen,
                "one feed permits consumer access between HEADERS and DATA");
        require(pthread_join(consumer, NULL) == 0, "coalesced consumer joins");
        boundary_fetch = NULL;
        require(f->ccs->streams->pb_len == 0u &&
                    (stop ? f->consumer_stopped : f->ccs->streams->p_break),
                "resumed readLoop respects body closure or stop without buffering the DATA");
        if (!stop) {
            require(f->ccs->read_write_id != 0u &&
                        lc_spider_fetch_take(f, &write) == 13 &&
                        write[3] == LC_H2_WINDOW_UPDATE && write[8] == 0u &&
                        r_u32(write + 9u) == 5000u,
                    "late DATA refund restores readLoop ownership after the consumer turn");
            require(lc_spider_fetch_write_complete(f, 1) == 0 &&
                        lc_spider_fetch_read_step(f) >= 0,
                    "readLoop completes its own refund without another consumer turn");
            free(write);
        }
        lc_spider_fetch_free(f);
    }
}

static void test_feed_returns_to_tls_owner(void)
{
    for (unsigned large = 0; large < 2u; large++)
        for (unsigned outcome = 0; outcome < 8u; outcome++) {
            uint8_t *write = NULL;
            lc_spider_fetch *f = driver_fixture_mode(&write, 1);
            require(lc_spider_fetch_write_complete(f, 1) == 0,
                    "feed-yield request completes");
            free(write);
            write = NULL;
            fetch_cc *cc = f->ccs;
            fetch_stream *s = cc->streams;
            int64_t original_credit = cc->in_avail + cc->in_unsent;
            size_t body = large ? 5000u : 32u;
            const lc_hpack_field fields[] = {
                {":status", "302"}, {"location", "/next"}, {"content-length", "5000"}
            };
            uint8_t headers[128], input[5200];
            long hn = lc_hpack_encode(fields, 3u, headers, sizeof headers);
            require(hn > 0, "feed-yield redirect encodes");
            size_t n = lc_h2_put_header(input, sizeof input, (uint32_t)hn,
                                       LC_H2_HEADERS, LC_H2_END_HEADERS, s->id);
            memcpy(input + n, headers, (size_t)hn);
            n += (size_t)hn;
            size_t header_end = n;
            n += lc_h2_put_header(input + n, sizeof input - n, (uint32_t)body,
                                  LC_H2_DATA, 0, s->id);
            memset(input + n, 'x', body);
            n += body;
            boundary_owner = pthread_self();
            boundary_seen = boundary_done = boundary_stop = 0;
            boundary_reset = 1;
            boundary_fetch = f;
            pthread_t consumer;
            require(pthread_create(&consumer, NULL, boundary_consumer, f) == 0,
                    "feed-yield consumer starts");
            require(lc_spider_fetch_feed(f, input, n) == 0 && boundary_seen,
                    "feed-yield accepts the record");
            require(pthread_join(consumer, NULL) == 0, "feed-yield consumer joins");
            boundary_fetch = NULL;
            boundary_reset = 0;
            require(cc->read_pending && !cc->data_pending && !cc->in_payload &&
                        cc->rr < cc->rw && !lc_spider_fetch_read_ready(f) &&
                        cc->in_avail + cc->in_unsent == original_credit,
                    "queued reset returns control before dispatching coalesced DATA");
            require(memcmp(cc->rbuf + cc->rr, input + header_end, cc->rw - cc->rr) == 0 &&
                        (large ? f->held_len == n - H2_BUFIO &&
                                     memcmp(f->held_input, input + H2_BUFIO, f->held_len) == 0 :
                                 f->held_input == NULL),
                    "bufio and record tails are retained byte-for-byte");
            uint8_t *held = f->held_input;
            require(lc_spider_fetch_feed(f, input, n) == -1 && f->held_input == held &&
                        cc->read_pending && cc->in_avail + cc->in_unsent == original_credit,
                    "a second record cannot overwrite a yielded accepted feed");
            if (outcome == 2u) {
                lc_spider_fetch_stop(f);
                require(lc_spider_fetch_read_step(f) == 0 && !cc->data_pending,
                        "stop does not resume the retained DATA");
                lc_spider_fetch_free(f);
                continue;
            }
            if (outcome == 4u) {
                lc_spider_fetch_loss_pending(f);
                require(!f->closed && readloop_pending(f),
                        "EOF cannot overtake the yielded accepted input");
            }
            if (outcome == 7u)
                require(lc_spider_fetch_read_step(f) == 1 && cc->read_pending &&
                            !cc->data_pending && !s->read_aborted &&
                            cc->in_avail + cc->in_unsent == original_credit && f->cuts == 1u,
                        "output queued after the owner checked take wins before retained DATA resumes");
            require(lc_spider_fetch_take(f, &write) == 13 && write[3] == LC_H2_RST_STREAM,
                    "TLS owner takes the reset before the retained DATA");
            if (outcome == 1u) {
                require(lc_spider_fetch_read_step(f) == 1 && !cc->read_pending &&
                            f->held_input == NULL && cc->data_pending == (int)large,
                        "in-flight foreign Write permits retained DATA dispatch");
            }
            require(lc_spider_fetch_write_complete(f, outcome != 3u) == 0,
                    "reset reports its actual socket outcome");
            free(write);
            write = NULL;
            if (outcome == 3u) {
                require(lc_spider_fetch_read_step(f) == -1 &&
                            cc->in_avail + cc->in_unsent == original_credit,
                        "failed reset never dispatches the retained DATA");
                lc_spider_fetch_free(f);
                continue;
            }
            /* Go's reset Flush return, forgetStreamID and final werr acquisition
             * are separate lock scopes. Test all three readLoop opportunities,
             * rather than declaring cleanup completion a DATA dispatch barrier. */
            if (outcome == 5u) {
                require(s->cleanup_pending && !s->forgotten && !s->done &&
                            s->cleanup_write_id == 0u && cc->cleanup_writer == NULL &&
                            s->p_err == LC_GZ_NONE && lc_spider_fetch_request_wait(f) == 1,
                        "reset completion makes cleanup runnable without executing it on TLS owner");
            } else if (outcome == 6u) {
                require(lc_spider_fetch_request_step(f) == 1 && s->forgotten &&
                            s->cleanup_final_pending && !s->done,
                        "DATA may arrive between forgetStreamID and final werr acquisition");
            } else if (outcome != 1u) {
                for (unsigned turn = 0; turn < 4u && !s->done; turn++)
                    require(lc_spider_fetch_request_step(f) == 1,
                            "cleanup resumes after its own reset completion");
                require(s->forgotten && s->done,
                        "cleanup can forget before retained DATA is dispatched");
            }
            require(lc_spider_fetch_read_step(f) >= 0 && !cc->read_pending &&
                        f->held_input == NULL && cc->in_avail + cc->in_unsent == original_credit,
                    "retained DATA is accounted exactly once without another feed");
            if (outcome == 5u)
                require(!s->forgotten && !s->done && s->cleanup_pending &&
                            s->p_break && s->pb_len == 0u && cc->data_reset == (int)large,
                        "DATA on the broken active pipe retains its reset continuation until credit Flush");
            if (outcome == 6u)
                require(s->forgotten && !s->done && s->cleanup_final_pending &&
                            !cc->data_reset,
                        "late DATA uses connection credit without resurrecting the forgotten stream");
            if (large) {
                require(lc_spider_fetch_take(f, &write) == 13 &&
                            write[3] == LC_H2_WINDOW_UPDATE && r_u32(write + 9u) == body &&
                            lc_spider_fetch_write_complete(f, 1) == 0 &&
                            lc_spider_fetch_read_step(f) >= 0,
                        "retained DATA returns exact connection credit through its own Write");
                free(write);
            }
            if (outcome >= 5u) {
                for (unsigned turn = 0; turn < 4u && !s->done; turn++)
                    require(lc_spider_fetch_request_step(f) == 1,
                            "cleanup finishes after independent DATA and its credit Write");
                require(s->done && s->forgotten && f->cuts == 0u &&
                            cc->in_avail + cc->in_unsent == original_credit &&
                            lc_spider_fetch_request_step(f) == 0,
                        "either cleanup interleaving ends once without duplicate CANCEL or credit");
            }
            if (outcome == 4u) {
                for (unsigned turn = 0; turn < 8u && !f->closed; turn++)
                    (void)lc_spider_fetch_step(f, 0);
                require(f->closed && !f->loss_pending && f->cuts == 0u,
                        "EOF applies after retained input, body continuation and Writes finish");
            }
            lc_spider_fetch_free(f);
        }
}

static void test_ready_write_before_new_feed(void)
{
    for (unsigned large = 0; large < 2u; large++) {
        uint8_t *write = NULL;
        lc_spider_fetch *f = driver_fixture_mode(&write, 1);
        require(lc_spider_fetch_write_complete(f, 1) == 0, "new-feed request completes");
        free(write);
        write = NULL;
        fetch_cc *cc = f->ccs;
        fetch_stream *s = cc->streams;
        const lc_hpack_field fields[] = {
            {":status", "302"}, {"location", "/next"}, {"content-length", "5000"}
        };
        uint8_t headers[128], body[5000];
        memset(body, 'x', sizeof body);
        long hn = lc_hpack_encode(fields, 3u, headers, sizeof headers);
        require(hn > 0, "new-feed redirect encodes");
        input_frame(f, LC_H2_HEADERS, LC_H2_END_HEADERS, s->id, headers, (size_t)hn);
        require(lc_spider_fetch_step(f, 0) == 1 && lc_spider_fetch_step(f, 0) >= 0 &&
                    lc_spider_fetch_take(f, &write) == 0 &&
                    lc_spider_fetch_request_step(f) == 1 && f->cuts == 1u,
                "executor queues reset after TLS owner observed an empty queue");
        int64_t avail = cc->in_avail;
        input_frame(f, LC_H2_DATA, 0, s->id, body, large ? sizeof body : 32u);
        require(cc->read_pending && !cc->data_pending && !s->read_aborted &&
                    cc->in_avail == avail && !lc_spider_fetch_read_ready(f),
                "fresh accepted DATA waits for already queued runnable output without parsing");
        require(lc_spider_fetch_take(f, &write) == 13 &&
                    lc_spider_fetch_write_complete(f, 1) == 0,
                "new-feed TLS owner actually completes reset");
        free(write);
        write = NULL;
        for (unsigned turn = 0; turn < 4u && !s->done; turn++)
            require(lc_spider_fetch_request_step(f) == 1, "new-feed cleanup continuation");
        require(s->done && s->forgotten && lc_spider_fetch_read_step(f) == 1 &&
                    f->held_input == NULL && !cc->read_pending,
                "fresh DATA resumes from owned input after cleanup without another feed");
        if (large) {
            require(lc_spider_fetch_take(f, &write) == 13 &&
                        write[3] == LC_H2_WINDOW_UPDATE && r_u32(write + 9u) == sizeof body &&
                        lc_spider_fetch_write_complete(f, 1) == 0 &&
                        lc_spider_fetch_read_step(f) >= 0,
                    "new-feed late DATA returns exactly its connection credit");
            free(write);
        }
        lc_spider_fetch_free(f);
    }
}

struct request_wait_result {
    lc_spider_fetch *fetch;
    int result;
};

static void *request_wait_once(void *arg)
{
    struct request_wait_result *r = arg;
    r->result = lc_spider_fetch_request_wait(r->fetch);
    return NULL;
}

static void *retirement_wait_once(void *arg)
{
    struct request_wait_result *r = arg;
    r->result = lc_spider_fetch_request_wait(r->fetch);
    pthread_mutex_lock(&wait_watch_lock);
    wait_watch_seen = 2;
    pthread_cond_broadcast(&wait_watch_changed);
    pthread_mutex_unlock(&wait_watch_lock);
    return NULL;
}

static void retirement_wait_checkpoint(int wanted, const char *message)
{
    struct timespec deadline;
    require(clock_gettime(CLOCK_REALTIME, &deadline) == 0, "retirement checkpoint clock");
    deadline.tv_sec += 3;
    pthread_mutex_lock(&wait_watch_lock);
    while (wait_watch_seen < wanted)
        require(pthread_cond_timedwait(&wait_watch_changed, &wait_watch_lock, &deadline) == 0,
                message);
    require(wait_watch_seen == wanted, message);
    pthread_mutex_unlock(&wait_watch_lock);
}

static void retirement_watch(lc_spider_fetch *f)
{
    pthread_mutex_lock(&wait_watch_lock);
    wait_watch_seen = 0;
    pthread_mutex_unlock(&wait_watch_lock);
    atomic_store(&watched_request_cond, &f->request_consumer);
    atomic_store(&watched_wait_mutex, &f->lock);
}

static void retirement_unwatch(void)
{
    atomic_store(&watched_wait_mutex, NULL);
    atomic_store(&watched_request_cond, NULL);
}

static void test_task_retirement_driver(void)
{
    uint8_t *bytes = NULL;
    lc_spider_fetch *f = driver_fixture_mode(&bytes, 1);
    require(lc_spider_fetch_write_complete(f, 1) == 0, "retirement request Flush completes");
    free(bytes);
    static const uint8_t status_ok[] = {0x88};
    input_frame(f, LC_H2_HEADERS, LC_H2_END_HEADERS | LC_H2_END_STREAM, 1u,
                status_ok, sizeof status_ok);
    for (unsigned turn = 0; turn < 32u && !f->ccs->streams->done; turn++)
        require(lc_spider_fetch_request_step(f) >= 0, "request cleanup progresses before Do returns");
    require(f->ccs->streams->done && !lc_spider_fetch_done(f),
            "completed request alone cannot retire a future Do producer");
    struct request_wait_result waiter = {f, -99};
    pthread_t thread;
    retirement_watch(f);
    require(pthread_create(&thread, NULL, retirement_wait_once, &waiter) == 0,
            "request executor parks before Do completion");
    retirement_wait_checkpoint(1, "request executor really waits before terminal Do state");
    for (unsigned turn = 0; turn < 32u && !lc_spider_fetch_done(f); turn++) {
        require(lc_spider_fetch_step(f, 0) >= 0, "Do consumes its final response/body");
        ssize_t n;
        while ((n = lc_spider_fetch_take(f, &bytes)) > 0) {
            require(lc_spider_fetch_write_complete(f, 1) == 0, "terminal Do Flush completes");
            free(bytes);
        }
        require(n == 0, "terminal Do output stays valid");
    }
    require(lc_spider_fetch_done(f), "real response completes Do");
    retirement_wait_checkpoint(2, "normal Do completion wakes parked request executor");
    require(pthread_join(thread, NULL) == 0 && waiter.result == 0,
            "request executor returns normally without stopping the fetch");
    retirement_unwatch();
    uint64_t generation = f->generation;
    require(lc_spider_fetch_wait(f, &generation) == 0 && !f->consumer_stopped &&
                !f->closed && lc_spider_fetch_read_ready(f),
            "Do executor completes while the connection and readLoop stay alive");

    uint8_t ping[8] = {1,2,3,4,5,6,7,8};
    input_frame(f, LC_H2_PING, 0, 0, ping, sizeof ping);
    require(lc_spider_fetch_take(f, &bytes) == 17 && bytes[3] == LC_H2_PING,
            "post-retirement readLoop owns a real PING ACK Write");
    free(bytes);
    require(lc_spider_fetch_wait(f, &generation) == 0 &&
                lc_spider_fetch_request_wait(f) == 0 && !f->closed,
            "foreign readLoop Write cannot resurrect completed HTTP executors");
    lc_spider_fetch_loss_pending(f);
    require(lc_spider_fetch_read_step(f) == 0 && f->loss_pending && !f->closed,
            "late EOF waits for the existing readLoop ACK Flush");
    require(lc_spider_fetch_write_complete(f, 1) == 0 &&
                lc_spider_fetch_read_step(f) == -1 && f->closed && !f->loss_pending,
            "readLoop consumes late EOF after the real Write completion without a Do executor");
    lc_spider_fetch_free(f);

    f = driver_fixture_mode(&bytes, 1);
    uint8_t reset[4] = {0,0,0,8};
    input_frame(f, LC_H2_RST_STREAM, 0, 1u, reset, sizeof reset);
    /* Supplement the public driver with a terminal Do checkpoint: an executor
     * must not mistake completed application work for a completed request Flush. */
    do_end(f);
    waiter.fetch = f;
    waiter.result = -99;
    retirement_watch(f);
    require(pthread_create(&thread, NULL, retirement_wait_once, &waiter) == 0,
            "unfinished request executor wait starts after Do checkpoint");
    retirement_wait_checkpoint(1, "Do completion cannot retire a request whose Write is in flight");
    require(lc_spider_fetch_write_complete(f, 1) == 0, "own request Flush releases producer");
    free(bytes);
    retirement_wait_checkpoint(2, "actual Flush completion wakes request cleanup");
    require(pthread_join(thread, NULL) == 0 && waiter.result == 1,
            "request wakes runnable for cleanup, not prematurely completed");
    retirement_unwatch();
    for (unsigned turn = 0; turn < 32u && !f->ccs->streams->done; turn++)
        require(lc_spider_fetch_request_step(f) >= 0, "retained request cleanup executes");
    require(f->ccs->streams->done && lc_spider_fetch_request_wait(f) == 0 && !f->closed,
            "only completed cleanup permits request executor retirement");
    lc_spider_fetch_free(f);
}

static void test_request_notification_channels(void)
{
    for (unsigned outcome = 0; outcome < 3u; outcome++) {
        uint8_t *write = NULL;
        lc_spider_fetch *f = driver_fixture_mode(&write, 1);
        require(lc_spider_fetch_write_complete(f, 1) == 0 && !request_task_ready(f),
                "request waits after its own HEADERS completed");
        free(write);
        atomic_store(&watched_request_cond, &f->request_consumer);
        atomic_store(&request_notifications, 0u);
        const uint8_t nonce[8] = {0};
        input_frame(f, LC_H2_PING, LC_H2_ACK, 0, nonce, sizeof nonce);
        require(atomic_load(&request_notifications) == 0u,
                "unrelated input does not wake the idle request executor");
        require(lc_spider_fetch_step(f, 0) == 0 &&
                    atomic_load(&request_notifications) == 0u,
                "quiescent Do continuation does not notify an idle request executor");
        pthread_mutex_lock(&wait_watch_lock);
        wait_watch_seen = 0;
        atomic_store(&watched_wait_mutex, &f->lock);
        struct request_wait_result result = {f, -99};
        pthread_t thread;
        require(pthread_create(&thread, NULL, request_wait_once, &result) == 0,
                "request waiter starts on the split channel");
        while (!wait_watch_seen)
            pthread_cond_wait(&wait_watch_changed, &wait_watch_lock);
        pthread_mutex_unlock(&wait_watch_lock);
        input_frame(f, LC_H2_PING, LC_H2_ACK, 0, nonce, sizeof nonce);
        require(atomic_load(&request_notifications) == 0u,
                "unrelated input leaves an already sleeping request task unnotified");
        if (outcome == 0u) {
            const uint8_t reset[4] = {0, 0, 0, ERR_CANCEL};
            input_frame(f, LC_H2_RST_STREAM, 0, f->ccs->streams->id, reset, sizeof reset);
        } else if (outcome == 1u) {
            lc_spider_fetch_stop(f);
        } else {
            lc_spider_fetch_lost(f);
        }
        require(pthread_join(thread, NULL) == 0 &&
                    result.result == (outcome == 0u ? 1 : outcome == 1u ? 0 : -1) &&
                    atomic_load(&request_notifications) > 0u,
                "ready work, stop and connection failure wake a sleeping request task");
        atomic_store(&watched_wait_mutex, NULL);
        atomic_store(&watched_request_cond, NULL);
        lc_spider_fetch_free(f);
    }
    for (unsigned failure = 1u; failure <= 2u; failure++) {
        lc_browser browser;
        require(lc_browser_chrome_anchored(&browser, LC_BROWSER_NAV) == 0,
                "condition initialization failure browser");
        atomic_store(&cond_initializations, 0u);
        atomic_store(&cond_destructions, 0u);
        atomic_store(&failed_cond_at, failure);
        lc_spider_fetch *f = lc_spider_fetch_new("condition-owner.example", &browser);
        require(f == NULL && atomic_load(&cond_initializations) == failure &&
                    atomic_load(&cond_destructions) == failure - 1u,
                "failed condition initialization destroys only initialized channels");
        atomic_store(&failed_cond_at, 0u);
    }
}

static void test_cleanup_driver(void)
{
    for (unsigned owner = 0; owner < 2u; owner++)
        for (unsigned teardown = 0; teardown < 3u; teardown++) {
            uint8_t *write = NULL;
            lc_spider_fetch *f = driver_fixture(&write);
            fetch_stream *s = f->ccs->streams;
            if (owner == 0u) {
                require(lc_spider_fetch_write_complete(f, 1) == 0,
                        "request completes before the foreign readLoop Write");
                free(write);
                const uint8_t status = 0x88; /* indexed :status 200 */
                input_frame(f, LC_H2_HEADERS, LC_H2_END_HEADERS | LC_H2_END_STREAM,
                            s->id, &status, 1u);
                const uint8_t nonce[8] = {0};
                input_frame(f, LC_H2_PING, 0, 0, nonce, sizeof nonce);
                require(lc_spider_fetch_take(f, &write) == 17,
                        "foreign PING ACK is in flight");
            } else {
                const uint8_t reset[4] = {0, 0, 0, ERR_CANCEL};
                input_frame(f, LC_H2_RST_STREAM, 0, s->id, reset, sizeof reset);
                require(lc_spider_fetch_step(f, 0) >= 0 && !s->forgotten &&
                            !s->cleanup_final_pending && !s->done && f->cuts == 0u &&
                            s->cc->request_writer == s && s->request_write_id != 0u,
                        "peer abort cannot enter cleanup before its own request Flush returns");
                if (teardown == 1u) {
                    lc_spider_fetch_stop(f);
                    require(lc_spider_fetch_step(f, 0) == 0 && !s->forgotten && !s->done,
                            "stop during own request Write cannot publish cleanup or donec");
                } else if (teardown == 2u) {
                    require(lc_spider_fetch_write_complete(f, 0) == 0 &&
                                lc_spider_fetch_step(f, 0) < 0 && !s->forgotten && !s->done &&
                                s->cc->request_writer == NULL && s->cc->werr,
                            "own request Write error terminates without inventing an entered cleanup");
                } else {
                    uint64_t own_generation = 0;
                    require(lc_spider_fetch_write_complete(f, 1) == 0 &&
                                lc_spider_fetch_wait(f, &own_generation) == 1 && !s->forgotten,
                            "own request completion wakes cleanup without running it inline");
                    require(lc_spider_fetch_step(f, 0) == 1 && s->forgotten &&
                                s->cleanup_final_pending && !s->done &&
                                lc_spider_fetch_step(f, 0) == 1 && s->done && f->cuts == 0u,
                            "peer-aborted request cleans up once after its own Flush without new input");
                }
                lc_spider_fetch_free(f);
                free(write);
                continue;
            }
            uint64_t generation = 0;
            require(lc_spider_fetch_wait(f, &generation) == 1,
                    "production wait admits non-writing cleanup behind a foreign Write owner");
            require(lc_spider_fetch_step(f, 0) == 1 && s->forgotten &&
                        s->cleanup_final_pending && !s->done,
                    "production step forgets the stream before the final writer wait");
            require(lc_spider_fetch_step(f, 0) == 2 && f->cuts == 0u && !s->done,
                    "repeated production step invents no cleanup output or success");
            const uint8_t reset[4] = {0, 0, 0, ERR_PROTOCOL};
            input_frame(f, LC_H2_RST_STREAM, 0, s->id, reset, sizeof reset);
            if (teardown == 1u) {
                lc_spider_fetch_stop(f);
                require(lc_spider_fetch_wait(f, &generation) == 0 &&
                            lc_spider_fetch_step(f, 0) == 0 && !s->done,
                        "stop interrupts scheduler cleanup wait without publishing done");
            } else if (teardown == 2u) {
                require(lc_spider_fetch_write_complete(f, 0) == 0 &&
                            lc_spider_fetch_step(f, 0) < 0 && s->done && s->cc->werr && f->closed,
                        "failed foreign Write ends Do but completes the pending final werr check");
            } else {
                require(lc_spider_fetch_write_complete(f, 1) == 0 &&
                            lc_spider_fetch_wait(f, &generation) == 1,
                        "actual completion wakes cleanup without additional input");
                require(lc_spider_fetch_step(f, 0) == 1 && s->done &&
                            !s->cleanup_final_pending && f->cuts == 0u,
                        "scheduler finalizes forgotten stream once after completion");
                require(s->abort_code != ERR_PROTOCOL && !f->ccs->do_not_reuse,
                        "later input for the forgotten stream cannot mutate it");
            }
            lc_spider_fetch_free(f);
            free(write);
        }
}

/* Even with cc.wmu free, forgetStreamID and the final cc.wmu/werr check are separate
 * acquisitions. Input, stop or another writer may intervene after the forget phase. */
static void test_cleanup_final_phase_driver(void)
{
    for (unsigned order = 0; order < 4u; order++) {
        uint8_t *write = NULL;
        lc_spider_fetch *f = driver_fixture(&write);
        fetch_stream *s = f->ccs->streams;
        require(lc_spider_fetch_write_complete(f, 1) == 0, "final-phase request completes");
        free(write);
        write = NULL;
        const uint8_t status = 0x88;
        input_frame(f, LC_H2_HEADERS, LC_H2_END_HEADERS | LC_H2_END_STREAM,
                    s->id, &status, 1u);
        require(lc_spider_fetch_step(f, 0) == 1 && s->forgotten &&
                    s->cleanup_final_pending && !s->done && !output_pending(f),
                "free-writer cleanup yields after forget before final writer acquisition");
        uint64_t generation = 0;
        if (order == 1u) {
            lc_spider_fetch_stop(f);
            require(lc_spider_fetch_wait(f, &generation) == 0 &&
                        lc_spider_fetch_step(f, 0) == 0 && !s->done,
                    "stop between cleanup acquisitions does not publish donec");
        } else {
            if (order >= 2u) {
                const uint8_t nonce[8] = {0};
                input_frame(f, LC_H2_PING, 0, 0, nonce, sizeof nonce);
                require(lc_spider_fetch_take(f, &write) == 17 &&
                            lc_spider_fetch_step(f, 0) == 2 && !s->done,
                        "new readLoop writer may acquire cc.wmu between cleanup phases");
                require(lc_spider_fetch_write_complete(f, order == 2u) == 0 && !s->done,
                        "completion itself does not execute cleanup's final acquisition");
            }
            require(lc_spider_fetch_wait(f, &generation) == 1,
                    "final cleanup continuation needs no additional input");
            int rc = lc_spider_fetch_step(f, 0);
            require((order == 3u ? rc < 0 : rc == 1) && s->done &&
                        !s->cleanup_final_pending && s->forgotten && f->cuts == 0u,
                    "final writer check closes donec once, including terminal werr");
            require((order == 3u) == (f->closed != 0) &&
                        (order == 3u) == (s->cc->werr != 0),
                    "donec is cleanup completion, not proof that a Write succeeded");
            require(lc_spider_fetch_step(f, 0) >= (order == 3u ? -1 : 0) &&
                        !s->cleanup_final_pending && f->cuts == 0u,
                    "repeated final cleanup does not forget or write twice");
        }
        free(write);
        lc_spider_fetch_free(f);
    }
}

static void test_opening_read_driver(void)
{
    for (unsigned outcome = 0; outcome < 3u; outcome++) {
        lc_browser b;
        require(lc_browser_chrome_anchored(&b, LC_BROWSER_NAV) == 0, "opening browser");
        lc_spider_fetch *f = lc_spider_fetch_new("opening-driver.example", &b);
        require(f != NULL && lc_spider_fetch_write_barrier(f) == 0,
                "opening completion fixture");
        fetch_cc *cc = f->ccs;
        unsigned initial_seq = cc->seq;
        uint8_t *write = NULL;
        require(!lc_spider_fetch_read_ready(f) && lc_spider_fetch_take(f, &write) > 24 &&
                    !lc_spider_fetch_read_ready(f) && lc_spider_fetch_step(f, 0) == 2,
                "taking opening bytes does not start readLoop or request under backpressure");
        input_frame(f, LC_H2_SETTINGS, 0, 0, NULL, 0);
        require(!cc->got_settings && cc->seq == initial_seq && cc->streams == NULL &&
                    f->held_len == LC_H2_HEADER && lc_spider_fetch_step(f, 0) == 2,
                "early peer input remains one held feed until opening Flush completes");
        uint64_t generation = 0;
        if (outcome == 1u) {
            lc_spider_fetch_stop(f);
            require(lc_spider_fetch_wait(f, &generation) == 0 &&
                        lc_spider_fetch_step(f, 0) == 0 && !cc->got_settings,
                    "stop while opening cannot start the saved readLoop");
        } else if (outcome == 2u) {
            require(lc_spider_fetch_write_complete(f, 0) == 0 &&
                        lc_spider_fetch_step(f, 0) < 0 && !cc->got_settings && cc->werr,
                    "failed opening Flush cannot dispatch early peer input");
        } else {
            require(lc_spider_fetch_write_complete(f, 1) == 0 &&
                        lc_spider_fetch_wait(f, &generation) == 1 && cc->seq > initial_seq,
                    "matching opening completion starts readLoop without new input");
            free(write);
            write = NULL;
            require(lc_spider_fetch_step(f, 0) == 1 && cc->got_settings &&
                        f->held_len == 0u && lc_spider_fetch_take(f, &write) == 9 &&
                        write[3] == LC_H2_SETTINGS && write[4] == LC_H2_ACK,
                    "saved SETTINGS produces exactly its ACK after opening completion");
            require(lc_spider_fetch_write_complete(f, 1) == 0,
                    "opening fixture ACK completes");
            free(write);
            write = NULL;
            require(lc_spider_fetch_step(f, 0) == 1 &&
                        lc_spider_fetch_take(f, &write) > 9 && write[3] == LC_H2_HEADERS,
                    "request follows opening once, with no repeated SETTINGS ACK");
        }
        free(write);
        lc_spider_fetch_free(f);
    }
}

static void test_data_driver(void)
{
    for (unsigned owner = 0; owner < 2u; owner++)
        for (unsigned teardown = 0; teardown < 3u; teardown++) {
            uint8_t *write = NULL;
            lc_spider_fetch *f = driver_fixture(&write);
            fetch_cc *cc = f->ccs;
            fetch_stream *s = cc->streams;
            if (owner == 0u) {
                require(lc_spider_fetch_write_complete(f, 1) == 0, "DATA request completes");
                free(write);
                write = NULL;
            }
            const uint8_t status = 0x88;
            input_frame(f, LC_H2_HEADERS, LC_H2_END_HEADERS, s->id, &status, 1u);
            /* Seed the inflow immediately below its refresh threshold to isolate one DATA. */
            cc->in_unsent = s->in_unsent = 4000;
            cc->in_avail = s->in_avail = 500;
            uint8_t padded[102] = {100, 'x'};
            input_frame(f, LC_H2_DATA, LC_H2_PADDED | LC_H2_END_STREAM,
                        s->id, padded, sizeof padded);
            require(s->pb_len == 1u && s->pb[s->pb_off] == 'x' && cc->data_pending &&
                        !s->peer_closed && s->p_err == LC_GZ_NONE,
                    "public DATA feed publishes body/accounting before writer or Flush completion");
            require(cc->in_avail == 4499 && s->in_avail == 4499 &&
                        cc->in_unsent == 0 && s->in_unsent == 0,
                    "padding accounting occurs exactly once before terminal continuation");
            if (owner != 0u && teardown == 0u) {
                require(f->cuts == 0u && cc->writer_wait &&
                            lc_spider_fetch_write_complete(f, 1) == 0,
                        "DATA waits without output until the request writer actually completes");
                free(write);
                write = NULL;
                require(lc_spider_fetch_step(f, 0) == 1 && !s->peer_closed,
                        "scheduler queues padding Flush without publishing END_STREAM");
            }
            if (owner == 0u || teardown == 0u) {
                require(lc_spider_fetch_take(f, &write) == 26 && write[3] == LC_H2_WINDOW_UPDATE &&
                            write[16] == LC_H2_WINDOW_UPDATE && !s->peer_closed,
                        "two padding WINDOW_UPDATEs share one pending Flush");
            }
            uint64_t generation = 0;
            if (teardown == 1u) {
                lc_spider_fetch_stop(f);
                require(lc_spider_fetch_wait(f, &generation) == 0 &&
                            lc_spider_fetch_step(f, 0) == 0 && !s->peer_closed,
                        "stop preserves DATA continuation at either pending phase");
            } else if (teardown == 2u) {
                require(lc_spider_fetch_write_complete(f, 0) == 0 &&
                            lc_spider_fetch_step(f, 0) < 0 && !s->peer_closed,
                        "Write error cannot publish the saved DATA END_STREAM");
            } else {
                require(lc_spider_fetch_write_complete(f, 1) == 0 &&
                            lc_spider_fetch_wait(f, &generation) == 1,
                        "padding Flush completion wakes the saved DATA continuation");
                require(lc_spider_fetch_step(f, 0) >= 0 && s->peer_closed && !cc->data_pending,
                        "production scheduler publishes END_STREAM only after padding Flush");
                require(cc->in_avail == 4499 && f->cuts == 0u,
                        "DATA resumption neither re-accounts padding nor repeats WINDOW_UPDATE");
            }
            lc_spider_fetch_free(f);
            free(write);
        }
}

/* processData releases wmu after padding Flush, before its terminal actions.
 * A later body Read/Close Write can acquire wmu but cannot postpone END_STREAM.
 * Owner fields are established only by the actual public drivers/completions. */
static void test_split_data_terminal_driver(void)
{
    for (unsigned close = 0; close < 2u; close++)
        for (unsigned tail = 0; tail < 2u; tail++)
            for (unsigned outcome = 0; outcome < 5u; outcome++) {
                uint8_t *write = NULL;
                lc_spider_fetch *f = driver_fixture_mode(&write, 1);
                fetch_cc *cc = f->ccs;
                fetch_stream *s = cc->streams;
                require(lc_spider_fetch_write_complete(f, 1) == 0,
                        "terminal DATA fixture completes request Flush");
                free(write);
                write = NULL;
                const lc_hpack_field response[] = {
                    {":status", close ? "302" : "200"}, {"content-length", "5001"},
                    {"location", "/next"}
                };
                uint8_t headers[128], body[5000];
                memset(body, 'x', sizeof body);
                long hn = lc_hpack_encode(response, close ? 3u : 2u, headers, sizeof headers);
                require(hn > 0, "terminal DATA response encodes");
                input_frame(f, LC_H2_HEADERS, LC_H2_END_HEADERS, s->id, headers, (size_t)hn);
                cc->in_avail = s->in_avail = 6000;
                input_frame(f, LC_H2_DATA, 0, s->id, body, sizeof body);
                cc->in_unsent = s->in_unsent = 4000;
                uint8_t message[128], padded[102] = {100, 'y'};
                (void)lc_h2_put_header(message, sizeof message, sizeof padded, LC_H2_DATA,
                                       LC_H2_PADDED | LC_H2_END_STREAM, s->id);
                memcpy(message + LC_H2_HEADER, padded, sizeof padded);
                size_t mn = LC_H2_HEADER + sizeof padded;
                const uint8_t nonce[8] = {1, 3, 5, 7, 2, 4, 6, 8};
                if (tail) {
                    (void)lc_h2_put_header(message + mn, sizeof message - mn, sizeof nonce,
                                           LC_H2_PING, 0, 0);
                    memcpy(message + mn + LC_H2_HEADER, nonce, sizeof nonce);
                    mn += LC_H2_HEADER + sizeof nonce;
                }
                require(lc_spider_fetch_feed(f, message, mn) == 0 &&
                            lc_spider_fetch_take(f, &write) == 26 &&
                            write[3] == LC_H2_WINDOW_UPDATE && r_u32(write + 9) == 4101u &&
                            write[16] == LC_H2_WINDOW_UPDATE && r_u32(write + 22) == 4101u &&
                            s->pb_len == 5001u && cc->data_pending && !s->peer_closed &&
                            lc_spider_fetch_read_step(f) == 0,
                        "terminal DATA waits for its own exact padding Flush");
                if (outcome == 1u || outcome == 2u) {
                    if (outcome == 1u)
                        lc_spider_fetch_stop(f);
                    else
                        require(lc_spider_fetch_write_complete(f, 0) == 0,
                                "terminal DATA own padding Flush fails");
                    require(lc_spider_fetch_read_step(f) == (outcome == 1u ? 0 : -1) &&
                                !s->peer_closed && cc->data_pending && f->cuts == 0u,
                            "stopped/failed own padding cannot publish terminal DATA");
                } else {
                    require(lc_spider_fetch_write_complete(f, 1) == 0 &&
                                !s->peer_closed && cc->data_pending,
                            "padding completion releases only its matching owner, not terminal DATA");
                    free(write);
                    write = NULL;
                    require(lc_spider_fetch_step(f, 0) == 1,
                            "real Do starts its response Read or Close after padding Flush");
                    if (close)
                        require(lc_spider_fetch_step(f, 0) == 1,
                                "real Close acquires its unread-credit writer");
                    else
                        for (unsigned turn = 0; turn < 32u && f->cuts == 0u; turn++)
                            require(lc_spider_fetch_step(f, 0) >= 0,
                                    "real Read accumulates credit through its actual buffer sizes");
                    long wn = lc_spider_fetch_take(f, &write);
                    require(wn == (close ? 13 : 26) && write[3] == LC_H2_WINDOW_UPDATE &&
                                (close ? r_u32(write + 9) == 5001u :
                                 r_u32(write + 9) > 0u && r_u32(write + 9) == r_u32(write + 22)) &&
                                (close ? cc->close_writer == s : cc->source_writer == s),
                            "a different goroutine owns a real unfinished body-credit Write");
                    uint64_t foreign_id = f->active_write.id;
                    if (outcome == 3u || outcome == 4u) {
                        if (outcome == 3u)
                            lc_spider_fetch_stop(f);
                        else
                            require(lc_spider_fetch_write_complete(f, 0) == 0,
                                    "later body-credit Write fails");
                        require(lc_spider_fetch_read_step(f) == (outcome == 3u ? 0 : -1) &&
                                    !s->peer_closed && cc->data_pending && f->cuts == 0u,
                                "stop/error between padding and terminal phases prevents END_STREAM");
                    } else {
                        require(lc_spider_fetch_read_step(f) == 1 && s->peer_closed &&
                                    !cc->data_pending && s->p_err == LC_GZ_EOF,
                                "completed DATA publishes END_STREAM behind a later body writer");
                        require(f->active_write.id == foreign_id && f->write_inflight &&
                                    f->cuts == 0u && cc->writer_wait == (tail != 0u) &&
                                    lc_spider_fetch_read_ready(f) == (tail == 0u),
                                "terminal progress preserves later Write and waits only for a buffered PING's writer");
                        uint64_t generation = f->generation;
                        for (unsigned turn = 0; turn < 3u; turn++)
                            require(lc_spider_fetch_read_step(f) == 0 &&
                                        f->generation == generation && f->cuts == 0u,
                                    "repeated terminal wait duplicates no credit, ACK or wake");
                        require(lc_spider_fetch_request_step(f) == 1 && s->forgotten &&
                                    !s->done && s->cleanup_final_pending && !s->cleanup_reset,
                                "independent cleanup sees END_STREAM before selecting CANCEL");
                        require(lc_spider_fetch_write_complete(f, 1) == 0,
                                "later body-credit Write actually completes");
                        free(write);
                        write = NULL;
                        require(lc_spider_fetch_read_step(f) == (tail ? 1 : 0),
                                "only a buffered control frame needs the completed later writer");
                        if (tail) {
                            require(lc_spider_fetch_take(f, &write) == 17 &&
                                        write[3] == LC_H2_PING && write[4] == LC_H2_ACK &&
                                        memcmp(write + LC_H2_HEADER, nonce, sizeof nonce) == 0 &&
                                        lc_spider_fetch_write_complete(f, 1) == 0 &&
                                        lc_spider_fetch_read_step(f) == 1,
                                    "saved tail produces one nonce-matching ACK after its writer wait");
                            free(write);
                            write = NULL;
                        }
                        require(lc_spider_fetch_request_step(f) == 1 && s->done,
                                "final cleanup acquires the completed body writer once");
                        if (!close) {
                            for (unsigned turn = 0; turn < 8u && !lc_spider_fetch_done(f); turn++)
                                require(lc_spider_fetch_step(f, 0) >= 0,
                                        "saved Read reaches accepted EOF without new input");
                            require(lc_spider_fetch_done(f),
                                    "Read consumer finishes after its own credit and cleanup");
                        }
                        require(f->cuts == 0u && cc->in_avail + cc->in_unsent == 10000 &&
                                    s->pb_len == 0u,
                                "terminal/body resumptions do not repeat accounting or reset");
                    }
                }
                free(write);
                lc_spider_fetch_free(f);
            }
}

/* A completed readLoop ACK may leave END_STREAM in bufio or the accepted feed.
 * Body.Close's later credit Write owns cc.wmu, not the readLoop: Go's processData
 * publishes an unpadded empty END_STREAM without acquiring that writer. */
static void test_split_reader_behind_close_driver(void)
{
    for (unsigned held = 0; held < 2u; held++)
        for (unsigned ping = 0; ping < 2u; ping++)
            for (unsigned outcome = 0; outcome < 4u; outcome++) {
                uint8_t *write = NULL;
                lc_spider_fetch *f = driver_fixture_mode(&write, 1);
                fetch_cc *cc = f->ccs;
                fetch_stream *s = cc->streams;
                require(lc_spider_fetch_write_complete(f, 1) == 0,
                        "buffered END fixture completes request Flush");
                free(write);
                write = NULL;
                const lc_hpack_field response[] = {
                    {":status", "302"}, {"content-length", "5000"}, {"location", "/next"}
                };
                uint8_t headers[128], body[5000] = {0}, message[4200];
                long hn = lc_hpack_encode(response, 3u, headers, sizeof headers);
                require(hn > 0, "buffered END redirect encodes");
                input_frame(f, LC_H2_HEADERS, LC_H2_END_HEADERS, s->id, headers, (size_t)hn);
                input_frame(f, LC_H2_DATA, 0, s->id, body, sizeof body);
                const uint8_t nonce[8] = {1, 2, 3, 4, 5, 6, 7, 8};
                (void)lc_h2_put_header(message, sizeof message, 8u, LC_H2_PING, 0, 0);
                memcpy(message + LC_H2_HEADER, nonce, sizeof nonce);
                size_t mn = 17u;
                if (held) {
                    /* An ignored extension spans the native 4096-byte fill, so
                     * reaching END also requires draining the accepted tail. */
                    (void)lc_h2_put_header(message + mn, sizeof message - mn, 4096u, 0xfe, 0, 0);
                    mn += LC_H2_HEADER;
                    memset(message + mn, 0, 4096u);
                    mn += 4096u;
                }
                (void)lc_h2_put_header(message + mn, sizeof message - mn, 0u,
                                       LC_H2_DATA, LC_H2_END_STREAM, s->id);
                mn += LC_H2_HEADER;
                if (ping) {
                    (void)lc_h2_put_header(message + mn, sizeof message - mn, 8u,
                                           LC_H2_PING, 0, 0);
                    memcpy(message + mn + LC_H2_HEADER, nonce, sizeof nonce);
                    mn += 17u;
                }
                require(lc_spider_fetch_feed(f, message, mn) == 0 &&
                            lc_spider_fetch_take(f, &write) == 17 &&
                            !s->peer_closed && cc->writer_wait &&
                            (f->held_input != NULL) == (held != 0u),
                        "readLoop retains END behind its own real PING Flush");
                require(lc_spider_fetch_read_step(f) == 0 && !s->peer_closed &&
                            lc_spider_fetch_write_complete(f, 1) == 0,
                        "only actual ACK completion releases the readLoop's writer");
                free(write);
                write = NULL;
                require(lc_spider_fetch_step(f, 0) == 1 &&
                            lc_spider_fetch_step(f, 0) == 1 &&
                            s->abort && s->p_break && cc->close_writer == s &&
                            lc_spider_fetch_take(f, &write) == 13 &&
                            write[3] == LC_H2_WINDOW_UPDATE && r_u32(write + 9) == 5000u,
                        "real Close refunds unread bytes through its own unfinished Write");
                uint64_t close_id = f->active_write.id;
                int64_t credit = cc->in_avail, unsent = cc->in_unsent;
                if (outcome == 1u || outcome == 2u) {
                    if (outcome == 1u)
                        lc_spider_fetch_stop(f);
                    else
                        require(lc_spider_fetch_write_complete(f, 0) == 0,
                                "buffered END foreign Write fails");
                    require(lc_spider_fetch_read_step(f) == (outcome == 1u ? 0 : -1) &&
                                !s->peer_closed && f->cuts == 0u,
                            "stop or failed transport cannot publish buffered END");
                } else {
                    if (outcome == 3u)
                        require(lc_spider_fetch_request_step(f) == 1 && s->cleanup_reset,
                                "cleanup may select CANCEL before the reader gets its turn");
                    require(lc_spider_fetch_read_step(f) == 1 && s->peer_closed &&
                                f->held_input == NULL && cc->writer_wait == (ping != 0u) &&
                                f->active_write.id == close_id && cc->close_writer == s &&
                                f->write_inflight && f->cuts == 0u &&
                                cc->in_avail == credit && cc->in_unsent == unsent,
                            "buffered END is published behind Close without completing or changing its Write");
                    uint64_t generation = f->generation;
                    require(lc_spider_fetch_read_step(f) == 0 && f->generation == generation,
                            "reader quiesces without duplicate credit, output or wakeups");
                    if (outcome == 0u)
                        require(lc_spider_fetch_request_step(f) == 1 &&
                                    s->forgotten && !s->cleanup_reset,
                                "cleanup sees accepted END before deciding whether to CANCEL");
                    else
                        require(s->cleanup_reset,
                                "later accepted END cannot retract a previously selected CANCEL");
                    require(lc_spider_fetch_write_complete(f, 1) == 0,
                            "only the socket completion releases Close's matching Write");
                    free(write);
                    write = NULL;
                    unsigned acks = 0, cancels = 0;
                    for (unsigned turn = 0; turn < 16u && !s->done; turn++) {
                        require(lc_spider_fetch_read_step(f) >= 0 &&
                                    lc_spider_fetch_request_step(f) >= 0,
                                "reader and cleanup resume after Close completion without new input");
                        long n = lc_spider_fetch_take(f, &write);
                        if (n > 0) {
                            if (n == 17 && write[3] == LC_H2_PING && write[4] == LC_H2_ACK &&
                                memcmp(write + LC_H2_HEADER, nonce, sizeof nonce) == 0)
                                acks++;
                            else {
                                require(n == 13 && write[3] == LC_H2_RST_STREAM &&
                                            write[12] == ERR_CANCEL,
                                        "only a preselected CANCEL may follow the completed Close");
                                cancels++;
                            }
                            require(lc_spider_fetch_write_complete(f, 1) == 0,
                                    "each resumed Write completes through its matching socket boundary");
                        }
                        free(write);
                        write = NULL;
                    }
                    require(s->done && s->forgotten && acks == ping &&
                                cancels == (outcome == 3u) && f->cuts == 0u &&
                                !f->write_inflight && f->held_input == NULL &&
                                cc->in_avail == credit && cc->in_unsent == unsent,
                            "accepted END completes cleanup with exact ACK/CANCEL and no duplicate credit");
                }
                free(write);
                lc_spider_fetch_free(f);
            }
}

static void test_forgotten_data_driver(void)
{
    uint8_t *request = NULL, *credit = NULL;
    lc_spider_fetch *f = driver_fixture(&request);
    fetch_cc *cc = f->ccs;
    fetch_stream *s = cc->streams;
    require(lc_spider_fetch_write_complete(f, 1) == 0,
            "forgotten DATA fixture completes its own request before peer abort");
    free(request);
    request = NULL;
    const uint8_t reset[4] = {0, 0, 0, ERR_CANCEL};
    input_frame(f, LC_H2_RST_STREAM, 0, s->id, reset, sizeof reset);
    const uint8_t nonce[8] = {0};
    input_frame(f, LC_H2_PING, 0, 0, nonce, sizeof nonce);
    require(lc_spider_fetch_take(f, &request) == 17,
            "forgotten DATA fixture holds a genuinely foreign readLoop Write");
    require(lc_spider_fetch_step(f, 0) == 1 && s->forgotten && !s->done,
            "peer cancellation forgets the stream while a foreign readLoop Write owns cc.wmu");
    cc->in_unsent = 4000;
    cc->in_avail = 500;
    uint8_t data[102] = {0};
    input_frame(f, LC_H2_DATA, 0, s->id, data, sizeof data);
    require(f->held_input != NULL && !cc->data_pending && f->cuts == 0u && s->pb_len == 0u,
            "forgotten DATA remains held until its readLoop's own PING Flush returns");
    require(lc_spider_fetch_write_complete(f, 1) == 0 && lc_spider_fetch_step(f, 0) == 1 &&
                lc_spider_fetch_take(f, &credit) == 13 && credit[3] == LC_H2_WINDOW_UPDATE,
            "forgotten DATA's connection refund follows actual foreign Write completion");
    require(cc->data_pending && cc->data_stream == NULL && cc->in_unsent == 0 &&
                cc->in_avail == 4500 && credit[9] == 0 && credit[10] == 0 &&
                credit[11] == 16 && credit[12] == 6,
            "resumed forgotten DATA refunds exactly 4102 bytes on connection only");
    require(lc_spider_fetch_write_complete(f, 1) == 0 && lc_spider_fetch_step(f, 0) == 1 &&
                s->done && !cc->data_pending && f->cuts == 0u,
            "forgotten DATA and final cleanup resume once without additional input");
    free(credit);
    free(request);
    lc_spider_fetch_free(f);
}

/* Close signals abort; cleanup's reset decision belongs to a subsequent doRequest turn.
 * Both legal peer/cleanup orders must remain possible, with no timer or fresh input needed. */
static void test_cleanup_decision_before_writer_driver(void)
{
    for (unsigned outcome = 0; outcome < 5u; outcome++) {
        uint8_t *write = NULL;
        lc_spider_fetch *f = driver_fixture(&write);
        fetch_stream *s = f->ccs->streams;
        require(lc_spider_fetch_write_complete(f, 1) == 0,
                "pre-writer cleanup request completes");
        free(write);
        write = NULL;
        const lc_hpack_field fields[] = {
            {":status", "302"}, {"location", "/next"}, {"content-length", "5000"}
        };
        uint8_t headers[128], body[5000] = {0};
        long hn = lc_hpack_encode(fields, 3u, headers, sizeof headers);
        require(hn > 0, "pre-writer cleanup response encodes");
        input_frame(f, LC_H2_HEADERS, LC_H2_END_HEADERS, s->id, headers, (size_t)hn);
        input_frame(f, LC_H2_DATA, 0, s->id, body, sizeof body);
        require(lc_spider_fetch_step(f, 0) == 1 && f->state == DO_CLOSE &&
                    lc_spider_fetch_step(f, 0) == 1 && s->p_break && s->abort,
                "pre-writer Close signals independent cleanup");
        require(lc_spider_fetch_take(f, &write) == 13 && write[3] == LC_H2_WINDOW_UPDATE,
                "pre-writer fixture holds actual Close refund Write");
        uint64_t refund_id = f->active_write.id;
        require(lc_spider_fetch_step(f, 0) >= 0,
                "cleanup can run its pre-writer decision while Close Flush waits");
        for (unsigned turn = 0; turn < 3u; turn++)
            require(lc_spider_fetch_step(f, 0) >= 0 && !s->done && !s->forgotten &&
                        f->active_write.id == refund_id && f->cuts == 0u,
                    "pre-writer retries neither duplicate reset nor complete refund");
        input_frame(f, LC_H2_DATA, LC_H2_END_STREAM, s->id, NULL, 0);
        require(s->peer_closed && !s->done && f->cuts == 0u,
                "peer END_STREAM is processed while the Close writer remains held");
        if (outcome == 1u) {
            lc_spider_fetch_stop(f);
            uint64_t generation = 0;
            require(lc_spider_fetch_wait(f, &generation) == 0 &&
                        lc_spider_fetch_step(f, 0) == 0 && !s->done && f->cuts == 0u,
                    "stop after cleanup decision does not publish reset or completion");
        } else if (outcome == 2u) {
            require(lc_spider_fetch_write_complete(f, 0) == 0 &&
                        lc_spider_fetch_step(f, 0) < 0 && !s->done && f->cuts == 0u,
                    "failed held writer cannot publish a saved cleanup reset");
        } else {
            require(lc_spider_fetch_write_complete(f, 1) == 0,
                    "held Close refund completes through the public driver");
            free(write);
            write = NULL;
            require(lc_spider_fetch_step(f, 0) == 1 &&
                        lc_spider_fetch_take(f, &write) == 13 &&
                        write[3] == LC_H2_RST_STREAM && write[12] == ERR_CANCEL,
                    "cleanup preserves CANCEL selected before writer wait despite later END_STREAM");
            uint8_t *duplicate = NULL;
            require(lc_spider_fetch_take(f, &duplicate) == 0 && duplicate == NULL && !s->done,
                    "pending cleanup Flush cannot repeat its reset or publish donec");
            if (outcome == 3u) {
                require(lc_spider_fetch_write_complete(f, 0) == 0 &&
                            lc_spider_fetch_step(f, 0) < 0 && !s->done,
                        "saved reset Write failure cannot publish successful cleanup");
            } else if (outcome == 4u) {
                lc_spider_fetch_stop(f);
                require(lc_spider_fetch_step(f, 0) == 0 && !s->done,
                        "stop during saved reset Flush cannot publish donec");
            } else {
                require(lc_spider_fetch_write_complete(f, 1) == 0 && !s->done &&
                            s->forgotten && lc_spider_fetch_step(f, 0) == 1 && s->done,
                        "saved reset Flush and separate final acquisition complete without input");
                free(write);
                write = NULL;
                for (unsigned turn = 0; turn < 8u && write == NULL; turn++) {
                    require(lc_spider_fetch_step(f, 0) >= 0,
                            "saved cleanup advances redirect without fresh input");
                    (void)lc_spider_fetch_take(f, &write);
                }
                require(write != NULL && write[3] == LC_H2_HEADERS && write[8] == 3u,
                        "saved cleanup emits next request, not duplicate refund or reset");
            }
        }
        free(write);
        lc_spider_fetch_free(f);
    }
}

static void test_close_handoff_driver(void)
{
    for (unsigned buffered = 0; buffered < 2u; buffered++)
        for (unsigned order = 0; order < 4u; order++) {
            uint8_t *write = NULL;
            lc_spider_fetch *f = driver_fixture(&write);
            fetch_stream *s = f->ccs->streams;
            require(lc_spider_fetch_write_complete(f, 1) == 0,
                    "handoff request actually completes");
            free(write);
            write = NULL;
            const lc_hpack_field fields[] = {
                {":status", "302"}, {"location", "/next"}, {"content-length", "5000"}
            };
            uint8_t headers[128], body[5000] = {0};
            long hn = lc_hpack_encode(fields, 3u, headers, sizeof headers);
            require(hn > 0, "handoff response encodes");
            input_frame(f, LC_H2_HEADERS, LC_H2_END_HEADERS, s->id, headers, (size_t)hn);
            if (buffered)
                input_frame(f, LC_H2_DATA, 0, s->id, body, sizeof body);
            require(lc_spider_fetch_step(f, 0) == 1 && f->state == DO_CLOSE,
                    "handoff response yields before Close");
            require(lc_spider_fetch_step(f, 0) == 1 && s->p_break && s->abort &&
                        !s->done && !s->forgotten && !s->cleanup_pending &&
                        s->cleanup_write_id == 0u,
                    "Close signals doRequest without executing its reset decision inline");
            long n = lc_spider_fetch_take(f, &write);
            require(buffered ? n == 13 && write[3] == LC_H2_WINDOW_UPDATE : n == 0,
                    "Close's turn publishes only its own connection refund, never cleanup reset");
            if (order == 2u) {
                lc_spider_fetch_stop(f);
                uint64_t generation = 0;
                require(lc_spider_fetch_wait(f, &generation) == 0 &&
                            lc_spider_fetch_step(f, 0) == 0 && !s->done &&
                            s->cleanup_write_id == 0u,
                        "stop between Close and cleanup cannot publish reset or donec");
            } else if (order == 3u && buffered) {
                require(lc_spider_fetch_write_complete(f, 0) == 0 &&
                            lc_spider_fetch_step(f, 0) < 0 && !s->done,
                        "failed Close refund terminates before independent cleanup");
            } else {
                if (buffered)
                    require(lc_spider_fetch_write_complete(f, 1) == 0,
                            "Close refund actually completes before cleanup");
                free(write);
                write = NULL;
                if (order == 0u)
                    input_frame(f, LC_H2_DATA, LC_H2_END_STREAM, s->id, NULL, 0);
                require(lc_spider_fetch_step(f, 0) == 1,
                        "independent cleanup continues after Close without fresh input");
                n = lc_spider_fetch_take(f, &write);
                if (order == 0u) {
                    require(n == 0 && s->peer_closed && !s->done && s->forgotten &&
                                s->cleanup_final_pending && lc_spider_fetch_step(f, 0) == 1 && s->done,
                            "peer END_STREAM before cleanup suppresses cancellation");
                } else {
                    require(n == 13 && write[3] == LC_H2_RST_STREAM &&
                                write[12] == ERR_CANCEL && !s->done,
                            "cleanup before peer END_STREAM selects exactly one CANCEL");
                    if (order == 3u) {
                        require(lc_spider_fetch_write_complete(f, 0) == 0 &&
                                    lc_spider_fetch_step(f, 0) < 0 && !s->done,
                                "failed independent reset cannot publish successful donec");
                    } else {
                        input_frame(f, LC_H2_DATA, LC_H2_END_STREAM, s->id, NULL, 0);
                        require(lc_spider_fetch_write_complete(f, 1) == 0 && !s->done &&
                                    lc_spider_fetch_step(f, 0) == 1 && s->done,
                                "later peer completion cannot rewrite an already selected reset");
                    }
                }
                if (order != 3u) {
                    free(write);
                    write = NULL;
                    for (unsigned turn = 0; turn < 8u && write == NULL; turn++) {
                        require(lc_spider_fetch_step(f, 0) >= 0,
                                "handoff redirect advances without new input");
                        n = lc_spider_fetch_take(f, &write);
                    }
                    require(n > 9 && write[3] == LC_H2_HEADERS && write[8] == 3u,
                            "handoff produces next request without duplicate refund or reset");
                }
            }
            free(write);
            lc_spider_fetch_free(f);
        }
}

typedef struct { lc_spider_fetch *f; int result; } prep_worker;

/* A redirect can reach stream 3 before stream 1's DATA reaches the readLoop. The old
 * stream is already forgotten; its connection refund must not use or cancel stream 3. */
static void test_late_redirect_data_driver(void)
{
    for (unsigned ended = 0; ended < 2u; ended++)
        for (unsigned teardown = 0; teardown < 5u; teardown++) {
            uint8_t *write = NULL;
            lc_spider_fetch *f = driver_fixture(&write);
            fetch_cc *cc = f->ccs;
            fetch_stream *old = cc->streams;
            require(lc_spider_fetch_write_complete(f, 1) == 0,
                    "late redirect's initial request completes");
            free(write);
            write = NULL;
            const lc_hpack_field fields[] = {
                {":status", "302"}, {"location", "/next"}, {"content-length", "5000"}
            };
            uint8_t headers[128], body[5000] = {0};
            long hn = lc_hpack_encode(fields, 3u, headers, sizeof headers);
            require(hn > 0, "late redirect headers encode");
            input_frame(f, LC_H2_HEADERS, LC_H2_END_HEADERS, old->id, headers, (size_t)hn);
            require(lc_spider_fetch_step(f, 0) == 1 && f->state == DO_CLOSE &&
                        lc_spider_fetch_step(f, 0) == 1 && old->p_break && old->abort &&
                        lc_spider_fetch_take(f, &write) == 0,
                    "Close before DATA publishes no invented body credit");
            require(lc_spider_fetch_step(f, 0) == 1 &&
                        lc_spider_fetch_take(f, &write) == 13 &&
                        write[3] == LC_H2_RST_STREAM && write[12] == ERR_CANCEL,
                    "independent cleanup writes one CANCEL before the redirect");
            require(lc_spider_fetch_write_complete(f, 1) == 0 && !old->done && old->forgotten &&
                        old->cleanup_final_pending && lc_spider_fetch_step(f, 0) == 1 && old->done,
                    "old stream is forgotten after actual reset completion");
            free(write);
            write = NULL;
            long n = 0;
            for (unsigned turn = 0; turn < 8u && write == NULL; turn++) {
                require(lc_spider_fetch_step(f, 0) >= 0, "late redirect advances without input");
                n = lc_spider_fetch_take(f, &write);
            }
            require(n > 9 && write[3] == LC_H2_HEADERS && write[8] == 3u &&
                        cc->request_writer != NULL && cc->request_writer != old,
                    "new request owns the actual stream 3 Write");
            fetch_stream *next = cc->request_writer;
            int64_t available = cc->in_avail;
            input_frame(f, LC_H2_DATA, ended ? LC_H2_END_STREAM : 0, old->id,
                        body, sizeof body);
            require(cc->data_pending && cc->data_stream == NULL && cc->writer_wait &&
                        cc->data_conn_credit == sizeof body && cc->data_stream_credit == 0u &&
                        cc->in_avail == available && f->cuts == 0u && old->pb_len == 0u &&
                        !old->peer_closed && !next->peer_closed && !next->abort,
                    "late DATA accounts only connection credit behind the new request writer");
            uint8_t *extra = NULL;
            require(lc_spider_fetch_step(f, 0) == 2 && lc_spider_fetch_take(f, &extra) == 0,
                    "pending request cannot be bypassed by late credit or duplicate reset");
            uint64_t generation = 0;
            if (teardown == 1u) {
                lc_spider_fetch_stop(f);
                require(lc_spider_fetch_wait(f, &generation) == 0 &&
                            lc_spider_fetch_step(f, 0) == 0 && cc->data_pending,
                        "stop behind the redirect Write preserves the late DATA continuation");
            } else if (teardown == 2u) {
                require(lc_spider_fetch_write_complete(f, 0) == 0 &&
                            lc_spider_fetch_step(f, 0) < 0 && cc->data_pending,
                        "failed redirect Write never publishes late credit success");
            } else {
                require(lc_spider_fetch_write_complete(f, 1) == 0 &&
                            lc_spider_fetch_wait(f, &generation) == 1,
                        "actual redirect completion wakes late DATA without fresh input");
                free(write);
                write = NULL;
                require(lc_spider_fetch_step(f, 0) >= 0 &&
                            lc_spider_fetch_take(f, &write) == 13 &&
                            write[3] == LC_H2_WINDOW_UPDATE && write[8] == 0u &&
                            write[9] == 0u && write[10] == 0u &&
                            write[11] == 0x13u && write[12] == 0x88u && cc->data_pending,
                        "late DATA emits exactly 5000 connection bytes after the request Flush");
                if (teardown == 3u) {
                    lc_spider_fetch_stop(f);
                    require(lc_spider_fetch_wait(f, &generation) == 0 &&
                                lc_spider_fetch_step(f, 0) == 0 && cc->data_pending,
                            "stop during late credit Flush preserves its terminal continuation");
                } else if (teardown == 4u) {
                    require(lc_spider_fetch_write_complete(f, 0) == 0 &&
                                lc_spider_fetch_step(f, 0) < 0 && cc->data_pending,
                            "failed late credit Flush cannot complete the DATA continuation");
                } else {
                    require(lc_spider_fetch_write_complete(f, 1) == 0 &&
                                lc_spider_fetch_step(f, 0) >= 0 && !cc->data_pending &&
                                cc->in_avail == available && cc->in_unsent == 0 &&
                                old->done && old->forgotten && !old->peer_closed &&
                                !next->peer_closed && !next->abort && next->pb_len == 0u,
                            "late credit completes once without mutating either stream");
                    free(write);
                    write = NULL;
                    for (unsigned turn = 0; turn < 3u; turn++)
                        require(lc_spider_fetch_step(f, 0) >= 0 &&
                                    lc_spider_fetch_take(f, &write) == 0 && f->cuts == 0u &&
                                    cc->in_avail == available && !cc->data_pending && !next->abort,
                                "late DATA leaves no duplicate refund or reset without new input");
                }
            }
            free(write);
            lc_spider_fetch_free(f);
        }
}

static void *prepare_on_worker(void *arg)
{
    prep_worker *worker = arg;
    worker->result = lc_spider_fetch_step(worker->f, 0);
    return NULL;
}

/* Force a real Do task to remain inside private redirect preparation. The
 * independently driven request task must make progress without that do_lock. */
static void test_split_private_cleanup_driver(void)
{
    for (unsigned outcome = 0; outcome < 5u; outcome++) {
        uint8_t *write = NULL;
        lc_spider_fetch *f = driver_fixture_mode(&write, 1);
        fetch_stream *s = f->ccs->streams;
        const lc_hpack_field fields[] = {
            {":status", "302"}, {"location", "/next"}, {"content-length", "5000"}
        };
        uint8_t headers[128], body[5000] = {0};
        long hn = lc_hpack_encode(fields, 3u, headers, sizeof headers);
        require(hn > 0, "split private redirect headers encode");
        input_frame(f, LC_H2_HEADERS, LC_H2_END_HEADERS, s->id, headers, (size_t)hn);
        pthread_mutex_lock(&prep_lock);
        prep_pause = 1;
        prep_entered = prep_release = 0;
        pthread_mutex_unlock(&prep_lock);
        prep_worker worker = { .f = f, .result = -99 };
        pthread_t thread;
        require(pthread_create(&thread, NULL, prepare_on_worker, &worker) == 0,
                "split Do starts private preparation");
        pthread_mutex_lock(&prep_lock);
        struct timespec deadline;
        require(clock_gettime(CLOCK_REALTIME, &deadline) == 0, "split checkpoint deadline");
        deadline.tv_sec += 5;
        while (!prep_entered)
            require(pthread_cond_timedwait(&prep_changed, &prep_lock, &deadline) == 0,
                    "split Do reaches private checkpoint");
        pthread_mutex_unlock(&prep_lock);
        require(pthread_mutex_trylock(&f->do_lock) == EBUSY,
                "Do still owns its private lock during independent request work");
        input_frame(f, LC_H2_DATA, LC_H2_END_STREAM, s->id, body, sizeof body);
        require(lc_spider_fetch_request_step(f) == 0 && !s->cleanup_prepared && !s->done,
                "split cleanup cannot outrun its own request Flush");
        if (outcome == 3u) {
            require(lc_spider_fetch_write_complete(f, 0) == 0 &&
                        lc_spider_fetch_request_step(f) < 0 && !s->done,
                    "own request failure does not invent entered split cleanup");
        } else if (outcome == 4u) {
            lc_spider_fetch_stop(f);
            require(lc_spider_fetch_request_wait(f) == 0 &&
                        lc_spider_fetch_request_step(f) == 0 && !s->done,
                    "stop interrupts split cleanup before entry");
        } else {
            require(lc_spider_fetch_write_complete(f, 1) == 0 &&
                        lc_spider_fetch_request_wait(f) == 1 &&
                        lc_spider_fetch_request_step(f) == 1 && s->forgotten &&
                        s->cleanup_final_pending && !s->done && !s->p_break,
                    "independent cleanup forgets stream while Do remains in private work");
            if (outcome == 1u) {
                lc_spider_fetch_stop(f);
                require(lc_spider_fetch_request_wait(f) == 0 &&
                            lc_spider_fetch_request_step(f) == 0 && !s->done,
                        "stop between split cleanup acquisitions preserves pending donec");
            } else if (outcome == 2u) {
                const uint8_t nonce[8] = {0};
                input_frame(f, LC_H2_PING, 0, 0, nonce, sizeof nonce);
                free(write);
                write = NULL;
                require(lc_spider_fetch_take(f, &write) == 17 &&
                            lc_spider_fetch_request_step(f) == 0 && !s->done,
                        "split final cleanup waits on foreign ClientConn writer");
                require(lc_spider_fetch_write_complete(f, 0) == 0 &&
                            lc_spider_fetch_request_step(f) < 0 && s->done && f->ccs->werr,
                        "split final werr acquisition completes independently on Write failure");
            } else {
                require(lc_spider_fetch_request_wait(f) == 1 &&
                            lc_spider_fetch_request_step(f) == 1 && s->done &&
                            !s->cleanup_final_pending && lc_spider_fetch_request_step(f) == 0 &&
                            f->cuts == 0u && !s->p_break,
                        "split cleanup finishes once without Do release or additional input");
            }
        }
        pthread_mutex_lock(&prep_lock);
        prep_release = 1;
        pthread_cond_broadcast(&prep_changed);
        pthread_mutex_unlock(&prep_lock);
        require(pthread_join(thread, NULL) == 0, "split private Do joins before free");
        pthread_mutex_lock(&prep_lock);
        prep_pause = 0;
        pthread_mutex_unlock(&prep_lock);
        require(worker.result == (outcome == 0u ? 1 :
                                  outcome == 1u || outcome == 4u ? 0 : -1),
                "split Do rechecks task completion, stop and error after private preparation");
        free(write);
        lc_spider_fetch_free(f);
    }
}

/* A real private Do checkpoint must not retain the readLoop's writer or input.
 * Every owner and frame below is created through public feed/take/completion. */
static void test_split_readloop_driver(void)
{
    for (unsigned large = 0; large < 2u; large++)
        for (unsigned outcome = 0; outcome < 6u; outcome++) {
            uint8_t *write = NULL;
            lc_spider_fetch *f = driver_fixture_mode(&write, 1);
            fetch_stream *s = f->ccs->streams;
            const lc_hpack_field fields[] = {
                {":status", "302"}, {"location", "/next"}, {"content-length", "5000"}
            };
            uint8_t headers[128], frames[5026] = {0};
            long hn = lc_hpack_encode(fields, 3u, headers, sizeof headers);
            require(hn > 0, "readLoop checkpoint response encodes");
            input_frame(f, LC_H2_HEADERS, LC_H2_END_HEADERS, s->id, headers, (size_t)hn);
            pthread_mutex_lock(&prep_lock);
            prep_pause = 1;
            prep_entered = prep_release = 0;
            pthread_mutex_unlock(&prep_lock);
            prep_worker worker = { .f = f, .result = -99 };
            pthread_t thread;
            require(pthread_create(&thread, NULL, prepare_on_worker, &worker) == 0,
                    "readLoop Do starts private preparation");
            pthread_mutex_lock(&prep_lock);
            struct timespec deadline;
            require(clock_gettime(CLOCK_REALTIME, &deadline) == 0, "readLoop checkpoint deadline");
            deadline.tv_sec += 5;
            while (!prep_entered)
                require(pthread_cond_timedwait(&prep_changed, &prep_lock, &deadline) == 0,
                        "readLoop Do reaches private checkpoint");
            pthread_mutex_unlock(&prep_lock);
            require(pthread_mutex_trylock(&f->do_lock) == EBUSY,
                    "readLoop resumes while private Do lock remains owned");

            size_t body_len = large ? 5000u : 0u;
            (void)lc_h2_put_header(frames, sizeof frames, 8u, LC_H2_PING, 0, 0);
            memset(frames + LC_H2_HEADER, 0x6a, 8u);
            (void)lc_h2_put_header(frames + 17, sizeof frames - 17, (uint32_t)body_len,
                                 LC_H2_DATA, LC_H2_END_STREAM, outcome == 5u ? 0u : s->id);
            memset(frames + 26, 'x', body_len);
            require(lc_spider_fetch_feed(f, frames, 26u + body_len) == 0 &&
                        !lc_spider_fetch_read_ready(f) && f->ccs->writer_wait &&
                        ((f->held_input != NULL) == (large != 0u)),
                    "readLoop retains actual PING and buffered or held DATA behind request Flush");
            require(lc_spider_fetch_read_step(f) == 0 && f->cuts == 0u && !s->peer_closed,
                    "readLoop cannot acquire the unfinished request writer or acknowledge it");
            if (outcome == 1u)
                lc_spider_fetch_stop(f);
            require(lc_spider_fetch_write_complete(f, outcome != 3u) == 0,
                    "readLoop fixture completes the actual request Write once");
            free(write);
            write = NULL;
            require(!s->peer_closed && f->ccs->writer_wait,
                    "completion alone never executes the saved readLoop continuation");
            if (outcome == 1u || outcome == 3u) {
                require(lc_spider_fetch_read_step(f) == (outcome == 1u ? 0 : -1) &&
                            f->cuts == 0u && !s->peer_closed &&
                            ((f->held_input != NULL) == (large != 0u)),
                        "stop or request Write error prevents ACK and END publication");
            } else {
                require(lc_spider_fetch_request_step(f) == 0 &&
                            lc_spider_fetch_read_step(f) == 1 &&
                            lc_spider_fetch_take(f, &write) == 17 &&
                            write[3] == LC_H2_PING && write[4] == LC_H2_ACK &&
                            memcmp(write + LC_H2_HEADER, frames + LC_H2_HEADER, 8u) == 0 &&
                            !s->peer_closed && f->ccs->read_write_id != 0u,
                        "loop owner resumes saved PING without private Do or fresh input");
                uint64_t generation = f->generation;
                for (unsigned repeat = 0; repeat < 3u; repeat++)
                    require(lc_spider_fetch_read_step(f) == 0 && f->cuts == 0u &&
                                f->generation == generation && !s->peer_closed,
                            "readLoop waits for its own ACK Flush without duplicate output or wakes");
                if (outcome == 2u)
                    lc_spider_fetch_stop(f);
                require(lc_spider_fetch_write_complete(f, outcome != 4u) == 0 &&
                            !s->peer_closed,
                        "ACK completion releases its owner but does not publish END inline");
                if (outcome == 2u || outcome == 4u || outcome == 5u) {
                    require(lc_spider_fetch_read_step(f) == (outcome == 2u ? 0 : -1) &&
                                !s->peer_closed && s->pb_len == 0u && f->cuts == 0u,
                            "stop, failed ACK or invalid buffered DATA prevents successful END");
                } else {
                    require(lc_spider_fetch_read_step(f) == 1 && s->peer_closed &&
                                s->pb_len == body_len && f->held_input == NULL &&
                                !f->ccs->writer_wait && f->cuts == 0u && !s->done,
                            "loop owner publishes buffered DATA and END once while private Do remains paused");
                    generation = f->generation;
                    for (unsigned repeat = 0; repeat < 3u; repeat++)
                        require(lc_spider_fetch_read_step(f) == 0 &&
                                    f->generation == generation && s->pb_len == body_len &&
                                    f->cuts == 0u && !s->done,
                                "quiescent readLoop neither repeats DATA nor runs request cleanup");
                    require(lc_spider_fetch_request_step(f) == 1 &&
                                lc_spider_fetch_request_step(f) == 1 && s->done &&
                                f->cuts == 0u,
                            "independent cleanup observes END and finishes without CANCEL or Do release");
                }
            }
            lc_spider_fetch_stop(f);
            pthread_mutex_lock(&prep_lock);
            prep_release = 1;
            pthread_cond_broadcast(&prep_changed);
            pthread_mutex_unlock(&prep_lock);
            require(pthread_join(thread, NULL) == 0 && worker.result == (outcome >= 3u ? -1 : 0),
                    "readLoop private Do stops and joins before resources are released");
            pthread_mutex_lock(&prep_lock);
            prep_pause = 0;
            pthread_mutex_unlock(&prep_lock);
            free(write);
            lc_spider_fetch_free(f);
        }
    uint8_t *write = NULL;
    lc_spider_fetch *legacy = driver_fixture(&write);
    require(lc_spider_fetch_read_step(NULL) == -1 &&
                lc_spider_fetch_read_step(legacy) == -1 && legacy->write_inflight,
            "readLoop driver rejects NULL and legacy mode without touching an active Write");
    free(write);
    lc_spider_fetch_free(legacy);
}

static void test_split_readloop_loss_driver(void)
{
    uint8_t *write = NULL;
    lc_spider_fetch *f = driver_fixture_mode(&write, 1);
    fetch_stream *s = f->ccs->streams;
    require(lc_spider_fetch_write_complete(f, 1) == 0, "split loss request completes");
    free(write);
    write = NULL;
    const lc_hpack_field fields[] = {{":status", "200"}, {"content-length", "5000"}};
    uint8_t headers[128], frames[5026] = {0};
    long hn = lc_hpack_encode(fields, 2u, headers, sizeof headers);
    require(hn > 0, "split loss response encodes");
    input_frame(f, LC_H2_HEADERS, LC_H2_END_HEADERS, s->id, headers, (size_t)hn);
    (void)lc_h2_put_header(frames, sizeof frames, 8u, LC_H2_PING, 0, 0);
    (void)lc_h2_put_header(frames + 17, sizeof frames - 17, 5000u,
                         LC_H2_DATA, LC_H2_END_STREAM, s->id);
    memset(frames + 26, 'x', 5000u);
    require(lc_spider_fetch_feed(f, frames, sizeof frames) == 0 &&
                lc_spider_fetch_take(f, &write) == 17 &&
                lc_spider_fetch_write_complete(f, 1) == 0 &&
                f->held_input != NULL && f->ccs->writer_wait && !s->peer_closed,
            "split EOF follows a completed ACK with accepted DATA still waiting on readLoop");
    free(write);
    write = NULL;
    lc_spider_fetch_loss_pending(f);
    for (unsigned turn = 0; turn < 4u; turn++)
        require(lc_spider_fetch_step(f, 0) >= 0 && !f->closed && f->loss_pending &&
                    !s->peer_closed && s->pb_len == 0u && f->held_input != NULL,
                "Do cannot apply transport EOF ahead of the independent accepted readLoop tail");
    require(lc_spider_fetch_read_step(f) == 1 && s->peer_closed &&
                s->pb_len == 5000u && f->held_input == NULL,
            "readLoop processes accepted DATA and END before Do consumes loss");
    int rc = 0;
    for (unsigned turn = 0; turn < 64u && rc >= 0; turn++) {
        int read_rc = lc_spider_fetch_read_step(f);
        if (read_rc < 0) {
            require(lc_spider_fetch_done(f) && s->done && f->closed &&
                        !f->loss_pending && f->held_input == NULL && f->cuts == 0u,
                    "readLoop EOF handoff requires completed Do, cleanup, input and Writes");
            rc = read_rc;
            break;
        }
        require(lc_spider_fetch_request_step(f) >= 0,
                "split EOF request continuation remains valid before transport close");
        rc = lc_spider_fetch_step(f, 0);
        long n = lc_spider_fetch_take(f, &write);
        if (n > 0) {
            require(n == 26 && write[3] == LC_H2_WINDOW_UPDATE &&
                        r_u32(write + 5) == 0u && write[16] == LC_H2_WINDOW_UPDATE &&
                        r_u32(write + 18) == s->id && r_u32(write + 9) == r_u32(write + 22) &&
                        lc_spider_fetch_write_complete(f, 1) == 0,
                    "accepted body credit completes without an invented CANCEL");
            free(write);
            write = NULL;
        }
    }
    require(rc == -1 && f->closed && !f->loss_pending &&
                lc_spider_fetch_done(f) && s->peer_closed && s->done &&
                f->cuts == 0u && f->held_input == NULL,
            "transport EOF arrives only after accepted page and independent cleanup finish");
    lc_spider_fetch_stop(f);
    free(write);
    lc_spider_fetch_free(f);
}

static void test_split_close_decision_driver(void)
{
    for (unsigned end_first = 0; end_first < 2u; end_first++) {
        uint8_t *write = NULL;
        lc_spider_fetch *f = driver_fixture_mode(&write, 1);
        fetch_stream *s = f->ccs->streams;
        require(lc_spider_fetch_write_complete(f, 1) == 0, "split Close request completes");
        free(write);
        write = NULL;
        const lc_hpack_field fields[] = {
            {":status", "302"}, {"location", "/next"}, {"content-length", "5000"}
        };
        uint8_t headers[128], body[5000] = {0};
        long hn = lc_hpack_encode(fields, 3u, headers, sizeof headers);
        require(hn > 0, "split Close headers encode");
        input_frame(f, LC_H2_HEADERS, LC_H2_END_HEADERS, s->id, headers, (size_t)hn);
        input_frame(f, LC_H2_DATA, 0, s->id, body, sizeof body);
        require(lc_spider_fetch_step(f, 0) == 1 && lc_spider_fetch_step(f, 0) == 1 &&
                    s->p_break && s->abort && !s->cleanup_prepared && !s->done &&
                    f->ccs->close_writer == s,
                "split Do Close signals abort but never executes cleanup inline");
        require(lc_spider_fetch_take(f, &write) == 13 && write[3] == LC_H2_WINDOW_UPDATE,
                "split Close decision holds an actual in-flight refund Write");
        if (end_first)
            input_frame(f, LC_H2_DATA, LC_H2_END_STREAM, s->id, NULL, 0);
        require(lc_spider_fetch_request_wait(f) == 1 &&
                    lc_spider_fetch_request_step(f) == 1 && s->cleanup_prepared &&
                    s->cleanup_reset == !end_first,
                "split cleanup chooses reset from peer state before writer wait");
        require(lc_spider_fetch_write_complete(f, 1) == 0,
                "split Close refund actually completes once");
        free(write);
        write = NULL;
        if (!end_first)
            input_frame(f, LC_H2_DATA, LC_H2_END_STREAM, s->id, NULL, 0);
        unsigned resets = 0;
        for (unsigned turn = 0; turn < 8u && !s->done; turn++) {
            require(lc_spider_fetch_request_step(f) >= 0, "split cleanup continuation");
            long n = lc_spider_fetch_take(f, &write);
            if (n == 0)
                continue;
            require(n == 13 && write[3] == LC_H2_RST_STREAM && write[12] == ERR_CANCEL,
                    "split cleanup emits only its selected CANCEL");
            resets++;
            require(lc_spider_fetch_write_complete(f, 1) == 0 &&
                        s->cleanup_pending && !s->done,
                    "Write completion wakes split cleanup without executing it inline");
            free(write);
            write = NULL;
        }
        require(s->done && resets == !end_first && lc_spider_fetch_request_step(f) == 0 &&
                    f->cuts == 0u,
                "both legal END_STREAM orders finish with no reset reselection or duplicate action");
        free(write);
        lc_spider_fetch_free(f);
    }
}

typedef struct {
    lc_spider_fetch *f;
    uint64_t generation;
    int request, result;
} split_wait_worker;

static void *split_wait_on_worker(void *arg)
{
    split_wait_worker *worker = arg;
    worker->result = worker->request ? lc_spider_fetch_request_wait(worker->f) :
                                     lc_spider_fetch_wait(worker->f, &worker->generation);
    return NULL;
}

static void test_split_idle_driver(void)
{
    uint8_t *write = NULL;
    lc_spider_fetch *f = driver_fixture_mode(&write, 1);
    require(lc_spider_fetch_write_complete(f, 1) == 0, "split idle request completes");
    free(write);
    uint64_t generation = f->generation;
    for (unsigned turn = 0; turn < 32u; turn++)
        require(lc_spider_fetch_step(f, 0) == 0 &&
                    lc_spider_fetch_request_step(f) == 0 && f->generation == generation &&
                    f->cuts == 0u && !request_task_ready(f),
                "quiescent tasks cannot manufacture a generation, retry wake or protocol action");
    split_wait_worker waiters[2] = {
        { .f = f, .generation = generation, .request = 0, .result = -99 },
        { .f = f, .generation = generation, .request = 1, .result = -99 }
    };
    pthread_t threads[2];
    for (unsigned i = 0; i < 2u; i++)
        require(pthread_create(&threads[i], NULL, split_wait_on_worker, &waiters[i]) == 0,
                "both split task waits start without new input");
    lc_spider_fetch_stop(f);
    for (unsigned i = 0; i < 2u; i++)
        require(pthread_join(threads[i], NULL) == 0 && waiters[i].result == 0,
                "stop interrupts either task before/during wait, both joined before free");
    require(lc_spider_fetch_request_wait(f) == 0 && lc_spider_fetch_wait(f, &generation) == 0,
            "stop persists for both later split waits");
    lc_spider_fetch_free(f);
}

/* processSettings always takes cc.wmu, including ACK; processPing's ACK does
 * not (vendor/x-net/http2/transport.go:2516-2532, :2700-2726). A held request
 * Write is real ownership, not a reason to discard or reorder the input tail. */
static void test_settings_ack_writer_driver(void)
{
    for (unsigned outcome = 0; outcome < 4u; outcome++) {
        uint8_t *write = NULL;
        lc_spider_fetch *f = driver_fixture_mode(&write, 1);
        fetch_cc *cc = f->ccs;
        fetch_stream *s = cc->streams;
        uint64_t request_id = s->request_write_id;
        require(cc->want_ack && cc->request_writer == s && request_id != 0u,
                "SETTINGS ACK fixture holds an unfinished request Write");
        const uint8_t nonce[8] = {0};
        input_frame(f, LC_H2_PING, LC_H2_ACK, 0, nonce, sizeof nonce);
        require(!cc->writer_wait && lc_spider_fetch_read_ready(f),
                "PING ACK does not acquire the request's writer");
        uint8_t input[2u * LC_H2_HEADER + 1u];
        (void)lc_h2_put_header(input, sizeof input, 0, LC_H2_SETTINGS, LC_H2_ACK, 0);
        (void)lc_h2_put_header(input + LC_H2_HEADER, sizeof input - LC_H2_HEADER,
                               1, LC_H2_HEADERS, LC_H2_END_HEADERS | LC_H2_END_STREAM, s->id);
        input[2u * LC_H2_HEADER] = 0x88; /* indexed :status 200 */
        require(lc_spider_fetch_feed(f, input, 4u) == 0 && !cc->writer_wait,
                "partial SETTINGS ACK header waits for its remaining input");
        require(lc_spider_fetch_feed(f, input + 4u, sizeof input - 4u) == 0 &&
                    cc->writer_wait && cc->want_ack && !s->resp && !s->peer_closed &&
                    !lc_spider_fetch_read_ready(f),
                "SETTINGS ACK and response tail wait for their own ClientConn writer");
        for (unsigned repeat = 0; repeat < 3u; repeat++)
            require(lc_spider_fetch_read_step(f) == 0 && cc->want_ack && !s->resp &&
                        s->request_write_id == request_id && f->cuts == 0u,
                    "repeated reader turns cannot acknowledge the held request Write");
        if (outcome == 1u) {
            lc_spider_fetch_stop(f);
            require(lc_spider_fetch_read_step(f) == 0 && cc->want_ack && !s->resp,
                    "stop leaves the unprocessed SETTINGS ACK and response tail intact");
        } else if (outcome == 2u) {
            require(lc_spider_fetch_write_complete(f, 0) == 0 &&
                        lc_spider_fetch_read_step(f) == -1 && cc->want_ack && !s->resp &&
                        cc->werr && cc->request_writer == NULL,
                    "failed request Write never publishes a successful SETTINGS ACK or response");
        } else {
            require(lc_spider_fetch_write_complete(f, 1) == 0 && cc->want_ack && !s->resp &&
                        cc->request_writer == NULL && s->sent_end_stream,
                    "socket completion releases ownership without dispatching the saved ACK");
            require(lc_spider_fetch_read_step(f) == 1 && !cc->want_ack && s->resp &&
                        s->peer_closed && lc_spider_fetch_read_ready(f) && f->cuts == 0u,
                    "reader resumes ACK then response exactly once without a reply ACK");
            if (outcome == 3u) {
                uint8_t ack[LC_H2_HEADER];
                (void)lc_h2_put_header(ack, sizeof ack, 0, LC_H2_SETTINGS, LC_H2_ACK, 0);
                require(lc_spider_fetch_feed(f, ack, sizeof ack) == -1,
                        "a duplicate SETTINGS ACK still fails the connection");
            } else {
                require(lc_spider_fetch_read_step(f) == 0 && !cc->want_ack && f->cuts == 0u,
                        "completed SETTINGS ACK has no duplicate continuation");
            }
        }
        free(write);
        lc_spider_fetch_free(f);
    }
}

/* ReadFrame parses and checks CONTINUATION ordering before processSettings or
 * processPing can acquire cc.wmu. Setting.Valid is later, inside processSettings. */
static void test_control_parser_before_writer_driver(void)
{
    for (unsigned kind = 0; kind < 8u; kind++) {
        uint8_t *write = NULL;
        lc_spider_fetch *f = driver_fixture_mode(&write, 1);
        fetch_cc *cc = f->ccs;
        uint8_t input[LC_H2_HEADER + 8u] = {0};
        uint8_t type = kind == 4u || kind == 5u ? LC_H2_PING : LC_H2_SETTINGS;
        uint8_t flags = kind < 2u ? LC_H2_ACK : 0;
        uint32_t stream = kind == 1u || kind == 5u ? 1u : 0u;
        uint32_t len = kind == 0u || kind == 3u || kind == 6u ? 6u :
                       kind == 2u ? 1u : kind == 4u ? 7u : kind == 5u ? 8u : 0u;
        (void)lc_h2_put_header(input, sizeof input, len, type, flags, stream);
        if (kind == 3u) {
            input[LC_H2_HEADER + 1u] = 4u;
            input[LC_H2_HEADER + 2u] = 0x80u; /* parseSettingsFrame: invalid window */
        } else if (kind == 6u) {
            input[LC_H2_HEADER + 1u] = 5u; /* Valid(): MAX_FRAME_SIZE=0 */
        } else if (kind == 7u) {
            const uint8_t status = 0x88;
            input_frame(f, LC_H2_HEADERS, 0, cc->streams->id, &status, 1u);
            require(cc->last_header_stream != 0u,
                    "parser fixture has an unfinished header block before SETTINGS");
        }
        int rc = lc_spider_fetch_feed(f, input, LC_H2_HEADER + len);
        if (kind == 6u) {
            require(rc == 0 && !f->closed && cc->writer_wait && f->cuts == 0u,
                    "Setting.Valid waits inside processSettings, after the parser succeeds");
            require(lc_spider_fetch_write_complete(f, 1) == 0 &&
                        lc_spider_fetch_read_step(f) == -1 && f->cuts == 0u,
                    "invalid setting is rejected after writer release without an ACK");
        } else {
            require(rc == -1 && f->closed && !cc->writer_wait && f->cuts == 0u,
                    "control frame parser and ordering errors do not wait for the request writer");
        }
        free(write);
        lc_spider_fetch_free(f);
    }
}

static void test_split_invalid_settings_driver(void)
{
    lc_browser b;
    require(lc_browser_chrome_anchored(&b, LC_BROWSER_NAV) == 0, "split invalid-settings browser");
    lc_spider_fetch *f = lc_spider_fetch_new("split-invalid.example", &b);
    require(f != NULL && lc_spider_fetch_request_tasks(f) == -1 &&
                lc_spider_fetch_request_step(f) == -1 && lc_spider_fetch_request_wait(f) == -1,
            "split task API rejects a legacy driver without advancing it");
    require(lc_spider_fetch_write_barrier(f) == 0 && lc_spider_fetch_request_tasks(f) == 0,
            "invalid-settings fixture enables split mode before publication");
    uint8_t *write = NULL;
    require(lc_spider_fetch_take(f, &write) > 0 &&
                lc_spider_fetch_request_tasks(f) == -1 &&
                lc_spider_fetch_write_complete(f, 1) == 0,
            "split driver cannot be reconfigured while a Write is in flight");
    free(write);
    write = NULL;
    const uint8_t settings[] = {0, 5, 0, 0, 0, 0};
    uint8_t input[LC_H2_HEADER + sizeof settings];
    (void)lc_h2_put_header(input, sizeof input, sizeof settings, LC_H2_SETTINGS, 0, 0);
    memcpy(input + LC_H2_HEADER, settings, sizeof settings);
    require(lc_spider_fetch_feed(f, input, sizeof input) == -1 &&
                lc_spider_fetch_request_wait(f) == -1 &&
                lc_spider_fetch_request_step(f) == -1 && lc_spider_fetch_step(f, 0) == -1 &&
                !f->ccs->stuck && f->cuts == 0u && f->ccs->streams == NULL,
            "invalid zero-frame SETTINGS terminate both tasks without ACK, request or stuck-writer fabrication");
    lc_spider_fetch_stop(f);
    require(lc_spider_fetch_request_wait(f) == 0, "stop takes precedence over invalid-input task failure");
    lc_spider_fetch_free(f);
}

/* A submitted request has not entered encodeAndWriteHeaders yet. A readLoop ACK
 * can win cc.wmu before the request task's first turn; drive actual Writes, not
 * synthetic owner changes. Abort is driven before and after the ACK in one fill. */
static void test_split_request_acquisition_driver(void)
{
    for (unsigned settings = 0; settings < 2u; settings++)
        for (unsigned outcome = 0; outcome < 5u; outcome++) {
            lc_browser b;
            require(lc_browser_chrome_anchored(&b, LC_BROWSER_NAV) == 0,
                    "queued request browser");
            lc_spider_fetch *f = lc_spider_fetch_new("queued-request.example", &b);
            require(f != NULL && lc_spider_fetch_write_barrier(f) == 0 &&
                        lc_spider_fetch_request_tasks(f) == 0,
                    "queued request split fixture");
            uint8_t *write = NULL;
            require(lc_spider_fetch_take(f, &write) > 0 &&
                        lc_spider_fetch_write_complete(f, 1) == 0,
                    "queued request opening completes");
            free(write);
            write = NULL;
            input_frame(f, LC_H2_SETTINGS, 0, 0, NULL, 0);
            require(lc_spider_fetch_take(f, &write) == 9 &&
                        lc_spider_fetch_write_complete(f, 1) == 0,
                    "queued request initial SETTINGS ACK completes");
            free(write);
            write = NULL;
            require(lc_spider_fetch_read_step(f) == 1 && lc_spider_fetch_read_ready(f),
                    "queued request initial reader resumes");
            lc_hpack_enc before = f->ccs->enc;
            require(lc_spider_fetch_step(f, 0) == 1,
                    "Do queues request without running its task");
            require(lc_spider_fetch_request_step(f) == 1 && f->cuts == 0u,
                    "request admission precedes the independent writer turn");
            fetch_cc *cc = f->ccs;
            fetch_stream *s = cc->streams;
            require(s->request_fields != NULL && !s->sent_headers && f->cuts == 0u &&
                        cc->request_pending == s &&
                        memcmp(&before, &cc->enc, sizeof before) == 0,
                    "queued request has not encoded or published HEADERS");
            const uint8_t nonce[8] = {0x13, 0x57, 0x9b, 0xdf, 0x24, 0x68, 0xac, 0xe0};
            /* INITIAL_WINDOW_SIZE=65534 takes effect before request writer entry. */
            const uint8_t setting[6] = {0, 4, 0, 0, 0xff, 0xfe};
            uint8_t input[30];
            size_t n = settings ? sizeof setting : sizeof nonce;
            uint8_t type = settings ? LC_H2_SETTINGS : LC_H2_PING;
            (void)lc_h2_put_header(input, sizeof input, (uint32_t)n, type, 0, 0);
            memcpy(input + LC_H2_HEADER, settings ? setting : nonce, n);
            n += LC_H2_HEADER;
            if (outcome >= 3u) {
                const uint8_t reset[4] = {0, 0, 0, ERR_CANCEL};
                size_t reset_at = n;
                if (outcome == 3u) {
                    memmove(input + LC_H2_HEADER + sizeof reset, input, n);
                    reset_at = 0;
                }
                (void)lc_h2_put_header(input + reset_at, sizeof input - reset_at, sizeof reset,
                                       LC_H2_RST_STREAM, 0, s->id);
                memcpy(input + reset_at + LC_H2_HEADER, reset, sizeof reset);
                n += LC_H2_HEADER + sizeof reset;
            }
            require(lc_spider_fetch_feed(f, input, n) == 0,
                    "readLoop accepts control frame before request task entry");
            long wn = lc_spider_fetch_take(f, &write);
            require(wn == (settings ? 9 : 17) && write[3] == type &&
                        write[4] == LC_H2_ACK &&
                        (settings || memcmp(write + LC_H2_HEADER, nonce, sizeof nonce) == 0),
                    "readLoop ACK precedes the queued request's first writer turn");
            require(cc->read_write_id != 0u && s->request_write_id == 0u &&
                        !s->sent_headers && s->request_fields != NULL &&
                        cc->request_pending == s && cc->request_writer == NULL &&
                        (!settings || (cc->init_window == 65534 && s->out == 65534)),
                    "ACK owns actual Flush while request remains unencoded");
            uint64_t generation = f->generation;
            for (unsigned turn = 0; turn < 3u; turn++)
                require(lc_spider_fetch_request_step(f) == 0 &&
                            !request_task_ready(f) && f->generation == generation &&
                            !s->cleanup_prepared && memcmp(&before, &cc->enc, sizeof before) == 0,
                        "request task cannot encode, clean up or spin behind the actual ACK Write");
            if (outcome == 1u) {
                lc_spider_fetch_stop(f);
                require(lc_spider_fetch_write_complete(f, 1) == 0 &&
                            lc_spider_fetch_request_wait(f) == 0 &&
                            lc_spider_fetch_request_step(f) == 0 && !s->sent_headers,
                        "stop before request acquisition never sends HEADERS");
            } else if (outcome == 2u) {
                require(lc_spider_fetch_write_complete(f, 0) == 0 &&
                            lc_spider_fetch_request_wait(f) == -1 &&
                            lc_spider_fetch_request_step(f) == -1 && !s->sent_headers,
                        "foreign ACK failure prevents request acquisition and successful completion");
            } else {
                require(lc_spider_fetch_write_complete(f, 1) == 0 &&
                            lc_spider_fetch_read_step(f) == 1 &&
                            lc_spider_fetch_read_ready(f) && cc->read_write_id == 0u,
                        "actual ACK completion resumes retained input without a fresh feed");
                free(write);
                write = NULL;
                require(lc_spider_fetch_request_wait(f) == 1 &&
                            lc_spider_fetch_request_step(f) == 1 && s->request_fields == NULL,
                        "request acquires its writer only on the independent task turn");
                if (outcome >= 3u) {
                    require(s->abort && !s->sent_headers && !s->cleanup_prepared &&
                                cc->request_pending == NULL && cc->request_writer == NULL &&
                                memcmp(&before, &cc->enc, sizeof before) == 0,
                            "retained peer abort skips encoding after actual writer acquisition");
                    require(lc_spider_fetch_request_step(f) == 1 &&
                                lc_spider_fetch_request_step(f) == 1 && s->done && s->forgotten &&
                                !s->cleanup_reset && lc_spider_fetch_take(f, &write) == 0 &&
                                lc_spider_fetch_request_step(f) == 0,
                            "queued aborted request finishes once without HEADERS, CANCEL or new input");
                } else {
                    require(lc_spider_fetch_take(f, &write) > 9 &&
                                write[3] == LC_H2_HEADERS && write[8] == s->id &&
                                cc->request_writer == s && s->request_write_id != 0u &&
                                cc->request_pending == NULL &&
                                s->sent_headers && !s->sent_end_stream,
                            "acquired request owns its real HEADERS Flush until completion");
                    require(lc_spider_fetch_request_step(f) == 0 &&
                                lc_spider_fetch_write_complete(f, 1) == 0 &&
                                cc->request_writer == NULL && s->sent_end_stream &&
                                lc_spider_fetch_request_step(f) == 0,
                            "actual request completion releases writer exactly once");
                }
            }
            free(write);
            write = NULL;
            require(lc_spider_fetch_take(f, &write) == 0,
                    "queued request boundary leaves no duplicate ACK or request Write");
            lc_spider_fetch_free(f);
        }
}

/* internalRoundTrip starts doRequest after newClientConn's Flush, not after
 * a readLoop ACK. Stream admission precedes encodeAndWriteHeaders' cc.wmu. */
/* A Do task is not a stream in ClientConn.streams until writeRequest enters
 * addStreamLocked. Exercise peer input and stop on that exact boundary. */
static void test_unassigned_stream_driver(void)
{
    for (unsigned outcome = 0; outcome < 4u; outcome++) {
        lc_browser b;
        require(lc_browser_chrome_anchored(&b, LC_BROWSER_NAV) == 0,
                "unassigned stream browser");
        lc_spider_fetch *f = lc_spider_fetch_new("unassigned.example", &b);
        require(f != NULL && lc_spider_fetch_write_barrier(f) == 0 &&
                    lc_spider_fetch_request_tasks(f) == 0, "unassigned stream fixture");
        uint8_t *write = NULL;
        require(lc_spider_fetch_take(f, &write) > 0 &&
                    lc_spider_fetch_write_complete(f, 1) == 0,
                "unassigned stream opening completes");
        free(write);
        input_frame(f, LC_H2_SETTINGS, 0, 0, NULL, 0);
        write = NULL;
        require(lc_spider_fetch_take(f, &write) == 9 &&
                    lc_spider_fetch_write_complete(f, 1) == 0 &&
                    lc_spider_fetch_read_step(f) == 1,
                "unassigned stream SETTINGS completes");
        free(write);
        fetch_cc *cc = f->ccs;
        lc_hpack_enc before = cc->enc;
        require(lc_spider_fetch_step(f, 0) == 1 && cc->request_pending != NULL,
                "Do queues the request without running its task");
        fetch_stream *s = cc->request_pending;
        require(s->id == 0u && cc->next_id == 1u && cc->reserved == 1u &&
                    stream_by_id(cc, 1u, 0) == NULL,
                "pending request owns a reservation but no observable stream ID");
        if (outcome == 0u) {
            uint8_t data[LC_H2_HEADER];
            (void)lc_h2_put_header(data, sizeof data, 0, LC_H2_DATA, 0, 1u);
            require(lc_spider_fetch_feed(f, data, sizeof data) == -1 && f->closed &&
                        s->id == 0u && cc->next_id == 1u &&
                        lc_spider_fetch_request_step(f) == -1,
                    "DATA before addStreamLocked fails the connection without assigning an ID");
        } else if (outcome == 1u) {
            const uint8_t reset[] = {0, 0, 0, ERR_CANCEL};
            input_frame(f, LC_H2_RST_STREAM, 0, 1u, reset, sizeof reset);
            require(!s->abort && lc_spider_fetch_request_step(f) == 1 &&
                        s->id == 1u && cc->next_id == 3u && cc->reserved == 0u &&
                        !s->sent_headers,
                    "reset for an unassigned stream is ignored before request admission");
        } else if (outcome == 2u) {
            lc_spider_fetch_stop(f);
            require(lc_spider_fetch_request_wait(f) == 0 &&
                        lc_spider_fetch_request_step(f) == 0 && s->id == 0u &&
                        cc->next_id == 1u && cc->reserved == 1u,
                    "stop before request execution cannot consume a stream ID");
        } else {
            const uint8_t setting[] = {0, 3, 0, 0, 0, 0};
            input_frame(f, LC_H2_SETTINGS, 0, 0, setting, sizeof setting);
            require(lc_spider_fetch_request_step(f) == 1 && s->abort &&
                        s->abort_kind == AB_UNUSABLE && s->id == 0u &&
                        cc->next_id == 1u && cc->reserved == 0u &&
                        cc->request_pending == NULL && s->request_fields == NULL,
                    "peer concurrency change is checked at admission without an ID or reservation leak");
        }
        require(!s->sent_headers && memcmp(&before, &cc->enc, sizeof before) == 0,
                "unassigned-stream outcomes never encode request HEADERS");
        lc_spider_fetch_free(f);
    }
}

static void test_request_admission_notifications(void)
{
    for (unsigned outcome = 0; outcome < 6u; outcome++) {
        lc_browser browser;
        require(lc_browser_chrome_anchored(&browser, LC_BROWSER_NAV) == 0,
                "admission notification browser");
        lc_spider_fetch *f = lc_spider_fetch_new("admission-notify.example", &browser);
        require(f != NULL && lc_spider_fetch_write_barrier(f) == 0 &&
                    lc_spider_fetch_request_tasks(f) == 0,
                "admission notification split fixture");
        uint8_t *write = NULL;
        require(lc_spider_fetch_take(f, &write) > 0 &&
                    lc_spider_fetch_write_complete(f, 1) == 0 &&
                    lc_spider_fetch_step(f, 0) == 1,
                "admission notification opening and request queue");
        free(write);
        fetch_cc *cc = f->ccs;
        fetch_stream *s = cc->request_pending;
        require(s != NULL && s->id == 0u, "admission starts without a stream ID");
        if (outcome == 1u)
            cc->closed = 1;
        else if (outcome == 2u)
            cc->max_streams = 0u;
        else if (outcome == 3u)
            lc_spider_fetch_lost(f);
        else if (outcome == 4u)
            lc_spider_fetch_stop(f);
        else if (outcome == 5u)
            f->oom = 1;
        atomic_store(&watched_do_cond, &f->consumer);
        atomic_store(&do_notifications, 0u);
        uint64_t generation = f->generation;
        int rc = lc_spider_fetch_request_step(f);
        if (outcome == 0u) {
            require(rc == 1 && s->id == 1u && !s->sent_headers && f->cuts == 0u &&
                        f->generation == generation && atomic_load(&do_notifications) == 0u,
                    "successful stream admission does not wake Do without a response");
            require(lc_spider_fetch_request_wait(f) == 1 &&
                        lc_spider_fetch_request_step(f) == 1 && f->cuts != 0u &&
                        f->generation != generation && atomic_load(&do_notifications) > 0u,
                    "encoding remains runnable and publishes its actual Write");
        } else if (outcome == 4u) {
            require(rc == 0 && f->generation == generation &&
                        atomic_load(&do_notifications) == 0u,
                    "stopped admission does not manufacture more task progress");
        } else {
            require(rc == (outcome < 3u ? 1 : -1) &&
                        f->generation != generation && atomic_load(&do_notifications) > 0u,
                    "admission rejection and terminal failure still notify Do");
            if (outcome < 3u)
                require(s->abort && s->id == 0u && cc->request_pending == NULL,
                        "failed admission releases the queued producer without assigning an ID");
        }
        atomic_store(&watched_do_cond, NULL);
        lc_spider_fetch_free(f);
    }
}

static void test_cleanup_completion_notifications(void)
{
    for (unsigned outcome = 0; outcome < 3u; outcome++) {
        uint8_t *write = NULL;
        lc_spider_fetch *f = driver_fixture_mode(&write, 1);
        require(lc_spider_fetch_write_complete(f, 1) == 0,
                "cleanup notification request completes");
        free(write);
        write = NULL;
        fetch_stream *s = f->ccs->streams;
        const lc_hpack_field fields[] = {
            {":status", "302"}, {"location", "/next"}, {"content-length", "5000"}
        };
        uint8_t headers[128];
        long hn = lc_hpack_encode(fields, 3u, headers, sizeof headers);
        require(hn > 0, "cleanup notification redirect encodes");
        input_frame(f, LC_H2_HEADERS, LC_H2_END_HEADERS, s->id, headers, (size_t)hn);
        require(lc_spider_fetch_step(f, 0) == 1 && lc_spider_fetch_step(f, 0) >= 0 &&
                    f->state == DO_CLOSE && s->p_break && !s->close_pending && !s->done &&
                    lc_spider_fetch_request_step(f) == 1 &&
                    lc_spider_fetch_take(f, &write) == 13,
                "Do waits for donec while executor holds its real reset Write");
        if (outcome == 2u)
            lc_spider_fetch_stop(f);
        atomic_store(&watched_do_cond, &f->consumer);
        atomic_store(&watched_request_cond, &f->request_consumer);
        atomic_store(&do_notifications, 0u);
        atomic_store(&request_notifications, 0u);
        uint64_t generation = f->generation;
        require(lc_spider_fetch_write_complete(f, outcome != 1u) == 0,
                "cleanup notification reports actual reset outcome");
        free(write);
        if (outcome == 0u) {
            require(f->generation == generation && atomic_load(&do_notifications) == 0u &&
                        atomic_load(&request_notifications) > 0u &&
                        lc_spider_fetch_request_wait(f) == 1,
                    "reset completion wakes executor without waking Do waiting on donec");
            require(lc_spider_fetch_request_step(f) == 1 && s->forgotten && !s->done &&
                        f->generation == generation && atomic_load(&do_notifications) == 0u,
                    "stream removal does not announce donec before final werr check");
            require(lc_spider_fetch_request_step(f) == 1 && s->done &&
                        f->generation != generation && atomic_load(&do_notifications) == 1u &&
                        lc_spider_fetch_wait(f, &generation) == 1,
                    "actual donec completion wakes Do once without fresh input");
        } else {
            require(f->generation != generation && atomic_load(&do_notifications) > 0u &&
                        atomic_load(&request_notifications) > 0u,
                    "failure and stopped completion still wake both tasks");
        }
        atomic_store(&watched_do_cond, NULL);
        atomic_store(&watched_request_cond, NULL);
        lc_spider_fetch_free(f);
    }
}

static void test_initial_admission_driver(void)
{
    for (unsigned ping = 0; ping < 2u; ping++)
        for (unsigned outcome = 0; outcome < 4u; outcome++) {
            lc_browser b;
            require(lc_browser_chrome_anchored(&b, LC_BROWSER_NAV) == 0,
                    "initial admission browser");
            lc_spider_fetch *f = lc_spider_fetch_new("initial-admission.example", &b);
            require(f != NULL && lc_spider_fetch_write_barrier(f) == 0 &&
                        lc_spider_fetch_request_tasks(f) == 0,
                    "initial admission split fixture");
            fetch_cc *cc = f->ccs;
            uint8_t *write = NULL;
            require(lc_spider_fetch_take(f, &write) > 0 &&
                        lc_spider_fetch_step(f, 0) == 2 && cc->streams == NULL &&
                        lc_spider_fetch_request_step(f) == 0,
                    "initial admission waits for its own opening Flush");
            require(lc_spider_fetch_write_complete(f, 1) == 0,
                    "initial admission opening completes");
            free(write);
            write = NULL;
            if (ping) {
                input_frame(f, LC_H2_SETTINGS, 0, 0, NULL, 0);
                require(lc_spider_fetch_take(f, &write) == 9 &&
                            lc_spider_fetch_write_complete(f, 1) == 0 &&
                            lc_spider_fetch_read_step(f) == 1,
                        "initial admission completes SETTINGS before later PING");
                free(write);
                write = NULL;
            }
            const uint8_t nonce[8] = {0};
            input_frame(f, ping ? LC_H2_PING : LC_H2_SETTINGS, 0, 0,
                        ping ? nonce : NULL, ping ? sizeof nonce : 0u);
            require(lc_spider_fetch_take(f, &write) == (ping ? 17 : 9),
                    "initial admission holds a real readLoop ACK Flush");
            uint64_t ack_id = f->active_write.id;
            lc_hpack_enc before = cc->enc;
            require(lc_spider_fetch_step(f, 0) == 1 && cc->request_pending != NULL,
                    "initial RoundTrip admits its request behind the readLoop ACK");
            fetch_stream *s = cc->request_pending;
            require(s->id == 0u && cc->next_id == 1u && s->request_fields != NULL && !s->sent_headers,
                    "Do submission leaves the stream ID unassigned");
            require(lc_spider_fetch_request_step(f) == 1 && s->id == 1u &&
                        s->request_fields != NULL && !s->sent_headers &&
                        memcmp(&before, &cc->enc, sizeof before) == 0 &&
                        f->active_write.id == ack_id && cc->read_write_id == ack_id &&
                        f->cuts == 0u && lc_spider_fetch_request_step(f) == 0 &&
                        lc_spider_fetch_step(f, 0) == 2,
                    "admission neither acquires the owned writer nor mutates HPACK or ACK completion");
            if (outcome == 1u) {
                lc_spider_fetch_stop(f);
                uint64_t generation = 0;
                require(lc_spider_fetch_wait(f, &generation) == 0 &&
                            lc_spider_fetch_request_wait(f) == 0 &&
                            lc_spider_fetch_request_step(f) == 0 && !s->sent_headers &&
                            f->active_write.id == ack_id,
                        "stop preserves the admitted request and unfinished ACK without writing");
            } else if (outcome == 2u) {
                require(lc_spider_fetch_write_complete(f, 0) == 0 && f->closed &&
                            lc_spider_fetch_request_step(f) == -1 && !s->sent_headers &&
                            memcmp(&before, &cc->enc, sizeof before) == 0,
                        "failed ACK cannot encode the newly admitted request");
            } else {
                require(lc_spider_fetch_write_complete(f, 1) == 0 &&
                            lc_spider_fetch_read_step(f) == 1,
                        "only actual ACK completion releases its writer");
                free(write);
                write = NULL;
                if (outcome == 3u) {
                    const uint8_t reset[4] = {0, 0, 0, ERR_CANCEL};
                    input_frame(f, LC_H2_RST_STREAM, 0, s->id, reset, sizeof reset);
                }
                require(lc_spider_fetch_request_step(f) == 1,
                        "admitted request reaches its independent writer turn");
                if (outcome == 3u) {
                    require(!s->sent_headers && cc->request_pending == NULL &&
                                cc->request_writer == NULL && f->cuts == 0u &&
                                memcmp(&before, &cc->enc, sizeof before) == 0,
                            "abort after admission but before encoding leaves HPACK and wire unchanged");
                } else {
                    require(lc_spider_fetch_take(f, &write) > 9 &&
                                write[3] == LC_H2_HEADERS && !s->sent_end_stream &&
                                lc_spider_fetch_write_complete(f, 1) == 0 && s->sent_end_stream,
                            "HEADERS follows the ACK and completes only through its own Flush");
                }
            }
            free(write);
            lc_spider_fetch_free(f);
        }
}

static void test_split_cancel_before_encoding_driver(void)
{
    lc_browser b;
    require(lc_browser_chrome_anchored(&b, LC_BROWSER_NAV) == 0, "pre-encoding browser");
    lc_spider_fetch *f = lc_spider_fetch_new("split-unsent.example", &b);
    require(f != NULL && lc_spider_fetch_write_barrier(f) == 0 &&
                lc_spider_fetch_request_tasks(f) == 0, "pre-encoding split fixture");
    uint8_t *write = NULL;
    require(lc_spider_fetch_take(f, &write) > 0 && lc_spider_fetch_write_complete(f, 1) == 0,
            "pre-encoding opening completes");
    free(write);
    write = NULL;
    input_frame(f, LC_H2_SETTINGS, 0, 0, NULL, 0);
    require(lc_spider_fetch_take(f, &write) == 9 && lc_spider_fetch_write_complete(f, 1) == 0,
            "pre-encoding SETTINGS ACK completes");
    free(write);
    write = NULL;
    require(lc_spider_fetch_read_step(f) == 1 && lc_spider_fetch_read_ready(f),
            "pre-encoding loop owner resumes initial SETTINGS before peer abort");
    lc_hpack_enc before = f->ccs->enc;
    require(lc_spider_fetch_step(f, 0) == 1, "Do submits unencoded request fields");
    require(lc_spider_fetch_request_step(f) == 1 && f->cuts == 0u,
            "request task assigns an ID before the separate encoding phase");
    fetch_stream *s = f->ccs->streams;
    require(s->request_fields != NULL && s->request_block == NULL && !s->sent_headers &&
                f->cuts == 0u && memcmp(&before, &f->ccs->enc, sizeof before) == 0,
            "request submission cannot mutate HPACK before its independent writer turn");
    const uint8_t reset[] = {0, 0, 0, ERR_CANCEL};
    input_frame(f, LC_H2_RST_STREAM, 0, s->id, reset, sizeof reset);
    require(lc_spider_fetch_request_wait(f) == 1 &&
                lc_spider_fetch_request_step(f) == 1 && s->abort &&
                s->request_fields == NULL && !s->sent_headers && !s->cleanup_prepared &&
                memcmp(&before, &f->ccs->enc, sizeof before) == 0,
            "abort before writer entry frees owned fields without encoding or sending HEADERS");
    require(lc_spider_fetch_request_step(f) == 1 &&
                lc_spider_fetch_request_step(f) == 1 && s->done && s->forgotten &&
                !s->cleanup_reset && lc_spider_fetch_take(f, &write) == 0 &&
                lc_spider_fetch_request_step(f) == 0,
            "unsent aborted request cleans up exactly once without CANCEL or HPACK divergence");
    lc_spider_fetch_free(f);
}

static void test_private_redirect_driver(void)
{
    for (unsigned outcome = 0; outcome < 3u; outcome++) {
        uint8_t *write = NULL;
        lc_spider_fetch *f = driver_fixture(&write);
        fetch_stream *s = f->ccs->streams;
        const lc_hpack_field fields[] = {
            {":status", "302"}, {"location", "/next"}, {"content-length", "5000"}
        };
        uint8_t headers[128], body[5000] = {0};
        long hn = lc_hpack_encode(fields, 3u, headers, sizeof headers);
        require(hn > 0, "private redirect headers encode");
        input_frame(f, LC_H2_HEADERS, LC_H2_END_HEADERS, s->id, headers, (size_t)hn);
        pthread_mutex_lock(&prep_lock);
        prep_pause = 1;
        prep_entered = prep_release = 0;
        pthread_mutex_unlock(&prep_lock);
        prep_worker worker = { .f = f, .result = -99 };
        pthread_t thread;
        require(pthread_create(&thread, NULL, prepare_on_worker, &worker) == 0,
                "private redirect starts on the consumer thread");
        pthread_mutex_lock(&prep_lock);
        struct timespec deadline;
        require(clock_gettime(CLOCK_REALTIME, &deadline) == 0, "checkpoint deadline");
        deadline.tv_sec += 5;
        while (!prep_entered)
            require(pthread_cond_timedwait(&prep_changed, &prep_lock, &deadline) == 0,
                    "consumer reaches the private redirect checkpoint");
        pthread_mutex_unlock(&prep_lock);
        require(pthread_mutex_trylock(&f->lock) == 0,
                "private URL/header preparation does not hold the protocol mutex");
        pthread_mutex_unlock(&f->lock);
        require(pthread_mutex_trylock(&f->do_lock) == EBUSY,
                "another consumer cannot replace Do during private preparation");
        if (outcome == 0u) {
            input_frame(f, LC_H2_DATA, LC_H2_END_STREAM, s->id, body, sizeof body);
            require(s->peer_closed && s->pb_len == sizeof body && !s->p_break &&
                        lc_spider_fetch_write_complete(f, 1) == 0,
                    "feed and actual request completion advance while Do prepares the redirect");
        } else if (outcome == 1u) {
            lc_spider_fetch_stop(f);
        } else {
            require(lc_spider_fetch_write_complete(f, 0) == 0,
                    "failed Write reaches private Do without waiting for its preparation");
        }
        pthread_mutex_lock(&prep_lock);
        prep_release = 1;
        pthread_cond_broadcast(&prep_changed);
        pthread_mutex_unlock(&prep_lock);
        require(pthread_join(thread, NULL) == 0, "private redirect joins before resource release");
        pthread_mutex_lock(&prep_lock);
        prep_pause = 0;
        pthread_mutex_unlock(&prep_lock);
        require(worker.result == (outcome == 0u ? 1 : outcome == 1u ? 0 : -1),
                "private Do rechecks input, stop and Write failure before publishing its next phase");
        if (outcome == 0u) {
            free(write);
            write = NULL;
            unsigned refunds = 0, requests = 0;
            for (unsigned turn = 0; turn < 12u && requests == 0u; turn++) {
                require(lc_spider_fetch_step(f, 0) >= 0, "private redirect continuation");
                long n = lc_spider_fetch_take(f, &write);
                if (n == 0) continue;
                require(n > 9 && (write[3] == LC_H2_WINDOW_UPDATE || write[3] == LC_H2_HEADERS),
                        "completed peer is refunded and redirected, never cancelled");
                if (write[3] == LC_H2_WINDOW_UPDATE) refunds++;
                else requests++;
                require(lc_spider_fetch_write_complete(f, 1) == 0,
                        "private redirect's own Write actually completes");
                free(write);
                write = NULL;
            }
            require(refunds == 1u && requests == 1u,
                    "private redirect resumes with exact refund and no duplicated request");
        } else {
            require(!s->p_break && !s->done && f->cuts == 0u && f->state == DO_ATTEMPT,
                    "stop/error during private preparation cannot run Close or publish success");
        }
        free(write);
        lc_spider_fetch_free(f);
    }
}

static void test_close_driver(void)
{
    for (unsigned owner = 0; owner < 2u; owner++)
        for (unsigned buffered = 0; buffered < 3u; buffered++)
            for (unsigned teardown = 0; teardown < (buffered == 2u ? 5u : 3u); teardown++) {
                uint8_t *write = NULL;
                lc_spider_fetch *f = driver_fixture(&write);
                fetch_cc *cc = f->ccs;
                fetch_stream *s = cc->streams;
                if (owner == 0u) {
                    require(lc_spider_fetch_write_complete(f, 1) == 0,
                            "Close fixture completes request before foreign ACK");
                    free(write);
                    write = NULL;
                }
                const lc_hpack_field fields[] = {
                    {":status", "302"}, {"location", "/next"}, {"content-length", "5000"}
                };
                uint8_t headers[128];
                long hn = lc_hpack_encode(fields, 3u, headers, sizeof headers);
                require(hn > 0, "Close redirect headers encode");
                input_frame(f, LC_H2_HEADERS, LC_H2_END_HEADERS, s->id, headers, (size_t)hn);
                int64_t credit_before = cc->in_avail;
                int64_t unsent_before = cc->in_unsent;
                size_t unread = buffered == 2u ? 5000u : buffered;
                if (buffered) {
                    uint8_t body[5000] = {0};
                    input_frame(f, LC_H2_DATA, 0, s->id, body, unread);
                }
                if (owner == 0u) {
                    const uint8_t nonce[8] = {0};
                    input_frame(f, LC_H2_PING, 0, 0, nonce, sizeof nonce);
                    require(lc_spider_fetch_take(f, &write) == 17,
                            "Close fixture holds foreign ACK");
                }
                uint64_t generation = 0;
                require(lc_spider_fetch_wait(f, &generation) == 1,
                        "response continuation is runnable behind either writer owner");
                for (unsigned turn = 0; turn < 4u; turn++)
                    if (lc_spider_fetch_step(f, 0) != 1)
                        break;
                require(s->p_break && s->abort && s->abort_kind == AB_CLOSED &&
                            s->pb_len == 0u &&
                            cc->in_avail == credit_before - (buffered == 1u ? 1 : 0) &&
                            cc->in_unsent == unsent_before + (buffered == 1u ? 1 : 0) && !s->done,
                        "Close breaks/aborts/accounts before acquiring the busy writer");
                require(f->cuts == 0u && lc_spider_fetch_step(f, 0) == 2,
                        "repeated Close wait emits no conflicting Write or duplicate credit");
                if (teardown == 1u) {
                    lc_spider_fetch_stop(f);
                    require(lc_spider_fetch_wait(f, &generation) == 0 &&
                                lc_spider_fetch_step(f, 0) == 0 && !s->done,
                            "stop interrupts Close's first writer wait");
                } else if (teardown == 2u) {
                    require(lc_spider_fetch_write_complete(f, 0) == 0 &&
                                lc_spider_fetch_step(f, 0) < 0 && !s->done,
                            "failed foreign Write cannot complete Close");
                } else {
                    require(lc_spider_fetch_write_complete(f, 1) == 0 &&
                                lc_spider_fetch_wait(f, &generation) == 1,
                            "foreign completion resumes Close without new input");
                    free(write);
                    write = NULL;
                    unsigned credits = 0, resets = 0, requests = 0;
                    int interrupted = 0;
                    for (unsigned turn = 0; turn < 20u && requests == 0u; turn++) {
                        require(lc_spider_fetch_step(f, 0) >= 0, "Close continuation step");
                        long n = lc_spider_fetch_take(f, &write);
                        if (n <= 0)
                            continue;
                        size_t off = 0;
                        int refund = 0;
                        while (off + LC_H2_HEADER <= (size_t)n) {
                            lc_h2_hd hd;
                            require(lc_h2_get_header(write + off, (size_t)n - off, &hd) == 0,
                                    "Close output header parses");
                            if (hd.type == LC_H2_WINDOW_UPDATE && hd.stream == 0u) {
                                credits++;
                                refund = 1;
                                require(hd.len == 4u && write[off + 11u] == 0x13 &&
                                            write[off + 12u] == 0x88,
                                        "Close returns exactly 5000 connection bytes");
                            }
                            if (hd.type == LC_H2_RST_STREAM && hd.stream == s->id)
                            {
                                require(hd.len == 4u && write[off + 12u] == ERR_CANCEL,
                                        "Close cleanup cancels the unfinished stream");
                                resets++;
                            }
                            if (hd.type == LC_H2_HEADERS && hd.stream != s->id)
                                requests++;
                            off += LC_H2_HEADER + hd.len;
                        }
                        require(off == (size_t)n, "Close output contains only complete frames");
                        if (refund) {
                            const uint8_t nonce[8] = {0};
                            input_frame(f, LC_H2_PING, 0, 0, nonce, sizeof nonce);
                            require(cc->close_writer == s && cc->writer_wait && f->cuts == 0u &&
                                        lc_spider_fetch_step(f, 0) == 2,
                                    "late ACK waits on Close's actual credit Flush owner");
                        }
                        if (refund && teardown >= 3u) {
                            require(requests == 0u, "next request waits for Close Flush completion");
                            if (teardown == 3u) {
                                lc_spider_fetch_stop(f);
                                require(lc_spider_fetch_wait(f, &generation) == 0 &&
                                            lc_spider_fetch_step(f, 0) == 0,
                                        "stop interrupts Close's own credit Flush");
                            } else {
                                require(lc_spider_fetch_write_complete(f, 0) == 0 &&
                                            lc_spider_fetch_step(f, 0) < 0,
                                        "failed Close credit Flush terminates before redirect");
                            }
                            interrupted = 1;
                            break;
                        }
                        require(lc_spider_fetch_write_complete(f, 1) == 0,
                                "Close output actually completes");
                        free(write);
                        write = NULL;
                    }
                    require(credits == (buffered == 2u ? 1u : 0u) && resets <= 1u &&
                                (teardown >= 3u ? interrupted : (requests == 1u && resets == 1u)),
                            "Close resumes once, without duplicate credit/reset or a lost wakeup");
                    require(cc->in_avail == credit_before - (buffered == 1u ? 1 : 0) &&
                                cc->in_unsent == unsent_before + (buffered == 1u ? 1 : 0),
                            "Close credit is not re-accounted, including below the refresh threshold");
                }
                free(write);
                lc_spider_fetch_free(f);
            }
}

static void test_read_driver(void)
{
    for (unsigned owner = 0; owner < 2u; owner++)
        for (unsigned gzip = 0; gzip < 2u; gzip++)
            for (unsigned credit = 0; credit < 2u; credit++)
                for (unsigned teardown = 0; teardown < (credit ? 5u : 3u); teardown++) {
                    uint8_t *write = NULL;
                    lc_spider_fetch *f = driver_fixture(&write);
                    fetch_cc *cc = f->ccs;
                    fetch_stream *s = cc->streams;
                    if (owner == 1u) {
                        require(lc_spider_fetch_write_complete(f, 1) == 0,
                                "Read fixture completes request before cleanup Write");
                        free(write);
                        write = NULL;
                    }
                    lc_hpack_field fields[] = {{":status", "200"}, {"content-encoding", "gzip"}};
                    uint8_t headers[128];
                    long hn = lc_hpack_encode(fields, gzip ? 2u : 1u, headers, sizeof headers);
                    require(hn > 0, "Read response headers encode");
                    input_frame(f, LC_H2_HEADERS, LC_H2_END_HEADERS, s->id, headers, (size_t)hn);
                    uint8_t body[2500], encoded[3000];
                    uint32_t random = 2463534242u;
                    for (size_t i = 0; i < sizeof body; i++) {
                        random ^= random << 13;
                        random ^= random >> 17;
                        random ^= random << 5;
                        body[i] = (uint8_t)"0123456789abcdef"[random & 15u];
                    }
                    const uint8_t *data = body;
                    size_t n = sizeof body;
                    if (gzip) {
                        z_stream z = {0};
                        require(deflateInit2(&z, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 31, 8,
                                             Z_DEFAULT_STRATEGY) == Z_OK, "Read gzip fixture encoder");
                        z.next_in = body;
                        z.avail_in = sizeof body;
                        z.next_out = encoded;
                        z.avail_out = sizeof encoded;
                        require(deflate(&z, Z_FINISH) == Z_STREAM_END, "Read gzip fixture encodes");
                        data = encoded;
                        n = sizeof encoded - z.avail_out;
                        require(deflateEnd(&z) == Z_OK, "Read gzip fixture encoder closes");
                    }
                    cc->in_unsent = s->in_unsent = credit ? 3000 : 0;
                    input_frame(f, LC_H2_DATA, owner == 0u ? LC_H2_END_STREAM : 0,
                                s->id, data, n);
                    if (owner == 1u) {
                        /* A duplicate pseudo-header aborts this stream locally, so production
                         * cleanup takes cc.wmu for its reset while the response pipe still has data. */
                        const uint8_t invalid[] = {0x88, 0x88};
                        input_frame(f, LC_H2_HEADERS, LC_H2_END_HEADERS,
                                    s->id, invalid, sizeof invalid);
                        require(lc_spider_fetch_step(f, 0) == 1 &&
                                    lc_spider_fetch_take(f, &write) == 13 && cc->cleanup_writer == s &&
                                    s->p_err == LC_GZ_NONE,
                                "Read fixture holds production cleanup reset Write");
                    }
                    uint64_t identity = f->active_write.id, generation = 0;
                    require(lc_spider_fetch_wait(f, &generation) == 1,
                            "Read consumer wakes behind request/cleanup Write");
                    for (unsigned turn = 0; turn < 30u; turn++)
                        if (lc_spider_fetch_step(f, 0) != 1)
                            break;
                    if (credit) {
                        require(s->source_pending && !s->source_flushed && s->source_len > 0u &&
                                    f->body_writer_wait && !f->d->rd_done && cc->source_writer == NULL,
                                "Read consumes/accounts before waiting on request/cleanup writer");
                        require(s->source_conn_credit == s->source_stream_credit &&
                                    s->source_conn_credit == 3000u + n - s->pb_len &&
                                    s->source_conn_credit >= 4096u && s->source_len <= n - s->pb_len &&
                                    memcmp(s->source_read, data + n - s->pb_len - s->source_len,
                                           s->source_len) == 0,
                                "Read retains its once-accounted credit and owned bytes");
                    } else {
                        require(f->d->rd_done == (owner == 0u) && s->pb_len == 0u && !s->done &&
                                    cc->in_unsent == (int64_t)n && s->in_unsent == (int64_t)n,
                                "plain/gzip Read drains behind either Write, but waits for cleanup's pipe error");
                        require(!f->d->rd_err && (owner == 0u || s->p_err == LC_GZ_NONE),
                                "independent Read cannot observe cleanup error before reset Flush");
                    }
                    require(f->active_write.id == identity && f->cuts == 0u &&
                                lc_spider_fetch_step(f, 0) == 2 && !consumer_ready(f) &&
                                !lc_spider_fetch_done(f),
                            "Read never completes foreign Write or invents competing output/success");
                    if (teardown == 1u) {
                        lc_spider_fetch_stop(f);
                        require(lc_spider_fetch_wait(f, &generation) == 0 &&
                                    lc_spider_fetch_step(f, 0) == 0 && !s->done,
                                "stop interrupts independent Read or its first writer wait");
                    } else if (teardown == 2u) {
                        require(lc_spider_fetch_write_complete(f, 0) == 0 &&
                                    lc_spider_fetch_step(f, 0) < 0 && !s->done,
                                "failed foreign Write terminates independent Read continuation");
                    } else {
                        require(lc_spider_fetch_write_complete(f, 1) == 0 &&
                                    lc_spider_fetch_wait(f, &generation) == 1,
                                "foreign completion resumes Read without fresh input");
                        if (owner == 1u)
                            require(s->p_err == LC_GZ_ERR && f->body_ready && !s->done &&
                                        s->cleanup_final_pending,
                                    "actual reset completion publishes pipe error and wakes its drained Read");
                        free(write);
                        write = NULL;
                        unsigned credits = 0;
                        int interrupted = 0;
                        for (unsigned turn = 0; turn < 40u && !lc_spider_fetch_done(f); turn++) {
                            require(lc_spider_fetch_step(f, 0) >= 0, "Read continuation step");
                            long wn = lc_spider_fetch_take(f, &write);
                            if (wn <= 0)
                                continue;
                            require(wn == 26 && write[3] == LC_H2_WINDOW_UPDATE &&
                                        write[16] == LC_H2_WINDOW_UPDATE &&
                                        cc->source_writer == s && s->source_pending &&
                                        s->source_flushed && !f->d->rd_done,
                                    "Read holds owned bytes until both credit updates actually Flush");
                            credits++;
                            require(lc_spider_fetch_step(f, 0) == 2 && !consumer_ready(f),
                                    "Read cannot consume its own pending credit Write");
                            if (teardown >= 3u) {
                                if (teardown == 3u) {
                                    lc_spider_fetch_stop(f);
                                    require(lc_spider_fetch_wait(f, &generation) == 0 &&
                                                lc_spider_fetch_step(f, 0) == 0 && !f->d->rd_done,
                                            "stop preserves Read pending its own Flush");
                                } else {
                                    require(lc_spider_fetch_write_complete(f, 0) == 0 &&
                                                lc_spider_fetch_step(f, 0) < 0 && s->source_pending,
                                            "failed Read Flush never returns its saved bytes");
                                }
                                interrupted = 1;
                                break;
                            }
                            require(lc_spider_fetch_write_complete(f, 1) == 0,
                                    "Read credit Flush actually completes");
                            free(write);
                            write = NULL;
                        }
                        require(credits == credit &&
                                    (teardown >= 3u ? interrupted : lc_spider_fetch_done(f)),
                                "Read resumes once without duplicate credit or additional input");
                    }
                    free(write);
                    lc_spider_fetch_free(f);
                }
}

static void test_data_consumer_driver(void)
{
    for (unsigned busy = 0; busy < 2u; busy++) {
        uint8_t *write = NULL;
        lc_spider_fetch *f = driver_fixture(&write);
        fetch_cc *cc = f->ccs;
        fetch_stream *s = cc->streams;
        if (!busy) {
            require(lc_spider_fetch_write_complete(f, 1) == 0, "consumer DATA request completes");
            free(write);
            write = NULL;
        }
        const uint8_t status = 0x88;
        input_frame(f, LC_H2_HEADERS, LC_H2_END_HEADERS, s->id, &status, 1u);
        cc->in_unsent = s->in_unsent = 4000;
        cc->in_avail = s->in_avail = 500;
        uint8_t padded[102] = {100, 'x'};
        input_frame(f, LC_H2_DATA, LC_H2_PADDED | LC_H2_END_STREAM,
                    s->id, padded, sizeof padded);
        require(lc_spider_fetch_step(f, 0) == 1 && f->state == DO_READ &&
                    f->d->len == 1u &&
                    s->pb_len == 0u && !f->d->rd_done && !s->peer_closed,
                "real Do consumes DATA before writer/refund completion but cannot see early EOF");
        require(lc_spider_fetch_step(f, 0) == 2 && !f->d->rd_done && f->d->len == 1u,
                "a repeated consumer turn cannot invent EOF while the DATA Flush waits");
        require(cc->in_avail == 4499 && cc->in_unsent == 1 &&
                    s->in_avail == 4499 && s->in_unsent == 1,
                "consumer accounts body separately from padding exactly once");
        if (busy) {
            require(lc_spider_fetch_write_complete(f, 1) == 0, "busy DATA writer releases");
            free(write);
            write = NULL;
            require(lc_spider_fetch_step(f, 0) == 1, "saved padding refund resumes");
        }
        require(lc_spider_fetch_take(f, &write) == 26 &&
                    lc_spider_fetch_write_complete(f, 1) == 0,
                "consumer fixture completes only the saved padding Flush");
        free(write);
        write = NULL;
        for (unsigned turn = 0; turn < 12u && !lc_spider_fetch_done(f); turn++)
            require(lc_spider_fetch_step(f, 0) >= 0 && lc_spider_fetch_take(f, &write) == 0,
                    "consumer reaches EOF without duplicate credit or fresh input");
        require(lc_spider_fetch_done(f) && s->done && s->peer_closed,
                "consumer EOF and cleanup follow the completed refund");
        lc_spider_fetch_free(f);
    }
}

static void test_broken_padded_data_driver(void)
{
    for (unsigned outcome = 0; outcome < 5u; outcome++) {
        uint8_t *write = NULL;
        lc_spider_fetch *f = driver_fixture(&write);
        fetch_cc *cc = f->ccs;
        fetch_stream *s = cc->streams;
        const lc_hpack_field fields[] = {
            {":status", "302"}, {"location", "/next"}, {"content-length", "5000"}
        };
        uint8_t headers[128], padded[102] = {100, 'x'};
        long hn = lc_hpack_encode(fields, 3u, headers, sizeof headers);
        require(hn > 0, "broken-pipe response encodes");
        input_frame(f, LC_H2_HEADERS, LC_H2_END_HEADERS, s->id, headers, (size_t)hn);
        require(lc_spider_fetch_step(f, 0) == 1 && lc_spider_fetch_step(f, 0) == 1 &&
                    s->p_break && !s->read_aborted && !s->forgotten,
                "public Close breaks the pipe behind the unfinished request Write");
        cc->in_unsent = s->in_unsent = 4000;
        cc->in_avail = s->in_avail = 500;
        input_frame(f, LC_H2_DATA, LC_H2_PADDED | LC_H2_END_STREAM,
                    s->id, padded, sizeof padded);
        require(cc->data_pending && cc->data_reset && !s->read_aborted &&
                    !s->peer_closed && s->pb_len == 0u && cc->data_conn_credit == 4102u &&
                    cc->data_stream_credit == 0u && cc->in_avail == 4500 &&
                    s->in_avail == 398 && s->in_unsent == 4000 && f->cuts == 0u,
                "broken DATA refunds body plus padding on connection only before writer wait");
        uint64_t generation = 0;
        if (outcome == 1u) {
            lc_spider_fetch_stop(f);
            require(lc_spider_fetch_wait(f, &generation) == 0 &&
                        lc_spider_fetch_step(f, 0) == 0 && !s->read_aborted,
                    "stop before broken DATA writer acquisition preserves terminal actions");
        } else if (outcome == 2u) {
            require(lc_spider_fetch_write_complete(f, 0) == 0 &&
                        lc_spider_fetch_step(f, 0) < 0 && !s->read_aborted,
                    "foreign writer failure cannot publish broken DATA terminal actions");
        } else {
            require(lc_spider_fetch_write_complete(f, 1) == 0,
                    "broken DATA foreign writer completes");
            free(write);
            write = NULL;
            require(lc_spider_fetch_step(f, 0) == 1 &&
                        lc_spider_fetch_take(f, &write) == 13 &&
                        write[3] == LC_H2_WINDOW_UPDATE && write[8] == 0u &&
                        r_u32(write + 9u) == 4102u && !s->read_aborted && !s->peer_closed,
                    "broken DATA terminal error waits for its own connection refund Flush");
            if (outcome == 3u) {
                lc_spider_fetch_stop(f);
                require(lc_spider_fetch_wait(f, &generation) == 0 &&
                            lc_spider_fetch_step(f, 0) == 0 && !s->read_aborted,
                        "stop during broken DATA Flush preserves its terminal continuation");
            } else if (outcome == 4u) {
                require(lc_spider_fetch_write_complete(f, 0) == 0 &&
                            lc_spider_fetch_step(f, 0) < 0 && !s->read_aborted,
                        "failed broken DATA refund cannot publish its saved terminal error");
            } else {
                require(lc_spider_fetch_write_complete(f, 1) == 0 &&
                            lc_spider_fetch_step(f, 0) == 1 && s->read_aborted &&
                            !s->peer_closed && !cc->data_pending && cc->in_avail == 4500,
                        "broken DATA publishes error, not END_STREAM, after successful refund");
                free(write);
                write = NULL;
                require(lc_spider_fetch_take(f, &write) == 13 &&
                            write[3] == LC_H2_RST_STREAM && write[12] == ERR_CANCEL &&
                            lc_spider_fetch_step(f, 0) == 2,
                        "independent cleanup reset follows refund without duplicated credit");
            }
        }
        free(write);
        lc_spider_fetch_free(f);
    }
}

static void test_gzip_source_ownership(void)
{
    uint8_t *write = NULL;
    lc_spider_fetch *f = driver_fixture_mode(&write, 1);
    fetch_stream *s = f->ccs->streams;
    require(lc_spider_fetch_write_complete(f, 1) == 0, "gzip source request completes");
    free(write);
    const lc_hpack_field fields[] = {{":status", "200"}, {"content-length", "20000"}};
    uint8_t headers[128], body[5000];
    long hn = lc_hpack_encode(fields, 2u, headers, sizeof headers);
    require(hn > 0, "gzip source ownership headers encode");
    input_frame(f, LC_H2_HEADERS, LC_H2_END_HEADERS, s->id, headers, (size_t)hn);
    memset(body, 'y', sizeof body);
    memset(body, 'x', 512u);
    input_frame(f, LC_H2_DATA, 0, s->id, body, sizeof body);
    pthread_mutex_lock(&f->do_lock);
    const uint8_t *held = NULL;
    size_t count = 0u;
    int error = LC_GZ_NONE;
    require(gzip_source(s, 512u, &held, &count, &error) == 0 && count == 512u &&
                error == LC_GZ_NONE && f->cuts == 0u,
            "private decoder receives its natural pipe Read without a flow-control Write");
    memset(body, 'z', sizeof body);
    for (unsigned i = 0; i < 3u; i++)
        input_frame(f, LC_H2_DATA, 0, s->id, body, sizeof body);
    require(s->pb_cap >= 20000u && s->pb[0] == 'y',
            "concurrent feed really compacts and grows the mutable pipe");
    int preserved = 1;
    for (size_t i = 0; i < count; i++)
        preserved &= held[i] == 'x';
    require(preserved, "decoder-owned bytes survive pipe compaction and growth");
    pthread_mutex_unlock(&f->do_lock);
    lc_spider_fetch_free(f);
}

/* Hold actual gzip.Read outside its source callback. Input, cleanup and stop
 * must stay independent; Do's decoder/lifetime remains protected by do_lock. */
static void test_private_gzip_driver(void)
{
    for (unsigned outcome = 0; outcome < 5u; outcome++) {
        uint8_t *write = NULL;
        lc_spider_fetch *f = driver_fixture_mode(&write, 1);
        fetch_stream *s = f->ccs->streams;
        require(lc_spider_fetch_write_complete(f, 1) == 0, "private gzip request completes");
        free(write);
        static const uint8_t page[] = "<a href='/x'>x</a>";
        uint8_t body[256], headers[128];
        z_stream z = {0};
        require(deflateInit2(&z, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 31, 8,
                             Z_DEFAULT_STRATEGY) == Z_OK, "private gzip encoder");
        z.next_in = (Bytef *)(void *)page;
        z.avail_in = (uInt)(sizeof page - 1u);
        z.next_out = body;
        z.avail_out = sizeof body;
        require(deflate(&z, Z_FINISH) == Z_STREAM_END, "private gzip page encodes");
        size_t bn = z.total_out;
        require(deflateEnd(&z) == Z_OK, "private gzip encoder ends");
        char length[32];
        (void)snprintf(length, sizeof length, "%zu", bn);
        const lc_hpack_field fields[] = {
            {":status", "200"}, {"content-length", length}, {"content-encoding", "gzip"}
        };
        long hn = lc_hpack_encode(fields, 3u, headers, sizeof headers);
        require(hn > 0, "private gzip response headers encode");
        input_frame(f, LC_H2_HEADERS, LC_H2_END_HEADERS, s->id, headers, (size_t)hn);
        unsigned commits_before = atomic_load(&harvest_commits);
        pthread_mutex_lock(&prep_lock);
        gzip_pause = 1;
        gzip_entered = gzip_release = 0;
        pthread_mutex_unlock(&prep_lock);
        prep_worker worker = { .f = f, .result = -99 };
        pthread_t thread;
        require(pthread_create(&thread, NULL, prepare_on_worker, &worker) == 0,
                "private gzip runs on the real Do task");
        pthread_mutex_lock(&prep_lock);
        struct timespec deadline;
        require(clock_gettime(CLOCK_REALTIME, &deadline) == 0, "gzip checkpoint deadline");
        deadline.tv_sec += 5;
        while (!gzip_entered)
            require(pthread_cond_timedwait(&prep_changed, &prep_lock, &deadline) == 0,
                    "Do reaches the decoder checkpoint before any source Read");
        pthread_mutex_unlock(&prep_lock);
        require(pthread_mutex_trylock(&f->lock) == 0,
                "gzip inflation does not own the HTTP/2 protocol mutex");
        pthread_mutex_unlock(&f->lock);
        require(pthread_mutex_trylock(&f->do_lock) == EBUSY,
                "Do retains exclusive decoder and lifetime ownership");
        input_frame(f, LC_H2_DATA, LC_H2_END_STREAM, s->id, body, bn);
        const uint8_t nonce[8] = {8, 6, 7, 5, 3, 0, 9, 1};
        input_frame(f, LC_H2_PING, 0, 0, nonce, sizeof nonce);
        write = NULL;
        require(lc_spider_fetch_take(f, &write) == 17 && write[3] == LC_H2_PING &&
                    write[4] == LC_H2_ACK && memcmp(write + LC_H2_HEADER, nonce, sizeof nonce) == 0,
                "readLoop publishes complete gzip input and exact PING ACK during inflation");
        require(lc_spider_fetch_request_step(f) == 1 && s->forgotten &&
                    s->cleanup_final_pending && !s->done && !s->cleanup_reset,
                "independent request cleanup advances while gzip stays paused");
        if (outcome == 1u) {
            lc_spider_fetch_stop(f);
        } else if (outcome == 2u) {
            require(lc_spider_fetch_write_complete(f, 0) == 0 && f->closed,
                    "Write failure terminates the connection without waiting for inflation");
        } else if (outcome >= 3u) {
            require(lc_spider_fetch_write_complete(f, 1) == 0 && lc_spider_fetch_read_step(f) == 1,
                    "gzip terminal fixture completes its actual ACK");
            if (outcome == 3u) {
                const uint8_t invalid[] = {0, 2, 0, 0, 0, 2};
                uint8_t frame[LC_H2_HEADER + sizeof invalid];
                (void)lc_h2_put_header(frame, sizeof frame, sizeof invalid, LC_H2_SETTINGS, 0, 0);
                memcpy(frame + LC_H2_HEADER, invalid, sizeof invalid);
                require(lc_spider_fetch_feed(f, frame, sizeof frame) < 0 && f->closed,
                        "invalid peer input terminates independently of the decoder");
            } else {
                require(lc_spider_fetch_request_step(f) == 1 && s->done,
                        "clean EOF fixture finishes separate final writer acquisition");
                lc_spider_fetch_loss_pending(f);
            }
        }
        pthread_mutex_lock(&prep_lock);
        gzip_release = 1;
        pthread_cond_broadcast(&prep_changed);
        pthread_mutex_unlock(&prep_lock);
        require(pthread_join(thread, NULL) == 0 &&
                    worker.result == (outcome == 1u ? 0 : outcome == 2u || outcome == 3u ? -1 : 1),
                "private gzip joins with its actual input, stop or failure result");
        pthread_mutex_lock(&prep_lock);
        gzip_pause = 0;
        pthread_mutex_unlock(&prep_lock);
        if (outcome == 0u || outcome == 4u) {
            for (unsigned turn = 0; turn < 16u && f->state != DO_FINISH; turn++)
                require(lc_spider_fetch_step(f, 0) >= 0, "private gzip finishes accepted body");
            require(f->state == DO_FINISH && atomic_load(&harvest_commits) == commits_before + 1u &&
                        s->pb_len == 0u && !s->p_break && !s->cleanup_reset && f->cuts == 0u,
                    "accepted gzip EOF commits once without spurious reset or flow credit");
            if (outcome == 0u)
                require(lc_spider_fetch_write_complete(f, 1) == 0 &&
                            lc_spider_fetch_read_step(f) == 1 &&
                            lc_spider_fetch_request_step(f) == 1 && s->done,
                        "held ACK releases cleanup only after its real completion");
            for (unsigned turn = 0; turn < 8u && !f->closed && f->state != DO_END; turn++)
                (void)lc_spider_fetch_step(f, 0);
            require(atomic_load(&harvest_commits) == commits_before + 1u && s->p_break,
                    "private gzip closes once after harvest, including transport EOF");
        } else {
            require(!f->d->rd_done && f->d->len == 0u && s->pb_len == bn && f->cuts == 0u &&
                        atomic_load(&harvest_commits) == commits_before,
                    "stop or failure performs no new source Read, credit or harvest");
        }
        free(write);
        lc_spider_fetch_free(f);
    }
}

static void test_private_harvest_driver(void)
{
    for (unsigned outcome = 0; outcome < 4u; outcome++) {
        uint8_t *write = NULL;
        lc_spider_fetch *f = driver_fixture_mode(&write, 1);
        fetch_stream *s = f->ccs->streams;
        require(lc_spider_fetch_write_complete(f, 1) == 0,
                "private harvest request actually completes");
        free(write);
        write = NULL;
        const lc_hpack_field fields[] = {{":status", "200"}, {"content-length", "15"}};
        const uint8_t page[] = "href=\"/harvest\"";
        uint8_t headers[128];
        long hn = lc_hpack_encode(fields, 2u, headers, sizeof headers);
        require(hn > 0 && sizeof page - 1u == 15u, "private harvest response encodes");
        input_frame(f, LC_H2_HEADERS, LC_H2_END_HEADERS, s->id, headers, (size_t)hn);
        input_frame(f, LC_H2_DATA, LC_H2_END_STREAM, s->id, page, sizeof page - 1u);
        require(lc_spider_fetch_step(f, 0) == 1 && f->state == DO_READ &&
                    !f->d->rd_done && s->pb_len == 0u && s->peer_closed && !s->done,
                "private harvest first reads the completed page before committing it");
        unsigned commits_before = atomic_load(&harvest_commits);
        pthread_mutex_lock(&prep_lock);
        harvest_pause = 1;
        harvest_entered = harvest_release = 0;
        pthread_mutex_unlock(&prep_lock);
        prep_worker worker = { .f = f, .result = -99 };
        pthread_t thread;
        require(pthread_create(&thread, NULL, prepare_on_worker, &worker) == 0,
                "private harvest starts on Do's thread");
        pthread_mutex_lock(&prep_lock);
        struct timespec deadline;
        require(clock_gettime(CLOCK_REALTIME, &deadline) == 0, "harvest checkpoint deadline");
        deadline.tv_sec += 5;
        while (!harvest_entered)
            require(pthread_cond_timedwait(&prep_changed, &prep_lock, &deadline) == 0,
                    "Do reaches the private harvest checkpoint after EOF");
        pthread_mutex_unlock(&prep_lock);
        require(pthread_mutex_trylock(&f->lock) == 0,
                "private path-store harvest does not hold the HTTP/2 protocol mutex");
        pthread_mutex_unlock(&f->lock);
        require(pthread_mutex_trylock(&f->do_lock) == EBUSY,
                "Do lifetime remains protected while the path-store harvest runs");
        const uint8_t nonce[8] = {0, 1, 2, 3, 4, 5, 6, 7};
        input_frame(f, LC_H2_PING, 0, 0, nonce, sizeof nonce);
        require(lc_spider_fetch_take(f, &write) == 17 &&
                    write[3] == LC_H2_PING && write[4] == LC_H2_ACK &&
                    memcmp(write + LC_H2_HEADER, nonce, sizeof nonce) == 0,
                "readLoop receives PING and produces its exact ACK during private harvest");
        if (outcome == 0u) {
            require(lc_spider_fetch_request_step(f) == 1 && s->forgotten &&
                        s->cleanup_final_pending && !s->done && !s->cleanup_reset,
                    "independent cleanup forgets the completed stream during private harvest");
            require(lc_spider_fetch_write_complete(f, 1) == 0 &&
                        lc_spider_fetch_read_step(f) == 1 &&
                        lc_spider_fetch_request_step(f) == 1 && s->done,
                    "ACK completion and final cleanup do not wait for path-store harvest");
        } else if (outcome == 1u) {
            lc_spider_fetch_stop(f);
            uint64_t generation = 0;
            require(lc_spider_fetch_wait(f, &generation) == 0,
                    "stop is accepted during private harvest without waiting for the store");
        } else if (outcome == 2u) {
            require(lc_spider_fetch_write_complete(f, 0) == 0 && f->closed,
                    "socket Write failure is accepted during private harvest");
        } else {
            require(lc_spider_fetch_write_complete(f, 1) == 0 &&
                        lc_spider_fetch_read_step(f) == 1,
                    "protocol-failure fixture releases its own ACK first");
            const uint8_t invalid[] = {0, 2, 0, 0, 0, 2}; /* ENABLE_PUSH=2 */
            uint8_t frame[LC_H2_HEADER + sizeof invalid];
            (void)lc_h2_put_header(frame, sizeof frame, sizeof invalid, LC_H2_SETTINGS, 0, 0);
            memcpy(frame + LC_H2_HEADER, invalid, sizeof invalid);
            require(lc_spider_fetch_feed(f, frame, sizeof frame) < 0 && f->closed,
                    "invalid peer settings terminate the readLoop during private harvest");
        }
        pthread_mutex_lock(&prep_lock);
        harvest_release = 1;
        pthread_cond_broadcast(&prep_changed);
        pthread_mutex_unlock(&prep_lock);
        require(pthread_join(thread, NULL) == 0 &&
                    worker.result == (outcome == 0u ? 1 : outcome == 1u ? 0 : -1),
                "private harvest joins with the observed input, stop or failure result");
        pthread_mutex_lock(&prep_lock);
        harvest_pause = 0;
        pthread_mutex_unlock(&prep_lock);
        require(atomic_load(&harvest_commits) == commits_before + 1u && !s->p_break &&
                    f->state == (outcome == 0u ? DO_FINISH : DO_READ),
                "begun EOF harvest commits once without advancing Close after stop or failure");
        if (outcome == 0u) {
            require(lc_spider_fetch_step(f, 0) == 1 && f->state == DO_END && s->p_break &&
                        lc_spider_fetch_step(f, 0) == 0 && f->cuts == 0u &&
                        atomic_load(&harvest_commits) == commits_before + 1u,
                    "private harvest finishes once without duplicate commit or protocol output");
        }
        free(write);
        lc_spider_fetch_free(f);
    }
}

static void test_harvest_commit_driver(void)
{
    for (unsigned gzip = 0; gzip < 2u; gzip++)
        for (unsigned outcome = 0; outcome < 4u; outcome++) {
            uint8_t *write = NULL;
            lc_spider_fetch *f = driver_fixture(&write);
            fetch_stream *s = f->ccs->streams;
            require(lc_spider_fetch_write_complete(f, 1) == 0, "harvest request completes");
            free(write);
            write = NULL;
            const uint8_t page[] = "<a href=\"/h0\">one</a><a href=\"/h1\">two</a>";
            uint8_t body[256];
            size_t bn = sizeof page - 1u;
            memcpy(body, page, bn);
            if (gzip) {
                z_stream z = {0};
                require(deflateInit2(&z, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 31, 8,
                                     Z_DEFAULT_STRATEGY) == Z_OK, "harvest gzip init");
                z.next_in = (Bytef *)(void *)page;
                z.avail_in = (uInt)(sizeof page - 1u);
                z.next_out = body;
                z.avail_out = sizeof body;
                require(deflate(&z, Z_FINISH) == Z_STREAM_END, "harvest gzip completes");
                bn = z.total_out;
                require(deflateEnd(&z) == Z_OK, "harvest gzip ends");
                if (outcome == 2u)
                    body[bn - 8u] ^= 1u; /* CRC failure after the linked page was produced. */
            }
            char length[32];
            (void)snprintf(length, sizeof length, "%zu", bn + (!gzip && outcome == 2u ? 1u : 0u));
            const lc_hpack_field fields[] = {
                {":status", "200"}, {"content-length", length}, {"content-encoding", "gzip"}
            };
            uint8_t headers[128];
            long hn = lc_hpack_encode(fields, gzip ? 3u : 2u, headers, sizeof headers);
            require(hn > 0, "harvest headers encode");
            unsigned before = atomic_load(&harvest_commits);
            input_frame(f, LC_H2_HEADERS, LC_H2_END_HEADERS, s->id, headers, (size_t)hn);
            input_frame(f, LC_H2_DATA, (uint8_t)(outcome == 1u ? 0u : LC_H2_END_STREAM),
                        s->id, body, bn);
            require(atomic_load(&harvest_commits) == before,
                    "feed does not commit harvest on the readLoop stack");
            lc_spider_fetch_loss_pending(f);
            if (outcome == 3u) {
                lc_spider_fetch_stop(f);
                require(lc_spider_fetch_step(f, 0) == 0, "harvest stop precedes consumer");
            } else {
                for (unsigned turn = 0; turn < 24u; turn++) {
                    int rc = lc_spider_fetch_step(f, 0);
                    long n = lc_spider_fetch_take(f, &write);
                    if (n > 0) {
                        require(lc_spider_fetch_write_complete(f, 1) == 0,
                                "harvest fixture output completes");
                        free(write);
                        write = NULL;
                    }
                    if (rc < 0 || lc_spider_fetch_done(f))
                        break;
                }
            }
            require(atomic_load(&harvest_commits) - before == (outcome == 0u ? 1u : 0u),
                    "closeafter counts actual commit once only for a complete valid page");
            unsigned after = atomic_load(&harvest_commits);
            for (unsigned repeat = 0; repeat < 3u; repeat++)
                (void)lc_spider_fetch_step(f, 0);
            require(atomic_load(&harvest_commits) == after,
                    "repeated terminal turns do not commit harvest again");
            free(write);
            lc_spider_fetch_free(f);
        }
}

/* A cross-host redirect really creates a second ClientConn over the reference's shared
 * TLS connection. Use public input/completion to park the older readLoop's PING Write,
 * while the new stream's cleanup acquires only its own cc.wmu. */
static void test_cross_cc_cleanup_driver(void)
{
    for (unsigned writing = 0; writing < 2u; writing++)
        for (unsigned outcome = 0; outcome < 3u; outcome++) {
            uint8_t *write = NULL;
            lc_spider_fetch *f = driver_fixture(&write);
            fetch_cc *old = f->ccs;
            fetch_stream *first = old->streams;
            require(lc_spider_fetch_write_complete(f, 1) == 0,
                    "cross-cc initial request completes");
            free(write);
            write = NULL;
            const lc_hpack_field redirect[] = {
                {":status", "302"}, {"location", "https://other-driver.example/next"}
            };
            uint8_t headers[256];
            long hn = lc_hpack_encode(redirect, 2u, headers, sizeof headers);
            require(hn > 0, "cross-cc redirect encodes");
            input_frame(f, LC_H2_HEADERS, LC_H2_END_HEADERS | LC_H2_END_STREAM,
                        first->id, headers, (size_t)hn);
            unsigned openings = 0, requests = 0;
            for (unsigned turn = 0; turn < 24u && requests == 0u; turn++) {
                require(lc_spider_fetch_step(f, 0) >= 0, "cross-cc redirect turn");
                long n = lc_spider_fetch_take(f, &write);
                if (n > 0) {
                    if (n >= 24 && memcmp(write, "PRI * HTTP/2.0", 13u) == 0)
                        openings++;
                    else {
                        require(n > 9 && write[3] == LC_H2_HEADERS,
                                "cross-cc redirect emits only opening and request");
                        requests++;
                    }
                    require(lc_spider_fetch_write_complete(f, 1) == 0,
                            "cross-cc redirect output completes");
                    free(write);
                    write = NULL;
                }
            }
            fetch_cc *cc = old->next;
            require(openings == 1u && requests == 1u && cc != NULL && cc->next == NULL &&
                        cc->streams != NULL && first->done && first->forgotten,
                    "public redirect establishes two real ClientConns");
            fetch_stream *s = cc->streams;
            const uint8_t nonce[8] = {0};
            input_frame(f, LC_H2_PING, 0, 0, nonce, sizeof nonce);
            require(lc_spider_fetch_take(f, &write) == 17 && f->active_write.writer == old,
                    "older readLoop temporarily holds the shared socket writer");
            input_frame(f, LC_H2_SETTINGS, 0, 0, NULL, 0);
            require(cc->got_settings && lc_spider_fetch_write_complete(f, 1) == 0,
                    "new readLoop receives initial SETTINGS behind the old writer");
            free(write);
            write = NULL;
            require(lc_spider_fetch_take(f, &write) == 9 && f->active_write.writer == cc &&
                        lc_spider_fetch_write_complete(f, 1) == 0 &&
                        lc_spider_fetch_step(f, 0) >= 0,
                    "new SETTINGS ACK completes and both readLoops resume");
            free(write);
            write = NULL;
            input_frame(f, LC_H2_PING, 0, 0, nonce, sizeof nonce);
            require(lc_spider_fetch_take(f, &write) == 17 && f->active_write.writer == old,
                    "foreign ClientConn owns an actual unfinished PING Write");
            uint64_t foreign_id = f->active_write.id;
            const lc_hpack_field response[] = {
                {":status", writing ? "302" : "200"},
                {"location", "/again"}, {"content-length", "5000"}
            };
            hn = lc_hpack_encode(response, writing ? 3u : 1u, headers, sizeof headers);
            require(hn > 0, "cross-cc response encodes");
            input_frame(f, LC_H2_HEADERS,
                        (uint8_t)(LC_H2_END_HEADERS | (writing ? 0u : LC_H2_END_STREAM)),
                        s->id, headers, (size_t)hn);
            if (writing) {
                require(lc_spider_fetch_step(f, 0) == 1 && f->state == DO_CLOSE &&
                            lc_spider_fetch_step(f, 0) == 1 && s->p_break && s->abort,
                        "new response Close signals its cleanup behind the foreign writer");
                require(lc_spider_fetch_step(f, 0) == 1 && s->cleanup_pending &&
                            cc->cleanup_writer == s && f->cuts == 1u && !s->forgotten,
                        "cleanup acquires its own cc.wmu and queues reset behind foreign Write");
            } else {
                require(lc_spider_fetch_step(f, 0) == 1 && s->forgotten &&
                            s->cleanup_final_pending && !s->done &&
                            lc_spider_fetch_step(f, 0) == 1 && s->done && f->cuts == 0u,
                        "non-writing cleanup finalizes on its own cc.wmu despite foreign Write");
            }
            require(f->active_write.id == foreign_id && old->read_write_id == foreign_id,
                    "local cleanup does not acknowledge or replace the foreign Write identity");
            if (outcome == 1u) {
                lc_spider_fetch_stop(f);
                uint64_t generation = 0;
                require(lc_spider_fetch_wait(f, &generation) == 0 &&
                            lc_spider_fetch_step(f, 0) == 0 && s->done == !writing,
                        "cross-cc stop preserves completed versus pending cleanup");
            } else if (outcome == 2u) {
                require(lc_spider_fetch_write_complete(f, 0) == 0 &&
                            lc_spider_fetch_step(f, 0) < 0 && old->werr && !cc->werr &&
                            s->done == !writing,
                        "foreign failure closes shared TLS but is sticky only on its ClientConn");
            } else {
                require(lc_spider_fetch_write_complete(f, 1) == 0 && old->read_write_id == 0u,
                        "foreign completion releases only its matching ClientConn owner");
                free(write);
                write = NULL;
                if (writing) {
                    require(lc_spider_fetch_take(f, &write) == 13 &&
                                f->active_write.writer == cc && write[3] == LC_H2_RST_STREAM &&
                                write[12] == ERR_CANCEL && lc_spider_fetch_write_complete(f, 1) == 0,
                            "own reset reaches the socket only after foreign Write completion");
                    require(!s->done && s->forgotten && lc_spider_fetch_step(f, 0) == 1 && s->done,
                            "own reset and separate final check complete without fresh input");
                } else {
                    require(s->done && !s->cleanup_final_pending && f->cuts == 0u,
                            "foreign completion cannot repeat completed non-writing cleanup");
                }
            }
            free(write);
            lc_spider_fetch_free(f);
        }
}

/* A redirect creates a separate ClientConn. Its request takes its own cc.wmu;
 * another ClientConn's unfinished TLS Write does not own that mutex. */
static lc_spider_fetch *driver_cross_cc_request_fixture(uint8_t **held)
{
    uint8_t *write = NULL;
    lc_spider_fetch *f = driver_fixture_mode(&write, 1);
    fetch_cc *old = f->ccs;
    require(lc_spider_fetch_write_complete(f, 1) == 0,
            "cross-cc request initial Flush completes");
    free(write);
    write = NULL;
    const lc_hpack_field redirect[] = {
        {":status", "302"}, {"location", "https://other-request.example/next"}
    };
    uint8_t headers[256];
    long hn = lc_hpack_encode(redirect, 2u, headers, sizeof headers);
    require(hn > 0, "cross-cc request redirect encodes");
    input_frame(f, LC_H2_HEADERS, LC_H2_END_HEADERS | LC_H2_END_STREAM,
                old->streams->id, headers, (size_t)hn);
    unsigned openings = 0;
    for (unsigned turn = 0; turn < 48u; turn++) {
        require(lc_spider_fetch_step(f, 0) >= 0, "cross-cc request redirect Do turn");
        if (old->next != NULL && old->next->request_pending != NULL &&
            old->next->opening_write_id == 0u)
            break;
        require(lc_spider_fetch_request_step(f) >= 0,
                "cross-cc request completes independent redirect cleanup");
        long n = lc_spider_fetch_take(f, &write);
        if (n > 0) {
            require(n >= 24 && memcmp(write, "PRI * HTTP/2.0", 13u) == 0,
                    "cross-cc request only completes the new opening before admission");
            openings++;
            require(lc_spider_fetch_write_complete(f, 1) == 0,
                    "cross-cc request new opening Flush completes");
            free(write);
            write = NULL;
        }
        require(lc_spider_fetch_read_step(f) >= 0,
                "cross-cc request resumes accepted reader input");
    }
    fetch_cc *cc = old->next;
    if (openings != 1u || cc == NULL || cc->request_pending == NULL)
        fprintf(stderr, "cross-cc request setup: openings=%u state=%d closed=%d "
                        "first_done=%d next=%d pending=%d\n", openings, f->state,
                f->closed, old->streams->done, cc != NULL,
                cc != NULL && cc->request_pending != NULL);
    require(openings == 1u && cc != NULL && cc->next == NULL &&
                cc->request_pending != NULL && cc->opening_write_id == 0u &&
                old->streams->done && old->streams->forgotten,
            "public split redirect queues a request on its second ClientConn");
    const uint8_t nonce[8] = {1, 3, 5, 7, 2, 4, 6, 8};
    input_frame(f, LC_H2_PING, 0, 0, nonce, sizeof nonce);
    require(lc_spider_fetch_take(f, &write) == 17 && f->active_write.writer == old &&
                old->read_write_id == f->active_write.id && !cleanup_writer_busy(cc),
            "old ClientConn holds a real PING Flush while the new writer is free");
    input_frame(f, LC_H2_SETTINGS, 0, 0, NULL, 0);
    require(cc->got_settings && cc->read_write_id != 0u &&
                cc->request_pending->id == 0u && lc_spider_fetch_request_step(f) == 1 &&
                cc->request_pending->id == 1u && !cc->request_pending->sent_headers &&
                lc_spider_fetch_request_step(f) == 0 &&
                lc_spider_fetch_write_complete(f, 1) == 0,
            "new request still waits for its own ClientConn SETTINGS ACK");
    free(write);
    write = NULL;
    require(lc_spider_fetch_take(f, &write) == 9 && f->active_write.writer == cc &&
                lc_spider_fetch_write_complete(f, 1) == 0 &&
                lc_spider_fetch_read_step(f) == 1,
            "new ClientConn completes its SETTINGS ACK and both readers resume");
    free(write);
    write = NULL;
    input_frame(f, LC_H2_PING, 0, 0, nonce, sizeof nonce);
    require(lc_spider_fetch_take(f, &write) == 17 && f->active_write.writer == old &&
                !cleanup_writer_busy(cc),
            "old ClientConn alone owns the unfinished socket Flush");
    *held = write;
    return f;
}

static void test_settings_ack_foreign_writer_driver(void)
{
    uint8_t *write = NULL;
    lc_spider_fetch *f = driver_cross_cc_request_fixture(&write);
    fetch_cc *old = f->ccs, *cc = old->next;
    uint64_t held_id = f->active_write.id;
    require(cc->want_ack && old->want_ack && !cleanup_writer_busy(cc),
            "redirect fixture has a free current writer behind an older socket Flush");
    input_frame(f, LC_H2_SETTINGS, LC_H2_ACK, 0, NULL, 0);
    require(!cc->want_ack && old->want_ack && !cc->writer_wait && f->cuts == 0u &&
                f->active_write.id == held_id && old->read_write_id == held_id,
            "SETTINGS ACK acquires only its own ClientConn writer, without completing foreign output");
    require(lc_spider_fetch_request_step(f) == 1 &&
                cc->request_writer == cc->streams && f->active_write.id == held_id,
            "request still owns its separate writer phase after the local SETTINGS ACK");
    free(write);
    lc_spider_fetch_free(f);
}

/* Client.Do sends the next redirect after Body.Close, independently of a
 * readLoop ACK. Only encodeAndWriteHeaders takes that ClientConn's cc.wmu. */
static void test_redirect_continuation_driver(void)
{
    for (unsigned own_ack = 0; own_ack < 2u; own_ack++)
        for (unsigned outcome = 0; outcome < 4u; outcome++) {
            uint8_t *write = NULL;
            lc_spider_fetch *f = driver_cross_cc_request_fixture(&write);
            fetch_cc *old = f->ccs, *cc = old->next;
            require(lc_spider_fetch_request_step(f) == 1 &&
                        lc_spider_fetch_write_complete(f, 1) == 0,
                    "redirect continuation completes the older fixture PING");
            free(write);
            write = NULL;
            require(lc_spider_fetch_take(f, &write) > 9 &&
                        f->active_write.writer == cc &&
                        lc_spider_fetch_write_complete(f, 1) == 0 &&
                        lc_spider_fetch_read_step(f) >= 0,
                    "redirect continuation completes the second request");
            free(write);
            write = NULL;
            const uint8_t increment[4] = {0, 0, 0, 1}, nonce[8] = {1};
            uint64_t current_turn = cc->seq;
            input_frame(f, LC_H2_WINDOW_UPDATE, 0, 0, increment, sizeof increment);
            require(cc->seq > current_turn, "current reader takes its turn before the older PING");
            input_frame(f, LC_H2_PING, 0, 0, nonce, sizeof nonce);
            require(lc_spider_fetch_take(f, &write) == 17 && f->active_write.writer == old,
                    "older ClientConn holds an actual PING Flush across the redirect");
            uint64_t foreign_id = f->active_write.id;
            fetch_stream *previous = f->d->s;
            const lc_hpack_field redirect[] = {
                {":status", "302"}, {"location", "/continued"}, {"content-length", "0"}
            };
            uint8_t headers[128];
            long hn = lc_hpack_encode(redirect, 3u, headers, sizeof headers);
            require(hn > 0, "continuation redirect encodes");
            input_frame(f, LC_H2_HEADERS, LC_H2_END_HEADERS | LC_H2_END_STREAM,
                        previous->id, headers, (size_t)hn);
            for (unsigned turn = 0; turn < 16u && f->state != DO_NEXT; turn++) {
                require(lc_spider_fetch_request_step(f) >= 0 &&
                            lc_spider_fetch_step(f, 0) >= 0,
                        "public request and Do turns finish the previous response");
            }
            require(f->state == DO_NEXT && previous->done && previous->forgotten &&
                        previous->close_pending == 0 && cc->request_pending == NULL,
                    "Body.Close and cleanup finish before redirect continuation");
            if (own_ack)
                input_frame(f, LC_H2_PING, 0, 0, nonce, sizeof nonce);
            lc_hpack_enc before = cc->enc;
            uint32_t next_id = cc->next_id;
            unsigned requests = f->d->nreqs;
            if (outcome == 1u)
                lc_spider_fetch_stop(f);
            else if (outcome == 2u)
                require(lc_spider_fetch_write_complete(f, 0) == 0 && old->werr && !cc->werr,
                        "foreign failure is sticky only on its own ClientConn");
            int rc = lc_spider_fetch_step(f, 0);
            if (outcome == 1u || outcome == 2u) {
                require(rc == (outcome == 1u ? 0 : -1) &&
                            cc->request_pending == NULL && cc->next_id == next_id &&
                            f->d->nreqs == requests && memcmp(&before, &cc->enc, sizeof before) == 0,
                        "stop or failure cannot admit the next redirect request");
            } else {
                fetch_stream *next = cc->request_pending;
                require(rc == 1 && next != NULL && f->d->s == next &&
                            next != previous && next->request_fields != NULL &&
                            !next->sent_headers && f->d->nreqs == requests + 1u,
                        "redirect admits its next RoundTrip behind an unrelated unfinished Flush");
                require(memcmp(&before, &cc->enc, sizeof before) == 0 &&
                            f->active_write.id == foreign_id && old->read_write_id == foreign_id,
                        "redirect admission neither encodes nor completes another task's Write");
                require(next->id == 0u && lc_spider_fetch_request_step(f) == 1 &&
                            next->id != 0u && !next->sent_headers,
                        "request task assigns the redirected stream before writer acquisition");
                if (outcome == 3u) {
                    lc_spider_fetch_stop(f);
                    require(lc_spider_fetch_request_wait(f) == 0 &&
                                lc_spider_fetch_request_step(f) == 0 && !next->sent_headers,
                            "stop after admission does not encode the queued request");
                } else {
                    if (own_ack) {
                        for (unsigned repeat = 0; repeat < 3u; repeat++)
                            require(lc_spider_fetch_request_step(f) == 0 && !next->sent_headers,
                                    "own ACK still blocks encoding without duplicate progress");
                    } else {
                        require(lc_spider_fetch_request_step(f) == 1 && next->sent_headers,
                                "free ClientConn writer encodes independently of the foreign Flush");
                    }
                    require(lc_spider_fetch_write_complete(f, 1) == 0,
                            "foreign PING reports its real socket completion");
                    free(write);
                    write = NULL;
                    if (own_ack) {
                        require(lc_spider_fetch_take(f, &write) == 17 &&
                                    f->active_write.writer == cc && write[3] == LC_H2_PING &&
                                    lc_spider_fetch_write_complete(f, 1) == 0 &&
                                    lc_spider_fetch_read_step(f) >= 0 &&
                                    lc_spider_fetch_request_step(f) == 1,
                                "own PING Flush completes before the request acquires its writer");
                        free(write);
                        write = NULL;
                    }
                    require(lc_spider_fetch_take(f, &write) > 9 &&
                                write[3] == LC_H2_HEADERS && f->active_write.writer == cc &&
                                f->active_write.id == next->request_write_id &&
                                lc_spider_fetch_write_complete(f, 1) == 0 && next->sent_end_stream,
                            "only its own HEADERS Flush completes the continued request");
                }
            }
            free(write);
            lc_spider_fetch_free(f);
        }
}

static void test_cross_cc_request_driver(void)
{
    for (unsigned cancelled = 0; cancelled < 2u; cancelled++)
        for (unsigned outcome = 0; outcome < 4u; outcome++) {
            uint8_t *write = NULL;
            lc_spider_fetch *f = driver_cross_cc_request_fixture(&write);
            fetch_cc *old = f->ccs, *cc = old->next;
            fetch_stream *s = cc->request_pending;
            lc_hpack_enc before = cc->enc;
            uint64_t foreign_id = f->active_write.id;
            require(s->id != 0u && !s->sent_headers,
                    "request task admitted this ID behind its own SETTINGS ACK");
            if (cancelled) {
                const uint8_t reset[4] = {0, 0, 0, ERR_CANCEL};
                input_frame(f, LC_H2_RST_STREAM, 0, s->id, reset, sizeof reset);
                require(s->abort, "new ClientConn receives its cancellation before encoding");
            }
            require(lc_spider_fetch_request_step(f) == 1 && cc->request_pending == NULL &&
                        s->request_fields == NULL,
                    "independent request acquires its own writer behind a foreign ClientConn Flush");
            require(f->active_write.id == foreign_id && f->write_inflight &&
                        old->read_write_id == foreign_id,
                    "new request never completes or replaces the foreign Write");
            if (cancelled) {
                require(!s->sent_headers && cc->request_writer == NULL && f->cuts == 0u &&
                            memcmp(&before, &cc->enc, sizeof before) == 0 &&
                            lc_spider_fetch_request_step(f) == 1 &&
                            lc_spider_fetch_request_step(f) == 1 && s->done && s->forgotten,
                        "cancelled foreign-cc request keeps HPACK and wire unchanged through cleanup");
            } else {
                require(s->sent_headers && !s->sent_end_stream && cc->request_writer == s &&
                            s->request_write_id != 0u && f->cuts == 1u &&
                            f->cut[0].writer == cc && f->cut[0].stream == s &&
                            lc_spider_fetch_request_step(f) == 0,
                        "new HEADERS retains its own queued Flush and whole-write ownership");
            }
            if (outcome == 1u) {
                lc_spider_fetch_stop(f);
                require(lc_spider_fetch_request_wait(f) == 0 &&
                            lc_spider_fetch_request_step(f) == 0 &&
                            f->active_write.id == foreign_id,
                        "stop wakes the request task without acknowledging either queued Write");
            } else if (outcome == 2u) {
                require(lc_spider_fetch_write_complete(f, 0) == 0 && f->closed &&
                            old->werr && !cc->werr && lc_spider_fetch_request_step(f) == -1,
                        "foreign Flush failure closes shared TLS and stays on its owning ClientConn");
            } else {
                require(lc_spider_fetch_write_complete(f, 1) == 0 && old->read_write_id == 0u,
                        "old Flush completes before the queued request reaches the socket");
                free(write);
                write = NULL;
                if (!cancelled) {
                    require(lc_spider_fetch_take(f, &write) > 9 &&
                                write[3] == LC_H2_HEADERS && f->active_write.writer == cc &&
                                f->active_write.id == s->request_write_id,
                            "queued HEADERS reaches the socket with its original completion identity");
                    require(lc_spider_fetch_write_complete(f, outcome != 3u) == 0,
                            "new request Flush reports its actual socket outcome");
                    if (outcome == 3u)
                        require(f->closed && cc->werr && !old->werr && !s->sent_end_stream,
                                "new request failure cannot mark the older ClientConn failed or sent");
                    else
                        require(!f->closed && s->sent_end_stream && cc->request_writer == NULL,
                                "only the new request's own Flush publishes sent-end and releases its writer");
                }
            }
            free(write);
            lc_spider_fetch_free(f);
        }
}


/* Body Read and Close take only their ClientConn's cc.wmu. A redirected
 * ClientConn's credit can queue behind the old one's unfinished PING Flush. */
static void test_cross_cc_body_credit_driver(void)
{
    for (unsigned closing = 0; closing < 2u; closing++)
        for (unsigned outcome = 0; outcome < 4u; outcome++) {
            uint8_t *write = NULL;
            lc_spider_fetch *f = driver_cross_cc_request_fixture(&write);
            fetch_cc *old = f->ccs, *cc = old->next;
            fetch_stream *s = cc->request_pending;
            require(lc_spider_fetch_request_step(f) == 1 &&
                        lc_spider_fetch_write_complete(f, 1) == 0,
                    "cross-cc body fixture completes the older opening PING Flush");
            free(write);
            write = NULL;
            require(lc_spider_fetch_take(f, &write) > 9 &&
                        f->active_write.writer == cc &&
                        lc_spider_fetch_write_complete(f, 1) == 0 &&
                        lc_spider_fetch_read_step(f) >= 0 && !cleanup_writer_busy(cc),
                    "new request completes and releases its own ClientConn writer");
            free(write);
            write = NULL;
            const uint8_t increment[4] = {0, 0, 0, 1};
            uint64_t new_reader_turn = cc->seq, old_reader_turn = old->seq;
            input_frame(f, LC_H2_WINDOW_UPDATE, 0, 0, increment, sizeof increment);
            require(cc->seq > new_reader_turn && old->seq == old_reader_turn,
                    "new reader consumes its scheduled fill before the older reader's PING");
            const uint8_t nonce[8] = {3, 5, 7, 9, 2, 4, 6, 8};
            input_frame(f, LC_H2_PING, 0, 0, nonce, sizeof nonce);
            require(lc_spider_fetch_take(f, &write) == 17 && f->active_write.writer == old,
                    "old ClientConn alone holds the body fixture's socket Flush");
            uint64_t foreign_id = f->active_write.id;
            const lc_hpack_field response[] = {
                {":status", closing ? "302" : "200"}, {"location", "/next"}
            };
            uint8_t headers[128], body[5000];
            memset(body, 'b', sizeof body);
            long hn = lc_hpack_encode(response, closing ? 2u : 1u, headers, sizeof headers);
            require(hn > 0, "cross-cc body response encodes");
            input_frame(f, LC_H2_HEADERS, LC_H2_END_HEADERS, s->id, headers, (size_t)hn);
            cc->in_unsent = s->in_unsent = closing ? 0u : 4095u;
            input_frame(f, LC_H2_DATA, 0, s->id, body, sizeof body);
            require(s->resp && s->pb_len == sizeof body && old->read_write_id == foreign_id,
                    "new ClientConn accepts its body while the old reader awaits its Flush");
            for (unsigned turn = 0; turn < 16u &&
                    !(closing ? s->close_flushed : s->source_flushed); turn++)
                require(lc_spider_fetch_step(f, 0) >= 0,
                        "public Do reaches its own Read or Close credit phase");
            require((closing ? s->close_flushed && cc->close_writer == s :
                               s->source_flushed && cc->source_writer == s) &&
                        f->cuts == 1u && f->active_write.id == foreign_id &&
                        f->cut[0].writer == cc && f->cut[0].stream == s,
                    "body credit acquires its own cc.wmu behind a foreign ClientConn Flush");
            uint64_t own_id = closing ? s->close_write_id : s->source_write_id;
            uint32_t credit = closing ? s->close_conn_credit : s->source_conn_credit;
            require(own_id != 0u && credit > 0u &&
                        lc_spider_fetch_step(f, 0) == 2 && f->cuts == 1u &&
                        f->active_write.id == foreign_id,
                    "body credit waits for its exact queued Write without duplicate progress");
            if (outcome == 1u) {
                lc_spider_fetch_stop(f);
                require(lc_spider_fetch_step(f, 0) == 0 &&
                            f->active_write.id == foreign_id && f->cuts == 1u,
                        "cross-cc body stop never acknowledges either Write");
            } else if (outcome == 2u) {
                require(lc_spider_fetch_write_complete(f, 0) == 0 &&
                            old->werr && !cc->werr && lc_spider_fetch_step(f, 0) == -1,
                        "foreign failure cannot complete the body or move its sticky error");
            } else {
                require(lc_spider_fetch_write_complete(f, 1) == 0,
                        "body fixture completes only the old ClientConn's PING Flush");
                free(write);
                write = NULL;
                long n = lc_spider_fetch_take(f, &write);
                require(n == (closing ? 13 : 26) && f->active_write.id == own_id &&
                            write[3] == LC_H2_WINDOW_UPDATE && r_u32(write + 9) == credit &&
                            (closing || (write[16] == LC_H2_WINDOW_UPDATE &&
                                         r_u32(write + 22) == s->source_stream_credit)),
                        "peer receives the exact body credit after the older whole Write");
                require(lc_spider_fetch_write_complete(f, outcome != 3u) == 0,
                        "body credit reports its own actual socket outcome");
                if (outcome == 3u)
                    require(cc->werr && !old->werr && lc_spider_fetch_step(f, 0) == -1,
                            "failed body Flush remains on its own ClientConn");
                else
                    require(lc_spider_fetch_step(f, 0) >= 0 &&
                                (closing ? !s->close_pending : !s->source_pending),
                            "matching body Flush alone resumes its saved Read or Close");
            }
            free(write);
            lc_spider_fetch_free(f);
        }
}

typedef struct {
    unsigned cancel, conn_credit, stream_credit, ping;
} close_oracle_result;

/* Compare observable reset/credit outcomes with tools/spiderclose's real pinned
 * Go transport. Production APIs drive every transition; state reads only assert
 * the chosen test interleaving. No scheduler checkpoint is added to the client. */
static void close_oracle_write(const uint8_t *write, size_t n, close_oracle_result *result)
{
    for (size_t off = 0; off < n;) {
        lc_h2_hd hd;
        require(lc_h2_get_header(write + off, n - off, &hd) == 0,
                "close oracle observes whole frames from an actual Write");
        const uint8_t *payload = write + off + LC_H2_HEADER;
        if (hd.type == LC_H2_RST_STREAM) {
            require(hd.len == 4u && hd.stream == 1u && r_u32(payload) == ERR_CANCEL,
                    "close oracle reset is CANCEL on its original stream");
            result->cancel++;
        } else if (hd.type == LC_H2_WINDOW_UPDATE) {
            require(hd.len == 4u && hd.stream == 0u && r_u32(payload) == 5000u,
                    "close oracle emits the exact connection-only unread refund");
            if (hd.stream == 0u)
                result->conn_credit += r_u32(payload);
            else
                result->stream_credit += r_u32(payload);
        } else if (hd.type == LC_H2_PING) {
            result->ping++;
        } else {
            require(0, "close oracle invents no other protocol output");
        }
        off += LC_H2_HEADER + hd.len;
    }
}

static void test_close_reference_driver(void)
{
    const char *names[] = {"end_before_close", "close_before_end", "end_during_reset"};
    for (unsigned scenario = 0; scenario < 3u; scenario++) {
        uint8_t *write = NULL;
        lc_spider_fetch *f = driver_fixture_mode(&write, 1);
        fetch_stream *s = f->ccs->streams;
        close_oracle_result result = {0};
        require(lc_spider_fetch_write_complete(f, 1) == 0,
                "close oracle initial request reaches the peer");
        free(write);
        write = NULL;
        const lc_hpack_field fields[] = {
            {":status", "302"}, {"location", "/next"}, {"content-length", "5000"}
        };
        uint8_t headers[128], body[5000];
        memset(body, 'b', sizeof body);
        long hn = lc_hpack_encode(fields, 3u, headers, sizeof headers);
        require(hn > 0, "close oracle redirect headers encode");
        input_frame(f, LC_H2_HEADERS, LC_H2_END_HEADERS, s->id, headers, (size_t)hn);
        if (scenario != 1u)
            input_frame(f, LC_H2_DATA, scenario == 0u ? LC_H2_END_STREAM : 0u,
                        s->id, body, sizeof body);
        if (scenario == 0u) {
            for (unsigned turn = 0; turn < 8u && !s->done; turn++)
                require(lc_spider_fetch_request_step(f) >= 0,
                        "close oracle peer END finishes independent cleanup");
            require(s->done && s->peer_closed && !s->p_break && f->cuts == 0u,
                    "close oracle accepts END and finishes cleanup before Close");
        }
        for (unsigned turn = 0; turn < 8u && !s->p_break; turn++)
            require(lc_spider_fetch_step(f, 0) >= 0,
                    "close oracle Do reaches unread redirect Body.Close");
        require(s->p_break && s->pb_len == 0u,
                "close oracle Close drops rather than reads the large redirect body");
        /* Finish Close's credit Write, if present, before holding the selected reset. */
        long n = lc_spider_fetch_take(f, &write);
        if (n > 0) {
            close_oracle_write(write, (size_t)n, &result);
            require(lc_spider_fetch_write_complete(f, 1) == 0,
                    "close oracle unread credit reaches the peer");
            free(write);
            write = NULL;
        }
        if (scenario != 0u) {
            for (unsigned turn = 0; turn < 8u && f->cuts == 0u; turn++)
                require(lc_spider_fetch_request_step(f) >= 0,
                        "close oracle independent cleanup selects a reset");
            n = lc_spider_fetch_take(f, &write);
            require(n == 13 && write[3] == LC_H2_RST_STREAM && !s->done,
                    "close oracle Close waits for the selected actual reset Write");
            require(lc_spider_fetch_step(f, 0) >= 0 && f->state == DO_CLOSE && !s->done,
                    "close oracle public Do cannot follow the redirect before reset completion");
            close_oracle_write(write, (size_t)n, &result);
            if (scenario == 2u) {
                input_frame(f, LC_H2_DATA, LC_H2_END_STREAM, s->id, NULL, 0);
                require(s->peer_closed && !s->done &&
                            lc_spider_fetch_request_step(f) == 0,
                        "close oracle END during reset cannot finish its outstanding Write");
            }
            require(lc_spider_fetch_write_complete(f, 1) == 0,
                    "close oracle selected reset actually reaches the peer");
            free(write);
            write = NULL;
            for (unsigned turn = 0; turn < 8u && !s->done; turn++)
                require(lc_spider_fetch_request_step(f) >= 0,
                        "close oracle cleanup resumes after exact reset completion");
        }
        require(s->done && s->forgotten && f->cuts == 0u,
                "close oracle request cleanup finishes once without duplicate reset");
        require(lc_spider_fetch_step(f, 0) == 1 && f->state == DO_NEXT &&
                    !s->close_pending && f->cuts == 0u,
                "close oracle actual Close returns only after credit and cleanup completion");
        if (scenario == 1u) {
            input_frame(f, LC_H2_DATA, LC_H2_END_STREAM, s->id, body, sizeof body);
            n = lc_spider_fetch_take(f, &write);
            require(n == 13, "close oracle late body refunds its connection credit");
            close_oracle_write(write, (size_t)n, &result);
            require(lc_spider_fetch_write_complete(f, 1) == 0,
                    "close oracle late credit actually reaches the peer");
            free(write);
            write = NULL;
            require(lc_spider_fetch_read_step(f) >= 0,
                    "close oracle loop resumes its late DATA continuation");
        }
        require(result.cancel == (scenario != 0u) && result.conn_credit == 5000u &&
                    result.stream_credit == 0u && result.ping == 0u,
                "close oracle exact CANCEL and connection-only credit match the reference");
        printf("CLOSE_ORACLE {\"case\":\"%s\",\"cancel\":%u,\"conn_credit\":%u,"
               "\"stream_credit\":%u,\"ping\":%u}\n", names[scenario], result.cancel,
               result.conn_credit, result.stream_credit, result.ping);
        lc_spider_fetch_free(f);
    }
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--close-oracle") == 0) {
        test_close_reference_driver();
        return 0;
    }
    test_coalesced_frame_consumer();
    test_feed_returns_to_tls_owner();
    test_ready_write_before_new_feed();
    test_task_retirement_driver();
    if (argc == 2 && strcmp(argv[1], "--gzip-private") == 0) {
        test_gzip_source_ownership();
        test_private_gzip_driver();
        return 0;
    }
    require(argc == 1, "expected no arguments, --gzip-private or --close-oracle");
    test_close_reference_driver();
    test_write_buffer_ownership();
    test_request_notification_channels();
    test_settings_ack_writer_driver();
    test_control_parser_before_writer_driver();
    test_settings_ack_foreign_writer_driver();
    test_unassigned_stream_driver();
    test_request_admission_notifications();
    test_cleanup_completion_notifications();
    test_initial_admission_driver();
    test_redirect_continuation_driver();
    test_cross_cc_body_credit_driver();
    test_cross_cc_request_driver();
    test_split_reader_behind_close_driver();
    test_split_request_acquisition_driver();
    test_split_readloop_loss_driver();
    test_split_data_terminal_driver();
    test_split_readloop_driver();
    test_split_private_cleanup_driver();
    test_split_close_decision_driver();
    test_split_idle_driver();
    test_split_invalid_settings_driver();
    test_split_cancel_before_encoding_driver();
    test_cleanup_final_phase_driver();
    test_opening_read_driver();
    test_data_consumer_driver();
    test_broken_padded_data_driver();
    test_harvest_commit_driver();
    test_private_harvest_driver();
    test_gzip_source_ownership();
    test_private_gzip_driver();
    test_cross_cc_cleanup_driver();
    test_cleanup_driver();
    test_data_driver();
    test_forgotten_data_driver();
    test_close_handoff_driver();
    test_cleanup_decision_before_writer_driver();
    test_late_redirect_data_driver();
    test_private_redirect_driver();
    test_close_driver();
    test_read_driver();
    for (unsigned owner = 0; owner < 6u; owner++) {
        lc_spider_fetch f = {0};
        fetch_cc cc = {0};
        fetch_stream s = {0}, writer = {0};
        f.write_barrier = 1;
        f.ccs = &cc;
        cc.f = &f;
        cc.streams = &s;
        s.cc = &cc;
        s.id = 1u;
        s.sent_headers = s.sent_end_stream = s.peer_closed = 1;
        s.p_err = LC_GZ_EOF;
        if (owner == 0u) cc.read_write_id = 7u;
        if (owner == 1u) cc.request_writer = &writer;
        if (owner == 2u) cc.source_writer = &writer;
        if (owner == 3u) cc.cleanup_writer = &writer;
        if (owner == 4u) cc.stuck = 1;
        if (owner == 5u) cc.close_writer = &writer;

        cleanup_stream(&f, &s);
        require(s.forgotten && s.cleanup_final_pending && !s.done,
                "non-writing cleanup forgets the stream but waits for its ClientConn writer");
        require(f.cuts == 0u && f.out_len == 0u,
                "final writer acquisition invents no protocol Write");
        cleanup_stream(&f, &s);
        require(s.cleanup_final_pending && !s.done && f.cuts == 0u,
                "repeated cleanup preserves the wait without duplicate side effects");

        cc.read_write_id = 0u;
        cc.request_writer = cc.source_writer = cc.close_writer = cc.cleanup_writer = NULL;
        cc.stuck = 0;
        cleanup_stream(&f, &s);
        require(s.done && !s.cleanup_final_pending && s.forgotten,
                "writer release completes donec without repeating stream removal");
    }

    {
        lc_spider_fetch f = {0};
        fetch_cc cc = {0};
        fetch_stream s = {0};
        f.write_barrier = 1;
        f.ccs = &cc;
        cc.f = &f;
        cc.streams = &s;
        cc.werr = 1;
        s.cc = &cc;
        s.id = 1u;
        s.forgotten = s.cleanup_final_pending = 1;
        cleanup_stream(&f, &s);
        require(f.closed && cc.closed && s.done && !s.cleanup_final_pending && f.cuts == 0u,
                "local final werr check closes the connection before donec without a Write");
    }
    return 0;
}
