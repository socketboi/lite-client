/* Exercise the actual tunnel's static socket/TLS handoff, with deterministic EAGAIN. */
#include <pthread.h>
#include <unistd.h>
#include "reality/spider.h"
static ssize_t test_task_write(int fd, const void *data, size_t len);
#define write test_task_write
static unsigned read_step_calls;
static void require(int yes, const char *message);
static int test_read_step(lc_spider_fetch *f);
#define lc_spider_fetch_read_step test_read_step
static int test_do_wait(lc_spider_fetch *f, uint64_t *generation);
static int test_do_step(lc_spider_fetch *f, uint64_t now);
static int test_request_wait(lc_spider_fetch *f);
static int test_request_step(lc_spider_fetch *f);
#define lc_spider_fetch_wait test_do_wait
#define lc_spider_fetch_step test_do_step
#define lc_spider_fetch_request_wait test_request_wait
#define lc_spider_fetch_request_step test_request_step
static int fail_thread_start;
static int test_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                               void *(*start)(void *), void *arg);
#define pthread_create test_pthread_create
#define main lc_tunnel_program_main
#include "../../src/cmd/lc-tunnel/main.c"
#undef main
#undef write
#undef pthread_create
#undef lc_spider_fetch_read_step
#undef lc_spider_fetch_wait
#undef lc_spider_fetch_step
#undef lc_spider_fetch_request_wait
#undef lc_spider_fetch_request_step
#include "h2/hpack.h"

#ifndef LC_TEST_RESOURCE_SESSIONS
#define LC_TEST_RESOURCE_SESSIONS 64u
#endif
_Static_assert(LC_TEST_RESOURCE_SESSIONS >= 1u && LC_TEST_RESOURCE_SESSIONS <= 64u,
               "resource fixture must keep 1..64 sessions");

static int startup_peer = -1;
static unsigned startup_creates;
static int opening_visible_before_create;
static int task_fixture_on, task_fixture_waits, task_fixture_steps, task_fixture_end;
static _Atomic int *task_fixture_result;
static session *task_fixture_session;
static pthread_mutex_t startup_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t startup_changed = PTHREAD_COND_INITIALIZER;
static _Atomic int startup_watch;
static lc_spider_fetch *startup_fetch;
static int startup_admitted;
static pthread_mutex_t foreign_do_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t foreign_do_changed = PTHREAD_COND_INITIALIZER;
static lc_spider_fetch *foreign_do_paused;
static unsigned foreign_do_active;
static session *drain_order_session;
static int drain_order_blocked;
static unsigned drain_order_observed;
static int drain_order_inject_loss;

static ssize_t test_task_write(int fd, const void *data, size_t len)
{
    if (task_fixture_on && task_fixture_session != NULL &&
        fd == task_fixture_session->spider_wake_fd) {
        require(atomic_load_explicit(task_fixture_result, memory_order_acquire) == task_fixture_end,
                "final task result is visible before eventfd notification");
        if (task_fixture_end < 0)
            require(atomic_load_explicit(task_fixture_result ==
                            &task_fixture_session->spider_request_result ?
                            &task_fixture_session->spider_request_done :
                            &task_fixture_session->spider_worker_done, memory_order_acquire) != 0,
                    "failed task completion is visible before eventfd notification");
    }
    return write(fd, data, len);
}

static void foreign_task_enter(lc_spider_fetch *f)
{
    pthread_mutex_lock(&foreign_do_lock);
    while (f == foreign_do_paused)
        pthread_cond_wait(&foreign_do_changed, &foreign_do_lock);
    foreign_do_active++;
    pthread_mutex_unlock(&foreign_do_lock);
}

static void foreign_task_leave(void)
{
    pthread_mutex_lock(&foreign_do_lock);
    foreign_do_active--;
    if (foreign_do_paused != NULL)
        pthread_cond_broadcast(&foreign_do_changed);
    pthread_mutex_unlock(&foreign_do_lock);
}

static int test_do_wait(lc_spider_fetch *f, uint64_t *generation)
{
    if (task_fixture_on)
        return task_fixture_waits++ == 0 ? 1 : 0;
    return lc_spider_fetch_wait(f, generation);
}

static int test_do_step(lc_spider_fetch *f, uint64_t now)
{
    if (task_fixture_on) {
        require(atomic_load_explicit(task_fixture_result, memory_order_acquire) == 0,
                "runnable Do phases do not publish intermediate results to the TLS owner");
        return ++task_fixture_steps < 4 ? 1 : task_fixture_end;
    }
    foreign_task_enter(f);
    int rc = lc_spider_fetch_step(f, now);
    foreign_task_leave();
    if (rc == 1 && atomic_load_explicit(&startup_watch, memory_order_acquire)) {
        pthread_mutex_lock(&startup_lock);
        if (f == startup_fetch) {
            startup_admitted = 1;
            pthread_cond_broadcast(&startup_changed);
        }
        pthread_mutex_unlock(&startup_lock);
    }
    return rc;
}

static int test_request_wait(lc_spider_fetch *f)
{
    if (task_fixture_on)
        return task_fixture_waits++ == 0 ? 1 : 0;
    return lc_spider_fetch_request_wait(f);
}

static int test_request_step(lc_spider_fetch *f)
{
    if (task_fixture_on) {
        require(atomic_load_explicit(task_fixture_result, memory_order_acquire) == 0,
                "runnable request phases do not publish intermediate results to the TLS owner");
        return ++task_fixture_steps < 4 ? 1 : task_fixture_end;
    }
    foreign_task_enter(f);
    int rc = lc_spider_fetch_request_step(f);
    foreign_task_leave();
    return rc;
}

static int test_read_step(lc_spider_fetch *f)
{
    read_step_calls++;
    if (drain_order_session != NULL && f == drain_order_session->fetch) {
        drain_order_observed++;
        require(drain_order_blocked ?
                    drain_order_session->spider_write_pending &&
                        q_pending(&drain_order_session->to_up) > 0u :
                    !drain_order_session->spider_write_pending &&
                        drain_order_session->tls_records_sent > 0u,
                "queued TLS Write is serviced before buffered read progress, including EAGAIN");
        if (drain_order_inject_loss) {
            drain_order_inject_loss = 0;
            uint8_t settings[LC_H2_HEADER];
            (void)lc_h2_put_header(settings, sizeof settings, 0, LC_H2_SETTINGS, 0, 0);
            require(lc_spider_fetch_feed(f, settings, sizeof settings) == 0,
                    "terminal read fixture queues a real SETTINGS ACK");
            lc_spider_fetch_lost(f);
        }
    }
    return lc_spider_fetch_read_step(f);
}

static int test_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                               void *(*start)(void *), void *arg)
{
    if (startup_peer >= 0 && startup_creates++ == 0u) {
        uint8_t byte;
        opening_visible_before_create = recv(startup_peer, &byte, 1u,
                                              MSG_PEEK | MSG_DONTWAIT) == 1;
    }
    /* Hold the second creation, not Do. The opening predicate is checked
     * independently: an unsubmitted opening is not permission to admit Do. */
    if (start == spider_request_worker_main && opening_visible_before_create &&
        atomic_load_explicit(&startup_watch, memory_order_acquire)) {
        pthread_mutex_lock(&startup_lock);
        struct timespec deadline;
        require(clock_gettime(CLOCK_REALTIME, &deadline) == 0, "startup admission checkpoint clock");
        deadline.tv_sec += 5;
        while (!startup_admitted) {
            int waited = pthread_cond_timedwait(&startup_changed, &startup_lock, &deadline);
            if (waited == ETIMEDOUT) {
                pthread_mutex_unlock(&startup_lock);
                require(0, "Do admission is independent of request-thread creation");
            }
            require(waited == 0, "startup admission checkpoint wait");
        }
        pthread_mutex_unlock(&startup_lock);
        require(lc_spider_fetch_request_wait(((session *)arg)->fetch) == 1,
                "later request task observes work published before its creation without a new wake");
    }
    if (fail_thread_start > 0 && --fail_thread_start == 0) {
        errno = EBADF; /* pthread_create reports its failure by return value, not errno. */
        return EAGAIN;
    }
    return pthread_create(thread, attr, start, arg);
}

static void require(int yes, const char *message)
{
    if (!yes) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
    printf("  ok    %s\n", message);
}

static FILE *capture_stdout(int *saved)
{
    fflush(stdout);
    FILE *out = tmpfile();
    *saved = dup(STDOUT_FILENO);
    require(out != NULL && *saved >= 0, "startup diagnostic capture");
    require(dup2(fileno(out), STDOUT_FILENO) >= 0, "startup diagnostic redirection");
    return out;
}

static void restore_stdout(FILE *out, int saved, char *text, size_t cap)
{
    fflush(stdout);
    int restored = dup2(saved, STDOUT_FILENO);
    close(saved);
    require(restored >= 0, "startup diagnostic output restored");
    rewind(out);
    size_t len = fread(text, 1u, cap - 1u, out);
    text[len] = 0;
    fclose(out);
}

static void fill_socket(int fd)
{
    uint8_t bytes[4096] = {0};
    while (write(fd, bytes, sizeof bytes) > 0) {
    }
    require(errno == EAGAIN || errno == EWOULDBLOCK, "socket reaches actual EAGAIN");
}

static void empty_socket(int fd)
{
    uint8_t bytes[8192];
    while (read(fd, bytes, sizeof bytes) > 0) {
    }
    require(errno == EAGAIN || errno == EWOULDBLOCK, "peer drains socket without a scheduling delay");
}

static long test_rss_kib(void)
{
    FILE *file = fopen("/proc/self/status", "r");
    if (file == NULL)
        return -1;
    char line[256];
    long rss = -1;
    while (fgets(line, sizeof line, file) != NULL)
        if (sscanf(line, "VmRSS: %ld kB", &rss) == 1)
            break;
    fclose(file);
    return rss;
}

static void collect_socket(int fd, uint8_t *wire, size_t *used, size_t cap)
{
    for (;;) {
        if (*used == cap) {
            fprintf(stderr, "FAIL: ciphertext capture overflow\n");
            exit(1);
        }
        ssize_t n = read(fd, wire + *used, cap - *used);
        if (n > 0) {
            *used += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return;
        fprintf(stderr, "FAIL: ciphertext capture read\n");
        exit(1);
    }
}

static uint8_t large_write_byte(size_t offset)
{
    return (uint8_t)(offset ^ (offset >> 8) ^ (offset >> 16));
}

static uint64_t test_cpu_us(const struct rusage *usage)
{
    return (uint64_t)usage->ru_utime.tv_sec * 1000000u + (uint64_t)usage->ru_utime.tv_usec +
           (uint64_t)usage->ru_stime.tv_sec * 1000000u + (uint64_t)usage->ru_stime.tv_usec;
}

static void server_record(session *s, int peer, lc_record_key *writer,
                          const uint8_t *message, size_t len)
{
    uint8_t record[LC_REC_MAX_WIRE12];
    size_t rn = 0;
    require(lc_record_protect(writer, LC_REC_APPLICATION_DATA, message, len, 0,
                              record, sizeof record, &rn) == 0 &&
                write(peer, record, rn) == (ssize_t)rn && spider_pump(s) == 0,
            "real TLS readLoop receives the peer's whole application record");
}

static void worker_event(lc_loop *loop, session *s, uint64_t deadline)
{
    lc_event event;
    require(lc_now_ms() < deadline && lc_loop_wait(loop, &event, 1u, 1000) == 1 &&
                event.data == &s->spider_tag && (event.events & LC_EV_READ) != 0u &&
                spider_worker_ready(s) == 0,
            "real eventfd resumes the independent consumer without polling");
}

/* SETTINGS ACK takes cc.wmu even though it sends no reply. A real TLS request
 * stalled at EAGAIN must hold the following response behind that acquisition. */
static void test_settings_ack_socket_driver(void)
{
    lc_loop *loop = lc_loop_new(4u);
    require(loop != NULL, "SETTINGS ACK socket lifecycle loop");
    for (unsigned stop = 0; stop < 2u; stop++) {
        int pair[2];
        session *s = session_new();
        require(s != NULL && socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair) == 0,
                "SETTINGS ACK socket fixture");
        s->st = ST_SPIDER;
        s->up_fd = pair[0];
        s->cl.hash = LC_SHA256;
        s->cl.alg = LC_AEAD_AES_128_GCM;
        s->cl.key_len = 16u;
        uint8_t key[16] = {0}, iv[12] = {0};
        lc_record_key peer_writer, peer_reader;
        require(lc_record_key_init(&s->cl.wr, s->cl.alg, key, iv) == 0 &&
                    lc_record_key_init(&s->cl.rd, s->cl.alg, key, iv) == 0 &&
                    lc_record_key_init(&peer_writer, s->cl.alg, key, iv) == 0 &&
                    lc_record_key_init(&peer_reader, s->cl.alg, key, iv) == 0,
                "SETTINGS ACK socket TLS keys");
        lc_browser browser;
        require(lc_browser_chrome_anchored(&browser, LC_BROWSER_NAV) == 0,
                "SETTINGS ACK socket browser");
        s->fetch = lc_spider_fetch_new("settings-ack.example", &browser);
        require(s->fetch != NULL && lc_spider_fetch_write_barrier(s->fetch) == 0 &&
                    lc_spider_fetch_request_tasks(s->fetch) == 0 && spider_drain(s) == 0,
                "SETTINGS ACK socket opening completes");
        empty_socket(pair[1]);
        uint8_t input[2u * LC_H2_HEADER + 1u];
        (void)lc_h2_put_header(input, sizeof input, 0, LC_H2_SETTINGS, 0, 0);
        server_record(s, pair[1], &peer_writer, input, LC_H2_HEADER);
        empty_socket(pair[1]);
        require(lc_spider_fetch_step(s->fetch, 0) == 1 &&
                    lc_spider_fetch_request_step(s->fetch) == 1 &&
                    lc_spider_fetch_request_step(s->fetch) == 1,
                "SETTINGS ACK socket submits its request before backpressure");
        peer_reader.seq = s->cl.wr.seq;
        fill_socket(pair[0]);
        require(spider_drain(s) == 0 && s->spider_write_pending &&
                    s->spider_write[3] == LC_H2_HEADERS && q_pending(&s->to_up) > 0u,
                "SETTINGS ACK socket request reaches actual EAGAIN");
        uint64_t sequence = s->cl.wr.seq;
        (void)lc_h2_put_header(input, sizeof input, 0, LC_H2_SETTINGS, LC_H2_ACK, 0);
        (void)lc_h2_put_header(input + LC_H2_HEADER, sizeof input - LC_H2_HEADER,
                               1, LC_H2_HEADERS, LC_H2_END_HEADERS | LC_H2_END_STREAM, 1u);
        input[2u * LC_H2_HEADER] = 0x88;
        server_record(s, pair[1], &peer_writer, input, sizeof input);
        require(!lc_spider_fetch_read_ready(s->fetch) && s->spider_write_pending &&
                    s->cl.wr.seq == sequence && lc_spider_fetch_read_step(s->fetch) == 0,
                "SETTINGS ACK cannot pass the real socket's unfinished request Write");
        if (stop) {
            lc_spider_fetch_stop(s->fetch);
            require(lc_spider_fetch_read_step(s->fetch) == 0 && s->spider_write_pending,
                    "SETTINGS ACK stop does not complete the blocked socket Write");
        } else {
            empty_socket(pair[1]);
            require(q_flush(&s->to_up, pair[0]) == 0 && spider_write_complete(s) == 0 &&
                        !s->spider_write_pending && !lc_spider_fetch_read_ready(s->fetch),
                    "actual request completion alone does not dispatch SETTINGS ACK");
            require(lc_spider_fetch_read_step(s->fetch) == 1 &&
                        lc_spider_fetch_read_ready(s->fetch) && spider_drain(s) == 0 &&
                        s->cl.wr.seq == sequence,
                    "loop resumes the ACK and response tail without another TLS Write");
            uint8_t wire[8192], plain[LC_REC_MAX_INNER], type = 0;
            size_t used = 0, n = 0;
            collect_socket(pair[1], wire, &used, sizeof wire);
            require(used >= LC_REC_HEADER &&
                        used == LC_REC_HEADER + ((size_t)wire[3] << 8) + wire[4] &&
                        lc_record_unprotect(&peer_reader, wire, used, plain, sizeof plain,
                                            &n, &type) == 0 &&
                        type == LC_REC_APPLICATION_DATA && n > LC_H2_HEADER &&
                        plain[3] == LC_H2_HEADERS && plain[8] == 1u,
                    "peer decrypts exactly the original request and no reply to SETTINGS ACK");
        }
        lc_record_key_free(&peer_reader);
        lc_record_key_free(&peer_writer);
        session_close(loop, s);
        close(pair[1]);
        sessions_reap();
        require(session_count == 0u, "SETTINGS ACK socket session is reaped");
    }
    lc_loop_free(loop);
}

/* Schedule the public task turns explicitly, without mocking their behavior.
 * The real tunnel must deliver the ACK first through TLS/socket backpressure. */
static void test_queued_request_socket_driver(void)
{
    lc_loop *loop = lc_loop_new(4u);
    require(loop != NULL, "queued request lifecycle loop");
    for (unsigned scenario = 0; scenario < 6u; scenario++) {
        unsigned settings = scenario & 1u;
        unsigned late_admission = scenario >= 2u;
        unsigned redirected = scenario >= 4u;
        int pair[2];
        require(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair) == 0,
                "queued request socket pair");
        session *s = session_new();
        require(s != NULL, "queued request socket session");
        s->st = ST_SPIDER;
        s->up_fd = pair[0];
        s->cl.hash = LC_SHA256;
        s->cl.alg = LC_AEAD_AES_128_GCM;
        s->cl.key_len = 16u;
        uint8_t key[16] = {0}, iv[12] = {0};
        require(lc_record_key_init(&s->cl.wr, LC_AEAD_AES_128_GCM, key, iv) == 0,
                "queued request socket TLS key");
        lc_browser browser;
        require(lc_browser_chrome_anchored(&browser, LC_BROWSER_NAV) == 0,
                "queued request socket browser");
        s->fetch = lc_spider_fetch_new("queued-socket.example", &browser);
        require(s->fetch != NULL && lc_spider_fetch_write_barrier(s->fetch) == 0 &&
                    lc_spider_fetch_request_tasks(s->fetch) == 0 && spider_drain(s) == 0 &&
                    !s->spider_write_pending,
                "queued request socket opening completes through actual tunnel");
        empty_socket(pair[1]);
        uint8_t input[512];
        (void)lc_h2_put_header(input, sizeof input, 0, LC_H2_SETTINGS, 0, 0);
        require(lc_spider_fetch_feed(s->fetch, input, LC_H2_HEADER) == 0 &&
                    spider_drain(s) == 0 && !s->spider_write_pending &&
                    lc_spider_fetch_read_ready(s->fetch),
                "socket driver completes the initial SETTINGS exchange");
        if (redirected) {
            require(lc_spider_fetch_step(s->fetch, 0) == 1 &&
                        lc_spider_fetch_request_step(s->fetch) == 1 &&
                        lc_spider_fetch_request_step(s->fetch) == 1 && spider_drain(s) == 0,
                    "redirect socket fixture completes the initial request");
            const lc_hpack_field redirect[] = {
                {":status", "302"}, {"location", "/continued"}, {"content-length", "0"}
            };
            long hn = lc_hpack_encode(redirect, 3u, input + LC_H2_HEADER,
                                      sizeof input - LC_H2_HEADER);
            require(hn > 0, "redirect socket response encodes");
            (void)lc_h2_put_header(input, sizeof input, (uint32_t)hn, LC_H2_HEADERS,
                                   LC_H2_END_HEADERS | LC_H2_END_STREAM, 1u);
            require(lc_spider_fetch_feed(s->fetch, input, LC_H2_HEADER + (size_t)hn) == 0 &&
                        lc_spider_fetch_request_step(s->fetch) == 1 &&
                        lc_spider_fetch_request_step(s->fetch) == 1 &&
                        lc_spider_fetch_request_step(s->fetch) == 0,
                    "redirect socket finishes the previous request's cleanup");
            for (unsigned turn = 0; turn < 3u; turn++)
                require(lc_spider_fetch_step(s->fetch, 0) == 1,
                        "redirect socket drives response, empty body and completed Close");
        } else if (!late_admission)
            require(lc_spider_fetch_step(s->fetch, 0) == 1,
                    "socket driver queues request before its first independent turn");
        empty_socket(pair[1]);
        const uint8_t nonce[8] = {1, 3, 5, 7, 9, 11, 13, 15};
        uint8_t type = settings ? LC_H2_SETTINGS : LC_H2_PING;
        size_t pn = settings ? 0u : sizeof nonce;
        (void)lc_h2_put_header(input, sizeof input, (uint32_t)pn, type, 0, 0);
        if (pn != 0u)
            memcpy(input + LC_H2_HEADER, nonce, pn);
        uint64_t sequence = s->cl.wr.seq;
        fill_socket(pair[0]);
        require(lc_spider_fetch_feed(s->fetch, input, LC_H2_HEADER + pn) == 0 &&
                    spider_drain(s) == 0 && s->spider_write_pending &&
                    q_pending(&s->to_up) > 0u && s->cl.wr.seq == sequence + 1u,
                "queued request permits real ACK ciphertext behind socket EAGAIN");
        if (late_admission)
            require(lc_spider_fetch_step(s->fetch, 0) == 1 &&
                        s->spider_write_pending && s->cl.wr.seq == sequence + 1u,
                    redirected ?
                    "redirect request is admitted while real ACK ciphertext stays backpressured" :
                    "initial request is admitted while real ACK ciphertext stays backpressured");
        require(lc_spider_fetch_request_step(s->fetch) == 1,
                "request task assigns its stream ID while ACK retains the writer");
        require(lc_spider_fetch_request_step(s->fetch) == 0,
                "queued request cannot overtake actual ACK socket completion");
        empty_socket(pair[1]); /* Filler only; ACK ciphertext remains in to_up. */
        require(q_flush(&s->to_up, pair[0]) == 0 && spider_write_complete(s) == 0 &&
                    !s->spider_write_pending && spider_drain(s) == 0 &&
                    lc_spider_fetch_read_ready(s->fetch),
                "socket ACK completion releases reader and wakes queued request");
        require(lc_spider_fetch_request_wait(s->fetch) == 1 &&
                    lc_spider_fetch_request_step(s->fetch) == 1 && spider_drain(s) == 0 &&
                    !s->spider_write_pending,
                "independent task sends HEADERS only after actual ACK completion");
        uint8_t wire[8192], plaintext[LC_REC_MAX_INNER];
        size_t used = 0, at = 0;
        collect_socket(pair[1], wire, &used, sizeof wire);
        lc_record_key reader;
        require(lc_record_key_init(&reader, LC_AEAD_AES_128_GCM, key, iv) == 0,
                "queued request peer decrypt key");
        reader.seq = sequence;
        for (unsigned record = 0; record < 2u; record++) {
            require(used - at >= LC_REC_HEADER, "queued request peer receives whole record header");
            size_t rn = LC_REC_HEADER + ((size_t)wire[at + 3u] << 8) + wire[at + 4u];
            size_t n = 0;
            uint8_t content_type = 0;
            require(rn <= used - at &&
                        lc_record_unprotect(&reader, wire + at, rn, plaintext, sizeof plaintext,
                                            &n, &content_type) == 0 &&
                        content_type == LC_REC_APPLICATION_DATA,
                    "queued request peer decrypts ordered real TLS records");
            if (record == 0u)
                require(n == LC_H2_HEADER + pn && plaintext[3] == type &&
                            plaintext[4] == LC_H2_ACK && plaintext[8] == 0u &&
                            (settings || memcmp(plaintext + LC_H2_HEADER, nonce, sizeof nonce) == 0),
                        "peer sees exact ACK before queued request HEADERS");
            else
                require(n > LC_H2_HEADER && plaintext[3] == LC_H2_HEADERS &&
                            plaintext[8] == (redirected ? 3u : 1u),
                        "peer sees the next stream HEADERS after its ACK predecessor");
            at += rn;
        }
        require(at == used && lc_spider_fetch_request_step(s->fetch) == 0,
                "queued socket request produces no duplicate records or task phase");
        lc_record_key_free(&reader);
        session_close(loop, s);
        close(pair[1]);
        sessions_reap();
        require(session_count == 0u, "queued socket session uses actual close/reap lifecycle");
    }
    lc_loop_free(loop);
}

/* A redirected ClientConn may prepare its own request while the older one is
 * blocked in TLS. Actual socket completion still orders ACK then HEADERS. */
static void test_cross_cc_request_socket_driver(void)
{
    lc_loop *loop = lc_loop_new(4u);
    require(loop != NULL, "cross-cc socket lifecycle loop");
    for (unsigned stop = 0; stop < 2u; stop++) {
        int pair[2];
        require(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair) == 0,
                "cross-cc nonblocking socket pair");
        session *s = session_new();
        require(s != NULL, "cross-cc socket session");
        s->st = ST_SPIDER;
        s->up_fd = pair[0];
        s->cl.hash = LC_SHA256;
        s->cl.alg = LC_AEAD_AES_128_GCM;
        s->cl.key_len = 16u;
        uint8_t key[16] = {0}, iv[12] = {0};
        require(lc_record_key_init(&s->cl.wr, LC_AEAD_AES_128_GCM, key, iv) == 0,
                "cross-cc socket TLS write key");
        lc_browser browser;
        require(lc_browser_chrome_anchored(&browser, LC_BROWSER_NAV) == 0,
                "cross-cc socket browser");
        s->fetch = lc_spider_fetch_new("cross-socket.example", &browser);
        require(s->fetch != NULL && lc_spider_fetch_write_barrier(s->fetch) == 0 &&
                    lc_spider_fetch_request_tasks(s->fetch) == 0 && spider_drain(s) == 0,
                "cross-cc initial opening reaches the socket");
        uint8_t input[512];
        (void)lc_h2_put_header(input, sizeof input, 0, LC_H2_SETTINGS, 0, 0);
        require(lc_spider_fetch_feed(s->fetch, input, LC_H2_HEADER) == 0 &&
                    spider_drain(s) == 0 && lc_spider_fetch_step(s->fetch, 0) == 1 &&
                    lc_spider_fetch_request_step(s->fetch) == 1 &&
                    lc_spider_fetch_request_step(s->fetch) == 1 && spider_drain(s) == 0,
                "cross-cc initial request reaches the socket");
        empty_socket(pair[1]);
        const lc_hpack_field redirect[] = {
            {":status", "302"}, {"location", "https://other-socket.example/next"}
        };
        long hn = lc_hpack_encode(redirect, 2u, input + LC_H2_HEADER,
                                  sizeof input - LC_H2_HEADER);
        require(hn > 0, "cross-cc socket redirect encodes");
        (void)lc_h2_put_header(input, sizeof input, (uint32_t)hn, LC_H2_HEADERS,
                               LC_H2_END_HEADERS | LC_H2_END_STREAM, 1u);
        require(lc_spider_fetch_feed(s->fetch, input, LC_H2_HEADER + (size_t)hn) == 0,
                "cross-cc socket accepts the redirect");
        uint64_t opening_seq = s->cl.wr.seq;
        for (unsigned turn = 0; turn < 48u && s->cl.wr.seq == opening_seq; turn++)
            require(lc_spider_fetch_request_step(s->fetch) >= 0 &&
                        lc_spider_fetch_step(s->fetch, 0) >= 0 && spider_drain(s) == 0,
                    "cross-cc socket drives redirect cleanup and the new opening");
        require(s->cl.wr.seq == opening_seq + 1u && !s->spider_write_pending,
                "cross-cc new opening completes before its request task enters");
        empty_socket(pair[1]);
        const uint8_t nonce[8] = {2, 4, 6, 8, 1, 3, 5, 7};
        (void)lc_h2_put_header(input, sizeof input, sizeof nonce, LC_H2_PING, 0, 0);
        memcpy(input + LC_H2_HEADER, nonce, sizeof nonce);
        uint64_t sequence = s->cl.wr.seq;
        fill_socket(pair[0]);
        require(lc_spider_fetch_feed(s->fetch, input, LC_H2_HEADER + sizeof nonce) == 0 &&
                    spider_drain(s) == 0 && s->spider_write_pending &&
                    q_pending(&s->to_up) > 0u && s->cl.wr.seq == sequence + 1u,
                "cross-cc older PING Flush reaches actual socket EAGAIN");
        require(lc_spider_fetch_request_step(s->fetch) == 1 &&
                    lc_spider_fetch_request_step(s->fetch) == 1 && spider_drain(s) == 0 &&
                    s->cl.wr.seq == sequence + 1u && lc_spider_fetch_request_step(s->fetch) == 0,
                "new ClientConn prepares HEADERS without sealing past the older blocked TLS Write");
        empty_socket(pair[1]);
        if (stop) {
            lc_spider_fetch_stop(s->fetch);
            require(lc_spider_fetch_request_wait(s->fetch) == 0 &&
                        lc_spider_fetch_request_step(s->fetch) == 0,
                    "cross-cc socket stop releases task wait without completing output");
        } else {
            require(q_flush(&s->to_up, pair[0]) == 0 && spider_write_complete(s) == 0 &&
                        spider_drain(s) == 0 && !s->spider_write_pending &&
                        s->cl.wr.seq == sequence + 2u,
                    "actual ACK socket completion permits exactly one HEADERS TLS record");
            uint8_t wire[8192], plain[LC_REC_MAX_INNER];
            size_t used = 0, at = 0;
            collect_socket(pair[1], wire, &used, sizeof wire);
            lc_record_key reader;
            require(lc_record_key_init(&reader, LC_AEAD_AES_128_GCM, key, iv) == 0,
                    "cross-cc socket peer decrypt key");
            reader.seq = sequence;
            for (unsigned record = 0; record < 2u; record++) {
                require(used - at >= LC_REC_HEADER, "cross-cc socket record header fits");
                size_t rn = LC_REC_HEADER + ((size_t)wire[at + 3u] << 8 | wire[at + 4u]);
                size_t n = 0;
                uint8_t type = 0;
                require(rn <= used - at && lc_record_unprotect(&reader, wire + at, rn,
                            plain, sizeof plain, &n, &type) == 0 && type == LC_REC_APPLICATION_DATA,
                        "cross-cc peer decrypts ordered whole TLS records");
                if (record == 0u)
                    require(n == 17u && plain[3] == LC_H2_PING && plain[4] == LC_H2_ACK &&
                                memcmp(plain + LC_H2_HEADER, nonce, sizeof nonce) == 0,
                            "cross-cc peer sees the older exact PING ACK first");
                else
                    require(n > LC_H2_HEADER && plain[3] == LC_H2_HEADERS && plain[8] == 1u,
                            "cross-cc peer sees the new stream HEADERS second");
                at += rn;
            }
            require(at == used && lc_spider_fetch_request_step(s->fetch) == 0,
                    "cross-cc socket produces no duplicate record or request turn");
            lc_record_key_free(&reader);
        }
        session_close(loop, s);
        close(pair[1]);
        sessions_reap();
        require(session_count == 0u, "cross-cc socket uses actual close and reap");
    }
    lc_loop_free(loop);
}

/* Explicit task turns plus actual TLS/socket backpressure. The response's END
 * waits behind the readLoop's ACK, then must advance behind Close's later Write. */
static void test_buffered_end_socket_driver(void)
{
    lc_loop *loop = lc_loop_new(4u);
    int pair[2];
    session *s = session_new();
    require(loop != NULL && s != NULL &&
                socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair) == 0,
            "buffered END socket fixture");
    s->st = ST_SPIDER;
    s->up_fd = pair[0];
    s->cl.hash = LC_SHA256;
    s->cl.alg = LC_AEAD_AES_128_GCM;
    s->cl.key_len = 16u;
    uint8_t key[16] = {0}, iv[12] = {0};
    lc_record_key peer_writer, peer_reader;
    require(lc_record_key_init(&s->cl.wr, s->cl.alg, key, iv) == 0 &&
                lc_record_key_init(&s->cl.rd, s->cl.alg, key, iv) == 0 &&
                lc_record_key_init(&peer_writer, s->cl.alg, key, iv) == 0 &&
                lc_record_key_init(&peer_reader, s->cl.alg, key, iv) == 0,
            "buffered END socket TLS keys");
    lc_browser browser;
    require(lc_browser_chrome_anchored(&browser, LC_BROWSER_NAV) == 0,
            "buffered END socket browser");
    s->fetch = lc_spider_fetch_new("buffered-end.example", &browser);
    require(s->fetch != NULL && lc_spider_fetch_write_barrier(s->fetch) == 0 &&
                lc_spider_fetch_request_tasks(s->fetch) == 0 && spider_drain(s) == 0,
            "buffered END socket opening");
    empty_socket(pair[1]);
    uint8_t message[6000];
    (void)lc_h2_put_header(message, sizeof message, 0, LC_H2_SETTINGS, 0, 0);
    server_record(s, pair[1], &peer_writer, message, LC_H2_HEADER);
    require(lc_spider_fetch_step(s->fetch, 0) == 1 &&
                lc_spider_fetch_request_step(s->fetch) == 1 &&
                lc_spider_fetch_request_step(s->fetch) == 1 && spider_drain(s) == 0,
            "buffered END socket initial request");
    empty_socket(pair[1]);
    const lc_hpack_field fields[] = {
        {":status", "302"}, {"location", "/next"}, {"content-length", "5000"}
    };
    uint8_t headers[128];
    long hn = lc_hpack_encode(fields, 3u, headers, sizeof headers);
    require(hn > 0, "buffered END socket redirect encodes");
    (void)lc_h2_put_header(message, sizeof message, (uint32_t)hn,
                           LC_H2_HEADERS, LC_H2_END_HEADERS, 1u);
    memcpy(message + LC_H2_HEADER, headers, (size_t)hn);
    size_t mn = LC_H2_HEADER + (size_t)hn;
    (void)lc_h2_put_header(message + mn, sizeof message - mn, 5000u, LC_H2_DATA, 0, 1u);
    mn += LC_H2_HEADER;
    memset(message + mn, 'x', 5000u);
    mn += 5000u;
    server_record(s, pair[1], &peer_writer, message, mn);
    peer_reader.seq = s->cl.wr.seq;
    fill_socket(pair[0]);
    (void)lc_h2_put_header(message, sizeof message, 8u, LC_H2_PING, 0, 0);
    memset(message + LC_H2_HEADER, 0x69, 8u);
    (void)lc_h2_put_header(message + 17u, sizeof message - 17u, 0,
                           LC_H2_DATA, LC_H2_END_STREAM, 1u);
    server_record(s, pair[1], &peer_writer, message, 17u + LC_H2_HEADER);
    require(s->spider_write_pending && s->spider_write[3] == LC_H2_PING &&
                !lc_spider_fetch_read_ready(s->fetch),
            "actual ACK EAGAIN retains the already accepted END");
    empty_socket(pair[1]);
    require(q_flush(&s->to_up, pair[0]) == 0 && spider_write_complete(s) == 0,
            "actual socket completion releases ACK without running the reader inline");
    uint8_t wire[4096], plain[4096], type = 0;
    size_t used = 0, pn = 0;
    collect_socket(pair[1], wire, &used, sizeof wire);
    require(lc_record_unprotect(&peer_reader, wire, used, plain, sizeof plain, &pn, &type) == 0 &&
                pn == 17u && plain[3] == LC_H2_PING && plain[4] == LC_H2_ACK,
            "peer decrypts the complete ACK before Close owns the next Write");
    require(lc_spider_fetch_step(s->fetch, 0) == 1 &&
                lc_spider_fetch_step(s->fetch, 0) == 1,
            "real Do queues Close's unread-credit Write before loop resumption");
    fill_socket(pair[0]);
    require(spider_drain(s) == 0 && s->spider_write_pending &&
                s->spider_write[3] == LC_H2_WINDOW_UPDATE &&
                lc_spider_fetch_request_step(s->fetch) == 1,
            "loop processes buffered END while Close ciphertext remains backpressured");
    empty_socket(pair[1]);
    require(q_flush(&s->to_up, pair[0]) == 0 && spider_write_complete(s) == 0,
            "actual Close socket completion releases only the credit Write");
    for (unsigned turn = 0; turn < 4u; turn++)
        require(lc_spider_fetch_request_step(s->fetch) >= 0 && spider_drain(s) == 0,
                "cleanup and reader settle without further peer input");
    used = 0;
    collect_socket(pair[1], wire, &used, sizeof wire);
    require(used >= LC_REC_HEADER &&
                used == LC_REC_HEADER + ((size_t)wire[3] << 8) + wire[4] &&
                lc_record_unprotect(&peer_reader, wire, used, plain, sizeof plain, &pn, &type) == 0 &&
                pn == 13u && plain[3] == LC_H2_WINDOW_UPDATE &&
                plain[9] == 0 && plain[10] == 0 && plain[11] == 0x13 && plain[12] == 0x88,
            "peer receives exactly the 5000-byte refund and no spurious CANCEL after END");
    lc_record_key_free(&peer_reader);
    lc_record_key_free(&peer_writer);
    session_close(loop, s);
    close(pair[1]);
    sessions_reap();
    require(session_count == 0u, "buffered END socket session is reaped");
    lc_loop_free(loop);
}

/* Read readiness can be stale, and signals can interrupt a read. An open peer
 * with no bytes is a wait; EOF remains distinct even after a partial TLS header. */
static void test_spurious_socket_readiness(void)
{
    lc_loop *loop = lc_loop_new(4u);
    int pair[2];
    session *s = session_new();
    require(loop != NULL && s != NULL &&
                socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair) == 0,
            "spurious readiness socket fixture");
    s->st = ST_SPIDER;
    s->up_fd = pair[0];
    s->cl.hash = LC_SHA256;
    s->cl.alg = LC_AEAD_AES_128_GCM;
    s->cl.key_len = 16u;
    uint8_t key[16] = {0}, iv[12] = {0};
    require(lc_record_key_init(&s->cl.wr, s->cl.alg, key, iv) == 0,
            "spurious readiness TLS write key");
    lc_browser browser;
    require(lc_browser_chrome_anchored(&browser, LC_BROWSER_NAV) == 0,
            "spurious readiness browser");
    s->fetch = lc_spider_fetch_new("readiness.example", &browser);
    require(s->fetch != NULL && lc_spider_fetch_write_barrier(s->fetch) == 0 &&
                lc_spider_fetch_request_tasks(s->fetch) == 0 && spider_drain(s) == 0 &&
                lc_spider_fetch_read_ready(s->fetch),
            "spurious readiness opening reaches the real socket");
    empty_socket(pair[1]);
    require(spider_read(s) == 0 && !s->spider_peer_lost && s->rx_len == 0u,
            "read readiness followed by EAGAIN keeps the open peer alive");
    const uint8_t partial[] = {LC_REC_APPLICATION_DATA, 3u, 3u};
    require(write(pair[1], partial, sizeof partial) == (ssize_t)sizeof partial &&
                spider_read(s) == 0 && !s->spider_peer_lost &&
                s->rx_len == sizeof partial && memcmp(s->rx, partial, sizeof partial) == 0,
            "partial TLS header remains buffered across EAGAIN");
    require(spider_read(s) == 0 && !s->spider_peer_lost && s->rx_len == sizeof partial,
            "repeated empty readiness preserves the partial TLS header");
    require(shutdown(pair[1], SHUT_WR) == 0 && spider_read(s) == 0 && s->spider_peer_lost,
            "actual peer EOF after a partial TLS header still publishes loss");
    session_close(loop, s);
    close(pair[1]);
    sessions_reap();
    require(session_count == 0u, "spurious readiness session is reaped");
    lc_loop_free(loop);
}

/* A real TLS PING ACK holds the reader behind its own Flush. After the
 * socket becomes writable, the same event must also consume the queued response. */
static void test_combined_socket_events(void)
{
    lc_loop *loop = lc_loop_new(4u);
    session *s = session_new();
    int pair[2];
    require(loop != NULL && s != NULL &&
                socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair) == 0,
            "combined event socket fixture");
    s->st = ST_SPIDER;
    s->up_fd = pair[0];
    s->cl.hash = LC_SHA256;
    s->cl.alg = LC_AEAD_AES_128_GCM;
    s->cl.key_len = 16u;
    uint8_t key[16] = {0}, iv[12] = {0};
    lc_record_key writer, reader;
    require(lc_record_key_init(&s->cl.wr, s->cl.alg, key, iv) == 0 &&
                lc_record_key_init(&s->cl.rd, s->cl.alg, key, iv) == 0 &&
                lc_record_key_init(&writer, s->cl.alg, key, iv) == 0 &&
                lc_record_key_init(&reader, s->cl.alg, key, iv) == 0,
            "combined event TLS keys");
    lc_browser browser;
    require(lc_browser_chrome_anchored(&browser, LC_BROWSER_NAV) == 0,
            "combined event browser");
    s->fetch = lc_spider_fetch_new("combined.example", &browser);
    require(s->fetch != NULL && lc_spider_fetch_write_barrier(s->fetch) == 0 &&
                lc_spider_fetch_request_tasks(s->fetch) == 0 && spider_drain(s) == 0,
            "combined event opening reaches the socket");
    empty_socket(pair[1]);
    uint8_t input[LC_H2_HEADER + 8u] = {0};
    (void)lc_h2_put_header(input, sizeof input, 0, LC_H2_SETTINGS, 0, 0);
    server_record(s, pair[1], &writer, input, LC_H2_HEADER);
    empty_socket(pair[1]);
    require(lc_spider_fetch_step(s->fetch, 0) == 1 &&
                lc_spider_fetch_request_step(s->fetch) == 1 &&
                lc_spider_fetch_request_step(s->fetch) == 1 && spider_drain(s) == 0,
            "combined event request is sent before peer response");
    empty_socket(pair[1]);
    reader.seq = s->cl.wr.seq;
    fill_socket(pair[0]);
    (void)lc_h2_put_header(input, sizeof input, 8u, LC_H2_PING, 0, 0);
    server_record(s, pair[1], &writer, input, sizeof input);
    require(s->spider_write_pending && q_pending(&s->to_up) > 0u &&
                !lc_spider_fetch_read_ready(s->fetch),
            "combined event PING ACK reaches actual EAGAIN");
    uint64_t sequence = s->cl.rd.seq;
    uint8_t response[LC_H2_HEADER + 1u];
    (void)lc_h2_put_header(response, sizeof response, 1u, LC_H2_HEADERS,
                         LC_H2_END_HEADERS | LC_H2_END_STREAM, 1u);
    response[LC_H2_HEADER] = 0x88;
    uint8_t record[LC_REC_MAX_WIRE12];
    size_t length = 0;
    require(lc_record_protect(&writer, LC_REC_APPLICATION_DATA, response, sizeof response,
                              0, record, sizeof record, &length) == 0 &&
                write(pair[1], record, length) == (ssize_t)length,
            "combined event response waits in the kernel socket");
    require(spider_socket_event(s, LC_EV_READ | LC_EV_WRITE) == 0 &&
                s->cl.rd.seq == sequence && s->spider_write_pending &&
                q_pending(&s->to_up) > 0u,
            "combined event preserves the reader's own unfinished Flush barrier");
    empty_socket(pair[1]);
    require(spider_socket_event(s, LC_EV_READ | LC_EV_WRITE) == 0 &&
                s->cl.rd.seq == sequence + 1u && s->rx_len == 0u &&
                !s->spider_write_pending && q_pending(&s->to_up) == 0u,
            "combined event dispatches queued peer response after completing its own Flush");
    require(spider_socket_event(s, LC_EV_READ | LC_EV_WRITE) == 0 &&
                s->cl.rd.seq == sequence + 1u && !s->spider_peer_lost,
            "repeated combined readiness with EAGAIN neither duplicates nor loses input");
    uint8_t wire[8192], plain[LC_REC_MAX_INNER], type = 0;
    size_t used = 0, plain_len = 0;
    collect_socket(pair[1], wire, &used, sizeof wire);
    require(used >= LC_REC_HEADER &&
                used == LC_REC_HEADER + ((size_t)wire[3] << 8) + wire[4] &&
                lc_record_unprotect(&reader, wire, used, plain, sizeof plain, &plain_len, &type) == 0 &&
                type == LC_REC_APPLICATION_DATA && plain_len == LC_H2_HEADER + 8u &&
                plain[3] == LC_H2_PING && plain[4] == LC_H2_ACK && plain[8] == 0u &&
                memcmp(plain + LC_H2_HEADER, input + LC_H2_HEADER, 8u) == 0,
            "combined event emits exactly the original encrypted PING ACK and no duplicate output");
    require(shutdown(pair[1], SHUT_WR) == 0 &&
                spider_socket_event(s, LC_EV_READ | LC_EV_WRITE) == 0 && s->spider_peer_lost,
            "combined readiness still publishes actual peer EOF");
    lc_record_key_free(&writer);
    lc_record_key_free(&reader);
    session_close(loop, s);
    close(pair[1]);
    sessions_reap();
    require(session_count == 0u, "combined event session is reaped");
    lc_loop_free(loop);
}

/* Exercise the real task loops and eventfd. Internal transitions are runnable
 * without a socket callback; the final quiescent/Write/error result must wake it. */
static void test_task_wake_batch(void)
{
    for (unsigned request = 0; request < 2u; request++) {
        for (int outcome = -1; outcome <= (request ? 0 : 2); outcome++) {
            if (outcome == 1)
                continue;
            session *s = calloc(1u, sizeof *s);
            require(s != NULL, "task wake fixture session");
            s->spider_wake_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
            require(s->spider_wake_fd >= 0, "task wake fixture eventfd");
            atomic_init(&s->spider_worker_result, 0);
            atomic_init(&s->spider_request_result, 0);
            task_fixture_waits = task_fixture_steps = 0;
            task_fixture_end = outcome;
            task_fixture_result = request ? &s->spider_request_result : &s->spider_worker_result;
            task_fixture_session = s;
            task_fixture_on = 1;
            if (request)
                (void)spider_request_worker_main(s);
            else
                (void)spider_worker_main(s);
            task_fixture_on = 0;
            task_fixture_result = NULL;
            task_fixture_session = NULL;
            uint64_t wakes = 0;
            ssize_t wake_read = read(s->spider_wake_fd, &wakes, sizeof wakes);
            printf("  task-wake request=%u outcome=%d phases=%d wakes=%llu\n",
                   request, outcome, task_fixture_steps, (unsigned long long)wakes);
            require(task_fixture_steps == 4 && wake_read == (ssize_t)sizeof wakes &&
                        wakes == (outcome < 0 ? 1u : 2u),
                    "runnable phases coalesce; normal executor completion publishes its own wake");
            require(request ? atomic_load(&s->spider_request_done) :
                              atomic_load(&s->spider_worker_done),
                    "terminal task publishes completion before its final wake");
            require((request ? atomic_load(&s->spider_request_result) :
                               atomic_load(&s->spider_worker_result)) == outcome,
                    "coalesced wake publishes the final task result before the loop consumes it");
            require(read(s->spider_wake_fd, &wakes, sizeof wakes) < 0 && errno == EAGAIN,
                    "terminal publication leaves no further eventfd wake");
            close(s->spider_wake_fd);
            free(s);
        }
    }
}

static void test_drain_write_before_read(void)
{
    lc_loop *loop = lc_loop_new(4u);
    require(loop != NULL, "drain-order lifecycle loop");
    for (int outcome = 0; outcome < 3; outcome++) {
        int pair[2];
        require(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair) == 0,
                "drain-order socket pair");
        session *s = session_new();
        require(s != NULL, "drain-order session");
        s->st = ST_SPIDER;
        s->up_fd = pair[0];
        s->cl.hash = LC_SHA256;
        s->cl.alg = LC_AEAD_AES_128_GCM;
        s->cl.key_len = 16u;
        const uint8_t key[16] = {0}, iv[12] = {0};
        require(lc_record_key_init(&s->cl.wr, LC_AEAD_AES_128_GCM, key, iv) == 0,
                "drain-order TLS key");
        lc_browser browser;
        require(lc_browser_chrome_anchored(&browser, LC_BROWSER_NAV) == 0,
                "drain-order browser");
        s->fetch = lc_spider_fetch_new("drain-order.example", &browser);
        require(s->fetch != NULL && lc_spider_fetch_write_barrier(s->fetch) == 0 &&
                    lc_spider_fetch_request_tasks(s->fetch) == 0,
                "drain-order queues the actual opening Write");
        if (outcome == 1)
            fill_socket(pair[0]);
        drain_order_session = s;
        drain_order_blocked = outcome == 1;
        drain_order_inject_loss = outcome == 2;
        drain_order_observed = 0;
        require(spider_drain(s) == (outcome == 2 ? -1 : 0) && drain_order_observed > 0u &&
                    (outcome != 2 || (s->tls_records_sent == 2u && !s->spider_write_pending)),
                "drain-order reads progress after Write service without a scheduling timer");
        drain_order_session = NULL;
        session_close(loop, s);
        close(pair[1]);
        sessions_reap();
    }
    lc_loop_free(loop);
}

int main(void)
{
    test_drain_write_before_read();
    test_task_wake_batch();
    test_combined_socket_events();
    test_spurious_socket_readiness();
    test_buffered_end_socket_driver();
    test_settings_ack_socket_driver();
    test_queued_request_socket_driver();
    test_cross_cc_request_socket_driver();
    int pair[2];
    require(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair) == 0,
            "nonblocking peer socket pair");
    int snd = 4096;
    require(setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF, &snd, sizeof snd) == 0,
            "small socket send buffer");
    session *s = calloc(1, sizeof *s);
    require(s != NULL, "session allocation");
    s->st = ST_SPIDER;
    s->up_fd = pair[0];
    s->rx = s->rx_small;
    s->rx_cap = sizeof s->rx_small;
    s->to_up.buf = s->to_up_buf;
    s->to_up.cap = sizeof s->to_up_buf;
    s->cl.hash = LC_SHA256;
    s->cl.alg = LC_AEAD_AES_128_GCM;
    s->cl.key_len = 16u;
    uint8_t key[16] = {0}, iv[LC_AEAD_NONCE] = {0};
    require(lc_record_key_init(&s->cl.wr, s->cl.alg, key, iv) == 0,
            "application TLS write key");
    lc_browser browser;
    require(lc_browser_chrome_anchored(&browser, LC_BROWSER_NAV) == 0,
            "browser fixture");
    s->fetch = lc_spider_fetch_new("socket-barrier.example", &browser);
    require(s->fetch != NULL && lc_spider_fetch_write_barrier(s->fetch) == 0,
            "completion-aware fetch");

    fill_socket(pair[0]);
    require(spider_drain(s) == 0 && s->spider_write_pending && q_pending(&s->to_up) > 0u,
            "application Write survives EAGAIN in ciphertext queue");
    require(lc_spider_fetch_step(s->fetch, 0) == 2,
            "taking/sealing Write does not release consumer");
    s->ku_owed = 1u;
    size_t queued = q_pending(&s->to_up);
    uint64_t sequence = s->cl.wr.seq;
    require(ku_settle(s) == 0 && s->ku_owed == 1u && q_pending(&s->to_up) == queued &&
                s->cl.wr.seq == sequence,
            "KeyUpdate waits for the application Write without sealing a reply");
    empty_socket(pair[1]);
    require(q_flush(&s->to_up, pair[0]) == 0 && q_pending(&s->to_up) == 0u &&
                spider_write_complete(s) == 0 && !s->spider_write_pending,
            "socket drain acknowledges precisely the pending application Write");
    lc_spider_fetch_stop(s->fetch);
    lc_spider_fetch_free(s->fetch);
    s->fetch = lc_spider_fetch_new("large-write.example", &browser);
    require(s->fetch != NULL && lc_spider_fetch_write_barrier(s->fetch) == 0,
            "large Write completion fixture");
    uint8_t *opening = NULL;
    require(lc_spider_fetch_take(s->fetch, &opening) > 0,
            "large Write owns one real fetch completion barrier");
    free(opening);
    s->spider_write_len = 1024u * 1024u;
    s->spider_write_off = 0;
    s->spider_write = malloc(s->spider_write_len);
    require(s->spider_write != NULL, "whole large Write allocation");
    for (size_t i = 0; i < s->spider_write_len; i++)
        s->spider_write[i] = large_write_byte(i);
    s->spider_write_pending = 1;
    uint64_t sent_before = stats.bytes_out;
    uint64_t first_sequence = s->cl.wr.seq;
    size_t wire_len = 0, wire_cap = 2u * 1024u * 1024u;
    uint8_t *wire = malloc(wire_cap);
    require(wire != NULL, "large Write ciphertext capture");
    fill_socket(pair[0]);
    require(spider_write_complete(s) == 0 && s->spider_write_pending &&
                s->spider_write_off < s->spider_write_len,
            "large Write suspends before filling bounded ciphertext queue");
    require(lc_spider_fetch_step(s->fetch, 0) == 2,
            "partial large Write cannot release fetch completion barrier");
    empty_socket(pair[1]); /* Discard filler only: the first sealed record is still queued. */
    unsigned drains = 0;
    while (s->spider_write_pending && drains++ < 2048u) {
        sequence = s->cl.wr.seq;
        require(ku_settle(s) == 0 && s->ku_owed == 1u && s->cl.wr.seq == sequence,
                "KeyUpdate cannot interrupt a resumed logical Write");
        collect_socket(pair[1], wire, &wire_len, wire_cap);
        require(q_flush(&s->to_up, pair[0]) == 0 && spider_write_complete(s) == 0,
                "large Write resumes after real socket drain");
    }
    require(!s->spider_write_pending && s->spider_write == NULL && drains > 1u &&
                stats.bytes_out - sent_before == 1024u * 1024u,
            "whole megabyte Write completes once without dropping or resealing payload");
    collect_socket(pair[1], wire, &wire_len, wire_cap);
    lc_record_key reader;
    require(lc_record_key_init(&reader, LC_AEAD_AES_128_GCM, key, iv) == 0,
            "large Write peer TLS key");
    reader.seq = first_sequence;
    size_t at = 0, received = 0;
    uint8_t plaintext[LC_REC_MAX_INNER];
    while (at < wire_len) {
        require(wire_len - at >= LC_REC_HEADER, "captured whole TLS record header");
        size_t record_len = LC_REC_HEADER + ((size_t)wire[at + 3u] << 8) + wire[at + 4u];
        require(record_len <= wire_len - at, "captured whole TLS ciphertext record");
        size_t payload_len = 0;
        uint8_t type = 0;
        require(lc_record_unprotect(&reader, wire + at, record_len, plaintext, sizeof plaintext,
                                    &payload_len, &type) == 0 && type == LC_REC_APPLICATION_DATA,
                "resumed record decrypts in sequence at the peer");
        int preserved = 1;
        for (size_t i = 0; i < payload_len; i++)
            if (plaintext[i] != large_write_byte(received + i))
                preserved = 0;
        require(preserved, "resumed plaintext preserved at the peer");
        received += payload_len;
        at += record_len;
    }
    require(received == 1024u * 1024u, "peer receives exactly the whole megabyte Write");
    lc_record_key_free(&reader);
    free(wire);
    fill_socket(pair[0]);
    require(ku_settle(s) == 0 && s->ku_owed == 0u && s->spider_ku_pending &&
                q_pending(&s->to_up) > 0u,
            "KeyUpdate reply tracks its own incomplete socket Write");
    /* Deliberately invalid next record: opening it would trigger loss. It must stay untouched. */
    s->rx_len = LC_REC_HEADER;
    memset(s->rx, 0xff, s->rx_len);
    require(spider_pump(s) == 0 && s->rx_len == LC_REC_HEADER && !s->spider_peer_lost,
            "readLoop leaves even buffered records beyond the KeyUpdate boundary unopened");
    require(spider_drain(s) == 0 && q_pending(&s->to_up) == LC_CLIENT_KEY_UPDATE_MAX,
            "application writes cannot overtake the outstanding KeyUpdate reply");
    require(ku_settle(s) == 0 && s->spider_ku_pending,
            "no duplicate KeyUpdate reply while its Write is pending");
    empty_socket(pair[1]);
    require(q_flush(&s->to_up, pair[0]) == 0 && ku_settle(s) == 0 && !s->spider_ku_pending,
            "complete reply Write releases the TLS read boundary");
    require(spider_pump(s) == 0 && s->spider_peer_lost,
            "next buffered record is processed only after reply completion");
    lc_spider_fetch_stop(s->fetch);
    lc_spider_fetch_free(s->fetch);
    lc_client_free(&s->cl);
    lc_post_free(&s->post);
    close(pair[0]);
    close(pair[1]);
    free(s);

    /* A real worker blocked behind its opening Write must be stopped and joined by session_close,
     * without anyone acknowledging that abandoned Write or retaining the session afterward. */
    lc_loop *loop = lc_loop_new(8u);
    require(loop != NULL, "lifecycle event loop");
    s = session_new();
    require(s != NULL && socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair) == 0,
            "startup without peer DATA fixture");
    s->st = ST_SPIDER;
    s->up_fd = pair[0];
    require(lc_record_key_init(&s->cl.wr, LC_AEAD_AES_128_GCM, key, iv) == 0,
            "startup socket key");
#if LC_SPIDER_PROFILE
    s->spider_profile_base = spider_profile_now();
#endif
    s->fetch = lc_spider_fetch_new("profile.example", &browser);
#if LC_SPIDER_PROFILE
    s->spider_profile_fetch = spider_profile_now();
#endif
    startup_peer = pair[1];
    startup_creates = 0u;
    opening_visible_before_create = 0;
    pthread_mutex_lock(&startup_lock);
    startup_fetch = s->fetch;
    startup_admitted = 0;
    atomic_store_explicit(&startup_watch, 1, memory_order_release);
    pthread_mutex_unlock(&startup_lock);
    int initial_startup_rc = s->fetch == NULL ? -1 : spider_start(loop, s);
    atomic_store_explicit(&startup_watch, 0, memory_order_release);
    require(s->fetch != NULL && initial_startup_rc == 0 && s->tls_records_sent >= 1u &&
                q_pending(&s->to_up) == 0u,
            "startup submits preface immediately without peer input or worker wake");
    startup_peer = -1;
    require(startup_creates == 2u && opening_visible_before_create,
            "encrypted opening reaches the peer before either worker is created");
    uint64_t profile_deadline = lc_now_ms() + 10000u;
    while (s->tls_records_sent < 2u) {
        lc_event event;
        require(lc_now_ms() < profile_deadline && lc_loop_wait(loop, &event, 1u, 1000) == 1,
                "startup worker wakes the real event loop without polling");
        require(event.data == &s->spider_tag && (event.events & LC_EV_READ) != 0u,
                "startup receives its worker's wake endpoint");
        int startup_rc = spider_worker_ready(s);
        if (startup_rc != 0)
            fprintf(stderr, "startup diagnostic: rc=%d worker=%d errno=%d writes=%llu\n",
                    startup_rc, atomic_load_explicit(&s->spider_worker_result, memory_order_acquire),
                    errno, (unsigned long long)s->tls_records_sent);
        require(startup_rc == 0,
                "startup event drains worker output without any peer DATA");
    }
#if LC_SPIDER_PROFILE
    unsigned published = atomic_load_explicit(&s->spider_profile_count, memory_order_acquire);
    require(published > 0u && published <= 16u &&
                atomic_load_explicit(&s->spider_profile_entry, memory_order_acquire) >=
                    s->spider_profile_create &&
                s->spider_profile_opening >= s->spider_profile_fetch,
            "profile samples publish before logging with monotonic phase boundaries");
#endif
    uint8_t startup_wire[8192], startup_plain[LC_REC_MAX_INNER];
    size_t startup_len = 0, startup_at = 0;
    collect_socket(pair[1], startup_wire, &startup_len, sizeof startup_wire);
    lc_record_key startup_reader;
    require(lc_record_key_init(&startup_reader, LC_AEAD_AES_128_GCM, key, iv) == 0,
            "startup peer decryption key");
    unsigned startup_records = 0;
    while (startup_at < startup_len) {
        require(startup_len - startup_at >= LC_REC_HEADER, "startup peer has whole record header");
        size_t rn = LC_REC_HEADER + ((size_t)startup_wire[startup_at + 3u] << 8) +
                    startup_wire[startup_at + 4u];
        size_t pn = 0;
        uint8_t type = 0;
        require(rn <= startup_len - startup_at &&
                    lc_record_unprotect(&startup_reader, startup_wire + startup_at, rn,
                                        startup_plain, sizeof startup_plain, &pn, &type) == 0 &&
                    type == LC_REC_APPLICATION_DATA,
                "startup peer decrypts ordered whole Writes");
        require(startup_records == 0u ? pn >= 24u && memcmp(startup_plain, "PRI * HTTP/2.0", 14u) == 0
                                     : pn >= 9u && startup_plain[3] == LC_H2_HEADERS &&
                                       startup_plain[8] == 1u,
                "startup sends preface followed by stream-one HEADERS without server bytes");
        startup_records++;
        startup_at += rn;
    }
    require(startup_records == 2u, "startup peer receives exactly opening and request Writes");
    lc_record_key_free(&startup_reader);
    session_close(loop, s);
    close(pair[1]);
    sessions_reap();
    s = session_new();
    require(s != NULL && socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair) == 0,
            "foreign readLoop Write tunnel fixture");
    s->st = ST_SPIDER;
    s->up_fd = pair[0];
    s->cl.hash = LC_SHA256;
    s->cl.alg = LC_AEAD_AES_128_GCM;
    s->cl.key_len = 16u;
    require(lc_record_key_init(&s->cl.wr, s->cl.alg, key, iv) == 0 &&
                lc_record_key_init(&s->cl.rd, s->cl.alg, key, iv) == 0,
            "foreign Write tunnel TLS keys");
    s->fetch = lc_spider_fetch_new("foreign-tunnel.example", &browser);
    require(s->fetch != NULL && spider_start(loop, s) == 0, "foreign Write tunnel worker");
    uint64_t foreign_deadline = lc_now_ms() + 10000u;
    while (s->tls_records_sent < 2u)
        worker_event(loop, s, foreign_deadline);
    empty_socket(pair[1]);
    lc_record_key site_writer;
    require(lc_record_key_init(&site_writer, s->cl.alg, key, iv) == 0,
            "foreign Write peer TLS key");
    uint8_t message[1024];
    (void)lc_h2_put_header(message, sizeof message, 0, LC_H2_SETTINGS, 0, 0);
    server_record(s, pair[1], &site_writer, message, LC_H2_HEADER);
    while (!lc_spider_fetch_read_ready(s->fetch))
        worker_event(loop, s, foreign_deadline);
    empty_socket(pair[1]);
    fill_socket(pair[0]);
    uint64_t ack_sequence = s->cl.wr.seq;
    lc_hpack_enc site_headers;
    lc_hpack_enc_init(&site_headers);
    lc_hpack_field status = {":status", "200"};
    uint8_t block[32];
    long bn = lc_hpack_enc_block(&site_headers, &status, 1u, block, sizeof block);
    require(bn > 0, "foreign Write response header block");
    size_t mn = LC_H2_HEADER;
    (void)lc_h2_put_header(message, sizeof message, (uint32_t)bn, LC_H2_HEADERS,
                           LC_H2_END_HEADERS, 1u);
    memcpy(message + mn, block, (size_t)bn);
    mn += (size_t)bn;
    const char foreign_page[] = "<a href=\"/foreign-tunnel\">link</a>";
    (void)lc_h2_put_header(message + mn, sizeof message - mn, sizeof foreign_page - 1u,
                           LC_H2_DATA, LC_H2_END_STREAM, 1u);
    mn += LC_H2_HEADER;
    memcpy(message + mn, foreign_page, sizeof foreign_page - 1u);
    mn += sizeof foreign_page - 1u;
    (void)lc_h2_put_header(message + mn, sizeof message - mn, 8u, LC_H2_PING, 0, 0);
    mn += LC_H2_HEADER;
    memset(message + mn, 0x73, 8u);
    mn += 8u;
    /* This case specifically tests Body.Close behind a foreign Flush. The
     * readLoop may now release its state mutex between these coalesced frames,
     * so park both HTTP tasks until that Flush actually exists. Otherwise
     * cleanup may publish donec before the readLoop even processes PING. */
    pthread_mutex_lock(&foreign_do_lock);
    foreign_do_paused = s->fetch;
    struct timespec foreign_pause_deadline;
    require(clock_gettime(CLOCK_REALTIME, &foreign_pause_deadline) == 0,
            "foreign Write consumer checkpoint clock");
    foreign_pause_deadline.tv_sec += 5;
    while (foreign_do_active > 0u)
        require(pthread_cond_timedwait(&foreign_do_changed, &foreign_do_lock,
                                      &foreign_pause_deadline) == 0,
                "foreign Write fixture parks in-flight HTTP tasks before publishing input");
    pthread_mutex_unlock(&foreign_do_lock);
    server_record(s, pair[1], &site_writer, message, mn);
    require(s->spider_write_pending && q_pending(&s->to_up) > 0u,
            "real PING ACK encounters socket EAGAIN and stays uncompleted");
    pthread_mutex_lock(&foreign_do_lock);
    foreign_do_paused = NULL;
    pthread_cond_broadcast(&foreign_do_changed);
    pthread_mutex_unlock(&foreign_do_lock);
    size_t foreign_queued = q_pending(&s->to_up);
    int harvested = 0;
    while (!harvested) {
        worker_event(loop, s, foreign_deadline);
        for (unsigned i = 0; i < 200u && !harvested; i++) {
        char *path = NULL;
        size_t path_len = 0;
        harvested = lc_spider_path("foreign-tunnel.example", &path, &path_len) == 0 &&
                    path_len == strlen("/foreign-tunnel") &&
                    memcmp(path, "/foreign-tunnel", path_len) == 0;
        free(path);
        }
    }
    int foreign_done = lc_spider_fetch_done(s->fetch);
    int foreign_read_ready = lc_spider_fetch_read_ready(s->fetch);
    if (!harvested || !s->spider_write_pending || q_pending(&s->to_up) != foreign_queued ||
        s->closing || foreign_done || foreign_read_ready)
        fprintf(stderr, "foreign Write state: harvested=%d pending=%d queued=%zu/%zu closing=%d done=%d read_ready=%d\n",
                harvested, s->spider_write_pending, q_pending(&s->to_up), foreign_queued,
                s->closing, foreign_done, foreign_read_ready);
    require(harvested && s->spider_write_pending && q_pending(&s->to_up) == foreign_queued &&
                !s->closing && !foreign_done && !foreign_read_ready,
            "real Do harvests while foreign TLS Write blocks final Close completion");
    empty_socket(pair[1]);
    require(q_flush(&s->to_up, pair[0]) == 0 && spider_write_complete(s) == 0,
            "only the socket drain completes the retained ACK Write");
    uint8_t ack_wire[2048], ack_plain[2048];
    size_t ack_wire_len = 0, ack_plain_len = 0;
    uint8_t ack_type = 0;
    collect_socket(pair[1], ack_wire, &ack_wire_len, sizeof ack_wire);
    lc_record_key ack_reader;
    require(lc_record_key_init(&ack_reader, s->cl.alg, key, iv) == 0,
            "retained ACK peer decryption key");
    ack_reader.seq = ack_sequence;
    require(lc_record_unprotect(&ack_reader, ack_wire, ack_wire_len, ack_plain, sizeof ack_plain,
                                &ack_plain_len, &ack_type) == 0 &&
                ack_type == LC_REC_APPLICATION_DATA && ack_plain_len == 17u &&
                ack_plain[3] == LC_H2_PING && ack_plain[4] == LC_H2_ACK &&
                memcmp(ack_plain + LC_H2_HEADER, message + mn - 8u, 8u) == 0,
            "peer decrypts exactly the original whole ACK after independent harvest");
    lc_record_key_free(&ack_reader);
    /* readLoop readiness is not Do completion: the split request task may
     * release cc.wmu before Do consumes donec. This fixture promises a PING
     * AFTER Do, so wait on both independent predicates, not their old ordering. */
    while (!lc_spider_fetch_read_ready(s->fetch) || !lc_spider_fetch_done(s->fetch))
        worker_event(loop, s, foreign_deadline);
    while (s->spider_worker_on || s->spider_request_worker_on)
        worker_event(loop, s, foreign_deadline);
    require(!s->closing && s->fetch != NULL && !s->spider_end,
            "completed HTTP executors are joined while their fetch and TLS connection stay alive");
    (void)lc_h2_put_header(message, sizeof message, 8u, LC_H2_PING, 0, 0);
    memset(message + LC_H2_HEADER, 0x74, 8u);
    uint64_t after_do_sequence = s->cl.wr.seq;
    server_record(s, pair[1], &site_writer, message, LC_H2_HEADER + 8u);
    ack_wire_len = 0;
    collect_socket(pair[1], ack_wire, &ack_wire_len, sizeof ack_wire);
    require(lc_record_key_init(&ack_reader, s->cl.alg, key, iv) == 0,
            "post-Do PING peer decryption key");
    ack_reader.seq = after_do_sequence;
    require(lc_record_unprotect(&ack_reader, ack_wire, ack_wire_len, ack_plain, sizeof ack_plain,
                                &ack_plain_len, &ack_type) == 0 &&
                ack_plain_len == 17u && ack_plain[3] == LC_H2_PING && ack_plain[4] == LC_H2_ACK &&
                memcmp(ack_plain + LC_H2_HEADER, message + LC_H2_HEADER, 8u) == 0 &&
                lc_spider_fetch_done(s->fetch) && !s->closing,
            "after Do ends the peer decrypts its next PING ACK on the same live TLS connection");
    lc_record_key_free(&ack_reader);
    uint64_t late_data_sequence = s->cl.wr.seq;
    /* inflowMinRefresh (vendor/x-net/http2/flow.go) accumulates small refunds.
     * Cross its 4 KiB threshold, including the already consumed page credit. */
    uint8_t late_data[LC_H2_HEADER + 4096u];
    (void)lc_h2_put_header(late_data, sizeof late_data, 4096u, LC_H2_DATA, 0, 1u);
    memset(late_data + LC_H2_HEADER, 0x6a, 4096u);
    server_record(s, pair[1], &site_writer, late_data, sizeof late_data);
    ack_wire_len = 0;
    collect_socket(pair[1], ack_wire, &ack_wire_len, sizeof ack_wire);
    require(lc_record_key_init(&ack_reader, s->cl.alg, key, iv) == 0,
            "retired-executor DATA peer decryption key");
    ack_reader.seq = late_data_sequence;
    require(lc_record_unprotect(&ack_reader, ack_wire, ack_wire_len, ack_plain, sizeof ack_plain,
                                &ack_plain_len, &ack_type) == 0 &&
                ack_plain_len == 13u && ack_plain[3] == LC_H2_WINDOW_UPDATE &&
                ack_plain[5] == 0u && ack_plain[6] == 0u && ack_plain[7] == 0u &&
                ack_plain[8] == 0u &&
                (((uint32_t)ack_plain[9] << 24) | ((uint32_t)ack_plain[10] << 16) |
                 ((uint32_t)ack_plain[11] << 8) | (uint32_t)ack_plain[12]) ==
                    4096u + sizeof foreign_page - 1u &&
                !s->spider_worker_on && !s->spider_request_worker_on && !s->closing,
            "late DATA refunds only connection credit after both HTTP executors retire");
    lc_record_key_free(&ack_reader);
    fill_socket(pair[0]);
    uint64_t final_ping_sequence = s->cl.wr.seq;
    (void)lc_h2_put_header(message, sizeof message, 8u, LC_H2_PING, 0, 0);
    memset(message + LC_H2_HEADER, 0x75, 8u);
    server_record(s, pair[1], &site_writer, message, LC_H2_HEADER + 8u);
    require(s->spider_write_pending && q_pending(&s->to_up) > 0u &&
                shutdown(pair[1], SHUT_WR) == 0 &&
                spider_socket_event(s, LC_EV_READ) == 0 && !s->spider_peer_lost,
            "retired-executor EOF cannot overtake an actual backpressured PING ACK");
    empty_socket(pair[1]);
    require(spider_socket_event(s, LC_EV_READ | LC_EV_WRITE) < 0 && s->spider_peer_lost &&
                !s->spider_write_pending && q_pending(&s->to_up) == 0u &&
                !s->spider_worker_on && !s->spider_request_worker_on,
            "one combined socket event completes the ACK then consumes EOF without HTTP executors");
    ack_wire_len = 0;
    collect_socket(pair[1], ack_wire, &ack_wire_len, sizeof ack_wire);
    require(lc_record_key_init(&ack_reader, s->cl.alg, key, iv) == 0,
            "retired-executor final ACK peer key");
    ack_reader.seq = final_ping_sequence;
    require(lc_record_unprotect(&ack_reader, ack_wire, ack_wire_len, ack_plain, sizeof ack_plain,
                                &ack_plain_len, &ack_type) == 0 &&
                ack_plain_len == 17u && ack_plain[3] == LC_H2_PING &&
                ack_plain[4] == LC_H2_ACK &&
                memcmp(ack_plain + LC_H2_HEADER, message + LC_H2_HEADER, 8u) == 0,
            "the peer receives exactly its original ACK before EOF closes the retained connection");
    lc_record_key_free(&ack_reader);
    lc_record_key_free(&site_writer);
    session_close(loop, s);
    close(pair[1]);
    sessions_reap();
    s = session_new();
    require(s != NULL && socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair) == 0,
            "body cc.wmu tunnel fixture");
    s->st = ST_SPIDER;
    s->up_fd = pair[0];
    s->cl.hash = LC_SHA256;
    s->cl.alg = LC_AEAD_AES_128_GCM;
    s->cl.key_len = 16u;
    require(lc_record_key_init(&s->cl.wr, s->cl.alg, key, iv) == 0 &&
                lc_record_key_init(&s->cl.rd, s->cl.alg, key, iv) == 0 &&
                lc_record_key_init(&site_writer, s->cl.alg, key, iv) == 0,
            "body cc.wmu TLS keys");
    s->fetch = lc_spider_fetch_new("body-writer-tunnel.example", &browser);
    require(s->fetch != NULL && spider_start(loop, s) == 0, "body cc.wmu real worker");
    foreign_deadline = lc_now_ms() + 10000u;
    while (s->tls_records_sent < 2u)
        worker_event(loop, s, foreign_deadline);
    empty_socket(pair[1]);
    (void)lc_h2_put_header(message, sizeof message, 0, LC_H2_SETTINGS, 0, 0);
    server_record(s, pair[1], &site_writer, message, LC_H2_HEADER);
    while (!lc_spider_fetch_read_ready(s->fetch))
        worker_event(loop, s, foreign_deadline);
    empty_socket(pair[1]);
    fill_socket(pair[0]);
    ack_sequence = s->cl.wr.seq;
    lc_hpack_enc_init(&site_headers);
    bn = lc_hpack_enc_block(&site_headers, &status, 1u, block, sizeof block);
    require(bn > 0, "body cc.wmu response headers");
    uint8_t credit_message[9000];
    (void)lc_h2_put_header(credit_message, sizeof credit_message, (uint32_t)bn,
                           LC_H2_HEADERS, LC_H2_END_HEADERS, 1u);
    memcpy(credit_message + LC_H2_HEADER, block, (size_t)bn);
    mn = LC_H2_HEADER + (size_t)bn;
    (void)lc_h2_put_header(credit_message + mn, sizeof credit_message - mn, 8192u,
                           LC_H2_DATA, LC_H2_END_STREAM, 1u);
    mn += LC_H2_HEADER;
    memset(credit_message + mn, 'x', 8192u);
    mn += 8192u;
    server_record(s, pair[1], &site_writer, credit_message, mn);
    while (!s->spider_write_pending)
        worker_event(loop, s, foreign_deadline);
    require(s->spider_write[3] == LC_H2_WINDOW_UPDATE && !lc_spider_fetch_done(s->fetch),
            "body Flush owns cc.wmu while its real TLS Write is backpressured");
    (void)lc_h2_put_header(message, sizeof message, 8u, LC_H2_PING, 0, 0);
    memset(message + LC_H2_HEADER, 0x75, 8u);
    server_record(s, pair[1], &site_writer, message, LC_H2_HEADER + 8u);
    require(!lc_spider_fetch_read_ready(s->fetch),
            "real PING dispatch waits on body cc.wmu rather than enqueueing an ACK");
    unsigned blocked_read_calls = read_step_calls;
    uint64_t blocked_sequence = s->cl.wr.seq;
    require(spider_drain(s) == 0 && read_step_calls == blocked_read_calls + 1u &&
                s->spider_write_pending && s->cl.wr.seq == blocked_sequence,
            "loop consults non-writing reader continuation while real ciphertext remains blocked");
    s->rx_len = LC_REC_HEADER;
    memset(s->rx, 0xff, s->rx_len);
    require(spider_pump(s) == 0 && s->rx_len == LC_REC_HEADER && !s->spider_peer_lost,
            "body writer/PING wait preserves the following buffered TLS boundary");
    empty_socket(pair[1]);
    require(q_flush(&s->to_up, pair[0]) == 0 && spider_write_complete(s) == 0,
            "real socket completion releases body cc.wmu");
    ack_wire_len = 0;
    collect_socket(pair[1], ack_wire, &ack_wire_len, sizeof ack_wire);
    require(lc_record_key_init(&ack_reader, s->cl.alg, key, iv) == 0,
            "body Flush peer decryption key");
    ack_reader.seq = ack_sequence;
    require(lc_record_unprotect(&ack_reader, ack_wire, ack_wire_len, ack_plain, sizeof ack_plain,
                                &ack_plain_len, &ack_type) == 0 && ack_plain_len > 0u,
            "peer decrypts the original whole body Flush");
    for (size_t off = 0; off < ack_plain_len; off += 13u)
        require(ack_plain_len - off >= 13u && ack_plain[off + 3u] == LC_H2_WINDOW_UPDATE,
                "body Flush contains only its flow-credit frames");
    fill_socket(pair[0]);
    require(spider_drain(s) == 0 && s->spider_write_pending,
            "event loop resumes the saved body-owner PING before waiting for a Do wake");
    require(s->spider_write_len == 17u && s->spider_write[3] == LC_H2_PING &&
                s->rx_len == LC_REC_HEADER && !s->spider_peer_lost,
            "saved PING produces its own ACK only after body Flush; later TLS stays unopened");
    empty_socket(pair[1]);
    require(q_flush(&s->to_up, pair[0]) == 0 && spider_write_complete(s) == 0,
            "saved PING ACK completes through the actual socket");
    ack_wire_len = 0;
    collect_socket(pair[1], ack_wire, &ack_wire_len, sizeof ack_wire);
    require(lc_record_unprotect(&ack_reader, ack_wire, ack_wire_len, ack_plain, sizeof ack_plain,
                                &ack_plain_len, &ack_type) == 0 && ack_plain_len == 17u &&
                ack_plain[3] == LC_H2_PING && ack_plain[4] == LC_H2_ACK &&
                memcmp(ack_plain + LC_H2_HEADER, message + LC_H2_HEADER, 8u) == 0,
            "peer decrypts saved ACK identity after body-credit Write, with ordered TLS sequence");
    lc_record_key_free(&ack_reader);
    lc_record_key_free(&site_writer);
    session_close(loop, s);
    close(pair[1]);
    sessions_reap();
    s = session_new();
    require(s != NULL && socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair) == 0,
            "single-frame request owner tunnel fixture");
    s->st = ST_SPIDER;
    s->up_fd = pair[0];
    s->cl.hash = LC_SHA256;
    s->cl.alg = LC_AEAD_AES_128_GCM;
    s->cl.key_len = 16u;
    require(lc_record_key_init(&s->cl.wr, s->cl.alg, key, iv) == 0 &&
                lc_record_key_init(&s->cl.rd, s->cl.alg, key, iv) == 0 &&
                lc_record_key_init(&site_writer, s->cl.alg, key, iv) == 0,
            "single-frame request owner TLS keys");
    s->fetch = lc_spider_fetch_new("single-writer-tunnel.example", &browser);
    /* Complete only the opening before creating workers. Starting them first
     * can also flush HEADERS before fill_socket, leaving no future Write to block. */
    require(s->fetch != NULL && lc_spider_fetch_write_barrier(s->fetch) == 0 &&
                lc_spider_fetch_request_tasks(s->fetch) == 0 && spider_drain(s) == 0 &&
                s->tls_records_sent == 1u && !s->spider_write_pending,
            "single-frame fixture completes only its opening before worker startup");
    empty_socket(pair[1]);
    fill_socket(pair[0]);
    require(spider_start(loop, s) == 0, "single-frame request owner real worker");
    foreign_deadline = lc_now_ms() + 10000u;
    while (!s->spider_write_pending)
        worker_event(loop, s, foreign_deadline);
    require(s->spider_write[3] == LC_H2_HEADERS &&
                (s->spider_write[4] & LC_H2_END_HEADERS) != 0u,
            "single-frame HEADERS Flush reaches actual socket EAGAIN");
    ack_sequence = s->cl.wr.seq - 1u;
    (void)lc_h2_put_header(message, sizeof message, 0, LC_H2_SETTINGS, LC_H2_ACK, 0);
    (void)lc_h2_put_header(message + LC_H2_HEADER, sizeof message - LC_H2_HEADER,
                           8u, LC_H2_PING, 0, 0);
    memset(message + 2u * LC_H2_HEADER, 0x79, 8u);
    server_record(s, pair[1], &site_writer, message, 2u * LC_H2_HEADER + 8u);
    require(!lc_spider_fetch_read_ready(s->fetch) && s->spider_write_pending,
            "real SETTINGS ACK and following PING wait for the pending request writer");
    s->rx_len = LC_REC_HEADER;
    memset(s->rx, 0xff, s->rx_len);
    require(!lc_spider_fetch_read_ready(s->fetch) && spider_pump(s) == 0 &&
                s->rx_len == LC_REC_HEADER && !s->spider_peer_lost,
            "request/PING writer wait preserves the next buffered TLS record");
    empty_socket(pair[1]);
    require(q_flush(&s->to_up, pair[0]) == 0 && spider_write_complete(s) == 0,
            "whole single-frame request completion releases cc.wmu");
    ack_wire_len = 0;
    collect_socket(pair[1], ack_wire, &ack_wire_len, sizeof ack_wire);
    require(lc_record_key_init(&ack_reader, s->cl.alg, key, iv) == 0,
            "single-frame request peer decryption key");
    ack_reader.seq = ack_sequence;
    require(lc_record_unprotect(&ack_reader, ack_wire, ack_wire_len, ack_plain, sizeof ack_plain,
                                &ack_plain_len, &ack_type) == 0 && ack_plain_len > 9u &&
                ack_plain[3] == LC_H2_HEADERS && (ack_plain[4] & LC_H2_END_HEADERS) != 0u,
            "peer decrypts exactly the retained single-frame request Flush");
    fill_socket(pair[0]);
    require(spider_drain(s) == 0 && s->spider_write_pending,
            "event loop resumes the saved request-owner PING before waiting for a Do wake");
    require(s->spider_write_len == 17u && s->spider_write[3] == LC_H2_PING &&
                s->rx_len == LC_REC_HEADER && !s->spider_peer_lost,
            "saved PING ACK follows successful request completion without crossing TLS boundary");
    empty_socket(pair[1]);
    require(q_flush(&s->to_up, pair[0]) == 0 && spider_write_complete(s) == 0,
            "saved request-owner PING ACK completes on the real socket");
    ack_wire_len = 0;
    collect_socket(pair[1], ack_wire, &ack_wire_len, sizeof ack_wire);
    require(lc_record_unprotect(&ack_reader, ack_wire, ack_wire_len, ack_plain, sizeof ack_plain,
                                &ack_plain_len, &ack_type) == 0 && ack_plain_len == 17u &&
                ack_plain[3] == LC_H2_PING && ack_plain[4] == LC_H2_ACK &&
                memcmp(ack_plain + LC_H2_HEADER, message + 2u * LC_H2_HEADER, 8u) == 0,
            "peer decrypts the saved request-owner ACK nonce in TLS Write order");
    lc_record_key_free(&ack_reader);
    lc_record_key_free(&site_writer);
    session_close(loop, s);
    close(pair[1]);
    sessions_reap();
    for (int failure = 1; failure <= 2; failure++) {
        s = session_new();
        require(s != NULL && socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair) == 0,
                "thread failure session and peer");
        s->st = ST_SPIDER;
        s->up_fd = pair[0];
        require(lc_record_key_init(&s->cl.wr, LC_AEAD_AES_128_GCM, key, iv) == 0,
                "thread failure opening key");
        s->fetch = lc_spider_fetch_new("thread-failure.example", &browser);
        startup_peer = pair[1];
        startup_creates = 0u;
        opening_visible_before_create = 0;
        pthread_mutex_lock(&startup_lock);
        startup_fetch = s->fetch;
        startup_admitted = 0;
        atomic_store_explicit(&startup_watch, 1, memory_order_release);
        pthread_mutex_unlock(&startup_lock);
        fail_thread_start = failure;
        int saved_stdout;
        FILE *diagnostic = capture_stdout(&saved_stdout);
        int startup_rc = spider_start(loop, s);
        atomic_store_explicit(&startup_watch, 0, memory_order_release);
        startup_peer = -1;
        char diagnostic_text[512];
        restore_stdout(diagnostic, saved_stdout, diagnostic_text, sizeof diagnostic_text);
        require(startup_creates == (unsigned)failure && opening_visible_before_create,
                "failed creation preserves the submitted opening and exact attempted task count");
        if (failure == 2) {
            pthread_mutex_lock(&startup_lock);
            int admitted = startup_admitted;
            pthread_mutex_unlock(&startup_lock);
            require(admitted, "second creation failure rolls back Do after request publication");
        }
        require(s->fetch != NULL && startup_rc == -1 &&
                    !s->spider_worker_on && !s->spider_request_worker_on &&
                    fail_thread_start == 0,
                "either task creation failure rolls back started tasks without synchronous fallback");
        require(strstr(diagnostic_text, failure == 1 ? "Do worker creation failed" :
                                                       "request worker creation failed") != NULL &&
                    strstr(diagnostic_text, strerror(EAGAIN)) != NULL &&
                    strstr(diagnostic_text, strerror(EBADF)) == NULL,
                "startup log identifies the task and pthread return code rather than stale errno");
        session_close(loop, s);
        require(s->fetch == NULL && s->spider_wake_fd == -1,
                "failed task startup releases its fetch and registered wake descriptor");
        close(pair[1]);
        sessions_reap();
    }
    fail_thread_start = 0;
    s = session_new();
    require(s != NULL, "failed opening transport fixture");
    s->st = ST_SPIDER;
    require(lc_record_key_init(&s->cl.wr, LC_AEAD_AES_128_GCM, key, iv) == 0,
            "failed opening key");
    s->fetch = lc_spider_fetch_new("failed-opening.example", &browser);
    fail_thread_start = 1;
    require(s->fetch != NULL && spider_start(loop, s) == -1 && fail_thread_start == 1 &&
                !s->spider_worker_on && !s->spider_request_worker_on,
            "failed opening never attempts to create a worker");
    fail_thread_start = 0;
    session_close(loop, s);
    sessions_reap();
    s = session_new();
    require(s != NULL && socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair) == 0,
            "pending Write teardown fixture");
    s->st = ST_SPIDER;
    s->up_fd = pair[0];
    require(lc_record_key_init(&s->cl.wr, LC_AEAD_AES_128_GCM, key, iv) == 0,
            "pending Write teardown key");
    s->fetch = lc_spider_fetch_new("pending-close.example", &browser);
    fill_socket(pair[0]);
    require(s->fetch != NULL && spider_start(loop, s) == 0 &&
                s->spider_write != NULL && s->spider_write_pending,
            "startup retains initial Write under socket backpressure for safe teardown");
    require(!lc_spider_fetch_read_ready(s->fetch),
            "backpressured opening has not started the TLS readLoop");
    /* No readLoop exists yet: even a complete invalid record must remain unopened. */
    static const uint8_t early_record[] = { 0x17, 0x03, 0x03, 0, 1, 0 };
    memcpy(s->rx, early_record, sizeof early_record);
    s->rx_len = sizeof early_record;
    require(spider_pump(s) == 0 && s->rx_len == sizeof early_record &&
                !s->spider_peer_lost && s->spider_write_pending,
            "opening EAGAIN preserves buffered TLS boundary without reporting loss");
    session_close(loop, s);
    require(!s->spider_worker_on && !s->spider_request_worker_on &&
                s->spider_write == NULL && s->fetch == NULL,
            "close joins worker and releases retained plaintext without acknowledging success");
    close(pair[1]);
    sessions_reap();
    for (unsigned round = 0; round < 16u; round++) {
        s = session_new();
        require(s != NULL, "lifecycle session");
        s->st = ST_SPIDER;
        s->fetch = lc_spider_fetch_new("lifecycle.example", &browser);
        require(s->fetch != NULL && spider_tasks_prepare(s) == 0 && spider_worker_start(loop, s) == 0,
                "real tunnel worker starts with outstanding opening Write");
        session_close(loop, s);
        require(s->closing && !s->spider_worker_on && !s->spider_request_worker_on && s->fetch == NULL &&
                    s->spider_wake_fd == -1,
                "session close joins worker before releasing fetch and wake descriptor");
        sessions_reap();
        require(session_count == 0u, "reap releases the worker session");
    }
    session *live[LC_TEST_RESOURCE_SESSIONS];
    struct rusage before, after;
    require(getrusage(RUSAGE_SELF, &before) == 0, "resource baseline");
    long baseline_rss = test_rss_kib();
    for (unsigned i = 0; i < LC_TEST_RESOURCE_SESSIONS; i++) {
        live[i] = session_new();
        require(live[i] != NULL, "concurrent stranger session allocation");
        live[i]->st = ST_SPIDER;
        live[i]->fetch = lc_spider_fetch_new("resource.example", &browser);
        require(live[i]->fetch != NULL && spider_tasks_prepare(live[i]) == 0 &&
                    spider_worker_start(loop, live[i]) == 0,
                "concurrent stranger worker starts");
        if (i == 0u || i == 15u || i + 1u == LC_TEST_RESOURCE_SESSIONS) {
            pthread_attr_t attr;
            size_t stack_size = 0;
            require(pthread_getattr_np(live[i]->spider_worker, &attr) == 0,
                    "query live worker stack reservation");
            require(pthread_attr_getstacksize(&attr, &stack_size) == 0,
                    "read live worker stack reservation");
            pthread_attr_destroy(&attr);
            size_t request_stack_size = 0;
            require(pthread_getattr_np(live[i]->spider_request_worker, &attr) == 0 &&
                        pthread_attr_getstacksize(&attr, &request_stack_size) == 0,
                    "query independent request task stack reservation");
            pthread_attr_destroy(&attr);
            require(getrusage(RUSAGE_SELF, &after) == 0, "resource sample");
            printf("resource: sessions=%u rss_kib=%ld baseline_rss_kib=%ld "
                   "do_stack_reserved_bytes=%zu request_stack_reserved_bytes=%zu startup_cpu_us=%llu\n",
                   i + 1u, test_rss_kib(), baseline_rss, stack_size, request_stack_size,
                   (unsigned long long)(test_cpu_us(&after) - test_cpu_us(&before)));
        }
    }
    for (unsigned i = 0; i < LC_TEST_RESOURCE_SESSIONS; i++)
        session_close(loop, live[i]);
    sessions_reap();
    require(session_count == 0u && getrusage(RUSAGE_SELF, &after) == 0,
            "all simultaneous workers join and their sessions are reaped");
    printf("resource: sessions=0 rss_kib=%ld lifecycle_cpu_us=%llu\n", test_rss_kib(),
           (unsigned long long)(test_cpu_us(&after) - test_cpu_us(&before)));
    lc_loop_free(loop);
    free(sessions);
    return 0;
}
