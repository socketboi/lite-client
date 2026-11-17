/* Native resource observations for the actual tunnel's HTTP workers. Completed
 * mode adds a controlled TLS/socketpair peer, never substituted task functions.
 * Holds are benchmark observation windows, not client scheduling changes.
 * CPU phases exclude procfs observations; total includes in-cycle observations.
 */
#define main lc_tunnel_program_main
#include "../../src/cmd/lc-tunnel/main.c"
#undef main

#include <dirent.h>
#include <time.h>

static void bw_require(int yes, const char *message)
{
    if (!yes) {
        fprintf(stderr, "FAIL bench-spider-workers: %s\n", message);
        exit(1);
    }
}

static uint64_t bw_clock(clockid_t clock)
{
    struct timespec value;
    bw_require(clock_gettime(clock, &value) == 0, "read measurement clock");
    return (uint64_t)value.tv_sec * 1000000000u + (uint64_t)value.tv_nsec;
}

static void bw_sleep(unsigned milliseconds)
{
    struct timespec duration = {
        .tv_sec = (time_t)(milliseconds / 1000u),
        .tv_nsec = (long)(milliseconds % 1000u) * 1000000L
    };
    while (nanosleep(&duration, &duration) != 0)
        bw_require(errno == EINTR, "observation sleep");
}

static unsigned bw_entries(const char *path)
{
    DIR *directory = opendir(path);
    bw_require(directory != NULL, "open proc directory");
    unsigned count = 0;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(directory)) != NULL)
        if (entry->d_name[0] != '.')
            count++;
    bw_require(errno == 0 && closedir(directory) == 0, "read proc directory");
    return count;
}

static long bw_rss(void)
{
    FILE *file = fopen("/proc/self/status", "r");
    bw_require(file != NULL, "open resident-memory observation");
    char line[256];
    long rss = -1;
    while (fgets(line, sizeof line, file) != NULL)
        if (sscanf(line, "VmRSS: %ld kB", &rss) == 1)
            break;
    bw_require(fclose(file) == 0 && rss >= 0, "read resident-memory observation");
    return rss;
}

static unsigned bw_argument(const char *text, unsigned maximum)
{
    unsigned value = 0;
    bw_require(text[0] != '\0', "empty argument");
    for (const char *p = text; *p != '\0'; p++) {
        bw_require(*p >= '0' && *p <= '9', "nondecimal argument");
        unsigned digit = (unsigned)(*p - '0');
        bw_require(digit <= maximum && value <= (maximum - digit) / 10u,
                   "argument exceeds benchmark bound");
        value = value * 10u + digit;
    }
    bw_require(value > 0u, "zero argument");
    return value;
}

static unsigned bw_wait_tasks(unsigned expected)
{
    uint64_t deadline = bw_clock(CLOCK_MONOTONIC) + 1000000000u;
    unsigned count = bw_entries("/proc/self/task");
    while (count != expected && bw_clock(CLOCK_MONOTONIC) < deadline) {
        bw_sleep(1u);
        count = bw_entries("/proc/self/task");
    }
    bw_require(count == expected, "retired workers leave the kernel task list");
    return count;
}

static void bw_dispatch(lc_loop *loop, session **live, unsigned count, uint64_t deadline)
{
    lc_event event;
    bw_require(lc_now_ms() < deadline && lc_loop_wait(loop, &event, 1u, 1000) == 1 &&
                   (event.events & LC_EV_READ) != 0u,
               "worker completion reaches its eventfd before the deadline");
    for (unsigned i = 0; i < count; i++)
        if (event.data == &live[i]->spider_tag) {
            bw_require(spider_worker_ready(live[i]) == 0, "drive actual worker completion");
            return;
        }
    bw_require(0, "event belongs to a live benchmark session");
}

static void bw_peer_drain(int peer)
{
    uint8_t buffer[8192];
    for (;;) {
        ssize_t got = read(peer, buffer, sizeof buffer);
        if (got > 0)
            continue;
        if (got < 0 && errno == EINTR)
            continue;
        bw_require(got < 0 && (errno == EAGAIN || errno == EWOULDBLOCK),
                   "drain prior client records at the controlled peer");
        return;
    }
}

static void bw_peer_send(session *s, int peer, lc_record_key *writer,
                         const uint8_t *payload, size_t len)
{
    uint8_t record[LC_REC_MAX_WIRE12];
    size_t written = 0;
    bw_require(lc_record_protect(writer, LC_REC_APPLICATION_DATA, payload, len, 0,
                                record, sizeof record, &written) == 0 &&
                   write(peer, record, written) == (ssize_t)written && spider_pump(s) == 0,
               "actual TLS readLoop accepts the controlled peer record");
}

static void bw_peer_reply(int peer, lc_record_key *reader,
                          const uint8_t *expected, size_t expected_len)
{
    uint8_t record[LC_REC_MAX_WIRE12], plain[8192];
    size_t used = 0;
    for (;;) {
        bw_require(used < sizeof record, "bounded reply record");
        ssize_t got = read(peer, record + used, sizeof record - used);
        if (got > 0) {
            used += (size_t)got;
            continue;
        }
        if (got < 0 && errno == EINTR)
            continue;
        bw_require(got < 0 && (errno == EAGAIN || errno == EWOULDBLOCK),
                   "reply reaches the controlled peer without EOF");
        break;
    }
    size_t len = 0;
    uint8_t type = 0;
    bw_require(used > LC_REC_HEADER && used == LC_REC_HEADER +
                   (((size_t)record[3] << 8) | record[4]), "one complete TLS reply record");
    bw_require(lc_record_unprotect(reader, record, used, plain, sizeof plain, &len, &type) == 0 &&
                   type == LC_REC_APPLICATION_DATA && len == expected_len &&
                   memcmp(plain, expected, len) == 0,
               "peer authenticates the exact retained-readLoop reply");
}

static void bw_completed(lc_loop *loop, const lc_browser *browser, unsigned rounds,
                          unsigned hold_ms, unsigned baseline_tasks, unsigned baseline_fds)
{
    const unsigned counts[] = {1u, 2u, 4u, 8u};
    const uint8_t key[16] = {0}, iv[LC_AEAD_NONCE] = {0};
    static const char page[] = "<a href=\"/retained-worker\">link</a>";
    for (unsigned round = 1; round <= rounds; round++) {
        for (unsigned index = 0; index < sizeof counts / sizeof counts[0]; index++) {
            unsigned count = counts[index];
            session *live[8];
            int peers[8];
            lc_record_key writers[8], readers[8];
            long rss_before = bw_rss();
            uint64_t total_begin = bw_clock(CLOCK_PROCESS_CPUTIME_ID);
            uint64_t setup_begin = bw_clock(CLOCK_PROCESS_CPUTIME_ID);
            for (unsigned i = 0; i < count; i++) {
                int pair[2];
                live[i] = session_new();
                bw_require(live[i] != NULL &&
                               socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair) == 0,
                           "allocate controlled TLS socket pair");
                session *s = live[i];
                s->st = ST_SPIDER;
                s->up_fd = pair[0];
                peers[i] = pair[1];
                s->cl.hash = LC_SHA256;
                s->cl.alg = LC_AEAD_AES_128_GCM;
                s->cl.key_len = sizeof key;
                bw_require(lc_record_key_init(&s->cl.wr, s->cl.alg, key, iv) == 0 &&
                               lc_record_key_init(&s->cl.rd, s->cl.alg, key, iv) == 0 &&
                               lc_record_key_init(&writers[i], s->cl.alg, key, iv) == 0 &&
                               lc_record_key_init(&readers[i], s->cl.alg, key, iv) == 0,
                           "initialize test-only TLS application keys");
                s->fetch = lc_spider_fetch_new("workers.example", browser);
                bw_require(s->fetch != NULL, "allocate actual HTTP fetch");
            }
            uint64_t setup_cpu = bw_clock(CLOCK_PROCESS_CPUTIME_ID) - setup_begin;
            uint64_t start_begin = bw_clock(CLOCK_PROCESS_CPUTIME_ID);
            for (unsigned i = 0; i < count; i++)
                bw_require(spider_start(loop, live[i]) == 0, "start ordinary TLS/HTTP workers");
            uint64_t deadline = lc_now_ms() + 10000u;
            for (;;) {
                int ready = 1;
                for (unsigned i = 0; i < count; i++)
                    ready &= live[i]->tls_records_sent >= 2u;
                if (ready)
                    break;
                bw_dispatch(loop, live, count, deadline);
            }
            uint64_t start_cpu = bw_clock(CLOCK_PROCESS_CPUTIME_ID) - start_begin;
            unsigned live_tasks = bw_entries("/proc/self/task");
            unsigned live_fds = bw_entries("/proc/self/fd");
            bw_require(live_tasks == baseline_tasks + 2u * count &&
                           live_fds == baseline_fds + 3u * count,
                       "response-waiting sessions retain both workers and their sockets");
            long rss_live = bw_rss();
            uint64_t finish_begin = bw_clock(CLOCK_PROCESS_CPUTIME_ID);
            uint8_t response[128];
            size_t used = 0;
            (void)lc_h2_put_header(response, sizeof response, 0, LC_H2_SETTINGS, 0, 0);
            used += LC_H2_HEADER;
            (void)lc_h2_put_header(response + used, sizeof response - used, 1u, LC_H2_HEADERS,
                                   LC_H2_END_HEADERS, 1u);
            used += LC_H2_HEADER;
            response[used++] = 0x88; /* HPACK static :status 200. */
            (void)lc_h2_put_header(response + used, sizeof response - used, sizeof page - 1u,
                                   LC_H2_DATA, LC_H2_END_STREAM, 1u);
            used += LC_H2_HEADER;
            memcpy(response + used, page, sizeof page - 1u);
            used += sizeof page - 1u;
            for (unsigned i = 0; i < count; i++)
                bw_peer_send(live[i], peers[i], &writers[i], response, used);
            for (;;) {
                int complete = 1;
                for (unsigned i = 0; i < count; i++)
                    complete &= lc_spider_fetch_done(live[i]->fetch) &&
                                lc_spider_fetch_read_ready(live[i]->fetch) &&
                                !live[i]->spider_worker_on && !live[i]->spider_request_worker_on;
                if (complete)
                    break;
                bw_dispatch(loop, live, count, deadline);
            }
            uint64_t finish_cpu = bw_clock(CLOCK_PROCESS_CPUTIME_ID) - finish_begin;
            unsigned retired_tasks = bw_wait_tasks(baseline_tasks);
            long rss_retired = bw_rss();
            uint64_t hold_begin = bw_clock(CLOCK_PROCESS_CPUTIME_ID);
            uint64_t hold_wall_begin = bw_clock(CLOCK_MONOTONIC);
            bw_sleep(hold_ms);
            uint64_t hold_wall = bw_clock(CLOCK_MONOTONIC) - hold_wall_begin;
            uint64_t hold_cpu = bw_clock(CLOCK_PROCESS_CPUTIME_ID) - hold_begin;
            uint64_t retained_begin = bw_clock(CLOCK_PROCESS_CPUTIME_ID);
            for (unsigned i = 0; i < count; i++) {
                session *s = live[i];
                bw_require(!s->closing && !s->spider_end && s->fetch != NULL &&
                               q_pending(&s->to_up) == 0u && !s->spider_write_pending,
                           "HTTP completion preserves a drained live TLS/readLoop");
                bw_peer_drain(peers[i]);
                readers[i].seq = s->cl.wr.seq;
                uint8_t ping[LC_H2_HEADER + 8u];
                (void)lc_h2_put_header(ping, sizeof ping, 8u, LC_H2_PING, 0, 0);
                memset(ping + LC_H2_HEADER, 0x57, 8u);
                bw_peer_send(s, peers[i], &writers[i], ping, sizeof ping);
                ping[4] = LC_H2_ACK;
                bw_peer_reply(peers[i], &readers[i], ping, sizeof ping);
                uint8_t late[LC_H2_HEADER + 4096u];
                (void)lc_h2_put_header(late, sizeof late, 4096u, LC_H2_DATA, 0, 1u);
                memset(late + LC_H2_HEADER, 0x6a, 4096u);
                bw_peer_send(s, peers[i], &writers[i], late, sizeof late);
                uint8_t credit[LC_H2_HEADER + 4u];
                (void)lc_h2_put_header(credit, sizeof credit, 4u, LC_H2_WINDOW_UPDATE, 0, 0);
                uint32_t increment = 4096u + (uint32_t)(sizeof page - 1u);
                credit[9] = (uint8_t)(increment >> 24);
                credit[10] = (uint8_t)(increment >> 16);
                credit[11] = (uint8_t)(increment >> 8);
                credit[12] = (uint8_t)increment;
                bw_peer_reply(peers[i], &readers[i], credit, sizeof credit);
                bw_require(!s->spider_worker_on && !s->spider_request_worker_on &&
                               !s->closing && lc_spider_fetch_done(s->fetch),
                           "late input does not restart completed HTTP tasks");
            }
            uint64_t retained_cpu = bw_clock(CLOCK_PROCESS_CPUTIME_ID) - retained_begin;
            bw_require(bw_entries("/proc/self/task") == baseline_tasks,
                       "retained readLoop runs without HTTP worker threads");
            uint64_t close_begin = bw_clock(CLOCK_PROCESS_CPUTIME_ID);
            for (unsigned i = 0; i < count; i++)
                session_close(loop, live[i]);
            sessions_reap();
            uint64_t close_cpu = bw_clock(CLOCK_PROCESS_CPUTIME_ID) - close_begin;
            for (unsigned i = 0; i < count; i++) {
                bw_require(close(peers[i]) == 0, "close controlled peer");
                lc_record_key_free(&writers[i]);
                lc_record_key_free(&readers[i]);
            }
            unsigned after_tasks = bw_wait_tasks(baseline_tasks);
            unsigned after_fds = bw_entries("/proc/self/fd");
            bw_require(session_count == 0u && after_fds == baseline_fds,
                       "completed sessions release slots and all descriptors");
            uint64_t total_cpu = bw_clock(CLOCK_PROCESS_CPUTIME_ID) - total_begin;
            printf("{\"type\":\"sample\",\"round\":%u,\"sessions\":%u,"
                   "\"setup_cpu_ns\":%llu,\"start_cpu_ns\":%llu,\"finish_cpu_ns\":%llu,"
                   "\"hold_cpu_ns\":%llu,\"hold_wall_ns\":%llu,\"retained_cpu_ns\":%llu,"
                   "\"close_cpu_ns\":%llu,\"total_cpu_ns\":%llu,\"rss_before_kib\":%ld,"
                   "\"rss_live_kib\":%ld,\"rss_retired_kib\":%ld,\"rss_after_kib\":%ld,"
                   "\"live_tasks\":%u,\"retired_tasks\":%u,\"after_tasks\":%u,"
                   "\"live_fds\":%u,\"after_fds\":%u,\"ping_acks\":%u,\"late_refunds\":%u}\n",
                   round, count, (unsigned long long)setup_cpu, (unsigned long long)start_cpu,
                   (unsigned long long)finish_cpu, (unsigned long long)hold_cpu,
                   (unsigned long long)hold_wall, (unsigned long long)retained_cpu,
                   (unsigned long long)close_cpu, (unsigned long long)total_cpu,
                   rss_before, rss_live, rss_retired, bw_rss(), live_tasks, retired_tasks,
                   after_tasks, live_fds, after_fds, count, count);
            fflush(stdout);
        }
    }
}

int main(int argc, char **argv)
{
    bw_require(argc >= 1 && argc <= 4, "expected optional rounds, hold milliseconds and mode");
    unsigned rounds = argc >= 2 ? bw_argument(argv[1], 32u) : 8u;
    unsigned hold_ms = argc >= 3 ? bw_argument(argv[2], 500u) : 250u;
    const char *mode = argc == 4 ? argv[3] : "blocked";
    bw_require(strcmp(mode, "blocked") == 0 || strcmp(mode, "completed") == 0,
               "unknown resource workload");
    alarm(120);
    lc_browser browser;
    bw_require(lc_browser_chrome_anchored(&browser, LC_BROWSER_NAV) == 0,
               "initialize ordinary browser fields");
    lc_loop *loop = lc_loop_new(32u);
    bw_require(loop != NULL, "create actual event loop");
    const unsigned counts[] = {1u, 2u, 4u, 8u};
    unsigned baseline_tasks = bw_entries("/proc/self/task");
    unsigned baseline_fds = bw_entries("/proc/self/fd");
    struct timespec resolution;
    bw_require(clock_getres(CLOCK_PROCESS_CPUTIME_ID, &resolution) == 0,
               "read CPU clock resolution");
    printf("{\"type\":\"metadata\",\"mode\":\"%s\",\"rounds\":%u,\"hold_ms\":%u,"
           "\"baseline_tasks\":%u,\"baseline_fds\":%u,\"cpu_clock_resolution_ns\":%llu}\n",
           mode, rounds, hold_ms, baseline_tasks, baseline_fds,
           (unsigned long long)((uint64_t)resolution.tv_sec * 1000000000u +
                                (uint64_t)resolution.tv_nsec));
    if (strcmp(mode, "completed") == 0) {
        bw_completed(loop, &browser, rounds, hold_ms, baseline_tasks, baseline_fds);
        lc_loop_free(loop);
        free(sessions);
        puts("{\"type\":\"complete\",\"exit\":0}");
        return 0;
    }
    for (unsigned round = 1; round <= rounds; round++) {
        for (unsigned index = 0; index < sizeof counts / sizeof counts[0]; index++) {
            unsigned count = counts[index];
            session *live[8];
            long rss_before = bw_rss();
            uint64_t total_begin = bw_clock(CLOCK_PROCESS_CPUTIME_ID);
            uint64_t setup_begin = bw_clock(CLOCK_PROCESS_CPUTIME_ID);
            for (unsigned i = 0; i < count; i++) {
                live[i] = session_new();
                bw_require(live[i] != NULL, "allocate session");
                live[i]->st = ST_SPIDER;
                live[i]->fetch = lc_spider_fetch_new("workers.example", &browser);
                bw_require(live[i]->fetch != NULL && spider_tasks_prepare(live[i]) == 0,
                           "prepare real fetch with uncompleted opening Write");
            }
            uint64_t setup_cpu = bw_clock(CLOCK_PROCESS_CPUTIME_ID) - setup_begin;
            uint64_t start_begin = bw_clock(CLOCK_PROCESS_CPUTIME_ID);
            for (unsigned i = 0; i < count; i++)
                bw_require(spider_worker_start(loop, live[i]) == 0, "start actual workers");
            uint64_t start_cpu = bw_clock(CLOCK_PROCESS_CPUTIME_ID) - start_begin;
            uint64_t idle_begin = bw_clock(CLOCK_PROCESS_CPUTIME_ID);
            uint64_t idle_wall_begin = bw_clock(CLOCK_MONOTONIC);
            bw_sleep(hold_ms);
            uint64_t idle_wall = bw_clock(CLOCK_MONOTONIC) - idle_wall_begin;
            uint64_t idle_cpu = bw_clock(CLOCK_PROCESS_CPUTIME_ID) - idle_begin;
            unsigned live_tasks = bw_entries("/proc/self/task");
            unsigned live_fds = bw_entries("/proc/self/fd");
            bw_require(live_tasks == baseline_tasks + 2u * count,
                       "both HTTP task threads stay alive behind opening backpressure");
            bw_require(live_fds == baseline_fds + count, "one wake descriptor per session");
            long rss_live = bw_rss();
            for (unsigned i = 0; i < count; i++)
                bw_require(!lc_spider_fetch_done(live[i]->fetch),
                           "blocked opening cannot finish Do");
            uint64_t close_begin = bw_clock(CLOCK_PROCESS_CPUTIME_ID);
            for (unsigned i = 0; i < count; i++)
                session_close(loop, live[i]);
            sessions_reap();
            uint64_t close_cpu = bw_clock(CLOCK_PROCESS_CPUTIME_ID) - close_begin;
            bw_require(session_count == 0u, "all session slots are released");
            /* A joined Linux task can briefly remain visible in procfs while
             * kernel exit bookkeeping finishes. Bound that observation race.
             */
            uint64_t deadline = bw_clock(CLOCK_MONOTONIC) + 1000000000u;
            unsigned after_tasks = bw_entries("/proc/self/task");
            while (after_tasks != baseline_tasks && bw_clock(CLOCK_MONOTONIC) < deadline) {
                bw_sleep(1u);
                after_tasks = bw_entries("/proc/self/task");
            }
            unsigned after_fds = bw_entries("/proc/self/fd");
            bw_require(after_tasks == baseline_tasks && after_fds == baseline_fds,
                       "worker and descriptor counts return to baseline");
            uint64_t total_cpu = bw_clock(CLOCK_PROCESS_CPUTIME_ID) - total_begin;
            printf("{\"type\":\"sample\",\"round\":%u,\"sessions\":%u,"
                   "\"setup_cpu_ns\":%llu,\"start_cpu_ns\":%llu,\"hold_cpu_ns\":%llu,"
                   "\"hold_wall_ns\":%llu,\"close_cpu_ns\":%llu,\"total_cpu_ns\":%llu,"
                   "\"rss_before_kib\":%ld,\"rss_live_kib\":%ld,\"rss_after_kib\":%ld,"
                   "\"live_tasks\":%u,\"after_tasks\":%u,\"live_fds\":%u,\"after_fds\":%u}\n",
                   round, count, (unsigned long long)setup_cpu,
                   (unsigned long long)start_cpu, (unsigned long long)idle_cpu,
                   (unsigned long long)idle_wall, (unsigned long long)close_cpu,
                   (unsigned long long)total_cpu, rss_before, rss_live, bw_rss(),
                   live_tasks, after_tasks, live_fds, after_fds);
            fflush(stdout);
        }
    }
    lc_loop_free(loop);
    free(sessions);
    puts("{\"type\":\"complete\",\"exit\":0}");
    return 0;
}
