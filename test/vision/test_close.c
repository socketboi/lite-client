/* Actual session ownership and sockets; observe close order and control time/write faults. */
#include "net/sock.h"
#include "vision_close_reference.h"
#include <unistd.h>
static ssize_t close_write(int fd, const void *p, size_t n);
static int observed_close(int fd);
static uint64_t close_now(void);
#define write close_write
#define close observed_close
#define lc_now_ms close_now
#define main lc_tunnel_program_main
#include "../../src/cmd/lc-tunnel/main.c"
#undef main
#undef lc_now_ms
#undef write
#undef close

static uint64_t now_ms = 10000u;
static int watched = -1, mode, calls, interrupts;
static int order_lan = -1, order_node = -1, close_step, tcp_fixture;
enum { NORMAL, INTERRUPTED, PARTIAL, ZERO, HARD };

static uint64_t close_now(void) { return now_ms; }

static ssize_t close_write(int fd, const void *p, size_t n)
{
    if (fd == watched) {
        calls++;
        if (mode == INTERRUPTED && interrupts-- > 0) {
            errno = EINTR;
            return -1;
        }
        if (mode == PARTIAL) {
            if (calls == 1)
                return write(fd, p, n > 3u ? 3u : n);
            errno = calls == 2 ? EINTR : EAGAIN;
            return -1;
        }
        if (mode == ZERO)
            return 0;
        if (mode == HARD) {
            errno = EIO;
            return -1;
        }
    }
    return write(fd, p, n);
}

static void require(int yes, const char *message)
{
    if (!yes) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static int observed_close(int fd)
{
    if (fd == order_node) {
        require(close_step == 0 && fcntl(order_lan, F_GETFD) >= 0,
                "client endpoint remains owned when node transport closes");
        close_step = 1;
    } else if (fd == order_lan) {
        require(close_step == 1 && fcntl(order_node, F_GETFD) == -1 && errno == EBADF,
                "node transport is closed before client endpoint release");
        close_step = 2;
    }
    return close(fd);
}

static int stream_pair(int pair[2])
{
    if (!tcp_fixture)
        return socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t n = sizeof addr;
    require(listener >= 0 && bind(listener, (struct sockaddr *)&addr, n) == 0 &&
            listen(listener, 1) == 0 && getsockname(listener, (struct sockaddr *)&addr, &n) == 0,
            "isolated loopback TCP listener");
    pair[1] = socket(AF_INET, SOCK_STREAM, 0);
    require(pair[1] >= 0 && connect(pair[1], (struct sockaddr *)&addr, n) == 0,
            "real TCP peer connects locally");
    pair[0] = accept(listener, NULL, NULL);
    close(listener);
    return pair[0] >= 0 ? 0 : -1;
}

static session *fixture(lc_loop *l, int lan[2], int node[2], lc_record_key *peer,
                        int paused, int tls12)
{
    session *s = session_new();
    require(s != NULL && stream_pair(lan) == 0 && stream_pair(node) == 0,
            "allocate real session and stream endpoints");
    for (unsigned i = 0; i < 2u; i++)
        require(lc_set_nonblocking(lan[i]) == 0 && lc_set_nonblocking(node[i]) == 0,
                "nonblocking endpoints");
    s->st = ST_OPEN;
    s->lan_fd = lan[0];
    s->up_fd = node[0];
    s->lan_on_loop = 1;
    s->raw_poll_paused = paused;
    require(lc_loop_add(l, lan[0], LC_EV_READ, &s->lan_tag) == 0 &&
            (paused || lc_loop_add(l, node[0], LC_EV_READ, &s->up_tag) == 0),
            "register exactly the owned watches");
    uint8_t key[16] = {0}, iv[12] = {0};
    memset(peer, 0, sizeof *peer);
    if (tls12) {
        const lc_tls12_suite *suite = lc_tls12_suite_by_id(0xc02fu);
        require(suite != NULL && lc_record_key_init12(&s->cl.wr, suite, key, iv, NULL, 0) == 0 &&
                lc_record_key_init12(peer, suite, key, iv, NULL, 1) == 0, "TLS 1.2 fixture keys");
    } else {
        require(lc_record_key_init(&s->cl.wr, LC_AEAD_AES_128_GCM, key, iv) == 0 &&
                lc_record_key_init(peer, LC_AEAD_AES_128_GCM, key, iv) == 0, "TLS 1.3 fixture keys");
    }
    watched = node[0];
    return s;
}

static void alert_then_eof(int fd, lc_record_key *peer)
{
    uint8_t rec[LC_CLIENT_ALERT_MAX], plain[16], typ = 0;
    size_t n = 0, pn = 0;
    for (;;) {
        ssize_t z = read(fd, rec + n, sizeof rec - n);
        require(z >= 0, "closed peer has no missing alert bytes");
        if (z == 0)
            break;
        n += (size_t)z;
        require(n < sizeof rec, "one bounded alert before EOF");
    }
    require(n > 5u && lc_record_unprotect(peer, rec, n, plain, sizeof plain, &pn, &typ) == 0 &&
            typ == LC_REC_ALERT && pn == 2u && plain[0] == 1u &&
            plain[1] == LC_CLIENT_ALERT_CLOSE_NOTIFY, "exactly one authenticated warning close_notify");
}

static size_t fill(int fd)
{
    int size = 4096;
    require(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof size) == 0, "bounded send buffer");
    uint8_t data[1024];
    memset(data, 0x5a, sizeof data);
    size_t total = 0;
    for (;;) {
        ssize_t z = write(fd, data, sizeof data);
        if (z < 0) {
            require(errno == EAGAIN || errno == EWOULDBLOCK, "real kernel backpressure");
            return total;
        }
        require(z > 0, "fill makes progress");
        total += (size_t)z;
        require(total < 1024u * 1024u, "bounded fixture preload");
    }
}

static void drain(int fd, size_t n)
{
    uint8_t data[1024];
    while (n > 0u) {
        ssize_t z = read(fd, data, n < sizeof data ? n : sizeof data);
        require(z > 0, "drain exactly the preloaded stream");
        for (ssize_t i = 0; i < z; i++)
            require(data[i] == 0x5a, "preload ordering preserved");
        n -= (size_t)z;
    }
}

static void retained(session *s, int lan_peer)
{
    sessions_reap();
    require(session_count == 1u, "pending close survives event-batch reap");
    require(s->up_fd >= 0 && s->lan_fd >= 0 && s->cl.wr.seq == 1u,
            "both transports and one sealed record stay owned");
    uint8_t b;
    require(read(lan_peer, &b, 1) < 0 && (errno == EAGAIN || errno == EWOULDBLOCK),
            "LAN FIN waits for the node close write");
}

static void run_case(int which)
{
    int label = which;
    if (which >= 12) {
        static const int scenarios[] = {0, 4, 5, 9, 0, 1};
        require(which < 18, "known close-order scenario");
        which = scenarios[which - 12];
    }
    tcp_fixture = label >= 16;
    lc_loop *l = lc_loop_new(16);
    require(l != NULL, "real epoll loop");
    int lan[2], node[2];
    lc_record_key peer;
    int paused = which == 4;
    session *s = fixture(l, lan, node, &peer, paused, which == 1);
    if (label >= 12) {
        order_lan = lan[0];
        order_node = node[0];
    }
    if (which == 2) {
        mode = INTERRUPTED;
        interrupts = 3;
    } else if (which == 3) {
        mode = PARTIAL;
    } else if (which == 6) {
        mode = ZERO;
    } else if (which == 7) {
        mode = HARD;
    } else if (which == 8) {
        close(node[1]);
        node[1] = -1;
    } else if (which == 9) {
        require(q_push(&s->to_up, (const uint8_t *)"x", 1) == 0, "active application write");
    } else if (which == 10) {
        s->own_fail = 1;
    } else if (which == 11) {
        s->st = ST_HANDSHAKE;
    }
    size_t preload = (which == 4 || which == 5) ? fill(node[0]) : 0u;
    session_close(l, s);
    if (which == 3 || which == 4 || which == 5) {
        retained(s, lan[1]);
        require(hy_wait(10000) == 5000 && hy_wait(20) == 20, "five-second close deadline caps sleep");
        require(write(lan[1], "x", 1) == 1, "client readable during pending close");
        lc_event events[16];
        int ready = lc_loop_wait(l, events, 16, 0);
        require(ready == (which == 3 ? 1 : 0) &&
                (ready == 0 || (events[0].data == &s->up_tag &&
                 events[0].events == LC_EV_WRITE)), "only the node writer is watched during close");
        now_ms += 1000u;
        session_close(l, s);
        retained(s, lan[1]);
        require(hy_wait(10000) == 4000, "continuation does not reset deadline");
        if (which == 5) {
            now_ms += 3999u;
            sessions_expire(l);
            retained(s, lan[1]);
            require(hy_wait(10000) == 1, "deadline honored to final millisecond");
            now_ms++;
            int attempts = calls;
            sessions_expire(l);
            require(calls == attempts, "expired close never writes late");
            drain(node[1], preload);
        } else {
            /* A different endpoint progresses while this socket cannot write. */
            int other[2], tag = 17;
            require(socketpair(AF_UNIX, SOCK_STREAM, 0, other) == 0 &&
                    lc_loop_add(l, other[0], LC_EV_READ, &tag) == 0 &&
                    write(other[1], "y", 1) == 1, "unrelated runnable connection");
            int n = lc_loop_wait(l, events, 16, 100);
            int found = 0;
            for (int i = 0; i < n; i++)
                found |= events[i].data == &tag;
            require(found, "close does not block unrelated event dispatch");
            close(other[0]);
            close(other[1]);
            if (preload != 0u)
                drain(node[1], preload);
            mode = NORMAL;
            n = lc_loop_wait(l, events, 16, 100);
            require(n == 1 && events[0].data == &s->up_tag &&
                    (events[0].events & LC_EV_WRITE) != 0u, "node WRITE resumes pending close");
            session_close(l, s);
        }
    }
    if (which <= 4) {
        alert_then_eof(node[1], &peer);
        if (which == 2)
            require(calls == 4, "EINTR retries the same alert write");
    } else if (node[1] >= 0) {
        uint8_t b;
        require(read(node[1], &b, 1) == 0, "failure or active write closes without extra bytes");
    }
    uint8_t b;
    ssize_t ended = read(lan[1], &b, 1);
    require(ended == 0 || (ended < 0 && errno == ECONNRESET),
            "LAN closes after node close completion, including unread client data");
    require(s->up_fd == -1 && s->lan_fd == -1, "final teardown releases endpoint descriptors");
    if (label >= 12)
        require(close_step == 2, "both endpoint closes observed exactly in reference order");
    int attempts = calls;
    session_close(l, s);
    require(calls == attempts, "repeated completed close is inert");
    sessions_reap();
    require(session_count == 0u && lc_loop_wait(l, (lc_event[16]){{0}}, 16, 0) == 0,
            "final reap removes session and all watches");
    close(lan[1]);
    if (node[1] >= 0)
        close(node[1]);
    lc_record_key_free(&peer);
    lc_loop_free(l);
    free(sessions);
    sessions = NULL;
    sessions_cap = 0;
    printf("  ok    close ownership case %d\n", label);
}

static void direct_close_case(int direction, int tcp)
{
    tcp_fixture = tcp;
    lc_loop *l = lc_loop_new(16);
    int lan[2], node[2];
    lc_record_key peer;
    session *s = fixture(l, lan, node, &peer, 0, 0);
    order_lan = lan[0];
    order_node = node[0];
    close_step = calls = 0;
    mode = NORMAL;
    if (direction == 0) {
        s->direct_in = 1;
    } else {
        s->vision.direct_out = 1;
        require(!s->raw_writer, "Direct announcement alone has not switched the writer");
        if (direction == 1) {
            vision_mb mb;
            vision_mb_begin(s, &mb);
            require(mb.raw && s->raw_writer, "the next write enters raw copy");
        }
    }
    session_close(l, s);
    if (!reference_suppresses_close_notify[direction]) {
        alert_then_eof(node[1], &peer);
        require(calls == 1, "announcement-only writer still sends its outer alert");
    } else {
        uint8_t b;
        require(read(node[1], &b, 1) == 0 && calls == 0,
                "direct copy closes raw transport without an outer alert");
    }
    require(close_step == 2, "raw close retains node-before-LAN ownership order");
    session_close(l, s);
    sessions_reap();
    require(session_count == 0u, "raw close reaps the session");
    close(lan[1]); close(node[1]);
    lc_record_key_free(&peer);
    lc_loop_free(l);
    free(sessions); sessions = NULL; sessions_cap = 0;
    order_lan = order_node = -1;
}

int main(int argc, char **argv)
{
    lc_ignore_sigpipe();
    if (argc == 2) {
        run_case(atoi(argv[1]));
        return 0;
    }
    for (int i = 0; i < 18; i++) {
        pid_t child = fork();
        require(child >= 0, "fork isolated ownership case");
        if (child == 0) {
            run_case(i);
            exit(0);
        }
        int status;
        require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "isolated close case succeeds");
    }
    puts("PASS 18 close ownership cases");
    for (int tcp = 0; tcp <= 1; tcp++)
        for (int direction = 0; direction < 3; direction++)
            direct_close_case(direction, tcp);
    puts("PASS 6 Vision direct/announcement close cases");
    return 0;
}
