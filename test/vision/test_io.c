/* Real nonblocking sockets; only syscall interruptions are injected. */
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>
static ssize_t observed_read(int fd, void *p, size_t n);
static ssize_t observed_write(int fd, const void *p, size_t n);
static ssize_t observed_recv(int fd, void *p, size_t n, int flags);
static int observed_ioctl(int fd, int request, void *p);
#define read observed_read
#define write observed_write
#define recv observed_recv
#define ioctl(fd, request, p) observed_ioctl(fd, (int)(request), p)
#define main lc_tunnel_program_main
#include "../../src/cmd/lc-tunnel/main.c"
#undef main
#undef ioctl
#undef recv
#undef write
#undef read

enum { CONTROL, FIRST_IOCTL, EMPTY_PEEK, SECOND_IOCTL, FILTER_PEEK,
       RAW_PEEK, RAW_WRITE, RAW_DRAIN, SINGLE_DRAIN, ZERO_WRITE, FIRST_READ };
static int fault, fault_errno, fault_left, input_fd = -1, output_fd = -1, empty_metadata;
static unsigned injected, output_attempts;

static void require(int yes, const char *message)
{
    if (!yes) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
    printf("  ok    %s\n", message);
}

static int interrupt(int matches)
{
    if (!matches || fault_left == 0)
        return 0;
    fault_left--;
    injected++;
    errno = fault_errno;
    return 1;
}

static ssize_t observed_read(int fd, void *p, size_t n)
{
    if (interrupt(fd == input_fd && (fault == RAW_DRAIN || fault == SINGLE_DRAIN || fault == FIRST_READ)))
        return -1;
    return read(fd, p, n);
}

static ssize_t observed_write(int fd, const void *p, size_t n)
{
    if (fd == output_fd)
        output_attempts++;
    if (fault == ZERO_WRITE && interrupt(fd == output_fd))
        return 0;
    if (interrupt(fd == output_fd && fault == RAW_WRITE))
        return -1;
    return write(fd, p, n);
}

static ssize_t observed_recv(int fd, void *p, size_t n, int flags)
{
    if (interrupt(fd == input_fd && flags == MSG_PEEK &&
                  ((fault == EMPTY_PEEK && n == 1u) ||
                   ((fault == FILTER_PEEK || fault == RAW_PEEK) && n > 1u))))
        return -1;
    return recv(fd, p, n, flags);
}

static int observed_ioctl(int fd, int request, void *p)
{
    require(request == FIONREAD, "uplink fixture observes only FIONREAD metadata");
    if (fd == input_fd && empty_metadata) {
        empty_metadata = 0;
        *(int *)p = 0;
        return 0; /* Bytes arrive after the first availability snapshot. */
    }
    if (interrupt(fd == input_fd && (fault == FIRST_IOCTL || fault == SECOND_IOCTL)))
        return -1;
    return ioctl(fd, FIONREAD, p);
}

static session *fixture(int lan[2], int node[2])
{
    session *s = calloc(1, sizeof *s);
    require(s != NULL && socketpair(AF_UNIX, SOCK_STREAM, 0, lan) == 0 &&
                socketpair(AF_UNIX, SOCK_STREAM, 0, node) == 0,
            "Vision I/O fixture owns two real stream socket pairs");
    for (unsigned i = 0; i < 2u; i++)
        require(lc_set_nonblocking(lan[i]) == 0 && lc_set_nonblocking(node[i]) == 0,
                "all fixture endpoints are nonblocking");
    s->st = ST_OPEN;
    s->lan_fd = lan[0];
    s->up_fd = node[0];
    s->pipe_rd = s->pipe_wr = -1;
    s->to_up = (queue){ .buf = s->to_up_buf, .cap = sizeof s->to_up_buf };
    s->to_lan = (queue){ .buf = s->to_lan_buf, .cap = sizeof s->to_lan_buf };
    s->use_vision = 1;
    s->vision.direct_out = 1;
    s->direct_in = 1;
    s->vless_header_seen = 1;
    s->rv_alloc = 4u;
    input_fd = lan[0];
    output_fd = node[0];
    output_attempts = injected = 0;
    return s;
}

static void release(session *s, int lan[2], int node[2])
{
    close(lan[0]); close(lan[1]);
    close(node[0]); close(node[1]);
    if (s->pipe_rd >= 0) close(s->pipe_rd);
    if (s->pipe_wr >= 0) close(s->pipe_wr);
    free(s);
    input_fd = output_fd = -1;
}

static void run_fault(int site, int error)
{
    int lan[2], node[2];
    fault = site;
    fault_errno = error;
    fault_left = site == CONTROL ? 0 : error == EINTR ? 2 : 1;
    empty_metadata = site == EMPTY_PEEK || site == SECOND_IOCTL;
    session *s = fixture(lan, node);
    if (site == FILTER_PEEK)
        s->vision.packets_to_filter = 4;
    if (site == SINGLE_DRAIN)
        s->rv_alloc = 1u;
    uint8_t sent[3u * READ_CHUNK + 37u], received[sizeof sent];
    size_t n = site == SINGLE_DRAIN ? READ_CHUNK : sizeof sent;
    for (size_t i = 0; i < n; i++)
        sent[i] = (uint8_t)(i % 251u);
    require(write(lan[1], sent, n) == (ssize_t)n, "fixture queues a complete known uplink payload");
    unsigned first_alloc = rv_current(s);
    int rc = stream_take(s);
    if (error != EINTR && site != CONTROL) {
        require(rc == -1 && injected == 1u && fault_left == 0,
                "a permanent syscall error still ends the uplink without retrying it");
    } else {
        require(rc == 1 && injected == (site == CONTROL ? 0u : 2u) && fault_left == 0,
                "the actual uplink resumes repeated EINTR without losing its MultiBuffer");
        require(s->up_n == 0u && s->up_left == 0u && q_pending(&s->to_up) == 0u &&
                    rv_current(s) == (first_alloc == 1u ? 2u : 8u) &&
                    output_attempts == (site == RAW_WRITE ? 3u : 1u),
                "interruption neither queues an unblocked Write nor repeats reader adaptation");
        require(read(node[1], received, n) == (ssize_t)n && memcmp(sent, received, n) == 0,
                "the peer receives exactly the original raw bytes in their original order");
        require(read(node[1], received, sizeof received) == -1 && errno == EAGAIN,
                "the uplink emits no duplicate bytes after retrying a syscall");
        require(shutdown(lan[1], SHUT_WR) == 0 && stream_take(s) == STREAM_EOF,
                "real client EOF remains EOF after the resumed transfer");
    }
    release(s, lan, node);
}

static void run_backpressure(int pipe_copy)
{
    int lan[2], node[2];
    fault = CONTROL;
    fault_left = empty_metadata = 0;
    session *s = fixture(lan, node);
    int small = 4096;
    require(setsockopt(node[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof small) == 0,
            "the node-facing socket has a bounded send buffer");
    if (pipe_copy) {
        int ends[2];
        require(pipe2(ends, O_NONBLOCK | O_CLOEXEC) == 0, "the direct downlink owns a real splice pipe");
        s->pipe_rd = ends[0];
        s->pipe_wr = ends[1];
    }
    uint8_t fill[4096];
    memset(fill, 'J', sizeof fill);
    size_t prefix = 0;
    for (;;) {
        ssize_t w = write(node[0], fill, sizeof fill);
        if (w < 0) {
            require(errno == EAGAIN, "real node write backpressure is EAGAIN");
            break;
        }
        require(w > 0 && prefix < 1024u * 1024u, "socket prefill stays bounded");
        prefix += (size_t)w;
    }
    uint8_t sent[3u * READ_CHUNK + 37u];
    for (size_t i = 0; i < sizeof sent; i++)
        sent[i] = (uint8_t)(i % 251u);
    require(write(lan[1], sent, sizeof sent) == (ssize_t)sizeof sent && stream_take(s) == 1 &&
                s->up_n > 0u && s->up_left > 0u && q_pending(&s->to_up) > 0u &&
                q_pending(&s->to_up) + s->up_left == sizeof sent,
            "a full uplink retains the exact remainder across the queue and client socket");
    lc_loop *loop = lc_loop_new(8);
    require(loop != NULL && lc_loop_add(loop, node[0], LC_EV_READ, &s->up_tag) == 0 &&
                session_rearm(loop, s) == 0,
            "the real session rearm keeps downlink readiness while the uplink is full");
    const char answer[] = "downlink while upload is blocked";
    require(write(node[1], answer, sizeof answer) == (ssize_t)sizeof answer,
            "the peer sends a response before consuming the blocked upload");
    lc_event events[8];
    int ready = lc_loop_wait(loop, events, 8, 1000), read_ready = 0;
    for (int i = 0; i < ready; i++)
        read_ready |= events[i].data == &s->up_tag && (events[i].events & LC_EV_READ) != 0u;
    char reply[sizeof answer];
    require(read_ready && direct_pump(s, 1) == 0 &&
                read(lan[1], reply, sizeof reply) == (ssize_t)sizeof reply &&
                memcmp(reply, answer, sizeof reply) == 0,
            "the real copy/splice downlink progresses independently of the blocked uplink");
    require(shutdown(node[1], SHUT_WR) == 0 && direct_pump(s, 1) == 0 && s->up_eof &&
                q_pending(&s->to_up) + s->up_left == sizeof sent,
            "downlink EOF preserves every already-accepted uplink byte");
    uint8_t *received = malloc(prefix + sizeof sent);
    require(received != NULL, "the bounded peer observation buffer is allocated");
    size_t got = 0;
    for (unsigned turn = 0; turn < 1024u && got < prefix + sizeof sent; turn++) {
        ssize_t n = read(node[1], received + got, prefix + sizeof sent - got);
        if (n > 0)
            got += (size_t)n;
        else
            require(n < 0 && errno == EAGAIN, "the open peer reader waits without inventing EOF");
        require(q_flush(&s->to_up, node[0]) == 0 &&
                    (s->up_n == 0u || stream_pump(s) == 0),
                "actual write readiness resumes the saved uplink without reframing");
    }
    int correct = got == prefix + sizeof sent && memcmp(received + prefix, sent, sizeof sent) == 0;
    for (size_t i = 0; correct && i < prefix; i++)
        correct = received[i] == 'J';
    require(correct && s->up_n == 0u && s->up_left == 0u && q_pending(&s->to_up) == 0u,
            "after backpressure clears the peer receives each queued/raw byte exactly once");
    free(received);
    lc_loop_free(loop);
    release(s, lan, node);
}

/* Snapshot after VisionReader has merged TLS input/rawInput into its returned
 * MultiBuffer. Those bytes must finish before the raw socket is read again. */
static void run_carry(unsigned mode)
{
    int lan[2], node[2];
    int pipe_copy = (mode & 1u) != 0u, blocked = (mode & 2u) != 0u;
    int fresh = (mode & 4u) != 0u;
    fault = CONTROL;
    fault_left = empty_metadata = 0;
    session *s = fixture(lan, node);
    int send_room = blocked ? 4096 : 256 * 1024;
    require(setsockopt(lan[0], SOL_SOCKET, SO_SNDBUF, &send_room, sizeof send_room) == 0,
            "carry fixture sets real client-side backpressure capacity");
    if (pipe_copy) {
        int ends[2];
        require(pipe2(ends, O_NONBLOCK | O_CLOEXEC) == 0, "carry fixture owns a real splice pipe");
        s->pipe_rd = ends[0];
        s->pipe_wr = ends[1];
    }
    uint8_t fill[4096];
    memset(fill, 'J', sizeof fill);
    size_t prefill = 0;
    if (blocked) {
        for (;;) {
            ssize_t n = write(lan[0], fill, sizeof fill);
            if (n < 0) {
                require(errno == EAGAIN, "carry fixture reaches actual client write EAGAIN");
                break;
            }
            require(n > 0 && prefill < 1024u * 1024u, "carry prefill stays bounded");
            prefill += (size_t)n;
        }
    }
    size_t queued = blocked ? READ_CHUNK : s->to_lan.cap - sizeof fill;
    memset(s->to_lan.buf, 'A', queued);
    s->to_lan.len = queued;
    size_t carry = (blocked ? 1u : 3u) * READ_CHUNK + 37u;
    s->rx = malloc(carry);
    require(s->rx != NULL, "carry fixture owns already-read rawInput bytes");
    s->rx_cap = s->rx_len = carry;
    for (size_t i = 0; i < carry; i++)
        s->rx[i] = (uint8_t)(i % 251u);
    size_t following = fresh ? 2048u : 0u;
    memset(fill, 'C', sizeof fill);
    if (fresh)
        require(write(node[1], fill, following) == (ssize_t)following &&
                    shutdown(node[1], SHUT_WR) == 0,
                "later raw bytes and FIN wait in the actual node socket");
    if ((mode & 8u) != 0u) {
        require(close(node[1]) == 0, "the peer fully closes while the older writer is blocked");
        node[1] = -1;
    }
    lc_loop *loop = lc_loop_new(8);
    require(loop != NULL && lc_loop_add(loop, node[0], LC_EV_READ, &s->up_tag) == 0,
            "carry fixture registers the real node descriptor");
    require(direct_pump(s, fresh) == 0 && session_rearm(loop, s) == 0,
            "the actual direct pump and rearm process the retained TLS tail");
    if (blocked) {
        int available = -1;
        require(ioctl(node[0], FIONREAD, &available) == 0 && available == (int)following &&
                    !s->up_eof && s->in_pipe == 0u && q_pending(&s->to_lan) > 0u,
                "blocked older bytes prevent both copy and splice from reading later data or FIN");
        lc_event events[8];
        require(lc_loop_wait(loop, events, 8, 0) == 0,
                "unconsumable raw readiness cannot spin while the client writer is blocked");
        if (node[1] >= 0) {
            const uint8_t upload = 'U';
            require(q_push(&s->to_up, &upload, 1u) == 0 && session_rearm(loop, s) == 0,
                    "a pending uplink writer resumes its node watch despite the blocked downlink");
            int n = lc_loop_wait(loop, events, 8, 1000), writable = 0;
            for (int i = 0; i < n; i++)
                writable |= events[i].data == &s->up_tag && (events[i].events & LC_EV_WRITE) != 0u;
            uint8_t got_upload;
            require(writable && q_flush(&s->to_up, node[0]) == 0 &&
                        read(node[1], &got_upload, 1u) == 1 && got_upload == upload &&
                        session_rearm(loop, s) == 0 && lc_loop_wait(loop, events, 8, 0) == 0,
                    "uplink bytes reach the peer and the idle node reader pauses again without a spin");
        }
    } else {
        require(s->rx_len == 0u && q_pending(&s->to_lan) == 0u && s->in_pipe == 0u,
                "a successful Flush cannot strand an older tail without another socket event");
    }
    size_t total = prefill + queued + carry + following;
    uint8_t *received = malloc(total);
    require(received != NULL, "carry peer observation stays bounded");
    size_t got = 0;
    for (unsigned turn = 0; turn < 2048u && got < total; turn++) {
        ssize_t n = read(lan[1], received + got, total - got);
        if (n > 0)
            got += (size_t)n;
        else
            require(blocked && n < 0 && errno == EAGAIN,
                    "only actual backpressure may require another carry writer turn");
        if (blocked)
            require(q_flush(&s->to_lan, lan[0]) == 0 && direct_pump(s, fresh) == 0 &&
                        session_rearm(loop, s) == 0,
                    "client drain resumes the same carry before later raw data");
    }
    int correct = got == total;
    for (size_t i = 0; correct && i < total; i++) {
        uint8_t expected;
        if (i < prefill) expected = 'J';
        else if (i < prefill + queued) expected = 'A';
        else if (i < prefill + queued + carry) expected = (uint8_t)((i - prefill - queued) % 251u);
        else expected = 'C';
        correct = received[i] == expected;
    }
    require(correct && s->rx_len == 0u && q_pending(&s->to_lan) == 0u && s->in_pipe == 0u,
            "the peer receives prefill, older data, the full TLS tail and fresh bytes exactly in order");
    if (fresh)
        require(direct_pump(s, 1) == 0 && s->up_eof && session_rearm(loop, s) == 0 &&
                    lc_loop_wait(loop, (lc_event[8]){{0}}, 8, 0) == 0,
                "consumed node EOF leaves no idle HUP watch while the other direction can remain open");
    free(received);
    free(s->rx);
    s->rx = NULL;
    lc_loop_free(loop);
    release(s, lan, node);
}

static void run_first_read(int error, size_t n, int fin)
{
    int lan[2], node[2];
    session *s = fixture(lan, node);
    close(lan[0]); close(lan[1]);
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t length = sizeof address;
    require(listener >= 0 && bind(listener, (struct sockaddr *)&address, length) == 0 &&
                listen(listener, 1) == 0 && getsockname(listener, (struct sockaddr *)&address, &length) == 0,
            "first-read owns a real loopback TCP listener");
    lan[1] = socket(AF_INET, SOCK_STREAM, 0);
    require(lan[1] >= 0 && connect(lan[1], (struct sockaddr *)&address, length) == 0 &&
                (lan[0] = accept(listener, NULL, NULL)) >= 0,
            "first-read has connected TCP endpoints");
    close(listener);
    require(lc_set_nonblocking(lan[0]) == 0 && lc_set_nonblocking(lan[1]) == 0,
            "first-read endpoints remain nonblocking");
    input_fd = s->lan_fd = lan[0];
    s->rv_alloc = 1u;
    lc_loop *loop = lc_loop_new(2u);
    require(loop != NULL && lc_loop_add(loop, lan[0], LC_EV_READ, s) == 0,
            "first-read uses the real epoll watch");
    uint8_t payload[READ_CHUNK], received[READ_CHUNK];
    for (size_t i = 0; i < n; i++) payload[i] = (uint8_t)(i % 251u);
    require(n == 0u || write(lan[1], payload, n) == (ssize_t)n, "first-read queues a known payload");
    if (fin == 1)
        require(shutdown(lan[1], SHUT_WR) == 0, "peer can half-close after its data");
    if (fin == 2) {
        struct linger reset = { .l_onoff = 1, .l_linger = 0 };
        require(setsockopt(lan[1], SOL_SOCKET, SO_LINGER, &reset, sizeof reset) == 0 && close(lan[1]) == 0,
                "peer resets the real TCP connection after its data");
        lan[1] = -1;
    }
    lc_event event;
    require(lc_loop_wait(loop, &event, 1u, 1000) == 1 && event.data == s &&
                (event.events & LC_EV_READ) && (fin != 2 || (event.events & LC_EV_ERROR)),
            "actual TCP readiness preserves queued data alongside reset or half-close");
    fault = FIRST_READ;
    fault_errno = error;
    fault_left = error == EINTR ? 2 : error == 0 ? 0 : 1;
    injected = 0;
    uint64_t calls = stats.reads_lan;
    ssize_t got = stream_read_first(s, received);
    int saved_errno = errno;
    if (error == 0 || error == EINTR) {
        require(got == (ssize_t)n && memcmp(payload, received, n) == 0,
                "first read retries interruption and delivers the queued bytes or real EOF");
        require(stats.reads_lan - calls == (error == EINTR ? 3u : 1u),
                "only interrupted syscalls are repeated and counted");
        require(!lc_ev_finished(event.events, lc_read_classify(got, saved_errno)) || n == 0u,
                "a simultaneous hangup does not discard the successful read");
    } else {
        require(got == -1 && saved_errno == error && stats.reads_lan - calls == 1u,
                "first read does not retry readiness or permanent errors");
        fault = CONTROL;
        require(read(lan[0], received, sizeof received) == (ssize_t)n && memcmp(payload, received, n) == 0,
                "a failed read did not consume or rewrite the queued payload");
    }
    require(rv_current(s) == 1u && s->up_left == 0u && q_pending(&s->to_up) == 0u,
            "read retries do not adapt or frame the stream before successful delivery");
    lc_loop_free(loop);
    release(s, lan, node);
}

static void first_reads(void)
{
    run_first_read(0, 37u, 2);
    run_first_read(EINTR, 37u, 2);
    run_first_read(EINTR, READ_CHUNK, 2);
    run_first_read(EINTR, 37u, 1);
    run_first_read(EINTR, 0u, 1);
    run_first_read(EINTR, 37u, 0);
    run_first_read(EAGAIN, 37u, 0);
    run_first_read(EIO, 37u, 2);
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--first-read") == 0) {
        first_reads();
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--carry") == 0) {
        unsigned mode = (unsigned)atoi(argv[2]);
        require(mode < 16u, "the selected carry scenario is valid");
        run_carry(mode);
        return 0;
    }
    if (argc == 2) {
        int site = atoi(argv[1]);
        require(site >= FIRST_IOCTL && site <= ZERO_WRITE, "the selected syscall fault site is valid");
        run_fault(site, site == ZERO_WRITE ? 0 : EINTR);
        return 0;
    }
    require(argc == 1, "expected no arguments or an interruption-site number");
    run_fault(CONTROL, EINTR);
    for (int site = FIRST_IOCTL; site <= SINGLE_DRAIN; site++) {
        run_fault(site, EINTR);
        run_fault(site, EIO);
    }
    run_fault(ZERO_WRITE, 0);
    run_backpressure(0);
    run_backpressure(1);
    for (unsigned mode = 0; mode < 8u; mode++)
        run_carry(mode);
    run_carry(14u);
    run_carry(15u);
    first_reads();
    return 0;
}
