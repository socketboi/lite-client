/* Real TCP/epoll recovery after EMFILE, with only ADD failures and time controlled. */
#include "net/loop.h"
#include "net/sock.h"
#include <fcntl.h>
#include <sys/resource.h>

static int observed_loop_add(lc_loop *loop, int fd, unsigned events, void *data);
static uint64_t observed_now(void);
#define lc_loop_add observed_loop_add
#define lc_now_ms observed_now
#define main lc_tunnel_program_main
#include "../../src/cmd/lc-tunnel/main.c"
#undef main
#undef lc_now_ms
#undef lc_loop_add

static uint64_t test_now;
static int watched_fd = -1, failed_adds, add_errno;
static unsigned add_calls, last_events;

static uint64_t observed_now(void)
{
    return test_now;
}

static int observed_loop_add(lc_loop *loop, int fd, unsigned events, void *data)
{
    if (fd == watched_fd) {
        add_calls++;
        last_events = events;
        if (failed_adds != 0) {
            failed_adds--;
            errno = add_errno;
            return -1;
        }
    }
    return lc_loop_add(loop, fd, events, data);
}

static void require(int yes, const char *message)
{
    if (!yes) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
    printf("  ok    %s\n", message);
}

static void run_case(int shared, int fault)
{
    lc_loop *loop = lc_loop_new(8);
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int active[2] = {-1, -1};
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t address_len = sizeof address;
    require(loop != NULL && listener >= 0 &&
                bind(listener, (struct sockaddr *)&address, sizeof address) == 0 &&
                listen(listener, 8) == 0 && lc_set_nonblocking(listener) == 0 &&
                getsockname(listener, (struct sockaddr *)&address, &address_len) == 0,
            "listener fixture binds a real nonblocking loopback TCP listener");
    require(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, active) == 0 &&
                lc_set_nonblocking(active[0]) == 0,
            "listener fixture retains a separate established connection");
    int active_tag;
    unsigned mask = LC_EV_READ | (shared ? LC_EV_EXCLUSIVE : 0u);
    watched_fd = listener;
    failed_adds = 0;
    add_calls = 0;
    listen_resume_at = 0;
    listen_resume_failed = 0;
    test_now = 1000u;
    require(lc_loop_add(loop, listener, mask, NULL) == 0 &&
                lc_loop_add(loop, active[0], LC_EV_READ, &active_tag) == 0,
            "listener and established connection have real epoll registrations");
    errno = EAGAIN;
    require(accept_exhausted(loop, listener) == 0 && listen_resume_at == 0u,
            "an ordinary empty accept queue does not suspend the listener");
    int client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    require(client >= 0 && connect(client, (struct sockaddr *)&address, sizeof address) == 0,
            "a real TCP handshake queues a connection before descriptor exhaustion");

    struct rlimit original, limited;
    require(getrlimit(RLIMIT_NOFILE, &original) == 0, "listener fixture records its descriptor limit");
    limited = original;
    if (limited.rlim_cur > 64u)
        limited.rlim_cur = 64u;
    require(setrlimit(RLIMIT_NOFILE, &limited) == 0,
            "descriptor exhaustion is bounded to this test process");
    int held[64];
    unsigned count = 0;
    while (count < sizeof held / sizeof held[0]) {
        int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            break;
        held[count++] = fd;
    }
    int accepted = accept4(listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    require(accepted == -1 && errno == EMFILE, "the actual pending TCP accept fails with EMFILE");
    errno = EMFILE;
    require(accept_exhausted(loop, listener) == 1 && listen_resume_at == 1500u,
            "EMFILE suspends only the listener for the reference's 500 ms retry");
    for (unsigned i = 0; i < count; i++)
        close(held[i]);
    require(setrlimit(RLIMIT_NOFILE, &original) == 0,
            "the fixture restores its original descriptor budget before retrying");

    require(write(active[1], "a", 1) == 1,
            "an established connection still receives bytes during listener suspension");
    lc_event event[8];
    char byte;
    require(lc_loop_wait(loop, event, 8, 0) == 1 && event[0].data == &active_tag &&
                read(active[0], &byte, 1) == 1 && byte == 'a',
            "suspension preserves established-session readiness without a listener spin");
    failed_adds = 2;
    add_errno = fault;
    unsigned before = add_calls;
    test_now = 1499u;
    accept_resume(loop, listener, shared, test_now);
    require(add_calls == before && hy_wait(1000) == 1,
            "the event loop sleeps until the due retry instead of registering early");
    for (unsigned attempt = 0; attempt < 2u; attempt++) {
        test_now = listen_resume_at;
        accept_resume(loop, listener, shared, test_now);
        require(add_calls == before + attempt + 1u && listen_resume_at == test_now + 500u &&
                    listen_resume_failed && hy_wait(1000) == 500 && hy_wait(25) == 25,
                "a failed epoll ADD retains a bounded retry and the earlier event-loop deadlines");
        for (unsigned repeat = 0; repeat < 10u; repeat++)
            accept_resume(loop, listener, shared, test_now);
        require(add_calls == before + attempt + 1u && lc_loop_wait(loop, event, 8, 0) == 0,
                "repeated loop turns neither retry early nor consume the queued TCP connection");
        require(write(active[1], "b", 1) == 1 && lc_loop_wait(loop, event, 8, 0) == 1 &&
                    event[0].data == &active_tag && read(active[0], &byte, 1) == 1 && byte == 'b',
                "established traffic continues through repeated listener-registration failures");
    }
    test_now = listen_resume_at;
    accept_resume(loop, listener, shared, test_now);
    require(add_calls == before + 3u && last_events == mask && listen_resume_at == 0u &&
                !listen_resume_failed && lc_loop_wait(loop, event, 8, 0) == 1 && event[0].data == NULL,
            "successful ADD restores the original exclusive/read mask and queued listener readiness");
    accepted = accept4(listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    require(accepted >= 0 && write(client, "q", 1) == 1 && read(accepted, &byte, 1) == 1 &&
                byte == 'q' && write(accepted, "r", 1) == 1 && read(client, &byte, 1) == 1 && byte == 'r',
            "the original queued TCP connection carries both directions after recovery");
    before = add_calls;
    accept_resume(loop, listener, shared, test_now + 1000u);
    require(add_calls == before && hy_wait(1000) == 1000,
            "successful recovery clears the retry without duplicate epoll ADD or a stale timer");
    close(accepted);
    close(client);
    close(active[0]);
    close(active[1]);
    close(listener);
    lc_loop_free(loop);
    watched_fd = -1;
}

int main(void)
{
    for (int shared = 0; shared < 2; shared++) {
        run_case(shared, ENOMEM);
        run_case(shared, ENOSPC);
    }
    return 0;
}
