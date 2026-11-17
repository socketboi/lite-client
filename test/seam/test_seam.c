/* What the PROGRAM does, checked on the real binary — not what a library decides when asked nicely.
 *
 * Two things live here, found a few hours apart and by the same means: reading a router, not running
 * a suite. The alert a refused handshake owes (below), and the log four workers write down one pipe
 * (at the foot of the file). Both were seams — correct pieces, missing wiring — and both were
 * invisible to every unit suite in this tree, which is the reason the file exists.
 *
 * ⚠️ THIS SUITE EXISTS BECAUSE EVERY OTHER ONE PASSED WHILE THE ANSWER WAS NO. tls/client.c picks
 * an alert for every way a handshake can be refused, with the reference cited for each; lc-tunnel
 * drives that machine from an event loop and, until 2026-08-26, never asked for the result. The
 * alert was chosen, written into a struct, and freed with it. Nothing went red: the unit suites end
 * at "the right alert is pending", and the one binary checked on hardware was lc-probe, which
 * reaches the wire through a different function and would have looked correct either way.
 *
 * So the thing under test here is a SEAM, and a seam is only visible from outside both sides of it.
 * That is why this runs the real binary against a real socket instead of calling anything: a test
 * that called lc_client_hs_alert_record would pass on the broken tree, which is exactly what the
 * broken tree did.
 *
 * The peer answers our ClientHello with EncryptedExtensions where a ServerHello belongs — refused
 * with unexpected_message (vendor/utls/handshake_client.go:313-317). Expected back: seven bytes,
 * 15 03 01 00 02 02 0a, in the clear, before any key exists.
 *
 * Everything here is bounded by a deadline and nothing blocks forever: a suite that hangs is worse
 * than one that fails, because it stops the gate rather than reporting on it. */

/* _GNU_SOURCE comes from TEST_CFLAGS; defining it here as well is a redefinition and -Werror. */
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef LC_TEST_TUNNEL
#error "LC_TEST_TUNNEL must name the binary built for this test"
#endif

static int failures;

static void expect(int cond, const char *what)
{
    printf(cond ? "  ok    %s\n" : "  FAIL  %s\n", what);
    if (!cond)
        failures++;
}

/* A listening socket on a port the kernel picks, so two gates on one machine cannot collide. */
static int listen_any(unsigned short *port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    a.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0 || listen(fd, 4) != 0) {
        close(fd);
        return -1;
    }
    socklen_t len = sizeof a;
    if (getsockname(fd, (struct sockaddr *)&a, &len) != 0) {
        close(fd);
        return -1;
    }
    *port = ntohs(a.sin_port);
    return fd;
}

/* Waits for readability. Returns 1 ready, 0 timed out, -1 error. */
static int wait_readable(int fd, int ms)
{
    struct pollfd p;
    p.fd = fd;
    p.events = POLLIN;
    for (;;) {
        int rc = poll(&p, 1, ms);
        if (rc < 0 && errno == EINTR)
            continue;
        return rc < 0 ? -1 : (rc == 0 ? 0 : 1);
    }
}

/* Connects to the tunnel's LAN port, retrying while it comes up. */
static int connect_lan(unsigned short port, int tries)
{
    for (int i = 0; i < tries; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
            return -1;
        struct sockaddr_in t;
        memset(&t, 0, sizeof t);
        t.sin_family = AF_INET;
        t.sin_addr.s_addr = inet_addr("127.0.0.1");
        t.sin_port = htons(port);
        if (connect(fd, (struct sockaddr *)&t, sizeof t) == 0)
            return fd;
        close(fd);
        usleep(200000);
    }
    return -1;
}

/* ---- the log four processes write down one pipe -------------------------------------------------
 *
 * ⚠️ THE SECOND SEAM OF THE SAME DAY, and it was found in a router's log rather than by any suite
 * here. procd gives an instance ONE pipe for stdout and hands the same descriptor to every fork of
 * it, so the workers are four writers on one file. A summary printed by all four at the same
 * millisecond came out shredded: a prefix alone on its line, a body with no prefix, two workers'
 * sentences spliced together, and tears inside a single line between a format's literal runs and
 * its conversions. Every unit suite was green throughout, because a log line is not a return value.
 *
 * ⚠️ AND THIS CHECK DOES NOT REPRODUCE IT, WHICH IS SAID HERE RATHER THAN HOPED PAST. It was written
 * to, and it went green on the broken code — on the host AND on the router. Chased down rather than
 * shrugged at, and the answer is that the tearing needs procd:
 *
 *   - the broken binary writing to a FILE, four workers, all four summaries: 56 lines, 0 torn;
 *   - the same binary writing to a pipe read by this suite, including with the pipe shrunk to one
 *     page and the reader starved so it stayed full: 0 torn — a full pipe SERIALISES the writers,
 *     so starving the reader hides the fault instead of causing it;
 *   - the same binary started by procd, dumping on SIGUSR1: 20 of 44 records torn;
 *   - the FIXED binary, same procd service, same signal: 44 records, 0 torn.
 *
 * Not the log daemon either: 240 messages from four concurrent `logger` processes all arrived whole.
 * On the host the question does not even arise — glibc's line buffering puts each line on the pipe
 * in one write, so the old code was correct there and no host gate can ever go red for this.
 *
 * To run the reproduction, put the binary under procd — a five-line /etc/init.d with `procd_set_param
 * stdout 1`, four workers — and `kill -USR1` all four at once.
 *
 * What is left here is still worth its place, but it is worth exactly this much: four workers really
 * start under one supervisor, each really produces a whole summary, and every line carries the stamp
 * note() owes it. That much would catch a lost prefix or a supervisor that stopped forking. */

/* The workers, by asking the kernel who the child's children are. Reading /proc/N/stat rather than
 * /proc/N/task/N/children because the latter needs a config option this suite has no way to require.
 * The comm field can hold spaces and parentheses, so ppid is read after the LAST ')'. */
static int children_of(pid_t parent, pid_t *out, int max)
{
    DIR *d = opendir("/proc");
    if (d == NULL)
        return 0;

    int            n = 0;
    struct dirent *e;
    while (n < max && (e = readdir(d)) != NULL) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9')
            continue;

        char path[300]; /* d_name is bounded by NAME_MAX, and -Werror=format-truncation counts it */
        snprintf(path, sizeof path, "/proc/%s/stat", e->d_name);
        FILE *f = fopen(path, "r");
        if (f == NULL)
            continue;
        char buf[512];
        size_t got = fread(buf, 1, sizeof buf - 1, f);
        fclose(f);
        buf[got] = '\0';

        char *close_paren = strrchr(buf, ')');
        if (close_paren == NULL)
            continue;
        int ppid = 0;
        if (sscanf(close_paren + 1, " %*c %d", &ppid) == 1 && ppid == (int)parent)
            out[n++] = (pid_t)atoi(e->d_name);
    }
    closedir(d);
    return n;
}

/* ---- the counter that tells a refusal from a hang ----------------------------------------------
 *
 * ⚠️ A SEAM, AND THE SAME KIND AS THE TWO ABOVE: `dial_failed` was added on 2026-08-28 because the
 * summary could not tell a node refusing every dial instantly from a node answering perfectly —
 * `gave_up_connecting` is incremented in ONE place, the deadline sweep, so it counts hangs and
 * nothing else, and a connect returning ECONNREFUSED was counted nowhere at all. A counter added to
 * make a distinction is worthless until something checks it makes it, and nothing did.
 *
 * The refused half is the half a gate can afford: a port bound and closed refuses instantly, while
 * the hang half would cost CONNECT_ATTEMPT_MS — sixteen seconds — for one assertion. So this asserts the
 * pair that matters and can be had in milliseconds: `dials failed outright` moves, and
 * `while connecting` stays at zero, because a refusal is not a timeout. Getting either wrong is
 * what the counter exists to prevent.
 *
 * One worker rather than four: the distinction is per-process arithmetic and needs no crowd. */
static void refused_dial_is_counted(void)
{
    printf("\nthe counter that tells a refused dial from a hung one\n");

    int fds[2];
    if (pipe(fds) != 0) {
        expect(0, "a pipe for the tunnel's log");
        return;
    }
    unsigned short lan_port = 0, dead_port = 0;
    int            probe = listen_any(&lan_port);
    if (probe >= 0)
        close(probe);
    probe = listen_any(&dead_port);
    if (probe >= 0)
        close(probe); /* bound and released: a connect here is refused at once, not dropped */

    char lan_s[16], dead_s[16];
    snprintf(lan_s, sizeof lan_s, "%u", (unsigned)lan_port);
    snprintf(dead_s, sizeof dead_s, "%u", (unsigned)dead_port);

    pid_t tun = fork();
    if (tun == 0) {
        (void)dup2(fds[1], 1);
        (void)dup2(fds[1], 2);
        close(fds[0]);
        close(fds[1]);
        execl(LC_TEST_TUNNEL, "lc-tunnel", "package/files/fingerprint.fpt", "127.0.0.1", dead_s,
              "www.example.com", "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo", "0123abcd",
              "00000000-0000-4000-8000-000000000001", lan_s, "-t", "1.1.1.1:80", "-w", "1",
              (char *)NULL);
        _exit(127);
    }
    close(fds[1]);
    expect(tun > 0, "the tunnel forks with one worker");

    /* ⚠️ ONE WORKER MEANS NO CHILD, and assuming otherwise is what the first version of this did:
     * it waited for a fork that never comes and then signalled an empty list, so no summary was
     * ever printed and the check reported the wrong thing about a working counter. With `-w 1` the
     * process that runs the loop IS the process that was started. */
    pid_t kids[16];
    int   found = children_of(tun, kids, 16);
    if (found < 1) {
        kids[0] = tun;
        found = 1;
    }

    int lan = connect_lan(lan_port, 25);
    expect(lan >= 0, "a client reaches the tunnel, which dials a port nothing listens on");
    /* The refusal happens on the loop's next turn; the pause is a floor, not the bound. What
     * bounds this is the read below, which leaves as soon as the pipe goes quiet. */
    usleep(300000);
    for (int i = 0; i < found; i++)
        (void)kill(kids[i], SIGUSR1);

    static char text[65536];
    size_t      have = 0;
    while (have < sizeof text - 1) {
        if (wait_readable(fds[0], 1500) != 1)
            break;
        ssize_t got = read(fds[0], text + have, sizeof text - 1 - have);
        if (got <= 0)
            break;
        have += (size_t)got;
    }
    text[have] = '\0';

    const char *line = strstr(text, "gave up: ");
    expect(line != NULL, "the summary reports what it gave up on");
    if (line != NULL) {
        char one[512];
        size_t n = strcspn(line, "\n");
        if (n >= sizeof one)
            n = sizeof one - 1;
        memcpy(one, line, n);
        one[n] = '\0';
        expect(strstr(one, "0 while connecting") != NULL,
               "with nothing given up while connecting, because a refusal is not a timeout");
        expect(strstr(one, "dials failed outright") != NULL &&
                   strstr(one, "0 dials failed outright") == NULL,
               "and the refused dial counted where refusals are counted");
        if (strstr(one, "0 dials failed outright") != NULL ||
            strstr(one, "0 while connecting") == NULL)
            printf("        %s\n", one);
    }
    expect(strstr(text, "cannot reach the node") != NULL,
           "and the line that says so names the node rather than the client");

    /* And no pool, because nothing asked for one: `testpre` is a Go zero value in the reference, so
     * a client started without -P dials for every request itself and keeps nothing ahead of need. */
    const char *warm = strstr(text, "warm tunnels: ");
    expect(warm != NULL && strncmp(warm, "warm tunnels: 0 dialled", 23) == 0,
           "and without -P the pool dials nothing, as the reference's is off by default");

    if (lan >= 0)
        close(lan);
    close(fds[0]);
    if (tun > 0) {
        kill(tun, SIGTERM);
        int st = 0;
        (void)waitpid(tun, &st, 0);
    }
}

/* ---- a failed dial is dialled again, as often and as slowly as the reference dials ---------------
 *
 * Xray's VLESS outbound wraps the whole dial — connect and handshake — in
 * `retry.ExponentialBackoff(5, 200)`, whose waits are 0, 200, 400, 600 and, after the fifth failure,
 * 800 ms before the request fails (vendor/Xray-core/common/retry/retry.go). Held here from outside
 * against the shipped binary, with a stand-in node that accepts every connection and closes it at once
 * — a handshake the node ended, which is a dial error like any other.
 *
 * What is checked is what the node and the client can see: exactly five connections arrive, the gaps
 * between them grow by about 200 ms each, and the client's connection stays open until about 800 ms
 * after the fifth. Tolerances are wide on purpose: the question is the shape, and a loaded machine
 * stretches every gap by the same few milliseconds. */
static double mono_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1000.0 + (double)t.tv_nsec / 1e6;
}

static void failed_dials_are_retried(void)
{
    printf("\nfive dials for one request, with the reference's waits between them\n");

    unsigned short node_port = 0, lan_port = 0;
    int            node_fd = listen_any(&node_port);
    int            probe = listen_any(&lan_port);
    if (probe >= 0)
        close(probe);
    expect(node_fd >= 0 && probe >= 0, "a stand-in node and a port for the tunnel");
    if (node_fd < 0)
        return;

    char node_s[16], lan_s[16];
    snprintf(node_s, sizeof node_s, "%u", (unsigned)node_port);
    snprintf(lan_s, sizeof lan_s, "%u", (unsigned)lan_port);

    pid_t tun = fork();
    if (tun == 0) {
        int null_fd = open("/dev/null", O_WRONLY);
        if (null_fd >= 0) {
            (void)dup2(null_fd, 1);
            (void)dup2(null_fd, 2);
        }
        execl(LC_TEST_TUNNEL, "lc-tunnel", "package/files/fingerprint.fpt", "127.0.0.1", node_s,
              "www.example.com", "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo", "0123abcd",
              "00000000-0000-4000-8000-000000000001", lan_s, "-t", "1.1.1.1:80", "-w", "1",
              (char *)NULL);
        _exit(127);
    }

    int lan = connect_lan(lan_port, 25);
    expect(lan >= 0, "a client reaches the tunnel");

    double at[8];
    int    seen = 0;
    double closed_at = 0;
    double start = mono_ms();
    while (lan >= 0 && mono_ms() - start < 6000.0) {
        struct pollfd p[2] = { { node_fd, POLLIN, 0 }, { lan, POLLIN, 0 } };
        if (poll(p, 2, 100) <= 0)
            continue;
        if (p[0].revents & POLLIN) {
            int c = accept(node_fd, NULL, NULL);
            if (c >= 0) {
                if (seen < 8)
                    at[seen] = mono_ms();
                seen++;
                close(c);
            }
        }
        if (p[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            char b[64];
            if (read(lan, b, sizeof b) <= 0) {
                closed_at = mono_ms();
                break;
            }
        }
    }

    expect(seen == 5, "the node sees exactly five connections for the one request");
    if (seen != 5)
        printf("        %d connections\n", seen);
    if (seen == 5) {
        static const double want[] = { 0.0, 200.0, 400.0, 600.0 };
        int shaped = 1;
        for (int k = 0; k < 4; k++) {
            double gap = at[k + 1] - at[k];
            if (gap < want[k] - 20.0 || gap > want[k] + 150.0)
                shaped = 0;
        }
        expect(shaped, "and the waits between them grow 0, 200, 400, 600 ms");
        if (!shaped)
            printf("        gaps %.0f %.0f %.0f %.0f ms\n", at[1] - at[0], at[2] - at[1],
                   at[3] - at[2], at[4] - at[3]);
        double tail = closed_at > 0 ? closed_at - at[4] : -1.0;
        expect(tail >= 780.0 && tail <= 950.0,
               "and the client's connection closes about 800 ms after the fifth, not before");
        if (!(tail >= 780.0 && tail <= 950.0))
            printf("        closed %.0f ms after the fifth\n", tail);
    }

    if (lan >= 0)
        close(lan);
    close(node_fd);
    if (tun > 0) {
        kill(tun, SIGTERM);
        int st = 0;
        (void)waitpid(tun, &st, 0);
    }
}

/* ---- the pool is Xray's testpre --------------------------------------------------------------
 *
 * Two things the reference's pool does that this client's used not to, both visible to the node and
 * both held here from the outside, against the shipped binary: nothing is dialled until the first
 * request (`h.initpre.Do` inside Process), and with the pool on a request takes a pooled connection
 * instead of dialling for itself — the only dial the node sees is the pool's. The stand-in node
 * accepts and says nothing, so that one dial stays in the air for the whole check. */
static void pool_starts_with_the_first_request(void)
{
    printf("\nthe pool, which starts with the first request and serves every request\n");

    int fds[2];
    if (pipe(fds) != 0) {
        expect(0, "a pipe for the tunnel's log");
        return;
    }
    unsigned short node_port = 0, lan_port = 0;
    int            node_fd = listen_any(&node_port);
    int            probe = listen_any(&lan_port);
    if (probe >= 0)
        close(probe);
    expect(node_fd >= 0 && probe >= 0, "a silent stand-in node, and a port for the tunnel");
    if (node_fd < 0) {
        close(fds[0]);
        close(fds[1]);
        return;
    }

    char node_s[16], lan_s[16];
    snprintf(node_s, sizeof node_s, "%u", (unsigned)node_port);
    snprintf(lan_s, sizeof lan_s, "%u", (unsigned)lan_port);

    pid_t tun = fork();
    if (tun == 0) {
        (void)dup2(fds[1], 1);
        (void)dup2(fds[1], 2);
        close(fds[0]);
        close(fds[1]);
        execl(LC_TEST_TUNNEL, "lc-tunnel", "package/files/fingerprint.fpt", "127.0.0.1", node_s,
              "www.example.com", "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo", "0123abcd",
              "00000000-0000-4000-8000-000000000001", lan_s, "-t", "1.1.1.1:80", "-w", "1", "-P",
              "1", (char *)NULL);
        _exit(127);
    }
    close(fds[1]);
    expect(tun > 0, "the tunnel forks with one worker and -P 1");

    /* Up and listening first, from its own line, so that the quiet below is a tunnel choosing not to
     * dial rather than one that has not started yet. */
    static char text[8192];
    size_t      have = 0;
    while (have < sizeof text - 1 && strstr(text, "listening on") == NULL) {
        if (wait_readable(fds[0], 5000) != 1)
            break;
        ssize_t got = read(fds[0], text + have, sizeof text - 1 - have);
        if (got <= 0)
            break;
        have += (size_t)got;
        text[have] = '\0';
    }
    expect(strstr(text, "listening on") != NULL, "the tunnel says it is listening");

    /* Longer than one idle turn of the loop (a second), which is the soonest a pool started at
     * startup would dial: waiting less than that once let exactly that mutant through. */
    expect(wait_readable(node_fd, 1500) != 1,
           "and dials nothing before the first request, as the reference dials nothing before Process");

    int lan = connect_lan(lan_port, 25);
    expect(lan >= 0, "a client arrives");
    int up = -1;
    if (lan >= 0 && wait_readable(node_fd, 8000) == 1)
        up = accept(node_fd, NULL, NULL);
    expect(up >= 0, "which starts the pool, and the pool's dial reaches the node");
    expect(up >= 0 && wait_readable(node_fd, 700) != 1,
           "and that is the only dial: the request waits for a pooled connection, it does not dial");

    if (lan >= 0)
        close(lan);
    if (up >= 0)
        close(up);
    close(node_fd);
    close(fds[0]);
    if (tun > 0) {
        kill(tun, SIGTERM);
        int st = 0;
        (void)waitpid(tun, &st, 0);
    }
}

/* ⚠️ AND THE POOL'S LINE HAS TO ADD UP, which is a defect this tree has already paid for: a pooled
 * connection that died before becoming available once fell through every counter, and the line
 * printed "3 dialled, 0 used, 0 expired unused, 0 closed by the node" on a live router — every number
 * right and together a lie. Used, expired and never opened are exhaustive, so they sum to what was
 * dialled, less the at most -P connections still in the pool at the moment the summary is taken.
 *
 * Against a port that refuses, every dial fails at once and the reference's dialler dials again with
 * no pause at all (vless/outbound/outbound.go:165-168), so the count climbs and the log fills fast: this reads the
 * pipe continuously and keeps only its tail, because a tunnel whose pipe is full stops. */
static void pool_accounts_for_every_dial(void)
{
    printf("\nthe pool against a node that refuses\n");

    int fds[2];
    if (pipe(fds) != 0) {
        expect(0, "a pipe for the tunnel's log");
        return;
    }
    unsigned short lan_port = 0, dead_port = 0;
    int            probe = listen_any(&lan_port);
    if (probe >= 0)
        close(probe);
    probe = listen_any(&dead_port);
    if (probe >= 0)
        close(probe);

    char lan_s[16], dead_s[16];
    snprintf(lan_s, sizeof lan_s, "%u", (unsigned)lan_port);
    snprintf(dead_s, sizeof dead_s, "%u", (unsigned)dead_port);

    pid_t tun = fork();
    if (tun == 0) {
        (void)dup2(fds[1], 1);
        (void)dup2(fds[1], 2);
        close(fds[0]);
        close(fds[1]);
        execl(LC_TEST_TUNNEL, "lc-tunnel", "package/files/fingerprint.fpt", "127.0.0.1", dead_s,
              "www.example.com", "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo", "0123abcd",
              "00000000-0000-4000-8000-000000000001", lan_s, "-t", "1.1.1.1:80", "-w", "1", "-P",
              "1", (char *)NULL);
        _exit(127);
    }
    close(fds[1]);
    expect(tun > 0, "the tunnel forks with one worker and -P 1");

    int lan = connect_lan(lan_port, 25);
    expect(lan >= 0, "a client arrives and starts the pool");

    static char buf[262144];
    size_t      have = 0;
    const char *warm = NULL, *gave = NULL;
    int         signalled = 0;
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        struct timespec t;
        clock_gettime(CLOCK_MONOTONIC, &t);
        int64_t ms = (t.tv_sec - t0.tv_sec) * 1000L + (t.tv_nsec - t0.tv_nsec) / 1000000L;
        if (ms > 8000)
            break;
        if (signalled == 0 && ms > 300 && tun > 0) {
            (void)kill(tun, SIGUSR1);
            signalled = 1;
        }
        if (wait_readable(fds[0], 200) != 1)
            continue;
        if (have > sizeof buf / 2) {
            memmove(buf, buf + have - sizeof buf / 4, sizeof buf / 4);
            have = sizeof buf / 4;
        }
        ssize_t got = read(fds[0], buf + have, sizeof buf - 1 - have);
        if (got <= 0)
            break;
        have += (size_t)got;
        buf[have] = '\0';
        warm = strstr(buf, "warm tunnels: ");
        gave = strstr(buf, "gave up: ");
        if (signalled && warm != NULL && gave != NULL && strchr(warm, '\n') != NULL &&
            strchr(gave, '\n') != NULL)
            break;
    }
    if (tun > 0)
        (void)kill(tun, SIGTERM);

    expect(warm != NULL, "the summary accounts for the pool");
    unsigned long long dialled = 0, used = 0, expired = 0, never = 0, lost = 0, failed = 0;
    int got5 = warm != NULL
                   ? sscanf(warm,
                            "warm tunnels: %llu dialled, %llu used, %llu expired unused, "
                            "%llu never opened; %llu closed by the node while waiting",
                            &dialled, &used, &expired, &never, &lost)
                   : 0;
    expect(got5 == 5, "in five numbers");
    const char *df = gave != NULL ? strstr(gave, " dials failed outright") : NULL;
    if (df != NULL) {
        const char *p = df;
        while (p > gave && p[-1] >= '0' && p[-1] <= '9')
            p--;
        failed = strtoull(p, NULL, 10);
    }
    if (got5 == 5) {
        expect(used + expired + never <= dialled && dialled - (used + expired + never) <= 1u,
               "and they add up, less the one connection -P 1 may have in the air");
        expect(never >= 2u && used == 0u,
               "with every refused dial dialled again at once, as the reference's dialler does");
        expect(df != NULL && failed == never,
               "and every failed dial is the pool's: the waiting request never dialled for itself");
        if (dialled - (used + expired + never) > 1u || failed != never)
            printf("        dialled %llu, used %llu, expired %llu, never %llu, failed outright %llu\n",
                   dialled, used, expired, never, failed);
    }

    if (lan >= 0)
        close(lan);
    close(fds[0]);
    if (tun > 0) {
        int st = 0;
        (void)waitpid(tun, &st, 0);
    }
}

static void lines_stay_whole(void)
{
    printf("\nthe log four workers write down one pipe\n");

    int fds[2];
    if (pipe(fds) != 0) {
        expect(0, "a pipe for the tunnel's log");
        return;
    }
    unsigned short lan_port = 0, dead_port = 0;
    int            probe = listen_any(&lan_port);
    if (probe >= 0)
        close(probe);
    probe = listen_any(&dead_port);
    if (probe >= 0)
        close(probe); /* nothing answers there, and nothing needs to: dialling is per-connection */

    char lan_s[16], dead_s[16];
    snprintf(lan_s, sizeof lan_s, "%u", (unsigned)lan_port);
    snprintf(dead_s, sizeof dead_s, "%u", (unsigned)dead_port);

    pid_t tun = fork();
    if (tun == 0) {
        (void)dup2(fds[1], 1);
        (void)dup2(fds[1], 2);
        close(fds[0]);
        close(fds[1]);
        execl(LC_TEST_TUNNEL, "lc-tunnel", "package/files/fingerprint.fpt", "127.0.0.1", dead_s,
              "www.example.com", "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo", "0123abcd",
              "00000000-0000-4000-8000-000000000001", lan_s, "-t", "1.1.1.1:80", "-w", "4",
              (char *)NULL);
        _exit(127);
    }
    close(fds[1]);
    expect(tun > 0, "the tunnel forks with four workers");

    /* Wait for all four to exist, bounded. Nothing is read meanwhile — the pipe filling is the
     * point, and the startup banner is far too small to fill it on its own. */
    /* Fifteen seconds, and generous on purpose: the loop leaves the moment all four exist, so the
     * bound is only ever paid by a failure. Five was the first figure and it is the shape of
     * assumption that makes a suite flake on a loaded machine — the cost of being wrong in the
     * patient direction is nothing, and in the impatient direction it is a red gate nobody trusts. */
    pid_t kids[16];
    int   found = 0;
    for (int i = 0; i < 300 && found < 4; i++) {
        found = children_of(tun, kids, 16);
        if (found < 4)
            usleep(50000);
    }
    expect(found == 4, "and the kernel sees four of them under one supervisor");

    for (int i = 0; i < found; i++)
        (void)kill(kids[i], SIGUSR1);

    /* Drained as fast as it arrives, which is what procd does. Starving this reader was tried and
     * is worse than useless here — see the note above the function. */
    static char text[65536];
    size_t      have = 0;
    while (have < sizeof text - 1) {
        if (wait_readable(fds[0], 1500) != 1)
            break;
        ssize_t got = read(fds[0], text + have, sizeof text - 1 - have);
        if (got <= 0)
            break;
        have += (size_t)got;
    }
    text[have] = '\0';

    int lines = 0, whole = 0, summaries = 0;
    for (char *p = text; *p != '\0';) {
        char *nl = strchr(p, '\n');
        if (nl == NULL)
            break;
        *nl = '\0';
        lines++;

        const char *body = NULL;
        if (p[0] == '[' && p[1] == 'w') {
            const char *end = strstr(p, "] ");
            if (end != NULL && end - p <= 20 && end[2] != '\0')
                body = end + 2;
        }
        /* A second stamp inside the line is one worker's sentence sitting in another's. */
        if (body != NULL && strstr(p + 1, "[w") == NULL)
            whole++;
        else
            printf("        torn: %.120s\n", p);

        if (body != NULL && strncmp(body, "gave up:", 8) == 0)
            summaries++;
        p = nl + 1;
    }

    expect(lines > 0, "which says something at all");
    expect(whole == lines, "every line of it whole, stamped, and one worker's alone");
    expect(summaries == 4, "and all four summaries arrive complete, not three and a smear");
    if (summaries != 4)
        printf("        %d of 4 summaries, %d of %d lines whole\n", summaries, whole, lines);

    /* THE OTHER DIAGNOSTIC SIGNAL, SENT WHERE AN OPERATOR SENDS IT: to the pid procd knows. The
     * supervisor forwarded USR1 and had no handler for USR2, so zeroing the counters before a
     * measurement terminated it, and PR_SET_PDEATHSIG took all four workers with it. Asserted as the
     * pair that tells the fixed tree from the broken one: every worker says it reset, AND the
     * supervisor is still there to be asked again. */
    (void)kill(tun, SIGUSR2);
    have = 0;
    while (have < sizeof text - 1) {
        if (wait_readable(fds[0], 1500) != 1)
            break;
        ssize_t got = read(fds[0], text + have, sizeof text - 1 - have);
        if (got <= 0)
            break;
        have += (size_t)got;
    }
    text[have] = '\0';
    int resets = 0;
    for (const char *p = text; (p = strstr(p, "counters reset")) != NULL; p++)
        resets++;
    int   st_now = 0;
    pid_t reaped = waitpid(tun, &st_now, WNOHANG);
    expect(resets == 4, "SIGUSR2 to the supervisor reaches all four workers");
    expect(reaped == 0, "and the supervisor survives it, rather than taking the service down");
    if (resets != 4 || reaped != 0)
        printf("        %d of 4 resets, supervisor %s\n", resets, reaped == 0 ? "alive" : "gone");
    if (reaped == tun)
        tun = 0;

    close(fds[0]);
    if (tun > 0) {
        kill(tun, SIGTERM);
        int st = 0;
        (void)waitpid(tun, &st, 0);
    }
}

/* ---- a table this build cannot read ------------------------------------------------------------
 *
 * ⚠️ THE THIRD SEAM OF THE SAME SHAPE: the library refuses correctly and the program never asks.
 *
 * lc_fpt_supported has named the gap in a table since the requirement block was written, and
 * lc_hello_build calls it — per connection, on the dial path. So a daemon handed a table from a
 * newer or older format STARTED, bound the LAN port, printed that it was listening, and then failed
 * every handshake for as long as it ran. From a router that is a node that is down, and that is
 * where the next hour goes.
 *
 * The case is not invented for the test. The GREASE-ECH record grew a candidate list, the format
 * version went 2 -> 3, and every table written before that is now one this build refuses — which is
 * exactly the file sitting in /etc/lite-client on a box updated in the wrong order.
 *
 * What is asserted is the pair, because either half alone would pass on the broken tree: the
 * process EXITS (rather than serving), and it says the word the person holding the router needs.
 * A daemon that exited silently would be no better than one that listened. */
/* One startup input, judged before anything is promised.
 *
 * The two callers below hand this a table and a server name; whichever is wrong, the daemon owes
 * the same three things, and they are asserted together because each alone passes on a broken tree:
 * it must LEAVE (not serve), it must never have bound a port for a client to reach, and it must say
 * a word that sends the reader to the right place. A daemon that exits silently is no better than
 * one that listens, and one that blames the wrong file is worse than either. */
static void refuses_at_startup(const char *const *args, const char *want_word, const char *what)
{
    printf("\n%s\n", what);

    int fds[2];
    if (pipe(fds) != 0) {
        expect(0, "a pipe for what the tunnel says");
        return;
    }

    unsigned short lan_port = 0;
    int            probe = listen_any(&lan_port);
    if (probe >= 0)
        close(probe);
    char lan_s[16];
    snprintf(lan_s, sizeof lan_s, "%u", (unsigned)lan_port);

    /* The caller's tokens with the chosen port substituted: every argument list here needs a LAN
     * port and none of them can know it before the kernel picks one, so "@" stands for it. */
    char       *av[24];
    int         ac = 0;
    av[ac++] = (char *)"lc-tunnel";
    for (int i = 0; args[i] != NULL && ac < 22; i++)
        av[ac++] = strcmp(args[i], "@") == 0 ? lan_s : (char *)args[i];
    av[ac] = NULL;

    pid_t tun = fork();
    if (tun == 0) {
        (void)dup2(fds[1], 1);
        (void)dup2(fds[1], 2);
        close(fds[0]);
        close(fds[1]);
        execv(LC_TEST_TUNNEL, av);
        _exit(127);
    }
    close(fds[1]);
    expect(tun > 0, "the tunnel is started with it");

    /* Bounded, because the failure this guards against is a process that does NOT leave. Five
     * seconds is far more than a refusal on an already-read buffer needs and far less than a
     * hanging suite, which is worse than a failing one. */
    int   st = 0;
    pid_t got = 0;
    int   served = 0;
    for (int i = 0; i < 50 && got == 0; i++) {
        /* ⚠️ ASKED INSIDE THE WAIT, and the first version of this asked after it — which could not
         * fail. A daemon that refuses correctly has exited, and one that does not was SIGKILLed two
         * lines above, so by the time anything connected the port was free either way: an assertion
         * true by construction, in the file whose whole subject is checks that are.
         *
         * Here it is a real question. The broken tree binds within a few of these turns and answers
         * a connect; the fixed tree has left before the second one. */
        int probe_fd = connect_lan(lan_port, 1);
        if (probe_fd >= 0) {
            served = 1;
            close(probe_fd);
        }
        got = waitpid(tun, &st, WNOHANG);
        if (got == 0)
            usleep(100000);
    }

    int exited_config = got == tun && WIFEXITED(st) && WEXITSTATUS(st) == 2;
    if (got == 0) {
        kill(tun, SIGKILL);
        (void)waitpid(tun, &st, 0);
        printf("        still running after five seconds\n");
    }
    expect(exited_config, "the daemon refuses it at startup and leaves, rather than serving");
    expect(!served, "and never bound a LAN port for a client to reach in the meantime");

    static char text[8192];
    size_t      have = 0;
    while (have < sizeof text - 1) {
        ssize_t n = read(fds[0], text + have, sizeof text - 1 - have);
        if (n <= 0)
            break;
        have += (size_t)n;
    }
    text[have] = '\0';
    close(fds[0]);

    int named = strstr(text, want_word) != NULL;
    expect(named, "and names what is actually wrong, so the search starts in the right place");
    if (!named)
        printf("        wanted \"%s\", said: %s\n", want_word, have ? text : "(nothing)");
}

/* ---- a table this build cannot read ------------------------------------------------------------
 *
 * ⚠️ THE THIRD SEAM OF THE SAME SHAPE: the library refuses correctly and the program never asks.
 *
 * lc_fpt_supported has named the gap in a table since the requirement block was written, and
 * lc_hello_build calls it — per connection, on the dial path. So a daemon handed a table from a
 * newer or older format STARTED, bound the LAN port, printed that it was listening, and then failed
 * every handshake for as long as it ran. From a router that is a node that is down, and that is
 * where the next hour goes.
 *
 * The case is not invented for the test. The GREASE-ECH record grew a candidate list, the format
 * version went 2 -> 3, and every table written before that is now one this build refuses — which is
 * exactly the file sitting in /etc/lite-client on a box updated in the wrong order. */
static void a_stale_table_stops_the_daemon(void)
{
    /* The shipped table with its version byte set to 2 — the format's own predecessor, so nothing
     * about this file is malformed except being from before the record grew. Built from the shipped
     * one rather than typed out, so it stays a real table when the shipped one changes. */
    static unsigned char blob[4096];
    size_t               len = 0;
    FILE                *in = fopen("package/files/fingerprint.fpt", "rb");
    if (in != NULL) {
        len = fread(blob, 1, sizeof blob, in);
        fclose(in);
    }
    if (len <= 8) {
        expect(0, "the shipped table is there to derive a stale one from");
        return;
    }
    blob[4] = 2u;

    const char *path = "/tmp/lc-seam-stale.fpt";
    FILE       *out = fopen(path, "wb");
    if (out != NULL) {
        (void)fwrite(blob, 1, len, out);
        fclose(out);
    }
    if (out == NULL) {
        expect(0, "and a copy of it one version behind can be written");
        return;
    }

    const char *args[] = { path, "127.0.0.1", "443", "www.example.com",
                           "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo", "0123abcd",
                           "00000000-0000-4000-8000-000000000001", "@", "-t", "1.1.1.1:80",
                           "-w", "1", NULL };
    refuses_at_startup(args, "version", "a fingerprint table this build cannot read");
    (void)unlink(path);
}

/* ---- and the argument that had the same disease -------------------------------------------------
 *
 * An empty SNI is what an init script writes when the config lost its option, and lc_hello_build is
 * the only thing that ever refused it — once per connection. Measured on the real binary before the
 * fix: the daemon printed `sni ` with nothing after it, ACCEPTED connections on its LAN port, and
 * repeated its refusal every second and a half for as long as it ran.
 *
 * The word asked for is "server name" and that is the point of this case as much as the exit is:
 * the message used to be "the fingerprint table does not build a hello" for this too, which sends
 * whoever is holding the router to a file that is perfectly fine. */
static void an_empty_sni_stops_the_daemon(void)
{
    const char *reality[] = { "package/files/fingerprint.fpt", "127.0.0.1", "443", "",
                              "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo", "0123abcd",
                              "00000000-0000-4000-8000-000000000001", "@", "-t", "1.1.1.1:80",
                              "-w", "1", NULL };
    refuses_at_startup(reality, "server name",
                       "a server name the config never filled in, on the REALITY plane");

    /* ⚠️ AND THE SAME ARGUMENT ON THE OTHER PLANE, which is the half the first version of this fix
     * missed — it guarded the REALITY branch, and the live router runs -H.
     *
     * Worse there, and that is why it is its own case rather than a repetition: an empty name goes
     * into the QUIC ClientHello, ngtcp2 refuses the write, and the daemon says "cannot reach the
     * node: ERR_CALLBACK_FAILURE" while ARMING THE DEVICE-WIDE BACKOFF. A missing config option
     * then looks exactly like a node that is down, and turns away new connections router-wide.
     *
     * `-p -` because the pin is required on this plane and its absence is a different refusal —
     * without it this case would pass on a tree where the name is never looked at. */
    const char *hy[] = { "-H", "127.0.0.1", "443", "", "testpass", "-", "@", "-w", "1", "-p", "-",
                         NULL };
    refuses_at_startup(hy, "server name", "the same argument on the hysteria2 plane");
}


/* Exercise the real allocation failure, without replacing cache or libc code.
 * The 128 MiB virtual-address budget admits the ordinary tunnel but not the
 * shared arena (256 MiB on MIPS32, 1 GiB on 64-bit hosts). */
static void cache_startup_case(const char *workers, int limited, int busy)
{
    printf("\nshared cache startup: workers=%s limited=%d busy=%d\n", workers, limited, busy);
    unsigned short lan_port = 0;
    int reservation = listen_any(&lan_port);
    expect(reservation >= 0, "a private loopback port is reserved for the startup check");
    if (reservation < 0)
        return;
    if (!busy) {
        close(reservation);
        reservation = -1;
    }
    int fds[2];
    if (pipe(fds) != 0) {
        expect(0, "startup diagnostic pipe opens");
        if (reservation >= 0)
            close(reservation);
        return;
    }
    char lan_s[16];
    snprintf(lan_s, sizeof lan_s, "%u", (unsigned)lan_port);
    pid_t child = fork();
    if (child == 0) {
        if (setpgid(0, 0) != 0)
            _exit(125);
        if (limited) {
            struct rlimit budget = { 128u * 1024u * 1024u, 128u * 1024u * 1024u };
            if (setrlimit(RLIMIT_AS, &budget) != 0)
                _exit(126);
        }
        (void)dup2(fds[1], 1);
        (void)dup2(fds[1], 2);
        close(fds[0]);
        close(fds[1]);
        if (reservation >= 0)
            close(reservation);
        execl(LC_TEST_TUNNEL, "lc-tunnel", "package/files/fingerprint.fpt", "127.0.0.1", "443",
              "www.example.com", "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo", "0123abcd",
              "00000000-0000-4000-8000-000000000001", lan_s, "-t", "127.0.0.1:80", "-w", workers,
              (char *)NULL);
        _exit(127);
    }
    close(fds[1]);
    expect(child > 0, "the real tunnel starts in its own process group");
    if (child < 0) {
        close(fds[0]);
        if (reservation >= 0)
            close(reservation);
        return;
    }
    (void)setpgid(child, child);
    (void)fcntl(fds[0], F_SETFL, O_NONBLOCK);
    char text[8192] = {0};
    size_t have = 0;
    int status = 0;
    pid_t exited = 0;
    int pipe_eof = 0;
    double deadline = mono_ms() + 3000.0;
    while (mono_ms() < deadline) {
        /* EOF is permanently readable and may precede a reapable child.
         * Keep the process deadline instead of exhausting a poll counter. */
        if (pipe_eof)
            (void)poll(NULL, 0, 10);
        else
            (void)wait_readable(fds[0], 50);
        ssize_t n = -1;
        while (have < sizeof text - 1u &&
               (n = read(fds[0], text + have, sizeof text - 1u - have)) > 0)
            have += (size_t)n;
        if (n == 0)
            pipe_eof = 1;
        text[have] = '\0';
        exited = waitpid(child, &status, WNOHANG);
        if (exited < 0 && errno == EINTR) {
            exited = 0;
            continue;
        }
        if (exited != 0 || strstr(text, "listening on ") != NULL)
            break;
    }
    ssize_t remaining;
    while (have < sizeof text - 1u &&
           (remaining = read(fds[0], text + have, sizeof text - 1u - have)) > 0)
        have += (size_t)remaining;
    text[have] = '\0';
    int refused = limited && strcmp(workers, "2") == 0;
    if (refused) {
        expect(exited == child && WIFEXITED(status) && WEXITSTATUS(status) == 1,
               "shared-cache allocation failure exits with a runtime failure");
        expect(strstr(text, "cannot initialize shared spider paths:") != NULL &&
                   strstr(text, strerror(ENOMEM)) != NULL,
               "the diagnostic identifies the shared cache and allocation error");
        expect(strstr(text, "worker ") == NULL && strstr(text, "listening on ") == NULL &&
                   strstr(text, "cannot listen on ") == NULL,
               "the cache failure precedes workers and listener setup, even on a busy port");
    } else {
        int fd = strstr(text, "listening on ") != NULL ? connect_lan(lan_port, 1) : -1;
        expect(exited == 0 && fd >= 0,
               "the control starts normally and accepts a loopback connection");
        if (fd >= 0)
            close(fd);
    }
    if (exited == 0) {
        (void)kill(-child, SIGKILL);
        (void)waitpid(child, &status, 0);
    }
    close(fds[0]);
    if (reservation >= 0)
        close(reservation);
}

static void shared_cache_is_required(void)
{
    cache_startup_case("2", 1, 0);
    cache_startup_case("2", 1, 1);
    cache_startup_case("1", 1, 0);
    cache_startup_case("2", 0, 0);
}

static int listener_released(unsigned short port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return 0;
    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    int free_port = bind(fd, (struct sockaddr *)&address, sizeof address) == 0;
    close(fd);
    return free_port;
}

/* exec preserves ignored dispositions and the blocked mask. Exercise both on
 * the real daemon, including the parent-death signal of forked workers. */
static void stop_signal_case(const char *workers, int ignored, int blocked)
{
    printf("\nstop signal: workers=%s ignored=%d blocked=%d\n", workers, ignored, blocked);
    unsigned short lan_port = 0;
    int reservation = listen_any(&lan_port);
    expect(reservation >= 0, "a loopback port is available for the stop check");
    if (reservation < 0)
        return;
    close(reservation);
    int fds[2];
    if (pipe(fds) != 0) {
        expect(0, "the stop-check diagnostic pipe opens");
        return;
    }
    char lan_s[16];
    snprintf(lan_s, sizeof lan_s, "%u", (unsigned)lan_port);
    fflush(NULL);
    pid_t child = fork();
    if (child == 0) {
        struct sigaction action;
        memset(&action, 0, sizeof action);
        action.sa_handler = ignored ? SIG_IGN : SIG_DFL;
        sigemptyset(&action.sa_mask);
        sigset_t stop;
        sigemptyset(&stop);
        sigaddset(&stop, SIGTERM);
        if (setpgid(0, 0) != 0 || sigaction(SIGTERM, &action, NULL) != 0 ||
            sigprocmask(blocked ? SIG_BLOCK : SIG_UNBLOCK, &stop, NULL) != 0)
            _exit(126);
        (void)dup2(fds[1], STDOUT_FILENO);
        (void)dup2(fds[1], STDERR_FILENO);
        close(fds[0]); close(fds[1]);
        execl(LC_TEST_TUNNEL, "lc-tunnel", "package/files/fingerprint.fpt", "127.0.0.1", "443",
              "www.example.com", "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo", "0123abcd",
              "00000000-0000-4000-8000-000000000001", lan_s, "-t", "127.0.0.1:80", "-w", workers,
              (char *)NULL);
        _exit(127);
    }
    close(fds[1]);
    expect(child > 0, "the real daemon starts with controlled inherited SIGTERM state");
    if (child < 0) {
        close(fds[0]);
        return;
    }
    (void)setpgid(child, child);
    (void)fcntl(fds[0], F_SETFL, O_NONBLOCK);
    char text[8192] = {0};
    size_t have = 0;
    unsigned ready = 0;
    unsigned wanted = strcmp(workers, "2") == 0 ? 2u : 1u;
    for (unsigned tick = 0; tick < 60u; tick++) {
        (void)wait_readable(fds[0], 50);
        ssize_t got;
        while (have < sizeof text - 1u &&
               (got = read(fds[0], text + have, sizeof text - 1u - have)) > 0)
            have += (size_t)got;
        text[have] = '\0';
        ready = 0;
        for (const char *line = text; (line = strstr(line, "listening on ")) != NULL; line++)
            ready++;
        if (ready == wanted)
            break;
    }
    expect(ready == wanted, "every worker reaches its normal listening state");
    expect(kill(child, SIGTERM) == 0, "SIGTERM is sent only to the daemon PID");
    int parent_stopped = 0, complete = 0;
    for (unsigned tick = 0; tick < 150u && !complete; tick++) {
        int status;
        pid_t gone;
        while ((gone = waitpid(-1, &status, WNOHANG)) > 0)
            if (gone == child)
                parent_stopped = WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM;
        if (gone < 0 && errno == ECHILD)
            complete = 1;
        else
            usleep(10000);
    }
    expect(parent_stopped, "the daemon terminates on SIGTERM despite the inherited state");
    expect(complete, "all workers terminate and are reaped after the daemon stops");
    expect(listener_released(lan_port), "the group releases the listener before another instance starts");
    if (!complete) {
        (void)kill(-child, SIGKILL);
        for (unsigned tick = 0; tick < 150u; tick++) {
            int status;
            pid_t gone;
            while ((gone = waitpid(-1, &status, WNOHANG)) > 0) {}
            if (gone < 0 && errno == ECHILD)
                break;
            usleep(10000);
        }
    }
    close(fds[0]);
}

static void termination_signal_is_usable(void)
{
    int original = 0;
    if (prctl(PR_GET_CHILD_SUBREAPER, &original, 0UL, 0UL, 0UL) != 0 ||
        prctl(PR_SET_CHILD_SUBREAPER, 1UL, 0UL, 0UL, 0UL) != 0) {
        expect(0, "the stop controller can reap adopted workers");
        return;
    }
    for (unsigned mode = 0; mode < 4u; mode++) {
        stop_signal_case("1", (mode & 1u) != 0u, (mode & 2u) != 0u);
        stop_signal_case("2", (mode & 1u) != 0u, (mode & 2u) != 0u);
    }
    expect(prctl(PR_SET_CHILD_SUBREAPER, (unsigned long)original, 0UL, 0UL, 0UL) == 0,
           "the controller restores its original subreaper setting");
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--stop-signals") == 0) {
        termination_signal_is_usable();
        return failures != 0;
    }
    if (argc == 2 && strcmp(argv[1], "--cache-startup") == 0) {
        shared_cache_is_required();
        return failures != 0;
    }
    printf("\nthe alert the tunnel owes a peer that refuses it\n");

    unsigned short node_port = 0, lan_port = 0;
    int            node_fd = listen_any(&node_port);
    expect(node_fd >= 0, "a stand-in node listens on a port the kernel chose");
    if (node_fd < 0)
        return 1;

    /* The tunnel needs a port of its own. Taking one the same way and closing it leaves a window,
     * which is the honest cost of a program that takes its port on the command line. */
    int probe = listen_any(&lan_port);
    if (probe >= 0)
        close(probe);
    expect(probe >= 0, "and a free port is found for the tunnel's own listener");

    char node_port_s[16], lan_port_s[16];
    snprintf(node_port_s, sizeof node_port_s, "%u", (unsigned)node_port);
    snprintf(lan_port_s, sizeof lan_port_s, "%u", (unsigned)lan_port);

    pid_t tun = fork();
    expect(tun >= 0, "the tunnel forks");
    if (tun == 0) {
        int null_fd = open("/dev/null", O_WRONLY);
        if (null_fd >= 0) {
            (void)dup2(null_fd, 1);
            (void)dup2(null_fd, 2);
        }
        /* The public key is the one RFC 7748 §6.1 publishes for Alice — a valid curve point that
         * belongs to nobody, so no real node's key sits in this tree. The handshake never reaches
         * authentication anyway; it dies on the first message the peer sends back. */
        execl(LC_TEST_TUNNEL, "lc-tunnel", "package/files/fingerprint.fpt", "127.0.0.1",
              node_port_s, "www.example.com", "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo",
              "0123abcd", "00000000-0000-4000-8000-000000000001", lan_port_s, "-t", "1.1.1.1:80",
              (char *)NULL);
        _exit(127);
    }

    int lan = connect_lan(lan_port, 25);
    expect(lan >= 0, "a client reaches the tunnel, which makes it dial the node");

    int up = -1;
    if (lan >= 0 && wait_readable(node_fd, 8000) == 1)
        up = accept(node_fd, NULL, NULL);
    expect(up >= 0, "and the node sees the connection arrive");

    /* THE WHOLE RECORD, not one read of it. A hello is about 1900 bytes and usually arrives at
     * once, but "usually" is how a suite becomes flaky on a loaded machine. */
    unsigned char buf[8192];
    size_t        have = 0;
    ssize_t       n = -1;
    while (up >= 0 && wait_readable(up, 8000) == 1) {
        n = recv(up, buf + have, sizeof buf - have, 0);
        if (n <= 0)
            break;
        have += (size_t)n;
        if (have >= 5u && have >= 5u + ((size_t)buf[3] << 8 | buf[4]))
            break;
    }
    expect(have > 200, "carrying a ClientHello");

    /* ⚠️ AND IT IS CHECKED, not merely counted. Every suite that looks at a hello builds one and
     * looks at that; none of them has ever seen what the shipped binary puts on the socket. The
     * pieces below are the ones a REALITY node reads first and the ones that die quietly if the
     * wiring between the builder and the writer ever drifts: it must be a handshake record whose
     * message is a ClientHello, the legacy_session_id must be the full 32 bytes because that is
     * where lc_reality_stamp puts the authenticator, and the name asked for must be the one the
     * command line named. */
    if (have > 60) {
        expect(buf[0] == 0x16 && buf[5] == 0x01,
               "which is a handshake record carrying a ClientHello");

        size_t sid_len = buf[43];
        expect(sid_len == 32, "whose legacy_session_id is the 32 bytes REALITY stamps");

        /* The SNI is looked for as its own extension rather than as a substring, so that a name
         * appearing anywhere else in the hello cannot pass for one that was sent. */
        int    sni_ok = 0;
        size_t p = 44 + sid_len;
        if (p + 2 <= have) {
            p += 2 + ((size_t)buf[p] << 8 | buf[p + 1]); /* cipher_suites */
            if (p < have)
                p += 1 + buf[p]; /* compression_methods */
            if (p + 2 <= have) {
                size_t ext_end = p + 2 + ((size_t)buf[p] << 8 | buf[p + 1]);
                p += 2;
                if (ext_end > have)
                    ext_end = have;
                while (p + 4 <= ext_end) {
                    unsigned id = (unsigned)buf[p] << 8 | buf[p + 1];
                    size_t   len = (size_t)buf[p + 2] << 8 | buf[p + 3];
                    if (id == 0x0000u && p + 4 + len <= ext_end && len > 5 &&
                        memcmp(buf + p + 9, "www.example.com", 15) == 0)
                        sni_ok = 1;
                    p += 4 + len;
                }
            }
        }
        expect(sni_ok, "and whose server_name extension carries the name it was given");
    }

    if (up >= 0 && n > 0) {
        /* EncryptedExtensions (8) with a four-byte body, in a handshake record. */
        const unsigned char bad[] = { 0x16, 0x03, 0x03, 0x00, 0x08,
                                      0x08, 0x00, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd };
        (void)send(up, bad, sizeof bad, 0);

        n = (wait_readable(up, 8000) == 1) ? recv(up, buf, sizeof buf, 0) : -1;
        const unsigned char want[7] = { 0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x0a };
        expect(n == 7 && memcmp(buf, want, 7) == 0,
               "and the tunnel answers 15 03 01 00 02 02 0a rather than hanging up");
        if (n != 7)
            printf("        got %zd bytes\n", n);
    }

    if (lan >= 0)
        close(lan);
    if (up >= 0)
        close(up);
    close(node_fd);
    if (tun > 0) {
        kill(tun, SIGTERM);
        int st = 0;
        (void)waitpid(tun, &st, 0);
    }

    refused_dial_is_counted();
    failed_dials_are_retried();
    pool_starts_with_the_first_request();
    pool_accounts_for_every_dial();
    a_stale_table_stops_the_daemon();
    an_empty_sni_stops_the_daemon();
    shared_cache_is_required();
    termination_signal_is_usable();
    lines_stay_whole();

    printf("\n%s\n", failures == 0 ? "all ok" : "FAILURES");
    return failures == 0 ? 0 : 1;
}
