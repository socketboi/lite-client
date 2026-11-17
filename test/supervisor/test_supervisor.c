/* Exercise the actual supervisor with real fork, reparenting and signals.
 * Only the pre-prctl scheduling boundary and a denied prctl are controlled. */
#include <stdarg.h>
#include <poll.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t observed_fork(void);
static int observed_prctl(int option, ...);
static pid_t observed_waitpid(pid_t pid, int *status, int options);
#define fork observed_fork
#define prctl observed_prctl
#define waitpid observed_waitpid
#define main lc_tunnel_program_main
#include "../../src/cmd/lc-tunnel/main.c"
#undef main
#undef prctl
#undef waitpid
#undef fork

enum { LIVE_PARENT, DEAD_BEFORE_PRCTL, DENIED_PRCTL, SIGNAL_BEFORE_WAIT, PARTIAL_FORK, ALL_FORKS_FAIL, LAST_WORKER };
static int scenario, ready_write, gate_read, boundary_write, worker_report;
static unsigned fork_calls, wait_boundary_seen;
static sigset_t expected_mask;
static struct sigaction expected_chld;
static unsigned failures;

static void check(int yes, const char *message)
{
    printf("  %s    %s\n", yes ? "ok" : "FAIL", message);
    failures += !yes;
}

static pid_t observed_fork(void)
{
    if (scenario == ALL_FORKS_FAIL) {
        errno = EAGAIN;
        return -1;
    }
    if (scenario == PARTIAL_FORK) {
        uint64_t now = lc_now_ms();
        if (write(boundary_write, &now, sizeof now) != (ssize_t)sizeof now)
            _exit(93);
        if (++fork_calls == 2u) {
            errno = EAGAIN;
            return -1;
        }
    }
    pid_t pid = fork();
    if (pid == 0) {
        pid_t self = getpid();
        if (write(ready_write, &self, sizeof self) != (ssize_t)sizeof self)
            _exit(90);
        if (scenario == DEAD_BEFORE_PRCTL) {
            char resume;
            if (read(gate_read, &resume, 1) != 1)
                _exit(91);
        }
    }
    return pid;
}

static pid_t observed_waitpid(pid_t pid, int *status, int options)
{
    if (scenario == SIGNAL_BEFORE_WAIT && !wait_boundary_seen++) {
        char boundary = 'W';
        if (write(boundary_write, &boundary, 1) != 1)
            _exit(94);
        /* Acknowledge actual delivery or a blocked pending signal before the
         * controller opens the wait boundary. This does not depend on a sleep
         * winning a scheduler race. */
        int seen = 0;
        for (unsigned tick = 0; tick < 2000u && !seen; tick++) {
            sigset_t pending;
            if (sigpending(&pending) != 0)
                _exit(95);
            seen = supervisor_usr1 || sigismember(&pending, SIGUSR1) == 1;
            if (!seen)
                usleep(1000);
        }
        boundary = 'A';
        if (!seen || write(boundary_write, &boundary, 1) != 1)
            _exit(96);
        char resume;
        ssize_t got;
        do { got = read(gate_read, &resume, 1); } while (got < 0 && errno == EINTR);
        if (got != 1)
            _exit(97);
    }
    return waitpid(pid, status, options);
}

static int observed_prctl(int option, ...)
{
    if (option != PR_SET_PDEATHSIG) {
        errno = EINVAL;
        return -1;
    }
    va_list args;
    va_start(args, option);
    int sig = va_arg(args, int);
    va_end(args);
    if (scenario == DENIED_PRCTL) {
        errno = EPERM;
        return -1;
    }
    return prctl(option, (unsigned long)sig, 0UL, 0UL, 0UL);
}

static int read_ready_for(int fd, void *out, size_t size, int timeout_ms)
{
    struct pollfd event = { .fd = fd, .events = POLLIN };
    int rc;
    do { rc = poll(&event, 1, timeout_ms); } while (rc < 0 && errno == EINTR);
    return rc > 0 && read(fd, out, size) == (ssize_t)size;
}

static int read_ready(int fd, void *out, size_t size)
{
    return read_ready_for(fd, out, size, 2000);
}

static int wait_for_crash_log(int fd);

static void on_worker_signal(int sig)
{
    int saved = errno;
    char event = sig == SIGUSR1 ? '1' : '2';
    (void)write(worker_report, &event, 1);
    errno = saved;
}

static void run_worker(unsigned index)
{
    sigset_t mask;
    struct sigaction action;
    int restored = sigprocmask(SIG_SETMASK, NULL, &mask) == 0 &&
                   sigaction(SIGCHLD, NULL, &action) == 0 &&
                   action.sa_handler == expected_chld.sa_handler;
    const int signals[] = { SIGUSR1, SIGUSR2, SIGCHLD };
    for (unsigned i = 0; restored && i < sizeof signals / sizeof signals[0]; i++)
        restored = sigismember(&mask, signals[i]) == sigismember(&expected_mask, signals[i]);
    if (scenario == SIGNAL_BEFORE_WAIT || scenario == PARTIAL_FORK) {
        memset(&action, 0, sizeof action);
        action.sa_handler = on_worker_signal;
        if (sigaction(SIGUSR1, &action, NULL) != 0 || sigaction(SIGUSR2, &action, NULL) != 0)
            _exit(98);
    }
    char entered = index < 2u && restored ? 'R' : 'X';
    if (write(worker_report, &entered, 1) != 1)
        _exit(92);
    if (scenario == DEAD_BEFORE_PRCTL || scenario == DENIED_PRCTL)
        _exit(75);
    for (;;)
        pause();
}

static int reap_bounded(pid_t pid, int *status)
{
    for (unsigned tick = 0; tick < 200u; tick++) {
        pid_t got = waitpid(pid, status, WNOHANG);
        if (got == pid)
            return 1;
        if (got < 0 && errno != EINTR)
            return 0;
        usleep(10000);
    }
    (void)kill(pid, SIGKILL);
    (void)waitpid(pid, status, 0);
    return 0;
}

static void run_case(int mode)
{
    int ready[2], gate[2], passed[2], errors[2], boundary[2];
    if (pipe(ready) != 0 || pipe(gate) != 0 || pipe(passed) != 0 || pipe(errors) != 0 || pipe(boundary) != 0) {
        check(0, "supervisor fixture pipes open");
        return;
    }
    scenario = mode;
    ready_write = ready[1];
    gate_read = gate[0];
    boundary_write = boundary[1];
    worker_report = passed[1];
    fork_calls = wait_boundary_seen = 0;
    fflush(NULL);
    pid_t supervisor = fork();
    if (supervisor == 0) {
        close(ready[0]);
        close(gate[1]);
        close(passed[0]);
        close(errors[0]);
        close(boundary[0]);
        (void)dup2(errors[1], STDERR_FILENO);
        close(errors[1]);
        run_worker(supervise(1u, "reality"));
    }
    close(ready[1]);
    close(gate[0]);
    close(passed[1]);
    close(errors[1]);
    close(boundary[1]);
    check(supervisor > 0, "the fixture starts a real supervisor process");
    if (supervisor < 0)
        goto close_pipes;
    pid_t worker = -1;
    int seen = read_ready(ready[0], &worker, sizeof worker) && worker > 0;
    check(seen, "a real worker reaches the controlled pre-prctl boundary");
    int parent_status = 0, worker_status = 0;
    if (!seen) {
        (void)kill(supervisor, SIGKILL);
        (void)reap_bounded(supervisor, &parent_status);
        goto close_pipes;
    }
    if (mode == LIVE_PARENT || mode == SIGNAL_BEFORE_WAIT || mode == LAST_WORKER) {
        char entered = 0;
        check(read_ready(passed[0], &entered, 1) && entered == 'R',
              "a protected worker returns from supervise while its parent lives");
        if (mode == SIGNAL_BEFORE_WAIT) {
            char event = 0;
            check(read_ready(boundary[0], &event, 1) && event == 'W',
                  "the supervisor reaches the controlled pre-wait boundary");
            (void)kill(supervisor, SIGUSR1);
            check(read_ready(boundary[0], &event, 1) && event == 'A',
                  "SIGUSR1 has reached the supervisor before it waits");
            event = 'G';
            check(write(gate[1], &event, 1) == 1, "the supervisor resumes into its wait");
            int delivered = read_ready_for(passed[0], &event, 1, 1500) && event == '1';
            check(delivered, "a diagnostic signal before wait is forwarded without another signal or exit");
            if (delivered) {
                (void)kill(supervisor, SIGUSR2);
                check(read_ready(passed[0], &event, 1) && event == '2',
                      "SIGUSR2 is forwarded while the worker remains healthy");
            }
        }
        if (mode == LAST_WORKER) {
            uint64_t crash = lc_now_ms();
            (void)kill(worker, SIGKILL);
            check(wait_for_crash_log(errors[0]), "the last worker's short crash is observed");
            (void)kill(supervisor, SIGUSR1);
            pid_t replacement = -1;
            int child_seen = read_ready_for(ready[0], &replacement, sizeof replacement, 7500) && replacement > 0;
            int returned = child_seen &&
                           read_ready(passed[0], &entered, 1) && entered == 'R';
            check(returned, "a pending respawn survives ECHILD when the last worker has died");
            check(returned && lc_now_ms() >= crash + (uint64_t)WORKER_RESPAWN_S * 1000u,
                  "a diagnostic during zero-worker backoff cannot force an early fork");
            if (child_seen)
                worker = replacement;
        }
        (void)kill(supervisor, SIGKILL);
        check(reap_bounded(supervisor, &parent_status), "the terminated supervisor is reaped");
        check(reap_bounded(worker, &worker_status) && WIFSIGNALED(worker_status) &&
                  WTERMSIG(worker_status) == SIGTERM,
              "registered parent death terminates the worker with SIGTERM");
    } else if (mode == DEAD_BEFORE_PRCTL) {
        (void)kill(supervisor, SIGKILL);
        check(reap_bounded(supervisor, &parent_status), "the parent dies before the child installs protection");
        char resume = 'G';
        check(write(gate[1], &resume, 1) == 1, "the adopted worker resumes past fork");
        check(reap_bounded(worker, &worker_status) && WIFEXITED(worker_status) &&
                  WEXITSTATUS(worker_status) == 0,
              "a worker adopted by a non-init subreaper exits without entering service");
        char escaped;
        check(read(passed[0], &escaped, 1) == 0,
              "the lost-parent race never returns a worker to the tunnel");
    } else {
        check(reap_bounded(supervisor, &parent_status) && WIFEXITED(parent_status) &&
                  WEXITSTATUS(parent_status) == LC_EXIT_FAILED,
              "denied parent-death protection fails the supervised group explicitly");
        char escaped;
        check(read(passed[0], &escaped, 1) == 0,
              "a worker without parent-death protection cannot enter service");
        char text[2048] = {0};
        ssize_t n = read(errors[0], text, sizeof text - 1u);
        check(n > 0 && strstr(text, "cannot set parent-death signal") != NULL &&
                  strstr(text, strerror(EPERM)) != NULL,
              "the error identifies failed parent-death protection and its cause");
    }
close_pipes:
    close(ready[0]);
    close(gate[1]);
    close(passed[0]);
    close(errors[0]);
    close(boundary[0]);
}

static int diagnostic(int supervisor, int fd, int sig, char expected)
{
    char event = 0;
    return kill(supervisor, sig) == 0 && read_ready_for(fd, &event, 1, 1500) && event == expected;
}

static int wait_for_crash_log(int fd)
{
    char text[2048] = {0};
    size_t have = 0;
    uint64_t deadline = lc_now_ms() + 2000u;
    while (have < sizeof text - 1u && lc_now_ms() < deadline) {
        struct pollfd event = { .fd = fd, .events = POLLIN };
        if (poll(&event, 1, 50) <= 0)
            continue;
        ssize_t got = read(fd, text + have, sizeof text - 1u - have);
        if (got <= 0)
            break;
        have += (size_t)got;
        if (strstr(text, "ended on a signal") != NULL)
            return 1;
    }
    return 0;
}

static void run_recovery(void)
{
    int ready[2], passed[2], attempts[2], errors[2];
    if (pipe(ready) != 0 || pipe(passed) != 0 || pipe(attempts) != 0 || pipe(errors) != 0) {
        check(0, "worker recovery fixture pipes open");
        return;
    }
    scenario = PARTIAL_FORK;
    fork_calls = wait_boundary_seen = 0;
    ready_write = ready[1];
    boundary_write = attempts[1];
    worker_report = passed[1];
    fflush(NULL);
    pid_t supervisor = fork();
    if (supervisor == 0) {
        close(ready[0]); close(passed[0]); close(attempts[0]); close(errors[0]);
        (void)dup2(errors[1], STDERR_FILENO);
        close(errors[1]);
        run_worker(supervise(2u, "reality"));
    }
    close(ready[1]); close(passed[1]); close(attempts[1]); close(errors[1]);
    check(supervisor > 0, "partial-fork fixture starts its supervisor");
    pid_t workers[4] = {-1, -1, -1, -1};
    uint64_t at[5] = {0};
    int status;
    char event;
    if (supervisor < 0)
        goto close_recovery;
    int first = read_ready(ready[0], &workers[0], sizeof workers[0]) &&
                read_ready(passed[0], &event, 1) && event == 'R';
    check(first, "one worker is healthy while the other fork fails");
    if (!first)
        goto stop_recovery;
    int timed = read_ready(attempts[0], &at[0], sizeof at[0]) &&
                read_ready(attempts[0], &at[1], sizeof at[1]);
    check(timed, "the first successful fork and the failed fork have real clock observations");
    int second = read_ready_for(ready[0], &workers[1], sizeof workers[1], 7500) &&
                 read_ready(passed[0], &event, 1) && event == 'R';
    check(second, "a failed fork is retried without any healthy worker exiting or receiving a signal");
    if (!second)
        goto stop_recovery;
    check(read_ready(attempts[0], &at[2], sizeof at[2]) &&
              at[2] >= at[1] + (uint64_t)WORKER_RESPAWN_S * 1000u,
          "resource-failure retry respects the existing procd backoff");
    check(kill(workers[0], 0) == 0, "the original healthy worker survives capacity recovery");
    uint64_t crash = lc_now_ms();
    (void)kill(workers[1], SIGKILL);
    check(wait_for_crash_log(errors[0]), "the supervisor observes a newly started worker's crash");
    check(diagnostic(supervisor, passed[0], SIGUSR1, '1'),
          "statistics reach the healthy worker during crash backoff");
    check(diagnostic(supervisor, passed[0], SIGUSR2, '2'),
          "counter reset reaches the healthy worker during crash backoff");
    int replacement = read_ready_for(ready[0], &workers[2], sizeof workers[2], 7500) &&
                      read_ready(passed[0], &event, 1) && event == 'R';
    check(replacement, "the quick crash gets a replacement after its deadline");
    if (!replacement)
        goto stop_recovery;
    check(read_ready(attempts[0], &at[3], sizeof at[3]) &&
              at[3] >= crash + (uint64_t)WORKER_RESPAWN_S * 1000u,
          "diagnostic signals cannot shorten the crash backoff");
    (void)kill(workers[0], SIGKILL);
    check(read_ready_for(ready[0], &workers[3], sizeof workers[3], 1500) &&
              read_ready(passed[0], &event, 1) && event == 'R',
          "a long-lived worker's crash is replaced without the startup backoff");
stop_recovery:
    (void)kill(supervisor, SIGKILL);
    (void)reap_bounded(supervisor, &status);
    for (unsigned i = 0; i < sizeof workers / sizeof workers[0]; i++)
        if (workers[i] > 0)
            (void)reap_bounded(workers[i], &status);
close_recovery:
    close(ready[0]); close(passed[0]); close(attempts[0]); close(errors[0]);
}

static void run_all_forks_fail(void)
{
    scenario = ALL_FORKS_FAIL;
    fflush(NULL);
    pid_t supervisor = fork();
    if (supervisor == 0) {
        (void)supervise(2u, "reality");
        _exit(75);
    }
    check(supervisor > 0, "zero-capacity fixture starts its supervisor");
    if (supervisor > 0) {
        int status;
        check(reap_bounded(supervisor, &status) && WIFEXITED(status) &&
                  WEXITSTATUS(status) == LC_EXIT_FAILED,
              "failure of every fork remains an explicit startup failure");
    }
}

int main(void)
{
    check(getpid() != 1 && sigprocmask(SIG_SETMASK, NULL, &expected_mask) == 0 &&
              sigaction(SIGCHLD, NULL, &expected_chld) == 0,
          "the controller has a non-init PID and records inherited signal state");
    int original = 0;
    check(prctl(PR_GET_CHILD_SUBREAPER, &original, 0UL, 0UL, 0UL) == 0 &&
              prctl(PR_SET_CHILD_SUBREAPER, 1UL, 0UL, 0UL, 0UL) == 0,
          "the controller becomes the real non-init orphan adopter");
    if (failures != 0u)
        return 1;
    run_case(LIVE_PARENT);
    run_case(DEAD_BEFORE_PRCTL);
    run_case(DENIED_PRCTL);
    run_case(SIGNAL_BEFORE_WAIT);
    run_recovery();
    run_case(LAST_WORKER);
    run_all_forks_fail();
    check(prctl(PR_SET_CHILD_SUBREAPER, (unsigned long)original, 0UL, 0UL, 0UL) == 0,
          "the controller restores its original subreaper setting");
    int status;
    check(waitpid(-1, &status, WNOHANG) == -1 && errno == ECHILD,
          "every fixture process is reaped without leaving an orphan");
    return failures != 0u;
}
