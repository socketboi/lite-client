/* Actual tunnel copy/close seam, with a controlled QUIC receive buffer and real LAN sockets. */
#if LC_HYSTERIA
#include "quic/conn.h"
static lc_qtcp_state seam_state(lc_qconn *c, int h, const char **why);
static const uint8_t *seam_peek(lc_qconn *c, int h, size_t *len);
static void seam_read(lc_qconn *c, int h, size_t n);
static void seam_take(lc_qconn *c, int h, size_t n);
static int seam_eof(lc_qconn *c, int h);
#define lc_qconn_tcp_state seam_state
#define lc_qconn_tcp_peek seam_peek
#define lc_qconn_tcp_read seam_read
#define lc_qconn_tcp_take seam_take
#define lc_qconn_tcp_eof seam_eof
#define main lc_tunnel_program_main
#include "../../src/cmd/lc-tunnel/main.c"
#undef main
#undef lc_qconn_tcp_state
#undef lc_qconn_tcp_peek
#undef lc_qconn_tcp_read
#undef lc_qconn_tcp_take
#undef lc_qconn_tcp_eof

static const uint8_t tail[] = "the final buffered QUIC bytes";
static size_t off, available, credited;
static int fin;

static void require(int yes, const char *what)
{
    if (!yes) { fprintf(stderr, "FAIL hy-tunnel: %s\n", what); exit(1); }
    printf("  ok    hy-tunnel: %s\n", what);
}
static lc_qtcp_state seam_state(lc_qconn *c, int h, const char **why)
{
    (void)c; (void)h; *why = NULL; return LC_QTCP_ESTABLISHED;
}
static const uint8_t *seam_peek(lc_qconn *c, int h, size_t *len)
{
    (void)c; (void)h; *len = available; return tail + off;
}
static void seam_read(lc_qconn *c, int h, size_t n)
{
    (void)c; (void)h; require(n <= available, "read within buffered tail"); credited += n;
}
static void seam_take(lc_qconn *c, int h, size_t n)
{
    (void)c; (void)h; require(n <= available, "take within buffered tail");
    off += n; available -= n;
}
static int seam_eof(lc_qconn *c, int h) { (void)c; (void)h; return fin; }

static void copy_tail(int early_fin, int blocked)
{
    int pair[2];
    require(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "LAN socketpair");
    require(fcntl(pair[0], F_SETFL, O_NONBLOCK) == 0, "nonblocking writer");
    require(fcntl(pair[1], F_SETFL, O_NONBLOCK) == 0, "nonblocking reader");
    lc_loop *loop = lc_loop_new(4);
    session *s = calloc(1, sizeof *s);
    hy_link link;
    memset(&link, 0, sizeof link);
    require(loop != NULL && s != NULL, "session and event loop");
    link.up = 1; link.gen = 1; hy.link = &link;
    s->st = ST_OPEN; s->hy_h = 1; s->hy_gen = 1; s->lan_fd = pair[0];
    s->to_lan.buf = s->to_lan_buf; s->to_lan.cap = sizeof s->to_lan_buf;
    s->to_up.buf = s->to_up_buf; s->to_up.cap = sizeof s->to_up_buf;
    s->stage.fd = -1;
    require(pthread_mutex_init(&s->stage.lock, NULL) == 0, "uplink stage lock");
    require(lc_loop_add(loop, s->lan_fd, LC_EV_WRITE, &s->lan_tag) == 0, "LAN readiness");
    static const uint8_t prefix[] = "queued before FIN:";
    require(q_push(&s->to_lan, prefix, sizeof prefix) == 0, "existing LAN queue");
    off = credited = 0; available = sizeof tail; fin = early_fin;
    if (blocked) {
        uint8_t fill[4096] = {0};
        size_t filled = 0;
        ssize_t n;
        while ((n = write(pair[0], fill, sizeof fill)) > 0) filled += (size_t)n;
        require(errno == EAGAIN || errno == EWOULDBLOCK, "fill LAN socket to EAGAIN");
        require(hy_pump(loop, s) == 0 && q_pending(&s->to_lan) == sizeof prefix,
                "FIN cannot discard blocked queued bytes");
        while (filled > 0) {
            n = read(pair[1], fill, sizeof fill);
            require(n > 0, "drain filler"); filled -= (size_t)n;
        }
    }
    require(hy_pump(loop, s) == (early_fin ? -1 : 0),
            "finishing previous Write must drain the next Read before closing or waiting");
    require(available == 0 && q_pending(&s->to_lan) == 0,
            "writable LAN drains the buffered QUIC tail without another readiness event");
    require(available == 0 && credited == sizeof tail, "tail taken and credited exactly once");
    if (!early_fin) { fin = 1; require(hy_pump(loop, s) == -1, "later FIN closes drained stream"); }
    uint8_t received[sizeof prefix + sizeof tail];
    size_t got = 0;
    while (got < sizeof received) {
        ssize_t n = read(pair[1], received + got, sizeof received - got);
        require(n > 0, "read all LAN bytes"); got += (size_t)n;
    }
    require(memcmp(received, prefix, sizeof prefix) == 0 &&
            memcmp(received + sizeof prefix, tail, sizeof tail) == 0,
            "LAN receives prefix and tail in order without loss");
    lc_loop_free(loop); close(pair[0]); close(pair[1]);
    pthread_mutex_destroy(&s->stage.lock); free(s); hy.link = NULL;
}
int main(void)
{
    alarm(20);
    for (int early = 0; early < 2; early++)
        for (int blocked = 0; blocked < 2; blocked++) copy_tail(early, blocked);
    puts("ok hy-tunnel: queued Write, buffered tail and FIN preserve all bytes");
    return 0;
}
#else
#include <stdio.h>
int main(void) { puts("  ok    hy-tunnel: Hysteria plane not selected"); return 0; }
#endif
