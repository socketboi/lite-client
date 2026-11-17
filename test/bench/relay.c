/* A relay that does nothing but move bytes, to find out what the machine can do at all.
 *
 * The tunnel on this router moves 1.1 MB/s. The cipher it uses costs 90 ms per megabyte, which
 * would account for a tenth of that — so nine tenths are spent somewhere else, and before
 * instrumenting stages it is worth knowing the ceiling. This is that ceiling: accept, connect,
 * copy both ways, no crypto, no framing, the same buffer size and the same event loop shape.
 *
 * If this is also around a megabyte a second, the tunnel is not slow — the device is, and the work
 * to do is elsewhere. If it is ten times faster, the difference is ours and worth finding.
 *
 *     relay LISTEN_PORT TARGET_HOST TARGET_PORT
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* The same chunk the tunnel reads with, so the comparison is like for like. */
#define CHUNK 8192

static int dial(const char *host, const char *port)
{
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0)
        return -1;

    int fd = -1;
    for (struct addrinfo *a = res; a != NULL; a = a->ai_next) {
        fd = socket(a->ai_family, a->ai_socktype | SOCK_CLOEXEC, a->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, a->ai_addr, a->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);
    if (argc != 4) {
        fprintf(stderr, "usage: relay LISTEN_PORT TARGET_HOST TARGET_PORT\n");
        return 2;
    }

    int ln = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int on = 1;
    setsockopt(ln, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons((uint16_t)atoi(argv[1]));
    if (bind(ln, (struct sockaddr *)&a, sizeof a) != 0 || listen(ln, 16) != 0) {
        perror("listen");
        return 1;
    }
    printf("relay on %s -> %s:%s\n", argv[1], argv[2], argv[3]);
    fflush(stdout);

    for (;;) {
        int c = accept(ln, NULL, NULL);
        if (c < 0)
            continue;

        int up = dial(argv[2], argv[3]);
        if (up < 0) {
            close(c);
            continue;
        }
        setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
        setsockopt(up, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);

        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        unsigned long long down = 0, upb = 0;

        static char buf[CHUNK];
        for (;;) {
            struct pollfd p[2] = { { c, POLLIN, 0 }, { up, POLLIN, 0 } };
            if (poll(p, 2, 20000) <= 0)
                break;

            int done = 0;
            for (int i = 0; i < 2 && !done; i++) {
                if (!(p[i].revents & (POLLIN | POLLHUP | POLLERR)))
                    continue;
                int from = i == 0 ? c : up, to = i == 0 ? up : c;
                ssize_t n = read(from, buf, sizeof buf);
                if (n <= 0) {
                    done = 1;
                    break;
                }
                if (i == 0)
                    upb += (unsigned long long)n;
                else
                    down += (unsigned long long)n;
                for (ssize_t off = 0; off < n;) {
                    ssize_t w = write(to, buf + off, (size_t)(n - off));
                    if (w <= 0) {
                        done = 1;
                        break;
                    }
                    off += w;
                }
            }
            if (done)
                break;
        }

        clock_gettime(CLOCK_MONOTONIC, &t1);
        double sec = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
        if (down > 100000)
            printf("%llu bytes down in %.2f s = %.0f B/s\n", down, sec,
                   sec > 0 ? (double)down / sec : 0);
        fflush(stdout);
        close(c);
        close(up);
    }
}
