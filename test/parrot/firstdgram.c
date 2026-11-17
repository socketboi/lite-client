/* The first datagram lc-tunnel sends on the Hysteria2 plane, caught where the node would be.
 *
 *     firstdgram LC-TUNNEL [OPTION...]
 *
 * binds a UDP socket on the loopback, starts LC-TUNNEL -H at it with the options given (and `-p -`,
 * since there is no node to pin), makes one TCP connection to the tunnel's LISTEN port in case the
 * plane dials on demand, and prints the size of the first datagram that arrives and its first byte.
 * No reply is sent: the first Initial is all that is asked about. test/parrot/test_parrot.sh reads
 * the size — 1250, chromeInitialPacketSize, for a client that parrots Chrome, and not 1250 for one
 * that does not. */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static unsigned short free_tcp_port(void)
{
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t l = sizeof(a);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    unsigned short port = 0;

    if (s >= 0 && bind(s, (struct sockaddr *)&a, sizeof(a)) == 0 &&
        getsockname(s, (struct sockaddr *)&a, &l) == 0) {
        port = ntohs(a.sin_port);
    }
    if (s >= 0) {
        close(s);
    }
    return port;
}

int main(int argc, char **argv)
{
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t l = sizeof(a);
    unsigned char buf[2048];
    char udp_port[8], listen_port[8];
    struct pollfd p;
    unsigned short lport = free_tcp_port();
    int u, i, knocked = 0, waited;
    pid_t pid;
    ssize_t n = -1;

    if (argc < 2 || lport == 0) {
        fprintf(stderr, "usage: firstdgram LC-TUNNEL [OPTION...]\n");
        return 2;
    }
    u = socket(AF_INET, SOCK_DGRAM, 0);
    if (u < 0 || bind(u, (struct sockaddr *)&a, sizeof(a)) != 0 ||
        getsockname(u, (struct sockaddr *)&a, &l) != 0) {
        perror("udp");
        return 2;
    }
    snprintf(udp_port, sizeof(udp_port), "%u", ntohs(a.sin_port));
    snprintf(listen_port, sizeof(listen_port), "%u", lport);

    pid = fork();
    if (pid == 0) {
        char *args[64];
        int k = 0;

        args[k++] = argv[1];
        args[k++] = "-H";
        args[k++] = "127.0.0.1";
        args[k++] = udp_port;
        args[k++] = "www.example.com";
        args[k++] = "password";
        args[k++] = "-";
        args[k++] = listen_port;
        for (i = 2; i < argc && k < 60; ++i) {
            args[k++] = argv[i];
        }
        args[k++] = "-p";
        args[k++] = "-";
        args[k] = NULL;
        close(u);
        if (freopen("/dev/null", "w", stdout) == NULL || freopen("/dev/null", "w", stderr) == NULL) {
            _exit(127);
        }
        execv(argv[1], args);
        perror("execv");
        _exit(127);
    }

    p.fd = u;
    p.events = POLLIN;
    for (waited = 0; waited < 5000; waited += 100) {
        if (poll(&p, 1, 100) > 0) {
            n = recv(u, buf, sizeof(buf), 0);
            break;
        }
        if (!knocked && waited >= 300) {
            struct sockaddr_in t = { .sin_family = AF_INET,
                                     .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
                                     .sin_port = htons(lport) };
            int c = socket(AF_INET, SOCK_STREAM, 0);

            if (c >= 0) {
                if (connect(c, (struct sockaddr *)&t, sizeof(t)) == 0) {
                    ssize_t w = write(c, "x", 1);

                    (void)w;
                }
                knocked = 1;
                /* Left open: a tunnel that dials on demand may give up the dial with the
                 * connection that asked for it. */
            }
        }
    }
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    if (n < 0) {
        printf("none\n");
        return 1;
    }
    printf("%zd %02x\n", n, buf[0]);
    return 0;
}
