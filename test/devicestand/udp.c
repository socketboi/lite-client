/* A bounded native UDP client for a loopback LiteClient listener. */
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 3) return 2;
    int hy = strcmp(argv[2], "hysteria") == 0;
    if (!hy && strcmp(argv[2], "reality") != 0) return 2;
    char *end;
    long port = strtol(argv[1], &end, 10);
    if (*end || port < 1 || port > 65535) return 2;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct timeval timeout = { .tv_sec = 5 };
    struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons((uint16_t)port),
                              .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) != 0 ||
        connect(fd, (struct sockaddr *)&to, sizeof to) != 0) return 1;
    /* Hysteria UDPMessage.HeaderSize for 127.0.0.1:29605 is 24.
     * MaxUDPSize includes that header; client udpIOImpl.SendMessage silently
     * drops messages above 4096 BEFORE considering QUIC fragmentation. */
    const size_t sizes[] = { 1, 23, 1200, hy ? 4072u : 4096u };
    uint8_t sent[4096] = {0}, received[4097];
    for (unsigned round = 0; round < 4; round++) {
        for (unsigned k = 0; k < sizeof sizes / sizeof sizes[0]; k++) {
            size_t n = sizes[k];
            for (size_t i = 0; i < n; i++) sent[i] = (uint8_t)(i * 131u + round * 17u + k);
            if (send(fd, sent, n, 0) != (ssize_t)n ||
                recv(fd, received, sizeof received, 0) != (ssize_t)n || memcmp(sent, received, n)) {
                fprintf(stderr, "UDP mismatch or delivery failure: round=%u size=%zu\n", round, n);
                close(fd);
                return 1;
            }
        }
    }
    if (hy) {
        timeout.tv_sec = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) != 0 ||
            send(fd, sent, 4073, 0) != 4073) return 1;
        ssize_t got = recv(fd, received, sizeof received, 0);
        if (got >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) return 1;
        timeout.tv_sec = 5;
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) != 0 ||
            send(fd, sent, 23, 0) != 23 || recv(fd, received, sizeof received, 0) != 23 ||
            memcmp(sent, received, 23)) return 1;
    }
    close(fd);
    printf("UDP_OK datagrams=%u max_payload=%u oversize_dropped=%u\n",
           hy ? 17u : 16u, hy ? 4072u : 4096u, hy ? 1u : 0u);
    return 0;
}
