/* What the far end sees, asked of the Internet instead of a stand: one UDP socket, two STUN servers,
 * and the two addresses they report back.
 *
 * WHY THIS EXISTS. The node opens one UDP socket per SESSION, and the session key is the client's
 * (vendor/hysteria/core/server/udp.go:309-340). So a client that opens a session per destination
 * makes the node use a different source port for each of them — an endpoint-dependent mapping, the
 * one that breaks games and calls — while a client that carries every destination in one session
 * gets one port for all of them. test/hystand/udpshape.sh measures the reference's half of that on
 * a stand; this client's half cannot be driven there, because its transparent mode needs tproxy and
 * the container kernel has no nft_tproxy.
 *
 * A router has tproxy. And a STUN server answers with exactly the address it saw — which is the
 * measurement, with no infrastructure of ours on the far side and nothing to trust but the protocol
 * (RFC 5389 §15.2: XOR-MAPPED-ADDRESS, the port and address exclusive-ORed with the magic cookie).
 *
 * HOW TO RUN IT, on a router whose tunnel carries UDP transparently. Resolve both servers FIRST and
 * put every address they answer with into the set — nft names addresses, the tool names hosts, and a
 * server that resolves to two addresses (stun.sipgate.net does) leaves one of them unsteered:
 *
 *   1. steer both servers into the tunnel's UDP listener, the way the speed test steers TCP:
 *        table inet natshape {
 *          chain out { type route hook output priority mangle - 1; policy accept;
 *                      ip daddr { A, B } udp dport 3478 meta mark set meta mark | 0x1000000 }
 *          chain pre { type filter hook prerouting priority mangle - 1; policy accept;
 *                      iifname "lo" udp dport 3478 meta mark & 0x1000000 == 0x1000000
 *                      tproxy ip to :19998 counter accept }
 *        }
 *      with the `ip rule fwmark 0x1000000/0x1000000 lookup 104 priority 102` installed by init; the
 *      counter is the proof the datagrams took that path and not another one;
 *   2. ./natshape A:3478 B:3478, twice, the second run for the control: a fresh local socket must
 *      report a DIFFERENT node port, or the measurement cannot tell the two models apart;
 *   3. nft delete table inet natshape
 *
 * WHAT THE ANSWER MEANS. Two identical ports: one session carried both destinations, and the node's
 * mapping is endpoint-independent. Two different ports: a session per destination, which is the
 * reference's model and, since 16 September, this client's as well.
 *
 * WHAT IT ANSWERED, on an MT7621 router through a live node, and it answered TWICE because the
 * client changed between the two:
 *
 *   16 September, before: both servers reported the same address and the same port, 36660, and two
 *   more runs from fresh local sockets reported 37614 and 39782 — the port following the LOCAL
 *   SOCKET and not the destination. One session carried everything, endpoint-independent.
 *
 *   16 September, after the session model was made the reference's (udp_session_for): 46269 and
 *   37514 to the two servers in one run, 60103 and 44472 in the next. A port per destination,
 *   endpoint-dependent — which is what the reference's transparent mode produces, and what this
 *   client now produces, by the maintainer's decision taken with both numbers in hand.
 *
 * The run without that nft table is worthless and looks convincing: only the steered destination
 * goes through the tunnel, the other leaves over the ISP, and two paths are read as two sessions.
 *
 * Build for the router with the toolchain the client uses:
 *   mipsel-openwrt-linux-gcc -O2 -static -o natshape tools/natshape/natshape.c
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define STUN_BINDING_REQUEST 0x0001u
#define STUN_MAGIC           0x2112A442u
#define STUN_XOR_MAPPED      0x0020u
#define STUN_MAPPED          0x0001u

/* One binding request: the twenty-byte header and nothing else. The transaction id is what pairs a
 * reply with its request, so it is drawn fresh and checked on the way back. */
static void request(uint8_t out[20], uint8_t txid[12])
{
    out[0] = (uint8_t)(STUN_BINDING_REQUEST >> 8);
    out[1] = (uint8_t)STUN_BINDING_REQUEST;
    out[2] = 0; /* no attributes */
    out[3] = 0;
    out[4] = (uint8_t)(STUN_MAGIC >> 24);
    out[5] = (uint8_t)(STUN_MAGIC >> 16);
    out[6] = (uint8_t)(STUN_MAGIC >> 8);
    out[7] = (uint8_t)STUN_MAGIC;
    memcpy(out + 8, txid, 12);
}

/* The address a reply reports, XOR-MAPPED-ADDRESS by preference and MAPPED-ADDRESS if that is all
 * there is. Returns 0 and fills `out` on success. */
static int mapped_address(const uint8_t *msg, size_t len, char *out, size_t cap)
{
    if (len < 20u)
        return -1;
    size_t attrs = (size_t)msg[2] << 8 | msg[3];
    if (attrs + 20u > len)
        return -1;

    size_t p = 20u;
    while (p + 4u <= 20u + attrs) {
        unsigned type = (unsigned)msg[p] << 8 | msg[p + 1u];
        size_t   n = (size_t)msg[p + 2u] << 8 | msg[p + 3u];
        size_t   body = p + 4u;
        if (body + n > len)
            return -1;

        if ((type == STUN_XOR_MAPPED || type == STUN_MAPPED) && n >= 8u && msg[body + 1u] == 0x01u) {
            unsigned port = (unsigned)msg[body + 2u] << 8 | msg[body + 3u];
            uint32_t ip = (uint32_t)msg[body + 4u] << 24 | (uint32_t)msg[body + 5u] << 16 |
                          (uint32_t)msg[body + 6u] << 8 | msg[body + 7u];
            if (type == STUN_XOR_MAPPED) {
                port ^= STUN_MAGIC >> 16;
                ip ^= STUN_MAGIC;
            }
            struct in_addr a;
            a.s_addr = htonl(ip);
            snprintf(out, cap, "%s:%u", inet_ntoa(a), port & 0xffffu);
            return 0;
        }

        p = body + ((n + 3u) & ~(size_t)3u); /* attributes are padded to four bytes */
    }
    return -1;
}

static int ask(int fd, const char *where, char *out, size_t cap)
{
    char host[256];
    snprintf(host, sizeof host, "%s", where);
    char *colon = strrchr(host, ':');
    if (colon == NULL) {
        fprintf(stderr, "natshape: %s is not HOST:PORT\n", where);
        return -1;
    }
    *colon = '\0';

    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, colon + 1, &hints, &res) != 0 || res == NULL) {
        fprintf(stderr, "natshape: cannot resolve %s\n", host);
        return -1;
    }

    uint8_t txid[12];
    for (int i = 0; i < 12; i++)
        txid[i] = (uint8_t)(rand() & 0xff);

    uint8_t req[20];
    request(req, txid);

    /* Three attempts, because this is UDP over a tunnel over the Internet and one lost datagram is
     * not an answer about anything. */
    for (int attempt = 0; attempt < 3; attempt++) {
        if (sendto(fd, req, sizeof req, 0, res->ai_addr, res->ai_addrlen) < 0) {
            fprintf(stderr, "natshape: send to %s: %s\n", where, strerror(errno));
            freeaddrinfo(res);
            return -1;
        }

        uint8_t reply[512];
        ssize_t n = recv(fd, reply, sizeof reply, 0);
        if (n < 0)
            continue;
        if ((size_t)n >= 20u && memcmp(reply + 8, txid, 12) == 0 &&
            mapped_address(reply, (size_t)n, out, cap) == 0) {
            freeaddrinfo(res);
            return 0;
        }
    }

    freeaddrinfo(res);
    return -1;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: natshape HOST:PORT HOST:PORT   (two STUN servers)\n");
        return 2;
    }

    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    /* ONE socket for both, which is the whole question: two destinations from one source. */
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    char first[64] = "", second[64] = "";
    int  rc1 = ask(fd, argv[1], first, sizeof first);
    int  rc2 = ask(fd, argv[2], second, sizeof second);
    close(fd);

    printf("%s says %s\n", argv[1], rc1 == 0 ? first : "nothing");
    printf("%s says %s\n", argv[2], rc2 == 0 ? second : "nothing");

    if (rc1 != 0 || rc2 != 0)
        return 1;

    const char *p1 = strrchr(first, ':');
    const char *p2 = strrchr(second, ':');
    if (p1 != NULL && p2 != NULL && strcmp(p1, p2) == 0)
        printf("the same port to both: one session carried them, endpoint-independent\n");
    else
        printf("a different port each: a session per destination, endpoint-dependent\n");
    return 0;
}
