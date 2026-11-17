#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

/* Test-only helper: exact nonce echoes and owned-process resource observations. */
static int udp(unsigned port, const char *host, int loopback, unsigned timeout)
{
    struct sockaddr_in target = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    if (inet_pton(AF_INET, host, &target.sin_addr) != 1) return 2;
    int entropy = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (entropy < 0) return 2;
    unsigned echoes = 0;
    int sockets[4];
    for (unsigned i = 0; i < 4; i++) sockets[i] = -1;
    int rc = 2;
    const char *step = "socket";
    for (unsigned i = 0; i < 4; i++) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        sockets[i] = fd;
        struct timeval wait = {.tv_sec = (time_t)timeout};
        /* Preserve the original loopback binding unless a routed target was requested. */
        struct sockaddr_in local = {.sin_family = AF_INET,
            .sin_addr.s_addr = htonl(loopback ? INADDR_LOOPBACK : INADDR_ANY)};
        if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &wait, sizeof wait) != 0 ||
            bind(fd, (struct sockaddr *)&local, sizeof local) != 0) goto done;
    }
    for (unsigned n = 0; n < 16; n++) {
        for (unsigned i = 0; i < 4; i++) {
            unsigned char payload[128], reply[129];
            size_t have = 0;
            while (have < sizeof payload) {
                ssize_t got = read(entropy, payload + have, sizeof payload - have);
                if (got <= 0) goto done;
                have += (size_t)got;
            }
            memcpy(payload, "LCSOAK1", 7);
            step = "send";
            if (sendto(sockets[i], payload, sizeof payload, 0, (struct sockaddr *)&target, sizeof target) !=
                (ssize_t)sizeof payload) goto done;
            struct sockaddr_in peer = {0};
            socklen_t peer_len = sizeof peer;
            step = "receive";
            ssize_t got = recvfrom(sockets[i], reply, sizeof reply, 0, (struct sockaddr *)&peer, &peer_len);
            if (got < 0) goto done;
            step = "payload/source";
            errno = 0;
            if (got != (ssize_t)sizeof payload || memcmp(payload, reply, sizeof payload) != 0 ||
                peer.sin_port != target.sin_port || peer.sin_addr.s_addr != target.sin_addr.s_addr) goto done;
            echoes++;
        }
    }
    printf("{\"echoes\":%u,\"bytes\":%u}\n", echoes, echoes * 128u);
    rc = 0;
done:
    if (rc) fprintf(stderr, "UDP probe failed: step=%s echoes=%u errno=%d\n", step, echoes, errno);
    for (unsigned i = 0; i < 4; i++) if (sockets[i] >= 0) close(sockets[i]);
    close(entropy);
    return rc;
}

typedef struct { unsigned long long inode; unsigned port, state; int tcp; } net_entry;
static net_entry *network;
static size_t network_count;

static int load_network(void)
{
    const char *tables[] = {"tcp", "tcp6", "udp", "udp6"};
    for (unsigned n = 0; n < 4; n++) {
        char path[64], line[2048];
        snprintf(path, sizeof path, "/proc/net/%s", tables[n]);
        FILE *file = fopen(path, "r");
        if (!file) return -1;
        if (!fgets(line, sizeof line, file)) { fclose(file); return -1; }
        while (fgets(line, sizeof line, file)) {
            char *fields[10], *save = NULL;
            unsigned count = 0;
            for (char *p = strtok_r(line, " \t\n", &save); p && count < 10; p = strtok_r(NULL, " \t\n", &save))
                fields[count++] = p;
            if (count < 10) { fclose(file); return -1; }
            char *colon = strrchr(fields[1], ':');
            if (!colon) { fclose(file); return -1; }
            net_entry entry = {.inode = strtoull(fields[9], NULL, 10), .port = (unsigned)strtoul(colon + 1, NULL, 16),
                               .state = (unsigned)strtoul(fields[3], NULL, 16), .tcp = n < 2};
            net_entry *grown = realloc(network, (network_count + 1) * sizeof *grown);
            if (!grown) { fclose(file); return -1; }
            network = grown;
            network[network_count++] = entry;
        }
        fclose(file);
    }
    return 0;
}

static int snapshot(pid_t root, unsigned expected, int check)
{
    if (load_network() != 0) return 2;
    DIR *proc = opendir("/proc");
    if (!proc) return 2;
    struct dirent *entry;
    unsigned tasks = 0, tcp = 0, udp_fds = 0, other = 0;
    int failed = 0;
    printf("{\"tasks\":[");
    while ((entry = readdir(proc)) != NULL) {
        char *end;
        long pid = strtol(entry->d_name, &end, 10);
        if (*end || pid <= 0 || getpgid((pid_t)pid) != root) continue;
        char path[256], line[4096];
        snprintf(path, sizeof path, "/proc/%ld/stat", pid);
        FILE *file = fopen(path, "r");
        if (!file) { failed = 1; break; }
        char *got = fgets(line, sizeof line, file);
        fclose(file);
        char *tail = got ? strrchr(line, ')') : NULL;
        if (!tail) { failed = 1; break; }
        unsigned field = 3;
        unsigned long long born = 0, cpu = 0;
        char *save = NULL;
        for (char *p = strtok_r(tail + 2, " \n", &save); p; p = strtok_r(NULL, " \n", &save), field++) {
            if (field == 14 || field == 15) cpu += strtoull(p, NULL, 10);
            if (field == 22) born = strtoull(p, NULL, 10);
        }
        if (!born) { failed = 1; break; }
        snprintf(path, sizeof path, "/proc/%ld/status", pid);
        file = fopen(path, "r");
        if (!file) { failed = 1; break; }
        unsigned long rss = 0, threads = 0;
        int have_rss = 0;
        while (fgets(line, sizeof line, file)) {
            if (sscanf(line, "VmRSS: %lu", &rss) == 1) have_rss = 1;
            (void)sscanf(line, "Threads: %lu", &threads);
        }
        fclose(file);
        if (!have_rss || !threads) { failed = 1; break; }
        snprintf(path, sizeof path, "/proc/%ld/fd", pid);
        DIR *fds = opendir(path);
        if (!fds) { failed = 1; break; }
        unsigned count = 0, sockets = 0;
        struct dirent *fd;
        while ((fd = readdir(fds)) != NULL) {
            if (fd->d_name[0] == '.') continue;
            char link[1024], target[256];
            snprintf(link, sizeof link, "%s/%s", path, fd->d_name);
            ssize_t length = readlink(link, target, sizeof target - 1);
            if (length < 0) { if (errno == ENOENT) continue; failed = 1; break; }
            target[length] = '\0';
            count++;
            unsigned long long inode;
            if (sscanf(target, "socket:[%llu]", &inode) == 1) {
                sockets++;
                int kind = 0;
                for (size_t j = 0; j < network_count; j++) if (network[j].inode == inode) {
                    if (network[j].tcp && network[j].port == 19971u && network[j].state == 10u) kind = 1;
                    if (!network[j].tcp && network[j].port == 19601u) kind = 2;
                }
                if (kind == 1) tcp++; else if (kind == 2) udp_fds++; else other++;
            }
        }
        closedir(fds);
        if (tasks++) printf(",");
        printf("{\"pid\":%ld,\"born\":%llu,\"cpu\":%llu,\"rss_kib\":%lu,\"threads\":%lu,\"fds\":%u,\"sockets\":%u}",
               pid, born, cpu, rss, threads, count, sockets);
    }
    closedir(proc);
    printf("],\"tcp_listener_fds\":%u,\"udp_listener_fds\":%u,\"other_socket_fds\":%u}\n", tcp, udp_fds, other);
    free(network);
    if (failed || !tasks) return 2;
    if (check && (tasks != expected || tcp != expected || udp_fds != (expected == 1 ? 1u : 4u) || other)) return 1;
    return 0;
}

static int positive_number(const char *text, unsigned maximum, unsigned *value)
{
    char *end;
    errno = 0;
    unsigned long number = strtoul(text, &end, 10);
    if (errno || text[0] < '0' || text[0] > '9' || *end || !number || number > maximum) return 2;
    *value = (unsigned)number;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "gone")) {
        pid_t root = (pid_t)strtol(argv[2], NULL, 10);
        if (root <= 0) return 2;
        DIR *proc = opendir("/proc");
        if (!proc) return 2;
        int found = 0;
        struct dirent *entry;
        while ((entry = readdir(proc)) != NULL) {
            char *end;
            long pid = strtol(entry->d_name, &end, 10);
            if (!*end && pid > 0 && getpgid((pid_t)pid) == root) found = 1;
        }
        closedir(proc);
        return found;
    }
    if (argc >= 3 && argc <= 5 && !strcmp(argv[1], "udp")) {
        unsigned port, timeout = 5;
        if (positive_number(argv[2], 65535, &port) ||
            (argc == 5 && positive_number(argv[4], 60, &timeout))) return 2;
        return udp(port, argc >= 4 ? argv[3] : "127.0.0.1", argc == 3, timeout);
    }
    if (argc == 4 && (!strcmp(argv[1], "sample") || !strcmp(argv[1], "check")))
        return snapshot((pid_t)strtol(argv[2], NULL, 10), (unsigned)strtoul(argv[3], NULL, 10), !strcmp(argv[1], "check"));
    return 2;
}
