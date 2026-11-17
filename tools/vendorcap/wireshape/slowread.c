/* A read of the node's socket that waits first — LD_PRELOAD'ed into one of the stand's tunnels.
 *
 * On loopback the record that announces direct copy always ends the read that brings it: the node
 * writes it, then splices the target's bytes after it, and the client has read the record before
 * the first raw byte is there. So a client that forgot what it had read ahead of the reference at
 * that point (O3, node_read_ahead and rin_ahead in lc-tunnel) behaved exactly like one that did not,
 * and the stand could not tell them apart. Waiting SLOWREAD_US microseconds before every read of a
 * TCP socket whose peer port is SLOWREAD_PORT lets the raw bytes arrive behind the record, so the
 * read that brings the announcement brings them too. Nothing else is touched. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static ssize_t (*real_read)(int, void *, size_t);

static int to_node(int fd)
{
    static int port = -1;
    if (port < 0) {
        const char *p = getenv("SLOWREAD_PORT");
        port = p != NULL ? atoi(p) : 0;
    }
    struct sockaddr_storage sa;
    socklen_t               len = sizeof sa;
    if (port == 0 || getpeername(fd, (struct sockaddr *)&sa, &len) != 0)
        return 0;
    if (sa.ss_family == AF_INET)
        return ntohs(((struct sockaddr_in *)&sa)->sin_port) == port;
    if (sa.ss_family == AF_INET6)
        return ntohs(((struct sockaddr_in6 *)&sa)->sin6_port) == port;
    return 0;
}

ssize_t read(int fd, void *buf, size_t n)
{
    if (real_read == NULL)
        real_read = (ssize_t (*)(int, void *, size_t))dlsym(RTLD_NEXT, "read");
    if (to_node(fd)) {
        const char *u = getenv("SLOWREAD_US");
        long        us = u != NULL ? atol(u) : 20000;
        struct timespec ts = { us / 1000000, (us % 1000000) * 1000 };
        nanosleep(&ts, NULL);
    }
    return real_read(fd, buf, n);
}
