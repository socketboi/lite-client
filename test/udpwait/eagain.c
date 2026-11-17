/* LD_PRELOAD: every third datagram this process sends to anything but the node's port 4443 fails
 * with EAGAIN, as a full send buffer would make it fail on a slow LAN. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static ssize_t (*real_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
static unsigned calls;

ssize_t sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *to,
               socklen_t tolen)
{
    int       type = 0;
    socklen_t sl = sizeof type;

    if (real_sendto == NULL)
        real_sendto = (ssize_t (*)(int, const void *, size_t, int, const struct sockaddr *,
                                   socklen_t))dlsym(RTLD_NEXT, "sendto");
    unsigned port = to == NULL                ? 0u
                    : to->sa_family == AF_INET  ? ntohs(((const struct sockaddr_in *)to)->sin_port)
                    : to->sa_family == AF_INET6 ? ntohs(((const struct sockaddr_in6 *)to)->sin6_port)
                                                : 0u;
    if (port != 0u && port != 4443u &&
        getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &sl) == 0 && type == SOCK_DGRAM &&
        ++calls % 3u == 0u) {
        static int said;
        if (!said) {
            static const char msg[] = "eagain.so: failing a send\n";
            said = 1;
            (void)write(2, msg, sizeof msg - 1);
        }
        errno = EAGAIN;
        return -1;
    }
    return real_sendto(fd, buf, len, flags, to, tolen);
}
