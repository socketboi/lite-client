/* Local, bounded crash evidence for the existing router diagnostic outbox.
 * No network I/O, command invocation, config or credentials enter these files.
 * Only the supervisor writes, after waitpid and before any replacement fork. */
#ifndef LC_WORKER_EVENT_H
#define LC_WORKER_EVENT_H
#include "core/rnd.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static void lc_worker_event(int status, const char *version, unsigned long long uptime, const char *plane)
{
    static unsigned sequence;
    const char *directory = getenv("LC_EVENT_DIR");
    if (!directory || !*directory)
        return;
    if (strcmp(plane, "reality") != 0 && strcmp(plane, "hysteria") != 0)
        return;
    if (!*version || strlen(version) > 80 ||
        strspn(version, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-") != strlen(version))
        return;
    int dir = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat info;
    if (dir < 0)
        return;
    if (fstat(dir, &info) != 0 || info.st_uid != getuid() || (info.st_mode & 077) != 0) {
        close(dir);
        return;
    }
    unsigned char random[16];
    if (lc_rnd(random, sizeof(random)) != 0) {
        close(dir);
        return;
    }
    random[6] = (unsigned char)((random[6] & 15u) | 64u);
    random[8] = (unsigned char)((random[8] & 63u) | 128u);
    char uuid[37], *p = uuid;
    for (unsigned i = 0; i < 16; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10)
            *p++ = '-';
        (void)snprintf(p, 3, "%02x", (unsigned)random[i]);
        p += 2;
    }
    const char *pending = ".event.pending";
    char target[32];
    /* Retain earlier evidence across supervisor respawns until the bounded
     * queue fills. A new supervisor must not overwrite slot zero immediately. */
    for (unsigned attempt = 0; attempt < 64u; attempt++) {
        (void)snprintf(target, sizeof(target), "worker-%u.json", sequence++ % 64u);
        struct stat occupied;
        if (fstatat(dir, target, &occupied, AT_SYMLINK_NOFOLLOW) != 0)
            break;
    }
    /* One supervisor owns this queue. A fixed staging slot also bounds debris
     * if that supervisor is killed between creating and publishing a record. */
    (void)unlinkat(dir, pending, 0);
    int fd = openat(dir, pending, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd >= 0) {
        const char *identity = getenv("LC_CLIENT_ID");
        unsigned long client_id = 0;
        if (identity && *identity && strlen(identity) <= 10u &&
            strspn(identity, "0123456789") == strlen(identity)) {
            client_id = strtoul(identity, NULL, 10);
            if (client_id > 2147483647ul)
                client_id = 0;
        }
        char record[320];
        int length = snprintf(record, sizeof(record),
            "{\"id\":\"%s\",\"version\":\"%s\",\"plane\":\"%s\",\"clientId\":%lu,\"uptime\":%llu,\"exitCode\":%d,\"exitSignal\":%d}\n",
            uuid, version, plane, client_id, uptime, WIFEXITED(status) ? WEXITSTATUS(status) : 0,
            WIFSIGNALED(status) ? WTERMSIG(status) : 0);
        int complete = length > 0 && (size_t)length < sizeof(record) && write(fd, record, (size_t)length) == length;
        if (close(fd) != 0)
            complete = 0;
        if (complete)
            (void)renameat(dir, pending, dir, target);
        (void)unlinkat(dir, pending, 0);
    }
    close(dir);
}
#endif
