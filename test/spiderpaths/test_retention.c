/* Direct cache observations complement the public draw tests. A legal root draw
 * cannot tell whether harvesting committed: inspect membership and retained hashes
 * under the real store lock instead. The pinned reference keeps paths for the
 * process lifetime (vendor/Xray-core/transport/internet/reality/reality.go,
 * UClient's maps.maps and get closure, lines 198-257).
 *
 * Include the implementation only in this test; production has no observer API.
 * Forked producers exercise the same shared arena used by lc-tunnel workers.
 * This fixture is not a paired wire experiment or evidence of G2 acceptance. */
#include "../../src/reality/paths.c"

#include <sys/wait.h>
#include <unistd.h>

static const char host[] = "retention.example";
static int failures;

static void check(int pass, const char *message)
{
    printf("  %s  %s\n", pass ? "ok" : "FAIL", message);
    failures += !pass;
}

/* Do not draw to decide membership: an intact cache may legally draw root. */
static int observe(uint32_t expected, const uint64_t *original, uint64_t *save)
{
    if (store_lock() != 0)
        return 0;
    name_set *s = set_for(host);
    int good = s != NULL && s->count == expected;
    if (good && expected > 21u)
        good = find(s, (const uint8_t *)"/after-producer", 15u) >= 0;
    for (int i = 0; good && i < 21; i++) {
        char key[32];
        int n = i == 0 ? snprintf(key, sizeof key, "/") :
                         snprintf(key, sizeof key, "/h%d", i - 1);
        long at = find(s, (const uint8_t *)key, (size_t)n);
        if (at < 0) {
            good = 0;
            break;
        }
        uint64_t hash = AT(s->hash, uint64_t)[(size_t)at];
        if (original != NULL && original[i] != hash)
            good = 0;
        if (save != NULL)
            save[i] = hash;
    }
    store_unlock();
    return good;
}

static int feed(const char *page, int commit)
{
    lc_spider_sink *sink = lc_spider_sink_new(host);
    if (sink == NULL)
        return 0;
    size_t n = strlen(page), cut = n / 2u;
    lc_spider_sink_data(sink, (const uint8_t *)page, cut);
    lc_spider_sink_data(sink, (const uint8_t *)page + cut, n - cut);
    if (commit)
        lc_spider_sink_commit(sink);
    lc_spider_sink_free(sink);
    return 1;
}

static int wait_ok(pid_t child)
{
    int status;
    return child > 0 && waitpid(child, &status, 0) == child &&
           WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/* Reproduce publication boundaries under the real robust mutex. A worker exits
 * without unlocking, just as when it is killed between these stores. No public
 * observer or fault injection enters the production implementation. */
static int dead_owner(unsigned boundary)
{
    char name[64];
    snprintf(name, sizeof name, "dead-owner-%u.example", boundary);
    if (store_lock() != 0)
        return 0;
    name_set *s = set_for(name);
    int good = s != NULL;
    for (unsigned i = 0; good && i < 7u; i++) {
        char key[24];
        int n = snprintf(key, sizeof key, "/saved%u", i);
        good = add(s, (const uint8_t *)key, (size_t)n) == 0;
    }
    uint64_t hashes[8];
    if (good)
        memcpy(hashes, AT(s->hash, uint64_t), sizeof hashes);
    store_unlock();
    if (!good)
        return 0;

    fflush(NULL);
    pid_t child = fork();
    if (child == 0) {
        alarm(10);
        if (store_lock() != 0)
            _exit(1);
        s = set_for(name);
        if (boundary == 0u || boundary == 3u) {
            if (add(s, (const uint8_t *)"/pending", 8u) != 0)
                _exit(1);
            if (boundary == 0u)
                s->count--; /* table slot published, count not yet published */
        } else if (boundary == 1u) {
            size_t t = room(32u * sizeof(uint32_t));
            if (t == 0u)
                _exit(1);
            memset(AT(t, uint32_t), 0, 32u * sizeof(uint32_t));
            name_set next = *s;
            next.table = t;
            next.tcap = 32u;
            for (uint32_t i = 0; i < next.count; i++)
                table_put(&next, i);
            s->table = t; /* new table published, old mask still visible */
        } else if (boundary == 2u) {
            size_t h = room(16u * sizeof(uint64_t));
            if (h == 0u)
                _exit(1);
            memcpy(AT(h, uint64_t), AT(s->hash, uint64_t), sizeof hashes);
            s->hash = h; /* hash array moved, key array not moved yet */
        }
        _exit(0); /* deliberately keep the robust mutex owned */
    }
    if (!wait_ok(child))
        return 0;
    if (boundary == 4u) {
        child = fork();
        if (child == 0) {
            alarm(10);
            if (pthread_mutex_lock(&A->lock) != EOWNERDEAD)
                _exit(1);
            /* A second worker dies while clearing the derived lookup index. */
            memset(AT(s->table, uint32_t), 0, (size_t)s->tcap * sizeof(uint32_t));
            _exit(0);
        }
        if (!wait_ok(child))
            return 0;
    }
    if (store_lock() != 0)
        return 0;
    s = set_for(name);
    if (s == NULL) {
        store_unlock();
        return 0;
    }
    uint32_t expected = boundary == 3u ? 9u : 8u;
    good = s != NULL && s->count == expected &&
           memcmp(hashes, AT(s->hash, uint64_t), sizeof hashes) == 0 &&
           find(s, (const uint8_t *)"/", 1u) >= 0;
    for (unsigned i = 0; good && i < 7u; i++) {
        char key[24];
        int n = snprintf(key, sizeof key, "/saved%u", i);
        good = find(s, (const uint8_t *)key, (size_t)n) >= 0;
    }
    uint32_t occupied = 0;
    for (uint32_t i = 0; i < s->tcap; i++)
        occupied += AT(s->table, uint32_t)[i] != 0u;
    good = good && occupied == expected &&
           (find(s, (const uint8_t *)"/pending", 8u) >= 0) == (boundary == 3u);
    good = good && add(s, (const uint8_t *)"/pending", 8u) == 0 &&
           s->count == 9u && find(s, (const uint8_t *)"/pending", 8u) >= 0;
    store_unlock();
    return good;
}

static int unrecoverable_lock(void)
{
    fflush(NULL);
    pid_t child = fork();
    if (child == 0) {
        alarm(10);
        /* Isolate the deliberately poisoned mutex from the parent's cache. */
        A = NULL;
        A_shared = 0;
        if (lc_spider_paths_share() != 0)
            _exit(1);
        pid_t owner = fork();
        if (owner == 0)
            _exit(store_lock() == 0 ? 0 : 1);
        if (!wait_ok(owner) || pthread_mutex_lock(&A->lock) != EOWNERDEAD ||
            pthread_mutex_unlock(&A->lock) != 0)
            _exit(1);
        errno = 0;
        _exit(store_lock() != 0 && errno == ENOTRECOVERABLE ? 0 : 1);
    }
    return wait_ok(child);
}

int main(void)
{
    alarm(30);
    printf("spider cache: commit and retention, independently of selected paths\n");
    char *first = NULL;
    size_t len = 0;
    check(lc_spider_path(host, &first, &len) == 0 && len == 1u &&
          first != NULL && strcmp(first, "/") == 0, "fresh cache contains root");
    free(first);

    char page[1024];
    size_t used = 0;
    for (int i = 0; i < 20; i++)
        used += (size_t)snprintf(page + used, sizeof page - used,
                                 "<a href=\"/h%d\">x</a>", i);
    check(feed(page, 0), "a complete-looking body can be discarded without commit");
    if (store_lock() != 0)
        return 1;
    name_set *fresh = set_for(host);
    check(fresh != NULL && fresh->count == 1u,
          "discarding an uncommitted body adds no paths");
    store_unlock();

    uint64_t original[21];
    check(feed(page, 1) && observe(21u, NULL, original),
          "commit inserts all twenty links and retains root");
    if (failures != 0)
        return 1;
    check(feed(page, 1) && observe(21u, original, NULL),
          "duplicate commit and sink destruction preserve every key and hash");
    int share_rc = lc_spider_paths_share();
    if (share_rc != 0)
        fprintf(stderr, "shared cache initialization: %s (errno=%d)\n", strerror(errno), errno);
    check(share_rc == 0 && observe(21u, original, NULL),
          "moving a populated cache into shared memory retains membership and hashes");
    if (failures != 0)
        return 1;

    /* This child commits after fork. A private arena would pass its own check but
     * fail the parent's, so the assertion detects a process-local fallback. */
    fflush(NULL);
    pid_t producer = fork();
    if (producer == 0) {
        alarm(15);
        int good = observe(21u, original, NULL) &&
                   feed("<a href=\"/after-producer\">x</a>", 1) &&
                   observe(22u, original, NULL);
        _exit(good ? 0 : 1);
    }
    check(wait_ok(producer), "forked producer commits and exits successfully");
    check(observe(22u, original, NULL),
          "producer exit leaves its commit visible to the parent");
    check(lc_spider_paths_share() == 0 && observe(22u, original, NULL),
          "repeating shared initialization preserves the producer's commit");

    fflush(NULL);
    pid_t reader = fork();
    if (reader == 0) {
        alarm(15);
        _exit(observe(22u, original, NULL) ? 0 : 1);
    }
    check(wait_ok(reader), "a later worker sees the previous worker's committed cache");

    /* Concurrent inserts cross several key-array/hash-table growth boundaries.
     * Every worker repeats its page; no key may be lost or counted twice. */
    pid_t workers[4];
    fflush(NULL);
    for (int worker = 0; worker < 4; worker++) {
        workers[worker] = fork();
        if (workers[worker] == 0) {
            alarm(15);
            char links[1024];
            size_t at = 0;
            for (int i = 0; i < 20; i++)
                at += (size_t)snprintf(links + at, sizeof links - at,
                                      "<a href=\"/worker%d/%d\">x</a>", worker, i);
            _exit(feed(links, 1) && feed(links, 1) ? 0 : 1);
        }
    }
    for (int worker = 0; worker < 4; worker++)
        check(wait_ok(workers[worker]), "concurrent producer finishes both commits");
    check(observe(102u, original, NULL),
          "four concurrent producers retain root, old hashes and eighty unique new links");
    if (store_lock() != 0)
        return 1;
    name_set *s = set_for(host);
    int all = s != NULL;
    for (int worker = 0; all && worker < 4; worker++)
        for (int i = 0; all && i < 20; i++) {
            char key[32];
            int n = snprintf(key, sizeof key, "/worker%d/%d", worker, i);
            all = find(s, (const uint8_t *)key, (size_t)n) >= 0;
        }
    store_unlock();
    check(all, "direct membership confirms every concurrent link, without random sampling");
    check(dead_owner(0u), "owner death before count publication discards an uncommitted lookup slot");
    check(dead_owner(1u), "owner death between table and mask publication preserves every old key");
    check(dead_owner(2u), "owner death between array moves preserves every old hash and key");
    check(dead_owner(3u), "owner death after count publication preserves the completed insertion");
    check(dead_owner(4u), "a second owner death during recovery still preserves every committed key");
    check(unrecoverable_lock(), "an unrecoverable mutex is an explicit error, never unlocked cache access");
    printf("spider cache retention: %s\n", failures ? "FAIL" : "PASS");
    return failures != 0;
}
