#ifndef LC_REALITY_PATHS_H
#define LC_REALITY_PATHS_H

#include <stddef.h>
#include <stdint.h>

/* The paths the spider asks for, which after the first page are not the one it was configured with.
 *
 * WHAT THE REFERENCE DOES. Its map of paths is PACKAGE-LEVEL — `var maps struct{ sync.Mutex; maps
 * map[string]map[string]struct{} }` (vendor/Xray-core/transport/internet/reality/reality.go:308-310)
 * — so it outlives the connection that filled it. A stranger connection seeds the set for its
 * ServerName with SpiderX, draws its request path from the set, reads the answer, and adds every
 * href the page carried (reality.go:220-231, :269-275). The NEXT stranger connection therefore asks
 * for a path the site really has, drawn at random, rather than for SpiderX again.
 *
 * That is reachable at this client's configuration, and the measurement is what said so: SpiderY is
 * all zeros, which makes it one fetch per connection and no concurrency — but a single refused
 * request dials five times, and tools/vendorcap/spiderlife saw the reference ask for `/`, `/two`,
 * `/two`, `/three`, `/` while this client asked for `/` five times. A node that answers as a
 * stranger sees the difference without decrypting anything.
 *
 * AS THE REFERENCE HOLDS THEM: a set per ServerName, as many paths as the pages carry, each as long
 * as it is and holding whatever bytes the match took — a NUL, a tab, anything but a newline — for as
 * long as the process runs. The limit is the memory the process has, as it is the reference's.
 *
 * The body is scanned as io.ReadAll returns it: the text, which for a gzip answer x/net's gzipReader
 * has already inflated — the fetch reads it through the same reader (reality/fetch.c, core/gozip)
 * and hands the sink what came out, never holding the page. */

/* The path for the next request to this name: SpiderX until a page has been read, a draw over
 * everything harvested since — a copy, `*len` bytes and a NUL after them, which the caller frees;
 * copied because the set may live in memory other processes write to (see lc_spider_paths_share).
 * -1 when the draw itself failed, or no memory could be had, which ends the request the same way a
 * failed shuffle does — an unrandomised choice is the mark this exists to remove. */
int lc_spider_path(const char *host, char **out, size_t *len);

/* Moves the sets into memory that processes forked after this call share, behind a process-shared
 * lock: the reference's one map per process, for a client that is several processes. lc-tunnel
 * calls it before it forks its workers. -1 with errno set when the memory or the lock could not be
 * had; the sets then stay this process's own, and each worker harvests for itself. */
int lc_spider_paths_share(void);

/* The answer's body, fed as it arrives and never held.
 *
 * One sink per connection, because a client that dials a stranger five times has five of these in
 * flight; the harvest they share is the sets above — one for the whole program, workers included —
 * which is what the reference shares too. */
typedef struct lc_spider_sink lc_spider_sink;

lc_spider_sink *lc_spider_sink_new(const char *host);
void            lc_spider_sink_data(lc_spider_sink *sink, const uint8_t *data, size_t len);
void            lc_spider_sink_free(lc_spider_sink *sink);

/* The page has been read to its end: what it links to goes into the set. Until this is called
 * nothing does — see paths.c. */
void lc_spider_sink_commit(lc_spider_sink *sink);

#endif
