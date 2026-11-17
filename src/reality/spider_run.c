/* Driving the spider over a socket, kept apart from building its request.
 *
 * The split is not tidiness: the request is bytes and can be checked without a network, a
 * record layer or mbedTLS, and test/spider does exactly that. This half needs all three, and
 * a test that had to link them to assert a frame layout would be asserting the frame layout
 * through three modules that have nothing to do with it. */
#include "reality/spider.h"

#include "reality/paths.h"

#include "core/rnd.h"
#include "h2/frame.h"
#include "net/sock.h"
#include "tls/record.h"

#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---- driving it over an established connection ------------------------------ */

/* One Write out, in records of at most a full plaintext each — not the tunnel's record sizing
 * (lc-tunnel's tls_write, the reference's writeRecordLocked); these are the diagnostic tools'. */
static int send_record(lc_client *cl, int fd, const uint8_t *data, size_t len, uint64_t deadline)
{
    static uint8_t rec[LC_REC_MAX_WIRE];
    while (len > 0u) {
        size_t n = len < LC_REC_MAX_PLAINTEXT ? len : LC_REC_MAX_PLAINTEXT;
        size_t rec_len = 0;
        if (lc_record_protect(&cl->wr, LC_REC_APPLICATION_DATA, data, n, 0, rec, sizeof rec,
                              &rec_len) != 0 ||
            lc_write_full(fd, rec, rec_len, deadline) != 0)
            return -1;
        data += n;
        len -= n;
    }
    return 0;
}

/* What the fetch has to write, a record each — see lc_spider_fetch_take. */
static int drain(lc_spider_fetch *f, lc_client *cl, int fd, uint64_t deadline)
{
    uint8_t *w;
    long           n;
    while ((n = lc_spider_fetch_take(f, &w)) > 0) {
        int rc = send_record(cl, fd, w, (size_t)n, deadline);
        free(w);
        if (rc != 0)
            return -1;
    }
    return n < 0 ? -1 : 0;
}

int lc_spider_run(lc_client *cl, int fd, const char *host, uint64_t deadline_ms)
{
    /* ONE IDENTITY FOR THE PROCESS, not one per connection.
     *
     * What stood here said the opposite — "it is drawn per connection in the reference too … a
     * client whose version never moved would be a client with one identity" — and the reference
     * says the reverse in three lines of package-level initialisation
     * (vendor/Xray-core/common/utils/browser.go:155-157). One identity is precisely what an Xray
     * process has, and having a new one every few seconds is what no browser has. See
     * lc_browser_chrome_anchored. */
    lc_browser b;
    if (lc_browser_chrome_anchored(&b, LC_BROWSER_NAV) != 0)
        return -1;

    /* The reference's client on this connection: its first request, the answers read, redirects
     * followed, the page harvested — see reality/fetch.c. Its first writes are two records: the
     * connection's opening, which newClientConn flushes when it makes the connection, now; then the
     * request, which writeHeaders flushes (vendor/x-net/http2/transport.go:539-543, :1440-1461),
     * at the first settle below. Fewer when the reference writes fewer. */
    lc_spider_fetch *f = lc_spider_fetch_new(host, &b);
    if (f == NULL || drain(f, cl, fd, deadline_ms) != 0) {
        lc_spider_fetch_free(f);
        return -1;
    }

    /* And read until Do has returned: the page read, or the redirects given up. Do and the
     * doRequests act when the socket has nothing more waiting — the nearest this blocking reader
     * has to the end of a read — which the first time round is the first request's turn. */
    int rv = -1;
    for (;;) {
        struct pollfd p = { .fd = fd, .events = POLLIN };
        if (poll(&p, 1, 0) == 0) {
            int rc = lc_spider_fetch_settle(f, lc_now_ms());
            if (drain(f, cl, fd, deadline_ms) != 0 || rc != 0)
                break;
        }
        if (lc_spider_fetch_done(f)) {
            rv = 0;
            break;
        }
        if (lc_now_ms() >= deadline_ms) {
            rv = 0; /* out of time is not out of order: what arrived, arrived */
            break;
        }

        static uint8_t rec[LC_REC_MAX_WIRE];
        if (lc_read_full(fd, rec, LC_REC_HEADER, deadline_ms) != 0)
            break;
        size_t body = (size_t)rec[3] << 8 | rec[4];
        if (body > sizeof rec - LC_REC_HEADER)
            break;
        if (lc_read_full(fd, rec + LC_REC_HEADER, body, deadline_ms) != 0)
            break;

        static uint8_t plain[LC_REC_MAX_OPEN];
        size_t         plain_len = 0;
        uint8_t        inner = 0;
        if (lc_record_unprotect(&cl->rd, rec, LC_REC_HEADER + body, plain, sizeof plain, &plain_len,
                                &inner) != 0)
            break;
        if (inner == LC_REC_APPLICATION_DATA) {
            int rc = lc_spider_fetch_feed(f, plain, plain_len);
            if (drain(f, cl, fd, deadline_ms) != 0 || rc != 0)
                break; /* x/net closed the connection, its writes out first */
        }
    }
    lc_spider_fetch_free(f);
    return rv;
}
