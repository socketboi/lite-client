/* What this client does when REALITY did not authenticate the node.
 *
 * Nothing, until now — the socket was closed and the failure reported. That is the one behaviour a
 * REALITY client must not have. The whole protocol is built so that a client which fails to
 * authenticate is INDISTINGUISHABLE from a browser that reached the site being masqueraded as: the
 * server, seeing a stranger, quietly proxies the real site, and the client is supposed to behave
 * like somebody who asked for it. A TLS 1.3 handshake followed by zero application bytes and an
 * immediate close is the opposite of that, and it is exactly what a probe looking for REALITY nodes
 * would measure.
 *
 * The reference does it in reality.go:183-274. On `!uConn.Verified` it starts an HTTP/2 client over
 * the SAME connection, fetches the masquerade site, harvests links, fetches more — and the comment
 * at the end of the goroutine says `// Do not close the connection`.
 *
 * WHAT THE DEFAULT CONFIGURATION ACTUALLY DOES, which is far less than the machinery suggests and
 * is what this file implements. SpiderY is ten integers filled only from query parameters on
 * spiderX, and spiderX defaults to "/" with no query
 * (vendor/Xray-core/infra/conf/transport_security.go:214-241), so all ten are zero. Then:
 *
 *   concurrency  RandBetween(0,0) = 0, so the parallel crawlers are never started
 *   times        the first pass is `times := 1` and only a later pass reads SpiderY, so: one request
 *   interval     zero, and nothing to space out anyway
 *   return       zero, so the caller does not wait before reporting the failure
 *   padding      RandBetween(0,0) = 0, so the padding cookie is present with an EMPTY value
 *
 * One GET per connection with a browser's headers, then the connection is left alone. Its path is
 * SpiderX on the first connection to a name and a harvested one after (reality/paths.h): the
 * harvest is not one of the passes above, it follows every read, the first included
 * (reality.go:271-277). The parallel passes and the repeats are not implemented, and that is a
 * statement rather than an omission: they are unreachable without a spiderX carrying `?c=` and
 * `?t=`, which nothing in this client's configuration can produce.
 *
 * The request is built here and driven by the caller, because the two callers drive sockets
 * differently and neither can be made to block on the other's terms. */
#ifndef LC_SPIDER_H
#define LC_SPIDER_H

#include "reality/browser.h"
#include "reality/paths.h"
#include "reality/url.h"
#include "tls/client.h"

#include <stddef.h>
#include <stdint.h>

/* What the reference makes of a request's URL once net/http hands it to x/net — the same for the
 * first request and for every redirect: the ClientConn it goes on, authorityAddr of its Host
 * (vendor/x-net/http2/transport_common.go:307-334); whether EncodeHeaders takes it — the Host
 * through PunycodeHostPort and ValidHostHeader, the :path its RequestURI through validPseudoPath
 * (vendor/x-net/internal/httpcommon/request.go:76-115), failing which the ClientConn is made and no
 * HEADERS go out on it; and the Authorization header send adds to a clone of the header map when
 * the URL carries userinfo (GOROOT/src/net/http/client.go:253-258). */
typedef struct {
    int    headers;       /* EncodeHeaders takes it, and HEADERS are written */
    lc_str authority;     /* :authority */
    lc_str path;          /* :path */
    lc_str key;           /* authorityAddr of the Host: where RoundTripOpt looks for a ClientConn */
    lc_str pool;          /* authorityAddr of canonicalAddr, the address net/http dials: where
                           * AddConn files the ClientConn it dials */
    lc_str authorization; /* "Basic " and base64 of "user:password"; empty without userinfo */
} lc_spider_req;

void lc_spider_req_free(lc_spider_req *q);

/* What the reference makes of "https://" + host + a stored path: `http.NewRequest` parses it
 * (reality.go:220, :231, :241; GOROOT/src/net/http/request.go), takes an empty port off the Host
 * (removeEmptyPort), and the request goes as above. The stored path is `sn` bytes, any bytes. `*url`
 * receives the request's URL and `*q` what x/net makes of it, both for LC_SPIDER_PREFACE and
 * LC_SPIDER_REQUEST; both are freed first. -1 without memory. Held to Go by tools/spiderurl. */
enum {
    LC_SPIDER_REQUEST = 0, /* a GET */
    LC_SPIDER_PREFACE = 1, /* the connection's opening goes out and no request follows it */
    LC_SPIDER_NONE = 2,    /* NewRequest fails: nothing is dialled and nothing is written */
};

int lc_spider_target(const char *host, const char *stored, size_t sn, lc_url *url, lc_spider_req *q);

/* ---- redirects ------------------------------------------------------------------------------
 *
 * What http.Client makes of a Location: the URL `req.URL.Parse(loc)` gives
 * (GOROOT/src/net/http/client.go:655-666); whether the transport takes it at all — https only
 * (vendor/x-net/http2/transport_wrap.go:213-215, GOROOT/src/net/http/transport.go:611-770); and
 * the request above. Held to Go's own net/http, net/url and x/net by tools/redirurl. Which
 * connection the request then goes out on — the base's, a new one, or none, the connection closed
 * — is not decided here but by the pool (reality/fetch.c, get_client_conn, held by
 * tools/spiderpool); `same` and the two outcomes below say only what the request's own key says. */
enum {
    LC_REDIR_NONE = 0,    /* the Location does not parse: Do returns an error, nothing more is sent */
    LC_REDIR_SCHEME = 1,  /* not https: x/net refuses it before dialling, nothing is sent */
    LC_REDIR_PREFACE = 2, /* another key, and a request x/net refuses: no HEADERS follow */
    LC_REDIR_REQUEST = 3, /* the base's key (`same`), or a request with HEADERS — unless
                           * `req.headers` is 0, which is the same refusal on the base's key */
};

typedef struct {
    int           outcome;
    int           same;    /* the new request's key is the base's */
    int           strip;   /* the cookie is left behind, by this hop or an earlier one */
    lc_str        url;     /* the new request's URL.String() */
    lc_str        referer; /* refererForURL: the new request's Referer, empty for none */
    lc_spider_req req;
} lc_redir;

void lc_redir_free(lc_redir *r);

/* The hop after `base` — the request whose answer carried the `ln` bytes of `location` — in a
 * fetch whose first request was `first` and whose cookie an earlier hop has left behind when
 * `stripped`. `next` receives the new request's URL and `r` the rest; both are freed first. 0, or -1
 * without memory. */
int lc_redirect(const lc_url *first, int stripped, const lc_url *base, const char *location,
                size_t ln, lc_url *next, lc_redir *r);

/* Everything that goes out before the answer: the connection preface, our SETTINGS, the connection
 * window and one GET that ends the stream. `host` is the server name the handshake used, which is
 * what the reference builds its URL from — and, usually, the :authority.
 *
 * Returns the length written: 0 when the reference would write nothing at all, exactly `*opening`
 * when it would write only the connection's opening (see lc_spider_target), or -1 if it does not
 * fit or no randomness could be had.
 *
 * `*opening` receives how much of it is the connection's opening — preface, SETTINGS and
 * WINDOW_UPDATE — which goes out as a write of its own, the request after it as another. Go's client
 * flushes the first when it makes the connection and the second when it sends the request
 * (vendor/x-net/http2/transport.go:539-543, :1440-1461), so the reference's spider shows two records
 * where one buffer written at once shows one. */
long lc_spider_request(const char *host, const lc_browser *b, uint8_t *out, size_t cap,
                       size_t *opening);

/* ---- the fetch ---------------------------------------------------------------------------------
 *
 * The whole of what the reference does on the connection: its first request, then x/net's
 * ClientConns reading every frame the site sends and Go's http.Client.Do following redirects — the
 * next HEADERS on the same connection, or a second opening for another host, and the retries x/net
 * makes — up to the page, whose links are harvested (reality/fetch.c). A machine without a socket:
 * the caller feeds it the application data it decrypts and writes what it hands back, one record
 * per write. */
typedef struct lc_spider_fetch lc_spider_fetch;

/* Starts one: the pool dials, and the connection's opening waits to be written. In completion mode
 * its readLoop starts only when that opening Write completes, not when take transfers the bytes.
 * The first request
 * goes out at the first lc_spider_fetch_settle — its doRequest's turn — which the caller makes once
 * it has fed whatever had already arrived, as the reference's readLoop reads that first. NULL when no
 * memory or no randomness could be had: the spider then sends nothing, as a request that did not
 * build sends nothing. */
lc_spider_fetch *lc_spider_fetch_new(const char *host, const lc_browser *b);
void             lc_spider_fetch_free(lc_spider_fetch *f);

/* Public operations below are serialized by the fetch's mutex. feed has one producer (input order
 * remains the caller's responsibility); take has one consumer. No socket I/O occurs under the lock.
 * Construction happens before publication. Before free, the owner must stop and join every user:
 * the operation lock protects state, not lifetime. This does not reproduce Go scheduling by itself. */

/* Removes one complete TLS Write from the queue and returns its length. Outside barrier mode a
 * successful take notifies a waiting consumer; barrier mode waits for actual completion. *out is an independently
 * allocated copy owned by the caller, who must free it. Returns 0 with *out NULL when empty, -1 on
 * failure; allocation failure leaves the write queued. This ownership transfer does not itself
 * replace the owner's obligation to join users before destroying the fetch. */
long lc_spider_fetch_take(lc_spider_fetch *f, uint8_t **out);

/* Application data from the connection, in order and in any pieces — a frame may span records.
 * In barrier mode consult read_ready before opening another TLS record: a blocked readLoop retains
 * a writing frame behind a body-credit Flush's cc.wmu until that owner's Write completes, and
 * also behind single/multi-frame request or writing-cleanup owners; their final Write id
 * releases the owner, independently of unrelated queue contents. The feed retains
 * the unread tail of one accepted feed, not a queue of later feeds. In split mode
 * it may also return at a frame boundary so the TLS owner can service queued output;
 * read_step resumes those buffered bytes without waiting for producer completion. -1
 * once x/net has closed the connection — a readLoop's error, or a connection gone idle after a
 * GOAWAY: the caller takes what is left to write, then closes it as tls.Conn.Close does. */
int lc_spider_fetch_feed(lc_spider_fetch *f, const uint8_t *data, size_t len);

/* The consumer turn: reads a body notified by feed, then advances Do and request cleanup. feed does
 * not consume body bytes itself. The synchronous diagnostic spider_run driver calls this after
 * input and at retry deadlines; it does not acknowledge actual socket Write completion.
 * Returns -1 as for feed. */
int lc_spider_fetch_settle(lc_spider_fetch *f, uint64_t now_ms);

/* Consumer continuation: at most one Do transition and one successful body Read per call, accounted and harvested before
 * returning. 1 means yielded with work potentially remaining: call step again without waiting for
 * a new input generation. 0 means the current turn completed or waits for input/retry; -1 means
 * failure. Barrier mode also resumes one natural request frame batch or one stream cleanup;
 * it preserves bufio Write boundaries and waits for owner-specific completion. Encoded headers,
 * body pipes and harvested paths still grow with their content, as in the reference.
 * Use one consumer, never drive settle and step concurrently as independent consumers. */
int lc_spider_fetch_step(lc_spider_fetch *f, uint64_t now_ms);

/* Enable before publishing the fetch or taking any writes. In this explicit driver mode step
 * returns 2 when the next operation waits for Write completion. A foreign readLoop Write does not
 * block non-writing Do/body work or completion of a body Read whose own Write was acknowledged.
 * take transfers at most one write
 * until write_complete is called; taking is NOT completion. Do not use settle in this mode.
 * Multi-frame requests retain their block/offset, cleanup retains its final Write id, and a
 * readLoop that wrote protocol output waits for its final Write before processing another frame.
 * Flow-credit Reads retain an owned result and final Write id: pipe consumption/accounting happens
 * once, but the source returns its bytes only after that Flush completes, including gzip WAIT.
 * Cleanup and split request tasks use their own ClientConn's writer predicate; a foreign
 * ClientConn's Write does not block their local acquisition. Other producer
 * resumptions retain a conservative queue
 * barrier. These contracts do not establish Go scheduler equivalence.
 * A driver must wait for actual write completion, not spin on step=2 or an expired retry timer. */
int lc_spider_fetch_write_barrier(lc_spider_fetch *f);

/* Optional split driver, enabled after write_barrier and BEFORE publication/take.
 * step/wait then drive only Do/body. The TLS owner drives read_step for retained
 * readLoop input, without Do's private lock. A separately
 * scheduled task must drive request_step/request_wait: writeRequest continuation
 * and cleanup never run on Do's stack or under do_lock. One driver per task;
 * neither task owns TLS/socket I/O. The protocol mutex still serializes shared
 * state, while private redirect work holds only Do's mutex.
 * Do queues owned fields, not writer ownership: request_step acquires the free
 * ClientConn writer before encoding. A readLoop ACK may acquire it first. The
 * opening Flush precedes initial admission; a later readLoop ACK does not block
 * that admission or allocate writer ownership on behalf of the request task.
 * After the previous Body.Close and cleanup finish, redirect admission likewise
 * does not wait for an unrelated Flush; encoding still takes its own cc.wmu.
 * Own opening/ACK/Flush ownership still blocks encoding; a foreign ClientConn's socket
 * Write only orders the queued output, not this writer's acquisition.
 * cleanup still waits for writeRequest to return, including this queued phase.
 * request_step returns 1 after one phase (continue without new input), 0 when
 * quiescent/stopped, -1 on failure. request_wait filters spurious/foreign wakes
 * by task readiness, has no Do retry timer, and returns 1 ready, 0 stopped or
 * normally completed, -1 failed. Normal completion requires Do to have returned
 * and every request producer/cleanup to have finished; readLoop stays alive.
 * stop interrupts BOTH tasks; join both before free.
 * Whole-Write completion only releases ownership and wakes cleanup in this
 * mode, never executes its pipe/forget/final phases inline. The legacy combined
 * step driver remains available for synchronous callers and existing fixtures.
 * Separate tasks do not themselves establish Go scheduling or resource parity. */
int lc_spider_fetch_request_tasks(lc_spider_fetch *f);
int lc_spider_fetch_request_step(lc_spider_fetch *f);
int lc_spider_fetch_request_wait(lc_spider_fetch *f);

/* Split mode only, one TLS/event-loop owner alongside feed/take/completion.
 * Resume already accepted frames/tail after producer progress or whole-Write
 * completion, before checking read_ready or waiting for more socket input.
 * After Do returns it also consumes deferred EOF once input and Writes drain.
 * Returns 1 after progress or a handoff to queued output (service take before
 * resuming), 0 quiescent/blocked/stopped, -1 failed/invalid mode.
 * Uses only the protocol mutex, never do_lock; does not execute Do/cleanup or
 * acknowledge writes. Completed Writes and stopped/error continuations must
 * still be driven explicitly. Calls without progress do not manufacture wakes.
 * This is not permission to open another TLS record while read_ready is false.
 * Drive this even while another goroutine's Write is pending: buffered frames
 * and the accepted tail advance until their own control/credit Write needs the
 * ClientConn writer. The readLoop's own Flush and opening still block it.
 * Stop/join all users before free. Legacy combined mode rejects this driver. */
int lc_spider_fetch_read_step(lc_spider_fetch *f);

/* Exactly once per positive take in barrier mode: success only after all bytes of that Write have
 * reached the socket. Error closes the fetch; completion wakes its consumer. The byte allocation
 * remains the caller's to free. Returns -1 for completion without an outstanding write.
 * Stop/join is still required before free, including when an outstanding write is abandoned. */
int lc_spider_fetch_write_complete(lc_spider_fetch *f, int success);

/* Independent consumer notification. Initialize *generation to zero, then preserve it across
 * calls. Returns 1 for the initial turn, new input/loss or the monotonic retry deadline, 0 after
 * stop (or normal Do completion in split mode), -1 on an error. Spurious wakeups
 * are filtered under the operation lock. A return of 1
 * permits the selected consumer driver (step in barrier mode, otherwise settle); it does not
 * grant TLS/socket ownership or acknowledge outgoing writes. Only one consumer may drive that
 * driver. Do not hold any driver lock while waiting. */
int lc_spider_fetch_wait(lc_spider_fetch *f, uint64_t *generation);

/* Permanently interrupts consumer waits, including stop-before-wait. Does not close TLS or the
 * fetch. The owner must stop, join every user, and only then free; stop alone does not join. */
void lc_spider_fetch_stop(lc_spider_fetch *f);

/* The connection's read failed — the site's EOF or close_notify, an alert, a record that would not
 * open: the error the read loop stops on. Its cleanup closes the connection and aborts every stream
 * the site had not finished — `case <-cs.peerClosed:` leaves one it had finished alone, and its body
 * still reads to EOF (vendor/x-net/http2/transport.go:1855-1863). So the caller settles what was fed first — a page
 * that ended in it is harvested as io.ReadAll harvests it — and only then calls this. */
void lc_spider_fetch_lost(lc_spider_fetch *f);

/* Worker-mode EOF handoff. Unlike lost(), this does not synchronously close streams: the sole
 * step consumer first processes every byte already supplied by feed, then applies the loss. */
void lc_spider_fetch_loss_pending(lc_spider_fetch *f);

/* When settle must run next whatever arrives — the end of a retry's backoff — or 0 for never. */
uint64_t lc_spider_fetch_deadline(lc_spider_fetch *f);

/* 1 once Do has returned — the page read, or the redirects given up — and 0 while it is still at
 * work. The connection outlives it: the reference keeps reading and answering the site. */
int lc_spider_fetch_done(lc_spider_fetch *f);

/* 0 when no ClientConn was ever made — NewRequest failed, or the first dial did — so that nothing
 * reads the connection at all, as nothing does in the reference. */
int lc_spider_fetch_reads(lc_spider_fetch *f);
/* Buffered input, including an I/O handoff or blocked writer, precedes another TLS record.
 * Service runnable output and drive read_step until readiness returns; a foreign socket Write
 * under backpressure does not prevent that read progress. No polling timer is needed. */
int lc_spider_fetch_read_ready(lc_spider_fetch *f);

/* Runs the fetch over an established connection — the request, the answers, the redirects the
 * reference would follow — until Do has returned or `deadline_ms` passes, whichever comes first.
 *
 * The body is read for its links, which go into the set the next connection to the name draws its
 * path from (reality/paths.h), and is not otherwise kept. Reading it is also what keeps the fetch a
 * fetch: a peer whose bytes are never collected is a peer that stops sending.
 *
 * THE SOCKET IS NOT CLOSED, and returning is not the same as being done with it: the caller closes
 * it, after the failure has been reported, in its own time. The reference is explicit about this —
 * `// Do not close the connection` — because a connection that ends the instant the page arrives is
 * itself a pattern.
 *
 * Returns 0 when the answer came, -1 when the connection would not carry it. Neither changes what
 * the caller does about the failed authentication: this is what it looks like while it does it. */
int lc_spider_run(lc_client *cl, int fd, const char *host, uint64_t deadline_ms);

#endif
