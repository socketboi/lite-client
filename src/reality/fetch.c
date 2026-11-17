/* The spider's HTTP/2 client and the http.Client.Do around it, over the connection a stranger's
 * handshake left open (vendor/Xray-core/transport/internet/reality/reality.go:207-299).
 *
 * The reference runs a whole client there: http.Client.Do following redirects over x/net's
 * http2.Transport, whose dialer hands back this one TLS connection every time it is asked for one.
 * Xray v26.9.9 is built with Go 1.27, and under Go 1.27 x/net's Transport is a shim over net/http's
 * own HTTP/2 client (x/net's transport_wrap.go, GOROOT/src/net/http/internal/http2). That client is
 * x/net's line for line but in four places — GOAWAY on an idle connection, a window SETTINGS
 * overflows, trailers past the header limit, and who dials — and those four follow Go 1.27 here and
 * cite GOROOT; everything else cites vendor/x-net/http2, which is the same code and which the cite
 * checks can read. This is that client as a machine without a socket — decrypted records in, the
 * reference's writes out — and it is net/http's, part for part:
 *
 *   the Transport   a pool of ClientConns keyed by authorityAddr (client_conn_pool.go), a dial per
 *                   miss — and every dial is a new ClientConn on the same TLS connection, its opening
 *                   in the middle of the stream — and RoundTripOpt's retries with their backoff on
 *                   one ClientConn, a new one dialled at once when that one is gone (see attempt);
 *   a ClientConn    its encoder and decoder, windows, settings, streams, the rules on which it takes
 *                   a request (idleStateLocked), and the close when it goes idle after a GOAWAY
 *                   (forgetStreamID) (transport.go);
 *   its readLoop    a bufio.Reader of 4096 over the TLS connection and a Framer over that — several
 *                   readLoops take turns at the one connection's reads (see readers_feed);
 *   its writer      a bufio.Writer of 4096 flushed after each operation, which is what cuts the
 *                   records the reference writes;
 *   a body          the pipe a response's DATA goes into, transportResponseBody's reads and Close,
 *                   and — for a gzip answer — x/net's gzipReader over it, which is compress/gzip,
 *                   compress/flate and bufio as Go reads (core/gozip);
 *   Do              redirects, the slurp, Close, the referer, the header copy, checkRedirect
 *                   (GOROOT/src/net/http/client.go), and the spider's io.ReadAll and harvest.
 *
 * THE ORDER OF GOROUTINES IS THE MODEL (a model: DIVERGES: G2), and it is stated once here. A
 * readLoop processes each frame the moment its bytes are in (lc_spider_fetch_feed). DATA and stream
 * endings notify the body's consumer. In the tunnel an independent Do worker uses wait/step to
 * run body reads, gzip and harvest; a separate request task drives header encoding, request
 * continuation and cleanup without taking Do's private-work lock. Write completion wakes that
 * task rather than executing cleanup inline. The event loop alone owns socket/TLS and feeds input. Public
 * operations serialize shared protocol state under the fetch mutex, never socket waits. Do's
 * URL/header preparation runs outside it, under a separate consumer guard; stop/error is checked
 * again before the prepared result is published. The
 * completion barrier pauses an operation that waits for its actual Write, not unrelated reads.
 * The diagnostic settle driver remains synchronous and cannot be mixed with that barrier.
 * Request production yields at a natural Framer boundary; pending request/cleanup/readLoop
 * Writes retain their owner and id until actual completion. This is not Go scheduler equivalence:
 * non-writing Do/body work may run behind a readLoop Write; cleanup acquires its own cc.wmu
 * independently of another ClientConn's socket Write, as do requests and body-credit writers.
 * Later Do attempts and other producer resumptions still use
 * a conservative output barrier. Measured cancellation differs (DIVERGES: G2).
 * See docs/TESTING.md for the measured sample and remaining lifecycle acceptance criteria. */
#include "reality/spider.h"

#include "reality/paths.h"
#include "reality/url.h"

#include "core/gomap.h"
#include "core/gozip.h"
#include "core/rnd.h"
#include "h2/frame.h"
#include "h2/hpack.h"
#include "h2/xhttp.h"

#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


/* The browser's fourteen headers and the cookie: req.Header. Four pseudo-headers, those, a referer,
 * an authorization and accept-encoding. */
#define FETCH_KEYS   (LC_BROWSER_HEADERS + 1u)
#define FETCH_FIELDS (4u + FETCH_KEYS + 3u)

/* maxBodySlurpSize = 2 << 10 (GOROOT/src/net/http/client.go:725); defaultCheckRedirect's
 * len(via) >= 10 (GOROOT/src/net/http/client.go:845-850); roundTripViaPool's retries while
 * retry <= 6 (vendor/x-net/http2/transport_common.go:347). */
#define FETCH_SLURP 2048u
#define FETCH_HOPS  10u
/* RoundTripOpt's `retry <= 6` on one ClientConn; a new one starts the count again — see attempt. */
#define FETCH_TRIES 6u

/* x/net's numbers (vendor/x-net/http2): Transport.maxHeaderListSize() with MaxHeaderListSize zero,
 * which is also what the Framer and the decoder's SetMaxStringLength get
 * (vendor/x-net/http2/transport.go:83-97, :515-516, vendor/x-net/http2/frame.go:1695-1702); the
 * concurrency a ClientConn assumes before and after the peer's first SETTINGS
 * (initialMaxConcurrentStreams, defaultMaxConcurrentStreams); a bufio of 4096 each way
 * (vendor/x-net/http2/transport.go:503-508). */
#define H2_MAX_HLS         LC_H2_MAX_HEADER_LIST
#define H2_INIT_STREAMS    100u
#define H2_DEFAULT_STREAMS 1000u
#define H2_BUFIO           4096u

#define H2_CONTINUATION 0x9u
#define H2_PRIORITY     0x2u
#define H2_PUSH_PROMISE 0x5u

#define ERR_NO       0x0u
#define ERR_PROTOCOL 0x1u
#define ERR_FLOW     0x3u
#define ERR_REFUSED  0x7u
#define ERR_CANCEL   0x8u

/* Why a stream was aborted — the error its abortErr would be, as far as what follows depends on it:
 * whether it is a StreamError, whose code is written in RST_STREAM unless the peer sent it, and
 * whether RoundTrip retries it (canRetryError, vendor/x-net/http2/transport_common.go:427-435). */
enum {
    AB_STREAM = 1, /* StreamError of ours: RST_STREAM with its code */
    AB_PEER,       /* StreamError from the peer's RST_STREAM: nothing written back */
    AB_GOAWAY,     /* errClientConnGotGoAway: retried on another connection */
    AB_GOAWAY_1,   /* "received GOAWAY from server": the first stream, a non-NO code — not retried */
    AB_CLOSED,     /* errClosedResponseBody: the body was closed */
    AB_LOST,       /* the connection ended under it */
    AB_UNUSABLE,   /* errClientConnUnusable: retried */
    AB_NOT_EST,    /* errClientConnNotEstablished: not retried, the connection marked dead */
    AB_FAILED,     /* any other error: an encoding refusal, a body longer than it said */
};

/* What a response's Body is (handleResponse, vendor/x-net/http2/transport.go:2046-2106). */
enum {
    BODY_NONE,    /* noBody: END_STREAM on the HEADERS, no length said */
    BODY_MISSING, /* missingBody: END_STREAM with a length: io.ErrUnexpectedEOF */
    BODY_PIPE,    /* transportResponseBody over the stream's pipe */
};

typedef struct fetch_stream fetch_stream;
typedef struct fetch_cc     fetch_cc;

/* A header block being read: readMetaFrame's state across HEADERS and its CONTINUATIONs
 * (vendor/x-net/http2/frame.go:1707-1826), and what the answer's fields say. */
typedef struct {
    uint32_t stream;
    uint8_t  flags;  /* the HEADERS frame's: END_STREAM */
    uint64_t remain, trailer_remain; /* independent readMetaFrame budgets */
    int      invalid, truncated, saw_regular;
    uint64_t size;   /* the fields kept: for the 1xx limit */
    unsigned n_pseudo, pseudo_seen;
    int      is_req, is_resp, pseudo_bad;
    int      have_status, status_ok;
    long     status;
    int      have_loc;
    char    *location;
    size_t   location_len;
    unsigned n_clen;
    int      clen_ok;
    int64_t  clen;
    int      have_ce, ce_gzip;
    int      oom;
} fetch_meta;

/* A clientStream: one request and its answer. */
struct fetch_stream {
    fetch_stream *next;
    fetch_cc     *cc;
    uint32_t      id; /* 0 until addStreamLocked gave it one */
    int      sent_headers, sent_end_stream;
    int      past_headers, past_trailers;
    int      peer_closed; /* readClosed and peerClosed */
    int      read_aborted;
    int      abort, abort_kind;
    uint32_t abort_code;
    int      from_peer;
    int      resp;        /* respHeaderRecv */
    int      done;        /* cleanupWriteRequest has run: donec */
    int      forgotten;   /* out of cc.streams */
    uint64_t size_1xx;
    int64_t  out;         /* flow: our send window on it */
    int64_t  in_avail, in_unsent;
    /* The answer. */
    long     status;
    int64_t  length;      /* resp.ContentLength */
    int      gzip;
    int      body;
    char    *location;   /* the first Location, which is Header.Get's */
    size_t   location_len;
    /* The body: its pipe (vendor/x-net/http2/pipe.go) and what transportResponseBody keeps. */
    uint8_t  *pb;
    size_t    pb_off, pb_len, pb_cap;
    int       p_err;      /* p.err: LC_GZ_EOF at the end of the stream, LC_GZ_ERR for any other */
    int       p_break;    /* p.breakErr: the body was closed, what it held let go */
    int64_t   remain;     /* bytesRemain */
    int       read_err;   /* readErr */
    lc_gozip *gz;
    /* A transport body Read already consumed/accounted its pipe bytes, but its flow-credit
     * Flush has not returned. Own the bytes across feed reallocations and gzip WAIT. */
    uint8_t *source_read;
    size_t source_len;
    int source_err, source_pending, source_flushed;
    uint32_t source_conn_credit, source_stream_credit;
    uint64_t source_write_id;
    /* Body.Close broke the pipe and accounted unread bytes; its cc.wmu/Flush still waits. */
    uint32_t close_conn_credit;
    uint64_t close_write_id;
    int close_pending, close_flushed;
    int       doreq_blocked; /* its doRequest waits on a stuck writer for good */
    lc_hpack_field *request_fields; /* Owned array and strings until writer acquisition. */
    unsigned request_nfields;
    int request_headers_ok;
    uint8_t  *request_block;
    size_t    request_len, request_off;
    uint64_t request_write_id, cleanup_write_id;
    /* cleanupWriteRequest selects its reset before writeStreamReset acquires cc.wmu.
     * Peer completion while that acquisition waits must not rewrite the decision. */
    int cleanup_prepared, cleanup_reset, cleanup_ping;
    uint32_t cleanup_reset_code;
    int cleanup_pending;
    int cleanup_final_pending; /* Stream forgotten; final cc.wmu acquisition still waits. */
};

/* A ClientConn. */
struct fetch_cc {
    fetch_cc        *next;
    lc_spider_fetch *f;
    char            *key; /* its pool key: authorityAddr of the address dialled */
    int              in_pool;
    unsigned         seq; /* when its readLoop last asked for bytes */
    uint32_t         next_id;
    uint32_t         max_frame;
    uint32_t         max_streams;
    uint64_t         peer_max_hls;
    int64_t          out; /* flow: our connection send window */
    uint32_t         init_window;
    int              seen_settings, want_ack, got_settings;
    int              goaway;
    uint32_t         goaway_last, goaway_code;
    int              closed, do_not_reuse;
    int              werr; /* Sticky failure of this ClientConn's underlying Write. */
    unsigned         reserved, pending_resets;
    int              rst_pings_blocked;
    uint32_t         read_before;
    int64_t          in_avail, in_unsent;
    lc_hpack_enc     enc;
    lc_hpack_dec     dec;
    fetch_stream    *streams;
    fetch_meta       m;
    uint32_t         last_header_stream; /* checkFrameOrder */
    /* The readLoop: its bufio.Reader and the Framer's frame in progress. */
    uint8_t  rbuf[H2_BUFIO];
    size_t   rr, rw;
    int      direct; /* the pending Read goes straight into the payload */
    uint8_t  hdr[LC_H2_HEADER];
    size_t   hdr_have;
    int      in_payload;
    lc_h2_hd fh;
    uint8_t *payload;
    size_t   pay_have;
    /* Its bufio.Writer. */
    uint8_t wbuf[H2_BUFIO];
    size_t  wn;
    fetch_stream *request_pending; /* Owned fields awaiting the request task's cc.wmu entry. */
    fetch_stream *request_writer; /* Logical cc.wmu owner across header continuation Writes. */
    fetch_stream *source_writer; /* transportResponseBody.Read holds cc.wmu through its Flush. */
    fetch_stream *close_writer; /* Body.Close holds cc.wmu through its unread-credit Flush. */
    fetch_stream *cleanup_writer; /* cleanup's reset/Flush owns cc.wmu until its final Write. */
    int writer_wait; /* ReadFrame is complete; dispatch waits for that owner. */
    int read_pending; /* Runnable buffered input yielded to queued TLS output. */
    uint64_t read_write_id; /* Last Write of a readLoop operation: resume only on its completion. */
    uint64_t opening_write_id; /* newClientConn starts readLoop only after its opening Flush. */
    /* processData publishes/account its body before acquiring cc.wmu. Padding credit and the
     * frame's terminal actions resume here after the owner and then the resulting Flush. */
    fetch_stream *data_stream;
    uint32_t data_conn_credit, data_stream_credit;
    int data_pending, data_reset, data_end_stream;
    /* A writer stuck writing empty frames for good, holding cc.wmu — see round_trip — and the
     * readLoop blocked behind it. */
    int      stuck, reader_blocked;
    uint32_t spew_id;
    unsigned spew_phase;
};

/* What Do needs: the request's header map and its clones, the URLs, the hop, the retries, and the
 * reader of the body it is reading. Let go when Do returns. */
struct fetch_do {
    lc_browser     b;
    lc_hpack_field keys[FETCH_KEYS];
    unsigned       nkeys;
    lc_gomap       h;     /* the first request's req.Header */
    lc_gomap       clone; /* makeHeadersCopier's Header.Clone of it */
    unsigned       clone_from[LC_GOMAP_KEYS];
    int            hop;   /* the request is a redirect's: its header map is `hop_map` */
    lc_gomap       hop_map;
    unsigned       hop_from[LC_GOMAP_KEYS];
    int            hop_copied;
    /* A URL with userinfo: send's clone of the request's map, Authorization set on it. */
    int            auth;
    lc_gomap       auth_map;
    unsigned       auth_from[LC_GOMAP_KEYS];
    int            auth_copied;

    lc_url        first;      /* reqs[0].URL */
    lc_url        base, next; /* the request in flight, and the one after it */
    lc_spider_req q;          /* what x/net makes of the request in flight */
    lc_str        ref;        /* its Referer, empty for none */
    lc_redir      r;
    unsigned nreqs;                  /* len(reqs) */
    int      strip;                  /* stripSensitiveHeaders */
    int      check_err;              /* checkRedirect's error, returned after the Close */
    unsigned retry;                  /* roundTripViaPool's */
    uint64_t retry_at;
    fetch_stream *s;                 /* the request's stream on the attempt in flight */
    fetch_cc     *first_cc;          /* the first request's ClientConn, reserved at the dial */

    /* The body's reader: io.CopyN(io.Discard, body, 2048) or io.ReadAll. */
    int      rd;
    int      rd_done, rd_err;
    int64_t  limit;                  /* the LimitedReader's N */
    size_t   cap, len, next_cap;     /* io.ReadAll's slice and the size of the one after */
};

enum { RD_NONE, RD_SLURP, RD_ALL };

enum {
    DO_START,   /* the first RoundTrip: its ClientConn dialled, its doRequest not yet run */
    DO_ATTEMPT, /* RoundTrip: the request is out, its answer's HEADERS are not in */
    DO_RETRY,   /* RoundTrip: waiting out a backoff */
    DO_SLURP,   /* a redirect's body, read to two kilobytes */
    DO_CLOSE,   /* close the previous response body */
    DO_NEXT,    /* close completed: prepare and send the next request */
    DO_READ,    /* the page: io.ReadAll */
    DO_FINISH,  /* the page harvested; its deferred body Close still has to run */
    DO_END,     /* Do has returned */
};

typedef struct {
    size_t end;
    uint64_t id;
    fetch_cc *writer;
    fetch_cc *reader;
    fetch_stream *stream;
    int ctx;
} fetch_write;

struct lc_spider_fetch {
    pthread_mutex_t do_lock; /* Sole consumer, including private work outside the protocol lock. */
    pthread_mutex_t lock; /* Public operations; no socket waits occur under this lock. */
    pthread_cond_t consumer;
    pthread_cond_t request_consumer;
    uint64_t       generation;
    int            consumer_stopped;
    int            request_tasks; /* Separate doRequest continuation/cleanup driver. */
    int              state;
    int              quiet;  /* no ClientConn was ever made: nothing reads, nothing answers */
    int              closed; /* the TLS connection closed: a readLoop's error, or idle */
    fetch_cc        *ccs;    /* the Transport's ClientConns, oldest first */
    unsigned         seq;
    lc_spider_sink  *sink;
    struct fetch_do *d;
    /* Writes, each one Write on the TLS connection. */
    uint8_t *out;
    size_t   out_len, out_cap;
    fetch_write *cut;
    unsigned cuts, cut_cap;
    uint64_t next_write_id;
    fetch_write active_write;
    int      oom;
    /* The goroutine running, for a write that finds its writer stuck: a readLoop, Do, or a
     * request's doRequest. And Do blocked for good. */
    int           ctx;
    fetch_stream *ctx_s;
    fetch_cc *ctx_cc;
    int           do_blocked;
    int           body_ready; /* readLoop notification, consumed by Do's settle operation */
    int           body_writer_wait; /* An accounted source Read waits for its credit Write. */
    int           single_read; /* Consumer-step boundary, never a wait inside a pipe callback. */
    int           yielded;
    int           write_barrier;
    int           write_inflight;
    int           loss_pending;
    uint8_t      *held_input; /* Tail of one accepted feed, not a queue of later TLS records. */
    size_t        held_len;
};

enum { CTX_READLOOP, CTX_DO, CTX_DOREQ };

static int output_pending(const lc_spider_fetch *f)
{
    return f->write_barrier && (f->cuts > 0u || f->write_inflight);
}

static int read_dispatch_pending(const lc_spider_fetch *f)
{
    for (const fetch_cc *cc = f->ccs; cc != NULL; cc = cc->next)
        if (cc->read_pending)
            return 1;
    return 0;
}

static int cleanup_writer_busy(const fetch_cc *cc);

/* Read owns its accounted bytes while waiting for its own cc.wmu or Flush.
 * A foreign ClientConn's socket Write only determines the output queue order. */
static int body_writer_ready(const fetch_stream *s)
{
    return s != NULL && s->source_pending &&
           (s->source_flushed ? s->source_write_id == 0u : !cleanup_writer_busy(s->cc));
}

/* pipe.Read and flow accounting precede cc.wmu. Only this Read's saved writer/Flush wait
 * blocks its consumer; a request, cleanup or readLoop Write belongs to another goroutine. */
static int body_consumer_ready(const lc_spider_fetch *f)
{
    const struct fetch_do *d = f->d;
    return d != NULL && !f->do_blocked &&
           (!f->body_writer_wait || body_writer_ready(d->s)) && f->body_ready &&
           d->rd != RD_NONE && !d->rd_done;
}

static int reader_only_response(const fetch_stream *s)
{
    int redirect = s->status == 301 || s->status == 302 || s->status == 303 ||
                   s->status == 307 || s->status == 308;
    return !redirect || s->location == NULL || s->location_len == 0u;
}

static int close_ready(const fetch_stream *s)
{
    if (s == NULL)
        return 0;
    if (s->body != BODY_PIPE || !s->p_break)
        return 1;
    if (s->close_pending)
        return s->close_flushed ? s->close_write_id == 0u : !cleanup_writer_busy(s->cc);
    return s->done;
}

/* newClientConn flushes its opening before returning. internalRoundTrip then
 * starts doRequest, whose stream allocation precedes encodeAndWriteHeaders'
 * cc.wmu acquisition (vendor/x-net/http2/transport.go:994, :1124-1149, :1249).
 * A readLoop ACK may hold that writer, but does not delay request admission.
 * After Body.Close, Client.do sends the next redirect without acquiring any
 * ClientConn writer (Go 1.27 src/net/http/client.go:726-746). */
static int round_trip_admission_ready(const lc_spider_fetch *f)
{
    return f->request_tasks && f->d != NULL &&
           (f->state == DO_NEXT || (f->state == DO_START &&
            f->d->first_cc != NULL && f->d->first_cc->opening_write_id == 0u));
}

/* Readiness includes continuation without fresh input. A runnable pre-writer phase does not
 * authorize another request or a conflicting Write; Close guards its saved writer phase. */
static int do_consumer_ready(const lc_spider_fetch *f)
{
    const struct fetch_do *d = f->d;
    if (d == NULL || f->do_blocked)
        return 0;
    if (round_trip_admission_ready(f))
        return 1;
    if (f->state == DO_ATTEMPT && d->s != NULL && d->s->resp &&
        (d->s->body != BODY_NONE || d->s->done))
        return 1;
    if ((f->state == DO_CLOSE || f->state == DO_FINISH) && close_ready(d->s))
        return 1;
    if (body_consumer_ready(f))
        return 1;
    return (f->state == DO_READ || f->state == DO_SLURP) && d->rd_done;
}

static void wake_reader(lc_spider_fetch *f, const fetch_stream *s);

static int cleanup_ready(const lc_spider_fetch *f, const fetch_stream *s)
{
    if (s->done || s->doreq_blocked)
        return 0;
    /* doRequest calls cleanup only after its own writeRequest returns. Peer abort
     * may wake RoundTrip while HEADERS still Flush, but cannot unwind that producer.
     * This is a stream-local dependency, not a barrier on another stream/cc's Write. */
    if (s->cc->request_pending == s || s->cc->request_writer == s)
        return 0;
    if (s->cleanup_final_pending)
        return !cleanup_writer_busy(s->cc);
    if (!(s->peer_closed || s->abort))
        return 0;
    if (s->cleanup_pending)
        return s->cleanup_write_id == 0u;
    /* The decision precedes cc.wmu acquisition. Only an already selected reset
     * waits for that ClientConn's writer, not for a different cc's socket Write. */
    return !s->cleanup_prepared || !f->write_barrier || !s->cleanup_reset ||
           !cleanup_writer_busy(s->cc);
}

static int consumer_ready(const lc_spider_fetch *f)
{
    if (do_consumer_ready(f))
        return 1;
    if (f->request_tasks)
        return 0; /* Cleanup wakes its own task, not Do's writer wait. */
    for (const fetch_cc *cc = f->ccs; cc != NULL; cc = cc->next)
        for (const fetch_stream *s = cc->streams; s != NULL; s = s->next)
            if (cleanup_ready(f, s))
                return 1;
    return 0;
}

/* get/Do returns independently of the retained connection/readLoop. Only the
 * split driver can retire its executor; the combined driver still owns readers.
 * Xray reality.go::UClient and x/net transport.go::clientStream.doRequest. */
static int do_task_finished(const lc_spider_fetch *f)
{
    return f->request_tasks && f->state == DO_END && !f->closed && !f->oom;
}

/* Submission retains reqHeaderMu's producer reservation, not cc.wmu. Each request
 * acquires only its ClientConn's writer (encodeAndWriteHeaders, transport.go:1221).
 * A foreign ClientConn's TLS Write is ordered by the socket queue, not this mutex.
 * An active request still owns HEADERS/CONTINUATION and its own unfinished Flush. */
static int request_producer_ready(const fetch_cc *cc)
{
    if (cc->request_writer != NULL)
        return cc->request_writer->request_write_id == 0u;
    if (cc->request_pending != NULL && cc->request_pending->id == 0u)
        return cc->opening_write_id == 0u && !cc->request_pending->doreq_blocked;
    return cc->request_pending != NULL && !cleanup_writer_busy(cc);
}

static int request_task_ready(const lc_spider_fetch *f)
{
    for (const fetch_cc *cc = f->ccs; cc != NULL; cc = cc->next) {
        if (request_producer_ready(cc))
            return 1;
        for (const fetch_stream *s = cc->streams; s != NULL; s = s->next)
            if (cleanup_ready(f, s))
                return 1;
    }
    return 0;
}

static int request_task_finished(const lc_spider_fetch *f)
{
    if (!do_task_finished(f))
        return 0;
    for (const fetch_cc *cc = f->ccs; cc != NULL; cc = cc->next) {
        if (cc->request_pending != NULL || cc->request_writer != NULL ||
            cc->cleanup_writer != NULL || cc->source_writer != NULL || cc->close_writer != NULL)
            return 0;
        for (const fetch_stream *s = cc->streams; s != NULL; s = s->next)
            if (!s->done)
                return 0;
    }
    return 1;
}

/* DIVERGES: O8. Do and doRequest wait on different predicates, as the
 * reference's respHeaderRecv/body pipe and abort/donec channels do
 * (vendor/x-net/http2/transport.go:internalRoundTrip, clientStream.writeRequest;
 * vendor/x-net/http2/pipe.go:Write). Input does not wake an idle request task.
 * Call under lock; terminal transitions must wake both kinds of waiter. */
static void notify_request_consumer(lc_spider_fetch *f)
{
    if (f->consumer_stopped || f->closed || f->oom ||
        (f->request_tasks && (request_task_ready(f) || request_task_finished(f))))
        pthread_cond_broadcast(&f->request_consumer);
}

static void notify_consumers(lc_spider_fetch *f)
{
    pthread_cond_broadcast(&f->consumer);
    notify_request_consumer(f);
}

/* DIVERGES: O8. Body.Close's final wait is donec, not a reset's Flush return
 * (vendor/x-net/http2/transport.go:2310-2319). Request/Write progress still wakes
 * its executor; an idle Do needs no generation or wake until cleanup closes
 * donec. A pending Close credit Write and every terminal event remain visible. */
static void publish_task_progress(lc_spider_fetch *f)
{
    const fetch_stream *s = f->d != NULL ? f->d->s : NULL;
    int waits_done = f->request_tasks && !f->consumer_stopped && !f->closed && !f->oom &&
                     (f->state == DO_CLOSE || f->state == DO_FINISH) && s != NULL &&
                     s->body == BODY_PIPE && s->p_break && !s->close_pending && !s->done;
    if (!waits_done) {
        f->generation++;
        pthread_cond_broadcast(&f->consumer);
    }
    notify_request_consumer(f);
}

/* ---- writes ---------------------------------------------------------------------------------- */

/* One Write on the TLS connection. Nothing is written once it is closed: the Write fails. */
static void put_write(lc_spider_fetch *f, fetch_cc *cc, const uint8_t *b, size_t n)
{
    if (n == 0u || f->oom || f->closed)
        return;
    if (f->out_len + n > f->out_cap) {
        size_t cap = f->out_cap == 0u ? 1024u : f->out_cap;
        while (cap < f->out_len + n)
            cap *= 2u;
        uint8_t *o = realloc(f->out, cap);
        if (o == NULL) {
            f->oom = 1;
            return;
        }
        f->out = o;
        f->out_cap = cap;
    }
    if (f->cuts == f->cut_cap) {
        unsigned cap = f->cut_cap == 0u ? 16u : f->cut_cap * 2u;
        fetch_write *c = realloc(f->cut, cap * sizeof *c);
        if (c == NULL) {
            f->oom = 1;
            return;
        }
        f->cut = c;
        f->cut_cap = cap;
    }
    memcpy(f->out + f->out_len, b, n);
    f->out_len += n;
    fetch_cc *reader = f->write_barrier && f->ctx == CTX_READLOOP ? f->ctx_cc : NULL;
    if (reader != NULL && reader->stuck)
        reader = NULL;
    uint64_t id = ++f->next_write_id;
    fetch_stream *stream = f->ctx == CTX_DOREQ ? f->ctx_s :
                           f->ctx == CTX_DO && f->d != NULL ? f->d->s : NULL;
    f->cut[f->cuts++] = (fetch_write){f->out_len, id, cc, reader, stream, f->ctx};
    if (reader != NULL)
        reader->read_write_id = id;
    if (f->write_barrier && stream != NULL && f->ctx == CTX_DO &&
        stream->source_pending && !stream->source_flushed)
        stream->source_write_id = id;
    if (f->write_barrier && stream != NULL && f->ctx == CTX_DO &&
        stream->close_pending && !stream->close_flushed)
        stream->close_write_id = id;
    if (f->write_barrier && stream != NULL && f->ctx == CTX_DOREQ) {
        if (stream->cc->request_writer == stream)
            stream->request_write_id = id;
        else {
            stream->cleanup_write_id = id;
            stream->cc->cleanup_writer = stream;
        }
    }
}

/* The stuck writer's next flush: CONTINUATION frames with nothing in them, nine bytes each, filling
 * its bufio.Writer's 4096 — each fill one Write, for as long as the connection takes them. */
static void spew(lc_spider_fetch *f)
{
    if (f->closed)
        return;
    for (fetch_cc *cc = f->ccs; cc != NULL; cc = cc->next) {
        if (!cc->stuck)
            continue;
        uint8_t fr[LC_H2_HEADER];
        (void)lc_h2_put_header(fr, sizeof fr, 0, H2_CONTINUATION, 0, cc->spew_id);
        while (cc->wn < H2_BUFIO) {
            cc->wbuf[cc->wn++] = fr[cc->spew_phase];
            cc->spew_phase = (cc->spew_phase + 1u) % LC_H2_HEADER;
        }
        put_write(f, cc, cc->wbuf, cc->wn);
        cc->wn = 0;
        return;
    }
}

static long fetch_take_locked(lc_spider_fetch *f, uint8_t **out)
{
    *out = NULL;
    if (f == NULL)
        return 0;
    if (f->cuts == 0u && !f->oom)
        spew(f);
    if (f->oom)
        return -1;
    if (f->cuts == 0u)
        return 0;
    size_t n = f->cut[0].end;
    /* DIVERGES: O7. The last queued Write can hand its allocation to the TLS
     * owner. No queued bytes still borrow it. With later Writes, copy only this
     * prefix, preserving their storage and the existing whole-Write boundary
     * (vendor/x-net/http2/transport.go:ClientConn.writeHeaders, bw.Flush).
     * Taking bytes never acknowledges their socket completion. */
    int last = f->cuts == 1u;
    uint8_t *copy = last ? f->out : malloc(n);
    if (copy == NULL)
        return -1; /* Leave the queued write intact. */
    f->active_write = f->cut[0];
    if (!last) {
        memcpy(copy, f->out, n);
        memmove(f->out, f->out + n, f->out_len - n);
    }
    f->out_len -= n;
    for (unsigned i = 1; i < f->cuts; i++) {
        f->cut[i - 1u] = f->cut[i];
        f->cut[i - 1u].end -= n;
    }
    f->cuts--;
    if (f->cuts == 0u) {
        free(f->cut);
        f->out = NULL;
        f->cut = NULL;
        f->out_cap = f->cut_cap = 0;
    }
    *out = copy;
    return (long)n;
}

long lc_spider_fetch_take(lc_spider_fetch *f, uint8_t **out)
{
    *out = NULL;
    if (f == NULL)
        return 0;
    pthread_mutex_lock(&f->lock);
    if (f->write_inflight) {
        pthread_mutex_unlock(&f->lock);
        return 0;
    }
    long n = fetch_take_locked(f, out);
    if (n > 0 && f->write_barrier) {
        f->write_inflight = 1;
    } else if (n > 0) {
        for (fetch_cc *cc = f->ccs; cc != NULL; cc = cc->next)
            if (cc->opening_write_id == f->active_write.id)
                cc->opening_write_id = 0;
        /* The TLS owner accepted one whole Write. A consumer that yielded while waiting for
         * downstream write capacity may now continue; the caller still owns TLS and the bytes. */
        f->generation++;
        notify_consumers(f);
    }
    pthread_mutex_unlock(&f->lock);
    return n;
}

int lc_spider_fetch_write_barrier(lc_spider_fetch *f)
{
    if (f == NULL)
        return -1;
    pthread_mutex_lock(&f->lock);
    f->write_barrier = 1;
    pthread_mutex_unlock(&f->lock);
    return 0;
}

int lc_spider_fetch_request_tasks(lc_spider_fetch *f)
{
    if (f == NULL)
        return -1;
    pthread_mutex_lock(&f->lock);
    int rc = f->write_barrier && !f->write_inflight ? 0 : -1;
    if (rc == 0)
        f->request_tasks = 1;
    pthread_mutex_unlock(&f->lock);
    return rc;
}

/* A write that finds its ClientConn's writer stuck — see round_trip — waits on cc.wmu for good, and
 * so does the goroutine that made it. 1 when that is what happened. */
static int blocked(lc_spider_fetch *f, fetch_cc *cc)
{
    if (!cc->stuck)
        return 0;
    if (f->ctx == CTX_READLOOP)
        cc->reader_blocked = 1;
    else if (f->ctx == CTX_DO)
        f->do_blocked = 1;
    else if (f->ctx_s != NULL)
        f->ctx_s->doreq_blocked = 1;
    return 1;
}

/* bufio.Writer.Write over the TLS connection (GOROOT/src/bufio/bufio.go): what does not fit what is
 * free goes out — straight from `p` when nothing is buffered, else the buffer filled and flushed. */
static void bw_write(lc_spider_fetch *f, fetch_cc *cc, const uint8_t *p, size_t n)
{
    if (blocked(f, cc))
        return;
    while (n > H2_BUFIO - cc->wn) {
        size_t w;
        if (cc->wn == 0u) {
            w = n; /* "Large write, empty buffer. Write directly from p to avoid copy." */
            put_write(f, cc, p, w);
        } else {
            w = H2_BUFIO - cc->wn;
            memcpy(cc->wbuf + cc->wn, p, w);
            cc->wn += w;
            put_write(f, cc, cc->wbuf, cc->wn);
            cc->wn = 0;
        }
        p += w;
        n -= w;
    }
    memcpy(cc->wbuf + cc->wn, p, n);
    cc->wn += n;
}

static void bw_flush(lc_spider_fetch *f, fetch_cc *cc)
{
    if (blocked(f, cc))
        return;
    put_write(f, cc, cc->wbuf, cc->wn);
    cc->wn = 0;
}

/* The Framer builds the whole frame in its wbuf and hands it to its writer in one Write. */
static void w_frame(lc_spider_fetch *f, fetch_cc *cc, uint8_t type, uint8_t flags, uint32_t id,
                    const uint8_t *p, size_t n)
{
    uint8_t *fr = malloc(LC_H2_HEADER + n);
    if (fr == NULL) {
        f->oom = 1;
        return;
    }
    (void)lc_h2_put_header(fr, LC_H2_HEADER, (uint32_t)n, type, flags, id);
    if (n > 0u)
        memcpy(fr + LC_H2_HEADER, p, n);
    bw_write(f, cc, fr, LC_H2_HEADER + n);
    free(fr);
}

static void w_u32(uint8_t *b, uint32_t v)
{
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)v;
}

static uint32_t r_u32(const uint8_t *b)
{
    return (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | b[3];
}

static void w_window(lc_spider_fetch *f, fetch_cc *cc, uint32_t id, uint32_t inc)
{
    uint8_t p[4];
    w_u32(p, inc);
    w_frame(f, cc, LC_H2_WINDOW_UPDATE, 0, id, p, 4);
}

static void w_reset(lc_spider_fetch *f, fetch_cc *cc, uint32_t id, uint32_t code)
{
    uint8_t p[4];
    w_u32(p, code);
    w_frame(f, cc, LC_H2_RST_STREAM, 0, id, p, 4);
}

/* ---- flow control (vendor/x-net/http2/flow.go) ----------------------------------------------- */

/* inflow.add: what has been read accumulates, and goes back to the peer only once it is at least
 * inflowMinRefresh — four kilobytes — or at least doubles the window the peer still has. The
 * increment to send, 0 while it is held. */
static uint32_t inflow_add(int64_t *avail, int64_t *unsent, uint64_t n)
{
    *unsent += (int64_t)n;
    if (*unsent < 4096 && *unsent < *avail)
        return 0;
    uint32_t out = (uint32_t)*unsent;
    *avail += *unsent;
    *unsent = 0;
    return out;
}

/* Go 1.27.3 outflow.add: SETTINGS can temporarily move a stream above
 * 2^31-1. A later WINDOW_UPDATE distinguishes that connection error from
 * an update which itself overflows the stream. Keep the lazy value in int64. */
static int outflow_add(int64_t *n, int64_t add)
{
    if (*n + add > INT32_MAX)
        return 0;
    *n += add;
    return 1;
}

/* ---- the connection closes -----------------------------------------------------------------------
 *
 * closeConn: tconn.Close() on the one TLS connection every ClientConn shares
 * (vendor/x-net/http2/transport.go:766-771) — so any of them closing ends all of them: every
 * readLoop's next Read fails, and its cleanup marks its ClientConn closed and dead to the pool and
 * aborts every stream the peer had not finished (vendor/x-net/http2/transport.go:1809-1873). What
 * is left in a writer's buffer is not flushed: the GOAWAY a readLoop writes on a connection error
 * goes into its bufio.Writer and nothing flushes it before the close
 * (vendor/x-net/http2/transport.go:1790-1799). */
static void abort_stream(fetch_stream *s, int kind, uint32_t code, int from_peer);

static void close_conn(lc_spider_fetch *f)
{
    f->closed = 1;
    for (fetch_cc *cc = f->ccs; cc != NULL; cc = cc->next) {
        cc->closed = 1;
        cc->in_pool = 0;
        for (fetch_stream *s = cc->streams; s != NULL; s = s->next)
            if (s->id != 0u && !s->forgotten && !s->peer_closed)
                abort_stream(s, AB_LOST, 0, 0);
    }
}

/* ---- streams --------------------------------------------------------------------------------- */

/* streamByID (vendor/x-net/http2/transport.go:2472-2490): the stream while it is in the map and not
 * read-aborted; and, called for a HEADERS or a DATA frame, the end of rstStreamPingsBlocked. Every
 * call records what the next stream ID was — readBeforeStreamID, which says later whether anything
 * was read since a stream began. */
static fetch_stream *stream_by_id(fetch_cc *cc, uint32_t id, int header_or_data)
{
    if (header_or_data)
        cc->rst_pings_blocked = 0;
    cc->read_before = cc->next_id;
    for (fetch_stream *s = cc->streams; s != NULL; s = s->next)
        if (s->id != 0u && s->id == id && !s->forgotten)
            return s->read_aborted ? NULL : s;
    return NULL;
}

/* abortStreamLocked (vendor/x-net/http2/transport.go:352-365): the first error sticks. */
static void abort_stream(fetch_stream *s, int kind, uint32_t code, int from_peer)
{
    if (s->abort)
        return;
    s->abort = 1;
    s->abort_kind = kind;
    s->abort_code = code;
    s->from_peer = from_peer;
}

/* endStreamError: the stream's reads end, and the stream is aborted. */
static void end_stream_error(fetch_stream *s, int kind, uint32_t code)
{
    s->read_aborted = 1;
    abort_stream(s, kind, code, 0);
}

/* pipe.closeWithError into p.err: a no-op once it is set. */
static void pipe_close(fetch_stream *s, int err)
{
    if (s->p_err == LC_GZ_NONE)
        s->p_err = err;
}

static void pipe_drop(fetch_stream *s)
{
    free(s->pb);
    s->pb = NULL;
    s->pb_off = s->pb_len = s->pb_cap = 0;
}

/* endStream (vendor/x-net/http2/transport.go:2438-2452): the peer is done with the stream. */
static void end_stream(fetch_stream *s)
{
    if (s->peer_closed)
        return;
    s->peer_closed = 1;
    pipe_close(s, LC_GZ_EOF);
}

static void random8(uint8_t p[8])
{
    if (lc_rnd(p, 8) != 0)
        memset(p, 0, 8);
}

/* forgetStreamID (vendor/x-net/http2/transport.go:1755-1781): out of the map — and when that leaves
 * a connection with a GOAWAY, or told not to be reused, with nothing on it, the connection is
 * closed. */
static void forget_stream(lc_spider_fetch *f, fetch_stream *s)
{
    fetch_cc *cc = s->cc;
    s->forgotten = 1;
    int left = 0;
    for (fetch_stream *o = cc->streams; o != NULL; o = o->next)
        left += o->id != 0u && !o->forgotten;
    int close_on_idle = cc->do_not_reuse || cc->goaway;
    if (close_on_idle && cc->reserved == 0u && left == 0) {
        cc->closed = 1;
        close_conn(f);
    }
}

/* cleanupWriteRequest (vendor/x-net/http2/transport.go:1305-1399), when doRequest's wait ends: with
 * the peer's close of the stream (err nil), or with its abort — or when writeRequest failed before
 * it waited. */
static int cleanup_writer_busy(const fetch_cc *cc)
{
    return cc->stuck || cc->request_writer != NULL || cc->source_writer != NULL ||
           cc->close_writer != NULL || cc->cleanup_writer != NULL || cc->read_write_id != 0u ||
           cc->opening_write_id != 0u;
}

/* forgetStreamID releases cc.mu before the separate final cc.wmu/werr acquisition
 * (vendor/x-net/http2/transport.go:1396-1408). Completion mode preserves that boundary
 * even with a free writer. donec closes after the check, not as proof of Write success. */
static void cleanup_finish(lc_spider_fetch *f, fetch_stream *s)
{
    if (!s->cleanup_final_pending) {
        if (s->id != 0u && !s->forgotten)
            forget_stream(f, s);
        s->cleanup_final_pending = 1;
        if (f->write_barrier)
            return;
    }
    if (f->write_barrier && cleanup_writer_busy(s->cc))
        return;
    if (s->cc->werr)
        close_conn(f);
    s->cleanup_final_pending = 0;
    s->done = 1;
}

/* A Write error ends Do/readLoop, but must not erase an already-forgotten stream's
 * final cleanup. This terminal-only pass cannot produce bytes or start another request.
 * Stop still takes precedence. Writers release their matching ownership on failure. */
static void cleanup_closed_finals(lc_spider_fetch *f)
{
    for (fetch_cc *cc = f->ccs; cc != NULL; cc = cc->next)
        for (fetch_stream *s = cc->streams; s != NULL; s = s->next)
            if (s->cleanup_final_pending && !s->done)
                cleanup_finish(f, s);
}

/* cleanupWriteRequest closes the pipe only after writeStreamReset's Flush returned.
 * Wake a body Read that drained the pipe while that reset owned cc.wmu. */
static void cleanup_after_write(lc_spider_fetch *f, fetch_stream *s)
{
    pipe_close(s, LC_GZ_ERR); /* errRequestCanceled, no-op after the peer's end */
    wake_reader(f, s);
    cleanup_finish(f, s);
}

static void cleanup_prepare(fetch_stream *s)
{
    if (s->cleanup_prepared)
        return;
    fetch_cc *cc = s->cc;
    if (s->id == 0u && cc->reserved > 0u)
        cc->reserved--; /* decrStreamReservations, a second time: guarded, as Go's is */
    int close_on_idle = cc->do_not_reuse || cc->goaway;
    int read_since = cc->read_before > s->id;
    int err = s->abort;
    if (err && s->sent_end_stream && s->peer_closed)
        err = 0; /* closed cleanly on both sides: no error */
    s->cleanup_prepared = 1;
    if (err) {
        if (s->sent_headers) {
            if (s->abort_kind == AB_STREAM || s->abort_kind == AB_PEER) {
                if (!s->from_peer) {
                    s->cleanup_reset = 1;
                    s->cleanup_reset_code = s->abort_code;
                }
            } else {
                /* An in-flight request cancelled: RST_STREAM(CANCEL), and a PING with it unless the
                 * connection is closing anyway or has been read from since the stream began. */
                if (!close_on_idle && !read_since && !cc->rst_pings_blocked) {
                    s->cleanup_ping = cc->pending_resets == 0u;
                    cc->pending_resets++;
                }
                s->cleanup_reset = 1;
                s->cleanup_reset_code = ERR_CANCEL;
            }
        }
    } else {
        if (s->sent_headers && !s->sent_end_stream) {
            s->cleanup_reset = 1;
            s->cleanup_reset_code = ERR_NO;
        }
    }
}

static void cleanup_run(lc_spider_fetch *f, fetch_stream *s)
{
    fetch_cc *cc = s->cc;
    cleanup_prepare(s);
    if (s->cleanup_reset) {
        if (blocked(f, cc))
            return;
        if (f->write_barrier && cleanup_writer_busy(cc))
            return;
        w_reset(f, cc, s->id, s->cleanup_reset_code);
        if (s->cleanup_ping) {
            uint8_t p[8];
            random8(p);
            w_frame(f, cc, LC_H2_PING, 0, 0, p, 8);
        }
        bw_flush(f, cc);
        if (s->doreq_blocked)
            return;
    }
    if (f->write_barrier && s->cleanup_write_id != 0u) {
        s->cleanup_pending = 1;
        return;
    }
    cleanup_after_write(f, s);
}

/* doRequest's cleanup, run as that goroutine: a write it makes on a stuck writer blocks it there for
 * good, and its donec never closes. */
static void cleanup_stream(lc_spider_fetch *f, fetch_stream *s)
{
    if (s->done || s->doreq_blocked)
        return;
    if (s->cleanup_final_pending) {
        cleanup_finish(f, s);
        return;
    }
    if (s->cleanup_pending) {
        if (s->cleanup_write_id != 0u)
            return;
        s->cleanup_pending = 0;
        cleanup_after_write(f, s);
        return;
    }
    int           ctx = f->ctx;
    fetch_stream *ctx_s = f->ctx_s;
    f->ctx = CTX_DOREQ;
    f->ctx_s = s;
    cleanup_run(f, s);
    f->ctx = ctx;
    f->ctx_s = ctx_s;
}

/* transportResponseBody.Close (vendor/x-net/http2/transport.go:2284-2320), under gzipReader.Close:
 * the pipe broken and what it held let go, the stream aborted, the window for what was never read
 * handed back on the connection — and its doRequest, woken by the abort, cleans it up, cancelling
 * it if the peer had not finished it. Close waits for that. noBody and missingBody close to nothing. */
static void close_body(lc_spider_fetch *f, fetch_stream *s)
{
    if (s->body != BODY_PIPE)
        return;
    fetch_cc *cc = s->cc;
    size_t    unread = 0;
    if (!s->p_break) {
        s->p_break = 1;
        unread = s->pb_len;
        pipe_drop(s);
        lc_gozip_free(s->gz);
        s->gz = NULL;
        abort_stream(s, AB_CLOSED, 0, 0);
        if (unread > 0u) {
            s->close_conn_credit = inflow_add(&cc->in_avail, &cc->in_unsent, unread);
            s->close_pending = 1; /* Acquires cc.wmu even when inflow.add returns zero. */
        }
        if (f->single_read)
            f->yielded = 1;
    }
    if (s->close_pending) {
        if (!s->close_flushed) {
            if (blocked(f, cc))
                return;
            if (f->write_barrier && cleanup_writer_busy(cc))
                return;
            cc->close_writer = s;
            if (s->close_conn_credit != 0u)
                w_window(f, cc, 0, s->close_conn_credit);
            bw_flush(f, cc);
            if (f->do_blocked)
                return;
            s->close_flushed = 1;
            if (s->close_write_id == 0u)
                cc->close_writer = NULL;
        }
        if (s->close_write_id != 0u)
            return;
        s->close_pending = 0;
    }
    /* abortStream wakes a separate doRequest; it does not run cleanup on Body.Close's stack.
     * The completion driver releases this turn before that goroutine chooses its reset. */
    if (!f->write_barrier)
        cleanup_stream(f, s);
}

/* ---- the body's reads ------------------------------------------------------------------------ */

/* transportResponseBody.Read (vendor/x-net/http2/transport.go:2230-2280) over pipe.Read
 * (vendor/x-net/http2/pipe.go:55-78): what has arrived — nothing once the body is closed — else the
 * pipe's end, else a wait; the Content-Length held to; and the window for what was read handed
 * back, both windows while the stream goes on. The source core/gozip reads through. */
static int body_read_complete(lc_spider_fetch *f, fetch_stream *s,
                              const uint8_t **p, size_t *n, int *err)
{
    if (!s->source_flushed) {
        if (cleanup_writer_busy(s->cc)) {
            f->body_writer_wait = 1;
            f->body_ready = 1;
            return 1;
        }
        s->cc->source_writer = s;
        if (s->source_conn_credit != 0u)
            w_window(f, s->cc, 0, s->source_conn_credit);
        if (s->source_stream_credit != 0u)
            w_window(f, s->cc, s->id, s->source_stream_credit);
        bw_flush(f, s->cc);
        s->source_flushed = 1;
        if (s->source_write_id == 0u)
            s->cc->source_writer = NULL;
    }
    if (s->source_write_id != 0u) {
        f->body_writer_wait = 1;
        f->body_ready = 1;
        return 1;
    }
    *p = s->source_read;
    *n = s->source_len;
    *err = s->source_err;
    s->source_pending = 0;
    f->body_writer_wait = 0;
    return 0;
}

static int body_source(void *ctx, size_t cap, const uint8_t **p, size_t *n, int *err)
{
    fetch_stream    *s = ctx;
    fetch_cc        *cc = s->cc;
    lc_spider_fetch *f = cc->f;
    *p = NULL;
    *n = 0;
    *err = LC_GZ_NONE;
    if (s->source_pending)
        return body_read_complete(f, s, p, n, err);
    free(s->source_read);
    s->source_read = NULL;
    if (s->read_err != LC_GZ_NONE) {
        *err = s->read_err;
        return 0;
    }
    if (s->p_break) {
        *err = LC_GZ_ERR;
    } else if (s->pb_len > 0u) {
        size_t k = cap < s->pb_len ? cap : s->pb_len;
        *p = s->pb + s->pb_off;
        s->pb_off += k;
        s->pb_len -= k;
        *n = k;
    } else if (s->p_err != LC_GZ_NONE) {
        *err = s->p_err;
    } else {
        return 1;
    }
    if (s->remain != -1) {
        if ((int64_t)*n > s->remain) {
            *n = (size_t)s->remain;
            if (*err == LC_GZ_NONE) {
                *err = LC_GZ_ERR; /* "server replied with more than declared Content-Length" */
                abort_stream(s, AB_FAILED, 0, 0);
            }
            s->read_err = *err;
            return 0;
        }
        s->remain -= (int64_t)*n;
        if (*err == LC_GZ_EOF && s->remain > 0) {
            *err = LC_GZ_ERR; /* io.ErrUnexpectedEOF */
            s->read_err = *err;
            return 0;
        }
    }
    if (*n == 0u)
        return 0;
    uint32_t conn_add = inflow_add(&cc->in_avail, &cc->in_unsent, *n);
    uint32_t stream_add = 0;
    if (*err == LC_GZ_NONE)
        stream_add = inflow_add(&s->in_avail, &s->in_unsent, *n);
    if (conn_add != 0u || stream_add != 0u) {
        if (f->write_barrier) {
            s->source_read = malloc(*n);
            if (s->source_read == NULL) {
                f->oom = 1;
                return 1;
            }
            memcpy(s->source_read, *p, *n);
            s->source_len = *n;
            s->source_err = *err;
            s->source_conn_credit = conn_add;
            s->source_stream_credit = stream_add;
            s->source_pending = 1;
            s->source_flushed = 0;
            *p = NULL;
            *n = 0;
            *err = LC_GZ_NONE;
            return body_read_complete(f, s, p, n, err);
        }
        if (conn_add != 0u)
            w_window(f, cc, 0, conn_add);
        if (stream_add != 0u)
            w_window(f, cc, s->id, stream_add);
        bw_flush(f, cc);
        if (f->do_blocked)
            return 1; /* the Read never returns */
    }
    return 0;
}

/* gzipReader.Read/flate run on Do's stack outside ClientConn locks. Its source
 * alone acquires pipe/flow state (Go 1.27 internal/http2/transport.go:
 * transportResponseBody.Read, gzipReader.Read). An unlocked decoder may keep
 * its source result until the next call, so never expose the mutable pipe. */
static int gzip_source(void *ctx, size_t cap, const uint8_t **p, size_t *n, int *err)
{
    fetch_stream *s = ctx;
    lc_spider_fetch *f = s->cc->f;
    pthread_mutex_lock(&f->lock);
    int rc = 0;
    *p = NULL;
    *n = 0u;
    *err = LC_GZ_ERR;
    if (!f->consumer_stopped && !f->closed && !f->oom) {
        int previous_ctx = f->ctx;
        fetch_stream *previous_stream = f->ctx_s;
        f->ctx = CTX_DO;
        f->ctx_s = NULL;
        rc = body_source(s, cap, p, n, err);
        if (rc == 0 && *n > 0u && *p != s->source_read) {
            uint8_t *owned = malloc(*n);
            if (owned == NULL) {
                f->oom = 1;
                *p = NULL;
                *n = 0u;
                *err = LC_GZ_ERR;
            } else {
                memcpy(owned, *p, *n);
                s->source_read = owned;
                *p = owned;
            }
        }
        f->ctx = previous_ctx;
        f->ctx_s = previous_stream;
    }
    pthread_mutex_unlock(&f->lock);
    return rc;
}

/* What `append([]byte(nil), make([]byte, n)...)` gives as a capacity: the size class above n
 * (roundupsize for a pointer-free object, GOROOT/src/runtime/msize.go:16-36, over
 * GOROOT/src/internal/runtime/gc/sizeclasses.go:98), or whole 8 KiB pages past the largest —
 * io.ReadAll's next slice. */
static size_t go_roundup(size_t n)
{
    static const uint16_t classes[] = {
        8,     16,    24,    32,    48,    64,    80,    96,    112,   128,   144,   160,
        176,   192,   208,   224,   240,   256,   288,   320,   352,   384,   416,   448,
        480,   512,   576,   640,   704,   768,   896,   1024,  1152,  1280,  1408,  1536,
        1792,  2048,  2304,  2688,  3072,  3200,  3456,  4096,  4864,  5376,  6144,  6528,
        6784,  6912,  8192,  9472,  9728,  10240, 10880, 12288, 13568, 14336, 16384, 18432,
        19072, 20480, 21760, 24576, 27264, 28672, 32768,
    };
    if (n <= 32768u - 8u)
        for (size_t i = 0; i < sizeof classes / sizeof classes[0]; i++)
            if (classes[i] >= n)
                return classes[i];
    return (n + 8191u) & ~(size_t)8191u;
}

/* The reader of the body Do is reading, run whenever what it waits for may have come: the slurp —
 * io.CopyN(io.Discard, body, 2048), a LimitedReader over io.Discard's 8192 (GOROOT/src/io/io.go
 * CopyN, LimitedReader.Read, discard.ReadFrom) — or io.ReadAll's slices
 * (GOROOT/src/io/io.go:709-750), the page's text going to the harvest as it is read. It reads until
 * it waits or is done; what Do does next waits for the settle. */
static void reader_run(lc_spider_fetch *f)
{
    struct fetch_do *d = f->d;
    if (d == NULL || d->rd == RD_NONE || d->rd_done)
        return;
    fetch_stream *s = d->s;
    for (;;) {
        size_t want;
        if (d->rd == RD_ALL) {
            want = d->cap - d->len;
        } else {
            if (d->limit <= 0) {
                d->rd_done = 1; /* LimitedReader: EOF without a Read */
                return;
            }
            want = d->limit < 8192 ? (size_t)d->limit : 8192u;
        }
        const uint8_t *out = NULL;
        size_t         n = 0;
        int            err = LC_GZ_NONE;
        if (s->body == BODY_NONE) {
            err = LC_GZ_EOF;
        } else if (s->body == BODY_MISSING) {
            err = LC_GZ_ERR;
        } else if (s->gzip) {
            /* do_lock owns this decoder and its lifetime. Source reads reacquire
             * only protocol state; feed/cleanup/stop need not wait for inflation. */
            pthread_mutex_unlock(&f->lock);
            if (s->gz == NULL)
                s->gz = lc_gozip_new(gzip_source, s);
            int r = s->gz == NULL ? -1 : lc_gozip_read(s->gz, want, &out, &n, &err);
            pthread_mutex_lock(&f->lock);
            f->ctx = CTX_DO;
            f->ctx_s = NULL;
            if (f->consumer_stopped || f->closed || f->oom)
                return;
            if (r < 0) {
                f->oom = 1;
                return;
            }
            if (r == 1)
                return;
        } else if (body_source(s, want, &out, &n, &err) == 1) {
            return;
        }
        if (f->do_blocked)
            return;
        if (d->rd == RD_ALL) {
            if (n > 0u)
                lc_spider_sink_data(f->sink, out, n);
            d->len += n;
            if (err != LC_GZ_NONE) {
                d->rd_done = 1;
                d->rd_err = err != LC_GZ_EOF;
                return;
            }
            if (d->cap - d->len < d->cap / 16u) {
                d->cap = go_roundup(d->next_cap);
                d->len = 0;
                d->next_cap += d->next_cap / 2u;
            }
        } else {
            d->limit -= (int64_t)n;
            if (err != LC_GZ_NONE) {
                d->rd_done = 1;
                return;
            }
        }
        if (f->single_read) {
            /* Account and harvest the returned bytes BEFORE releasing the protocol lock. The
             * source pointer may name a pipe buffer that the next feed reallocates. Gzip keeps
             * its own continuation; no pointer from this Read is retained across the boundary. */
            f->body_ready = 1;
            f->yielded = 1;
            return;
        }
    }
}

/* The reader runs as Do's goroutine, whoever woke it. */
static void reader_step(lc_spider_fetch *f)
{
    if (f->do_blocked)
        return;
    int           ctx = f->ctx;
    fetch_stream *ctx_s = f->ctx_s;
    f->ctx = CTX_DO;
    f->ctx_s = NULL;
    reader_run(f);
    f->ctx = ctx;
    f->ctx_s = ctx_s;
}

/* A reader woken: its stream's pipe took DATA or was closed. Do consumes the notification on its
 * own turn; the HTTP/2 readLoop must not run gzip, slurp or harvest inside a frame callback. */
static void wake_reader(lc_spider_fetch *f, const fetch_stream *s)
{
    if (f->d != NULL && f->d->s == s && f->d->rd != RD_NONE)
        f->body_ready = 1;
}

/* ---- a readLoop ------------------------------------------------------------------------------ */

/* httpguts.ValidHeaderFieldValue, and validWireHeaderFieldName over bytes — a byte past 0x7f is
 * part of a rune IsTokenRune refuses (vendor/x-net/http2/http2.go:206-219). */
static int valid_value(const char *v, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        uint8_t c = (uint8_t)v[i];
        if ((c < 0x20u && c != '\t') || c == 0x7fu)
            return 0;
    }
    return 1;
}

static int valid_name(const char *v, size_t n)
{
    if (n == 0u)
        return 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t c = (uint8_t)v[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              (c != 0u && c < 0x80u && strchr("!#$%&'*+-.^_`|~", c) != NULL)))
            return 0;
    }
    return 1;
}

/* strconv.Atoi, as handleResponse reads :status — into an int, which is the platform's word, as
 * Go's is. */
static int go_atoi(const char *s, size_t n, long *out)
{
    size_t        i = 0;
    int           neg = 0;
    unsigned long v = 0, lim = (unsigned long)-1 >> 1;
    if (i < n && (s[i] == '+' || s[i] == '-'))
        neg = s[i++] == '-';
    if (i == n)
        return -1;
    for (; i < n; i++) {
        if (s[i] < '0' || s[i] > '9')
            return -1;
        unsigned long dgt = (unsigned long)(s[i] - '0');
        if (v > (lim + (unsigned long)neg - dgt) / 10u)
            return -1;
        v = v * 10u + dgt;
    }
    *out = neg ? (long)(0ul - v) : (long)v;
    return 0;
}

/* strconv.ParseUint(v, 10, 63), as handleResponse reads Content-Length. */
static int go_parse_uint63(const char *s, size_t n, int64_t *out)
{
    uint64_t v = 0;
    if (n == 0u)
        return -1;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9')
            return -1;
        uint64_t dgt = (uint64_t)(s[i] - '0');
        if (v > (0x7fffffffffffffffull - dgt) / 10u)
            return -1;
        v = v * 10u + dgt;
    }
    *out = (int64_t)v;
    return 0;
}

static int ascii_equal_fold(const char *a, size_t an, const char *b)
{
    size_t bn = strlen(b);
    if (an != bn)
        return 0;
    for (size_t i = 0; i < an; i++) {
        char x = a[i] >= 'A' && a[i] <= 'Z' ? (char)(a[i] - 'A' + 'a') : a[i];
        if (x != b[i])
            return 0;
    }
    return 1;
}

/* readMetaFrame's emit function (vendor/x-net/http2/frame.go:1719-1750), and what the answer's
 * fields say: the first of each that Header.Get reads, and how many Content-Lengths there were. */
static void on_field(void *ctx, lc_hpack_dec *dec)
{
    fetch_meta *m = ctx;
    if (!valid_value(dec->value, dec->value_len))
        m->invalid = 1;
    int pseudo = dec->name_len > 0u && dec->name[0] == ':';
    if (pseudo) {
        if (m->saw_regular)
            m->invalid = 1;
    } else {
        m->saw_regular = 1;
        if (!valid_name(dec->name, dec->name_len))
            m->invalid = 1;
    }
    if (m->invalid) {
        dec->emit_off = 1;
        return;
    }
    uint64_t size = (uint64_t)dec->name_len + dec->value_len + 32u;
    uint64_t cost = size;
    uint64_t *budget = &m->remain;
    if (dec->name_len == 7u && memcmp(dec->name, "trailer", 7u) == 0) {
        uint64_t fields = 1;
        for (size_t i = 0; i < dec->value_len; i++)
            fields += dec->value[i] == ',';
        /* Each declared trailer field costs its name plus hpack's 32 bytes;
         * commas are separators, while spaces still count, as in Go 1.27.3. */
        cost = (uint64_t)dec->value_len + 1u + 31u * fields;
        budget = &m->trailer_remain;
    }
    if (cost > *budget) {
        dec->emit_off = 1;
        m->truncated = 1;
        m->remain = 0;
        m->trailer_remain = 0;
        return;
    }
    *budget -= cost;
    m->size += size;
    if (pseudo) {
        /* checkPseudos (vendor/x-net/http2/frame.go:1668-1693), over the fields kept. */
        static const char *const names[] = { ":method", ":path", ":scheme", ":authority",
                                             ":protocol", ":status" };
        m->n_pseudo++;
        unsigned k = 0;
        while (k < 6u && (strlen(names[k]) != dec->name_len ||
                          memcmp(names[k], dec->name, dec->name_len) != 0))
            k++;
        if (k == 6u || (m->pseudo_seen & (1u << k)) != 0u) {
            m->pseudo_bad = 1;
            return;
        }
        m->pseudo_seen |= 1u << k;
        if (k < 5u) {
            m->is_req = 1;
            return;
        }
        m->is_resp = 1;
        m->have_status = 1;
        m->status_ok = dec->value_len > 0u && go_atoi(dec->value, dec->value_len, &m->status) == 0;
        return;
    }
    if (dec->name_len == 8u && memcmp(dec->name, "location", 8) == 0 && !m->have_loc) {
        m->have_loc = 1;
        m->location = malloc(dec->value_len + 1u);
        if (m->location == NULL) {
            m->oom = 1;
            return;
        }
        memcpy(m->location, dec->value, dec->value_len + 1u);
        m->location_len = dec->value_len;
    } else if (dec->name_len == 14u && memcmp(dec->name, "content-length", 14) == 0) {
        if (m->n_clen++ == 0u)
            m->clen_ok = go_parse_uint63(dec->value, dec->value_len, &m->clen) == 0;
    } else if (dec->name_len == 16u && memcmp(dec->name, "content-encoding", 16) == 0 &&
               !m->have_ce) {
        m->have_ce = 1;
        m->ce_gzip = ascii_equal_fold(dec->value, dec->value_len, "gzip");
    }
}

static void meta_reset(fetch_meta *m)
{
    free(m->location);
    memset(m, 0, sizeof *m);
}

/* One fragment of the block (vendor/x-net/http2/frame.go:1776-1806): refused, and the connection
 * with it, when it is more than twice what the list may still hold, or follows an invalid field;
 * decoded otherwise. -1 for the connection. */
static int meta_fragment(lc_spider_fetch *f, fetch_cc *cc, const uint8_t *frag, size_t n)
{
    fetch_meta *m = &cc->m;
    if ((uint64_t)n > 2u * (m->remain + m->trailer_remain) || m->invalid)
        return -1;
    int rc = lc_hpack_write(&cc->dec, frag, n, on_field, m);
    if (m->oom)
        f->oom = 1;
    return rc == 0 ? 0 : -1;
}

/* processHeaders, handleResponse, processTrailers (vendor/x-net/http2/transport.go:1970-2222). -1
 * for the connection. */
static int process_headers(lc_spider_fetch *f, fetch_cc *cc)
{
    fetch_meta   *m = &cc->m;
    int           end = (m->flags & LC_H2_END_STREAM) != 0;
    fetch_stream *s = stream_by_id(cc, m->stream, 1);
    if (s == NULL)
        return 0; /* something cancelled: ignored */
    if (s->peer_closed) {
        end_stream_error(s, AB_STREAM, ERR_PROTOCOL); /* headers after END_STREAM */
        return 0;
    }
    if (s->past_headers) {
        if (s->past_trailers || !end || m->n_pseudo > 0u)
            return -1;
        s->past_trailers = 1;
        /* Trailers past the header-list limit end the stream with PROTOCOL_ERROR
         * (processTrailers, GOROOT/src/net/http/internal/http2/transport.go:2322-2329); Go 1.26's
         * x/net kept what it had decoded. */
        if (m->truncated) {
            end_stream_error(s, AB_STREAM, ERR_PROTOCOL);
            return 0;
        }
        end_stream(s);
        wake_reader(f, s);
        return 0;
    }
    s->past_headers = 1;
    /* handleResponse: every error of it is a stream error, PROTOCOL. */
    if (m->truncated || !m->have_status || !m->status_ok) {
        end_stream_error(s, AB_STREAM, ERR_PROTOCOL);
        return 0;
    }
    if (m->status >= 100 && m->status <= 199) {
        if (end) {
            end_stream_error(s, AB_STREAM, ERR_PROTOCOL);
            return 0;
        }
        s->size_1xx += m->size;
        if (s->size_1xx > H2_MAX_HLS) {
            end_stream_error(s, AB_STREAM, ERR_PROTOCOL);
            return 0;
        }
        s->past_headers = 0; /* do it all again */
        return 0;
    }
    s->status = m->status;
    s->length = -1;
    if (m->n_clen == 1u) {
        if (m->clen_ok)
            s->length = m->clen;
    } else if (m->n_clen == 0u && end) {
        s->length = 0;
    }
    if (end) {
        s->body = s->length > 0 ? BODY_MISSING : BODY_NONE;
    } else {
        /* setBuffer — which a pipe the peer has already reset does not take — and bytesRemain. */
        s->body = BODY_PIPE;
        s->remain = s->length;
        if (m->have_ce && m->ce_gzip) {
            s->gzip = 1;
            s->length = -1;
        }
    }
    s->location = m->location;
    s->location_len = m->location_len;
    m->location = NULL;
    s->resp = 1;
    if (end)
        end_stream(s);
    return 0;
}

/* The block is over: Close, then the stream errors readMetaFrame returns, then — the frame
 * returned — the SETTINGS rule and processHeaders. -1 for the connection. */
static int meta_end(lc_spider_fetch *f, fetch_cc *cc)
{
    fetch_meta *m = &cc->m;
    cc->dec.emit_off = 0;
    if (lc_hpack_close(&cc->dec) != 0)
        return -1; /* COMPRESSION_ERROR */
    if (m->is_req && m->is_resp)
        m->pseudo_bad = 1; /* errMixPseudoHeaderTypes */
    if (m->invalid || m->pseudo_bad) {
        fetch_stream *s = stream_by_id(cc, m->stream, 0);
        if (s != NULL)
            end_stream_error(s, AB_STREAM, ERR_PROTOCOL);
        return 0;
    }
    if (!cc->got_settings)
        return -1;
    return process_headers(f, cc);
}

/* pipe.Write (vendor/x-net/http2/pipe.go:87-104): taken, unless the pipe is closed or broken. */
static int pipe_write(lc_spider_fetch *f, fetch_stream *s, const uint8_t *p, size_t n)
{
    if (s->p_err != LC_GZ_NONE || s->p_break)
        return -1;
    if (s->pb_len == 0u)
        s->pb_off = 0;
    if (s->pb_off + s->pb_len + n > s->pb_cap) {
        if (s->pb_off > 0u) {
            memmove(s->pb, s->pb + s->pb_off, s->pb_len);
            s->pb_off = 0;
        }
        if (s->pb_len + n > s->pb_cap) {
            size_t   cap = s->pb_cap == 0u ? 16384u : s->pb_cap;
            while (cap < s->pb_len + n)
                cap *= 2u;
            uint8_t *b = realloc(s->pb, cap);
            if (b == NULL) {
                f->oom = 1;
                return -1;
            }
            s->pb = b;
            s->pb_cap = cap;
        }
    }
    memcpy(s->pb + s->pb_off + s->pb_len, p, n);
    s->pb_len += n;
    return 0;
}

/* processData (vendor/x-net/http2/transport.go:2322-2436). -1 for the connection. */
static int process_data(lc_spider_fetch *f, fetch_cc *cc, const lc_h2_hd *hd, const uint8_t *body,
                        size_t body_len)
{
    fetch_stream *s = stream_by_id(cc, hd->stream, 1);
    if (s == NULL) {
        if (hd->stream >= cc->next_id)
            return -1; /* "unsolicited DATA frame" */
        if (hd->len > 0u) {
            /* Something cancelled: its window goes back all the same. */
            int ok = (int64_t)hd->len <= cc->in_avail;
            if (ok)
                cc->in_avail -= hd->len;
            uint32_t inc = inflow_add(&cc->in_avail, &cc->in_unsent, hd->len);
            if (!ok)
                return -1;
            if (inc > 0u) {
                cc->data_stream = NULL;
                cc->data_conn_credit = inc;
                cc->data_stream_credit = 0u;
                cc->data_reset = cc->data_end_stream = 0;
                cc->data_pending = 1;
            }
        }
        return 0;
    }
    if (s->peer_closed || !s->past_headers) {
        end_stream_error(s, AB_STREAM, ERR_PROTOCOL);
        return 0;
    }
    if (hd->len > 0u) {
        if ((int64_t)hd->len > cc->in_avail || (int64_t)hd->len > s->in_avail)
            return -1; /* FLOW_CONTROL_ERROR */
        cc->in_avail -= hd->len;
        s->in_avail -= hd->len;
        uint64_t refund = hd->len - body_len; /* padding, never to be read */
        int      reset = 0;
        if (body_len > 0u && pipe_write(f, s, body, body_len) != 0) {
            reset = 1; /* the data will never be read: its window goes back now */
            refund += body_len;
        }
        uint32_t c = inflow_add(&cc->in_avail, &cc->in_unsent, refund);
        uint32_t st = reset ? 0u : inflow_add(&s->in_avail, &s->in_unsent, refund);
        if (!reset && body_len > 0u)
            wake_reader(f, s);
        cc->data_stream = s;
        cc->data_conn_credit = c;
        cc->data_stream_credit = st;
        cc->data_reset = reset;
        cc->data_end_stream = (hd->flags & LC_H2_END_STREAM) != 0u;
        cc->data_pending = 1;
        return 0;
    }
    if (hd->flags & LC_H2_END_STREAM) {
        end_stream(s);
        wake_reader(f, s);
    }
    return 0;
}

/* The part of processData after pipe.Write and inflow accounting. It first acquires cc.wmu for
 * padding credit, then waits for that Flush to complete before publishing reset/END_STREAM. */
static int process_data_resume(lc_spider_fetch *f, fetch_cc *cc)
{
    if (!cc->data_pending)
        return 0;
    fetch_stream *s = cc->data_stream;
    if (cc->data_conn_credit != 0u || cc->data_stream_credit != 0u) {
        if (cc->request_writer != NULL || cc->source_writer != NULL || cc->close_writer != NULL ||
            cc->cleanup_writer != NULL || cc->stuck) {
            cc->writer_wait = 1;
            return 0;
        }
        if (cc->data_conn_credit != 0u)
            w_window(f, cc, 0, cc->data_conn_credit);
        if (cc->data_stream_credit != 0u)
            w_window(f, cc, s->id, cc->data_stream_credit);
        cc->data_conn_credit = cc->data_stream_credit = 0u;
        bw_flush(f, cc);
        if (cc->reader_blocked)
            return 0;
    }
    if (cc->read_write_id != 0u) {
        cc->writer_wait = 1;
        return 0;
    }
    if (cc->data_reset)
        end_stream_error(s, AB_FAILED, 0); /* errClosedPipeWrite */
    else if (cc->data_end_stream) {
        end_stream(s);
        wake_reader(f, s);
    }
    cc->data_stream = NULL;
    cc->data_pending = cc->data_reset = cc->data_end_stream = 0;
    return 0;
}

/* processSettings (vendor/x-net/http2/transport.go:2516-2602; Go 1.27's is
 * GOROOT/src/net/http/internal/http2/transport.go:2666-2760): each setting asked Valid() and then
 * applied as it is read, and the ACK. -1 for the connection.
 *
 * Valid() is asked of EVERY setting — the callback opens with `if err := s.Valid(); err != nil
 * { return err }` (vendor/x-net/http2/transport.go:2548-2551) — so ENABLE_PUSH or
 * ENABLE_CONNECT_PROTOCOL outside 0 and 1, and MAX_FRAME_SIZE outside [16384, 2^24-1], end the
 * connection (vendor/x-net/http2/http2.go:141-160), with what came before them in the frame already
 * applied. Until 2026-09-26 this checked ENABLE_CONNECT_PROTOCOL alone, and said the reference did. */
static int process_settings(lc_spider_fetch *f, fetch_cc *cc, const lc_h2_hd *hd, const uint8_t *p)
{
    if (hd->flags & LC_H2_ACK) {
        if (cc->want_ack) {
            cc->want_ack = 0;
            return 0;
        }
        return -1;
    }
    int seen_max = 0;
    for (uint32_t i = 0; i < hd->len; i += 6u) {
        uint16_t id = (uint16_t)(p[i] << 8 | p[i + 1u]);
        uint32_t v = r_u32(p + i + 2u);
        switch (id) {
        case 0x2u:
            if (v > 1u)
                return -1; /* Setting.Valid: PROTOCOL_ERROR */
            break;
        case 0x5u:
            if (v < 16384u || v > 0xffffffu)
                return -1; /* Setting.Valid: PROTOCOL_ERROR */
            cc->max_frame = v;
            break;
        case 0x3u:
            cc->max_streams = v;
            seen_max = 1;
            break;
        case 0x6u:
            cc->peer_max_hls = v;
            break;
        case 0x4u: {
            if (v > 0x7fffffffu)
                return -1; /* FLOW_CONTROL_ERROR */
            int64_t delta = (int64_t)(int32_t)v - (int64_t)(int32_t)cc->init_window;
            /* Go 1.27.3 connOutflow.changeInitialWindowSize defers per-stream
             * overflow detection until flow is queried. These GET requests send
             * no DATA; their next query is processWindowUpdate below. */
            for (fetch_stream *s = cc->streams; s != NULL; s = s->next)
                if (s->id != 0u && !s->forgotten)
                    s->out += delta;
            cc->init_window = v;
            break;
        }
        case 0x1u:
            lc_hpack_enc_table_size(&cc->enc, v);
            break;
        case 0x8u:
            if (v > 1u)
                return -1; /* Setting.Valid: PROTOCOL_ERROR */
            break;
        default:
            break;
        }
    }
    if (!cc->seen_settings) {
        if (!seen_max)
            cc->max_streams = H2_DEFAULT_STREAMS;
        cc->seen_settings = 1;
    }
    uint8_t ack[LC_H2_HEADER];
    bw_write(f, cc, ack, lc_h2_settings_ack(ack, sizeof ack));
    bw_flush(f, cc);
    return 0;
}

/* processSettings acquires cc.wmu even for ACK (vendor/x-net/http2/transport.go:2516-2532).
 * processPing only acquires it for a non-ACK. DATA uses its saved post-body phase. */
static int frame_needs_writer(const lc_h2_hd *hd)
{
    if (hd->type == LC_H2_SETTINGS)
        return 1;
    if (hd->type == LC_H2_PING)
        return (hd->flags & LC_H2_ACK) == 0u;
    return 0;
}

/* One whole frame of this ClientConn's: ReadFrame's parse and order check, then run()'s dispatch
 * (vendor/x-net/http2/transport.go:1902-1968). -1 ends the readLoop, 1 retains a validated
 * control frame waiting for cc.wmu, and 0 consumes it. Parser errors never wait for a writer. */
static int cc_frame(lc_spider_fetch *f, fetch_cc *cc, const lc_h2_hd *hd, const uint8_t *p)
{
    uint32_t       len = hd->len, id = hd->stream;
    uint8_t        t = hd->type, fl = hd->flags;
    const uint8_t *frag = p;
    size_t         frag_len = len;
    const uint8_t *body = NULL;
    size_t         body_len = 0;

    /* The type's parser: a connError or a short read ends the readLoop; a StreamError aborts that
     * stream if it is one of ours and drops the frame, before the order check. */
    switch (t) {
    case LC_H2_DATA:
        if (id == 0u || lc_h2_data_body(hd, p, &body, &body_len) != 0)
            return -1;
        break;
    case LC_H2_HEADERS: {
        if (id == 0u)
            return -1;
        size_t at = 0, pad = 0;
        if (fl & LC_H2_PADDED) {
            if (len < 1u)
                return -1;
            pad = p[0];
            at = 1;
        }
        if (fl & 0x20u) {
            if (len < at + 5u)
                return -1;
            at += 5u;
        }
        if (len - at < pad) {
            fetch_stream *s = stream_by_id(cc, id, 0);
            if (s != NULL)
                end_stream_error(s, AB_STREAM, ERR_PROTOCOL);
            return 0;
        }
        frag = p + at;
        frag_len = len - at - pad;
        break;
    }
    case H2_PRIORITY:
        if (id == 0u || len != 5u)
            return -1;
        break;
    case LC_H2_RST_STREAM:
        if (len != 4u || id == 0u)
            return -1;
        break;
    case LC_H2_SETTINGS:
        if ((fl & LC_H2_ACK) && len > 0u)
            return -1;
        if (id != 0u || len % 6u != 0u)
            return -1;
        for (uint32_t i = 0; i < len; i += 6u)
            if ((p[i] << 8 | p[i + 1u]) == 0x4) { /* the first INITIAL_WINDOW_SIZE: Value */
                if (r_u32(p + i + 2u) > 0x7fffffffu)
                    return -1;
                break;
            }
        break;
    case H2_PUSH_PROMISE: {
        if (id == 0u)
            return -1;
        size_t at = 0, pad = 0;
        if (fl & LC_H2_PADDED) {
            if (len < 1u)
                return -1;
            pad = p[0];
            at = 1;
        }
        if (len < at + 4u || pad > len - at - 4u)
            return -1;
        break;
    }
    case LC_H2_PING:
        if (len != 8u || id != 0u)
            return -1;
        break;
    case LC_H2_GOAWAY:
        if (id != 0u || len < 8u)
            return -1;
        break;
    case LC_H2_WINDOW_UPDATE:
        if (len != 4u)
            return -1;
        if ((r_u32(p) & 0x7fffffffu) == 0u) {
            if (id == 0u)
                return -1;
            fetch_stream *s = stream_by_id(cc, id, 0);
            if (s != NULL)
                end_stream_error(s, AB_STREAM, ERR_PROTOCOL);
            return 0;
        }
        break;
    case H2_CONTINUATION:
        if (id == 0u)
            return -1;
        break;
    default:
        break;
    }

    /* checkFrameOrder (vendor/x-net/http2/frame.go:591-624). */
    if (cc->last_header_stream != 0u) {
        if (t != H2_CONTINUATION || id != cc->last_header_stream)
            return -1;
    } else if (t == H2_CONTINUATION) {
        return -1;
    }
    if (t == LC_H2_HEADERS || t == H2_CONTINUATION)
        cc->last_header_stream = (fl & LC_H2_END_HEADERS) ? 0u : id;

    /* HEADERS and its CONTINUATIONs are one frame to run(): readMetaFrame. */
    if (t == LC_H2_HEADERS) {
        meta_reset(&cc->m);
        cc->m.stream = id;
        cc->m.flags = fl;
        cc->m.remain = H2_MAX_HLS;
        cc->m.trailer_remain = H2_MAX_HLS;
        cc->dec.emit_off = 0; /* SetEmitEnabled(true) */
        cc->dec.max_str = H2_MAX_HLS;
    }
    if (t == LC_H2_HEADERS || t == H2_CONTINUATION) {
        if (meta_fragment(f, cc, frag, frag_len) != 0)
            return -1;
        return (fl & LC_H2_END_HEADERS) ? meta_end(f, cc) : 0;
    }

    if (!cc->got_settings) {
        if (t != LC_H2_SETTINGS)
            return -1;
        cc->got_settings = 1;
    }
    if (frame_needs_writer(hd) && cleanup_writer_busy(cc)) {
        cc->writer_wait = 1;
        return 1;
    }
    switch (t) {
    case LC_H2_DATA:
        return process_data(f, cc, hd, body, body_len);
    case LC_H2_SETTINGS:
        return process_settings(f, cc, hd, p);
    case LC_H2_PING:
        /* processPing (vendor/x-net/http2/transport.go:2700-2726). */
        if (fl & LC_H2_ACK) {
            if (cc->pending_resets > 0u) {
                cc->pending_resets = 0;
                cc->rst_pings_blocked = 1;
            }
            return 0;
        }
        w_frame(f, cc, LC_H2_PING, LC_H2_ACK, 0, p, 8);
        bw_flush(f, cc);
        return 0;
    case LC_H2_GOAWAY: {
        /* processGoAway (GOROOT/src/net/http/internal/http2/transport.go:2616-2664, Go 1.27): dead to
         * the pool, the codes merged, and then — with no stream open — errStopReadLoop: the readLoop
         * ends, and its cleanup closes the connection (:1942-1944, :922-927), with no GOAWAY of its
         * own since that error is not a ConnectionError (:1910-1918). Otherwise every stream past the
         * last the peer took aborted. Go 1.26's x/net kept a connection with nothing on it open
         * until the server closed it. */
        uint32_t last = r_u32(p) & 0x7fffffffu;
        uint32_t code = r_u32(p + 4);
        cc->in_pool = 0;
        if (!(cc->goaway && cc->goaway_code != ERR_NO))
            cc->goaway_code = code;
        cc->goaway = 1;
        cc->goaway_last = last;
        int open = 0;
        for (fetch_stream *s = cc->streams; s != NULL; s = s->next)
            open += s->id != 0u && !s->forgotten;
        if (open == 0)
            return -1;
        for (fetch_stream *s = cc->streams; s != NULL; s = s->next) {
            if (s->id == 0u || s->forgotten || s->id <= last)
                continue;
            abort_stream(s, s->id == 1u && cc->goaway_code != ERR_NO ? AB_GOAWAY_1 : AB_GOAWAY, 0,
                         0);
        }
        return 0;
    }
    case LC_H2_RST_STREAM: {
        /* processResetStream (vendor/x-net/http2/transport.go:2635-2653). */
        fetch_stream *s = stream_by_id(cc, id, 0);
        if (s == NULL)
            return 0;
        uint32_t code = r_u32(p);
        if (code == ERR_PROTOCOL)
            cc->do_not_reuse = 1;
        abort_stream(s, AB_PEER, code, 1);
        pipe_close(s, LC_GZ_ERR);
        wake_reader(f, s);
        return 0;
    }
    case LC_H2_WINDOW_UPDATE: {
        /* processWindowUpdate (vendor/x-net/http2/transport.go:2604-2633). */
        fetch_stream *s = stream_by_id(cc, id, 0);
        if (id != 0u && s == NULL)
            return 0;
        /* A prior SETTINGS already overflowed this stream: Go marks its
         * shared connOutflow.flowErr and ends the connection, not just s. */
        if (s != NULL && s->out > INT32_MAX)
            return -1;
        if (!outflow_add(s != NULL ? &s->out : &cc->out, r_u32(p) & 0x7fffffffu)) {
            if (s != NULL) {
                end_stream_error(s, AB_STREAM, ERR_FLOW);
                return 0;
            }
            return -1;
        }
        return 0;
    }
    case H2_PUSH_PROMISE:
        return -1; /* processPushPromise: we said no push */
    default:
        return 0;
    }
}

/* The readLoop's reading: io.ReadFull of the frame header and then of the payload through a
 * bufio.Reader of 4096 (GOROOT/src/bufio/bufio.go Read; frame.go ReadFrame). What the buffer holds
 * is taken from it; an empty buffer is filled with a Read of 4096 — or, for the rest of a payload
 * that is itself at least 4096, the Read goes straight into the payload. `cc->direct` says which the
 * pending Read is. -1 when the readLoop ends. */
static int cc_run(lc_spider_fetch *f, fetch_cc *cc)
{
    for (;;) {
        if (f->closed || f->oom || cc->closed)
            return -1;
        if (f->consumer_stopped)
            return 0;
        /* DIVERGES: G2. The TLS owner can observe an empty output queue, then
         * enter feed/read_step after a producer queued a Write. Check again
         * under the same protocol lock as frame dispatch, including the first
         * frame of a fresh feed. Retain accepted input and return to runnable
         * I/O; never wait for a producer or block reads behind an in-flight Write. */
        if (f->request_tasks && f->write_barrier && !f->write_inflight && f->cuts > 0u) {
            cc->read_pending = 1;
            return 0;
        }
        /* A consumer may have run at the preceding frame boundary. Restore the
         * readLoop's Write ownership before resuming parsing or DATA credit. */
        f->ctx = CTX_READLOOP;
        f->ctx_cc = cc;
        if (cc->data_pending) {
            cc->writer_wait = 0;
            if (process_data_resume(f, cc) != 0)
                return -1;
            if (cc->reader_blocked || cc->writer_wait)
                return 0;
        }
        if (!cc->in_payload) {
            size_t take = LC_H2_HEADER - cc->hdr_have;
            if (take > cc->rw - cc->rr)
                take = cc->rw - cc->rr;
            memcpy(cc->hdr + cc->hdr_have, cc->rbuf + cc->rr, take);
            cc->hdr_have += take;
            cc->rr += take;
            if (cc->hdr_have < LC_H2_HEADER) {
                cc->direct = 0;
                return 0;
            }
            uint32_t n = (uint32_t)cc->hdr[0] << 16 | (uint32_t)cc->hdr[1] << 8 | cc->hdr[2];
            if (n > LC_H2_MAX_READ_FRAME)
                return -1; /* ErrFrameTooLarge */
            cc->fh.len = n;
            cc->fh.type = cc->hdr[3];
            cc->fh.flags = cc->hdr[4];
            cc->fh.stream = ((uint32_t)cc->hdr[5] & 0x7fu) << 24 | (uint32_t)cc->hdr[6] << 16 |
                            (uint32_t)cc->hdr[7] << 8 | cc->hdr[8];
            cc->payload = n > 0u ? malloc(n) : NULL;
            if (n > 0u && cc->payload == NULL) {
                f->oom = 1;
                return -1;
            }
            cc->pay_have = 0;
            cc->in_payload = 1;
        }
        size_t take = cc->fh.len - cc->pay_have;
        if (take > cc->rw - cc->rr)
            take = cc->rw - cc->rr;
        if (take > 0u)
            memcpy(cc->payload + cc->pay_have, cc->rbuf + cc->rr, take);
        cc->pay_have += take;
        cc->rr += take;
        if (cc->pay_have < cc->fh.len) {
            cc->direct = cc->fh.len - cc->pay_have >= H2_BUFIO;
            return 0;
        }
        if (cc->read_write_id != 0u) {
            cc->writer_wait = 1;
            return 0;
        }
        lc_h2_hd       hd = cc->fh;
        uint8_t       *pl = cc->payload;
        static const uint8_t none[1];
        int rc = cc_frame(f, cc, &hd, pl != NULL ? pl : none);
        if (rc == 1)
            return 0; /* Keep the parsed frame and bufio tail until its cc.wmu acquisition. */
        cc->in_payload = 0;
        cc->hdr_have = 0;
        cc->payload = NULL;
        free(pl);
        if (rc == 0 && cc->data_pending)
            rc = process_data_resume(f, cc);
        if (cc->read_write_id != 0u)
            cc->writer_wait = 1;
        if (cc->reader_blocked)
            return 0;
        if (rc != 0 || f->closed || f->oom)
            return -1;
        if (cc->writer_wait)
            return 0;
        if (f->request_tasks) {
            /* processHeaders publishes respHeaderRecv; processData publishes to
             * bufPipe (vendor/x-net/http2/transport.go). Neither holds cc.mu
             * across the next ReadFrame. A TLS record is not an atomic batch
             * relative to Do/Body.Close. No scheduler yield or consumer wait is
             * imposed here; either participant may acquire the mutex next. */
            f->generation++;
            notify_consumers(f);
            pthread_mutex_unlock(&f->lock);
            pthread_mutex_lock(&f->lock);
        }
    }
}

/* Bytes of one record, handed out as the readLoops' Reads ask for them: the one that has waited
 * longest gets what its Read asks for — a fill, or the rest of a payload — and asks again at the
 * back of the line once it has read what it got. tls.Conn.Read returns from one record at a time
 * and holds its lock while it waits (GOROOT/src/crypto/tls/conn.go Read), so every ClientConn's
 * readLoop takes its turn, in the order it asked. With one ClientConn, which is the rule, it reads
 * everything. */
static int retain_input(lc_spider_fetch *f, const uint8_t *rec, size_t len)
{
    if (len == 0u)
        return 0;
    f->held_input = malloc(len);
    if (f->held_input == NULL) {
        f->oom = 1;
        return -1;
    }
    memcpy(f->held_input, rec, len);
    f->held_len = len;
    return 0;
}

static int readers_feed(lc_spider_fetch *f, const uint8_t *rec, size_t len)
{
    while (len > 0u && !f->closed) {
        fetch_cc *cc = NULL;
        for (fetch_cc *c = f->ccs; c != NULL; c = c->next)
            if (!c->closed && !c->reader_blocked && !c->writer_wait && !c->read_pending &&
                (!f->write_barrier || c->opening_write_id == 0u) &&
                (cc == NULL || c->seq < cc->seq))
                cc = c;
        if (cc == NULL) {
            int waiting = 0;
            for (fetch_cc *c = f->ccs; c != NULL; c = c->next)
                waiting |= c->writer_wait || c->read_pending ||
                           (f->write_barrier && c->opening_write_id != 0u);
            return waiting ? retain_input(f, rec, len) : 0;
        }
        size_t want = cc->direct ? cc->fh.len - cc->pay_have : H2_BUFIO;
        size_t n = want < len ? want : len;
        if (cc->direct) {
            memcpy(cc->payload + cc->pay_have, rec, n);
            cc->pay_have += n;
            cc->rr = cc->rw = 0;
        } else {
            memcpy(cc->rbuf, rec, n);
            cc->rr = 0;
            cc->rw = n;
        }
        rec += n;
        len -= n;
        cc->seq = ++f->seq;
        f->ctx = CTX_READLOOP;
        f->ctx_cc = cc;
        if (cc_run(f, cc) != 0) {
            close_conn(f);
            return -1;
        }
        if (cc->read_pending)
            return retain_input(f, rec, len);
    }
    return f->closed ? -1 : 0;
}

/* ---- ClientConns and the pool ---------------------------------------------------------------- */

/* currentRequestCountLocked and idleStateLocked (vendor/x-net/http2/transport.go:727-731, :665-700):
 * the ClientConn takes a new request while it is under its peer's concurrency and still usable — no
 * GOAWAY, not closed, not told not to be reused, stream IDs left — and, never having carried one,
 * even when closed: that request then fails and says why. */
static unsigned request_count(const fetch_cc *cc)
{
    unsigned n = cc->reserved + cc->pending_resets;
    for (const fetch_stream *s = cc->streams; s != NULL; s = s->next)
        n += s->id != 0u && !s->forgotten;
    return n;
}

static int can_take(const fetch_cc *cc)
{
    int take = request_count(cc) < cc->max_streams && !cc->goaway && !cc->closed &&
               !cc->do_not_reuse && cc->next_id < 0x7fffffffu;
    if (cc->next_id == 1u && cc->reserved == 0u && cc->closed)
        take = 1;
    return take;
}

/* newClientConn (vendor/x-net/http2/transport.go:467-557): the opening — preface, SETTINGS and the
 * connection window, one flush — and a readLoop reading from then on. On a connection already
 * closed the flush fails, and the dial with it. */
static fetch_cc *new_cc(lc_spider_fetch *f, const char *key)
{
    if (f->closed)
        return NULL;
    fetch_cc *cc = calloc(1, sizeof *cc);
    if (cc == NULL || (cc->key = strdup(key)) == NULL) {
        free(cc);
        f->oom = 1;
        return NULL;
    }
    cc->f = f;
    cc->next_id = 1;
    cc->max_frame = 16384u;
    cc->max_streams = H2_INIT_STREAMS;
    cc->peer_max_hls = UINT64_MAX;
    cc->out = 65535;
    cc->init_window = 65535u;
    cc->want_ack = 1;
    cc->in_avail = (int64_t)LC_XHTTP_CONN_CREDIT + 65535;
    lc_hpack_enc_init(&cc->enc);
    uint8_t o[128];
    size_t  at = lc_h2_preface(o, sizeof o);
    at += lc_h2_settings(o + at, sizeof o - at, LC_XHTTP_STREAM_WINDOW);
    at += lc_h2_window_update(o + at, sizeof o - at, 0, LC_XHTTP_CONN_CREDIT);
    bw_write(f, cc, o, at);
    bw_flush(f, cc);
    cc->opening_write_id = f->next_write_id;
    cc->in_pool = 1;
    if (!f->write_barrier)
        cc->seq = ++f->seq; /* synchronous driver: Flush accepted; readLoop asks for bytes */
    fetch_cc **tail = &f->ccs;
    while (*tail != NULL)
        tail = &(*tail)->next;
    *tail = cc;
    return cc;
}

/* A ClientConn for the request, found as net/http of Go 1.27 finds one for an x/net Transport
 * (roundTrip, GOROOT/src/net/http/transport.go:611-770), or NULL for a dial that fails. `*dialed`
 * says a dial was made.
 *
 * Round and round, until something takes the request:
 *   - the pool behind every RoundTripper net/http holds for HTTP/2 gives the first ClientConn filed
 *     under the Host's authorityAddr that reserves, oldest first (clientConnPool.getClientConn,
 *     GOROOT/src/net/http/internal/http2/client_conn_pool.go:39-85) — and never dials;
 *   - when none does, net/http dials canonicalAddr. The reference's DialTLSContext hands back
 *     the one TLS connection whatever the address (reality.go:188-193), and AddConn files a new
 *     ClientConn on it — its opening goes out — under authorityAddr of the ADDRESS
 *     (GOROOT/src/net/http/internal/http2/transport.go:113-120).
 * What net/http dialled also goes into its idle list under canonicalAddr, which it looks in before
 * it dials again (dialConnFor and queueForIdleConn, GOROOT/src/net/http/transport.go:1706-1726,
 * :1241-1325). That changes nothing here: what the idle list hands out is the same pool asked the
 * same thing (http2AddConn, GOROOT/src/net/http/http2.go:354-363), which says ErrNoCachedConn, and
 * the entry is dropped — one round more, and no byte on the connection. So it is not kept.
 * The two keys differ where the Host is not all ASCII and idna.Lookup maps what ToASCII keeps
 * (`WWÉ.example`: xn--ww-cja against xn--WW-lga), and then the new ClientConn is never found: the
 * round comes back to a dial, and this time AddConn finds a ClientConn under its key that can
 * take a request, does not use what it was handed, and closes it
 * (GOROOT/src/net/http/internal/http2/client_conn_pool.go:137-164) — the TLS connection. net/http
 * goes on round and round after that, with nothing left to write to. */
static fetch_cc *get_client_conn(lc_spider_fetch *f, const lc_spider_req *q, int *dialed)
{
    *dialed = 0;
    for (;;) {
        for (fetch_cc *cc = f->ccs; cc != NULL; cc = cc->next)
            if (cc->in_pool && strcmp(cc->key, q->key.p) == 0 && can_take(cc)) {
                cc->reserved++;
                return cc;
            }
        for (fetch_cc *cc = f->ccs; cc != NULL; cc = cc->next)
            if (cc->in_pool && strcmp(cc->key, q->pool.p) == 0 && can_take(cc)) {
                close_conn(f);
                return NULL;
            }
        fetch_cc *cc = new_cc(f, q->pool.p);
        if (cc == NULL)
            return NULL;
        *dialed = 1;
    }
}

/* ---- a request ------------------------------------------------------------------------------- */

/* The field behind key `k` of the request's map before send: the first request's own, or a hop's —
 * a key copied from the clone, or the referer set on top. */
static lc_hpack_field map_field(const struct fetch_do *d, unsigned k)
{
    if (!d->hop)
        return d->keys[k];
    if (k < (unsigned)d->hop_copied)
        return d->keys[d->clone_from[d->hop_from[k]]];
    return (lc_hpack_field){ "referer", d->ref.p };
}

/* The fields of one request as x/net writes them: `:authority`, `:method`, `:path`, `:scheme`, then
 * req.Header walked as Go walks the map — afresh for every attempt — then accept-encoding, which the
 * transport adds after the walk (vendor/x-net/internal/httpcommon/request.go:76-190). The map is
 * send's clone when the URL has userinfo. 0 when no randomness could be had for the walk. */
static unsigned request_fields(struct fetch_do *d, lc_hpack_field *fs)
{
    unsigned n = 0, order[LC_GOMAP_KEYS];
    fs[n++] = (lc_hpack_field){ ":authority", d->q.authority.p != NULL ? d->q.authority.p : "" };
    fs[n++] = (lc_hpack_field){ ":method", "GET" };
    fs[n++] = (lc_hpack_field){ ":path", d->q.path.p != NULL ? d->q.path.p : "" };
    fs[n++] = (lc_hpack_field){ ":scheme", "https" };
    const lc_gomap *map = d->auth ? &d->auth_map : d->hop ? &d->hop_map : &d->h;
    if (lc_gomap_walk(map, order) != 0)
        return 0;
    for (unsigned p = 0; p < map->n; p++) {
        unsigned k = order[p];
        if (!d->auth)
            fs[n++] = map_field(d, k);
        else if (k < (unsigned)d->auth_copied)
            fs[n++] = map_field(d, d->auth_from[k]);
        else
            fs[n++] = (lc_hpack_field){ "authorization", d->q.authorization.p };
    }
    fs[n++] = (lc_hpack_field){ "accept-encoding", "gzip" };
    return n;
}

/* send, for a URL with userinfo: `req.Header = cloneOrMakeHeader(ireq.Header)` and Authorization
 * set on the clone (GOROOT/src/net/http/client.go:253-258, GOROOT/src/net/http/clone.go:106-112) —
 * Header.Clone makes a map sized for the source and fills it in the source's walk order
 * (GOROOT/src/net/http/header.go:94-118). Once per send: roundTripViaPool's retries carry the same
 * request. */
static int auth_map(struct fetch_do *d)
{
    d->auth = 0;
    if (d->q.authorization.n == 0u)
        return 0;
    const lc_gomap *src = d->hop ? &d->hop_map : &d->h;
    lc_gomap_init_hint(&d->auth_map, src->n);
    int copied = lc_gomap_copy(src, &d->auth_map, ~0u, d->auth_from);
    if (copied < 0 || lc_gomap_insert(&d->auth_map) != 0)
        return -1;
    d->auth_copied = copied;
    d->auth = 1;
    return 0;
}

/* A RoundTrip on `cc` (internalRoundTrip, doRequest, writeRequest, encodeAndWriteHeaders —
 * vendor/x-net/http2/transport.go:972-1283): the reservation given back, a slot, the stream and its
 * ID, the header list held to the peer's MAX_HEADER_LIST_SIZE and the host to ValidHostHeader —
 * both refused after the ID is taken, nothing written — and the HEADERS, cut into CONTINUATIONs at
 * the peer's frame size, one flush. A failure before the wait is cleaned up at once, as doRequest
 * does. NULL only without memory. */
static int request_encode(lc_spider_fetch *f, fetch_stream *s,
                          const lc_hpack_field *fs, unsigned n, int headers_ok)
{
    fetch_cc *cc = s->cc;
    uint64_t hl = 0;
    size_t cap = 256u;
    for (unsigned i = 0; i < n; i++) {
        size_t name_len = strlen(fs[i].name), value_len = strlen(fs[i].value);
        hl += name_len + value_len + 32u;
        cap += 2u * (name_len + value_len) + 16u;
    }
    if (!headers_ok || (cc->peer_max_hls > 0u && hl > cc->peer_max_hls)) {
        abort_stream(s, AB_FAILED, 0, 0);
        return 1;
    }
    uint8_t *block = malloc(cap);
    long bl = block != NULL ? lc_hpack_enc_block(&cc->enc, fs, n, block, cap) : -1;
    if (bl < 0) {
        free(block);
        f->oom = 1;
        return -1;
    }
    s->request_block = block;
    s->request_len = (size_t)bl;
    s->sent_headers = 1;
    return 0;
}

static void request_progress(lc_spider_fetch *f, fetch_stream *s)
{
    fetch_cc *cc = s->cc;
    if (s->request_fields != NULL) {
        /* encodeAndWriteHeaders checks abort AFTER writer acquisition and BEFORE
         * touching the encoder. Dropping an encoded-but-unsent block corrupts
         * the shared dynamic table for the next request. Own fields, not Do data. */
        int rc = s->abort ? 1 : request_encode(f, s, s->request_fields,
                                               s->request_nfields, s->request_headers_ok);
        free(s->request_fields);
        s->request_fields = NULL;
        if (rc != 0) {
            cc->request_writer = NULL;
            return;
        }
    }
    if (s->request_off == s->request_len) {
        /* All bufio Writes, including the final Flush, have completed before this turn. */
        free(s->request_block);
        s->request_block = NULL;
        cc->request_writer = NULL;
        s->sent_end_stream = 1;
        return;
    }
    size_t chunk = s->request_len - s->request_off;
    if (chunk > cc->max_frame)
        chunk = cc->max_frame;
    uint8_t flags = (uint8_t)(s->request_off + chunk == s->request_len ? LC_H2_END_HEADERS : 0u);
    int saved_ctx = f->ctx;
    fetch_stream *saved_stream = f->ctx_s;
    f->ctx = CTX_DOREQ;
    f->ctx_s = s;
    if (cc->max_frame == 0u) {
        w_frame(f, cc, LC_H2_HEADERS, LC_H2_END_STREAM, s->id, NULL, 0);
        cc->stuck = 1;
        cc->spew_id = s->id;
        cc->spew_phase = 0;
        s->doreq_blocked = 1;
        free(s->request_block);
        s->request_block = NULL;
        cc->request_writer = NULL;
        f->ctx = saved_ctx;
        f->ctx_s = saved_stream;
        return;
    }
    w_frame(f, cc, s->request_off == 0u ? LC_H2_HEADERS : H2_CONTINUATION,
            (uint8_t)(flags | (s->request_off == 0u ? LC_H2_END_STREAM : 0u)),
            s->id, s->request_block + s->request_off, chunk);
    s->request_off += chunk;
    if (s->request_off == s->request_len)
        bw_flush(f, cc);
    f->ctx = saved_ctx;
    f->ctx_s = saved_stream;
}

/* writeRequest acquires reqHeaderMu and then cc.mu before assigning an ID;
 * RoundTrip's Do goroutine only creates the task (vendor/x-net/http2/transport.go:
 * internalRoundTrip, clientStream.writeRequest, ClientConn.addStreamLocked).
 * A readLoop cc.wmu owner does not block this admission phase. */
static int request_admit(fetch_stream *s)
{
    fetch_cc *cc = s->cc;
    if (cc->stuck) {
        s->doreq_blocked = 1;
        return 1;
    }
    if (cc->reserved > 0u)
        cc->reserved--;
    if (cc->closed && cc->next_id == 1u && cc->reserved == 0u) {
        abort_stream(s, AB_NOT_EST, 0, 0);
        return 1;
    }
    if (cc->closed || !can_take(cc)) {
        abort_stream(s, AB_UNUSABLE, 0, 0);
        return 1;
    }
    s->id = cc->next_id;
    cc->next_id += 2u;
    s->out = cc->init_window;
    s->in_avail = (int64_t)LC_XHTTP_STREAM_WINDOW;
    return 0;
}

static fetch_stream *round_trip(lc_spider_fetch *f, fetch_cc *cc, const lc_hpack_field *fs,
                                unsigned n, int headers_ok)
{
    fetch_stream *s = calloc(1, sizeof *s);
    if (s == NULL) {
        f->oom = 1;
        return NULL;
    }
    s->cc = cc;
    s->remain = -1;
    s->next = cc->streams;
    cc->streams = s;
    if (!f->request_tasks && request_admit(s) != 0) {
        if (s->abort)
            cleanup_stream(f, s);
        return s;
    }

    if (f->request_tasks) {
        size_t size = n * sizeof *s->request_fields;
        for (unsigned i = 0; i < n; i++)
            size += strlen(fs[i].name) + strlen(fs[i].value) + 2u;
        s->request_fields = malloc(size);
        if (s->request_fields == NULL) {
            f->oom = 1;
            return s;
        }
        char *at = (char *)(s->request_fields + n);
        for (unsigned i = 0; i < n; i++) {
            size_t len = strlen(fs[i].name) + 1u;
            s->request_fields[i].name = at;
            memcpy(at, fs[i].name, len);
            at += len;
            len = strlen(fs[i].value) + 1u;
            s->request_fields[i].value = at;
            memcpy(at, fs[i].value, len);
            at += len;
        }
        s->request_nfields = n;
        s->request_headers_ok = headers_ok;
        cc->request_pending = s;
        return s;
    }
    int encoded = request_encode(f, s, fs, n, headers_ok);
    if (encoded != 0) {
        if (encoded > 0)
            cleanup_stream(f, s);
        return s;
    }
    uint8_t *block = s->request_block;
    size_t bl = s->request_len;
    if (cc->max_frame == 0u) {
        /* writeHeaders with the peer's SETTINGS_MAX_FRAME_SIZE of zero, which x/net takes without
         * question (processSettingsNoWrite): every chunk of the block is empty, so the loop writes
         * HEADERS and then CONTINUATIONs with nothing in them for as long as writes succeed, holding
         * cc.wmu and reqHeaderMu all the while (vendor/x-net/http2/transport.go:1440-1463). What
         * waits on either waits for good; the frames go out as fast as the connection takes them —
         * see spew. */
        w_frame(f, cc, LC_H2_HEADERS, LC_H2_END_STREAM, s->id, NULL, 0);
        cc->stuck = 1;
        cc->spew_id = s->id;
        cc->spew_phase = 0;
        free(block);
        s->request_block = NULL;
        return s;
    }
    /* writeHeaders (vendor/x-net/http2/transport.go:1440-1463). */
    if (f->write_barrier) {
        cc->request_writer = s;
        request_progress(f, s);
        return s;
    }
    for (size_t done = 0; done < (size_t)bl;) {
        size_t  chunk = (size_t)bl - done < cc->max_frame ? (size_t)bl - done : cc->max_frame;
        uint8_t flags = (uint8_t)(done + chunk == (size_t)bl ? LC_H2_END_HEADERS : 0u);
        if (done == 0u)
            w_frame(f, cc, LC_H2_HEADERS, (uint8_t)(flags | LC_H2_END_STREAM), s->id, block, chunk);
        else
            w_frame(f, cc, H2_CONTINUATION, flags, s->id, block + done, chunk);
        done += chunk;
    }
    bw_flush(f, cc);
    free(block);
    s->request_block = NULL;
    s->sent_end_stream = 1;
    return s;
}

/* ---- Do -------------------------------------------------------------------------------------- */

static void do_free(lc_spider_fetch *f)
{
    struct fetch_do *d = f->d;
    if (d == NULL)
        return;
    lc_url_free(&d->first);
    lc_url_free(&d->base);
    lc_url_free(&d->next);
    lc_spider_req_free(&d->q);
    lc_str_free(&d->ref);
    lc_redir_free(&d->r);
    free(d);
    f->d = NULL;
}

/* Do has returned, or the spider's pass after it. What it needed goes; the connection stays, and so
 * does every readLoop on it. */
static void do_end(lc_spider_fetch *f)
{
    f->state = DO_END;
    do_free(f);
}

/* One attempt: a ClientConn for the key, and RoundTrip on it. A dial that fails fails Do.
 *
 * WHO DIALS IS GO 1.27'S. The attempts are RoundTripOpt's — up to seven, at once the first time and
 * then after a backoff (GOROOT/src/net/http/internal/http2/transport.go:408-461) — but its pool no
 * longer dials: with no ClientConn for the key it returns ErrNoCachedConn, and net/http's own
 * roundTrip loop takes that for a retry — at once, with no bound — dials, and calls RoundTripOpt
 * afresh on the new connection, whose count starts from nothing (GOROOT/src/net/http/
 * transport.go:740-770). So a dial puts the count back to 0: attempts on one connection that stays
 * usable keep their backoff and their cap, and a connection that dies is replaced every time.
 * Go 1.26's x/net pool dialled itself and kept counting (roundTripViaPool,
 * vendor/x-net/http2/transport_common.go:336-389): seven attempts, dials included, then Do failed. */
static void attempt(lc_spider_fetch *f)
{
    struct fetch_do *d = f->d;
    int              dialed;
    fetch_cc        *cc = get_client_conn(f, &d->q, &dialed);
    if (dialed)
        d->retry = 0;
    if (cc == NULL) {
        do_end(f);
        return;
    }
    lc_hpack_field fs[FETCH_FIELDS];
    unsigned       n = request_fields(d, fs);
    if (n == 0u) {
        do_end(f);
        return;
    }
    d->s = round_trip(f, cc, fs, n, d->q.headers);
    if (d->s == NULL) {
        do_end(f);
        return;
    }
    f->state = DO_ATTEMPT;
}

/* mathrand.Float64: 53 random bits. */
static double rand_float64(void)
{
    uint8_t  b[8];
    uint64_t v = 0;
    if (lc_rnd(b, sizeof b) != 0)
        memset(b, 0, sizeof b);
    for (int i = 0; i < 8; i++)
        v = v << 8 | b[i];
    return (double)(v >> 11) / 9007199254740992.0;
}

/* RoundTrip returned its stream's error: retried when canRetryError says so, while retry <= 6 —
 * at once the first time, then after 2^(retry-1) seconds and a tenth more at most, which
 * time.Duration(backoff) cuts to whole seconds. */
static void on_failure(lc_spider_fetch *f, uint64_t now)
{
    struct fetch_do *d = f->d;
    fetch_stream    *s = d->s;
    int kind = s->abort_kind;
    int retryable = kind == AB_UNUSABLE || kind == AB_GOAWAY ||
                    ((kind == AB_STREAM || kind == AB_PEER) && s->abort_code == ERR_REFUSED);
    if (retryable && d->retry <= FETCH_TRIES) {
        if (d->retry == 0u) {
            d->retry++;
            attempt(f);
            return;
        }
        double backoff = (double)(1u << (d->retry - 1u));
        backoff += backoff * (0.1 * rand_float64());
        d->retry_at = now + (uint64_t)backoff * 1000u;
        d->retry++;
        f->state = DO_RETRY;
        return;
    }
    if (kind == AB_NOT_EST)
        s->cc->in_pool = 0; /* MarkDead */
    do_end(f);
}

/* The slurp or the page read starts. */
static void start_reader(lc_spider_fetch *f, int kind)
{
    struct fetch_do *d = f->d;
    d->rd = kind;
    d->rd_done = 0;
    d->rd_err = 0;
    d->limit = FETCH_SLURP;
    d->cap = 512u;
    d->len = 0;
    d->next_cap = 256u;
    reader_step(f);
}

/* The next hop's req.Header: a fresh map filled from the clone — without the cookie once the host
 * has left the first one's domain — and the referer set on top when refererForURL gives one
 * (makeHeadersCopier and refererForURL, GOROOT/src/net/http/client.go:149-173, :695-712,
 * :772-843). The cookie is the last key Xray sets. */
static int hop_map(struct fetch_do *d)
{
    unsigned skip = ~0u;
    if (d->strip)
        for (unsigned i = 0; i < d->clone.n; i++)
            if (d->clone_from[i] == d->nkeys - 1u)
                skip = i;
    lc_gomap_init(&d->hop_map);
    int copied = lc_gomap_copy(&d->clone, &d->hop_map, skip, d->hop_from);
    if (copied < 0)
        return -1;
    d->hop_copied = copied;
    if (d->ref.n != 0u && lc_gomap_insert(&d->hop_map) != 0)
        return -1;
    d->hop = 1;
    return 0;
}

/* Do's answer to a response (GOROOT/src/net/http/client.go:634-762): the page, returned; or a
 * redirect — the Location resolved, the next request made, checkRedirect asked, the body slurped
 * when it is short or of no known length, and closed. */
/* http.Client.Do prepares the next URL/header map outside ClientConn's locks. Only Do owns
 * these fields; neither readLoop nor Write completion uses them. */
static int prepare_redirect(struct fetch_do *d, const char *location, size_t location_len)
{
    /* req.URL.Parse(loc), and what x/net makes of the result — see lc_redirect. */
    if (lc_redirect(&d->first, d->strip, &d->base, location, location_len, &d->next, &d->r) !=
        0) {
        return -1;
    }
    if (d->r.outcome == LC_REDIR_NONE) {
        d->check_err = 1; /* resp.closeBody() and the error: no slurp */
        return 0;
    }
    d->strip = d->r.strip;
    lc_str_free(&d->ref);
    d->ref = d->r.referer;
    d->r.referer = (lc_str){ 0 };
    if (hop_map(d) != 0)
        return -1;
    d->check_err = d->nreqs >= FETCH_HOPS;
    return 0;
}

static void on_response(lc_spider_fetch *f)
{
    struct fetch_do *d = f->d;
    fetch_stream    *s = d->s;
    if (reader_only_response(s)) {
        f->state = DO_READ; /* Do returns it, and the spider reads it (reality.go:263-268) */
        start_reader(f, RD_ALL);
        return;
    }
    /* Response metadata remains stream-owned until stop/join/free; do_lock keeps another
     * consumer from replacing Do. Feed/completion/stop need only the protocol mutex. */
    const char *location = s->location;
    size_t location_len = s->location_len;
    int64_t length = s->length;
    pthread_mutex_unlock(&f->lock);
    int rc = prepare_redirect(d, location, location_len);
    pthread_mutex_lock(&f->lock);
    f->ctx = CTX_DO;
    f->ctx_s = NULL;
    if (f->consumer_stopped || f->closed)
        return;
    if (rc != 0) {
        f->oom = 1;
        do_end(f);
        return;
    }
    if (d->r.outcome == LC_REDIR_NONE) {
        f->state = DO_CLOSE;
        return;
    }
    if (length == -1 || length <= (int64_t)FETCH_SLURP) {
        f->state = DO_SLURP;
        start_reader(f, RD_SLURP);
        return;
    }
    f->state = DO_CLOSE;
}

/* After the Close: checkRedirect's error returned, or the next request sent — refused by x/net
 * outright when it is not https (vendor/x-net/http2/transport.go:404-416). */
static void after_close(lc_spider_fetch *f)
{
    struct fetch_do *d = f->d;
    if (d->check_err || d->r.outcome == LC_REDIR_SCHEME) {
        do_end(f);
        return;
    }
    d->nreqs++;
    lc_url was = d->base;
    d->base = d->next;
    d->next = was;
    lc_spider_req_free(&d->q);
    d->q = d->r.req;
    d->r.req = (lc_spider_req){ 0 };
    if (auth_map(d) != 0) {
        do_end(f);
        return;
    }
    d->retry = 0;
    d->rd = RD_NONE;
    attempt(f);
}

/* io.ReadAll has returned: the page is harvested when it ended in EOF — `if body, err =
 * io.ReadAll(resp.Body); err != nil { break }`, then the links (reality.go:263-275) — and the body
 * closed by the deferred Close as the pass returns. */
static void page_end(lc_spider_fetch *f)
{
    struct fetch_do *d = f->d;
    if (!d->rd_err) {
        /* DIVERGES: G2. Xray harvests after io.ReadAll under maps.Lock alone
         * (vendor/Xray-core/transport/internet/reality/reality.go:268-284).
         * The path-store lock can wait on another session. Do owns the sink and
         * its lifetime through do_lock; readLoop/cleanup must keep progressing. */
        pthread_mutex_unlock(&f->lock);
        lc_spider_sink_commit(f->sink);
        pthread_mutex_lock(&f->lock);
        f->ctx = CTX_DO;
        f->ctx_s = NULL;
        if (f->consumer_stopped || f->closed)
            return;
    }
    f->state = DO_FINISH;
}

/* Do, and the spider's pass around it, going as far as what it waits for allows. */
static void do_run(lc_spider_fetch *f, uint64_t now)
{
    f->ctx = CTX_DO;
    f->ctx_s = NULL;
    while (f->d != NULL && !f->consumer_stopped && !f->closed && !f->oom &&
           !f->do_blocked && !f->yielded) {
        struct fetch_do *d = f->d;
        fetch_stream    *s = d->s;
        if (output_pending(f) &&
            !(round_trip_admission_ready(f) ||
              (f->state == DO_ATTEMPT && s != NULL && s->resp) ||
              f->state == DO_SLURP || f->state == DO_READ ||
              ((f->state == DO_CLOSE || f->state == DO_FINISH) && close_ready(s))))
            return;
        switch (f->state) {
        case DO_START: {
            lc_hpack_field fs[FETCH_FIELDS];
            unsigned       n = request_fields(d, fs);
            d->s = n > 0u ? round_trip(f, d->first_cc, fs, n, d->q.headers) : NULL;
            if (d->s == NULL) {
                do_end(f);
                break;
            }
            f->state = DO_ATTEMPT;
            break;
        }
        case DO_ATTEMPT:
            /* RoundTrip's wait in internalRoundTrip (vendor/x-net/http2/transport.go:1057-1081):
             * the answer, when it came — even with an abort beside it (golang.org/issue/49645);
             * else the abort, once doRequest has cleaned up. */
            if (s->resp) {
                if (s->body == BODY_NONE && !s->done)
                    return; /* waitDone */
                on_response(f);
                break;
            }
            if (s->abort && s->done) {
                on_failure(f, now);
                break;
            }
            return;
        case DO_RETRY:
            if (now < d->retry_at)
                return;
            attempt(f);
            break;
        case DO_SLURP:
            if (!d->rd_done)
                return;
            f->state = DO_CLOSE;
            break;
        case DO_CLOSE:
            close_body(f, s);
            if (f->write_barrier && s->body == BODY_PIPE && (s->close_pending || !s->done))
                return; /* Body.Close waits for cleanup's donec, not merely its queued reset. */
            f->state = DO_NEXT;
            break;
        case DO_NEXT:
            after_close(f);
            break;
        case DO_READ:
            if (!d->rd_done)
                return;
            page_end(f);
            break;
        case DO_FINISH:
            close_body(f, s);
            if (f->write_barrier && s->body == BODY_PIPE && (s->close_pending || !s->done))
                return;
            do_end(f);
            break;
        default:
            return;
        }
        if (f->single_read && f->d != NULL && !f->consumer_stopped &&
            !f->closed && !f->oom && !f->do_blocked) {
            /* Yield only after the transition is committed. Never retain d/s across the boundary:
             * on_response, after_close and page_end may replace or free Do's state. */
            f->yielded = 1;
            return;
        }
    }
}

/* ---- the first request ----------------------------------------------------------------------- */

static int first_request(lc_spider_fetch *f, const char *host, const lc_browser *b)
{
    /* THE PATH IS DRAWN, NOT FIXED — see reality/paths.h. SpiderX until a page has been read, and
     * after that whatever that page linked to, which is what the reference's package-level map of
     * paths makes of the second and later connections to a node that answers as a stranger. */
    char  *drawn = NULL;
    size_t dn = 0;
    if (lc_spider_path(host, &drawn, &dn) != 0)
        return -1;

    struct fetch_do *d = calloc(1, sizeof *d);
    if (d == NULL) {
        free(drawn);
        return -1;
    }
    f->d = d;

    /* And it is applied the way the reference applies it, which is not by putting it in a field.
     * The reference CONCATENATES — `firstURL := string(prefix) + getPathLocked(paths)`, prefix
     * being "https://" + ServerName (reality.go:220-231) — and hands the result to http.NewRequest,
     * so what the request carries is whatever parsing that string made of it, and sometimes that is
     * no request at all. The URL it made is the one the redirects resolve against and the cookie is
     * kept for. See lc_spider_target, held to Go's own net/http, net/url and x/net by test/spider. */
    int target = lc_spider_target(host, drawn, dn, &d->first, &d->q);
    free(drawn);
    if (target < 0)
        return -1;
    if (target == LC_SPIDER_NONE) {
        /* NewRequest failed: the reference dials nothing, so nothing is written — and no ClientConn
         * exists to read the connection or answer a SETTINGS on it. */
        f->quiet = 1;
        do_end(f);
        return 0;
    }
    if (lc_url_copy(&d->base, &d->first) != 0)
        return -1;

    /* The browser's headers and the padding cookie — req.Header, in the order Xray fills it:
     * TryDefaultHeadersWith's fourteen — on an untouched header it calls applyMasqueradedHeaders
     * with "chrome", whose chrome and "nav" arms set them
     * (vendor/Xray-core/common/utils/browser.go:269-270, :165-171, :196-220) — then the cookie
     * (reality.go:262), fifteen keys in all.
     *
     * The padding cookie has an EMPTY value: `req.AddCookie(&http.Cookie{Name: "padding", Value:
     * strings.Repeat("0", RandBetween(SpiderY[0], SpiderY[1]))})` — and both of those are zero
     * unless spiderX carries `?p=`. Repeat of zero is the empty string, and Go writes the cookie
     * anyway: the header is present and its value is "padding=". It goes into req.Header like any
     * other, so it is walked with the rest rather than pinned after them. */
    d->b = *b;
    for (unsigned i = 0; i < d->b.count && d->nkeys < FETCH_KEYS - 1u; i++) {
        const char *v = b->header[i].value;
        if (v == b->ua)
            v = d->b.ua;
        else if (v == b->chua)
            v = d->b.chua;
        d->keys[d->nkeys++] = (lc_hpack_field){ b->header[i].name, v };
    }
    d->keys[d->nkeys++] = (lc_hpack_field){ "cookie", "padding=" };

    /* THE ORDER OF THE FIRST FOUR IS THE REFERENCE'S, AND THE REST ARE WALKED AS A GO MAP.
     *
     * Go's HTTP/2 writer emits `:authority`, `:method`, `:path`, `:scheme` and then walks the
     * request's header MAP (vendor/x-net/internal/httpcommon/request.go:138-146, :156). A map walk
     * in Go is deliberately randomised, and a client that sent the same order every time would be
     * read off the wire by a prober poking the same node twice. The walk is Go's, not a shuffle — see
     * core/gomap, held to Go's own maps by test/gomap.
     *
     * AND IT IS ONE MAP, walked again and again: once by makeHeadersCopier, whose Header.Clone is
     * what every redirect copies from (GOROOT/src/net/http/client.go:772-777 — made before the first
     * request is sent), and once by x/net for every attempt at the first request. Walks of one map
     * are rotations of one layout, not unrelated orders. */
    lc_gomap_init(&d->h);
    for (unsigned i = 0; i < d->nkeys; i++)
        if (lc_gomap_insert(&d->h) != 0)
            return -1;
    lc_gomap_init_hint(&d->clone, d->nkeys);
    if (lc_gomap_copy(&d->h, &d->clone, ~0u, d->clone_from) < 0 || auth_map(d) != 0)
        return -1;

    /* The first RoundTrip follows the opening Flush. The readLoop and doRequest then run
     * independently; admission does not wait for a readLoop ACK's writer. HEADERS still acquires
     * cc.wmu on the request task's turn, using any SETTINGS parsed before encoding. */
    d->nreqs = 1u;
    int dialed;
    d->first_cc = get_client_conn(f, &d->q, &dialed);
    if (d->first_cc == NULL) {
        do_end(f);
        return f->oom ? -1 : 0;
    }
    f->state = DO_START;
    return f->oom ? -1 : 0;
}

lc_spider_fetch *lc_spider_fetch_new(const char *host, const lc_browser *b)
{
    if (host == NULL || host[0] == '\0' || b == NULL)
        return NULL;
    lc_spider_fetch *f = calloc(1, sizeof *f);
    if (f == NULL)
        return NULL;
    if (pthread_mutex_init(&f->lock, NULL) != 0) {
        free(f);
        return NULL;
    }
    if (pthread_mutex_init(&f->do_lock, NULL) != 0) {
        pthread_mutex_destroy(&f->lock);
        free(f);
        return NULL;
    }
    pthread_condattr_t attr;
    if (pthread_condattr_init(&attr) != 0) {
        pthread_mutex_destroy(&f->do_lock);
        pthread_mutex_destroy(&f->lock);
        free(f);
        return NULL;
    }
    int rc = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    if (rc == 0) {
        rc = pthread_cond_init(&f->consumer, &attr);
        if (rc == 0) {
            rc = pthread_cond_init(&f->request_consumer, &attr);
            if (rc != 0)
                pthread_cond_destroy(&f->consumer);
        }
    }
    pthread_condattr_destroy(&attr);
    if (rc != 0) {
        pthread_mutex_destroy(&f->do_lock);
        pthread_mutex_destroy(&f->lock);
        free(f);
        return NULL;
    }
    f->generation = 1u; /* The first Do turn is ready before publication. */
    /* What the page says the site has, kept for the connections that follow this one: the reference
     * draws the path of every later stranger connection out of exactly this harvest
     * (reality/paths.h). A sink that could not be made costs the harvest and nothing else. */
    f->sink = lc_spider_sink_new(host);
    if (first_request(f, host, b) != 0) {
        lc_spider_fetch_free(f);
        return NULL;
    }
    return f;
}

void lc_spider_fetch_free(lc_spider_fetch *f)
{
    if (f == NULL)
        return;
    do_free(f);
    for (fetch_cc *cc = f->ccs; cc != NULL;) {
        fetch_cc *next = cc->next;
        for (fetch_stream *s = cc->streams; s != NULL;) {
            fetch_stream *sn = s->next;
            free(s->location);
            free(s->request_fields);
            free(s->request_block);
            pipe_drop(s);
            lc_gozip_free(s->gz);
            free(s->source_read);
            free(s);
            s = sn;
        }
        meta_reset(&cc->m);
        lc_hpack_dec_free(&cc->dec);
        free(cc->payload);
        free(cc->key);
        free(cc);
        cc = next;
    }
    lc_spider_sink_free(f->sink);
    free(f->out);
    free(f->cut);
    free(f->held_input);
    pthread_cond_destroy(&f->request_consumer);
    pthread_cond_destroy(&f->consumer);
    pthread_mutex_destroy(&f->do_lock);
    pthread_mutex_destroy(&f->lock);
    free(f);
}

int lc_spider_fetch_wait(lc_spider_fetch *f, uint64_t *generation)
{
    if (f == NULL || generation == NULL)
        return -1;
    pthread_mutex_lock(&f->lock);
    int rc = 0;
    while (!f->consumer_stopped && !f->closed && !f->oom && !do_task_finished(f) && rc == 0) {
        /* Completion is a predicate, not an input generation: DATA/PING may wake this condition
         * while the socket still holds our Write. Retry must not turn that wait into a spin. */
        if (output_pending(f) && !consumer_ready(f)) {
            rc = pthread_cond_wait(&f->consumer, &f->lock);
            continue;
        }
        if (*generation != f->generation)
            break;
        uint64_t at = f->state == DO_RETRY && f->d != NULL ? f->d->retry_at : 0u;
        if (at == 0u) {
            rc = pthread_cond_wait(&f->consumer, &f->lock);
        } else {
            struct timespec deadline = { .tv_sec = (time_t)(at / 1000u),
                                        .tv_nsec = (long)(at % 1000u) * 1000000L };
            rc = pthread_cond_timedwait(&f->consumer, &f->lock, &deadline);
        }
    }
    int result = f->consumer_stopped || do_task_finished(f) ? 0 :
                 (rc == 0 || rc == ETIMEDOUT ? 1 : -1);
    *generation = f->generation;
    pthread_mutex_unlock(&f->lock);
    return result;
}

void lc_spider_fetch_stop(lc_spider_fetch *f)
{
    if (f == NULL)
        return;
    pthread_mutex_lock(&f->lock);
    f->consumer_stopped = 1;
    notify_consumers(f);
    pthread_mutex_unlock(&f->lock);
}

int lc_spider_fetch_feed(lc_spider_fetch *f, const uint8_t *data, size_t len)
{
    if (f == NULL)
        return -1;
    pthread_mutex_lock(&f->lock);
    /* A feed accepted while dispatch blocks retains its tail. The TLS owner must consult
     * read_ready before opening another record, rather than making an unbounded input queue. */
    int rc = f->closed || f->held_input != NULL || read_dispatch_pending(f) ?
             -1 : readers_feed(f, data, len);
    if (f->oom)
        rc = -1;
    f->generation++;
    notify_consumers(f);
    pthread_mutex_unlock(&f->lock);
    return rc;
}

static int fetch_settle_locked(lc_spider_fetch *f, uint64_t now_ms)
{
    if (f == NULL || f->closed)
        return -1;
    int output_before = output_pending(f);
    for (fetch_cc *cc = f->request_tasks ? NULL : f->ccs; cc != NULL; cc = cc->next) {
        if (output_pending(f))
            break; /* A readLoop/request producer resumes only after its own Write boundary. */
        if (!f->request_tasks && cc->request_writer != NULL) {
            request_progress(f, cc->request_writer);
            f->yielded = 1;
            return f->oom ? -1 : 0;
        }
        if (cc->writer_wait && cc->read_write_id == 0u) {
            cc->writer_wait = 0;
            f->ctx = CTX_READLOOP;
            f->ctx_cc = cc;
            if (cc_run(f, cc) != 0) {
                close_conn(f);
                return -1;
            }
        }
    }
    if (!f->request_tasks && f->held_input != NULL && !output_pending(f)) {
        uint8_t *held = f->held_input;
        size_t len = f->held_len;
        f->held_input = NULL;
        f->held_len = 0;
        int rc = readers_feed(f, held, len);
        free(held);
        if (rc != 0)
            return rc;
    }
    if (!output_before && output_pending(f)) {
        f->yielded = 1;
        return 0;
    }
    if (output_pending(f) && !consumer_ready(f)) {
        return 0;
    }
    if (f->body_ready && (!output_pending(f) || body_consumer_ready(f))) {
        f->body_ready = 0;
        reader_step(f);
        if (f->consumer_stopped || f->closed || f->oom)
            return f->closed || f->oom ? -1 : 0;
        if (f->yielded)
            return f->closed || f->oom ? -1 : 0;
    }
    /* Every doRequest whose wait has ended — the peer finished its stream, or it was aborted —
     * cleans up before Do acts: Do waits on that where it waits on anything (waitDone, Close). */
    for (fetch_cc *cc = f->request_tasks ? NULL : f->ccs;
         cc != NULL && !f->closed; cc = cc->next)
        for (fetch_stream *s = cc->streams; s != NULL && !f->closed; s = s->next)
            if (cleanup_ready(f, s)) {
                cleanup_stream(f, s);
                if (f->single_read) {
                    /* Completed or permanently blocked cleanup is recorded on s. The next step
                     * rescans those predicates rather than retaining a stream pointer/cursor. */
                    f->yielded = 1;
                    return f->closed || f->oom ? -1 : 0;
                }
            }
    if (!output_pending(f) || do_consumer_ready(f))
        do_run(f, now_ms);
    return f->closed || f->oom ? -1 : 0;
}

int lc_spider_fetch_settle(lc_spider_fetch *f, uint64_t now_ms)
{
    if (f == NULL)
        return -1;
    pthread_mutex_lock(&f->do_lock);
    pthread_mutex_lock(&f->lock);
    /* Legacy driver cannot bypass explicit completion ownership. Reject mixed drivers without
     * advancing state; barrier callers must use step and acknowledge actual socket completion. */
    int rc = f->write_barrier ? -1 : fetch_settle_locked(f, now_ms);
    pthread_mutex_unlock(&f->lock);
    pthread_mutex_unlock(&f->do_lock);
    return rc;
}

static int readloop_pending(const lc_spider_fetch *f)
{
    if (f->held_input != NULL)
        return 1;
    for (const fetch_cc *cc = f->ccs; cc != NULL; cc = cc->next)
        if (cc->writer_wait || cc->data_pending || cc->read_pending)
            return 1;
    return 0;
}

/* The socket/TLS owner resumes its already accepted input, independently of Do.
 * No socket operation, private Do state, cleanup phase or Write acknowledgment
 * is performed here. An in-flight foreign Write is not a read barrier. Already
 * queued runnable I/O returns to the owner before further frame dispatch.
 * cc_run takes cc.wmu only for a frame's own control/credit Write, as Go's
 * readLoop/processData do. Its own pending Flush and the opening still block it.
 * One accepted feed remains the input bound; read_ready controls further TLS reads. */
int lc_spider_fetch_read_step(lc_spider_fetch *f)
{
    if (f == NULL)
        return -1;
    pthread_mutex_lock(&f->lock);
    int rc = 0;
    if (!f->request_tasks)
        rc = -1;
    else if (f->consumer_stopped)
        rc = 0;
    else if (f->closed || f->oom)
        rc = -1;
    else {
        for (fetch_cc *cc = f->ccs; cc != NULL; cc = cc->next) {
            if (cc->closed || cc->reader_blocked || (!cc->writer_wait && !cc->read_pending) ||
                cc->read_write_id != 0u || cc->opening_write_id != 0u)
                continue;
            /* A pending DATA post-body phase needs wmu only while credit remains;
             * after its own Flush, END_STREAM can run behind a different owner. */
            int needs_writer = cc->data_pending ?
                cc->data_conn_credit != 0u || cc->data_stream_credit != 0u :
                cc->in_payload && cc->pay_have == cc->fh.len && frame_needs_writer(&cc->fh);
            if (needs_writer && cleanup_writer_busy(cc))
                continue;
            cc->writer_wait = 0;
            cc->read_pending = 0;
            f->ctx = CTX_READLOOP;
            f->ctx_cc = cc;
            rc = 1;
            if (cc_run(f, cc) != 0) {
                close_conn(f);
                rc = -1;
                break;
            }
            if (cc->read_pending)
                break;
        }
        if (rc >= 0 && f->held_input != NULL && !read_dispatch_pending(f)) {
            int ready = 0;
            for (fetch_cc *cc = f->ccs; cc != NULL; cc = cc->next)
                ready |= !cc->closed && !cc->reader_blocked && !cc->writer_wait &&
                         cc->opening_write_id == 0u;
            if (ready) {
                uint8_t *held = f->held_input;
                size_t len = f->held_len;
                f->held_input = NULL;
                f->held_len = 0;
                rc = readers_feed(f, held, len) == 0 ? 1 : -1;
                free(held);
            }
        }
        /* Once Do has returned, readLoop owns deferred EOF too. Retiring an
         * HTTP executor must not strand a later TLS close_notify/socket EOF.
         * Preserve the existing barrier: accepted input and queued Writes go first. */
        if (f->loss_pending && do_task_finished(f) &&
            !readloop_pending(f) && !output_pending(f)) {
            f->loss_pending = 0;
            close_conn(f);
            rc = -1;
        }
        if (f->closed || f->oom)
            rc = -1;
    }
    if (rc != 0) {
        f->generation++;
        notify_consumers(f);
    }
    pthread_mutex_unlock(&f->lock);
    return rc;
}

int lc_spider_fetch_step(lc_spider_fetch *f, uint64_t now_ms)
{
    if (f == NULL)
        return -1;
    pthread_mutex_lock(&f->do_lock);
    pthread_mutex_lock(&f->lock);
    f->single_read = 1;
    f->yielded = 0;
    int rc;
    if (f->consumer_stopped)
        rc = 0;
    else if (f->closed || f->oom) {
        if (f->closed && !f->request_tasks)
            cleanup_closed_finals(f);
        rc = -1;
    }
    else if (output_pending(f) && !consumer_ready(f))
        rc = 2;
    else {
        rc = fetch_settle_locked(f, now_ms);
        /* EOF/error is handed off by the TLS owner, but consumed here: bytes fed immediately
         * before it (including DATA|END_STREAM) must get their body turn before close_conn aborts
         * unfinished streams. */
        if (rc == 0 && !f->consumer_stopped && f->loss_pending &&
            !f->yielded && !output_pending(f) &&
            (!f->request_tasks || !readloop_pending(f))) {
            f->loss_pending = 0;
            close_conn(f);
            rc = -1;
        }
    }
    if (rc == 0 && f->yielded)
        rc = 1;
    else if (rc == 0 && !f->consumer_stopped && output_pending(f))
        rc = 2;
    f->single_read = 0;
    f->yielded = 0;
    if (f->request_tasks) {
        /* Request readiness is a predicate. Do must not advance its own input
         * generation on a quiescent step, which would make wait/step spin. */
        notify_request_consumer(f);
    }
    pthread_mutex_unlock(&f->lock);
    pthread_mutex_unlock(&f->do_lock);
    return rc;
}

/* Only protocol-owned state is touched here. In particular this task never takes
 * do_lock, uses Do's per-turn yielded flags, or keeps a cursor across a wait.
 * It can finish a request while Do prepares a redirect outside the protocol lock. */
int lc_spider_fetch_request_step(lc_spider_fetch *f)
{
    if (f == NULL)
        return -1;
    pthread_mutex_lock(&f->lock);
    int rc = 0;
    int admitted_only = 0;
    if (!f->request_tasks)
        rc = -1;
    else if (f->consumer_stopped)
        rc = 0;
    else if (f->closed || f->oom) {
        if (f->closed)
            cleanup_closed_finals(f);
        rc = -1;
    } else {
        for (fetch_cc *cc = f->ccs; cc != NULL && rc == 0; cc = cc->next) {
            if (request_producer_ready(cc)) {
                if (cc->request_pending != NULL && cc->request_pending->id == 0u) {
                    fetch_stream *pending = cc->request_pending;
                    if (request_admit(pending) != 0) {
                        if (!pending->doreq_blocked) {
                            cc->request_pending = NULL;
                            free(pending->request_fields);
                            pending->request_fields = NULL;
                        }
                        rc = 1;
                        break;
                    }
                    admitted_only = 1;
                    rc = 1; /* Release cc.mu before encodeAndWriteHeaders acquires cc.wmu. */
                    break;
                }
                if (cc->request_writer == NULL) {
                    cc->request_writer = cc->request_pending;
                    cc->request_pending = NULL;
                }
                request_progress(f, cc->request_writer);
                rc = 1;
                break;
            }
            for (fetch_stream *s = cc->streams; s != NULL; s = s->next)
                if (cleanup_ready(f, s)) {
                    cleanup_stream(f, s);
                    rc = 1;
                    break;
                }
        }
        if (f->closed || f->oom)
            rc = -1;
    }
    if (rc != 0) {
        /* DIVERGES: O8. addStreamLocked only assigns protocol state; it does not
         * signal RoundTrip's response/abort/donec channels (transport.go:1710).
         * Keep the request continuation runnable without waking an idle Do.
         * Encoding, rejection, cleanup and terminal failures still publish. */
        if (!admitted_only || rc < 0) {
            publish_task_progress(f);
        } else {
            notify_request_consumer(f);
        }
    }
    pthread_mutex_unlock(&f->lock);
    return rc;
}

int lc_spider_fetch_request_wait(lc_spider_fetch *f)
{
    if (f == NULL)
        return -1;
    pthread_mutex_lock(&f->lock);
    int rc = 0;
    while (f->request_tasks && !f->consumer_stopped && !f->closed && !f->oom &&
           !request_task_finished(f) && !request_task_ready(f) && rc == 0)
        rc = pthread_cond_wait(&f->request_consumer, &f->lock);
    int result = f->consumer_stopped ? 0 :
                 !f->request_tasks || f->closed || f->oom || rc != 0 ? -1 :
                 request_task_finished(f) ? 0 : 1;
    pthread_mutex_unlock(&f->lock);
    return result;
}

int lc_spider_fetch_write_complete(lc_spider_fetch *f, int success)
{
    if (f == NULL)
        return -1;
    pthread_mutex_lock(&f->lock);
    if (!f->write_barrier || !f->write_inflight) {
        pthread_mutex_unlock(&f->lock);
        return -1;
    }
    f->write_inflight = 0;
    if (!success && f->active_write.writer != NULL) {
        f->active_write.writer->werr = 1;
        f->active_write.writer->stuck = 0;
    }
    for (fetch_cc *cc = f->ccs; cc != NULL; cc = cc->next)
        if (cc->opening_write_id == f->active_write.id) {
            cc->opening_write_id = 0;
            if (success)
                cc->seq = ++f->seq; /* start readLoop at its own completed Flush */
        }
    fetch_cc *reader = f->active_write.reader;
    if (success && reader != NULL && reader->read_write_id == f->active_write.id)
        reader->read_write_id = 0;
    fetch_stream *stream = f->active_write.stream;
    if (success && stream != NULL && f->active_write.ctx == CTX_DOREQ) {
        if (stream->request_write_id == f->active_write.id) {
            stream->request_write_id = 0;
            if (stream->request_off == stream->request_len) {
                free(stream->request_block);
                stream->request_block = NULL;
                stream->cc->request_writer = NULL;
                stream->sent_end_stream = 1;
            }
        }
        if (stream->cleanup_write_id == f->active_write.id) {
            stream->cleanup_write_id = 0;
            if (stream->cc->cleanup_writer == stream)
                stream->cc->cleanup_writer = NULL;
            if (stream->cleanup_pending && !f->request_tasks) {
                stream->cleanup_pending = 0;
                cleanup_after_write(f, stream);
            }
        }
    }
    if (success && stream != NULL && stream->source_write_id == f->active_write.id) {
        stream->source_write_id = 0;
        if (stream->cc->source_writer == stream)
            stream->cc->source_writer = NULL;
    }
    if (success && stream != NULL && stream->close_write_id == f->active_write.id) {
        stream->close_write_id = 0;
        if (stream->cc->close_writer == stream)
            stream->cc->close_writer = NULL;
    }
    if (!success) {
        /* The underlying Write returned an error: its goroutine releases cc.wmu.
         * Saved body/DATA results must not be delivered after the connection failure. */
        if (reader != NULL && reader->read_write_id == f->active_write.id)
            reader->read_write_id = 0;
        if (stream != NULL) {
            fetch_cc *cc = stream->cc;
            if (stream->request_write_id == f->active_write.id) {
                stream->request_write_id = 0;
                if (cc->request_writer == stream)
                    cc->request_writer = NULL;
            }
            if (stream->cleanup_write_id == f->active_write.id) {
                stream->cleanup_write_id = 0;
                if (cc->cleanup_writer == stream)
                    cc->cleanup_writer = NULL;
            }
            if (stream->source_write_id == f->active_write.id) {
                stream->source_write_id = 0;
                if (cc->source_writer == stream)
                    cc->source_writer = NULL;
            }
            if (stream->close_write_id == f->active_write.id) {
                stream->close_write_id = 0;
                if (cc->close_writer == stream)
                    cc->close_writer = NULL;
            }
        }
    }
    memset(&f->active_write, 0, sizeof f->active_write);
    if (f->d != NULL && body_writer_ready(f->d->s))
        f->body_writer_wait = 0;
    if (!success && !f->closed)
        close_conn(f);
    publish_task_progress(f);
    pthread_mutex_unlock(&f->lock);
    return 0;
}

void lc_spider_fetch_lost(lc_spider_fetch *f)
{
    if (f == NULL)
        return;
    pthread_mutex_lock(&f->lock);
    if (!f->closed)
        close_conn(f);
    f->generation++;
    notify_consumers(f);
    pthread_mutex_unlock(&f->lock);
}

void lc_spider_fetch_loss_pending(lc_spider_fetch *f)
{
    if (f == NULL)
        return;
    pthread_mutex_lock(&f->lock);
    if (!f->closed)
        f->loss_pending = 1;
    f->generation++;
    notify_consumers(f);
    pthread_mutex_unlock(&f->lock);
}

uint64_t lc_spider_fetch_deadline(lc_spider_fetch *f)
{
    if (f == NULL)
        return 0;
    pthread_mutex_lock(&f->lock);
    uint64_t at = f->state == DO_RETRY && f->d != NULL ? f->d->retry_at : 0u;
    pthread_mutex_unlock(&f->lock);
    return at;
}

int lc_spider_fetch_done(lc_spider_fetch *f)
{
    if (f == NULL)
        return 1;
    pthread_mutex_lock(&f->lock);
    int done = f->state == DO_END;
    pthread_mutex_unlock(&f->lock);
    return done;
}

int lc_spider_fetch_reads(lc_spider_fetch *f)
{
    if (f == NULL)
        return 0;
    pthread_mutex_lock(&f->lock);
    int reads = f->ccs != NULL;
    pthread_mutex_unlock(&f->lock);
    return reads;
}

int lc_spider_fetch_read_ready(lc_spider_fetch *f)
{
    if (f == NULL)
        return 0;
    pthread_mutex_lock(&f->lock);
    int ready = 0;
    if (!f->closed && f->held_input == NULL && !read_dispatch_pending(f))
        for (fetch_cc *cc = f->ccs; cc != NULL; cc = cc->next)
            ready |= !cc->closed && !cc->reader_blocked && !cc->writer_wait &&
                     (!f->write_barrier || cc->opening_write_id == 0u);
    pthread_mutex_unlock(&f->lock);
    return ready;
}

/* ---- the request alone ----------------------------------------------------------------------- */

long lc_spider_request(const char *host, const lc_browser *b, uint8_t *out, size_t cap,
                       size_t *opening)
{
    lc_spider_fetch *f = lc_spider_fetch_new(host, b);
    if (f == NULL)
        return -1;
    (void)lc_spider_fetch_settle(f, 0); /* the request, nothing having arrived */
    *opening = 0;
    size_t at = 0;
    for (int i = 0; i < 2; i++) {
        uint8_t *w;
        long           n = lc_spider_fetch_take(f, &w);
        if (n < 0 || (size_t)n > cap - at) {
            free(w);
            lc_spider_fetch_free(f);
            return -1;
        }
        if (n > 0) {
            memcpy(out + at, w, (size_t)n);
        }
        free(w);
        if (i == 0)
            *opening = (size_t)n;
        at += (size_t)n;
    }
    lc_spider_fetch_free(f);
    return (long)at;
}
