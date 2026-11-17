/* lc-fetch — one request through the tunnel, end to end.
 *
 * The probe proved the server is ours. This proves the tunnel carries traffic: REALITY handshake,
 * VLESS request, an HTTP GET to a third host, and the reply read back. If this works, everything
 * between the socket and the proxied stream works.
 *
 *   lc-fetch TABLE.fpt HOST PORT SNI PBK SHORTID UUID TARGET [FLOW]
 *
 * TARGET is host:port. FLOW must match what the server has configured for this user — omit it for
 * a plain user, pass xtls-rprx-vision for a Vision one. A mismatch is refused without a diagnostic.
 */

#include "core/args.h"
#include "net/sock.h"
#include "reality/spider.h"
#include "tls/client.h"
#include "vless/vless.h"
#include "vless/vision.h"
#include "core/wipe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_TABLE 65536u
#define MAX_REC LC_REC_MAX_WIRE





/* Sends one application record and reads one back. Deliberately not a loop over a socket: this
 * tool answers "does anything come through at all", and a single exchange answers it. */
/* HOW LONG THIS PROBE READS A BODY BEFORE GIVING THE ANSWER IT HAS.

 * Named because it is now printed. It used to be a literal buried in the loop head, and the report
 * at the end said "N bytes" whether the body had ended or this number had — two different answers in
 * one sentence. A probe is a measuring tool before it is anything else, and a measuring tool that
 * cannot say which of the two happened produces numbers that look like measurements.
 *
 * 20 seconds is not a target for how long a transfer should take. It is the bound on a peer that
 * neither ends the stream nor sends anything more, which is the failure this probe exists to survive.
 * Fetching something larger than the window carries in 20 seconds is a legitimate use — that is how
 * the throughput figures in this tree were taken — and the line now says so instead of implying a
 * total. */
#define BODY_WINDOW_MS 20000u

static int send_app(int fd, lc_client *cl, const uint8_t *data, size_t len, uint64_t deadline)
{
    static uint8_t out[MAX_REC];
    size_t         out_len = 0;
    if (lc_record_protect(&cl->wr, LC_REC_APPLICATION_DATA, data, len, 0,
                          out, sizeof out, &out_len) != 0)
        return -1;
    return lc_write_full(fd, out, out_len, deadline);
}

static int recv_app(int fd, lc_client *cl, uint8_t *out, size_t cap, size_t *out_len,
                    uint8_t *inner, uint64_t deadline)
{
    static uint8_t rec[MAX_REC];
    if (lc_read_full(fd, rec, LC_REC_HEADER, deadline) != 0)
        return -1;
    size_t body = (size_t)rec[3] << 8 | rec[4];
    if (body > sizeof rec - LC_REC_HEADER)
        return -1;
    if (lc_read_full(fd, rec + LC_REC_HEADER, body, deadline) != 0)
        return -1;
    return lc_record_unprotect(&cl->rd, rec, LC_REC_HEADER + body, out, cap, out_len, inner);
}

int main(int argc, char **argv)
{
    /* Before any socket exists: a write to a peer that has gone must not end the process. */
    lc_ignore_sigpipe();
    if (argc < 9 || argc > 11) {
        fprintf(stderr,
                "usage: lc-fetch TABLE.fpt HOST PORT SNI PBK SHORTID UUID TARGET[:PORT] [FLOW [PATH]]\n"
                "  UUID takes @FILE as well as a literal.\n");
        return LC_EXIT_CONFIG;
    }

    static uint8_t table[MAX_TABLE];
    long           table_len = lc_read_file(argv[1], table, sizeof table);
    if (table_len < 0) {
        fprintf(stderr, "cannot read %s\n", argv[1]);
        return LC_EXIT_CONFIG;
    }

    lc_reality_config reality;
    memset(&reality, 0, sizeof reality);
    if (lc_from_hex(argv[5], reality.public_key, sizeof reality.public_key) != 0 &&
        lc_from_base64url(argv[5], reality.public_key, sizeof reality.public_key) != 0) {
        fprintf(stderr, "the public key is neither hex nor base64url\n");
        return LC_EXIT_CONFIG;
    }
    size_t sid_hex = strlen(argv[6]);
    if (sid_hex % 2u != 0u || sid_hex > LC_REALITY_SHORT_ID * 2u ||
        lc_from_hex(argv[6], reality.short_id, sid_hex / 2u) != 0) {
        fprintf(stderr, "the short id is not up to 16 hex characters\n");
        return LC_EXIT_CONFIG;
    }
    /* The version this client gives the node: Xray's own, v26.10.31
     * (vendor/Xray-core/core/core.go:21-23), which the REALITY client writes into the
     * session ID
     * (vendor/Xray-core/transport/internet/reality/reality.go:168-170). */
    reality.version[0] = LC_REALITY_VERSION_MAJOR;
    reality.version[1] = LC_REALITY_VERSION_MINOR;
    reality.version[2] = LC_REALITY_VERSION_PATCH;

    /* The account, written out or read from a file named with a leading @, and gone from the process
     * title either way. This was the last of the six tools to take it as a bare literal and leave it
     * there: a UUID in /proc/PID/cmdline is the whole credential, readable by anything on the box,
     * and lc-xfetch and lc-tunnel carried a comment each explaining why that is not acceptable while
     * the tool people copy from did it anyway. */
    uint8_t uuid[LC_VLESS_UUID];
    char    uuid_text[64] = { 0 };
    int     rc = lc_read_secret(argv[7], uuid_text, sizeof uuid_text);
    if (rc != 0) {
        fprintf(stderr, "cannot read the uuid: %s\n", lc_secret_why(rc));
        return LC_EXIT_CONFIG;
    }
    if (lc_vless_uuid(uuid_text, uuid) != 0) {
        fprintf(stderr, "the uuid does not parse\n");
        return LC_EXIT_CONFIG;
    }
    lc_wipe(uuid_text, sizeof uuid_text);
    memset(argv[7], 'x', strlen(argv[7]));

    char     target[256];
    uint16_t target_port = 80;
    if (lc_host_port(argv[8], target, sizeof target, &target_port, 80) != 0) {
        fprintf(stderr, "%s is not a target: HOST, HOST:PORT or [V6ADDR]:PORT\n", argv[8]);
        return LC_EXIT_CONFIG;
    }
    /* argc >= 10, not == 10: the path may follow the flow, and an equality test here silently
     * dropped the flow the moment it did — turning a Vision run into a plain one that still
     * connects, still transfers, and is simply not the thing being measured. */
    const char *flow = argc >= 10 ? argv[9] : NULL;
    /* One flow and the absence of one is the whole set (vendor/Xray-core/proxy/vless/vless.go:17-18).
     * Refused here rather than sent, because a third string used to travel in the addons block while
     * the framing beside it stayed plain — which the node answers with silence. */
    if (lc_vless_flow(flow) < 0) {
        fprintf(stderr, "%s is not a flow: pass " LC_VLESS_FLOW_VISION " or omit it\n", flow);
        return LC_EXIT_CONFIG;
    }

    uint16_t node_port;
    if (lc_port(argv[3], &node_port) != 0) {
        fprintf(stderr, "%s is not a port\n", argv[3]);
        return LC_EXIT_CONFIG;
    }

    uint64_t deadline = lc_now_ms() + BODY_WINDOW_MS;
    int      fd = lc_connect(argv[2], node_port, deadline);
    if (fd < 0) {
        fprintf(stderr, "cannot connect\n");
        return LC_EXIT_FAILED;
    }

    lc_client_config cfg = {
        .table = table, .table_len = (size_t)table_len, .sni = argv[4],
        .use_reality = 1, .reality = &reality, .unix_time = (uint32_t)time(NULL),
    };
    lc_client cl;
    char      err[256] = { 0 };
    if (lc_client_handshake(&cl, fd, &cfg, deadline, err, sizeof err) != 0) {
        printf("handshake failed while %s: %s\n", cl.stage, err);
        lc_close(fd);
        return LC_EXIT_FAILED;
    }
    if (!cl.reality_verified) {
        printf("REALITY did not authenticate — the server served the site behind it, not the tunnel\n");
        /* And then behave like somebody who asked for that site, which is the whole of what REALITY
         * promises a client that fails: see reality/spider.h. The result is not acted on — the
         * answer is already known and this tool is about to report it — so it is not checked. */
        (void)lc_spider_run(&cl, fd, argv[4], lc_now_ms() + 5000u);
        lc_close(fd);
        return LC_EXIT_CONFIG;
    }
    printf("REALITY authenticated, opening %s:%u%s%s\n", target, target_port,
           flow ? " with flow " : " without flow", flow ? flow : "");

    int use_vision = lc_vless_flow(flow) == 1;
    lc_vision vision;
    lc_vision_init(&vision, uuid);

    /* The VLESS request and the first payload go in one record, exactly as Xray's own client does:
     * a header alone in its own record is a distinctive shape on the wire. */
    static uint8_t first[16384];
    size_t         hdr_len = 0;
    if (lc_vless_request(uuid, flow, target, target_port, first, sizeof first, &hdr_len) != 0) {
        printf("cannot build the VLESS request\n");
        lc_close(fd);
        return LC_EXIT_FAILED;
    }

    /* The path, because "/" is a page and the question is usually how fast the tunnel carries a
     * body. Its twin lc-hyfetch has taken one all along; without it this tool could prove the
     * tunnel works and could not measure what it does. */
    const char *path = argc >= 11 ? argv[10] : "/";

    char req[512];
    int  n = snprintf(req, sizeof req,
                      "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: lc-fetch\r\n\r\n",
                      path, target);
    /* snprintf reports the length it WANTED, which is not the length it wrote. Left unchecked, a
     * path long enough to truncate the request makes every later use of n read past the end of req.
     * The target alone could never do that — it is bounded to 255 bytes — so this only became
     * reachable when the path stopped being a constant. */
    if (n < 0 || (size_t)n >= sizeof req) {
        fprintf(stderr, "the request does not fit\n");
        lc_close(fd);
        return LC_EXIT_FAILED;
    }

    size_t first_len = hdr_len;
    if (use_vision) {
        /* THE REQUEST GOES IN THE FIRST FRAME, WITH THE HEADER, IN ONE RECORD.
         *
         * This used to send an empty camouflage frame here and the request in a SECOND record
         * afterwards, on the reasoning that Vision's first frame carries no content. That is one of
         * the reference's two arms, and not the one this tool is ever in. Upstream reads the payload
         * with a deadline and branches on whether it arrived:
         *
         *     multiBuffer, err1 := timeoutReader.ReadMultiBufferTimeout(time.Millisecond * 500)
         *     if err1 == nil {
         *         if err := serverWriter.WriteMultiBuffer(multiBuffer); err != nil { return err }
         *     } else if err1 != buf.ErrReadTimeout {
         *         return err1
         *     } else if requestAddons.Flow == vless.XRV {
         *         mb := make(buf.MultiBuffer, 1)   // the empty frame
         *     }      (vendor/Xray-core/proxy/vless/outbound/outbound.go:322-337)
         *
         * The writer is still buffered there and is flushed only afterwards
         * (bufferWriter.SetBuffered(false), :342), so a payload that WAS ready leaves in one record
         * together with the VLESS header. The empty frame is reached only on ErrReadTimeout — only
         * when half a second passed with nothing to send.
         *
         * Here the request is built before either send and is therefore always ready, so the timeout
         * arm cannot be this tool's. What went out instead was a pair: one record holding the header
         * and a frame announcing zero content padded to about a kilobyte, then a short record
         * holding the GET. Two records where the reference sends one, the first with a content
         * length of 0x0000, is a signature of this binary in particular — and this is the binary
         * pointed at real nodes to test them. */
        lc_vision_filter(&vision, (const uint8_t *)req, (size_t)n);
        size_t pad_len = 0;
        if (lc_vision_pad(&vision, LC_VISION_CONTINUE, vision.is_tls, (const uint8_t *)req,
                          (size_t)n, first + first_len, sizeof first - first_len, &pad_len) != 0) {
            printf("cannot build the Vision padding frame\n");
            lc_close(fd);
            return LC_EXIT_FAILED;
        }
        first_len += pad_len;
    } else {
        memcpy(first + first_len, req, (size_t)n);
        first_len += (size_t)n;
    }

    if (send_app(fd, &cl, first, first_len, deadline) != 0) {
        printf("cannot send the request\n");
        lc_close(fd);
        return LC_EXIT_FAILED;
    }

    /* And nothing else: the request already went with the header, in the record above. */

    static uint8_t plain[LC_REC_MAX_OPEN];
    size_t         plain_len = 0;
    uint8_t        inner = 0;
    int            saw_header = 0;
    size_t         total = 0;

    /* Until the stream ends or the deadline does. A fixed count of records — eight, as this had —
     * proves the tunnel carries traffic and stops at the first hundred kilobytes, which is enough
     * to answer "does it work" and nothing at all to answer "how fast". recv_app reports the end of
     * the stream, and the deadline bounds a peer that neither ends nor sends. */
    for (;;) {
        if (recv_app(fd, &cl, plain, sizeof plain, &plain_len, &inner, deadline) != 0)
            break;
        if (inner != LC_REC_APPLICATION_DATA)
            continue; /* NewSessionTicket and friends arrive on the same stream */
        if (plain_len == 0)
            continue; /* an empty record is legal and carries nothing; it is not the stream start */

        static uint8_t unpadded[LC_REC_MAX_PLAINTEXT];
        const uint8_t *body = plain;
        size_t         body_len = plain_len;
        if (!saw_header) {
            size_t vh = 0;
            if (lc_vless_response(plain, plain_len, &vh) != 0) {
                printf("the VLESS response header does not parse; %zu bytes beginning", plain_len);
                for (size_t i = 0; i < plain_len && i < 12u; i++)
                    printf(" %02x", plain[i]);
                printf("\n");
                break;
            }
            saw_header = 1;
            body += vh;
            body_len -= vh;
        }

        if (use_vision && body_len > 0) {
            /* The peer frames its side too, and the frame boundaries do not line up with record
             * boundaries — which is exactly why the unpadder carries state across calls. */
            size_t un = 0;
            int    direct = 0;
            if (lc_vision_read(&vision, body, body_len, unpadded, sizeof unpadded, &un, &direct) != 0) {
                printf("a record larger than the buffer it is unpadded into\n");
                break;
            }
            /* Direct copy would mean the node has stopped using the record layer, and this loop is
             * a record reader. It cannot happen here — the probe fetches over plain HTTP and the
             * node only announces direct for a TLS inner stream — so it is reported rather than
             * handled: a probe that carries on reading raw bytes as records prints nonsense. */
            if (direct) {
                printf("the node announced direct copy, which this probe does not read\n");
                break;
            }
            body = unpadded;
            body_len = un;
            if (body_len == 0)
                continue;
        }
        if (body_len == 0)
            continue;

        if (total == 0) {
            /* The first line of the reply is the whole point: it comes from the target host, which
             * means the tunnel carried the request and brought an answer back. */
            const uint8_t *nl = memchr(body, '\n', body_len);
            int            line = (int)(nl != NULL ? (size_t)(nl - body) : body_len);
            printf("target replied: %.*s\n", line, (const char *)body);
        }
        total += body_len;
    }

    /* ⚠️ WHY THE READING STOPPED, because the two reasons are not the same answer and this line said
     * the same thing for both. A body that ended is a TOTAL; a window that expired is a RATE over
     * that window, and printing the second in the words of the first is how a measurement quietly
     * becomes wrong.
     *
     * Measured 2026-09-09: memory pressure on the router slowed a 32 MB fetch, this probe stopped at
     * the deadline and reported the partial count in the same sentence it prints for a complete
     * transfer. The search that followed went to the network, which was fine.
     *
     * The clock is asked rather than a flag threaded through every exit: the receive paths report
     * "the stream ended" and "the time ended" through one return, and a deadline that has passed is
     * exactly what that return means when the body has not. A stream that ends in the same
     * millisecond as the window is called cut off — a warning on a complete transfer, which is the
     * harmless direction of being wrong. */
    if (total == 0)
        printf("nothing came back through the tunnel\n");
    else if (lc_now_ms() >= deadline)
        printf("tunnel carried %zu bytes back — CUT OFF by this probe's %u s window, not by the "
               "end of the body: a rate over that window, not a total\n",
               total, (unsigned)(BODY_WINDOW_MS / 1000u));
    else
        printf("tunnel carried %zu bytes back\n", total);

    lc_client_free(&cl);
    lc_close(fd);
    return total > 0 ? LC_EXIT_OK : LC_EXIT_FAILED;
}
