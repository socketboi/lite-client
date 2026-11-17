/* lc-xfetch — one fetch through VLESS over XHTTP over REALITY.
 *
 * The same role lc-fetch plays for the plain TCP transport: the first thing that carries real
 * traffic end to end, and the first that can fail for a reason no offline test could have caught.
 * Underneath it, the framing and the header compression were each proved against nghttp2 and the
 * request shape against Xray's own client — but a server is the only thing that can say whether
 * they were wired together in the right order.
 *
 *   lc-xfetch TABLE.fpt NODE PORT SNI PBK SHORTID UUID PATH TARGET[:PORT]
 *
 * There is no flow argument, and that is not an omission: Xray forbids XTLS-Vision on any transport
 * but raw TCP, because Vision works by recognising the inner stream's own TLS records and here they
 * are buried inside HTTP/2 frames. So this path is plain VLESS — which is also why it will never
 * reach the speeds the Vision path does, and why both exist. */

#include "core/args.h"
#include "h2/frame.h"
#include "h2/xhttp.h"
#include "net/sock.h"
#include "reality/spider.h"
#include "tls/client.h"
#include "vless/vless.h"
#include "core/wipe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_TABLE 65536u
#define MAX_REC LC_REC_MAX_WIRE





/* One TLS record's worth of whatever is handed over. */
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
    if (lc_record_protect(&cl->wr, LC_REC_APPLICATION_DATA, data, len, 0, out, sizeof out,
                          &out_len) != 0)
        return -1;
    return lc_write_full(fd, out, out_len, deadline);
}

/* One record in, its plaintext out. Returns 0 on a record, 1 at end of stream, -1 on failure. */
static int recv_app(int fd, lc_client *cl, uint8_t *out, size_t cap, size_t *out_len,
                    uint64_t deadline)
{
    /* Loops, because the first thing a TLS 1.3 server sends after the handshake is usually not the
     * answer: it is a session ticket, which is a handshake record travelling under application
     * protection. Treating the first non-application record as the end of the stream — as this did
     * — means the reply is never read at all, on every connection, against every ordinary server.
     *
     * Tickets are stepped over rather than kept: this client does not resume, because a resumed
     * session is a session that can be recognised as the same client returning. */
    for (;;) {
        /* lc_read_full answers 0 for "all of it arrived", 1 for "the peer closed" and -1 for a
         * failure. It is not a byte count, and reading it as one — as this did — declares the end
         * of the stream on every successful read, which is a client that never receives anything
         * and cannot say why. */
        uint8_t hdr[LC_REC_HEADER];
        int     r = lc_read_full(fd, hdr, sizeof hdr, deadline);
        if (r != 0)
            return r == 1 ? 1 : -1;

        size_t body = (size_t)hdr[3] << 8 | hdr[4];
        if (body > MAX_REC - LC_REC_HEADER)
            return -1;

        static uint8_t rec[MAX_REC];
        memcpy(rec, hdr, sizeof hdr);
        if (lc_read_full(fd, rec + sizeof hdr, body, deadline) != 0)
            return -1;

        uint8_t inner = 0;
        if (lc_record_unprotect(&cl->rd, rec, sizeof hdr + body, out, cap, out_len, &inner) != 0)
            return -1;

        if (inner == LC_REC_APPLICATION_DATA)
            return 0;
        if (inner != LC_REC_HANDSHAKE)
            return 1; /* an alert, or the peer closing */
    }
}

int main(int argc, char **argv)
{
    /* Before any socket exists: a write to a peer that has gone must not end the process. */
    lc_ignore_sigpipe();
    if (argc != 10) {
        fprintf(stderr,
                "usage: lc-xfetch TABLE.fpt NODE PORT SNI PBK SHORTID UUID PATH TARGET[:PORT]\n");
        return LC_EXIT_CONFIG;
    }

    static uint8_t table[MAX_TABLE];
    long           table_len = lc_read_file(argv[1], table, sizeof table);
    if (table_len < 0) {
        fprintf(stderr, "cannot read %s\n", argv[1]);
        return LC_EXIT_CONFIG;
    }

    const char *node = argv[2];
    uint16_t    node_port;
    if (lc_port(argv[3], &node_port) != 0) {
        fprintf(stderr, "%s is not a port\n", argv[3]);
        return LC_EXIT_CONFIG;
    }
    const char *sni = argv[4];

    lc_reality_config reality;
    memset(&reality, 0, sizeof reality);
    if (lc_from_hex(argv[5], reality.public_key, sizeof reality.public_key) != 0 &&
        lc_from_base64url(argv[5], reality.public_key, sizeof reality.public_key) != 0) {
        fprintf(stderr, "bad public key\n");
        return LC_EXIT_CONFIG;
    }
    size_t sid_hex = strlen(argv[6]);
    if (sid_hex % 2u != 0u || sid_hex > LC_REALITY_SHORT_ID * 2u ||
        lc_from_hex(argv[6], reality.short_id, sid_hex / 2u) != 0) {
        fprintf(stderr, "bad short id\n");
        return LC_EXIT_CONFIG;
    }
    /* The version this client gives the node: Xray's own, v26.10.31
     * (vendor/Xray-core/core/core.go:21-23), which the REALITY client writes into the
     * session ID
     * (vendor/Xray-core/transport/internet/reality/reality.go:168-170). */
    reality.version[0] = LC_REALITY_VERSION_MAJOR;
    reality.version[1] = LC_REALITY_VERSION_MINOR;
    reality.version[2] = LC_REALITY_VERSION_PATCH;

    /* The account, written out or read from a file named with a leading @. The file form is what a
     * deployment should use — see lc_read_secret — and this tool is the example people copy. */
    uint8_t uuid[LC_VLESS_UUID];
    char    uuid_text[64] = { 0 };
    int     rc = lc_read_secret(argv[7], uuid_text, sizeof uuid_text);
    if (rc != 0) {
        fprintf(stderr, "cannot read the uuid: %s\n", lc_secret_why(rc));
        return LC_EXIT_CONFIG;
    }
    if (lc_vless_uuid(uuid_text, uuid) != 0) {
        fprintf(stderr, "that is not a uuid\n");
        return LC_EXIT_CONFIG;
    }
    lc_wipe(uuid_text, sizeof uuid_text);
    memset(argv[7], 'x', strlen(argv[7]));

    const char *path = argv[8];

    char     target[256];
    uint16_t target_port = 80;
    if (lc_host_port(argv[9], target, sizeof target, &target_port, 80) != 0) {
        fprintf(stderr, "%s is not a target: HOST, HOST:PORT or [V6ADDR]:PORT\n", argv[9]);
        return LC_EXIT_CONFIG;
    }

    uint64_t deadline = lc_now_ms() + BODY_WINDOW_MS;

    int fd = lc_connect(node, node_port, deadline);
    if (fd < 0) {
        printf("cannot reach %s:%u\n", node, node_port);
        return LC_EXIT_FAILED;
    }

    lc_client        cl;
    lc_client_config cfg = {
        .table = table, .table_len = (size_t)table_len, .sni = sni,
        /* The client's own clock, which REALITY writes into the block it authenticates with. Zero,
         * as this passed before, claims 1970 — the server may or may not check, and a client that
         * differs from every other one in a field nobody looks at is still a client that differs. */
        .use_reality = 1, .reality = &reality, .unix_time = (uint32_t)time(NULL),
    };
    char err[192] = { 0 };
    if (lc_client_handshake(&cl, fd, &cfg, deadline, err, sizeof err) != 0) {
        printf("the handshake failed: %s\n", err);
        lc_close(fd);
        return LC_EXIT_FAILED;
    }
    if (!cl.reality_verified) {
        /* A REALITY server that took us for a stranger produces a perfectly good handshake with the
         * donor site behind it, so this is the difference between reaching the node and reaching a
         * web site with the user's traffic. */
        printf("REALITY not authenticated: %s\n",
               cl.reality_note[0] ? cl.reality_note : "no certificate seen");
        /* The site is then fetched, because that is what a client which failed to authenticate is
         * supposed to look like — reality/spider.h. Not checked: the verdict is already printed. */
        (void)lc_spider_run(&cl, fd, sni, lc_now_ms() + 5000u);
        lc_close(fd);
        /* 2, as lc-probe and lc-fetch have always answered this: the handshake worked, the node did
         * not take us for one of its own, and no amount of retrying changes a short id. This tool
         * answered 1 — "try again later" — for the one case where trying again is pointless. */
        return LC_EXIT_CONFIG;
    }
    printf("REALITY authenticated\n");

    /* The opening burst of HTTP/2, then the request that is the tunnel. */
    lc_xhttp x;
    uint8_t  open[LC_XHTTP_OPEN_MAX];
    long     open_len = lc_xhttp_open(&x, sni, path, open, sizeof open);
    if (open_len < 0 || send_app(fd, &cl, open, (size_t)open_len, deadline) != 0) {
        printf("cannot open the XHTTP stream\n");
        lc_close(fd);
        return LC_EXIT_FAILED;
    }
    printf("XHTTP stream-one opened, path %s\n", path);

    /* The VLESS request and the first payload travel together in one DATA frame, for the same
     * reason lc-fetch puts them in one record: a header alone is a shape of its own. */
    static uint8_t body[16384];
    size_t         hdr_len = 0;
    if (lc_vless_request(uuid, NULL, target, target_port, body, sizeof body, &hdr_len) != 0) {
        printf("cannot build the VLESS request\n");
        lc_close(fd);
        return LC_EXIT_FAILED;
    }

    char req[512];
    int  rn = snprintf(req, sizeof req,
                       "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: lc-xfetch\r\n\r\n",
                       target);
    if (rn < 0 || hdr_len + (size_t)rn > sizeof body) {
        lc_close(fd);
        return LC_EXIT_FAILED;
    }
    memcpy(body + hdr_len, req, (size_t)rn);
    size_t body_len = hdr_len + (size_t)rn;

    uint8_t dh[LC_H2_HEADER];
    size_t  carried = 0;
    size_t  dn = lc_xhttp_data(&x, body_len, dh, sizeof dh, &carried);
    if (dn == 0 || carried != body_len) {
        printf("the window would not take the request\n");
        lc_close(fd);
        return LC_EXIT_FAILED;
    }
    if (send_app(fd, &cl, dh, dn, deadline) != 0 ||
        send_app(fd, &cl, body, body_len, deadline) != 0) {
        printf("cannot send the request\n");
        lc_close(fd);
        return LC_EXIT_FAILED;
    }

    /* And read back, unwrapping two layers: TLS records outside, HTTP/2 frames within. The response
     * body is the inner connection, and its first byte is VLESS's own one-byte answer. */
    static uint8_t plain[LC_REC_MAX_OPEN];
    /* Big enough for one frame of what we advertise: SETTINGS_MAX_FRAME_SIZE now says a megabyte,
     * the reference's number, so a peer may legally send one and this is where it lands. */
    static uint8_t pending[LC_H2_MAX_READ_FRAME + LC_H2_HEADER];
    size_t         pending_len = 0;
    size_t         total = 0;
    int            saw_vless = 0;
    char           status[64] = { 0 };

    for (;;) {
        size_t plain_len = 0;
        int    r = recv_app(fd, &cl, plain, sizeof plain, &plain_len, deadline);
        if (r != 0)
            break;
        if (pending_len + plain_len > sizeof pending) {
            printf("the node sent more than this tool holds\n");
            break;
        }
        memcpy(pending + pending_len, plain, plain_len);
        pending_len += plain_len;

        for (;;) {
            lc_xhttp_event ev;
            int            fr = lc_xhttp_read(&x, pending, pending_len, &ev);
            if (fr < 0) {
                printf("the node's framing is not something this can follow\n");
                pending_len = 0;
                break;
            }
            if (fr == 0)
                break;

            if (ev.reply_len > 0 && send_app(fd, &cl, ev.reply, ev.reply_len, deadline) != 0)
                break;

            const uint8_t *p = ev.body;
            size_t         n = ev.body_len;
            if (n > 0 && !saw_vless) {
                /* VLESS answers with one byte of version and a length of addons, and the inner
                 * connection begins after them.
                 *
                 * Split across two DATA frames it would need holding onto, which this tool does not
                 * do — it reads one exchange and stops. Refused rather than waited for: waiting
                 * would mean reading the same frame again for as long as the deadline allows. */
                if (n < 2u) {
                    printf("the node's answer begins in a frame too small to read it\n");
                    return LC_EXIT_FAILED;
                }
                size_t addons = p[1];
                if (n < 2u + addons) {
                    printf("the node's answer begins in a frame too small to read it\n");
                    return LC_EXIT_FAILED;
                }
                p += 2u + addons;
                n -= 2u + addons;
                saw_vless = 1;
            }
            if (n > 0) {
                if (total == 0 && status[0] == '\0') {
                    size_t k = n < sizeof status - 1u ? n : sizeof status - 1u;
                    memcpy(status, p, k);
                    status[strcspn(status, "\r\n")] = '\0';
                }
                total += n;
            }

            /* Credit for what the frame spent, so the node is not stopped by a window this tool
             * forgot to reopen. What it spent is the whole DATA payload, not what came out of the
             * strips above: RFC 9113 §6.9.1 charges the pad-length byte and the padding to the
             * window alongside the application data, and the VLESS response header taken off the
             * front was payload as far as HTTP/2 ever knew. Crediting the remainder gives back
             * 1 + pad_len too little on every frame a peer pads towards the client, and the window
             * closes on a transfer that has nothing else wrong with it. Xray's xhttp server does not
             * pad inbound, so the shortfall only falls due against some other server.
             *
             * The nine bytes are read a second time because the event reports the body already
             * stripped and does not say which kind of frame it came from. Only DATA may be credited:
             * a WINDOW_UPDATE for bytes that never spent window carries the peer's send window past
             * what was advertised, which is the same mistake in the other direction. */
            lc_h2_hd fh;
            if (lc_h2_get_header(pending, pending_len, &fh) == 0 && fh.type == LC_H2_DATA) {
                uint8_t credit[2u * (LC_H2_HEADER + 4u)];
                size_t  cn = lc_xhttp_credit(&x, fh.len, credit, sizeof credit);
                if (cn > 0 && send_app(fd, &cl, credit, cn, deadline) != 0)
                    break;
            }

            memmove(pending, pending + ev.consumed, pending_len - ev.consumed);
            pending_len -= ev.consumed;
        }

        if (x.ended)
            break;
    }

    lc_close(fd);

    if (total == 0) {
        printf("nothing came back\n");
        return LC_EXIT_FAILED;
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
    if (lc_now_ms() >= deadline)
        printf("%s\n%zu bytes through VLESS over XHTTP over REALITY — CUT OFF by this probe's "
               "%u s window, not by the end of the body: a rate over that window, not a total\n",
               status, total, (unsigned)(BODY_WINDOW_MS / 1000u));
    else
        printf("%s\n%zu bytes through VLESS over XHTTP over REALITY\n", status, total);
    return LC_EXIT_OK;
}
