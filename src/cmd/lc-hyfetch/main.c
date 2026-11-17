/* lc-hyfetch — one HTTP request carried through a Hysteria2 node, reported honestly.
 *
 * What lc-fetch is to the REALITY plane. lc-hy proves the node lets us in; this proves the part
 * that comes after, which is the only part a user ever notices: a stream opened to somewhere else,
 * bytes in one end and the same bytes out the other.
 *
 *   lc-hyfetch HOST PORT SNI OBFS_PASSWORD AUTH_PASSWORD TARGET[:PORT]
 *              [PATH [RECEIVE_BYTES_PER_SEC [PIN_SHA256]]]
 *
 * TARGET is resolved by the NODE, not here. That is the point of sending it as a name: a client
 * that resolves first has already told its own network where it is going.
 *
 * The rate is the one number that decides how fast this goes, because stating it is what turns
 * Brutal on at the node. Measured without it, this tool reports whatever ordinary congestion
 * control settles at, which is not what Hysteria2 is for. */

#include "core/args.h"
#include "net/sock.h"
#include "quic/conn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Said wherever a handshake fails rather than only where it gave up waiting.
 *
 * The pin is checked inside the handshake — see qtls.c — so a digest that is merely out of date
 * arrives here as a connection that ended, which looks exactly like a network that dropped it. Its
 * sibling lc-hy said this and this tool said nothing at all, which is the same decision made
 * differently in two files. */
/* HOW LONG THIS PROBE READS A BODY BEFORE GIVING THE ANSWER IT HAS.

 * Named because it is now printed. It used to be a literal buried in the loop head, and the report
 * at the end said "N bytes" whether the body had ended or this number had — two different answers in
 * one sentence. A probe is a measuring tool before it is anything else, and a measuring tool that
 * cannot say which of the two happened produces numbers that look like measurements.
 *
 * 15 seconds is not a target for how long a transfer should take. It is the bound on a peer that
 * neither ends the stream nor sends anything more, which is the failure this probe exists to survive.
 * Fetching something larger than the window carries in 15 seconds is a legitimate use — that is how
 * the throughput figures in this tree were taken — and the line now says so instead of implying a
 * total. */
#define BODY_WINDOW_MS 15000u

static void pin_hint(int have_pin)
{
    if (have_pin)
        printf("  (a pin that does not match the node's certificate ends the handshake the same"
               " way — check it before blaming the path)\n");
}

int main(int argc, char **argv)
{
    /* Before any socket exists: a write to a peer that has gone must not end the process. */
    lc_ignore_sigpipe();
    if (argc < 7 || argc > 10) {
        fprintf(stderr,
                "usage: lc-hyfetch HOST PORT SNI OBFS_PASSWORD AUTH_PASSWORD TARGET[:PORT] "
                "[PATH [RECEIVE_BYTES_PER_SEC [PIN_SHA256]]]\n"
                "  Both passwords take @FILE as well as a literal; OBFS_PASSWORD takes - or \"\"\n"
                "  where the node runs none. Exit: 0 carried, 1 the network, 2 the arguments or a\n"
                "  node that would not have us — see src/core/args.h.\n");
        return LC_EXIT_CONFIG;
    }

    const char *host = argv[1];
    uint16_t    port;
    if (lc_port(argv[2], &port) != 0) {
        fprintf(stderr, "%s is not a port\n", argv[2]);
        return LC_EXIT_CONFIG;
    }
    const char *sni = argv[3];
    /* The obfuscation password gets the same treatment as the account below it, and for the same
     * reason: it is a shared secret that gates the node's whole UDP port — a peer that does not know
     * it gets no answer at all — so leaving it legible in /proc for the life of the run is the same
     * exposure one argument to the left.
     *
     * "" and "-" both mean the node runs none: the empty string is what this has always taken, and
     * the dash is what lc-tunnel and the service file spell it as. An empty secret is refused
     * everywhere else, so the two spellings are answered here rather than by making "nothing" a
     * password. */
    char obfs_password[128] = { 0 };
    if (argv[4][0] != '\0' && strcmp(argv[4], "-") != 0) {
        int rc = lc_read_secret(argv[4], obfs_password, sizeof obfs_password);
        if (rc != 0) {
            fprintf(stderr, "cannot read the obfuscation password: %s\n", lc_secret_why(rc));
            return LC_EXIT_CONFIG;
        }
    }
    /* A dash is left alone — see lc-tunnel, where the same line is written out at length: an x where
     * the dash was makes an unobfuscated run indistinguishable in ps from one started with a secret,
     * and there is nothing in a dash to hide. */
    if (strcmp(argv[4], "-") != 0)
        memset(argv[4], 'x', strlen(argv[4]));
    const char *obfs = obfs_password[0] != '\0' ? obfs_password : NULL;
    const char *path = argc >= 8 ? argv[7] : "/";

    /* The account, out of the process title as soon as it has been read. A command line is readable
     * through /proc by every process on the machine for as long as this one runs, and this argument
     * is the whole credential — lc-tunnel has taken it as @FILE and wiped it from the start, and the
     * three Hysteria2 probes took it as a literal and left it there. */
    char auth_password[128];
    int  rc = lc_read_secret(argv[5], auth_password, sizeof auth_password);
    if (rc != 0) {
        fprintf(stderr, "cannot read the account password: %s\n", lc_secret_why(rc));
        return LC_EXIT_CONFIG;
    }
    memset(argv[5], 'x', strlen(argv[5]));

    /* Stating a receive rate is what turns Brutal on AT THE NODE; left unstated the node falls back
     * to ordinary congestion control, and a measurement taken that way says nothing about the
     * protocol this client exists to speak. Its siblings lc-hy and lc-tunnel have always been able
     * to state it — this one could not, which made it the wrong tool for the one question anybody
     * asks of Hysteria2. In bytes per second, and refused rather than guessed at: strtoull read
     * "100mbps" as 100 and "abc" as 0, and zero is Brutal switched off, so the figure printed at the
     * end was ordinary congestion control wearing this protocol's name. */
    uint64_t rx_rate = 0;
    if (argc >= 9 && lc_u64(argv[8], &rx_rate) != 0) {
        fprintf(stderr, "%s is not a receive rate in bytes per second\n", argv[8]);
        return LC_EXIT_CONFIG;
    }

    /* "host" alone means port 80, which is what anyone typing a bare name means.
     *
     * Split by the shared reader rather than here. The copy that used to be here took everything
     * after the last colon and pasted it back on without looking at it, so "example.com:htp" and
     * "example.com:" travelled to the NODE as an address it could only refuse — and the refusal, when
     * it came back, named neither the argument nor the reason. */
    char     addr[300], hostname[256];
    uint16_t target_port = 80;
    if (lc_host_port(argv[6], hostname, sizeof hostname, &target_port, 80) != 0) {
        fprintf(stderr, "%s is not a target: HOST, HOST:PORT or [V6ADDR]:PORT\n", argv[6]);
        return LC_EXIT_CONFIG;
    }
    /* An IPv6 literal goes back into the node's "host:port" string with its brackets on, which is
     * what the node's own parser wants and what taking the address apart just removed. */
    snprintf(addr, sizeof addr, strchr(hostname, ':') != NULL ? "[%s]:%u" : "%s:%u", hostname,
             target_port);

    /* Zeroed — lc_qconn_open carries the gecko and hop settings across its own wipe, so it reads
     * them from here first. See the note in lc-hydns and the contract in conn.h. */
    lc_qconn c = { 0 };
    /* This tool carries traffic and an account password, so it must be able to say who it is
     * carrying them to. It could not, while its sibling lc-hy could — the same decision made
     * differently in two files, which is how one of them ends up wrong. */
    uint8_t pin[LC_QTLS_PIN];
    int     have_pin = 0;
    if (argc >= 10) {
        if (lc_from_hex(argv[9], pin, sizeof pin) != 0) {
            fprintf(stderr, "the pin is not %u hex bytes\n", (unsigned)sizeof pin);
            return LC_EXIT_CONFIG;
        }
        have_pin = 1;
    }

    if (lc_qconn_open(&c, host, (uint16_t)port, sni, obfs, have_pin ? pin : NULL) != 0) {
        printf("failed: %s\n", c.err);
        return LC_EXIT_FAILED;
    }

    uint64_t deadline = lc_qconn_now_ms() + 5000u;
    while (!c.handshake_done && lc_qconn_now_ms() < deadline) {
        int rv = lc_qconn_step(&c, 100);
        if (rv <= 0) {
            printf("failed: %s\n", c.err);
            pin_hint(have_pin);
            lc_qconn_close(&c);
            return LC_EXIT_FAILED;
        }
    }
    if (!c.handshake_done) {
        printf("no answer: the handshake did not complete\n");
        pin_hint(have_pin);
        lc_qconn_close(&c);
        return LC_EXIT_FAILED;
    }

    lc_h3_auth_result got;
    if (lc_qconn_authenticate(&c, auth_password, rx_rate, &got, 5000) != 0) {
        printf("authentication refused: %s\n", c.err);
        lc_qconn_close(&c);
        /* The node answered and would not have us, which is the same class as a REALITY node
         * serving the site behind it: a password, not a network. */
        return LC_EXIT_CONFIG;
    }
    printf("authenticated, udp %s\n", got.udp_enabled ? "yes" : "no");
    /* The middle arm is not reachable in practice: a pin that does not match ends the handshake
     * inside qtls.c, so nothing that got as far as authenticating failed it. It stays because the
     * verdict must not be able to lie if that ever stops being true. */
    printf("node identity: %s\n",
           lc_qconn_pinned(&c)
               ? "the node holds the pinned certificate"
               : have_pin ? "PIN DID NOT MATCH — which should be impossible past the handshake"
                          : "not checked — no pin given");

    int h = lc_qconn_tcp_open(&c, addr);
    if (h < 0) {
        printf("cannot open a connection to %s: %s\n", addr, c.err);
        lc_qconn_close(&c);
        return LC_EXIT_FAILED;
    }

    char request[512];
    int  req_len = snprintf(request, sizeof request,
                            "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: lc-hyfetch\r\n"
                             "Connection: close\r\n\r\n",
                            path, hostname);
    if (req_len < 0 || (size_t)req_len >= sizeof request) {
        printf("the request does not fit\n");
        lc_qconn_close(&c);
        return LC_EXIT_FAILED;
    }

    /* Sent before the node has answered. Hysteria calls this fast open and its own client offers it
     * as a setting; it is safe because the reply and the connection's bytes arrive on the same
     * stream in that order, so nothing can be read out of turn — and it saves the round trip that
     * would otherwise sit between "the node agrees" and "the request leaves".
     *
     * And that is all that is sent. Not an end-of-stream after it, however finished with asking we
     * are: the node ends the whole connection on one — see lc_qconn_tcp_close — so saying "no more
     * questions" here would mean never hearing the answer. "Connection: close" above is what ends
     * this exchange, from the far end, where it belongs. */
    size_t sent = lc_qconn_tcp_send(&c, h, (const uint8_t *)request, (size_t)req_len);
    if (sent != (size_t)req_len) {
        printf("the request did not fit the send buffer\n");
        lc_qconn_close(&c);
        return LC_EXIT_FAILED;
    }

    size_t   total = 0;
    int      shown = 0;
    int      established = 0;
    deadline = lc_qconn_now_ms() + BODY_WINDOW_MS;

    while (lc_qconn_now_ms() < deadline) {
        int rv = lc_qconn_step(&c, 50);
        if (rv < 0) {
            printf("failed: %s\n", c.err);
            lc_qconn_close(&c);
            return LC_EXIT_FAILED;
        }
        if (rv == 0) {
            printf("%s\n", c.err);
            break;
        }

        const char   *why = NULL;
        lc_qtcp_state st = lc_qconn_tcp_state(&c, h, &why);
        if (st == LC_QTCP_REFUSED) {
            printf("the node refused to connect to %s: %s\n", addr, why);
            lc_qconn_close(&c);
            return LC_EXIT_FAILED;
        }
        if (st == LC_QTCP_CLOSED) {
            printf("%s\n", why);
            lc_qconn_close(&c);
            return LC_EXIT_FAILED;
        }
        if (st == LC_QTCP_GONE && total == 0) {
            printf("the stream ended before the node said anything\n");
            lc_qconn_close(&c);
            return LC_EXIT_FAILED;
        }
        if (st == LC_QTCP_ESTABLISHED && !established) {
            established = 1;
            printf("connected to %s through the node\n", addr);
        }

        size_t         have = 0;
        const uint8_t *data = lc_qconn_tcp_peek(&c, h, &have);
        if (have > 0) {
            /* The first few lines, which is enough to tell "this is the site" from "this is a
             * proxy explaining itself". The rest is counted and dropped. */
            if (!shown) {
                size_t n = have < 200u ? have : 200u;
                printf("--- what came back ---\n%.*s\n----------------------\n", (int)n,
                       (const char *)data);
                shown = 1;
            }
            /* Read as the reference's io.Copy reads, 32 KiB at a time, so that the node is
             * credited in the same steps as it is by the reference (see hy_pump in lc-tunnel). */
            while (have > 0) {
                size_t n = have < 32768u ? have : 32768u;
                lc_qconn_tcp_read(&c, h, n);
                lc_qconn_tcp_take(&c, h, n);
                total += n;
                have -= n;
            }
        }

        if (lc_qconn_tcp_eof(&c, h))
            break;
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
    if (lc_qconn_now_ms() >= deadline)
        printf("%zu bytes read from %s — CUT OFF by this probe's %u s window, not by the end of "
               "the body: a rate over that window, not a total\n",
               total, addr, (unsigned)(BODY_WINDOW_MS / 1000u));
    else
        printf("%zu bytes read from %s\n", total, addr);
    lc_qconn_tcp_close(&c, h);
    lc_qconn_close(&c);
    return total > 0 ? LC_EXIT_OK : LC_EXIT_FAILED;
}
