/* lc-probe — one handshake, reported honestly.
 *
 * This is the gate the whole project turns on. Everything up to here was proved against documents
 * and reference implementations; this is the first thing that talks to a server, and the first that
 * can fail for reasons no local test could have caught.
 *
 * Read the output carefully, because "handshake complete" on its own means very little. Against a
 * REALITY server, a client that is wrong in almost any way still completes a perfectly good
 * handshake — the server decides it is a stranger and proxies the real web site. The line that
 * matters is whether the server proved it holds the REALITY key.
 *
 *   lc-probe TABLE.fpt HOST PORT SNI              plain TLS 1.3, no REALITY
 *   lc-probe TABLE.fpt HOST PORT SNI PBK SHORTID  with REALITY
 *
 * PBK is the server's public key as 64 hex characters or base64url, SHORTID as hex. */

#include "core/args.h"
#include "net/sock.h"
#include "fp/fpt.h"
#include "tls/kex.h"
#include "reality/spider.h"
#include "tls/client.h"

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_TABLE 65536u




/* Xray writes REALITY public keys in base64url without padding, which is what a subscription
 * carries, so both spellings are accepted rather than making the operator convert by hand. */

static int parse_key(const char *s, uint8_t *out, size_t len)
{
    if (lc_from_hex(s, out, len) == 0)
        return 0;
    return lc_from_base64url(s, out, len);
}

/* Saves everything needed to replay one failed stamp against the reference implementation: the
 * ClientHello as sent, the ephemeral private key it was signed with, and the timestamp inside it.
 *
 * Off unless LC_PROBE_DUMP names a directory, and rightly so — the file contains a private key.
 * Ephemeral and worthless a second later, but a key nonetheless, and writing one to disk should be
 * something someone asked for. */
static void dump_failure(const lc_client_hs *hs, uint32_t stamp_time)
{
    const char *dir = getenv("LC_PROBE_DUMP");
    if (dir == NULL || dir[0] == '\0')
        return;

    size_t         hello_len = 0;
    const uint8_t *hello = lc_client_hs_hello(hs, &hello_len);
    const uint8_t *priv = lc_client_hs_stamp_key(hs);

    char path[512];
    snprintf(path, sizeof path, "%s/fail-%u-%d.txt", dir, (unsigned)stamp_time, (int)getpid());

    /* 0600 and O_EXCL, not fopen("w"). The file holds a private key, so the usual mode would leave
     * it readable by everyone on the machine; O_EXCL refuses to follow a symbolic link someone else
     * put there first, which matters because this directory is often a shared temporary one. */
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        return;
    FILE *f = fdopen(fd, "w");
    if (f == NULL) {
        close(fd);
        return;
    }

    fprintf(f, "unix_time %u\nhello_len %zu\nprivate ", (unsigned)stamp_time, hello_len);
    for (size_t i = 0; i < LC_X25519_KEY; i++)
        fprintf(f, "%02x", priv[i]);
    fprintf(f, "\nhello ");
    for (size_t i = 0; i < hello_len; i++)
        fprintf(f, "%02x", hello[i]);
    fprintf(f, "\n");
    fclose(f);
    fprintf(stderr, "saved the failing hello to %s\n", path);
}

int main(int argc, char **argv)
{
    /* Before any socket exists: a write to a peer that has gone must not end the process. */
    lc_ignore_sigpipe();
    if (argc != 5 && argc != 7) {
        fprintf(stderr,
                "usage: lc-probe TABLE.fpt HOST PORT SNI [PBK SHORTID]\n"
                "  without PBK/SHORTID: a plain TLS 1.3 handshake, which any public server answers\n"
                "  with them: REALITY, and the only line that matters is the last one\n");
        return LC_EXIT_CONFIG;
    }

    static uint8_t table[MAX_TABLE];
    long           table_len = lc_read_file(argv[1], table, sizeof table);
    if (table_len < 0) {
        fprintf(stderr, "cannot read %s\n", argv[1]);
        return LC_EXIT_CONFIG;
    }

    /* Said here rather than left to a generic build failure: "this build cannot produce a key share
     * for group 0x11ed" is something an operator can act on, and "the table does not build a hello"
     * is not. */
    char why[160];
    if (lc_fpt_supported(table, (size_t)table_len, why, sizeof why) != 0) {
        fprintf(stderr, "%s: %s\n", argv[1], why);
        return LC_EXIT_CONFIG;
    }

    const char *host = argv[2];
    uint16_t    port;
    if (lc_port(argv[3], &port) != 0) {
        fprintf(stderr, "%s is not a port\n", argv[3]);
        return LC_EXIT_CONFIG;
    }
    const char *sni = argv[4];

    lc_reality_config reality;
    memset(&reality, 0, sizeof reality);
    int use_reality = 0;

    if (argc == 7) {
        if (parse_key(argv[5], reality.public_key, sizeof reality.public_key) != 0) {
            fprintf(stderr, "the public key is neither 64 hex characters nor base64url\n");
            return LC_EXIT_CONFIG;
        }
        /* Short ids are shorter than eight bytes as often as not; the rest stays zero, which is
         * what the server compares against. */
        size_t hex_len = strlen(argv[6]);
        if (hex_len > LC_REALITY_SHORT_ID * 2u || hex_len % 2u != 0u) {
            fprintf(stderr, "the short id must be up to 16 hex characters\n");
            return LC_EXIT_CONFIG;
        }
        if (lc_from_hex(argv[6], reality.short_id, hex_len / 2u) != 0) {
            fprintf(stderr, "the short id is not hexadecimal\n");
            return LC_EXIT_CONFIG;
        }
        /* The version the server compares against its configured minimum. Xray sends its own
         * version here; anything within the server's range is accepted. */
        /* The version this client gives the node: Xray's own, v26.10.31
         * (vendor/Xray-core/core/core.go:21-23), which the REALITY client writes into the
         * session ID
         * (vendor/Xray-core/transport/internet/reality/reality.go:168-170). */
        reality.version[0] = LC_REALITY_VERSION_MAJOR;
        reality.version[1] = LC_REALITY_VERSION_MINOR;
        reality.version[2] = LC_REALITY_VERSION_PATCH;
        use_reality = 1;
    }

    printf("connecting to %s:%d, SNI %s%s\n", host, port, sni,
           use_reality ? ", REALITY" : ", plain TLS 1.3");

    uint64_t deadline = lc_now_ms() + 15000u;
    uint32_t stamp_time = (uint32_t)time(NULL);

    lc_client_config cfg = {
        .table = table,
        .table_len = (size_t)table_len,
        .sni = sni,
        .use_reality = use_reality,
        .reality = &reality,
        .unix_time = stamp_time,
    };

    /* The probe drives the handshake state machine itself rather than calling the blocking wrapper.
     * Not for concurrency — it has one connection — but because a REALITY failure is silent by
     * design, and the only way to investigate one is to still be holding the message that failed.
     * LC_PROBE_DUMP names a directory to leave it in. */
    lc_client     cl;
    char          err[256] = { 0 };
    lc_client_hs *hs = lc_client_hs_new(&cfg);
    if (hs == NULL) {
        fprintf(stderr, "out of memory\n");
        return LC_EXIT_FAILED;
    }

    /* The hello is built before the socket is opened, which keeps two key generations and the
     * REALITY stamp — a few milliseconds — off the connect path.
     *
     * It was tried as a fix for something else and was not one: a REALITY server refuses roughly
     * one connection in ten from this client with "failed to read client hello", and the rate was
     * the same either way. Recording that here so the ordering is not mistaken for the cure. */
    if (lc_client_hs_step(hs, &cl) != LC_HS_WANT_WRITE) {
        printf("failed while %s: %s\n", cl.stage, lc_client_hs_error(hs));
        lc_client_hs_free(hs);
        return LC_EXIT_FAILED;
    }

    int fd = lc_connect(host, (uint16_t)port, deadline);
    if (fd < 0) {
        fprintf(stderr, "cannot connect\n");
        lc_client_hs_free(hs);
        return LC_EXIT_FAILED;
    }

    /* The same pump the library uses, called rather than copied: the probe only wants to still be
     * holding the machine afterwards, which is not a reason to have a second implementation of the
     * loop that can quietly disagree with the first. */
    int rc = lc_client_hs_run(hs, &cl, fd, deadline, err, sizeof err);

    if (rc == 0 && use_reality && !cl.reality_verified)
        dump_failure(hs, stamp_time);

    if (rc != 0) {
        printf("failed while %s: %s\n", cl.stage, err[0] ? err : "no reason recorded");
        lc_client_hs_free(hs);
        lc_close(fd);
        return LC_EXIT_FAILED;
    }
    lc_client_hs_free(hs);

    printf("handshake complete\n");
    if (use_reality) {
        if (cl.reality_verified) {
            printf("REALITY: the server proved it holds the private key — this is our node\n");
        } else {
            printf("REALITY: NOT authenticated. The handshake succeeded, which means the server\n"
                   "         treated this client as a stranger and served the real site behind it.\n"
                   "         Check the short id, the public key, and the clock.\n"
                   "         reason: %s\n",
                   cl.reality_note[0] ? cl.reality_note : "no certificate message arrived at all");

            /* AND THEN BEHAVE LIKE SOMEBODY WHO ASKED FOR THAT SITE, which is the whole of what
             * REALITY promises a client that fails — and which this tool alone did not do.
             *
             * lc-fetch, lc-xfetch and lc-tunnel all fetch the masquerade here; this one printed its
             * verdict and closed. What it emitted was a TLS 1.3 handshake followed by zero
             * application bytes and an immediate FIN — the exact shape reality/spider.h names as
             * the one behaviour a REALITY client must not have, and as what a probe looking for
             * REALITY nodes would measure.
             *
             * Worse here than anywhere else, because of WHO runs it: this is the tool an operator
             * reaches for when a node is not working, pointed at a node whose short id or key is
             * wrong — that is, precisely at a node already under suspicion, from an address the
             * operator cares about.
             *
             * Upstream's fallback is unconditional on !Verified and closes nothing:
             * `if !uConn.Verified { ... go func() { ... get(true) ... // Do not close the
             * connection }() }` (vendor/Xray-core/transport/internet/reality/reality.go:183-274).
             *
             * The result is not acted on — the verdict is already decided and already printed — so
             * it is not checked, exactly as in lc-fetch. */
            (void)lc_spider_run(&cl, fd, sni, lc_now_ms() + 5000u);
        }
    }

    lc_client_free(&cl);
    lc_close(fd);
    return (use_reality && !cl.reality_verified) ? 2 : 0;
}
