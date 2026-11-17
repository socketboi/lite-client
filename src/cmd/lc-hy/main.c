/* lc-hy — one QUIC handshake against a Hysteria2 node, reported honestly.
 *
 * The same role lc-probe plays for REALITY: the first thing that talks to a server, and the first
 * that can fail for reasons no local test could have caught. Everything underneath was proved
 * against documents and reference implementations — the AEAD, the header protection, the key
 * schedule, the transport parameters. What only a server can say is whether they are wired together
 * in the right order.
 *
 *   lc-hy HOST PORT SNI [OBFS_PASSWORD [AUTH_PASSWORD [RECEIVE_BYTES_PER_SECOND [PIN_SHA256]]]]
 *
 * A completed handshake means the crypto backend works: ngtcp2 drove a TLS 1.3 exchange through
 * code that has never seen OpenSSL. It does NOT mean the node accepted us — Hysteria2 authenticates
 * over HTTP/3 afterwards, which is what the fifth argument asks for.
 *
 * The sixth is the rate we tell the node we can receive at, and it is the one number in this
 * protocol that changes how fast anything goes: state it and the node sends at that rate whatever
 * the path between us is doing. In bytes per second — hysteria writes "100 mbps" in its config and
 * puts 12 500 000 on the wire.
 *
 * The seventh is the node's certificate digest, and with it the handshake proves who answered: the
 * digest says WHICH key the peer must hold and CertificateVerify says it HAS it — see qtls.h, where
 * the two halves are set out. Without it this tool, like the client, completes a handshake with
 * whatever answered. Produced on the node by:
 *
 *   openssl x509 -in cert.pem -outform der | sha256sum */

#include "core/args.h"
#include "net/sock.h"
#include "quic/conn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Said wherever a handshake fails rather than only where it gave up waiting.
 *
 * The pin is checked inside the handshake — see qtls.c — so a digest that is merely out of date
 * arrives here as a connection that ended, which looks exactly like a network that dropped it. This
 * hint used to sit only after the loop, on the path taken when the deadline passed; a refused pin
 * leaves through the step that returns an error, several lines earlier, so the one case the hint
 * exists for was the one case it never printed. */
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
    if (argc < 4 || argc > 8) {
        fprintf(stderr,
                "usage: lc-hy HOST PORT SNI [OBFS_PASSWORD [AUTH_PASSWORD [RECEIVE_BYTES_PER_SEC "
                "[PIN_SHA256]]]]\n"
                "  Both passwords take @FILE as well as a literal; OBFS_PASSWORD takes - or \"\"\n"
                "  where the node runs none. Exit: 0 it worked, 1 the network, 2 the arguments or a\n"
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

    /* Bytes per second, and refused rather than guessed at. strtoull read "100mbps" — the spelling
     * hysteria's own configuration uses — as 100 and "abc" as 0, and said nothing about either; a
     * rate of zero is not a slow one, it is Brutal switched off at the node, so the throughput this
     * tool then printed was ordinary congestion control wearing the protocol's name. */
    uint64_t rx_rate = 0;
    if (argc >= 7 && lc_u64(argv[6], &rx_rate) != 0) {
        fprintf(stderr, "%s is not a receive rate in bytes per second\n", argv[6]);
        return LC_EXIT_CONFIG;
    }

    /* The account, out of the process title as soon as it has been read. A command line is readable
     * through /proc by every process on the machine for as long as this one runs, and this argument
     * is the whole credential — lc-tunnel has taken it as @FILE and wiped it from the start, and the
     * three Hysteria2 probes took it as a literal and left it there. */
    char auth_password[128] = { 0 };
    if (argc >= 6) {
        int rc = lc_read_secret(argv[5], auth_password, sizeof auth_password);
        if (rc != 0) {
            fprintf(stderr, "cannot read the account password: %s\n", lc_secret_why(rc));
            return LC_EXIT_CONFIG;
        }
        memset(argv[5], 'x', strlen(argv[5]));
    }

    uint8_t pin[LC_QTLS_PIN];
    int     have_pin = 0;
    if (argc >= 8) {
        if (lc_from_hex(argv[7], pin, sizeof pin) != 0) {
            fprintf(stderr, "the pin is not %u hex bytes\n", (unsigned)sizeof pin);
            return LC_EXIT_CONFIG;
        }
        have_pin = 1;
    }

    /* The obfuscation password gets the same treatment as the account, and for the same reason: it
     * is a shared secret that gates the node's whole UDP port — a peer that does not know it gets no
     * answer at all — so leaving it legible in /proc for the life of the run is the same exposure
     * one argument to the left. Optional here, unlike its siblings, so an absent one stays absent —
     * as do "" and "-", the two ways the other tools and the service file spell "the node runs
     * none". An empty secret is refused everywhere now, so those two are answered here rather than
     * by letting nothing be a password. */
    char obfs_password[128] = { 0 };
    if (argc >= 5 && argv[4][0] != '\0' && strcmp(argv[4], "-") != 0) {
        int rc = lc_read_secret(argv[4], obfs_password, sizeof obfs_password);
        if (rc != 0) {
            fprintf(stderr, "cannot read the obfuscation password: %s\n", lc_secret_why(rc));
            return LC_EXIT_CONFIG;
        }
    }
    /* A dash is left alone, as it is in lc-tunnel and for the same reason: masking it puts an x where
     * the answer to "is this run obfuscated" used to be, and ps is where that question gets asked.
     * Nothing is hidden by masking it either — the argument is a password or @path, and a dash is
     * neither. */
    if (argc >= 5 && strcmp(argv[4], "-") != 0)
        memset(argv[4], 'x', strlen(argv[4]));
    const char *obfs = obfs_password[0] != '\0' ? obfs_password : NULL;

    printf("connecting to %s:%d over QUIC, SNI %s\n", host, port, sni);

    /* Zeroed — lc_qconn_open carries the gecko and hop settings across its own wipe, so it reads
     * them from here first. See the note in lc-hydns and the contract in conn.h. */
    lc_qconn c = { 0 };
    if (lc_qconn_open(&c, host, (uint16_t)port, sni, obfs, have_pin ? pin : NULL) != 0) {
        printf("failed: %s\n", c.err);
        return LC_EXIT_FAILED;
    }

    /* The ClientHello exactly as it went into the first CRYPTO frames. A QUIC server that dislikes
     * it says nothing at all — there is no alert, no reset, only silence — so the one way to find
     * out why is to take the message somewhere that will explain itself. */
    if (getenv("LC_HY_DUMP") != NULL) {
        FILE *f = fopen(getenv("LC_HY_DUMP"), "w");
        if (f != NULL) {
            for (size_t i = 0; i < c.shim.out[0].len; i++)
                fprintf(f, "%02x", c.shim.out[0].buf[i]);
            fprintf(f, "\n");
            fclose(f);
            fprintf(stderr, "wrote the %zu-byte ClientHello to %s\n", c.shim.out[0].len,
                    getenv("LC_HY_DUMP"));
        }
    }

    /* Five seconds is generous for a handshake that is two round trips at worst; anything longer
     * and the answer is that it is not happening. Measured on the clock: lc_qconn_step comes back
     * as soon as ngtcp2 wants attention, so fifty turns of it are not five seconds of waiting. */
    uint64_t deadline = lc_qconn_now_ms() + 5000u;
    while (!c.handshake_done && lc_qconn_now_ms() < deadline) {
        int rv = lc_qconn_step(&c, 100);
        if (rv < 0) {
            printf("failed: %s\n", c.err);
            pin_hint(have_pin);
            lc_qconn_close(&c);
            return LC_EXIT_FAILED;
        }
        if (rv == 0) {
            printf("%s\n", c.err);
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

    printf("QUIC handshake complete — the crypto backend works end to end\n");
    /* Said either way. A handshake that completed without a pin proves the crypto, and proves
     * nothing at all about who is on the other end — which is the distinction this line exists to
     * keep visible rather than let the reader assume.
     *
     * The middle arm is not reachable in practice: a pin that does not match ends the handshake
     * inside qtls.c, so nothing that got this far failed it. It stays because the verdict must not
     * be able to lie if that ever stops being true. */
    printf("node identity: %s\n",
           lc_qconn_pinned(&c)
               ? "the node holds the pinned certificate"
               : have_pin ? "PIN DID NOT MATCH — which should be impossible past the handshake"
                          : "not checked — no pin given");

    if (argc >= 6) {
        lc_h3_auth_result auth;
        if (lc_qconn_authenticate(&c, auth_password, rx_rate, &auth, 5000) != 0) {
            printf("authentication refused: %s\n", c.err);
            lc_qconn_close(&c);
            /* The node answered and would not have us: a password, not a network. */
            return LC_EXIT_CONFIG;
        }
        printf("authenticated: status %d, udp %s\n", auth.status, auth.udp_enabled ? "yes" : "no");

        /* What the two of us settled on. Stating a rate is what turns Brutal on at the node — it
         * then sends at that rate whatever the path does — so it is worth saying out loud which of
         * the two happened. */
        if (rx_rate > 0)
            printf("we asked to be sent at %llu B/s (%llu Mbit/s), which is Brutal at the node\n",
                   (unsigned long long)rx_rate, (unsigned long long)(rx_rate * 8u / 1000000u));
        else
            printf("we stated no receive rate, so the node decides its own\n");

        if (auth.rate_auto)
            printf("the node asks us to work our own sending rate out, which is what we do\n");
        else if (auth.rate_bytes > 0)
            printf("the node will receive at up to %llu B/s (%llu Mbit/s)\n",
                   (unsigned long long)auth.rate_bytes,
                   (unsigned long long)(auth.rate_bytes * 8u / 1000000u));
        else
            printf("the node stated no limit of its own\n");

        lc_qconn_close(&c);
        return LC_EXIT_OK;
    }

    printf("(this says nothing about being authenticated: Hysteria2 does that over HTTP/3 next)\n");
    lc_qconn_close(&c);
    return LC_EXIT_OK;
}
