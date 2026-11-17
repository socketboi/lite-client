/* lc-hydns — one DNS question asked through a Hysteria2 node, reported honestly.
 *
 * UDP is not TCP with the reliability removed: it is a different path through the whole client —
 * QUIC's unreliable datagrams instead of streams, a session instead of a connection, an address on
 * every packet instead of once at the start. None of that is exercised by lc-hyfetch, and none of
 * it fails in a way a stream would.
 *
 * A name lookup is the right thing to prove it with, and not only because it is small. Resolving
 * through the tunnel rather than beside it is the difference between a network that knows only that
 * you opened a QUIC connection and one that knows every site you visited.
 *
 *   lc-hydns HOST PORT SNI OBFS_PASSWORD AUTH_PASSWORD RESOLVER[:PORT] NAME
 *            [TYPE [PADDING [PIN_SHA256]]]
 *
 * The last three are positional and therefore stacked: a pin can only be given by giving a padding
 * as well, and a padding only by giving a type. AUTH_PASSWORD takes @FILE, which is what a run on
 * anything but a private machine should use. */

#include "core/args.h"
#include "core/rnd.h"
#include "net/sock.h"
#include "quic/conn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* What came back, filled in by the handler below. */
typedef struct {
    /* As large as a reassembled packet can be, not as large as one datagram: an answer that arrives
     * in pieces is exactly the answer worth asking for here. */
    uint8_t  buf[LC_HY_UDP_MAX];
    size_t   len;
    int      got;
    uint16_t id;
} answer;

static int on_datagram(void *user, int session, const char *addr, const uint8_t *data, size_t len)
{
    (void)session;
    (void)addr;
    answer *a = user;

    if (a->got || len < 2u || len > sizeof a->buf)
        return 0;
    /* The identifier that went out has to be the one that comes back; anything else is a reply to a
     * question we did not ask. */
    if (((uint16_t)data[0] << 8 | data[1]) != a->id)
        return 0;

    memcpy(a->buf, data, len);
    a->len = len;
    a->got = 1;
    return 0;
}

/* A question for one name. Returns the length or -1.
 *
 * It carries an OPT record saying we can take four kilobytes, which is what makes an answer bigger
 * than one datagram possible at all — and an answer bigger than one datagram is the only way to
 * exercise the reassembly this client does. Without it a resolver keeps every reply under 512
 * bytes and the interesting path is never taken. */
static long dns_query(uint16_t id, const char *name, unsigned qtype, size_t pad, uint8_t *out,
                      size_t cap)
{
    /* The four extra bytes are the padding option's own header — its code and its length — which is
     * written below only when there is padding to describe. Left out of the reserve, a name and a
     * padding length that together come to within four bytes of the caller's buffer pass this test
     * and then write past the end of it. */
    if (cap < 12u + strlen(name) + 6u + 11u + pad + (pad > 0 ? 4u : 0u))
        return -1;

    out[0] = (uint8_t)(id >> 8);
    out[1] = (uint8_t)id;
    out[2] = 0x01; /* recursion desired */
    out[3] = 0x00;
    out[4] = 0x00;
    out[5] = 0x01; /* one question */
    memset(out + 6, 0, 6);
    out[11] = 0x01; /* one additional record: the OPT below */

    /* The name as its labels: each preceded by its length, the lot ended by a zero. The root is a
     * name with no labels at all, written "." because nothing else can be. */
    size_t      n = 12;
    const char *at = name;
    if (strcmp(name, ".") == 0)
        at = "";
    for (; *at != '\0';) {
        const char *dot = strchr(at, '.');
        size_t      part = dot != NULL ? (size_t)(dot - at) : strlen(at);
        if (part == 0 || part > 63u)
            return -1;
        out[n++] = (uint8_t)part;
        memcpy(out + n, at, part);
        n += part;
        if (dot == NULL || dot[1] == '\0')
            break;
        at = dot + 1;
    }
    out[n++] = 0x00;

    out[n++] = (uint8_t)(qtype >> 8);
    out[n++] = (uint8_t)qtype;
    out[n++] = 0x00;
    out[n++] = 0x01; /* IN */

    /* OPT: an empty record on the root name whose class field is the size we can accept. */
    out[n++] = 0x00; /* root */
    out[n++] = 0x00;
    out[n++] = 0x29; /* type 41, OPT */
    out[n++] = 0x10;
    out[n++] = 0x00; /* 4096 */
    out[n++] = 0x00; /* extended rcode */
    out[n++] = 0x00; /* version */
    /* DNSSEC OK. Nothing here verifies a signature — the bit is set because it is what makes a
     * resolver attach them, and an answer with signatures in it is an answer too large for one
     * datagram. That is the path this probe exists to walk. */
    out[n++] = 0x80;
    out[n++] = 0x00;

    /* The rdata: nothing, or the padding option of RFC 7830, which exists precisely so that a query
     * can be made any size without meaning anything different. Here it is what makes a question too
     * large for one datagram — the only way to see this client split one from the outside. */
    size_t rdata = pad > 0 ? 4u + pad : 0u;
    out[n++] = (uint8_t)(rdata >> 8);
    out[n++] = (uint8_t)rdata;
    if (pad > 0) {
        out[n++] = 0x00;
        out[n++] = 0x0c; /* option 12, padding */
        out[n++] = (uint8_t)(pad >> 8);
        out[n++] = (uint8_t)pad;
        memset(out + n, 0, pad);
        n += pad;
    }
    return (long)n;
}

/* Steps over a name at `off`, which may end in a pointer to somewhere earlier. Returns the offset
 * after it, or 0. */
static size_t dns_skip_name(const uint8_t *in, size_t len, size_t off)
{
    for (;;) {
        if (off >= len)
            return 0;
        uint8_t l = in[off];
        if ((l & 0xc0u) == 0xc0u)
            return off + 2u <= len ? off + 2u : 0; /* a pointer, and nothing follows it */
        off += 1u + l;
        if (l == 0)
            return off <= len ? off : 0;
    }
}

/* Prints every address in the answer. Returns how many there were. */
static int dns_show(const uint8_t *in, size_t len)
{
    if (len < 12u)
        return 0;
    unsigned questions = (unsigned)in[4] << 8 | in[5];
    unsigned answers = (unsigned)in[6] << 8 | in[7];
    unsigned rcode = in[3] & 0x0fu;

    if (rcode != 0) {
        printf("the resolver answered with code %u\n", rcode);
        return 0;
    }

    size_t off = 12;
    for (unsigned i = 0; i < questions; i++) {
        off = dns_skip_name(in, len, off);
        if (off == 0 || off + 4u > len)
            return 0;
        off += 4u;
    }

    int found = 0;
    for (unsigned i = 0; i < answers; i++) {
        off = dns_skip_name(in, len, off);
        if (off == 0 || off + 10u > len)
            break;
        unsigned type = (unsigned)in[off] << 8 | in[off + 1];
        unsigned rdlen = (unsigned)in[off + 8] << 8 | in[off + 9];
        off += 10u;
        if (off + rdlen > len)
            break;
        if (type == 1u && rdlen == 4u) {
            printf("  %u.%u.%u.%u\n", in[off], in[off + 1], in[off + 2], in[off + 3]);
            found++;
        }
        off += rdlen;
    }
    return found;
}

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
    if (argc < 8 || argc > 11) {
        fprintf(stderr, "usage: lc-hydns HOST PORT SNI OBFS_PASSWORD AUTH_PASSWORD "
                        "RESOLVER[:PORT] NAME [TYPE [PADDING [PIN_SHA256]]]\n"
                        "  Both passwords take @FILE as well as a literal; OBFS_PASSWORD takes -\n"
                        "  or \"\" where the node runs none. Exit: 0 answered, 1 the network, 2 the\n"
                        "  arguments or a node that would not have us — see src/core/args.h.\n");
        return LC_EXIT_CONFIG;
    }

    /* Every argument is read here, before anything is opened. It used to be read in two places: the
     * type and the padding were parsed after the connection was up and the account had been sent, so
     * a mistyped padding was reported only once the password had crossed the network to a node that
     * may not be ours — and that refusal returned without lc_qconn_close, leaving the session on the
     * node until its idle timer collected it. An argument the program will refuse costs nothing to
     * refuse first. */
    const char *host = argv[1];
    uint16_t    port;
    if (lc_port(argv[2], &port) != 0) {
        fprintf(stderr, "%s is not a port\n", argv[2]);
        return LC_EXIT_CONFIG;
    }
    const char *sni = argv[3];
    const char *name = argv[7];

    /* The obfuscation password gets the same treatment as the account below it, and for the same
     * reason: it is a shared secret that gates the node's whole UDP port — a peer that does not know
     * it gets no answer at all — so leaving it legible in /proc for the life of the run is the same
     * exposure one argument to the left.
     *
     * "" and "-" both mean the node runs none — the first is what this has always taken, the second
     * is what lc-tunnel and the service file spell it as. An empty secret is refused everywhere now,
     * so those two are answered here rather than by letting nothing be a password. */
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

    /* The resolver, split and put back together rather than tested for a colon and passed on. The
     * test for a colon was the whole of the checking: "1.1.1.1:" and "1.1.1.1:domain" went to the
     * node as addresses it could only refuse, and the refusal came back saying nothing about which
     * argument caused it. */
    char     resolver[300], resolver_host[256];
    uint16_t resolver_port = 53;
    if (lc_host_port(argv[6], resolver_host, sizeof resolver_host, &resolver_port, 53) != 0) {
        fprintf(stderr, "%s is not a resolver: HOST, HOST:PORT or [V6ADDR]:PORT\n", argv[6]);
        return LC_EXIT_CONFIG;
    }
    snprintf(resolver, sizeof resolver, strchr(resolver_host, ':') != NULL ? "[%s]:%u" : "%s:%u",
             resolver_host, resolver_port);

    /* A by default; anything else by number, because a table of names would be a table to keep. Read
     * as a bounded sixteen-bit number rather than with atoi, which answered "AAAA" with type 0 and
     * "-1" with 65535 once the conversion had happened — a question asked about the wrong type comes
     * back answered, so nothing in the output would have said which one went out. */
    unsigned qtype = 1u;
    if (argc >= 9) {
        uint16_t t;
        if (lc_u16(argv[8], &t) != 0) {
            fprintf(stderr, "%s is not a DNS type number\n", argv[8]);
            return LC_EXIT_CONFIG;
        }
        qtype = t;
    }

    /* Bounded here, before it becomes a size_t, and not with atoi. atoi returns an int, and "-1"
     * written into a size_t becomes SIZE_MAX — at which point the sum in dns_query's capacity check
     * wraps, passes, and the memset walks four gigabytes past the end of the buffer. That check's
     * arithmetic is right for every sensible value; the insensible ones have to be refused before the
     * conversion, which is what this is.
     *
     * argc >= 10, not == 10: the pin follows the padding, so with a pin given argc is 11 and the
     * equality test threw the padding away without a word. The arguments are positional, which means
     * a pin can only be given by giving padding as well — so every pinned run was an unpadded one,
     * and the padded case, the whole reason this tool exists, could never be measured with the node
     * authenticated. The same equality was fixed once already in lc-fetch: see
     * src/cmd/lc-fetch/main.c:106. */
    size_t pad = 0;
    if (argc >= 10) {
        uint64_t pad_arg;
        if (lc_u64(argv[9], &pad_arg) != 0 || pad_arg > (uint64_t)LC_HY_UDP_MAX) {
            fprintf(stderr, "padding must be between 0 and %u\n", (unsigned)LC_HY_UDP_MAX);
            return LC_EXIT_CONFIG;
        }
        pad = (size_t)pad_arg;
    }

    /* This tool sends the account password and the user's DNS questions over the connection, so it
     * has to be able to say who answered. Its siblings could and it could not. */
    uint8_t pin[LC_QTLS_PIN];
    int     have_pin = 0;
    if (argc >= 11) {
        if (lc_from_hex(argv[10], pin, sizeof pin) != 0) {
            fprintf(stderr, "the pin is not %u hex bytes\n", (unsigned)sizeof pin);
            return LC_EXIT_CONFIG;
        }
        have_pin = 1;
    }

    /* ZEROED, and it is not tidiness: lc_qconn_open reads the gecko and hop settings out of this
     * struct BEFORE it wipes it, so that a caller can arm them beforehand. Left uninitialised here,
     * those reads take whatever the stack held — and a non-zero `gecko.on` turns on frame splitting
     * against a node that runs none, which the node answers by dropping every packet. See conn.h. */
    lc_qconn c = { 0 };
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
    if (lc_qconn_authenticate(&c, auth_password, 0, &got, 5000) != 0) {
        /* The node answered and would not have us: a password, not a network — 2, as it is
         * everywhere else. */
        printf("authentication refused: %s\n", c.err);
        lc_qconn_close(&c);
        return LC_EXIT_CONFIG;
    }
    /* Three states, and the middle one is not reachable in practice: a pin that does not match ends
     * the handshake inside qtls.c, so this line is only ever reached by a connection that got past
     * it. The arm stays because the verdict must not be able to lie if that ever stops being true —
     * an unpinned connection reported as pinned is the one mistake this line exists to prevent. */
    printf("node identity: %s\n",
           lc_qconn_pinned(&c)
               ? "the node holds the pinned certificate"
               : have_pin ? "PIN DID NOT MATCH — which should be impossible past the handshake"
                          : "not checked — no pin given");
    if (!got.udp_enabled) {
        printf("the node does not relay datagrams for us\n");
        lc_qconn_close(&c);
        return LC_EXIT_FAILED;
    }

    answer  a;
    uint8_t idb[2];
    memset(&a, 0, sizeof a);
    if (lc_rnd(idb, sizeof idb) != 0) {
        printf("no randomness for a transaction id\n");
        lc_qconn_close(&c);
        return LC_EXIT_FAILED;
    }
    a.id = (uint16_t)((uint16_t)idb[0] << 8 | idb[1]);

    lc_qconn_udp_handler(&c, on_datagram, &a);

    int session = lc_qconn_udp_open(&c);
    if (session < 0) {
        printf("cannot open a session: %s\n", c.err);
        lc_qconn_close(&c);
        return LC_EXIT_FAILED;
    }

    uint8_t query[LC_HY_UDP_MAX];
    long    qn = dns_query(a.id, name, qtype, pad, query, sizeof query);
    if (qn < 0) {
        /* Two different refusals used to share one sentence, and it named the wrong one: a padding
         * size that does not leave room for the question is not a bad name, and being told it is
         * sends the reader to check a name that was fine. */
        if (pad > 0)
            printf("%s plus %zu bytes of padding does not fit a %zu-byte query\n", name, pad,
                   sizeof query);
        else
            printf("%s is not a name this can ask about\n", name);
        lc_qconn_close(&c);
        return LC_EXIT_FAILED;
    }

    if (lc_qconn_udp_send(&c, session, resolver, query, (size_t)qn) != 0) {
        printf("the question was dropped before it left: %s\n", c.err);
        lc_qconn_close(&c);
        return LC_EXIT_FAILED;
    }
    printf("asked %s about %s, through the node — %ld bytes%s\n", resolver, name, qn,
           (size_t)qn + lc_hy_udp_header_len(resolver) > LC_QUDP_PAYLOAD
               ? ", which had to be split across datagrams"
               : "");

    /* Three seconds and no retry. A question that goes missing is what UDP is, and a client that
     * hid that behind a retry here would be hiding the one thing this is meant to show. */
    deadline = lc_qconn_now_ms() + 3000u;
    while (!a.got && lc_qconn_now_ms() < deadline) {
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
    }

    if (!a.got) {
        printf("no answer came back within three seconds\n");
        lc_qconn_udp_close(&c, session);
        lc_qconn_close(&c);
        return LC_EXIT_FAILED;
    }

    /* The size is the point when the answer is a big one: over about eleven hundred bytes it cannot
     * have arrived in a single datagram, so reading it at all means the pieces were put back
     * together in the right order. */
    printf("%zu bytes back%s\n", a.len,
           a.len + lc_hy_udp_header_len(resolver) > LC_QUDP_PAYLOAD
               ? ", which is more than one datagram holds"
               : "");

    /* Pointed at something that echoes rather than a resolver, this is the whole test: a packet
     * split into datagrams here, put together at the node, split again on the way back and put
     * together here. The length alone would not show it — a reassembly that got the order wrong
     * returns exactly as many bytes as went out. */
    if (a.len == (size_t)qn && memcmp(a.buf, query, a.len) == 0)
        printf("  byte for byte what went out\n");
    if (dns_show(a.buf, a.len) == 0)
        printf("  (no addresses in it)\n");

    lc_qconn_udp_close(&c, session);
    lc_qconn_close(&c);
    return LC_EXIT_OK;
}
