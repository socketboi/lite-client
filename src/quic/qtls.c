#include "quic/qtls.h"

#if defined(__aarch64__)
#include <sys/auxv.h>
#endif

#include "core/buf.h"
#include "core/rnd.h"
#include "quic/chrome_hello.h"
#include "cert/cert.h"
#include "cert/x509go.h"
#include "fp/hello.h"
#include "tls/certcomp.h"
#include "tls/certverify.h"
#include "tls/goerr.h"
#include "tls/kex.h"
#include "tls/msg.h"
#include "tls/stdmsg.h"
#include "tls/suite.h"
#include "core/wipe.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/md.h>
#include <mbedtls/pk.h>

#define EXT_SERVER_NAME 0x0000u
#define EXT_STATUS_REQUEST 0x0005u
#define EXT_SUPPORTED_GROUPS 0x000au
#define EXT_EC_POINT_FORMATS 0x000bu
#define EXT_SIGNATURE_ALGORITHMS 0x000du
#define EXT_SIGNATURE_ALGORITHMS_CERT 0x0032u
#define EXT_SCT 0x0012u
#define EXT_EXTENDED_MASTER_SECRET 0x0017u
#define EXT_SESSION_TICKET 0x0023u
#define EXT_SUPPORTED_VERSIONS 0x002bu
#define EXT_PSK_KEY_EXCHANGE_MODES 0x002du
#define EXT_KEY_SHARE 0x0033u
#define EXT_COOKIE 0x002cu
#define EXT_QUIC_TRANSPORT_PARAMS 0x0039u
#define EXT_RENEGOTIATION_INFO 0xff01u

/* Hysteria2 speaks HTTP/3 for its authentication exchange, so the ALPN is "h3" and a server that
 * offers nothing else will reject any other value. */
static const char alpn_h3[] = "h3";

/* The hello in force: the first, or the second after a HelloRetryRequest. */
static const uint8_t *hello_bytes(const lc_qtls *q) { return q->ch_heap != NULL ? q->ch_heap : q->ch; }

static void put_u16(lc_buf *b, uint16_t v) { lc_buf_u16(b, v); }

/* An extension with a body written by `fill`, whose length is patched once known. Extensions are
 * length-prefixed and their bodies are built from other length-prefixed pieces, so patching is
 * simpler than computing sizes twice and getting one of them wrong. */
static size_t ext_begin(lc_buf *b, uint16_t type)
{
    put_u16(b, type);
    size_t at = b->len;
    put_u16(b, 0);
    return at;
}

static void ext_end(lc_buf *b, size_t at)
{
    size_t n = b->len - at - 2u;
    if (b->err || at + 1u >= b->cap)
        return;
    b->p[at] = (uint8_t)(n >> 8);
    b->p[at + 1u] = (uint8_t)n;
}

/* max_datagram_frame_size, from RFC 9221 §3. Written out here rather than taken from ngtcp2, whose
 * name for it lives in a private header — `#define NGTCP2_TRANSPORT_PARAM_MAX_DATAGRAM_FRAME_SIZE
 * 0x20U` (vendor/ngtcp2/lib/ngtcp2_transport_params.h:56), same value, not includable from here:
 * this file is our own TLS and knows nothing of ngtcp2, which is what lets the same code serve the
 * shim and the tests. */
#define QUIC_TP_MAX_DATAGRAM_FRAME_SIZE 0x20u

/* QUIC transport parameters are a sequence of (id, length, value), each of the first two a QUIC
 * variable-length integer. Only the top two bits of the first byte matter for the length: 1, 2, 4
 * or 8 bytes. That is the whole of the format, which is why this is a dozen lines rather than a
 * dependency. */
static int varint_take(const uint8_t **p, const uint8_t *end, uint64_t *out)
{
    if (*p >= end)
        return -1;
    unsigned len = 1u << ((**p) >> 6);
    if ((size_t)(end - *p) < len)
        return -1;

    uint64_t v = (uint64_t)(**p & 0x3fu);
    for (unsigned i = 1; i < len; i++)
        v = (v << 8) | (*p)[i];

    *p += len;
    *out = v;
    return 0;
}

/* A QUIC variable-length integer, in the shortest encoding that holds the value.
 *
 * Only the two shorter forms are needed here — the greased id below never exceeds 7932 — but both
 * are written out because a value of 63 encoded in two bytes is legal, unusual, and exactly the kind
 * of thing that makes a client its own. */
static void varint_put(lc_buf *b, uint64_t v)
{
    if (v < 64u) {
        lc_buf_u8(b, (uint8_t)v);
    } else {
        lc_buf_u8(b, (uint8_t)(0x40u | (v >> 8)));
        lc_buf_u8(b, (uint8_t)v);
    }
}

/* The greased transport parameter every quic-go client sends, and this one did not.
 *
 * TransportParameters.Marshal opens with it, before initial_max_stream_data_bidi_local and before
 * anything else (vendor/quic-go/internal/wire/transport_parameters.go:361-378):
 *
 *   random := make([]byte, 18); rand.Read(random)
 *   id     = 27 + 31*random[0]        so one of 256 values, 27 through 7932
 *   length = random[1] % 16           zero to fifteen
 *   body   = random[2 : 2+length]
 *
 * It is there so that a peer which chokes on an unknown parameter is found early rather than in the
 * field — the same reason TLS has GREASE — and the consequence for us is that its ABSENCE is a
 * signal. Every hysteria client puts one in the first packet of every connection, in the clear as
 * far as anyone who derives the Initial keys is concerned, and this client put none.
 *
 * ngtcp2 does not do it: what it calls grease_quic_bit is RFC 9287's parameter 0x2ab2, a defined
 * value with a defined meaning, and it defaults off — which is right, since quic-go does not know
 * that parameter at all and a client sending it would be inventing a difference rather than closing
 * one.
 *
 * Written here rather than asked of ngtcp2 because ngtcp2 has no way to carry an unknown parameter,
 * and this function is already the place where the encoded blob is rewritten. */
static int write_greased_param(lc_buf *b)
{
    uint8_t r[18];
    if (lc_rnd(r, sizeof r) != 0)
        return -1;

    varint_put(b, 27u + 31u * (uint64_t)r[0]);
    uint8_t len = r[1] % 16u;
    varint_put(b, len);
    if (len > 0)
        lc_buf_write(b, r + 2, len);
    return 0;
}

/* The transport parameters as the reference writes them: a fixed sequence, and nothing else.
 *
 * TransportParameters.Marshal is a straight run of writes in one order
 * (vendor/quic-go/internal/wire/transport_parameters.go:361-457) — greased entry, then the
 * parameters, then done. It has no rule for an identifier it does not know, because it never
 * encounters one: it writes the list it has.
 *
 * This does the same. The values come from ngtcp2's own encoding, because this file must not know
 * ngtcp2 and cannot ask it for numbers directly, and each is copied with the bytes ngtcp2 chose —
 * so a varint written wider than it had to be travels as it was. What changes is the ORDER, and the
 * order is the reference's:
 *
 *   ngtcp2   05 06 07 04 08 09 03 0b 01 0e ...   with initial_scid ahead of 05
 *   quic-go  05 06 07 04 08 09 01 03 0b 0e 0f
 *
 * Both encode the same set and neither is wrong — a server reads by identifier. But the bytes are
 * inside the ClientHello, inside an Initial whose keys are derived from a connection id sent in the
 * clear, so the order is visible to anyone who cares to look.
 *
 * WHAT IS NOT HERE, HAVING BEEN HERE: a tail for identifiers this list does not name, and a retreat
 * that copied the whole blob through when it would not parse. Both were mine and neither has a
 * counterpart in Marshal. An identifier quic-go does not write is one this client should not write
 * either; a blob that does not parse is this code being wrong about a blob it produced a moment
 * earlier, and answering that by sending something is worse than answering it by stopping. */
static int write_params_without_datagram_size(lc_buf *b, const uint8_t *params, size_t params_len)
{
    /* First, exactly as Marshal opens. */
    if (write_greased_param(b) != 0)
        return -1;

    static const uint64_t order[] = {
        0x05u, /* initial_max_stream_data_bidi_local */
        0x06u, /* initial_max_stream_data_bidi_remote */
        0x07u, /* initial_max_stream_data_uni */
        0x04u, /* initial_max_data */
        0x08u, /* initial_max_streams_bidi */
        0x09u, /* initial_max_streams_uni */
        0x01u, /* max_idle_timeout */
        0x03u, /* max_udp_payload_size */
        0x0bu, /* max_ack_delay */
        0x0au, /* ack_delay_exponent */
        0x0cu, /* disable_active_migration */
        0x0eu, /* active_connection_id_limit */
        0x0fu, /* initial_source_connection_id */
    };

    /* max_datagram_frame_size (0x20) is deliberately absent from that list — the long reason is at
     * the caller. Everything else ngtcp2 emits for this configuration is named. */
    for (unsigned i = 0; i < sizeof order / sizeof order[0]; i++) {
        const uint8_t *p = params;
        const uint8_t *end = params + params_len;
        int            found = 0;
        while (p < end) {
            const uint8_t *entry = p;
            uint64_t       id = 0, len = 0;
            if (varint_take(&p, end, &id) != 0 || varint_take(&p, end, &len) != 0 ||
                (uint64_t)(end - p) < len)
                return -1;
            p += len;
            if (id == order[i]) {
                lc_buf_write(b, entry, (size_t)(p - entry));
                found = 1;
            }
        }

        /* initial_max_streams_bidi, written here when ngtcp2 did not write it, and in its place in
         * the order rather than appended.
         *
         * The reference says zero (the whole derivation is in src/quic/params.c) and says it out
         * loud: marshalVarintParam is called unconditionally for this identifier
         * (vendor/quic-go/internal/wire/transport_parameters.go:388-389, the line commented
         * `// initial_max_bidi_streams`, with :487-491), so a
         * quic-go hello always carries `08 01 00`. ngtcp2's encoder is the opposite — it skips a
         * parameter whose value is zero (`if (params->initial_max_streams_bidi) {`,
         * vendor/ngtcp2/lib/ngtcp2_transport_params.c:330-333) — so asking ngtcp2 for zero and
         * copying what it produced would drop the entry entirely, trading a wrong value for a
         * missing one. Both are visible in the same place and the missing one is rarer.
         *
         * Only this identifier is synthesised, and only when absent: every other entry in `order`
         * is non-zero for this configuration, so ngtcp2 emits it and the copy above finds it. */
        if (!found && order[i] == 0x08u) {
            static const uint8_t zero_streams_bidi[] = { 0x08u, 0x01u, 0x00u };
            lc_buf_write(b, zero_streams_bidi, sizeof zero_streams_bidi);
        }
    }
    return 0;
}

/* randUint64n from the fork, draw for draw: eight bytes from the system source read big-endian, then
 * the remainder by n — "the modulo bias is negligible at the magnitudes used here", as it says, and
 * reproduced rather than corrected, since a corrected draw is a different distribution
 * (vendor/quic-go/internal/wire/transport_parameters_chrome.go:150-156). */
static int rand_u64n(uint64_t n, uint64_t *out)
{
    uint8_t r[8];
    if (lc_rnd(r, sizeof r) != 0)
        return -1;
    uint64_t v = 0;
    for (unsigned i = 0; i < sizeof r; i++)
        v = v << 8 | r[i];
    *out = v % n;
    return 0;
}

/* A QUIC variable-length integer of any width, shortest form — what quicvarint.Append writes. */
static void varint_put_any(lc_buf *b, uint64_t v)
{
    if (v < (1u << 6)) {
        lc_buf_u8(b, (uint8_t)v);
    } else if (v < (1u << 14)) {
        lc_buf_u16(b, (uint16_t)(0x4000u | v));
    } else if (v < (1ull << 30)) {
        lc_buf_u16(b, (uint16_t)(0x8000u | v >> 16));
        lc_buf_u16(b, (uint16_t)v);
    } else {
        lc_buf_u16(b, (uint16_t)(0xc000u | v >> 48));
        lc_buf_u16(b, (uint16_t)(v >> 32));
        lc_buf_u16(b, (uint16_t)(v >> 16));
        lc_buf_u16(b, (uint16_t)v);
    }
}

static void put_u32(lc_buf *b, uint32_t v)
{
    lc_buf_u16(b, (uint16_t)(v >> 16));
    lc_buf_u16(b, (uint16_t)v);
}

/* The most parameters marshalChrome writes: eight numbers, the source connection ID, the version
 * information, the DATAGRAM size, Google's connection options and one GREASE entry. */
#define CHROME_TP_MAX 13u

/* THE TRANSPORT PARAMETERS AS THE REFERENCE WRITES THEM WHILE IT PARROTS CHROME, which is a
 * different function from the one above: marshalChrome
 * (vendor/quic-go/internal/wire/transport_parameters_chrome.go:49-88), reached from Marshal whenever
 * ChromeFingerprint is set on a client's parameters (vendor/quic-go/internal/wire/
 * transport_parameters.go:363-365), which chromeParrotTransportParameters sets
 * (vendor/quic-go/chrome_parrot.go:31-39).
 *
 * Four things differ from quic-go's own encoding, each visible to anyone who opens the Initial:
 *
 *   - the entries are SHUFFLED, a fresh order every connection — Fisher-Yates on randUint64n
 *     (:142-148);
 *   - two entries quic-go never writes: version_information, version 1 chosen and a GREASE version
 *     beside it in either order (:90-119), and google_connection_options carrying "ORIG" (:75-77);
 *   - four that quic-go always writes are gone — ack_delay_exponent, max_ack_delay,
 *     disable_active_migration and active_connection_id_limit — the parrot resetting each to the
 *     value its absence means (chrome_parrot.go:34-37);
 *   - the GREASE entry takes an identifier wide enough for an eight-byte varint and a value of
 *     zero to fifteen random bytes (:127-140), not quic-go's short one.
 *
 * The values are ngtcp2's own encoding, copied with the bytes it chose, exactly as the writer above
 * copies them — the numbers are set in src/quic/params.c. Every entry is required: an identifier
 * missing from ngtcp2's blob is this code wrong about a blob it made a moment earlier, and
 * answering that by sending a different set is worse than stopping. */
static int write_params_chrome(lc_buf *b, const uint8_t *params, size_t params_len)
{
    static const uint64_t taken[] = {
        0x01u, /* max_idle_timeout */
        0x03u, /* max_udp_payload_size */
        0x04u, /* initial_max_data */
        0x05u, /* initial_max_stream_data_bidi_local */
        0x06u, /* initial_max_stream_data_bidi_remote */
        0x07u, /* initial_max_stream_data_uni */
        0x08u, /* initial_max_streams_bidi */
        0x09u, /* initial_max_streams_uni */
        0x0fu, /* initial_source_connection_id — empty, the source identifier being empty */
        0x20u, /* max_datagram_frame_size, which the parrot always sends */
    };

    /* Each entry built on its own, in the order marshalChrome adds them, so the shuffle permutes
     * what the reference permutes. */
    uint8_t        store[512];
    lc_buf         s;
    const uint8_t *at[CHROME_TP_MAX];
    size_t         len[CHROME_TP_MAX];
    unsigned       n = 0;
    lc_buf_init(&s, store, sizeof store);

    for (unsigned i = 0; i < sizeof taken / sizeof taken[0]; i++) {
        const uint8_t *entry = NULL, *p = params, *end = params + params_len;
        size_t         entry_len = 0;
        while (p < end) {
            const uint8_t *start = p;
            uint64_t       id = 0, l = 0;
            if (varint_take(&p, end, &id) != 0 || varint_take(&p, end, &l) != 0 ||
                (uint64_t)(end - p) < l)
                return -1;
            p += l;
            if (id == taken[i]) {
                entry = start;
                entry_len = (size_t)(p - start);
            }
        }
        if (entry == NULL)
            return -1;
        /* version_information goes between the source identifier and the DATAGRAM size, which is
         * where marshalChrome adds it (:69). */
        if (taken[i] == 0x20u) {
            at[n] = store + s.len;
            varint_put_any(&s, 0x11u);
            varint_put_any(&s, 12u);
            put_u32(&s, 0x00000001u);
            uint8_t g[4];
            uint64_t swap;
            if (lc_rnd(g, sizeof g) != 0 || rand_u64n(2u, &swap) != 0)
                return -1;
            uint32_t grease = 0;
            for (unsigned k = 0; k < sizeof g; k++)
                grease = grease << 8 | (uint32_t)((g[k] & 0xf0u) | 0x0au);
            put_u32(&s, swap == 1u ? grease : 0x00000001u);
            put_u32(&s, swap == 1u ? 0x00000001u : grease);
            len[n] = (size_t)(store + s.len - at[n]);
            n++;
        }
        at[n] = store + s.len;
        lc_buf_write(&s, entry, entry_len);
        len[n] = entry_len;
        n++;
    }

    /* google_connection_options, "ORIG" and nothing else (:23-25, :75-77). */
    at[n] = store + s.len;
    varint_put_any(&s, 0x3128u);
    varint_put_any(&s, 4u);
    lc_buf_write(&s, (const uint8_t *)"ORIG", 4u);
    len[n] = (size_t)(store + s.len - at[n]);
    n++;

    /* The GREASE entry: 31N+27 with N drawn so the identifier needs all eight bytes of a varint,
     * then a length of 0..15 and that many random bytes (:127-140). */
    {
        const uint64_t n_min = ((1ull << 30) - 27u + 30u) / 31u;
        const uint64_t n_max = ((1ull << 62) - 1u - 27u) / 31u;
        uint64_t       k, vlen;
        uint8_t        val[15];
        if (rand_u64n(n_max - n_min, &k) != 0 || rand_u64n(16u, &vlen) != 0 ||
            lc_rnd(val, sizeof val) != 0)
            return -1;
        at[n] = store + s.len;
        varint_put_any(&s, 31u * (n_min + k) + 27u);
        varint_put_any(&s, vlen);
        lc_buf_write(&s, val, (size_t)vlen);
        len[n] = (size_t)(store + s.len - at[n]);
        n++;
    }
    if (s.err || n != CHROME_TP_MAX)
        return -1;

    /* shuffleParams: i from the last index down to 1, j drawn over [0, i] (:142-148). */
    unsigned order[CHROME_TP_MAX];
    for (unsigned i = 0; i < n; i++)
        order[i] = i;
    for (unsigned i = n - 1u; i > 0u; i--) {
        uint64_t j;
        if (rand_u64n((uint64_t)i + 1u, &j) != 0)
            return -1;
        unsigned t = order[i];
        order[i] = order[(unsigned)j];
        order[(unsigned)j] = t;
    }
    for (unsigned i = 0; i < n; i++)
        lc_buf_write(b, at[order[i]], len[order[i]]);
    return b->err ? -1 : 0;
}

/* Whether this machine has the assembly GCM Go looks for, answered the way Go answers it.
 *
 * The whole of why it matters is in the cipher-suite block below: the answer decides which of two
 * orders goes on the wire, and the wrong one is a client no Go program produces. See
 * vendor/utls/cipher_suites.go:360-368 for the four rules being reproduced.
 *
 * Exported rather than kept static so that the answer can be asked for on its own. It is NOT
 * covered by the gate, and could not usefully be: the only machines this tree builds on are an
 * x86_64 with AES-NI and a mipsel without it, and both gave the same answer under the arch-only
 * test this replaced. What the change fixes is the case neither of them is — an x86_64 whose AES
 * the kernel or the hypervisor does not offer — and asserting that would mean asserting against a
 * processor nobody here has. */
int lc_qtls_aesgcm_hardware(void)
{
#if defined(__x86_64__) || defined(__i386__)
    /* The same four, and all four are required — Go ands them together. __builtin_cpu_supports is
     * resolved at run time by gcc and clang, which is what makes this a question about the machine
     * rather than about the compiler. */
    return __builtin_cpu_supports("aes") && __builtin_cpu_supports("pclmul") &&
           __builtin_cpu_supports("sse4.1") && __builtin_cpu_supports("ssse3");
#elif defined(__aarch64__)
    /* HWCAP_AES and HWCAP_PMULL, which are what cpu.ARM64.HasAES and HasPMULL are read from on
     * Linux — the kernel's auxiliary vector. */
    unsigned long hw = getauxval(AT_HWCAP);
    return (hw & HWCAP_AES) != 0 && (hw & HWCAP_PMULL) != 0;
#elif defined(__powerpc64__)
    /* The architecture alone, which is Go's rule here and not a simplification of it. */
    return 1;
#else
    /* mipsel among others, and s390x deliberately: see the block below. */
    return 0;
#endif
}

/* Records why the handshake stopped and answers -1, so that a refusal reads as one statement.
 *
 * The FIRST reason is kept: see the note beside `err` in the header. Deliberately no logging and no
 * output — this file is a state machine that several programs drive, and one of them is a daemon
 * whose stderr is a router's syslog. */
static int fail(lc_qtls *q, uint8_t alert, const char *fmt, ...)
{
    if (q->err[0] == '\0') {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(q->err, sizeof q->err, fmt, ap);
        va_end(ap);
        q->alert = alert;
    }
    return -1;
}

/* A failure of this client's own, which the reference has no counterpart to — see `own` in the
 * header. Kept as the first reason like any other, with internal_error beside it for the log. */
static int own_fail(lc_qtls *q, const char *fmt, ...)
{
    if (q->err[0] == '\0') {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(q->err, sizeof q->err, fmt, ap);
        va_end(ap);
        q->alert = LC_ALERT_INTERNAL_ERROR;
        q->own = 1;
    }
    return -1;
}

/* The reference's words for the refusal about to be made: called just before the fail() it goes
 * with, and kept only when that refusal will be the first — the same rule fail() keeps. See go_err
 * in the header. Returns nothing, so that a site reads `go_says(...); return fail(...);`. */
static void go_says(lc_qtls *q, const char *fmt, ...)
{
    if (q->err[0] == '\0' && q->go_err[0] == '\0' && fmt != NULL) {
        va_list ap;
        va_start(ap, fmt);
        lc_go_vsnprintf(q->go_err, sizeof q->go_err, fmt, ap);
        va_end(ap);
    }
}

/* What %T prints for the message uTLS reads a handshake type into: the cases of
 * unmarshalHandshakeMessage and utlsHandshakeMessageType (vendor/utls/conn.go:1134-1185,
 * vendor/utls/u_conn.go:826-838), the TLS 1.3 message for a type that has two once a ServerHello or
 * a retry has set c.vers (`tls13`), the TLS 1.2 one before. NULL for a type uTLS has no reader for. */
static const char *go_msg_type(uint8_t type, int tls13)
{
    switch (type) {
    case 0u:  return "*tls.helloRequestMsg";
    case 1u:  return "*tls.clientHelloMsg";
    case 2u:  return "*tls.serverHelloMsg";
    case 4u:  return tls13 ? "*tls.newSessionTicketMsgTLS13" : "*tls.newSessionTicketMsg";
    case 5u:  return "*tls.endOfEarlyDataMsg";
    case 8u:  return "*tls.encryptedExtensionsMsg";
    case 11u: return tls13 ? "*tls.certificateMsgTLS13" : "*tls.certificateMsg";
    case 12u: return "*tls.serverKeyExchangeMsg";
    case 13u: return tls13 ? "*tls.certificateRequestMsgTLS13" : "*tls.certificateRequestMsg";
    case 14u: return "*tls.serverHelloDoneMsg";
    case 15u: return "*tls.certificateVerifyMsg";
    case 16u: return "*tls.clientKeyExchangeMsg";
    case 20u: return "*tls.finishedMsg";
    case 22u: return "*tls.certificateStatusMsg";
    case 24u: return "*tls.keyUpdateMsg";
    case 25u: return "*tls.utlsCompressedCertificateMsg";
    default:  return NULL;
    }
}

/* Whether uTLS's readHandshake reads `whole` — the message, header included — which it does in
 * unmarshalHandshakeMessage before the handshake looks at the type (vendor/utls/conn.go:1125-1201):
 * a type with no reader does not, and a known one does when its unmarshal does. Its readers are the
 * standard library's for every TLS 1.3 message but two (vendor/utls/handshake_messages.go, compared
 * with the Go 1.26.6 toolchain's on 2026-09-29; vendor/utls-hy's differ from them only in writing
 * a ClientHello): EncryptedExtensions, which has no repeat check and no server_name case, and
 * CompressedCertificate, which is uTLS's own. */
static int utls_reads(const uint8_t *whole, size_t whole_len, int tls13)
{
    if (go_msg_type(whole[0], tls13) == NULL)
        return 0;
    if (whole[0] == LC_HS_ENCRYPTED_EXT)
        return lc_utls_ee_reads(whole + 4, whole_len - 4u);
    if (whole[0] == LC_HS_COMPRESSED_CERTIFICATE)
        return lc_utls_certcomp_reads(whole + 4, whole_len - 4u);
    return lc_std_misplaced_alert(whole, whole_len, tls13) != LC_ALERT_DECODE_ERROR;
}

uint8_t lc_qtls_alert(const lc_qtls *q)
{
    return q->alert;
}

const char *lc_qtls_go_error(const lc_qtls *q)
{
    return q->go_err;
}

int lc_qtls_own(const lc_qtls *q)
{
    return q->own;
}

const char *lc_qtls_error(const lc_qtls *q)
{
    return q->err;
}

static int build_hello(lc_qtls *q, const char *sni, const uint8_t *params, size_t params_len,
                       uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (strlen(sni) == 0 || strlen(sni) > 255u)
        return -1;
    /* The name as hostnameInSNI leaves it — an IP literal none, trailing dots cut — and no
     * extension for none: `if len(m.serverName) > 0` (vendor/utls-hy/handshake_client.go:82,
     * vendor/utls-hy/handshake_messages.go:116, the standard library's code in both). */
    size_t sni_len = lc_hello_sni_len(sni);

    /* One generation, two key shares. The hybrid share is `ML-KEM ek || X25519 pub`, so its last
     * 32 bytes ARE the X25519 public key and the fallback share reuses them rather than generating
     * a second ephemeral — which is what the reference does, and says so:
     * "we send both key shares (as a fallback) and we reuse the same X25519 ephemeral key, as
     * allowed by draft-ietf-tls-hybrid-design-09, Section 3.2"
     * (vendor/utls/handshake_client.go:184-189). Two independent keys would be visible to anyone
     * comparing the two shares in the first packet. */
    uint8_t share[LC_HYBRID_SHARE];
    if (lc_hybrid_keygen(&q->hybrid, share) != 0)
        return -1;
    const uint8_t *pub = share + LC_MLKEM_EK;

    lc_buf b;
    lc_buf_init(&b, out, out_cap);

    lc_buf_u8(&b, LC_HS_CLIENT_HELLO);
    size_t len_at = b.len;
    lc_buf_u24(&b, 0);
    size_t body_at = b.len;

    lc_buf_u16(&b, 0x0303u); /* legacy_version */

    uint8_t random[32];
    if (lc_rnd(random, sizeof random) != 0)
        return -1;
    lc_buf_write(&b, random, sizeof random);

    /* An empty legacy session id. A browser sends 32 random bytes and REALITY overwrites them, but
     * neither applies here: QUIC forbids the middlebox-compatibility mode those bytes exist for. */
    lc_buf_u8(&b, 0);

    /* THREE SUITES, IN THE ORDER THE REFERENCE CLIENT WOULD SEND THEM ON THIS HARDWARE.
     *
     * One was here before, with a comment saying that offering three "would only add three code
     * paths to get wrong". Both halves of that were wrong.
     *
     * It is a fingerprint. Hysteria's client builds its whole tls.Config in one literal and no
     * CipherSuites field appears in it (vendor/hysteria/core/client/client.go:75-82), so the choice
     * falls to quic-go, which takes Go's own lists — and utls, vendored here, carries them with a
     * comment naming quic-go by name as the consumer that reaches in by linkname
     * (vendor/utls/defaults.go:81-95): three suites, ordered by whether the machine has AES
     * acceleration, with the NoAES order alongside it (vendor/utls/defaults.go:97-111).
     * A ClientHello offering exactly one is a thing no Go client and no browser sends.
     *
     * And it cost about five times the speed. Re-measured on the target router 2026-09-19 with the
     * bench built at the flags the binary ships, 8 MB through each cipher: AES-128-GCM 443 ms per
     * megabyte, ChaCha20-Poly1305 91 ms. (This line said 1077 against 91 and "twelve times" — the
     * bench was measuring its own -O1 build of the one cipher it compiles; see the note at the
     * bench-aead rule. The ratio moved, the conclusion did not.) This CPU has no AES instructions,
     * which is precisely the case Go's NoAES order exists for — so sending ChaCha20 first is not a
     * deviation from the reference, it IS the reference.
     *
     * WHICH OF THE TWO ORDERS IS ASKED OF THE PROCESSOR, NOT OF THE ARCHITECTURE.
     *
     * This used to be `#if defined(__x86_64__) || defined(__aarch64__) || …` with a comment saying
     * it followed Go's test. It did not. Go's test is three CPU-feature checks and one architecture
     * check (vendor/utls/cipher_suites.go:360-368):
     *
     *   amd64  cpu.X86.HasAES && HasPCLMULQDQ && HasSSE41 && HasSSSE3
     *   arm64  cpu.ARM64.HasAES && HasPMULL
     *   s390x  HasAES && HasAESCTR && HasGHASH
     *   ppc64  the architecture alone, ppc64 or ppc64le
     *
     * so on an x86_64 without AES-NI — an old machine, a VM told to hide it, an emulator — a Go
     * client sends ChaCha20 first and this one sent AES first. On the target the two agreed, which
     * is why it went unnoticed: mipsel is "everywhere else" under either reading.
     *
     * Asked properly now, and only where it can be: __builtin_cpu_supports on x86, the auxiliary
     * vector on arm64, the architecture on ppc64 exactly as Go does. s390x is deliberately NOT in
     * the list — Go tests three features there and this has no way to ask for them, so claiming
     * hardware AES would be a guess, and the conservative answer is the one that matches a machine
     * without it.
     *
     * Not LC_QTLS_SUITE. That names the Initial-packet algorithm RFC 9001 fixes, which is a
     * different decision that happens to share a number; a commit about the mini-app's help text
     * once replaced this whole block with it, and nothing on any gate noticed for a day. */
    lc_buf_u16(&b, 6);
    if (lc_qtls_aesgcm_hardware()) {
        lc_buf_u16(&b, 0x1301u); /* TLS_AES_128_GCM_SHA256 */
        lc_buf_u16(&b, 0x1302u); /* TLS_AES_256_GCM_SHA384 */
        lc_buf_u16(&b, 0x1303u); /* TLS_CHACHA20_POLY1305_SHA256 */
    } else {
        lc_buf_u16(&b, 0x1303u);
        lc_buf_u16(&b, 0x1301u);
        lc_buf_u16(&b, 0x1302u);
    }

    lc_buf_u8(&b, 1);
    lc_buf_u8(&b, 0); /* no compression */

    size_t exts_at = b.len;
    lc_buf_u16(&b, 0);
    size_t exts_start = b.len;

    if (sni_len > 0u) {
        size_t at = ext_begin(&b, EXT_SERVER_NAME);
        lc_buf_u16(&b, (uint16_t)(sni_len + 3u));
        lc_buf_u8(&b, 0);
        lc_buf_u16(&b, (uint16_t)sni_len);
        lc_buf_write(&b, (const uint8_t *)sni, sni_len);
        ext_end(&b, at);
    }

    /* SIX EXTENSIONS THAT WERE NOT HERE, AND THE ORDER OF EVERYTHING.
     *
     * This hello is built by hand, and what it was built to carry was what the handshake NEEDS. Go's
     * crypto/tls — which is what quic-go hands the QUIC handshake to, and therefore what every
     * hysteria client sends — carries what a Go client always carries, need or no need:
     * makeClientHello sets extendedMasterSecret, ocspStapling, scts, supportedPoints and
     * secureRenegotiationSupported unconditionally (vendor/utls/handshake_client.go:75-88),
     * ticketSupported likewise (:376), and pskModes for any client offering TLS 1.3 (:378-382).
     * clientHelloMsg.marshal writes each of them with no test on the version and no test on QUIC
     * (vendor/utls/handshake_messages.go:119-297) — four of the six are TLS 1.2 machinery that a 1.3-only QUIC
     * handshake cannot use, and they go out anyway.
     *
     * So a hello with seven extensions where the reference has THIRTEEN is not a smaller hello, it
     * is a different client. And this one is in the clear to anybody on the path: the keys that
     * protect an Initial are derived from a connection id sent unencrypted, so the ClientHello
     * inside it is readable by anyone who cares to, without a secret of any kind.
     *
     * ⚠️ THIRTEEN IS MEASURED, NOT COUNTED FROM THE SOURCE, and the two numbers that stood here
     * before — "fourteen" here and "twelve" below — were both wrong. tools/vendorcap/qstand is a
     * QUIC server built from the reference library; it prints chi.Extensions, the identifiers in
     * the order they arrived. Pointed at hysteria's own client (2026-09-01) it recorded
     *
     *     extensions=[0 11 65281 23 18 57 5 10 13 50 16 43 51]
     *
     * — server_name, ec_point_formats, renegotiation_info, extended_master_secret,
     * signed_certificate_timestamp, quic_transport_parameters, status_request, supported_groups,
     * signature_algorithms, signature_algorithms_cert, alpn, supported_versions, key_share.
     * session_ticket (35) and psk_key_exchange_modes (45) are absent, which is the early return
     * described further down; signature_algorithms_cert (50) IS present, which counting by hand
     * from utls would have got wrong, because the QUIC handshake goes through Go's crypto/tls and
     * not through the uTLS parrot path.
     *
     * The same run pointed OUR client at the same server and got the same thirteen identifiers in
     * the same order, with the same seven signature schemes, the same three ciphers, the same five
     * curves and the same ALPN. On this plane the hello matches.
     *
     * The ORDER below is Go's, taken from the sequence of `if` blocks in marshal rather than from
     * the extension numbers, which it does not follow. quic_transport_parameters sits eighth, ahead
     * of status_request — it used to be last here, which is where it would naturally go and is not
     * where the reference puts it. */
    {
        /* uncompressed, and nothing else: `supportedPoints: []uint8{pointFormatUncompressed}`. */
        size_t at = ext_begin(&b, EXT_EC_POINT_FORMATS);
        lc_buf_u8(&b, 1);
        lc_buf_u8(&b, 0);
        ext_end(&b, at);
    }
    /* NO session_ticket HERE, AND NO psk_key_exchange_modes AT THE END. Both were written, with a
     * comment claiming Go sets ticketSupported before the version is known and never clears it.
     * That is not where Go sets it. Both fields are assigned INSIDE loadSession, and loadSession
     * returns before either assignment when there is no cache to load from:
     *
     *   if c.config.SessionTicketsDisabled || c.config.ClientSessionCache == nil {
     *       return nil, nil, nil, nil
     *   }
     *   ...
     *   hello.ticketSupported = true && !echInner            (vendor/utls/handshake_client.go:368-376)
     *   if hello.supportedVersions[0] == VersionTLS13 {
     *       hello.pskModes = []uint8{pskModeDHE}             (:378-382)
     *
     * hysteria builds its tls.Config out of five fields and a cache is not among them
     * (vendor/hysteria/core/client/client.go:72-82); quic-go clones that config and adds only
     * MinVersion, and nothing in the library ever installs a cache of its own — the single
     * ClientSessionCache in the whole of vendor/quic-go is in interop/client, a test tool. So the
     * early return is the path EVERY hysteria client takes, and neither extension is ever written.
     *
     * The cost of having them was fifteen extensions against the reference's THIRTEEN, ten extra
     * bytes, and two identifiers no client of this stack emits — inside the ClientHello, inside an
     * Initial whose keys come from a connection id sent in the clear. psk_key_exchange_modes was
     * also LAST, so its absence moves the end of the extension block back to key_share, which is
     * where a real hysteria hello ends.
     *
     * This is the QUIC hello only. The REALITY hello is built from a uTLS fingerprint table in
     * src/fp/, where Firefox does send session_ticket, and it is right to send it there. */
    {
        /* One byte of length, zero: an empty renegotiated_connection. */
        size_t at = ext_begin(&b, EXT_RENEGOTIATION_INFO);
        lc_buf_u8(&b, 0);
        ext_end(&b, at);
    }
    {
        size_t at = ext_begin(&b, EXT_EXTENDED_MASTER_SECRET);
        ext_end(&b, at);
    }
    {
        size_t at = ext_begin(&b, EXT_SCT);
        ext_end(&b, at);
    }
    {
        /* QUIC's own parameters, EIGHTH — see the note above about where the reference puts them.
         * The body is produced by the transport and passed through with one entry removed; the long
         * reason is at write_params_without_datagram_size. */
        size_t at = ext_begin(&b, EXT_QUIC_TRANSPORT_PARAMS);
        if (write_params_without_datagram_size(&b, params, params_len) != 0)
            return -1;
        ext_end(&b, at);
    }
    {
        /* status_type = ocsp, then two empty lists — responder_id_list and request_extensions. */
        size_t at = ext_begin(&b, EXT_STATUS_REQUEST);
        lc_buf_u8(&b, 1);
        lc_buf_u16(&b, 0);
        lc_buf_u16(&b, 0);
        ext_end(&b, at);
    }
    {
        /* All seven, in the reference's order. quic-go takes Go's own list — hysteria sets no
         * CurvePreferences of its own — and Go 1.26, which hysteria 2.12 is built with
         * (`go-version: "1.26"`, and `go 1.26.0` in vendor/hysteria/app/go.mod:3, which leaves
         * GODEBUG tlssecpmlkem at its new default), returns
         *
         *     X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024,
         *     X25519, CurveP256, CurveP384, CurveP521,
         *                        (GOROOT/src/crypto/tls/defaults.go:21-35, go1.26.6)
         *
         * Go 1.25 had five, without the two P-curve hybrids, and so did this list until 2026-09-26.
         * Only the first two are key-shared; any of the other five is one a server may ask for in a
         * retry, and the two hybrids among them are answered as Go answers them — see the retry
         * below. */
        static const uint16_t groups[] = { LC_GROUP_X25519MLKEM768, LC_GROUP_SECP256R1MLKEM768,
                                           LC_GROUP_SECP384R1MLKEM1024, LC_GROUP_X25519,
                                           LC_GROUP_SECP256R1, LC_GROUP_SECP384R1,
                                           LC_GROUP_SECP521R1 };
        size_t at = ext_begin(&b, EXT_SUPPORTED_GROUPS);
        lc_buf_u16(&b, (uint16_t)(sizeof groups / sizeof groups[0] * 2u));
        for (size_t i = 0; i < sizeof groups / sizeof groups[0]; i++)
            lc_buf_u16(&b, groups[i]);
        ext_end(&b, at);
    }
    {
        size_t at = ext_begin(&b, EXT_SIGNATURE_ALGORITHMS);
        /* SEVEN, which is what a Go client sends OVER QUIC — not the twelve of the general default.
         *
         * The twelve stood here, taken from defaultSupportedSignatureAlgorithms
         * (vendor/utls-hy/defaults.go:33-46), replacing an earlier list of nine that had an order of
         * its own. That was the right correction and the wrong list, and the reason is a filter
         * neither uTLS nor this file had: Go does not send its default set as it stands. It sends
         *
         *     sigAlgs := defaultSupportedSignatureAlgorithms()
         *     return slices.DeleteFunc(sigAlgs, func(s SignatureScheme) bool {
         *         return isDisabledSignatureAlgorithm(minVers, s, false)
         *     })
         *
         * (Go's own crypto/tls/common.go:1753-1759), and for a connection whose minimum version is
         * TLS 1.3 that deletes every PKCS#1 v1.5 scheme and both SHA-1 ones — they are not legal in
         * a TLS 1.3 CertificateVerify at all. QUIC has no minimum below 1.3, so on this path the
         * deletion ALWAYS happens. uTLS keeps the undeleted list because its callers are browser
         * fingerprints that really do offer TLS 1.2; copying it into a QUIC hello was copying the
         * right constant out of the wrong context.
         *
         * MEASURED, not deduced. A server built from vendor/quic-go with GetConfigForClient printing
         * the parsed hello, 2026-08-25: the reference hysteria client offered exactly
         *
         *     PSSWithSHA256 ECDSAWithP256AndSHA256 Ed25519 PSSWithSHA384 PSSWithSHA512
         *     ECDSAWithP384AndSHA384 ECDSAWithP521AndSHA512
         *
         * and this client offered those seven with PKCS1WithSHA256/384/512, PKCS1WithSHA1 and
         * ECDSAWithSHA1 spliced in. Everything else in the hello already agreed to the value — SNI,
         * ALPN, version, the three cipher suites, the five curves, the point format — so this list
         * was the whole of the difference between the two on the wire, and signature_algorithms is
         * one of the fields JA3 and JA4 hash.
         *
         * ⚠️ AND THE FIVE ARE NOT SIMPLY DROPPED — THEY MOVE, which is the half of this that a
         * narrower reading would have got wrong and made worse. Go sends TWO extensions:
         *
         *     hello.supportedSignatureAlgorithms     = supportedSignatureAlgorithms(minVersion)
         *     hello.supportedSignatureAlgorithmsCert = supportedSignatureAlgorithmsCert()
         *
         * (crypto/tls/handshake_client.go:121-124), and the second is NOT filtered at all:
         * `isDisabledSignatureAlgorithm` returns false immediately when isCert is set, with the
         * reason written beside it — "we include all algorithms, including SHA-1 and PKCS#1 v1.5,
         * because it's more likely that something on our side will be willing to accept a
         * *-with-SHA1 certificate than that the peer would have a better certificate but is just
         * choosing not to send it". Deleting the five from here without adding them there would
         * have told servers we cannot accept a PKCS#1-signed CHAIN, which is most chains that
         * exist. See the block below. */
        static const uint16_t sigs[] = { 0x0804u, 0x0403u, 0x0807u, 0x0805u, 0x0806u,
                                         0x0503u, 0x0603u };
        lc_buf_u16(&b, (uint16_t)(sizeof sigs / sizeof sigs[0] * 2u));
        for (size_t i = 0; i < sizeof sigs / sizeof sigs[0]; i++)
            lc_buf_u16(&b, sigs[i]);
        ext_end(&b, at);
    }
    {
        /* signature_algorithms_cert: what may have signed the CERTIFICATES, as opposed to the
         * handshake. The full default list, unfiltered, exactly as Go builds it — see the block
         * above for the source and the quoted reason.
         *
         * It goes immediately after signature_algorithms because that is where Go puts it:
         * `if len(m.supportedSignatureAlgorithms) > 0` (vendor/utls/handshake_messages.go:215) and
         * then, as the very next statement, `if len(m.supportedSignatureAlgorithmsCert) > 0`
         * (vendor/utls/handshake_messages.go:230). Position is not decoration in a hello. */
        size_t at = ext_begin(&b, EXT_SIGNATURE_ALGORITHMS_CERT);
        static const uint16_t sigs_cert[] = { 0x0804u, 0x0403u, 0x0807u, 0x0805u, 0x0806u, 0x0401u,
                                              0x0501u, 0x0601u, 0x0503u, 0x0603u, 0x0201u, 0x0203u };
        lc_buf_u16(&b, (uint16_t)(sizeof sigs_cert / sizeof sigs_cert[0] * 2u));
        for (size_t i = 0; i < sizeof sigs_cert / sizeof sigs_cert[0]; i++)
            lc_buf_u16(&b, sigs_cert[i]);
        ext_end(&b, at);
    }
    {
        size_t at = ext_begin(&b, EXT_ALPN);
        lc_buf_u16(&b, (uint16_t)(strlen(alpn_h3) + 1u));
        lc_buf_u8(&b, (uint8_t)strlen(alpn_h3));
        lc_buf_write(&b, (const uint8_t *)alpn_h3, strlen(alpn_h3));
        ext_end(&b, at);
    }
    {
        size_t at = ext_begin(&b, EXT_SUPPORTED_VERSIONS);
        lc_buf_u8(&b, 2);
        lc_buf_u16(&b, 0x0304u);
        ext_end(&b, at);
    }
    {
        /* Two shares, hybrid first and bare X25519 as the fallback, sharing one ephemeral —
         * vendor/utls/handshake_client.go:181-189. */
        size_t at = ext_begin(&b, EXT_KEY_SHARE);
        lc_buf_u16(&b, (uint16_t)(LC_HYBRID_SHARE + 4u + LC_X25519_KEY + 4u));
        lc_buf_u16(&b, LC_GROUP_X25519MLKEM768);
        lc_buf_u16(&b, LC_HYBRID_SHARE);
        lc_buf_write(&b, share, LC_HYBRID_SHARE);
        lc_buf_u16(&b, LC_GROUP_X25519);
        lc_buf_u16(&b, LC_X25519_KEY);
        lc_buf_write(&b, pub, LC_X25519_KEY);
        ext_end(&b, at);
    }
    /* key_share is the last extension, as it is for the reference. psk_key_exchange_modes used to
     * close the run here; the reason it does not is with session_ticket, above. */

    /* And the note that belongs with the transport parameters written above, kept whole because it
     * is the reason one entry is missing from them.
     *
     * THE ONE REMOVED IS max_datagram_frame_size, because the reference client does not send it.
         * hysteria asks quic-go for `MaxDatagramFrameSize: 1200` and `OmitMaxDatagramFrameSize:
         * true` in the same breath (vendor/hysteria/core/client/client.go:92-93): it knows the
         * limit and stays silent about it. Its server closes the loop from the other side with
         * `AssumePeerMaxDatagramFrameSize: protocol.MaxDatagramFrameSize`
         * (vendor/hysteria/core/server/server.go:64) — it simply assumes the client can take them.
         *
         * These parameters are readable on the wire. They travel in a TLS extension inside the
         * Initial packet, whose keys are derived from the connection id and therefore available to
         * anybody watching. So the set of parameters is part of the fingerprint exactly as the list
         * of cipher suites is — and this client was announcing one that no real Hysteria2 client
         * announces, on a port where Hysteria2 is what lives.
         *
         * Cut here rather than at the source because ngtcp2 uses the same field for two jobs: what
         * to advertise, and what to ACCEPT. Setting it to zero would omit the parameter and also
         * make ngtcp2 answer the first relayed datagram with NGTCP2_ERR_PROTO: the DATAGRAM cases
         * compare the frame against `conn->local.transport_params.max_datagram_frame_size` and
         * refuse anything larger (vendor/ngtcp2/lib/ngtcp2_conn.c:9762-9767) — the connection would
         * die the moment anybody looked up a name. Removing it from the encoded blob leaves the
         * enforcement intact and changes only what goes out. */

    {
        size_t n = b.len - exts_start;
        if (!b.err) {
            out[exts_at] = (uint8_t)(n >> 8);
            out[exts_at + 1u] = (uint8_t)n;
        }
    }
    {
        size_t n = b.len - body_at;
        if (!b.err) {
            out[len_at] = (uint8_t)(n >> 16);
            out[len_at + 1u] = (uint8_t)(n >> 8);
            out[len_at + 2u] = (uint8_t)n;
        }
    }
    if (b.err)
        return -1;

    *out_len = b.len;
    return 0;
}

/* THE HELLO WHILE PARROTING CHROME, which is uTLS's and not crypto/tls's, and not this file's either.
 *
 * The fork hands its own spec, chromeQUICClientHelloSpec, to a uTLS QUIC connection
 * (vendor/quic-go/internal/handshake/tls_conn_utls.go:33-45): eleven extensions permuted per
 * connection, three suites in a FIXED order, four groups with two shares, ALPS at the new code
 * point, brotli certificate compression, psk_dhe_ke, GREASE ECH, and no GREASE anywhere else. That
 * is a table — tools/fp renders it through the same uTLS calls and packs it into chrome_hello.h, and
 * check-fingerprint holds both the copy of the spec and the table to the fork — built by the same
 * code as the REALITY hello, src/fp/hello.c, whose shuffle and GREASE ECH are uTLS's already. What
 * the table cannot carry is the transport parameters, which go in as write_params_chrome encodes
 * them, and the two public keys, which are filled below.
 *
 * ⚠️ THE SUITES DO NOT FOLLOW THE HARDWARE HERE. The paragraph in build_hello about Go ordering by AES
 * acceleration is crypto/tls's rule; the spec lists AES-128, AES-256, ChaCha20 and uTLS sends the
 * list as written. A server that has AES acceleration then picks AES-128-GCM because the client
 * put it first — on a router without AES instructions exactly as the reference does on one. */

static int build_hello_chrome(lc_qtls *q, const char *sni, const uint8_t *params,
                              size_t params_len, uint8_t *out, size_t out_cap, size_t *out_len)
{
    uint8_t tp[512];
    lc_buf  b;
    lc_buf_init(&b, tp, sizeof tp);
    if (write_params_chrome(&b, params, params_len) != 0)
        return -1;

    lc_hello_out info;
    if (lc_hello_build_quic(lc_chrome_hello_fpt, sizeof lc_chrome_hello_fpt, sni, tp, b.len, out,
                            out_cap, &info) != LC_HELLO_OK)
        return -1;

    /* Two shares, two keys: the hybrid's classical half and the bare X25519 entry are generated
     * separately, as ApplyPreset generates them (vendor/utls-hy/u_parrots.go:2875-2922). */
    for (unsigned i = 0; i < info.slot_count; i++) {
        uint8_t *key = out + info.slots[i].off;
        if (info.slots[i].group == LC_GROUP_X25519MLKEM768 &&
            info.slots[i].len == LC_HYBRID_SHARE) {
            if (lc_hybrid_keygen(&q->hybrid, key) != 0)
                return -1;
        } else if (info.slots[i].group == LC_GROUP_X25519 && info.slots[i].len == LC_X25519_KEY) {
            if (lc_x25519_keygen(q->x25519_priv, key) != 0)
                return -1;
        } else {
            return -1;
        }
    }
    q->hello_info = info;
    *out_len = info.len;
    return 0;
}

int lc_qtls_start(lc_qtls *q, const lc_qtls_sink *sink, const char *sni,
                  const uint8_t *params, size_t params_len, const uint8_t *pin, unsigned flags)
{
    memset(q, 0, sizeof *q);
    q->chrome = (flags & LC_QTLS_CHROME) != 0u;
    q->partial = q->partial_inline;
    q->partial_cap = sizeof q->partial_inline;
    q->sink = *sink;
    /* A placeholder until the server chooses. Three suites are offered now, so what this holds
     * before the ServerHello is only what the initial keys use — and those are fixed by RFC 9001 to
     * AES-128-GCM regardless of what the handshake later agrees. The real suite arrives below, and
     * everything derived from it is derived AFTER that.
     *
     * The hash comes from the suite table rather than being asserted beside it. It was written as
     * a bare LC_SHA256 one line below the suite — the silent kind of duplicate: change the suite to
     * 0x1302 and q->suite reaches ngtcp2 correctly as SHA-384 while this stays SHA-256, so the key
     * schedule derives 32-byte secrets that QUIC then expands as 48-byte ones. No compile error, no
     * assertion; nothing decrypts. */
    q->suite = LC_QTLS_SUITE;
    if (lc_tls_suite_params(q->suite, NULL, &q->hash, NULL) != 0)
        return -1;
    if (pin != NULL) {
        memcpy(q->pin, pin, LC_QTLS_PIN);
        q->have_pin = 1;
    }

    static uint8_t hello[4096];
    size_t         hello_len = 0;
    if ((q->chrome ? build_hello_chrome(q, sni, params, params_len, hello, sizeof hello, &hello_len)
                   : build_hello(q, sni, params, params_len, hello, sizeof hello, &hello_len)) != 0)
        return -1;

    /* Kept rather than hashed. See lc_qtls.ch: the transcript cannot start until the ServerHello
     * says which hash it is to be, and the ClientHello is the only message before that. */
    if (hello_len > sizeof q->ch)
        return -1;
    memcpy(q->ch, hello, hello_len);
    q->ch_len = hello_len;

    return q->sink.send(q->sink.ctx, LC_QTLS_INITIAL, hello, hello_len);
}

/* THE SECOND HELLO, AS THE REFERENCE MAKES IT: the first one again, with the cookie echoed and,
 * when the retry named a group, the key share replaced by a single share for it
 * (GOROOT/src/crypto/tls/handshake_client_tls13.go:303-351, go1.25.14). Go mutates its one hello
 * object and marshals it a second time, so everything else — the random, every list, the transport
 * parameters — is the first hello's, byte for byte. Its marshal writes the cookie between
 * supported_versions and key_share (GOROOT/src/crypto/tls/handshake_messages.go:267-281), and in
 * this hello that is directly ahead of key_share, which build_hello writes last. So this is a
 * splice at the one place that changes rather than a second builder to keep in step with the
 * first. `share` NULL keeps the first hello's key shares, which is what a retry asking only for a
 * cookie gets. */
static int build_retry_hello(lc_qtls *q, const uint8_t *cookie, size_t cookie_len, uint16_t group,
                             const uint8_t *share, size_t share_len)
{
    const uint8_t *h1 = q->ch;
    size_t         len1 = q->ch_len;

    size_t off = 4u + 2u + 32u; /* header, legacy_version, random */
    if (off + 1u > len1)
        return -1;
    off += 1u + h1[off]; /* legacy_session_id */
    if (off + 2u > len1)
        return -1;
    off += 2u + ((size_t)h1[off] << 8 | h1[off + 1u]); /* cipher_suites */
    if (off + 1u > len1)
        return -1;
    off += 1u + h1[off]; /* legacy_compression_methods */
    size_t exts_at = off;
    off += 2u;
    size_t ks_at = 0;
    while (off + 4u <= len1) {
        unsigned type = (unsigned)h1[off] << 8 | h1[off + 1u];
        size_t   elen = (size_t)h1[off + 2u] << 8 | h1[off + 3u];
        if (off + 4u + elen > len1)
            return -1;
        if (type == EXT_KEY_SHARE) {
            ks_at = off;
            break;
        }
        off += 4u + elen;
    }
    size_t ks_len = ks_at != 0u ? 4u + ((size_t)h1[ks_at + 2u] << 8 | h1[ks_at + 3u]) : 0u;
    if (ks_at == 0u || ks_at + ks_len != len1)
        return -1; /* not the hello build_hello writes, which ends with key_share */

    size_t len2 = ks_at + (cookie != NULL ? 6u + cookie_len : 0u) +
                  (share != NULL ? 10u + share_len : ks_len);
    /* A cookie can push the extensions past what their two-byte length holds. Go's marshal fails
     * then, and the handshake ends on that error with no alert of its own (-2 for the caller). */
    if (len2 - exts_at - 2u > 0xffffu)
        return -2;
    uint8_t *h2 = malloc(len2);
    if (h2 == NULL)
        return -1;
    memcpy(h2, h1, ks_at);
    size_t w = ks_at;
    if (cookie != NULL) {
        h2[w++] = (uint8_t)(EXT_COOKIE >> 8);
        h2[w++] = (uint8_t)EXT_COOKIE;
        h2[w++] = (uint8_t)((cookie_len + 2u) >> 8);
        h2[w++] = (uint8_t)(cookie_len + 2u);
        h2[w++] = (uint8_t)(cookie_len >> 8);
        h2[w++] = (uint8_t)cookie_len;
        memcpy(h2 + w, cookie, cookie_len);
        w += cookie_len;
    }
    if (share != NULL) {
        h2[w++] = (uint8_t)(EXT_KEY_SHARE >> 8);
        h2[w++] = (uint8_t)EXT_KEY_SHARE;
        h2[w++] = (uint8_t)((share_len + 6u) >> 8);
        h2[w++] = (uint8_t)(share_len + 6u);
        h2[w++] = (uint8_t)((share_len + 4u) >> 8);
        h2[w++] = (uint8_t)(share_len + 4u);
        h2[w++] = (uint8_t)(group >> 8);
        h2[w++] = (uint8_t)group;
        h2[w++] = (uint8_t)(share_len >> 8);
        h2[w++] = (uint8_t)share_len;
        memcpy(h2 + w, share, share_len);
    } else {
        memcpy(h2 + w, h1 + ks_at, ks_len);
    }

    size_t exts = len2 - exts_at - 2u, body = len2 - 4u;
    h2[exts_at] = (uint8_t)(exts >> 8);
    h2[exts_at + 1u] = (uint8_t)exts;
    h2[1] = (uint8_t)(body >> 16);
    h2[2] = (uint8_t)(body >> 8);
    h2[3] = (uint8_t)body;

    free(q->ch_heap);
    q->ch_heap = h2;
    q->ch_len = len2;
    return 0;
}

/* THE SECOND HELLO UNDER THE PARROT, which is uTLS's and not the one above. uTLS does not re-marshal
 * a crypto/tls hello: it replaces the shares in its KeyShareExtension, puts a CookieExtension at an
 * index drawn over all but the last two of its extensions, and marshals its own list again
 * (vendor/utls/handshake_client_tls13.go:381-428) — the permuted order, the random and every other
 * extension carried over. The REALITY hello answers a retry the same way, with the same two
 * splices, now in fp/hello.c. A cookie that takes the extension block past sixteen bits fails the
 * marshal with no alert of its own, as it does above. */
static int build_retry_hello_chrome(lc_qtls *q, const uint8_t *cookie, size_t cookie_len,
                                   uint16_t group, const uint8_t *share, size_t share_len)
{
    size_t cap = q->ch_len + (cookie != NULL ? 6u + cookie_len : 0u) + 10u + share_len;
    if (cap - 4u > 0xffffffu)
        return -2;
    uint8_t *h = malloc(cap);
    if (h == NULL)
        return -1;
    memcpy(h, hello_bytes(q), q->ch_len);
    lc_hello_out info = q->hello_info;
    info.len = q->ch_len;
    if (cookie != NULL) {
        int rc = lc_hello_splice_cookie(h, cap, &info, cookie, cookie_len);
        if (rc != 0) {
            free(h);
            return rc == -2 ? -2 : -1;
        }
    }
    if (share != NULL) {
        if (lc_hello_splice_key_share(h, cap, &info, group, share_len) != 0) {
            free(h);
            return -1;
        }
        memcpy(h + info.slots[0].off, share, share_len);
    }
    free(q->ch_heap);
    q->ch_heap = h;
    q->ch_len = info.len;
    q->hello_info = info;
    return 0;
}

/* Derives the handshake secrets once the ServerHello is in the transcript, and hands both to QUIC.
 * The order matters only in that both must be installed before any handshake packet is processed. */
static int install_handshake_keys(lc_qtls *q, uint16_t group, const uint8_t *peer_share)
{
    size_t  hlen = lc_hash_len(q->hash);
    /* Sized for the hybrid, used for whichever the server picked. Two shares went out, so two
     * answers are legitimate and the schedule takes a different number of bytes for each: 64 for
     * X25519MLKEM768 (ML-KEM secret || X25519 secret) and 32 for bare X25519. */
    uint8_t shared[LC_KEX_SHARED_MAX];
    size_t  shared_len;
    /* A share that yields no secret — X25519 with a low-order point comes out all zeroes and is
     * refused — is illegal_parameter, "invalid server key share", as the reference answers it
     * (GOROOT/src/crypto/tls/handshake_client_tls13.go:486-504, go1.25.14). It was a bare -1, and
     * this is on the first flight, where anyone who can see the connection ID can forge it. */
    if (group == LC_GROUP_X25519MLKEM768) {
        if (lc_hybrid_shared(&q->hybrid, peer_share, shared) != 0) {
            go_says(q, LC_GO("tls: invalid server key share"));
            return fail(q, LC_ALERT_ILLEGAL_PARAMETER, "the node's X25519MLKEM768 share is invalid");
        }
        shared_len = LC_HYBRID_SECRET;
    } else if (group == LC_GROUP_X25519) {
        /* The key the X25519 share was made with: its own under the parrot, the hybrid's classical
         * half otherwise — see x25519_priv in qtls.h. */
        if (lc_x25519(q->chrome ? q->x25519_priv : q->hybrid.x25519_priv, peer_share, shared) != 0) {
            go_says(q, LC_GO("tls: invalid server key share"));
            return fail(q, LC_ALERT_ILLEGAL_PARAMETER, "the node's X25519 share is invalid");
        }
        shared_len = LC_X25519_SHARED;
    } else if (group == LC_GROUP_SECP256R1MLKEM768 || group == LC_GROUP_SECP384R1MLKEM1024) {
        /* A hybrid only a retry reaches, keyed there: the ECDH secret and then the ML-KEM one, in
         * that order for these two (GOROOT/src/crypto/tls/key_schedule.go:240-273, go1.26.6). An
         * ECDH point off the curve is "invalid server key share", illegal_parameter; ML-KEM
         * rejects implicitly and never fails here. */
        int    p256 = group == LC_GROUP_SECP256R1MLKEM768;
        size_t elen = p256 ? LC_P256_SHARED : LC_P384_SHARED;
        int    bad = p256 ? lc_p256_shared(q->retry_priv, peer_share, shared)
                          : lc_p384_shared(q->retry_priv, peer_share, shared);
        if (bad == 0)
            bad = p256 ? lc_mlkem_decap(peer_share + LC_P256_POINT, q->retry_dk, shared + elen)
                       : lc_mlkem1024_decap(peer_share + LC_P384_POINT, q->retry_dk, shared + elen);
        lc_wipe(q->retry_priv, sizeof q->retry_priv);
        lc_wipe(q->retry_dk, sizeof q->retry_dk);
        if (bad != 0) {
            go_says(q, LC_GO("tls: invalid server key share"));
            return fail(q, LC_ALERT_ILLEGAL_PARAMETER, "the node's share for group 0x%04x is invalid",
                        group);
        }
        shared_len = elen + LC_MLKEM_SS;
    } else {
        /* One of the NIST curves, which only a retry reaches: the key was made for it there. A
         * point that is not on the curve is the same illegal_parameter (:486-504). */
        int bad = group == LC_GROUP_SECP256R1   ? lc_p256_shared(q->retry_priv, peer_share, shared)
                  : group == LC_GROUP_SECP384R1 ? lc_p384_shared(q->retry_priv, peer_share, shared)
                                                : lc_p521_shared(q->retry_priv, peer_share, shared);
        lc_wipe(q->retry_priv, sizeof q->retry_priv);
        if (bad != 0) {
            go_says(q, LC_GO("tls: invalid server key share"));
            return fail(q, LC_ALERT_ILLEGAL_PARAMETER, "the node's share for group 0x%04x is invalid",
                        group);
        }
        shared_len = group == LC_GROUP_SECP256R1   ? LC_P256_SHARED
                     : group == LC_GROUP_SECP384R1 ? LC_P384_SHARED
                                                   : LC_P521_SHARED;
    }

    uint8_t zeros[LC_HASH_MAX], early[LC_HASH_MAX], derived[LC_HASH_MAX], empty[LC_HASH_MAX];
    memset(zeros, 0, hlen);
    int failed = lc_hash_digest(q->hash, NULL, 0, empty) != 0 ||
                 lc_hkdf_extract(q->hash, NULL, 0, zeros, hlen, early) != 0 ||
                 lc_derive_secret(q->hash, early, "derived", empty, derived) != 0 ||
                 lc_hkdf_extract(q->hash, derived, hlen, shared, shared_len, q->hs_secret) != 0;
    /* Both intermediates are wiped, not just the ECDH output: `derived` combined with the shared
     * secret reproduces the handshake secret outright, and `early` reproduces `derived`. The
     * failure path wipes them too, because a schedule that broke at its last step still left every
     * earlier one sitting in this frame. */
    lc_wipe(shared, sizeof shared);
    lc_wipe(early, hlen);
    lc_wipe(derived, hlen);
    if (failed)
        return own_fail(q, "cannot derive the handshake keys");

    uint8_t th[LC_HASH_MAX];
    if (lc_transcript_snapshot(&q->tr, th) != 0 ||
        lc_derive_secret(q->hash, q->hs_secret, "c hs traffic", th, q->c_hs) != 0 ||
        lc_derive_secret(q->hash, q->hs_secret, "s hs traffic", th, q->s_hs) != 0)
        return own_fail(q, "cannot derive the handshake keys");

    if (q->sink.rx_secret(q->sink.ctx, LC_QTLS_HANDSHAKE, q->s_hs, hlen) != 0 ||
        q->sink.tx_secret(q->sink.ctx, LC_QTLS_HANDSHAKE, q->c_hs, hlen) != 0)
        return own_fail(q, "cannot derive the handshake keys");
    return 0;
}

/* CertificateVerify, through the one implementation both planes share — src/tls/certverify.c.
 * The reasoning that used to live here moved with the code; what stays is the plane-specific half:
 * on this plane the pin says WHICH key the node must hold and only this message proves it HAS it,
 * so a refusal here ends the handshake and is named rather than folded into a generic failure. */
static int check_cert_verify(lc_qtls *q, const uint8_t *body, size_t body_len,
                             const uint8_t *transcript_hash)
{
    if (!q->cert_seen || q->cert_der_len == 0u)
        return fail(q, LC_ALERT_UNEXPECTED_MESSAGE,
                    "the node sent no certificate to check a signature against");

    char    why[192], go[256];
    uint8_t alert = LC_ALERT_DECRYPT_ERROR;
    /* stdlib's rules, or uTLS's under the parrot: see `stdlib` in tls/certverify.h. */
    if (lc_cert_verify(q->cert_der, q->cert_der_len, q->hash, transcript_hash, body, body_len,
                       !q->chrome, 0,
                       why, sizeof why, &alert, go, sizeof go) != 0) {
        if (go[0] != '\0')
            go_says(q, "%s", go);
        return fail(q, alert, "%s", why);
    }

    q->cert_verified = 1;
    return 0;
}

/* SHA-256 of the leaf against the pin, and nothing else — the comparison half of check_pin, which
 * the reference makes at the Certificate itself. Constant time, as everywhere else a
 * secret-derived value is compared here: a comparison that stops at the first wrong byte tells
 * whoever is probing how much of a guess was right. */
static int pin_matches(const lc_qtls *q)
{
    uint8_t got[LC_HASH_MAX];
    if (q->cert_der_len == 0u || lc_hash_digest(LC_SHA256, q->cert_der, q->cert_der_len, got) != 0)
        return 0;
    uint8_t diff = 0;
    for (size_t i = 0; i < LC_QTLS_PIN; i++)
        diff = (uint8_t)(diff | (got[i] ^ q->pin[i]));
    return diff == 0;
}

/* The node against its pin: SHA-256 over the leaf certificate exactly as it arrived on the wire,
 * compared with the value configured out of band. Returns 0 when they match.
 *
 * The digest is over the DER of the whole certificate rather than over its public key, because that
 * is what Hysteria2's pinSHA256 means and what `openssl x509 -outform der | sha256sum` prints — a
 * pin an operator cannot produce with one command is a pin nobody sets.
 *
 * A flight with no Certificate in it fails too. Otherwise a peer could simply omit the message and
 * be treated as unpinned, which is the whole check handed back to the party it is aimed at. */
static int check_pin(lc_qtls *q)
{
    if (!q->cert_seen || q->cert_der_len == 0u)
        return fail(q, LC_ALERT_BAD_CERTIFICATE,
                    "the node sent no certificate, so the pin had nothing to compare");
    /* A pin over a certificate nobody proved they hold is a comparison of public bytes. The
     * signature is what makes the match mean something, so this is one check with two halves. */
    if (!q->cert_verified)
        return fail(q, LC_ALERT_DECRYPT_ERROR,
                    "the node did not prove it holds the key in its certificate");

    if (!pin_matches(q)) {
        go_says(q, LC_GO("no certificate matches the pinned hash"));
        return fail(q, LC_ALERT_BAD_CERTIFICATE,
                    "the node's certificate does not match the configured pin");
    }

    q->peer_pinned = 1;
    return 0;
}

/* Everything after the server's Finished: the master secret, the application keys, and our own
 * Finished, which goes out at the handshake level. */
static int finish(lc_qtls *q, const uint8_t *th_before_finished)
{
    size_t hlen = lc_hash_len(q->hash);

    /* The empty Certificate a CertificateRequest is owed — type 0x0b, an empty request context, an
     * empty list, the eight bytes Go marshals when getClientCertificate has nothing
     * (GOROOT/src/crypto/tls/handshake_client_tls13.go:759-795) — and it goes into the transcript
     * our Finished covers. The application secrets are taken from the transcript through the
     * SERVER's Finished, which is `th_before_finished`, and do not see it. */
    uint8_t th_client[LC_HASH_MAX];
    const uint8_t *th_for_vd = th_before_finished;
    /* Under the parrot a server's application settings are answered first: uTLS writes an
     * EncryptedExtensions of its own right after reading the server's Finished and before its
     * Certificate and Finished (serverFinishedReceived, vendor/utls/u_handshake_client.go:143-164,
     * called at vendor/utls/handshake_client_tls13.go:155-159), into the same transcript. What it
     * carries is lc_utls_alps_answer's, as on the TLS plane. */
    if (q->alps_answer_len != 0u) {
        if (q->sink.send(q->sink.ctx, LC_QTLS_HANDSHAKE, q->alps_answer, q->alps_answer_len) != 0 ||
            lc_transcript_add(&q->tr, q->alps_answer, q->alps_answer_len) != 0 ||
            lc_transcript_snapshot(&q->tr, th_client) != 0)
            return -1;
        th_for_vd = th_client;
    }
    if (q->cert_requested) {
        if (q->sink.send(q->sink.ctx, LC_QTLS_HANDSHAKE, lc_empty_certificate,
                         sizeof lc_empty_certificate) != 0 ||
            lc_transcript_add(&q->tr, lc_empty_certificate,
                              sizeof lc_empty_certificate) != 0 ||
            lc_transcript_snapshot(&q->tr, th_client) != 0)
            return -1;
        th_for_vd = th_client;
    }

    uint8_t vd[LC_HASH_MAX];
    if (lc_finished_verify_data(q->hash, q->c_hs, th_for_vd, vd) != 0)
        return -1;

    uint8_t msg[4 + LC_HASH_MAX];
    msg[0] = LC_HS_FINISHED;
    msg[1] = 0;
    msg[2] = 0;
    msg[3] = (uint8_t)hlen;
    memcpy(msg + 4, vd, hlen);

    uint8_t empty[LC_HASH_MAX], derived[LC_HASH_MAX], master[LC_HASH_MAX], zeros[LC_HASH_MAX];
    uint8_t c_ap[LC_HASH_MAX], s_ap[LC_HASH_MAX];
    int     rc = -1;
    memset(zeros, 0, hlen);
    if (lc_hash_digest(q->hash, NULL, 0, empty) != 0 ||
        lc_derive_secret(q->hash, q->hs_secret, "derived", empty, derived) != 0 ||
        lc_hkdf_extract(q->hash, derived, hlen, zeros, hlen, master) != 0)
        goto out;

    if (lc_derive_secret(q->hash, master, "c ap traffic", th_before_finished, c_ap) != 0 ||
        lc_derive_secret(q->hash, master, "s ap traffic", th_before_finished, s_ap) != 0)
        goto out;

    if (q->sink.rx_secret(q->sink.ctx, LC_QTLS_APPLICATION, s_ap, hlen) != 0 ||
        q->sink.tx_secret(q->sink.ctx, LC_QTLS_APPLICATION, c_ap, hlen) != 0)
        goto out;

    if (q->sink.send(q->sink.ctx, LC_QTLS_HANDSHAKE, msg, 4u + hlen) != 0)
        goto out;

    q->done = 1;
    rc = 0;

out:
    /* Every exit runs through here, the error ones included, where these are just as populated as
     * on success. The master secret and the two application traffic secrets are the connection
     * itself: the real data keys are expanded from them and they survive key updates, so a copy
     * left behind decrypts everything the session goes on to send — and the frame holding it is
     * reused immediately by the code that carries exactly that traffic. src/tls/client.c wipes the
     * same three at the same point. */
    lc_wipe(derived, hlen);
    lc_wipe(master, hlen);
    lc_wipe(c_ap, hlen);
    lc_wipe(s_ap, hlen);
    return rc;
}

/* Makes room for |n| more bytes in the reassembly window, growing it onto the heap when the inline
 * one cannot hold what is already there plus that much. The ceiling is the largest message the
 * reference reads plus its header; a claim above that is what the caller refuses (-1). -2 when the
 * memory could not be had, which is a failure of our own (see own_fail). */
static int qtls_reserve(lc_qtls *q, size_t n)
{
    if (n <= q->partial_cap - q->partial_len)
        return 0;

    size_t   want = q->partial_len + n;
    size_t   cap = LC_QTLS_MAX_CERTIFICATE + 4u;
    uint8_t *grown;

    if (want > cap)
        return -1;

    grown = malloc(cap);
    if (grown == NULL)
        return -2;

    memcpy(grown, q->partial, q->partial_len);
    if (q->partial != q->partial_inline) {
        lc_wipe(q->partial, q->partial_cap);
        free(q->partial);
    }
    q->partial = grown;
    q->partial_cap = cap;
    return 0;
}

/* The ceiling for a message of |type|: the reference reads a Certificate four times larger than
 * anything else — once the version is settled, which on this plane is once the ServerHello has been
 * taken (GOROOT/src/crypto/tls/conn.go:1104-1113, go1.25.14) — and after the handshake it reads
 * nothing larger than maxHandshake of any type (GOROOT/src/crypto/tls/quic.go:274-280). None of it
 * is reachable while CRYPTO data stops at sixteen kilobytes (patches/ngtcp2/0012); it is the second
 * line, as it is in the reference. */
static size_t qtls_msg_ceiling(const lc_qtls *q, uint8_t type)
{
    return type == LC_HS_CERTIFICATE && q->expect != LC_QX_SERVER_HELLO && !q->done
               ? LC_QTLS_MAX_CERTIFICATE
               : LC_QTLS_MAX_MESSAGE;
}

/* A Certificate message — as it came, or as a CompressedCertificate opened into it under the
 * parrot. Everything the reference asks of it, in the reference's order; 0 to go on, -1 with the
 * reason recorded. */
/* verifyServerCertificate's first loop, certificate by certificate in its order: each one parsed by
 * x509.ParseCertificate — cert/x509go.c, Go's parser of the toolchain hysteria is built with — and
 * only a parsed one weighed for the size of its RSA key (vendor/utls-hy/handshake_client.go:
 * 1125-1136, GOROOT/src/crypto/tls/handshake_client.go:1111-1123 in go1.26.6). Returns 0, or the
 * alert: bad_certificate for either under the parrot; without it the standard library answers a
 * certificate that does not parse with decode_error. The words are said for both, and heard only
 * under the parrot (tls/goerr.h). -1 when memory ran out. */
static int go_cert_parse(lc_qtls *q, const uint8_t *body, size_t body_len)
{
    size_t         off = 0, der_len = 0;
    const uint8_t *der = NULL;
    while (lc_cert_next_from_message(body, body_len, &off, &der, &der_len) == 0) {
        lc_obuf e = { 0 };
        size_t  bits = 0;
        if (lc_x509_go_parse(der, der_len, &bits, &e) != 0) {
            int oom = e.oom;
            if (!oom)
                go_says(q, LC_GO("tls: failed to parse certificate from server: %s"),
                        e.p != NULL ? e.p : "");
            free(e.p);
            if (oom)
                return -1;
            return q->chrome ? (int)LC_ALERT_BAD_CERTIFICATE : (int)LC_ALERT_DECODE_ERROR;
        }
        if (bits > LC_MAX_RSA_BITS) {
            go_says(q, LC_GO("tls: server sent certificate containing RSA key larger than %d bits"),
                    (int)LC_MAX_RSA_BITS);
            return LC_ALERT_BAD_CERTIFICATE;
        }
    }
    return 0;
}

/* What %T prints for the key of a certificate Go parses but TLS cannot use: *dsa.PublicKey for DSA
 * (the id-dsa OID, 1.2.840.10040.4.1), and nil for a key type Go's parser has no type for — Ed448,
 * X25519, an RSASSA-PSS key (GOROOT/src/crypto/x509/x509.go:500-512). */
static const char *go_unsupported_key(const uint8_t *der, size_t der_len)
{
    static const uint8_t id_dsa[] = { 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01 };
    const uint8_t       *spki = NULL;
    size_t               spki_len = 0;
    if (lc_cert_spki(der, der_len, &spki, &spki_len) == 0 && spki_len > sizeof id_dsa) {
        for (size_t i = 0; i + sizeof id_dsa <= spki_len && i < 16u; i++)
            if (memcmp(spki + i, id_dsa, sizeof id_dsa) == 0)
                return "*dsa.PublicKey";
    }
    return "<nil>";
}

static int take_certificate(lc_qtls *q, const uint8_t *body, size_t body_len, int compressed)
{
    /* The order rule is what keeps this honest, and it is the whole of the pin's soundness.
     * cert_verified says "somebody proved they hold the key for the certificate in
     * cert_der" — it is a flag, so it cannot say WHICH bytes were there when it was set.
     * Let a second Certificate through and an impersonator holding no key of ours pulls the
     * two apart: its own leaf, a CertificateVerify it can honestly sign, then the real
     * node's leaf replayed over the top. check_pin would hash the replay, match, and report
     * the peer as the node — after which the account password goes to it. That was a
     * working attack against this file.
     *
     * THE WHOLE MESSAGE, THEN EVERY CERTIFICATE IN IT, THEN THE LEAF — the reference's
     * order (GOROOT/src/crypto/tls/handshake_client_tls13.go:647-662, verifyServerCertificate
     * at GOROOT/src/crypto/tls/handshake_client.go:1135-1222, go1.25.14). This read the
     * leaf and nothing after it, so a malformed or unparseable intermediate was accepted,
     * and a leaf the parser could not read failed several messages later. */
    size_t         off = 0;
    unsigned       count = 0;
    const uint8_t *der = NULL, *leaf = NULL;
    size_t         der_len = 0, leaf_len = 0;
    int            step;
    while ((step = lc_cert_next_from_message(body, body_len, &off, &der, &der_len)) == 0) {
        if (count++ == 0u) {
            leaf = der;
            leaf_len = der_len;
        }
    }
    /* Under the parrot, uTLS's verdict on the message, which the TLS plane already applies:
     * unexpected_message when it does not parse, decode_error when it holds no certificates,
     * bad_certificate for one that is not X.509 or an RSA key over 8192 bits — see
     * lc_utls_cert_msg_alert. The key type and the pin follow, as they do below. */
    if (q->chrome) {
        uint8_t a = lc_utls_cert_msg_alert(body, body_len);
        /* A message that does not unmarshal is the error sendAlert returns; opened from a
         * CompressedCertificate, wrapped as its failure (vendor/utls/u_handshake_client.go:38,
         * :137-139). No certificates is :819-822. */
        if (a == LC_ALERT_UNEXPECTED_MESSAGE)
            go_says(q, compressed ? LC_GO("tls: failed to decompress certificate message: local error: tls: unexpected message")
                                  : LC_GO("local error: tls: unexpected message"));
        else if (a == LC_ALERT_DECODE_ERROR)
            go_says(q, LC_GO("tls: received empty certificates message"));
        else {
            /* the certificates themselves: Go's parser, not the mbedTLS one the TLS plane's
             * verdict stands on */
            int v = go_cert_parse(q, body, body_len);
            if (v < 0)
                return own_fail(q, "no memory to parse the node's certificates");
            a = (uint8_t)v;
        }
        if (a != 0u)
            return fail(q, a,
                        a == LC_ALERT_DECODE_ERROR ? "the node's Certificate holds no certificates"
                        : a == LC_ALERT_BAD_CERTIFICATE
                            ? "a certificate the node sent does not parse as X.509, or carries an "
                              "RSA key over 8192 bits"
                            : "the node's Certificate does not parse");
    }
    /* A message that does not unmarshal, and one carrying no certificates, are both
     * decode_error here (GOROOT/src/crypto/tls/conn.go:1185-1186,
     * GOROOT/src/crypto/tls/handshake_client_tls13.go:652-655). */
    if (step < 0 || count == 0u)
        return fail(q, LC_ALERT_DECODE_ERROR, "the node's Certificate does not parse");
    /* Every certificate parsed by Go's parser, and an RSA key over 8192 bits refused as a bad
     * certificate once parsed — see go_cert_parse. It used to be mbedTLS's parser here, which
     * refuses what Go reads (an unknown critical extension) and reads what Go refuses, and which
     * had to be asked about the key size first, since it refuses a large key outright. */
    if (!q->chrome) {
        int v = go_cert_parse(q, body, body_len);
        if (v < 0)
            return own_fail(q, "no memory to parse the node's certificates");
        if (v == LC_ALERT_DECODE_ERROR)
            return fail(q, LC_ALERT_DECODE_ERROR, "a certificate the node sent does not parse as X.509");
        if (v != 0)
            return fail(q, (uint8_t)v, "the node's certificate carries an RSA key larger than %u bits",
                        (unsigned)LC_MAX_RSA_BITS);
    }
    /* No chain is built: the reference runs with InsecureSkipVerify when it pins, and this
     * plane pins or trusts nothing. Then the key-type switch on the leaf
     * (GOROOT/src/crypto/tls/handshake_client.go:1207-1213) — without it a pinned Ed448
     * certificate would sail to CertificateVerify and die there, a refusal no Go client
     * produces for this cause. */
    if (lc_cert_key_supported(leaf, leaf_len) != 1) {
        go_says(q, LC_GO("tls: server's certificate contains an unsupported type of public key: %T"),
                go_unsupported_key(leaf, leaf_len));
        return fail(q, LC_ALERT_UNSUPPORTED_CERTIFICATE,
                    "the node's certificate carries a public key of a kind this client "
                    "does not support");
    }
    /* Copied rather than referenced: the buffer this points into is about to be consumed.
     * Sized to the leaf, so that what a peer may send is the reference's limit and not a
     * field's. */
    free(q->cert_der);
    q->cert_der = malloc(leaf_len ? leaf_len : 1u);
    if (q->cert_der == NULL) {
        q->cert_der_len = 0;
        return own_fail(q, "no memory for the node's certificate");
    }
    memcpy(q->cert_der, leaf, leaf_len);
    q->cert_der_len = leaf_len;
    q->cert_seen = 1;
    /* THE PIN, WHERE THE REFERENCE CHECKS IT. hysteria's pinSHA256 is a
     * VerifyPeerCertificate callback (vendor/hysteria/app/cmd/client.go:389-401), which
     * runs inside verifyServerCertificate and answers a mismatch with bad_certificate
     * before CertificateVerify is even read (GOROOT/src/crypto/tls/handshake_client.go:
     * 1217-1222). This compared at Finished, so a wrong certificate followed by a bad
     * signature got the signature's alert, and a wrong certificate followed by silence got
     * nothing at all until a timeout. Whether the peer then PROVES it holds the key is still
     * decided by CertificateVerify, and only a Finished after it marks the peer pinned. */
    /* hysteria's own error, which uTLS hands on as it is: under the parrot the reason of the
     * close (tls/goerr.h). */
    if (q->have_pin && !pin_matches(q)) {
        go_says(q, LC_GO("no certificate matches the pinned hash"));
        return fail(q, LC_ALERT_BAD_CERTIFICATE,
                    "the node's certificate does not match the configured pin");
    }
    q->expect = LC_QX_CERT_VERIFY;
    return 0;
}

/* The handshake types the reference's reader has a message for: the cases of
 * unmarshalHandshakeMessage (GOROOT/src/crypto/tls/conn.go:1127-1178, go1.25.14). Anything else is
 * unexpected_message before a byte of it is parsed (:1176-1177); a known type is parsed first, and
 * only then refused for being in the wrong place. */
static int std_knows(uint8_t type)
{
    switch (type) {
    case 0u: case 1u: case 2u: case 4u: case 5u: case 8u: case 11u: case 12u: case 13u:
    case 14u: case 15u: case 16u: case 20u: case 22u: case 24u:
        return 1;
    default:
        return 0;
    }
}

/* How many handshake messages the reference reads after the handshake before it calls them
 * "too many non-advancing records": maxUselessRecords (GOROOT/src/crypto/tls/common.go:71,
 * go1.25.14 — sixteen, where uTLS has thirty-two). The count is retryCount, and on QUIC nothing
 * resets it: the reset lives in the record reader, which QUIC never runs. */
#define LC_QTLS_MAX_POST_MSGS 16u

/* A handshake message after the handshake: handlePostHandshakeMessage
 * (GOROOT/src/crypto/tls/conn.go:1309-1336). Returns 0 when it is dropped, -1 with the alert set.
 *
 * A session ticket is the only message a node sends here, and it is DROPPED rather than kept
 * because the reference keeps none: hysteria builds its tls.Config without a ClientSessionCache
 * (vendor/hysteria/core/client/client.go:75-82), and handleNewSessionTicket returns right there
 * (GOROOT/src/crypto/tls/handshake_client_tls13.go:863-865). But it is READ first, as every
 * message is — readHandshake, then the count, then the type (:1314-1335) — so a message of a type
 * the library has no reader for is unexpected_message, one of its fifteen that does not unmarshal
 * decode_error (conn.go:1176-1187), both before the count, and the seventeenth message of any kind
 * unexpected_message. A KeyUpdate has no place on QUIC at all (:1339-1342), and nor has anything
 * else that is not a ticket. This client used to accept tickets unparsed and without end, and
 * then refused every known type but those two after the count and with 10, parsed or not. */
static int post_handshake(lc_qtls *q, const uint8_t *whole, size_t whole_len)
{
    uint8_t type = whole[0];
    /* UNDER THE PARROT, uTLS's READER, uTLS's COUNT AND uTLS's ANSWER. Its limit is thirty-two
     * (maxUselessRecords, vendor/utls/common.go:73), and every way this ends is unexpected_message:
     * a message readHandshake does not read — see utls_reads — the thirty-third message, a KeyUpdate
     * on QUIC, and anything that is not a ticket (handlePostHandshakeMessage,
     * vendor/utls/u_conn.go:957-984). A ticket is dropped as it is without the parrot:
     * SessionTicketsDisabled is set on the uTLS config
     * (vendor/quic-go/internal/handshake/tls_conn_utls.go:77-78), and handleNewSessionTicket
     * returns there (vendor/utls/handshake_client_tls13.go:981-983). */
    if (q->chrome) {
        if (!utls_reads(whole, whole_len, 1)) {
            /* sendAlert's error, before the count (vendor/utls/conn.go:1183-1194) */
            go_says(q, LC_GO("local error: tls: unexpected message"));
            return fail(q, LC_ALERT_UNEXPECTED_MESSAGE,
                        "the node's handshake message type %u after the handshake does not read",
                        (unsigned)type);
        }
        if (++q->post_msgs > 32u) {
            go_says(q, LC_GO("tls: too many non-advancing records")); /* u_conn.go:966-970 */
            return fail(q, LC_ALERT_UNEXPECTED_MESSAGE,
                        "the node sent more than 32 handshake messages after the handshake");
        }
        if (type == LC_HS_NEW_SESSION_TICKET)
            return 0;
        /* A KeyUpdate has words of its own on QUIC (vendor/utls/conn.go:1345-1349), any other
         * message handlePostHandshakeMessage's default (vendor/utls/u_conn.go:978-984). */
        if (type == LC_HS_KEY_UPDATE)
            go_says(q, LC_GO("tls: received unexpected key update message"));
        else
            go_says(q, LC_GO("tls: received unexpected handshake message of type %T"),
                    go_msg_type(type, 1));
        return fail(q, LC_ALERT_UNEXPECTED_MESSAGE,
                    "the node sent handshake message type %u after the handshake finished",
                    (unsigned)type);
    }
    if (!std_knows(type))
        return fail(q, LC_ALERT_UNEXPECTED_MESSAGE,
                    "the node sent handshake message type %u, which has no meaning in TLS 1.3",
                    (unsigned)type);
    if (lc_std_misplaced_alert(whole, whole_len, 1) == LC_ALERT_DECODE_ERROR)
        return fail(q, LC_ALERT_DECODE_ERROR,
                    "the node's handshake message type %u after the handshake does not parse",
                    (unsigned)type);
    if (++q->post_msgs > LC_QTLS_MAX_POST_MSGS)
        return fail(q, LC_ALERT_UNEXPECTED_MESSAGE,
                    "the node sent more than %u handshake messages after the handshake",
                    LC_QTLS_MAX_POST_MSGS);
    if (type == LC_HS_NEW_SESSION_TICKET)
        return 0;
    return fail(q, LC_ALERT_UNEXPECTED_MESSAGE,
                "the node sent handshake message type %u after the handshake finished",
                (unsigned)type);
}

/* encryptedExtensionsMsg.unmarshal (GOROOT/src/crypto/tls/handshake_messages.go:1056-1121,
 * go1.25.14): one two-byte-prefixed extension block that is the whole message, no identifier twice,
 * and for the five it names a body of the right shape — ALPN one non-empty name in a non-empty
 * list, server_name and early_data empty, the transport parameters and encrypted_client_hello
 * anything at all. Hands back what the verdict needs; -1 when the message does not unmarshal. */
typedef struct {
    const uint8_t *alpn;
    size_t         alpn_len;
    const uint8_t *params;
    size_t         params_len;
    int            have_params;
    int            early_data;
} ee_fields;

static int ee_unmarshal(const uint8_t *body, size_t len, ee_fields *f)
{
    memset(f, 0, sizeof *f);
    if (len < 2u || ((size_t)body[0] << 8 | body[1]) != len - 2u)
        return -1;
    size_t start = 2u, off = 2u;
    while (off < len) {
        if (len - off < 4u)
            return -1;
        size_t   rec = off;
        uint16_t ext = (uint16_t)((uint16_t)body[off] << 8 | body[off + 1u]);
        size_t   n = (size_t)body[off + 2u] << 8 | body[off + 3u];
        off += 4u;
        if (n > len - off)
            return -1;
        for (size_t p = start; p < rec;) {
            if (((uint16_t)((uint16_t)body[p] << 8 | body[p + 1u])) == ext)
                return -1;
            p += 4u + ((size_t)body[p + 2u] << 8 | body[p + 3u]);
        }
        if (ext == EXT_ALPN) {
            if (lc_alpn_selected(body + off, n, &f->alpn, &f->alpn_len) != 0)
                return -1;
        } else if (ext == EXT_QUIC_TRANSPORT_PARAMS) {
            f->params = body + off;
            f->params_len = n;
            f->have_params = 1;
        } else if (ext == 0x002au) { /* early_data */
            if (n != 0u)
                return -1;
            f->early_data = 1;
        } else if (ext == 0x0000u) { /* server_name */
            if (n != 0u)
                return -1;
        }
        off += n;
    }
    return 0;
}

/* What the flight expects next, in the order clientHandshakeStateTLS13 reads it: readHandshake
 * then a type assertion, message by message
 * (GOROOT/src/crypto/tls/handshake_client_tls13.go:547-757). */
static int expected_type(const lc_qtls *q, uint8_t type)
{
    switch (q->expect) {
    case LC_QX_SERVER_HELLO:  return type == LC_HS_SERVER_HELLO;
    case LC_QX_ENCRYPTED_EXT: return type == LC_HS_ENCRYPTED_EXT;
    /* A CertificateRequest may come first, once (:637-645). */
    case LC_QX_CERTIFICATE:
        /* Under the parrot a CompressedCertificate stands where a Certificate does: the hello
         * offered brotli, and uTLS reads the message in its place (utlsReadServerCertificate,
         * vendor/utls/u_handshake_client.go:25-48). */
        return type == LC_HS_CERTIFICATE ||
               (q->chrome && type == LC_HS_COMPRESSED_CERTIFICATE) ||
               (type == LC_HS_CERTIFICATE_REQUEST && !q->cert_requested);
    case LC_QX_CERT_VERIFY:   return type == LC_HS_CERTIFICATE_VERIFY;
    case LC_QX_FINISHED:      return type == LC_HS_FINISHED;
    default:                  return 0;
    }
}

int lc_qtls_recv(lc_qtls *q, lc_qtls_level level, const uint8_t *data, size_t len)
{
    /* ONE READ LEVEL AT A TIME, which is the reference's rule and was not ours.
     *
     *     if c.in.level != level {
     *         return quicError(c.in.setErrorLocked(errors.New("tls: handshake data received at wrong level")))
     *     }                          (GOROOT/src/crypto/tls/quic.go:257-261, go1.25.14)
     *
     * The level moves forward twice — to Handshake once the ServerHello has produced its keys, to
     * application once the server's Finished has — and data at any other level is refused. The
     * error carries no alert of its own, so quicError makes it internal_error (:358-373).
     *
     * This used to bind each message TYPE to a level instead, which is a weaker rule: a second
     * ServerHello in a later Initial frame reached the parser and was refused as a repeat (10), where
     * the reference never reads it at all (80); and a message could not straddle two levels only
     * because the partial buffer remembered where it began. Binding by level is also what stops a
     * flight delivered entirely at Initial — whose keys come from a connection ID travelling in the
     * clear — from being read as though it were encrypted. */
    if (level != q->read_level) {
        go_says(q, LC_GO("tls: handshake data received at wrong level")); /* vendor/utls/u_quic.go:98-100 */
        return fail(q, LC_ALERT_INTERNAL_ERROR,
                    "handshake data received at encryption level %u while reading level %u",
                    (unsigned)level, (unsigned)q->read_level);
    }

    int room = qtls_reserve(q, len);
    if (room == -2)
        return own_fail(q, "no memory for a handshake message");
    if (room != 0)
        return fail(q, LC_ALERT_INTERNAL_ERROR,
                    "a handshake message larger than the %u bytes the reference reads",
                    (unsigned)LC_QTLS_MAX_CERTIFICATE);
    memcpy(q->partial + q->partial_len, data, len);
    q->partial_len += len;

    for (;;) {
        if (q->partial_len < 4u)
            return 0;
        size_t body_len = (size_t)q->partial[1] << 16 | (size_t)q->partial[2] << 8 | q->partial[3];
        /* A message that cannot fit the window is refused NOW, not waited for. Waiting costs the
         * caller its whole handshake deadline for four bytes, and reports "no answer" for what is
         * really a malformed peer — the TLS twin refuses immediately and test/hsframe pins it. */
        if (body_len > qtls_msg_ceiling(q, q->partial[0])) {
            /* uTLS's words for it, both numbers in decimal (vendor/utls-hy/conn.go:1109,
             * vendor/utls-hy/u_quic.go:120). */
            go_says(q, LC_GO("tls: handshake message of length %d bytes exceeds maximum of %d bytes"),
                    (int)body_len, (int)qtls_msg_ceiling(q, q->partial[0]));
            return fail(q, LC_ALERT_INTERNAL_ERROR,
                        "the peer declared a %zu-byte handshake message, larger than the reference "
                        "reads",
                        body_len);
        }
        /* Only while the message is still short of complete: the subtraction is unsigned. */
        int rest = q->partial_len < 4u + body_len
                       ? qtls_reserve(q, 4u + body_len - q->partial_len)
                       : 0;
        if (rest == -2)
            return own_fail(q, "no memory for a %zu-byte handshake message", body_len);
        if (rest != 0)
            return fail(q, LC_ALERT_INTERNAL_ERROR, "no room for a %zu-byte handshake message",
                        body_len);
        if (q->partial_len < 4u + body_len)
            return 0; /* the rest of this message has not arrived yet */

        uint8_t        type = q->partial[0];
        const uint8_t *body = q->partial + 4;
        const uint8_t *whole = q->partial;
        size_t         whole_len = 4u + body_len;

        /* After the handshake: session tickets, parsed, counted and dropped — see post_handshake.
         * They used to be copied in and left there, which filled the window with tickets until it
         * tore down a connection that was working. */
        if (q->done) {
            if (post_handshake(q, whole, whole_len) != 0)
                return -1;
            goto consumed;
        }

        /* The message the flight expects, and no other. A type the reference has no message for is
         * unexpected_message outright (GOROOT/src/crypto/tls/conn.go:1176-1177); one it knows is
         * UNMARSHALLED FIRST, and is decode_error if that fails (:1185-1187) and unexpected_message
         * only if it succeeds, at the type assertion after it
         * (GOROOT/src/crypto/tls/handshake_client_tls13.go:555-559, :647-651, :672-676, :719-723).
         * This used to be 10 for all of them; tls/stdmsg.h has the fifteen readers, and the
         * version they read at is the library's c.vers — TLS 1.3 once a ServerHello or a retry
         * has been through pickTLSVersion, nothing before.
         *
         * THIS IS THE ORDER RULE, AND IT WAS MISSING. A table of which messages had arrived once
         * stood here, and it held nothing about which came first: a Certificate before
         * EncryptedExtensions was taken, and a flight of EncryptedExtensions and Finished alone —
         * no Certificate, no CertificateVerify — completed the handshake on a connection started
         * without a pin. The reference cannot be walked out of its sequence at all. */
        /* Under the parrot every refusal here is 10: uTLS kept unexpected_message for a message that
         * does not unmarshal (vendor/utls/conn.go:1192-1194), a type it has no reader for is the same
         * 10 from utlsHandshakeMessageType (vendor/utls/u_conn.go:826-838), and one out of turn fails
         * a type assertion that sends 10 too (vendor/utls/handshake_client_tls13.go:633-637,
         * :754-758, :833-837). */
        if (!expected_type(q, type)) {
            /* In uTLS's words: a type it has no reader for, or a message its reader refuses, is the
             * error sendAlert returns; one that unmarshals is unexpectedMessageError, got then
             * wanted (vendor/utls/common.go:1841-1843) — see utls_reads. */
            int         tls13 = q->retried || q->keys_installed;
            const char *got = go_msg_type(type, tls13);
            if (!utls_reads(whole, whole_len, tls13))
                go_says(q, LC_GO("local error: tls: unexpected message"));
            else
                go_says(q, LC_GO("tls: received unexpected handshake message of type %T when waiting for %T"),
                        got,
                        q->expect == LC_QX_SERVER_HELLO    ? "*tls.serverHelloMsg"
                        : q->expect == LC_QX_ENCRYPTED_EXT ? "*tls.encryptedExtensionsMsg"
                        : q->expect == LC_QX_CERTIFICATE   ? "*tls.certificateMsgTLS13"
                        : q->expect == LC_QX_CERT_VERIFY   ? "*tls.certificateVerifyMsg"
                                                           : "*tls.finishedMsg");
            return fail(q, q->chrome ? LC_ALERT_UNEXPECTED_MESSAGE
                                     : lc_std_misplaced_alert(whole, whole_len,
                                                              q->retried || q->keys_installed),
                        "the node sent handshake message type %u where the flight expects %s",
                        (unsigned)type,
                        q->expect == LC_QX_SERVER_HELLO    ? "ServerHello"
                        : q->expect == LC_QX_ENCRYPTED_EXT ? "EncryptedExtensions"
                        : q->expect == LC_QX_CERTIFICATE   ? "a Certificate"
                        : q->expect == LC_QX_CERT_VERIFY   ? "CertificateVerify"
                                                           : "Finished");
        }

        /* The transcript for Finished stops before Finished itself, and the one CertificateVerify
         * signs stops before CertificateVerify — so both take their snapshot before the message is
         * added. The order rule above guarantees a ServerHello, and so a transcript, before
         * either. */
        uint8_t th[LC_HASH_MAX];
        if (type == LC_HS_FINISHED || type == LC_HS_CERTIFICATE_VERIFY) {
            if (lc_transcript_snapshot(&q->tr, th) != 0)
                return own_fail(q, "the transcript cannot be read");
        }

        switch (type) {
        case LC_HS_SERVER_HELLO: {
            /* THE SAME VERDICT AS THE TLS PLANE, against this plane's own hello. crypto/tls runs
             * one client handshake for both transports, so a ServerHello the node gets wrong earns
             * the same alert here as over TCP — as CONNECTION_CLOSE 0x100 plus the alert. This used
             * to be a bare -1 for every refusal, so ngtcp2 closed with a code that named none of
             * them, and a version, session id or suite this plane never offered was not checked
             * at all. q->ch still holds the hello: it is released only once the transcript has it. */
            lc_server_hello sh;
            lc_sh_expect    ex;
            if (lc_sh_expect_from_hello(hello_bytes(q), q->ch_len, &ex) != 0)
                return own_fail(q, "our own ClientHello does not parse");
            /* Under the parrot the verdict is uTLS's, the TLS plane's: see `stdlib` in lc_sh_expect. */
            ex.stdlib = !q->chrome;
            ex.retried = q->retried;
            ex.retry_suite = q->retry_suite;
            /* A ServerHello that does not unmarshal is decode_error here, not the unexpected_message
             * the parser reports for the TLS plane: this plane's reference is the standard library
             * (GOROOT/src/crypto/tls/conn.go:1185-1186, go1.25.14) — unless it parrots Chrome, when
             * it is uTLS and 10 (vendor/utls/conn.go:1192-1194). */
            if (lc_parse_server_hello(body, body_len, &sh) != 0) {
                go_says(q, LC_GO("local error: tls: unexpected message"));
                return fail(q, q->chrome ? LC_ALERT_UNEXPECTED_MESSAGE : LC_ALERT_DECODE_ERROR, "%s",
                            sh.why);
            }
            if (lc_check_server_hello(&sh, &ex) != 0) {
                if (sh.go != NULL)
                    go_says(q, "%s", sh.go);
                return fail(q, sh.alert, "%s", sh.why);
            }
            /* A RETRY THAT PASSED THE VERDICT IS ANSWERED, as the reference answers it
             * (processHelloRetryRequest, GOROOT/src/crypto/tls/handshake_client_tls13.go:235-351,
             * go1.25.14). The verdict has made the checks the message settles on its own — ECH 110,
             * a retry that changes nothing 47, a full key share 50, a group already shared 47 — and
             * a second retry is 10 there, since `retried` is set below. What is left needs the
             * hello: the group has to be one it advertised (:303-306), which after the verdict leaves
             * the three NIST curves and, in the hello that is Go's, the two P-curve hybrids of Go 1.26 —
             * all of which this build keys.
             *
             * THE TRANSCRIPT STARTS HERE, AND NOT WITH THE FIRST HELLO. RFC 8446 4.4.1 replaces
             * ClientHello1 with a synthetic message_hash — type 254, a three-byte length, the hash of
             * the hello — and the retry follows it (:238-246); the second hello goes in when it is
             * written (:391). No ChangeCipherSpec: the reference sends none on QUIC. The keys of the
             * Initial level do not change, and the next message is read at it again. */
            if (sh.is_hello_retry) {
                size_t point_len = 0;
                if (sh.selected_group != 0u) {
                    /* Of the seven groups the hello advertises, the verdict has refused the two it
                     * shared; the other five are the NIST curves and two hybrids, and every name
                     * outside the seven is the reference's "server selected unsupported group" — 47
                     * either way. */
                    /* The parrot's hello advertises four groups, not five: P-521 is not among them
                     * (vendor/quic-go/internal/handshake/chrome_client_hello.go:35-40), so a retry
                     * naming it is "server selected unsupported group" there — 47, like any other
                     * name outside the list (vendor/utls/handshake_client_tls13.go:329-333). */
                    /* And the two hybrids Go 1.26 advertises, only in the hello that is Go's: one
                     * share for the group asked for, the ECDH point first and the ML-KEM
                     * encapsulation key after it — "For SecP256r1MLKEM768 and SecP384r1MLKEM1024,
                     * the ECDH share comes first" — and not the fallback ECDH share the first hello
                     * sends beside X25519MLKEM768: "Do not send the fallback ECDH key share in a HRR
                     * response" (GOROOT/src/crypto/tls/key_schedule.go:168-198,
                     * GOROOT/src/crypto/tls/handshake_client_tls13.go:322-334, go1.26.6). */
                    point_len = sh.selected_group == LC_GROUP_SECP256R1   ? LC_P256_POINT
                                : sh.selected_group == LC_GROUP_SECP384R1 ? LC_P384_POINT
                                : sh.selected_group == LC_GROUP_SECP521R1 && !q->chrome
                                    ? LC_P521_POINT
                                : sh.selected_group == LC_GROUP_SECP256R1MLKEM768 && !q->chrome
                                    ? LC_P256_POINT + LC_MLKEM_EK
                                : sh.selected_group == LC_GROUP_SECP384R1MLKEM1024 && !q->chrome
                                    ? LC_P384_POINT + LC_MLKEM1024_EK
                                    : 0u;
                    if (point_len == 0u) {
                        /* vendor/utls/handshake_client_tls13.go:330-333 */
                        go_says(q, LC_GO("tls: server selected unsupported group"));
                        return fail(q, LC_ALERT_ILLEGAL_PARAMETER,
                                    "the retry asks for group 0x%04x, which the hello did not offer",
                                    sh.selected_group);
                    }
                }
                if (lc_tls_suite_params(sh.cipher_suite, NULL, &q->hash, NULL) != 0)
                    return own_fail(q,
                                "a suite that passed the check has no parameters");
                q->suite = sh.cipher_suite;
                size_t  hlen = lc_hash_len(q->hash);
                uint8_t h1[LC_HASH_MAX];
                if (lc_hash_digest(q->hash, q->ch, q->ch_len, h1) != 0 ||
                    lc_transcript_init(&q->tr, q->hash) != 0)
                    return own_fail(q, "cannot start the transcript of a retry");
                q->tr_ready = 1;
                const uint8_t synth[4] = { 0xfeu, 0x00u, 0x00u, (uint8_t)hlen }; /* message_hash */
                if (lc_transcript_add(&q->tr, synth, sizeof synth) != 0 ||
                    lc_transcript_add(&q->tr, h1, hlen) != 0 ||
                    lc_transcript_add(&q->tr, whole, whole_len) != 0)
                    return own_fail(q, "cannot hash the retry");

                static uint8_t point[LC_P384_POINT + LC_MLKEM1024_EK];
                if (point_len != 0u) {
                    uint16_t g = sh.selected_group;
                    int      bad =
                        g == LC_GROUP_SECP256R1 || g == LC_GROUP_SECP256R1MLKEM768
                                 ? lc_p256_keygen(q->retry_priv, point)
                        : g == LC_GROUP_SECP384R1 || g == LC_GROUP_SECP384R1MLKEM1024
                            ? lc_p384_keygen(q->retry_priv, point)
                            : lc_p521_keygen(q->retry_priv, point);
                    /* The ECDH key first and the ML-KEM seed after it, the order keyShares draws
                     * them in (GOROOT/src/crypto/tls/key_schedule.go:168-198, go1.26.6). */
                    if (bad == 0 && g == LC_GROUP_SECP256R1MLKEM768)
                        bad = lc_mlkem_keygen(point + LC_P256_POINT, q->retry_dk);
                    else if (bad == 0 && g == LC_GROUP_SECP384R1MLKEM1024)
                        bad = lc_mlkem1024_keygen(point + LC_P384_POINT, q->retry_dk);
                    if (bad != 0)
                        return own_fail(q, "cannot generate a key for the retry");
                }
                int built = q->chrome
                                ? build_retry_hello_chrome(q, sh.cookie, sh.cookie_len,
                                                           sh.selected_group,
                                                           point_len != 0u ? point : NULL, point_len)
                                : build_retry_hello(q, sh.cookie, sh.cookie_len, sh.selected_group,
                                                    point_len != 0u ? point : NULL, point_len);
                if (built == -2)
                    return fail(q, 0u, "the retry's cookie does not fit in a hello");
                if (built != 0)
                    return own_fail(q, "cannot build the second hello");
                if (lc_transcript_add(&q->tr, hello_bytes(q), q->ch_len) != 0)
                    return own_fail(q, "cannot hash the second hello");
                q->retried = 1;
                q->retry_suite = sh.cipher_suite;
                q->retry_group = sh.selected_group;
                if (q->sink.send(q->sink.ctx, LC_QTLS_INITIAL, hello_bytes(q), q->ch_len) != 0)
                    return own_fail(q, "cannot send the second hello");
                goto consumed;
            }
            /* The length the group implies — the server's hybrid reply is the ML-KEM ciphertext
             * followed by its X25519 public key (LC_HYBRID_CT), not the 1216-byte share we sent. A
             * share of the wrong length is illegal_parameter in the reference, "invalid server key
             * share" (establishHandshakeKeys, vendor/utls/handshake_client_tls13.go:573-585);
             * which GROUP was already checked against those we shared — after a retry, the one
             * NIST curve it named, whose share is an uncompressed point. */
            if (!((sh.group == LC_GROUP_X25519MLKEM768 && sh.key_share_len == LC_HYBRID_CT) ||
                  (sh.group == LC_GROUP_X25519 && sh.key_share_len == LC_X25519_KEY) ||
                  (sh.group == LC_GROUP_SECP256R1 && sh.key_share_len == LC_P256_POINT) ||
                  (sh.group == LC_GROUP_SECP384R1 && sh.key_share_len == LC_P384_POINT) ||
                  (sh.group == LC_GROUP_SECP521R1 && sh.key_share_len == LC_P521_POINT) ||
                  /* A hybrid's reply is its ECDH point and then the ML-KEM ciphertext; any other
                   * length is "invalid server key share length for hybrid key exchange", which
                   * establishHandshakeKeys turns into illegal_parameter
                   * (GOROOT/src/crypto/tls/key_schedule.go:240-243,
                   * GOROOT/src/crypto/tls/handshake_client_tls13.go:473-482, go1.26.6). */
                  (sh.group == LC_GROUP_SECP256R1MLKEM768 &&
                   sh.key_share_len == LC_P256_POINT + LC_MLKEM_CT) ||
                  (sh.group == LC_GROUP_SECP384R1MLKEM1024 &&
                   sh.key_share_len == LC_P384_POINT + LC_MLKEM1024_CT))) {
                /* The hybrid's own words, and the ECDH groups' (:586-590, :601-606). */
                go_says(q, sh.group == LC_GROUP_X25519MLKEM768
                               ? LC_GO("tls: invalid server X25519MLKEM768 key share")
                               : LC_GO("tls: invalid server key share"));
                return fail(q, LC_ALERT_ILLEGAL_PARAMETER,
                            "the node's key share has the wrong length for group 0x%04x", sh.group);
            }
            /* Whichever of the three the server chose — the verdict has already refused a suite
             * this hello did not offer, so this only looks up what the choice implies.
             *
             * The hash is re-derived HERE and not left at the placeholder from lc_qtls_start,
             * because with three suites on offer it is now genuinely variable: AES-256-GCM brings
             * SHA-384 with it, and every secret below this line is sized by that answer. */
            if (lc_tls_suite_params(sh.cipher_suite, NULL, &q->hash, NULL) != 0)
                return own_fail(q, "a suite that passed the check has no parameters");
            q->suite = sh.cipher_suite;
            /* And only now can the transcript exist, with the hash that answer implies. The
             * ClientHello has been waiting in q->ch for exactly this. After a retry it exists
             * already, holding everything up to the second hello, and only this message is new. */
            if (!q->retried) {
                if (lc_transcript_init(&q->tr, q->hash) != 0)
                    return own_fail(q, "cannot start a transcript");
                q->tr_ready = 1;
                if (lc_transcript_add(&q->tr, q->ch, q->ch_len) != 0)
                    return own_fail(q, "cannot hash the hellos");
            }
            if (lc_transcript_add(&q->tr, whole, whole_len) != 0)
                return own_fail(q, "cannot hash the hellos");
            /* Not wiped: a ClientHello is what we shouted on the wire, not a secret. Kept under the
             * parrot, where EncryptedExtensions and a compressed certificate are both judged against
             * what it offered, as uTLS judges them against its hello. */
            if (!q->chrome)
                q->ch_len = 0;
            if (install_handshake_keys(q, sh.group, sh.key_share) != 0)
                return -1;
            q->keys_installed = 1;
            /* THE READ KEYS CHANGE HERE, and the reference will not change them over buffered bytes:
             *
             *     if c.hand.Len() != 0 {
             *         c.sendAlert(alertUnexpectedMessage)
             *         return errors.New("tls: handshake buffer not empty before setting read traffic secret")
             *     }                 (GOROOT/src/crypto/tls/quic.go:384-392, go1.25.14)
             *
             * Anything that came in the same Initial CRYPTO data after the ServerHello was encrypted
             * under keys that are about to be discarded. This client used to keep it and refuse it
             * later, with no alert, once Handshake data arrived. */
            /* ⚠️ UNDER THE PARROT THE SAME BYTES ARE READ ON, NOT REFUSED. uTLS predates that rule:
             * it installs the keys over a non-empty buffer and only records unexpected_message
             * (vendor/utls/handshake_client_tls13.go:602-607), and on QUIC a recorded alert is
             * consulted only if the handshake later fails (vendor/utls/conn.go:1589-1613). The
             * buffered bytes are then the next messages it reads — EncryptedExtensions onwards, at
             * the level just installed. So the handshake goes on over them here too, and whatever
             * stops it, if anything does, supplies the alert. */
            if (q->partial_len > whole_len && !q->chrome)
                return fail(q, LC_ALERT_UNEXPECTED_MESSAGE,
                            "%zu bytes followed the ServerHello at the Initial level",
                            q->partial_len - whole_len);
            q->read_level = LC_QTLS_HANDSHAKE;
            q->expect = LC_QX_ENCRYPTED_EXT;
            goto consumed;
        }
        case LC_HS_CERTIFICATE_REQUEST:
            /* A server asking for a client certificate, which the reference answers rather than
             * refuses: it reads the request, then the Certificate after it
             * (GOROOT/src/crypto/tls/handshake_client_tls13.go:637-645), and sends back an empty
             * Certificate ahead of its Finished, having no certificate to give (:759-795). This plane
             * refused the request with unexpected_message. It is parsed first, and a request that
             * does not parse is decode_error here, as every message that does not unmarshal is. */
            if (!lc_cert_request_parses(body, body_len)) {
                go_says(q, LC_GO("local error: tls: unexpected message"));
                return fail(q, q->chrome ? LC_ALERT_UNEXPECTED_MESSAGE : LC_ALERT_DECODE_ERROR,
                            "the node's CertificateRequest does not parse");
            }
            q->cert_requested = 1;
            break;

        case LC_HS_COMPRESSED_CERTIFICATE: {
            /* Only under the parrot — expected_type admits it nowhere else. Opened into a buffer
             * the size it declares, as uTLS allocates it (vendor/utls/u_handshake_client.go:100),
             * against the algorithms our hello offered, and then read as the Certificate it
             * stands for; the transcript takes the compressed message as it came, which is what
             * uTLS writes (:25-48), and this is the message the loop adds below. */
            size_t want = lc_utls_certcomp_want(body, body_len);
            free(q->opened);
            q->opened = malloc(want ? want : 1u);
            if (q->opened == NULL)
                return own_fail(q, "no memory to open a compressed certificate");
            size_t         offered_len = 0, n = 0;
            const uint8_t *offered = lc_ch_ext(hello_bytes(q), q->ch_len,
                                               LC_EXT_COMPRESS_CERTIFICATE, &offered_len);
            char           why[192], go[160];
            int            a = lc_certcomp_open(body, body_len, offered, offered_len, q->opened,
                                                want, &n, why, sizeof why, go, sizeof go);
            if (a != 0) {
                /* In uTLS's words (vendor/utls-hy/u_handshake_client.go:37, :67): a header that does not
                 * unmarshal is sendAlert's error; an algorithm the hello did not offer is named with
                 * its number; and a brotli stream that does not open, the decoder's own error or a
                 * short read, is in the words lc_certcomp_open hands back — the only algorithm the
                 * parrot offers. */
                size_t compressed = body_len >= 8u ? ((size_t)body[5] << 16 |
                                                      (size_t)body[6] << 8 | body[7])
                                                   : 0u;
                if (body_len < 8u || compressed > body_len - 8u)
                    go_says(q, LC_GO("local error: tls: unexpected message"));
                else if (a == LC_ALERT_BAD_CERTIFICATE) {
                    unsigned algorithm = (unsigned)body[0] << 8 | body[1];
                    int      listed = 0;
                    for (size_t i = 1u; offered != NULL && i + 1u < offered_len &&
                                        i <= (size_t)offered[0];
                         i += 2u)
                        if (((unsigned)offered[i] << 8 | offered[i + 1u]) == algorithm)
                            listed = 1;
                    if (!listed)
                        go_says(q, LC_GO("tls: failed to decompress certificate message: unadvertised algorithm (%d)"),
                                (int)algorithm);
                    else if (go[0] != '\0')
                        go_says(q, "%s", go);
                }
                return fail(q, (uint8_t)a, "%s", why);
            }
            if (take_certificate(q, q->opened, n, 1) != 0)
                return -1;
            break;
        }

        case LC_HS_CERTIFICATE:
            if (take_certificate(q, body, body_len, 0) != 0)
                return -1;
            break;

        case LC_HS_FINISHED:
            /* A Finished that does not verify is decrypt_error
             * (GOROOT/src/crypto/tls/handshake_client_tls13.go:725-729); it was a bare -1. */
            if (lc_finished_check(q->hash, q->s_hs, th, body, body_len) != 0) {
                /* vendor/utls/handshake_client_tls13.go:839-843 */
                go_says(q, LC_GO("tls: invalid server finished hash"));
                return fail(q, LC_ALERT_DECRYPT_ERROR, "the node's Finished does not verify");
            }
            /* A verified Finished says the peer completed the key exchange, and nothing more: any
             * party that can carry the packets can do that much. Who the peer IS is decided here,
             * against the pin, and it is decided before finish() installs application keys and sets
             * done — so a node that fails it never reaches a state where traffic could be sent to
             * it. Without a pin there is nothing to decide and the connection proceeds
             * unauthenticated, which peer_pinned reports to the caller. */
            if (q->have_pin && check_pin(q) != 0)
                return -1;
            /* The read keys change again, to application, and again not over buffered bytes — the
             * same rule as after the ServerHello (GOROOT/src/crypto/tls/handshake_client_tls13.go:739,
             * GOROOT/src/crypto/tls/quic.go:384-392), and checked before our own Finished leaves,
             * as the reference changes its read keys before it writes. */
            /* Under the parrot, read on, as after the ServerHello: uTLS records the alert when it
             * installs the write key after its own Finished and goes on
             * (vendor/utls/handshake_client_tls13.go:968-970), and whatever follows is read as
             * post-handshake messages once the handshake is done (vendor/utls-hy/u_quic.go:111-129). */
            if (q->partial_len > whole_len && !q->chrome)
                return fail(q, LC_ALERT_UNEXPECTED_MESSAGE,
                            "%zu bytes followed the server's Finished at the Handshake level",
                            q->partial_len - whole_len);
            if (lc_transcript_add(&q->tr, whole, whole_len) != 0)
                return own_fail(q, "cannot hash the Finished");
            {
                uint8_t th_after[LC_HASH_MAX];
                if (lc_transcript_snapshot(&q->tr, th_after) != 0 || finish(q, th_after) != 0)
                    return own_fail(q, "cannot derive the application keys");
            }
            q->read_level = LC_QTLS_APPLICATION;
            q->expect = LC_QX_DONE;
            goto consumed;

        case LC_HS_ENCRYPTED_EXT: {
            /* THE WHOLE MESSAGE FIRST, THEN WHAT IT SAYS — the reference's order, and not the one
             * this used to have. readHandshake unmarshals EncryptedExtensions before anything looks
             * at it, and a message that does not unmarshal is decode_error
             * (GOROOT/src/crypto/tls/conn.go:1185-1186); only then does readServerParameters check
             * the protocol, the transport parameters and early_data, in that order
             * (GOROOT/src/crypto/tls/handshake_client_tls13.go:561-588, go1.25.14).
             *
             * This walked the extensions and judged each as it came: a malformed length stopped
             * the walk without a word, an ALPN that did not parse was refused before the rest of
             * the message was read, and a repeated extension or a server_name with a body was
             * accepted. Every one of those is decode_error in the reference, and the ALPN verdict
             * comes after all of them. */
            ee_fields f;
            if (q->chrome) {
                /* UNDER THE PARROT, uTLS's MESSAGE AND uTLS's VERDICT: no repeat check and no
                 * server_name case in its parser, 10 for one that does not parse, then the
                 * protocol (120), application settings without one (110), the transport parameters
                 * (109 without them) and early data (110) — lc_utls_ee_alert, the TLS plane's
                 * verdict with QUIC's two rules, in readServerParameters' order
                 * (vendor/utls/handshake_client_tls13.go:625-675). The parameters are the LAST
                 * block the message carries, as its parser keeps the last. */
                uint8_t a = lc_utls_ee_alert(hello_bytes(q), q->ch_len, body, body_len, 1);
                /* In uTLS's words (vendor/utls/handshake_client_tls13.go:639-676, checkALPN at
                 * vendor/utls/handshake_client.go:1001-1019): the parrot always offers h3, so a 120 is
                 * no protocol chosen or one not offered, and a 110 — application settings need a
                 * protocol, which the 120 before it has settled — is early data. */
                if (a == LC_ALERT_UNEXPECTED_MESSAGE) {
                    go_says(q, LC_GO("local error: tls: unexpected message"));
                } else if (a == LC_ALERT_NO_APPLICATION_PROTOCOL) {
                    int alpn = 0;
                    for (size_t off = 2u; off + 4u <= body_len;) {
                        size_t n = (size_t)body[off + 2u] << 8 | body[off + 3u];
                        if (((uint16_t)body[off] << 8 | body[off + 1u]) == 0x0010u)
                            alpn = 1;
                        off += 4u + n;
                    }
                    go_says(q, alpn ? LC_GO("tls: server selected unadvertised ALPN protocol")
                                    : LC_GO("tls: server did not select an ALPN protocol"));
                } else if (a == LC_ALERT_MISSING_EXTENSION) {
                    go_says(q, LC_GO("tls: server did not send a quic_transport_parameters extension"));
                } else if (a != 0u) {
                    go_says(q, LC_GO("tls: server sent an unexpected early_data extension"));
                }
                if (a != 0u)
                    return fail(q, a,
                                a == LC_ALERT_UNEXPECTED_MESSAGE
                                    ? "the node's EncryptedExtensions does not parse"
                                : a == LC_ALERT_NO_APPLICATION_PROTOCOL
                                    ? "the node chose no application protocol, or one that is not h3"
                                : a == LC_ALERT_MISSING_EXTENSION
                                    ? "the node sent no quic_transport_parameters"
                                    : "the node's EncryptedExtensions carries an extension it may "
                                      "not send");
                memset(&f, 0, sizeof f);
                for (size_t off = 2u; off + 4u <= body_len;) {
                    uint16_t ext = (uint16_t)((uint16_t)body[off] << 8 | body[off + 1u]);
                    size_t   n = (size_t)body[off + 2u] << 8 | body[off + 3u];
                    if (ext == EXT_QUIC_TRANSPORT_PARAMS) {
                        f.params = body + off + 4u;
                        f.params_len = n;
                        f.have_params = 1;
                    }
                    off += 4u + n;
                }
                /* And a server's application settings are answered after its Finished — see
                 * finish() and lc_utls_alps_answer. */
                q->alps_answer_len = lc_utls_alps_answer(body, body_len, q->alps_answer);
            } else if (ee_unmarshal(body, body_len, &f) != 0)
                return fail(q, LC_ALERT_DECODE_ERROR, "the node's EncryptedExtensions does not parse");
            /* THE PROTOCOL THE SERVER PICKED. checkALPN is not advisory, and on QUIC it is not
             * optional: with the transport being QUIC and the client having offered a list, no
             * selection is "server did not select an ALPN protocol" (RFC 9001 §8.1) and a selection
             * outside the list is "server selected unadvertised ALPN protocol" — both
             * no_application_protocol (GOROOT/src/crypto/tls/handshake_client_tls13.go:561-568).
             * On QUIC that is CONNECTION_CLOSE 0x0178. We offered exactly one, "h3". */
            if (!q->chrome && f.alpn == NULL)
                return fail(q, LC_ALERT_NO_APPLICATION_PROTOCOL,
                            "the node selected no application protocol at all");
            if (!q->chrome &&
                (f.alpn_len != strlen(alpn_h3) || memcmp(f.alpn, alpn_h3, f.alpn_len) != 0))
                return fail(q, LC_ALERT_NO_APPLICATION_PROTOCOL,
                            "the node chose an application protocol that is not %s", alpn_h3);
            /* The transport parameters, without which QUIC cannot open a stream — they carry the
             * flow control windows and the idle timeout. Missing is missing_extension (RFC 9001
             * §8.2, :571-576); this used to go on without them and fail after our own Finished had
             * left, with no alert at all. An EMPTY block is present, as the reference reads it, and
             * is refused by the parameter parser instead — see the shim. */
            if (!f.have_params)
                return fail(q, LC_ALERT_MISSING_EXTENSION,
                            "the node sent no quic_transport_parameters");
            /* early_data we never offered (:585-588). */
            if (f.early_data)
                return fail(q, LC_ALERT_UNSUPPORTED_EXTENSION,
                            "the node accepted early data this client never offered");
            free(q->peer_params);
            q->peer_params = malloc(f.params_len ? f.params_len : 1u);
            if (q->peer_params == NULL) {
                q->peer_params_len = 0;
                return own_fail(q, "no memory for the node's transport parameters");
            }
            memcpy(q->peer_params, f.params, f.params_len);
            q->peer_params_len = f.params_len;
            q->params_fresh = 1;
            q->expect = LC_QX_CERTIFICATE;
            break;
        }


        case LC_HS_CERTIFICATE_VERIFY:
            if (check_cert_verify(q, body, body_len, th) != 0)
                return -1;
            q->expect = LC_QX_FINISHED;
            break;

        default:
            return own_fail(q, "the flight reached a type it has no case for");
        }

        if (lc_transcript_add(&q->tr, whole, whole_len) != 0)
            return own_fail(q, "cannot hash a handshake message");

    consumed:
        memmove(q->partial, q->partial + whole_len, q->partial_len - whole_len);
        q->partial_len -= whole_len;
    }
}

void lc_qtls_free(lc_qtls *q)
{
    if (q->tr_ready)
        lc_transcript_free(&q->tr);
    if (q->partial != q->partial_inline) {
        lc_wipe(q->partial, q->partial_cap);
        free(q->partial);
    }
    free(q->cert_der);
    free(q->peer_params);
    free(q->ch_heap);
    free(q->opened);
    /* Every secret in this structure protects the connection that is ending; leaving them in
     * memory that is about to be reused is the cheapest avoidable mistake here. */
    memset(q, 0, sizeof *q);
}
