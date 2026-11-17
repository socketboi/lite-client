/* The seam between ngtcp2 and our TLS.
 *
 * qcrypto.c gave ngtcp2 its primitives; this file gives it a handshake. Six functions remain in the
 * contract, and they are the ones that actually carry state: ngtcp2 hands us bytes it received in
 * CRYPTO frames, we hand back bytes to send and keys to install, and each side owns the half it
 * understands. ngtcp2 never learns what TLS 1.3 is, and qtls.c never learns what a packet is.
 *
 * Two details about ownership are worth stating, because both are the sort of thing that works in
 * testing and fails under loss:
 *
 *   submitted data must outlive the call. ngtcp2_conn_submit_crypto_data does not copy — it keeps
 *   the pointer until the peer acknowledges the frame, which may be after a retransmission several
 *   round trips later. So every byte we submit is first copied into a per-level buffer that lives
 *   as long as the connection, and that buffer only ever grows: appending must not move what was
 *   submitted earlier.
 *
 *   levels are renumbered. ngtcp2 orders its levels initial, handshake, 1-RTT, 0-RTT; TLS libraries
 *   order them initial, early, handshake, application. The two agree only on initial, and the shim
 *   translates rather than trusting the coincidence. */

#include "quic/shim.h"

#include "quic/params.h"

#include <string.h>

#include <ngtcp2/ngtcp2_crypto.h>

/* The transport-parameter half of the contract is not in the installed header — it is declared in
 * ngtcp2's own crypto/shared.h, which is what shared.c compiles against. Including that file is
 * therefore the correct move rather than a reach into private headers: it is the interface between
 * shared.c and a backend, and a backend is exactly what this is. */
#include "shared.h"

#include "quic/qcrypto.h"

/* ---- level translation ------------------------------------------------------ */

/* One table for both directions and for the buffer index. Three levels exist on this path, each
 * appears here exactly once, and nothing downstream has to decide what an unlisted level means:
 * from_ngtcp2 is the single place a level can be rejected, and everything after it is total. */
static const struct {
    lc_qtls_level           ours;
    ngtcp2_encryption_level theirs;
} levels[] = {
    { LC_QTLS_INITIAL,     NGTCP2_ENCRYPTION_LEVEL_INITIAL   },
    { LC_QTLS_HANDSHAKE,   NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE },
    { LC_QTLS_APPLICATION, NGTCP2_ENCRYPTION_LEVEL_1RTT      },
};

#define LEVEL_COUNT (sizeof levels / sizeof levels[0])

/* ⚠️ THE TABLE ABOVE AND THE BUFFERS IN shim.h ARE ONE NUMBER IN TWO FILES.
 *
 * level_index returns an index into `levels` and the caller uses it to reach `s->out[i]`, with
 * `i == LEVEL_COUNT` as the only rejection. Add a fourth entry here and that rejection stops firing
 * at three — `3 == 4` is false — while `out` is still three deep, so sink_send would memcpy past the
 * end of the last buffer and hand ngtcp2 a pointer into whatever follows it. Nothing in the compiler
 * or the tests would have said anything: the two declarations are in different files and neither
 * mentions the other.
 *
 * The assertion is not decoration for a table that "obviously" has three rows. This client already
 * has a fourth level in its vocabulary — 0-RTT, which level_index exists to reject — and adding it
 * here is precisely the plausible edit. */
_Static_assert(LEVEL_COUNT == sizeof(((lc_qshim *)0)->out) / sizeof(((lc_qshim *)0)->out[0]),
               "levels[] and lc_qshim.out must hold the same number of levels");

/* The index into `levels`, which is also the index into the outbound buffers. Returns LEVEL_COUNT
 * for a level this client never uses — 0-RTT, which it does not attempt because it keeps no
 * session tickets. */
static unsigned level_index(lc_qtls_level level)
{
    unsigned i;
    for (i = 0; i < LEVEL_COUNT && levels[i].ours != level; ++i)
        ;
    return i;
}

static int from_ngtcp2(ngtcp2_encryption_level level, unsigned *index)
{
    for (unsigned i = 0; i < LEVEL_COUNT; ++i) {
        if (levels[i].theirs == level) {
            *index = i;
            return 0;
        }
    }
    return -1;
}

/* ---- sink: qtls speaking to ngtcp2 ------------------------------------------ */

static int sink_send(void *ctx, lc_qtls_level level, const uint8_t *data, size_t len)
{
    lc_qshim *s = ctx;
    unsigned  i = level_index(level);

    if (i == LEVEL_COUNT || len > sizeof s->out[i].buf - s->out[i].len)
        return -1;

    /* The append point is the pointer handed to ngtcp2, and it stays valid because the buffer is a
     * fixed array: later appends move the end, never what came before. */
    uint8_t *at = s->out[i].buf + s->out[i].len;
    memcpy(at, data, len);
    s->out[i].len += len;

    return ngtcp2_conn_submit_crypto_data(s->conn, levels[i].theirs, at, len) != 0 ? -1 : 0;
}

static int sink_rx_secret(void *ctx, lc_qtls_level level, const uint8_t *secret, size_t len)
{
    lc_qshim *s = ctx;
    unsigned  i = level_index(level);
    if (i == LEVEL_COUNT)
        return -1;
    return ngtcp2_crypto_derive_and_install_rx_key(s->conn, NULL, NULL, NULL, levels[i].theirs,
                                                   secret, len);
}

static int sink_tx_secret(void *ctx, lc_qtls_level level, const uint8_t *secret, size_t len)
{
    lc_qshim *s = ctx;
    unsigned  i = level_index(level);
    if (i == LEVEL_COUNT)
        return -1;
    return ngtcp2_crypto_derive_and_install_tx_key(s->conn, NULL, NULL, NULL, levels[i].theirs,
                                                   secret, len);
}

/* ---- setup ------------------------------------------------------------------ */

int lc_qshim_init(lc_qshim *s, ngtcp2_conn *conn, const char *sni, const uint8_t *pin,
                  unsigned tls_flags)
{
    memset(s, 0, sizeof *s);
    s->conn = conn;
    s->sni = sni;
    s->tls_flags = tls_flags;
    if (pin != NULL) {
        memcpy(s->pin, pin, LC_QTLS_PIN);
        s->have_pin = 1;
    }

    /* ngtcp2 reaches back for this handle from inside shared.c — to pick the crypto context, to
     * fetch the peer's transport parameters — so the shim is what the connection knows as its TLS,
     * not the lc_qtls inside it. */
    ngtcp2_conn_set_tls_native_handle(conn, s);
    return 0;
}

void lc_qshim_free(lc_qshim *s)
{
    lc_qtls_free(&s->tls);
    memset(s, 0, sizeof *s);
}

/* ---- the contract ----------------------------------------------------------- */

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_tls(ngtcp2_crypto_ctx *ctx, void *tls_native_handle)
{
    const lc_qshim *s = tls_native_handle;

    /* Called the moment handshake keys are installed, which is after ServerHello and therefore
     * after a suite has been chosen. A zero here would mean ngtcp2 asked ahead of the handshake,
     * and answering with a default would hide that rather than surface it. */
    if (s == NULL || lc_qcrypto_ctx_from_suite(ctx, s->tls.suite) != 0)
        return NULL;

    return ctx;
}

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_tls_early(ngtcp2_crypto_ctx *ctx, void *tls_native_handle)
{
    (void)ctx;
    (void)tls_native_handle;
    /* 0-RTT. Hysteria2 opens a fresh connection each time and this client keeps no session tickets,
     * so there is no early data to protect. */
    return NULL;
}

int ngtcp2_crypto_read_write_crypto_data(ngtcp2_conn *conn,
                                         ngtcp2_encryption_level encryption_level,
                                         const uint8_t *data, size_t datalen)
{
    lc_qshim *s = ngtcp2_conn_get_tls_native_handle(conn);
    unsigned  i;

    if (s == NULL || from_ngtcp2(encryption_level, &i) != 0)
        return NGTCP2_ERR_CRYPTO;

    if (datalen > 0 && lc_qtls_recv(&s->tls, levels[i].ours, data, datalen) != 0) {
        /* THE ALERT, WHICH IS HOW THE NODE LEARNS WHICH REFUSAL THIS WAS.
         *
         * NGTCP2_ERR_CRYPTO on its own says only "the TLS stack refused", and ngtcp2 then closes
         * with a code that carries none of the reason. The reference backend exists to close that
         * gap and does nothing else: quictls installs an SSL_QUIC_METHOD whose send_alert hook is
         *
         *     static int send_alert(SSL *ssl, OSSL_ENCRYPTION_LEVEL level, uint8_t alert) {
         *       ngtcp2_crypto_conn_ref *conn_ref = SSL_get_app_data(ssl);
         *       ngtcp2_conn *conn = conn_ref->get_conn(conn_ref);
         *       (void)level;
         *       ngtcp2_conn_set_tls_alert(conn, alert);
         *       return 1;
         *     }             (vendor/ngtcp2/crypto/quictls/quictls.c:1000-1014)
         *
         * ngtcp2 keeps the number and closes with CRYPTO_ERROR — transport error 0x0100|alert — so
         * a pin that did not match leaves as 0x012a and a signature scheme this build cannot verify
         * leaves as 0x012f, which is what any other client would send. We had no such hook at all,
         * so every one of those left as the same thing, and the one place in the exchange where a
         * node can see WHY a client walked away said nothing.
         *
         * Zero is not sent as an alert: alert 0 is close_notify, which is not what any of these is,
         * and lc_qtls leaves the field at zero when it has not refused for a reason of its own. */
        uint8_t alert = lc_qtls_alert(&s->tls);
        if (alert != 0u)
            ngtcp2_conn_set_tls_alert(conn, alert);
        return NGTCP2_ERR_CRYPTO;
    }

    /* THE PEER'S TRANSPORT PARAMETERS, handed on as soon as the data that carried them has been
     * read — which is when the reference reads them. quic-go gives TLS one CRYPTO message at a time
     * and handles the events it produces before the next (vendor/quic-go/connection.go:2027-2033,
     * vendor/quic-go/internal/handshake/crypto_setup.go:239-252), so parameters that do not parse
     * end the connection with TRANSPORT_PARAMETER_ERROR right after EncryptedExtensions, before any
     * Certificate is looked at. They used to be applied only once the server's Finished had been
     * verified and our own Finished had gone out, and a failure then left as a crypto error.
     *
     * ngtcp2's own error is recorded as the TLS error, which its callback returns in place of
     * NGTCP2_ERR_CRYPTO (vendor/ngtcp2/crypto/shared.c:1776-1805); it closes with
     * TRANSPORT_PARAMETER_ERROR, as quic-go does. */
    if (s->tls.params_fresh) {
        s->tls.params_fresh = 0;
        int rv = ngtcp2_crypto_set_remote_transport_params(conn, s);
        if (rv != 0) {
            ngtcp2_conn_set_tls_error(conn, rv);
            return rv;
        }
    }

    if (!s->tls.done)
        return 0;

    /* Announced once. ngtcp2 calls this function again for post-handshake messages — a session
     * ticket, a key update — and repeating the completion would restart timers that have already
     * started. */
    if (ngtcp2_conn_get_handshake_completed(conn))
        return 0;

    ngtcp2_conn_tls_handshake_completed(conn);
    return 0;
}

int ngtcp2_crypto_set_remote_transport_params(ngtcp2_conn *conn, void *tls)
{
    const lc_qshim *s = tls;

    if (s == NULL || s->tls.peer_params == NULL)
        return NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM;

    uint8_t        buf[1280];
    const uint8_t *p = s->tls.peer_params;
    size_t         n = s->tls.peer_params_len;
    ngtcp2_ssize   floored = lc_qtp_floor_idle(p, n, buf, sizeof buf);
    if (floored < 0)
        return NGTCP2_ERR_TRANSPORT_PARAM;
    if (floored > 0) {
        p = buf;
        n = (size_t)floored;
    }

    return ngtcp2_conn_decode_and_set_remote_transport_params(conn, p, n);
}

int ngtcp2_crypto_set_local_transport_params(void *tls, const uint8_t *buf, size_t len)
{
    lc_qshim *s = tls;

    if (s == NULL)
        return -1;

    /* ⚠️ BOTH ARGUMENTS ARE IGNORED, AND THE SIZE CHECK THAT USED TO STAND HERE WAS ON THE WRONG ONE.
     *
     * The guard read `len > sizeof s->local_params`, refusing when NGTCP2'S encoding was longer than
     * our buffer — but `buf` is never read and `len` never used again. What is actually written is
     * re-encoded a few lines down, and that call is bounded by the buffer it writes into, which is
     * the only bound that could matter.
     *
     * So the check could only ever refuse wrongly: ngtcp2's own encoding carries one entry more than
     * ours (max_datagram_frame_size, zeroed below), so it is the LARGER of the two, and the day it
     * crosses 256 bytes this would refuse a handshake that would have encoded and sent perfectly.
     * The refusal has no message and happens before the ClientHello exists, so what a reader would
     * see is a QUIC connection that never sends anything. Unreachable today at roughly a hundred
     * bytes encoded — which is exactly how a guard on the wrong quantity survives. */
    (void)buf;
    (void)len;

    /* Written out again from ngtcp2's own view of them, with one entry left out, rather than copied
     * as handed over.
     *
     * max_datagram_frame_size has to be set on the connection or ngtcp2 refuses every DATAGRAM
     * frame that arrives — it compares each one against the local value and treats anything larger,
     * including anything at all when the value is zero, as a protocol violation. And it must not
     * appear on the wire, because hysteria's client does not put it there:
     * `OmitMaxDatagramFrameSize: true` (vendor/hysteria/core/client/client.go:93), asked for in the
     * same breath as the limit itself (vendor/hysteria/core/client/client.go:92). The client's
     * transport parameters ride in the ClientHello, and an
     * Initial packet is encrypted with keys derived from a connection id sent in the clear — so
     * everything in there is readable by anyone on the path, and one parameter nobody else sends is
     * a mark that survives every other kind of care taken here.
     *
     * The node still sends us datagrams: its own config assumes a client that says nothing can take
     * 1200 bytes — `AssumePeerMaxDatagramFrameSize: protocol.MaxDatagramFrameSize`
     * (vendor/hysteria/core/server/server.go:64). That assumption
     * is the only reason omitting it works, and it is upstream's, not ours — the reference client
     * depends on exactly the same thing.
     *
     * Re-encoded with ngtcp2's own encoder from a copy of ngtcp2's own structure, so what comes out
     * is byte for byte what it handed over, minus the entry that is now zero. */
    ngtcp2_transport_params p = *ngtcp2_conn_get_local_transport_params2(s->conn);
    /* ⚠️ EXCEPT WHILE PARROTING CHROME, which sends it: populateConfig turns
     * OmitMaxDatagramFrameSize off because "Chrome always advertises DATAGRAM support"
     * (vendor/quic-go/config.go:109-114), and marshalChrome writes the entry
     * (vendor/quic-go/internal/wire/transport_parameters_chrome.go:71-73). */
    if (!(s->tls_flags & LC_QTLS_CHROME))
        p.max_datagram_frame_size = 0;

    ngtcp2_ssize n = ngtcp2_transport_params_encode(s->local_params, sizeof s->local_params, &p);
    if (n < 0)
        return -1;
    s->local_params_len = (size_t)n;

    /* ngtcp2 hands these over before the first packet is written, which is the moment the
     * ClientHello has to exist — it carries them in extension 0x0039. Starting the handshake here
     * rather than in lc_qshim_init is what keeps the two in the right order. */
    static const lc_qtls_sink sink = {
        .send = sink_send,
        .rx_secret = sink_rx_secret,
        .tx_secret = sink_tx_secret,
    };
    lc_qtls_sink bound = sink;
    bound.ctx = s;

    return lc_qtls_start(&s->tls, &bound, s->sni, s->local_params, s->local_params_len,
                         s->have_pin ? s->pin : NULL, s->tls_flags);
}

/* Path validation data: eight bytes that must be unguessable and nothing more — no key schedule, no
 * algorithm choice. A peer that could predict them could claim our connection after an address
 * change, which is the whole reason the challenge exists.
 *
 * Two spellings of the same thing, because ngtcp2 kept the older one after wrapping the buffer in a
 * type. Both are provided rather than one, since which a caller uses is its business. */
int ngtcp2_crypto_get_path_challenge_data_cb(ngtcp2_conn *conn, uint8_t *data, void *user_data)
{
    (void)conn;
    (void)user_data;
    return lc_rnd(data, NGTCP2_PATH_CHALLENGE_DATALEN) != 0 ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}

int ngtcp2_crypto_get_path_challenge_data2_cb(ngtcp2_conn *conn, ngtcp2_path_challenge_data *data,
                                              void *user_data)
{
    (void)conn;
    (void)user_data;
    return lc_rnd(data->data, sizeof data->data) != 0 ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
