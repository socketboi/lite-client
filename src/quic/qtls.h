/* TLS 1.3 as QUIC needs it.
 *
 * The same handshake as in src/tls, with three differences that make it a separate module rather
 * than a flag on the existing one:
 *
 *   no records      QUIC carries handshake messages in CRYPTO frames and encrypts packets itself,
 *                   so the record layer is not merely unused — it must not be there.
 *   levels          keys are handed to QUIC as they are derived, per encryption level, instead of
 *                   being installed into a record layer this module owns.
 *   transport       the ClientHello must carry quic_transport_parameters, and a server that does
 *                   not see it refuses the connection.
 *
 * And one simplification worth stating: this handshake is not pretending to be a browser, so it
 * needs no fingerprint table. The ClientHello here is built to be correct, not to be
 * indistinguishable.
 *
 * WHO THE SERVER IS. Two checks, and neither is worth anything alone:
 *
 *   the pin    SHA-256 of the node's leaf certificate, supplied out of band, compared against what
 *              the node presented. Says WHICH key the peer must hold.
 *              `openssl x509 -outform der | sha256sum` on the node produces the value.
 *   the        the signature in CertificateVerify, over the transcript, with that certificate's
 *   signature  private key. Says the peer HAS it.
 *
 * The pin without the signature compares public bytes: a certificate is not a secret, and anyone who
 * has connected to the node once can replay its leaf verbatim. The signature without the pin proves
 * only that whoever answered holds the key for whatever certificate they chose to send. Together
 * they are an identity, and both must pass before the handshake completes.
 *
 * There is deliberately no chain validation and no hostname check. Those answer "which authority
 * vouches for this name", which is a question about the public web; this client already knows
 * exactly which key it expects. Confusing the two is what left the signature unchecked here for a
 * while, with the pin advertised as an identity it could not provide.
 *
 * Without any pin at all the peer is not authenticated: a valid Finished proves only that whoever
 * answered completed an X25519 exchange, which anyone carrying the packets can do. The caller is
 * told which case it got — see peer_pinned — and this module does not decide on the caller's behalf,
 * because refusing to run unpinned would strand every deployment that has not distributed one. */
#ifndef LC_QTLS_H
#define LC_QTLS_H

#include "cert/cert.h"
#include "fp/hello.h"
#include "tls/msg.h"
#include "tls/hkdf.h"
#include "tls/hybrid.h"
#include "tls/kex.h"
#include "tls/transcript.h"

#include <stddef.h>
#include <stdint.h>

/* Encryption levels. The numbering is the one TLS libraries use, which is deliberately NOT ngtcp2's
 * — ngtcp2 orders them initial, handshake, 1-RTT, 0-RTT, and silently treating the two as
 * interchangeable would install handshake keys where application keys belong. The shim maps
 * between them explicitly for that reason.
 *
 * ⚠️ AND THAT ORDER WAS AN ASSERTION WITHOUT A LINE UNTIL NOW, in a header the sieve therefore
 * never opened. It is checkable in one place and it is exactly as stated — the enum is declared
 * in that sequence with no explicit values, so 1-RTT is 2 and 0-RTT is 3 where this file's
 * APPLICATION is 3:
 *
 *     NGTCP2_ENCRYPTION_LEVEL_INITIAL,
 *     NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,
 *     NGTCP2_ENCRYPTION_LEVEL_1RTT,
 *     NGTCP2_ENCRYPTION_LEVEL_0RTT
 *              (vendor/ngtcp2/lib/includes/ngtcp2/ngtcp2.h:2679-2696)
 *
 * So the two numberings agree on 0 and disagree on everything else, and a missing conversion is
 * not a compile error anywhere: both sides are small integers. That is the whole reason the shim
 * converts rather than casts.
 *
 * Initial keys come from the connection ID and are QUIC's business; this module produces the rest. */
typedef enum {
    LC_QTLS_INITIAL = 0,
    LC_QTLS_HANDSHAKE = 2,
    LC_QTLS_APPLICATION = 3,
} lc_qtls_level;

/* A certificate pin is the SHA-256 of the leaf, so it is always this long. */
#define LC_QTLS_PIN 32u

/* The largest handshake message this plane will read, which is the reference's own number.
 * crypto/tls reads a message up to maxHandshake and a Certificate up to maxHandshakeCertificateMsg
 * (vendor/utls/common.go:71-72, vendor/utls/conn.go:1102-1117), and quic-go rides that same reader.
 * On QUIC neither is the bound that bites first, though: quic-go refuses CRYPTO data that reaches past
 * MaxCryptoStreamOffset — sixteen kilobytes, at every encryption level — with CRYPTO_BUFFER_EXCEEDED
 * before crypto/tls sees a byte of it (vendor/quic-go/internal/protocol/params.go:86-88,
 * vendor/quic-go/crypto_stream.go:34-41), and patches/ngtcp2/0012 gives ngtcp2 that number. These two
 * stay as crypto/tls has them, behind the sixteen kilobytes and unreachable, as they are in the
 * reference; they would be the first answer only if that bound went. */
#define LC_QTLS_MAX_MESSAGE     65536u
#define LC_QTLS_MAX_CERTIFICATE 262144u

/* What `suite` holds before the ServerHello names the real one.
 *
 * This used to be "the one suite this client offers", and that was both a fingerprint — no Go client
 * and no browser sends a single suite — and, on hardware without AES instructions, twelve times the
 * cost of the alternative. Three are offered now, in the order the reference sends them (see the
 * ClientHello in qtls.c), and the node chooses.
 *
 * AES-128-GCM stays the value here because QUIC's Initial packets are keyed with it regardless of
 * what the handshake later settles on — RFC 9001 fixes the algorithm — so before the ServerHello
 * this is not a guess but the only thing in use. */
#define LC_QTLS_SUITE 0x1301u

/* What the module hands back to the caller. Secrets go straight to QUIC, which derives packet keys
 * from them with its own labels — this module never sees a packet. */
typedef struct {
    void *ctx;
    int (*send)(void *ctx, lc_qtls_level level, const uint8_t *data, size_t len);
    int (*rx_secret)(void *ctx, lc_qtls_level level, const uint8_t *secret, size_t len);
    int (*tx_secret)(void *ctx, lc_qtls_level level, const uint8_t *secret, size_t len);
} lc_qtls_sink;

/* The flight in the order the reference reads it (GOROOT/src/crypto/tls/handshake_client_tls13.go,
 * readServerParameters, readServerCertificate, readServerFinished).
 *
 * A HelloRetryRequest is not a state of its own: it arrives where the ServerHello is expected, is
 * answered with a second ClientHello, and the ServerHello is expected again — the reference's
 * processHelloRetryRequest (GOROOT/src/crypto/tls/handshake_client_tls13.go:235-412, go1.25.14).
 * The hello shares both groups a hysteria node supports, so a node never sends one; but the first
 * flight is keyed by a connection ID in the clear, so anyone on the path can, and until 2026-09-24
 * this plane stopped where the reference answers. */
enum {
    LC_QX_SERVER_HELLO = 0,
    LC_QX_ENCRYPTED_EXT,
    LC_QX_CERTIFICATE,
    LC_QX_CERT_VERIFY,
    LC_QX_FINISHED,
    LC_QX_DONE,
};

typedef struct {
    lc_qtls_sink  sink;
    lc_hash       hash;
    uint16_t      suite;
    lc_transcript tr;
    int           tr_ready;

    /* The ClientHello, held until the transcript can be started.
     *
     * The transcript hashes with ONE algorithm from the moment it is created, and which algorithm is
     * not known until the ServerHello names a suite: TLS_AES_256_GCM_SHA384 brings SHA-384 with it,
     * every other suite SHA-256. Starting it early — which is what this code did while exactly one
     * suite was on offer — hashed the ClientHello with SHA-256 and then derived 48-byte secrets from
     * a 32-byte snapshot, reading sixteen bytes of stack that nothing had written. Silent: no
     * assertion fires, nothing decrypts, and the node looks unreachable. */
    uint8_t ch[4096];
    size_t  ch_len;
    /* THE SECOND HELLO, after a HelloRetryRequest: the first one with a cookie echoed and the key
     * share replaced, as the reference re-marshals its one hello object
     * (GOROOT/src/crypto/tls/handshake_client_tls13.go:303-351, go1.25.14). On the heap only when
     * it outgrows `ch` — a cookie may run to 64 KiB — and `ch` otherwise; qtls.c reads the hello
     * through hello_bytes() either way. */
    uint8_t *ch_heap;
    int      retried;
    uint16_t retry_suite; /* the suite the retry chose, which the ServerHello must keep */
    uint16_t retry_group; /* the group it named, 0 for a retry that only asked for a cookie */
    uint8_t  retry_priv[LC_P521_KEY];
    /* And the ML-KEM half, when the retry named one of the two hybrids Go 1.26 advertises without
     * sharing — SecP256r1MLKEM768 or SecP384r1MLKEM1024, each an ECDH key in retry_priv plus a
     * decapsulation key here, sized for the larger. */
    uint8_t  retry_dk[LC_MLKEM1024_DK];

    /* Both halves of X25519MLKEM768, because the reference offers that group first and falls back
     * to bare X25519 with the SAME ephemeral. lc_hybrid_key holds the ML-KEM decapsulation key and
     * the X25519 private key together, so one object serves both key shares. */
    lc_hybrid_key hybrid;

    /* ⚠️ AND A SECOND X25519 KEY, BUT ONLY WHILE PARROTING CHROME. The hello uTLS builds from the
     * fork's spec gives the bare X25519 share an ephemeral of its OWN: ApplyPreset generates one
     * key for the hybrid's classical half and another for the X25519 entry, and keeps the second as
     * the key an X25519 answer is decided with (vendor/utls-hy/u_parrots.go:2875-2922). The reuse the
     * paragraph above describes is crypto/tls's, and a key-reuse marker uTLS grew later is not in
     * the version the fork links. */
    uint8_t x25519_priv[LC_X25519_KEY];

    /* Whether this client parrots Chrome: hysteria's default from 2.11, off only with
     * DisableChromeParrot (vendor/hysteria/core/client/client.go:95-103). The hello, its transport
     * parameters and the way the handshake is read all follow uTLS rather than crypto/tls while it
     * is set — each place it decides something names the reference beside it. */
    int chrome;
    /* Where the table put the key shares in the hello, for a retry that has to replace them. */
    lc_hello_out hello_info;
    /* Our EncryptedExtensions answering a server's application settings, owed after its Finished
     * under the parrot — see finish() in qtls.c. */
    uint8_t alps_answer[LC_ALPS_ANSWER_LEN];
    size_t  alps_answer_len;
    /* A CompressedCertificate opened, sized to what it declared. */
    uint8_t *opened;

    uint8_t hs_secret[LC_HASH_MAX];
    uint8_t c_hs[LC_HASH_MAX];
    uint8_t s_hs[LC_HASH_MAX];

    /* Whatever arrived at a level but is not yet a whole message. QUIC delivers CRYPTO frames in
     * order but not in message-sized pieces, and a four-byte header can straddle two of them.
     *
     * The inline buffer takes every flight this client will meet; a message larger than it grows
     * `partial` onto the heap, up to the size the reference reads, so that the number a peer runs
     * into is Go's and not this buffer's — see lc_qtls_recv and LC_QTLS_MAX_MESSAGE. */
    uint8_t  partial_inline[16384];
    uint8_t *partial;
    size_t   partial_cap;
    size_t   partial_len;
    /* The one encryption level handshake data is read at, as the reference's c.in.level: Initial
     * until the ServerHello's keys, Handshake until the server's Finished, application after. Data
     * at any other level is refused — see lc_qtls_recv. */
    lc_qtls_level read_level;

    /* The peer's transport parameters, which arrive inside EncryptedExtensions — on the heap and
     * sized to what came, since the reference takes a parameter block of any size and this used to
     * drop one over a kilobyte without a word, which then failed the handshake later as though the
     * node had sent none. `params_fresh` says they arrived in the data just read, for the shim to
     * hand to ngtcp2 before the next message, which is when quic-go reads them. */
    uint8_t *peer_params;
    size_t   peer_params_len;
    int      params_fresh;

    /* The peer's leaf certificate as it arrived, kept because the pin is checked against it once the
     * flight is complete rather than at the moment it turns up. On the heap and sized to the leaf:
     * the reference reads whatever the peer sent, and a field sized to what it permits would be
     * carried by every connection for a certificate that is under a kilobyte. */
    uint8_t *cert_der;
    size_t   cert_der_len;
    int     cert_seen;
    /* Whether CertificateVerify proved the peer holds that certificate's private key. The pin is
     * refused without it: a hash of public bytes is not an identity. */
    int     cert_verified;

    /* The expected SHA-256 of that certificate, and whether one was given at all. When there is one
     * it must match before the handshake completes; when there is none the peer is unauthenticated
     * and peer_pinned stays clear to say so. */
    uint8_t pin[LC_QTLS_PIN];
    int     have_pin;
    int     peer_pinned;

    /* The message the flight expects next, in the reference's order — LC_QX_*. It replaced a record
     * of which messages had arrived at most once, which stopped a repeat and nothing else: a
     * Certificate before EncryptedExtensions was taken, and EncryptedExtensions followed by Finished
     * completed a handshake with no Certificate at all. A second Certificate is refused by it too,
     * which is what the old record existed for — it used to be able to replace the bytes the pin
     * is compared against while the flag saying "somebody proved they hold this key" stayed set
     * from the first one. */
    uint8_t expect;
    /* Handshake messages read after the handshake, against the reference's limit — see
     * post_handshake in qtls.c. */
    unsigned post_msgs;
    /* The node asked for a certificate; ours is the empty one, sent ahead of our Finished. */
    int      cert_requested;

    /* Set once ServerHello has produced the handshake secrets. Every later message of the flight is
     * checked or interpreted with those secrets, so this flag is the whole of the ordering rule
     * lc_qtls_recv enforces — see the ServerHello case there for what a missing one lets through. */
    int keys_installed;

    int done;

    /* WHY THE HANDSHAKE STOPPED, in the words of whoever stopped it.
     *
     * Every refusal in qtls.c used to be a bare `return -1`, so a connection that ended because the
     * pin did not match, because the node signed with something this build cannot verify, or
     * because a middlebox ate the flight all arrived at the tunnel as the same nothing — and the
     * tunnel printed "no reason recorded, which is what a silent path looks like" for every one of
     * them. That line is true only of the last case, and half a session went into rediscovering
     * which case a real failure had been.
     *
     * FIRST WRITER WINS. A failure cascades — a refused message ends the flight, which ends the
     * connection — and the reason worth keeping is the innermost one, not the outermost. */
    char err[160];
    /* The alert that goes with it. A refusal is two things — a sentence for our log and a number
     * the peer reads — and only the first was produced, so every way our TLS can refuse a node
     * reached the transport as one indistinguishable failure. Kept with the FIRST reason, for the
     * same reason the sentence is. */
    uint8_t alert;
    /* And the reference's own words for it under the Chrome parrot, err.Error() of what uTLS
     * returns, which quic-go closes with as INTERNAL_ERROR (tls/goerr.h). Kept with the FIRST
     * reason too; "" when the refusal has no counterpart there — a failure of our own, out of
     * memory or the like. */
    char go_err[256];
    /* Set when that refusal is a failure of this client's own — out of memory, a key that cannot be
     * derived, a buffer of ours too small — which the reference cannot have: where this client
     * fails, Go has ended the process. The transport then closes as the reference's process does,
     * without a word (see lc_qconn_close). */
    int own;
} lc_qtls;

/* What stopped it, or "" while nothing has. Never NULL. */
const char *lc_qtls_error(const lc_qtls *q);

/* The TLS alert number for that refusal, or 0 when there has not been one. The QUIC transport puts
 * it on the wire as CONNECTION_CLOSE with error 0x0100|alert, which is where a node learns which
 * refusal this was — see the shim. */
uint8_t lc_qtls_alert(const lc_qtls *q);

/* The reference's error text for that refusal under the Chrome parrot, or "" when there is none.
 * Never NULL. */
const char *lc_qtls_go_error(const lc_qtls *q);

/* Whether the refusal was a failure of this client's own; see `own`. */
int lc_qtls_own(const lc_qtls *q);

/* Starts a client handshake and emits the ClientHello through the sink at the initial level.
 * `params` is the encoded quic_transport_parameters body, which QUIC produces.
 *
 * `pin` is LC_QTLS_PIN bytes, or NULL to run without authenticating the node — see the note at the
 * top of this file about what that costs. */
/* LC_QTLS_CHROME in `flags` parrots Chrome, as the reference does unless told not to. */
#define LC_QTLS_CHROME 1u

int lc_qtls_start(lc_qtls *q, const lc_qtls_sink *sink, const char *sni,
                  const uint8_t *params, size_t params_len, const uint8_t *pin, unsigned flags);

/* Feeds handshake bytes received at a level. Returns 0 on success; the handshake is complete when
 * q->done is set. */
int lc_qtls_recv(lc_qtls *q, lc_qtls_level level, const uint8_t *data, size_t len);

void lc_qtls_free(lc_qtls *q);

/* Whether this machine has the assembly GCM Go tests for — see the cipher-suite block in qtls.c,
 * which is where the answer is used and where the four rules it reproduces are cited.
 *
 * ⚠️ THIS LINE USED TO SAY "exported so the gate can compare what the hello carries against what
 * this answers", AND THE GATE DOES NO SUCH THING — qtls.c says so directly, two comments apart:
 * "It is NOT covered by the gate, and could not usefully be", because the only two machines this
 * tree builds on agree, and the case worth asserting is neither of them. A header promising a check
 * that does not exist is worse than silence: the next reader takes the behaviour for verified.
 *
 * It is exported so the answer can be asked for on its own — by a person on a machine in doubt, not
 * by a suite. */
int lc_qtls_aesgcm_hardware(void);

#endif
