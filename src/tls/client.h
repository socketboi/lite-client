/* Driving one TLS 1.3 handshake to completion, optionally with REALITY on top.
 *
 * This is where every piece proved separately gets connected, and it is also the first place that
 * cannot be proved without a server. The pieces are right — key schedule, record layer, transcript,
 * key exchange, message parsing, the REALITY stamp all match their references byte for byte. What
 * only a live server can tell us is whether they are wired together in the right order.
 *
 * The failure mode to keep in mind: with REALITY, a client that is wrong in almost any way does not
 * get an error. The server decides it is a stranger and quietly proxies the real web site, so the
 * handshake succeeds, the certificate is genuine, and nothing looks broken. That is why the result
 * carries `reality_verified` separately from success, and why a probe that reports "connected" has
 * reported nothing. */
#ifndef LC_CLIENT_H
#define LC_CLIENT_H

#include "reality/reality.h"
#include "tls/hkdf.h"
#include "tls/record.h"

#include <stddef.h>
#include <stdint.h>

typedef struct {
    const uint8_t *table; /* fingerprint table */
    size_t         table_len;
    const char    *sni;

    /* When set, the ClientHello is stamped and the server's certificate is authenticated with the
     * REALITY key rather than a certificate chain. */
    int                     use_reality;
    const lc_reality_config *reality;
    uint32_t                 unix_time; /* what the server checks against its clock */
} lc_client_config;

typedef struct {
    /* Application traffic keys, ready for whatever rides on top. */
    lc_record_key rd;
    lc_record_key wr;
    lc_hash       hash;

    /* ⚠️ THE SECRETS THE KEYS CAME FROM OUTLIVE THE HANDSHAKE, for KeyUpdate alone. The reference
     * moves its read key on at one and, when asked, answers and moves its write key on too
     * (vendor/utls/conn.go:1345-1382); each next key comes from the current SECRET
     * (vendor/utls/key_schedule.go:25-27), not from the key, so the secret has to be kept. Wiped by
     * lc_client_free. */
    uint8_t     s_ap[LC_HASH_MAX];
    uint8_t     c_ap[LC_HASH_MAX];
    lc_aead_alg alg;
    size_t      key_len;

    /* Set only when the server proved it holds the REALITY private key. Without REALITY it stays
     * zero and means nothing. */
    int reality_verified;

    /* Kept because the certificate arrives after the stamp and has to be checked against it. */
    uint8_t reality_auth_key[LC_REALITY_AUTH_KEY];

    /* Why authentication did not happen, when it did not. The two cases look identical from outside
     * and have opposite causes: a certificate that is not ours at all means the server decided we
     * were a stranger and served the donor site, while one that is ours but does not verify means
     * the fault is on this side. Without the distinction a failure is unactionable. */
    char reality_note[72];

    /* Where the handshake got to, for a probe to report. */
    char stage[64];
} lc_client;

/* ---- the handshake as a resumable object ------------------------------------
 *
 * The conversation is strictly sequential — send, read, send — but a client that blocks inside it
 * stops being able to do anything else, and on a router "anything else" is every other household
 * device. So the handshake is a state machine that never touches a socket: bytes go in, bytes come
 * out, and whoever owns the descriptor decides when.
 *
 * There is a second reason, found while writing this: the buffers used to be `static`, which is
 * harmless for one handshake at a time and silently corrupts two.
 *
 * It is allocated rather than declared because it carries about 36 KB of buffers — one whole
 * incoming record and its plaintext — which does not belong on a caller's stack. It is freed as
 * soon as the handshake ends, so the cost is per handshake in flight, not per connection.
 *
 * `cfg` is held by pointer copy: the fingerprint table, SNI and REALITY configuration must outlive
 * the handshake. On this client they are program constants, so nothing is duplicated. */
typedef enum {
    LC_HS_WANT_READ,  /* needs bytes from the peer; lc_client_hs_want says how many */
    LC_HS_WANT_WRITE, /* has bytes to send; drain them with lc_client_hs_out */
    LC_HS_OK,         /* complete — and, with REALITY, still say nothing until reality_verified */
    LC_HS_FAILED,
} lc_client_progress;

typedef struct lc_client_hs lc_client_hs;

lc_client_hs *lc_client_hs_new(const lc_client_config *cfg);
void          lc_client_hs_free(lc_client_hs *hs);

/* Advances as far as it can on what it already has. Updates `cl` — including `stage`, which is
 * meaningful after a failure as well. */
lc_client_progress lc_client_hs_step(lc_client_hs *hs, lc_client *cl);

/* How many bytes the machine needs to finish the record it is assembling. Exact rather than a hint,
 * so a blocking caller can ask for precisely that and still tell a clean close from a truncation —
 * a distinction REALITY diagnosis depends on. */
size_t lc_client_hs_want(const lc_client_hs *hs);

/* Hands received bytes to the machine. Returns how many it took, which may be fewer than offered
 * when a read spans the end of the current record. */
size_t lc_client_hs_feed(lc_client_hs *hs, const uint8_t *data, size_t len);

const uint8_t *lc_client_hs_out(const lc_client_hs *hs, size_t *len);
void           lc_client_hs_out_taken(lc_client_hs *hs, size_t n);

const char *lc_client_hs_error(const lc_client_hs *hs);

/* The ClientHello exactly as it went out, stamp included. For diagnosis only: a REALITY failure is
 * invisible by design — the handshake succeeds and the wrong site is served — so the one thing that
 * makes it investigable is keeping the message that failed. */
const uint8_t *lc_client_hs_hello(const lc_client_hs *hs, size_t *len);



/* The ephemeral X25519 private key the stamp was made with. Diagnosis only, and secret: it is what
 * lets a saved failure be replayed against the reference implementation. */
const uint8_t *lc_client_hs_stamp_key(const lc_client_hs *hs);

/* Drives an existing machine to completion on a blocking socket. Separate from the call below so
 * that a caller who wants the machine afterwards — to look at the message that failed — does not
 * have to write the pump a second time and have the two drift apart. */
int lc_client_hs_run(lc_client_hs *hs, lc_client *cl, int fd, uint64_t deadline_ms,
                     char *err, size_t err_cap);

/* Runs the handshake on an already-connected blocking socket: the state machine above with a read
 * and a write around it. Returns 0 when the handshake completed — which, again, is not the same as
 * having reached our server.
 *
 * `err` receives a description of the first thing that went wrong. */
int lc_client_handshake(lc_client *cl, int fd, const lc_client_config *cfg,
                        uint64_t deadline_ms, char *err, size_t err_cap);

/* Seals a close_notify with the application write key into `out`, returning its length (0 if it
 * cannot be built). The caller writes it and then closes.
 *
 * Separate from the closing itself because this file owns no descriptor: the tunnel closes its
 * sockets in one place and needs the bytes, not a socket call. That the bytes exist at all is the
 * point — Go's tls.Conn.Close sends this once the handshake has completed
 * (vendor/utls/conn.go:1457, closeNotify at :1482-1493) and the VLESS outbound closes a REALITY
 * connection through it (`defer conn.Close()`,
 * vendor/Xray-core/proxy/vless/outbound/outbound.go:201), so a connection ending in a bare FIN is
 * one no Xray client produces. */
size_t lc_client_alert_record(lc_client *cl, uint8_t desc, uint8_t *out, size_t cap);
#define LC_CLIENT_ALERT_CLOSE_NOTIFY 0u

/* KeyUpdate, as handleKeyUpdate does it (vendor/utls/conn.go:1345-1382): the read key one
 * generation on; and, when the peer asked, the answer — a KeyUpdate with update_not_requested, the
 * only one the reference ever writes, sealed with the write key still in force — and then the write
 * key one generation on. A generation is the secret through HKDF-Expand-Label "traffic upd", its key
 * and iv, and the sequence number back at zero (nextTrafficSecret and setTrafficSecret,
 * vendor/utls/key_schedule.go:25-27, vendor/utls/conn.go:233-239). The two moves return 0, or -1
 * when a key cannot be built, and then nothing further can be opened or sealed. The record returns
 * its length, 0 when `cap` is short of LC_CLIENT_KEY_UPDATE_MAX. */
int    lc_client_update_read(lc_client *cl);
int    lc_client_update_write(lc_client *cl);
size_t lc_client_key_update_record(lc_client *cl, uint8_t *out, size_t cap);
#define LC_CLIENT_KEY_UPDATE_MAX (LC_REC_HEADER + 5u + 1u + LC_AEAD_TAG)

/* Puts the alert a failed handshake owes on the wire, best effort. Called by the run loop, which is
 * where the descriptor is. */
/* Everything an alert record can be: the header, the two bytes, the inner content type the sealed
 * form appends, and the tag — twenty-four bytes — twice over, since a handshake type the reference
 * does not know draws the alert twice, behind the six-byte dummy ChangeCipherSpec it flushes ahead
 * of an alert once a ServerHello has been taken. Fifty-four in all.
 *
 * Named because the first caller reached for LC_REC_MAX_WIRE — sixteen kilobytes of stack in the
 * event loop for a record that cannot exceed this, in a tree that had already moved a buffer that
 * size OFF the stack for being the largest frame there (see the compressed-certificate arm in
 * client.c). A ceiling that is right by a factor of seven hundred is not a safe default, it is an
 * unread one. */
#define LC_CLIENT_ALERT_MAX (6u + 2u * (LC_REC_HEADER + 2u + 1u + LC_AEAD_TAG))

/* Builds the alert record a failed handshake owes, for a caller that owns the socket and cannot
 * afford to block on it — which is what the tunnel is, and why this exists separately from the
 * function below. `out` needs LC_CLIENT_ALERT_MAX. Returns its length, or 0 when none is owed or
 * the buffer is smaller than that. Once it commits to building, the debt is cleared whether or not
 * the caller manages to write what it gets back: one refusal is one alert, and a caller that
 * retried would send two.
 *
 * One call is ONE WRITE's worth, and a caller writes each result on its own until this returns 0:
 * where the reference sends its alert twice without buffering, those are two writes, and the first
 * call hands out one copy and leaves the second owed. */
size_t lc_client_hs_alert_record(lc_client_hs *hs, uint8_t *out, size_t cap);

void lc_client_hs_send_alert(lc_client_hs *hs, int fd, uint64_t deadline_ms);

/* What the server sent after its Finished in the same record: the start of whatever handshake
 * message comes next, which the reference keeps in c.hand past the end of the handshake and reads
 * the post-handshake messages from (vendor/utls/conn.go:1406-1410) — so a caller hands it to its
 * lc_post as `hand`. Valid until lc_client_hs_free; empty against any real server. */
const uint8_t *lc_client_hs_leftover(const lc_client_hs *hs, size_t *len);

void lc_client_free(lc_client *cl);

#endif
