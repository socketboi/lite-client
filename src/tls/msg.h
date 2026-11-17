/* Handshake messages: framing, the fields the client actually reads, and Finished.
 *
 * Only what a REALITY client needs is parsed. ServerHello decides the cipher suite and carries the
 * server's key share; the rest of the flight is walked to reach Certificate and Finished. Nothing
 * here validates a certificate chain, because REALITY does not use one — authentication is an HMAC
 * over the server's static key, and the chain is a decoy meant for whoever is watching.
 *
 * The framing matters more than it looks. Messages are delimited by their own four-byte header, not
 * by records: one record can hold several messages and one message can span records. Code that
 * assumes otherwise works against most servers and fails against some, which is the worst possible
 * distribution of outcomes. */
#ifndef LC_MSG_H
#define LC_MSG_H

#include "tls/hkdf.h"

#include <stddef.h>
#include <stdint.h>

/* Handshake message types the client meets. */
#define LC_HS_CLIENT_HELLO       0x01u
#define LC_HS_SERVER_HELLO       0x02u
#define LC_HS_NEW_SESSION_TICKET 0x04u
#define LC_HS_ENCRYPTED_EXT      0x08u
#define LC_HS_CERTIFICATE        0x0bu
/* RFC 8446 §4.3.2. A server that wants a client certificate sends this between EncryptedExtensions
 * and its own Certificate. This client has no certificate to send, which is not the same as having
 * nothing to say: the reference answers with an EMPTY Certificate message and no CertificateVerify
 * (vendor/utls/handshake_client_tls13.go:873-914), and a client that answers with nothing at all is
 * a client the server can tell apart from every other. */
#define LC_HS_CERTIFICATE_REQUEST 0x0du
#define LC_HS_CERTIFICATE_VERIFY 0x0fu
/* RFC 8879. The hello this client sends invites the server to use it, and the arm in tls/client.c
 * reads it — inflated by tls/certcomp with zlib, brotli or zstd, whichever the server chose — and
 * then treats it as the Certificate it stands for. */
#define LC_HS_COMPRESSED_CERTIFICATE 0x19u
#define LC_HS_FINISHED           0x14u
/* The four TLS 1.2 adds to what a client reads and writes (T3): ServerKeyExchange, ServerHelloDone,
 * ClientKeyExchange and CertificateStatus (vendor/utls/common.go:78-102). */
#define LC_HS_SERVER_KEY_EXCHANGE 0x0cu
#define LC_HS_SERVER_HELLO_DONE   0x0eu
#define LC_HS_CLIENT_KEY_EXCHANGE 0x10u
#define LC_HS_CERTIFICATE_STATUS  0x16u
/* RFC 8446 §4.6.3. The one post-handshake message that ENDS a connection this client cannot save:
 * whoever sends a KeyUpdate rotates its own write key immediately afterwards, so a client that
 * ignores one cannot open anything that follows. Named here so the record path can say that rather
 * than die of a bad tag three records later — see deliver_record in cmd/lc-tunnel. */
#define LC_HS_KEY_UPDATE         0x18u

/* A cursor over a run of handshake messages. */
typedef struct {
    const uint8_t *p;
    size_t         len;
    size_t         off;
} lc_msg_reader;

void lc_msg_reader_init(lc_msg_reader *r, const uint8_t *buf, size_t len);

/* Yields the next message: its type, its body, and the whole message including the header — the
 * last because the transcript hashes messages as sent, headers included.
 * Returns 1 on a message, 0 at the end, -1 on a malformed one. */
int lc_msg_next(lc_msg_reader *r, uint8_t *type,
                const uint8_t **body, size_t *body_len,
                const uint8_t **whole, size_t *whole_len);

/* What the client takes out of ServerHello. */
typedef struct {
    uint16_t       cipher_suite;
    /* key_share in the ServerHello's form: the group, then the share. */
    uint16_t       group;
    const uint8_t *key_share;  /* points into the message */
    size_t         key_share_len;
    const uint8_t *random;     /* 32 bytes, points into the message */
    /* legacy_session_id_echo, which the caller must compare with the id it sent — the parser cannot,
     * having never seen the hello. `if !bytes.Equal(hs.hello.sessionId, hs.serverHello.sessionId)`
     * is an illegal_parameter alert in the reference (vendor/utls/handshake_client_tls13.go:211-214)
     * and matters here beyond conformance: on the REALITY plane the session id is where this client
     * puts its authenticator, so an echo that differs is a peer that did not receive what we sent. */
    const uint8_t *session_id;  /* points into the message */
    size_t         session_id_len;
    int            is_hello_retry;
    /* A cookie the retry wants echoed back, pointing into the message like every other field
     * here. RFC 8446 4.2.2 declares it `opaque cookie<1..2^16-1>`, so the INNER two-byte length is
     * the one that means anything and the extension_data length only frames it; a parse that took
     * the outer one would echo two bytes of length as though they were cookie.
     *
     * Bytes rather than the flag this used to be, because the second hello has to carry it
     * VERBATIM and a flag cannot say what to carry. */
    const uint8_t *cookie;
    size_t         cookie_len;

    /* WHAT THE VERDICT READS. The parse records these and never refuses on them, because the
     * reference refuses none of them while it is still reading the message: serverHelloMsg.unmarshal
     * takes the whole message first (vendor/utls/handshake_messages.go:909-1036), and only then do
     * pickTLSVersion and checkServerHelloOrHRR look at what it said. See lc_check_server_hello.
     *
     * `version` is supported_versions, zero when the extension is absent — and zero when it is
     * present and says zero, which Go cannot tell apart either: `if serverHello.supportedVersion
     * != 0` is its whole test (vendor/utls/handshake_client.go:545-548). */
    uint16_t legacy_version;
    uint16_t version;
    uint8_t  compression;
    /* One of the six a TLS 1.3 ServerHello may not carry (vendor/utls/handshake_client_tls13.go:200-209). */
    uint8_t  forbidden;
    /* pre_shared_key was present: Go's `selectedIdentityPresent`. */
    uint8_t  psk;
    /* encrypted_client_hello was present, whatever it held: unmarshal copies any body, and the retry
     * path refuses the extension for being there (vendor/utls/handshake_client_tls13.go:303-306). */
    uint8_t  ech;
    /* key_share in the HelloRetryRequest's form, a bare group. Go reads the two forms into two
     * fields — `selectedGroup` when the body is two bytes, `serverShare` otherwise — and leaves it
     * to the handshake to refuse the wrong one for the message it is in. */
    uint16_t selected_group;

    /* WHAT TLS 1.2 READS OUT OF IT, when that is what the server chose (T3): the five fields
     * processServerHello and the handshake after it look at (vendor/utls/handshake_client.go:912-997,
     * :1055-1078), all recorded by the parse above and none of them judged there. */
    uint8_t        ocsp;    /* status_request: a CertificateStatus may follow the Certificate */
    uint8_t        ticket;  /* session_ticket: a NewSessionTicket comes before the server's Finished */
    uint8_t        ems;     /* extended_master_secret */
    uint8_t        reneg;   /* renegotiation_info was present, and `reneg_len` is what it held */
    size_t         reneg_len;
    const uint8_t *alpn;    /* the protocol chosen, pointing into the message; NULL for none */
    size_t         alpn_len;
    /* Set by lc_check_server_hello when the server chose TLS 1.2 and nothing before the TLS 1.3
     * checks refused it: the handshake goes on as hs12.handshake() (vendor/utls/u_handshake_client.go:
     * 569-579), and those checks are not the ones it makes. */
    int            tls12;

    /* WHY IT WAS REFUSED, when it was — always set, never NULL after a failed parse.
     *
     * Carried in the struct rather than through the signature so that the four callers and four
     * tests keep the call they have. The reason exists because the one sentence this refusal used to
     * produce, "the ServerHello does not parse", is wrong for the case that actually happens: a
     * server that only does TLS 1.2 sends a perfectly well-formed ServerHello and the message sends
     * whoever reads it looking for a corrupt field. Found on the live web — mail.ru, TLS 1.2 only,
     * one refusal out of twenty-two sites probed on 2026-08-18. Refusing it is right and is what a
     * 1.3-only client must do; saying it does not parse is not. */
    const char *why;

    /* And what the reference's error says, for the QUIC plane under the Chrome parrot, where it
     * becomes the reason of the CONNECTION_CLOSE (tls/goerr.h); NULL where uTLS never reaches the
     * check. go_buf holds it when it has numbers in it. */
    const char *go;
    char        go_buf[80];

    /* AND THE NUMBER THE PEER READS, which is the half that was missing entirely.
     *
     * Every one of these refusals ends the handshake, and until now it ended with nothing on the
     * wire: phase_server_hello called hs_fail and no alert was ever raised, so the peer saw a TCP
     * close where uTLS sends a named one. The reference sends five different alerts from the
     * equivalent block (vendor/utls/handshake_client_tls13.go:185-219) and unexpected_message for a
     * message that does not unmarshal at all (vendor/utls/conn.go:1185-1186) — and this client
     * ALREADY raised illegal_parameter on the three checks of the same phase that lived in client.c:
     * the session id echo, a suite that is not TLS 1.3, a suite that was not offered. Three branches
     * of one decision spoke and five did not. All of them are in lc_check_server_hello now.
     *
     * That difference is a prober's whole job: inject an anomalous ServerHello and tell a Go client
     * from this one by whether alert 47 comes back or the socket merely dies. Set on every failure,
     * beside the sentence, so the two cannot drift apart. */
    uint8_t alert;

    /* Set by lc_check_server_hello once the reference's pickTLSVersion would have succeeded — the
     * moment it sets `c.vers` (vendor/utls/handshake_client.go:557) — whether or not a later check
     * refuses the hello. The record an alert goes out in reads it: 0x0301 before, 0x0303 after. */
    int vers_settled;
} lc_server_hello;

/* Parses a ServerHello body — the shape only. 0 when it parsed; -1 with `why` and `alert` set when
 * it did not, and the alert is then always unexpected_message, the reference's answer to a message
 * that does not unmarshal (vendor/utls/conn.go:1185-1186). What the message says is judged by
 * lc_check_server_hello, which every caller runs next. */
int lc_parse_server_hello(const uint8_t *body, size_t len, lc_server_hello *out);

/* What this client sent, which is half of what the verdict compares. Read out of the ClientHello
 * itself by lc_sh_expect_from_hello rather than assembled by each caller, so the TLS and QUIC planes
 * cannot come to judge the same ServerHello against different ideas of their own hello. */
#define LC_SH_MAX_SHARES 8u
typedef struct {
    const uint8_t *session_id;
    size_t         session_id_len;
    const uint8_t *suites; /* the cipher_suites vector, two bytes each */
    size_t         suites_len;
    /* The lowest version supported_versions offers, GREASE aside — which is the bottom of the
     * reference's range: uTLS takes MinVersion from that list when the spec names none
     * (vendor/utls/u_conn.go:696-755), and the Firefox spec names the same number
     * (vendor/utls/u_parrots.go:1547-1550). The top is 1.3 on both planes. */
    uint16_t       min_version;
    uint16_t       shares[LC_SH_MAX_SHARES]; /* the groups key_share carries, GREASE included */
    unsigned       share_count;
    /* The caller's: a HelloRetryRequest has been answered, so this is the second ServerHello, and
     * `retry_suite` is what the retry chose. */
    int            retried;
    uint16_t       retry_suite;
    /* The caller's too: which library the plane's reference is. The TLS plane's is uTLS, inside
     * Xray's REALITY client; the QUIC plane's is Go's own crypto/tls, which hysteria is built with
     * (go1.25.14 in the vendored binaries, go1.26.6 on the stand) — and the two part ways on two
     * numbers in this path. The fork kept unexpected_message for a message that does not unmarshal
     * and illegal_parameter for a compression method; the standard library sends decode_error for
     * both (GOROOT/src/crypto/tls/conn.go:1185-1186 and
     * GOROOT/src/crypto/tls/handshake_client_tls13.go:199-201, go1.25.14). */
    int            stdlib;
} lc_sh_expect;

/* Fills `ex` from a ClientHello handshake message, header included, leaving `retried` and
 * `retry_suite` zero. -1 when our own hello does not parse, which is this client being wrong about
 * itself and owes the peer internal_error. */
int lc_sh_expect_from_hello(const uint8_t *hello, size_t len, lc_sh_expect *ex);

/* The reference's verdict on a ServerHello that parsed, in the reference's order: pickTLSVersion
 * and the downgrade canary on the first hello, checkServerHelloOrHRR on every one, then
 * processHelloRetryRequest or processServerHello. 0 when the handshake may go on; -1 with `why` and
 * `alert` set when it may not.
 *
 * What it does NOT decide, because it needs more than the two messages: whether a group the retry
 * names is one this build can key, and whether the share the server sent is a valid point. Both
 * callers ask those next, and the reference's answer to both is illegal_parameter, the same as the
 * checks here that come immediately before them. */
int lc_check_server_hello(lc_server_hello *sh, const lc_sh_expect *ex);

/* Computes verify_data for Finished: HMAC over the transcript with a key expanded from the traffic
 * secret. Writes lc_hash_len(h) bytes. */
int lc_finished_verify_data(lc_hash h, const uint8_t *traffic_secret,
                            const uint8_t *transcript_hash, uint8_t *out);

/* Checks a received Finished body against the expected verify_data, in constant time — a leaky
 * comparison here would tell an attacker how much of a forged tag was right. */
int lc_finished_check(lc_hash h, const uint8_t *traffic_secret,
                      const uint8_t *transcript_hash,
                      const uint8_t *body, size_t body_len);

/* application_layer_protocol_negotiation. Lived as three identical #defines — here, in tls/client.c
 * and in quic/qtls.c — until the two planes were made to read the field the same way. */
#define EXT_ALPN 0x0010u

/* The one protocol name a server's ALPN extension body names: 0 and the name, or -1 when the body
 * does not have the shape the reference requires.
 *
 * That shape is `encryptedExtensionsMsg.unmarshal` (vendor/utls/handshake_messages.go:1125-1135): a
 * non-empty list, exactly one uint8-prefixed name, the name non-empty, and nothing left over. A
 * body failing any of it makes unmarshal return false, which the caller answers with
 * unexpected_message on the TLS plane and decode_error on the QUIC one — the alert is the caller's
 * to choose, the shape is not.
 *
 * Shared because BOTH planes read this field and each had its own copy of the arithmetic. The
 * copies agreed, which is the dangerous kind: a client whose two planes drift on the same wire
 * shape is one that behaves differently depending on which protocol carried it, and nothing would
 * have said so. */

/* The eight bytes of the empty Certificate message a client sends when asked for one and holding
 * none — see tls/msg.c. */
extern const uint8_t lc_empty_certificate[8];
int lc_alpn_selected(const uint8_t *body, size_t len, const uint8_t **name, size_t *name_len);

/* Whether a CertificateRequest body has the shape certificateRequestMsgTLS13.unmarshal demands —
 * the same in uTLS and in the standard library (vendor/utls/handshake_messages.go, beside the
 * uTLS-only `original`): an empty request context, one two-byte-prefixed extension block that ends
 * the message, status_request and SCT with no body, the two signature-algorithm lists non-empty
 * and of whole schemes, certificate_authorities a non-empty list of non-empty names, anything else
 * stepped over, and no repeat check. 1 when it parses. Each plane answers a failure with its own
 * reference's number for a message that does not unmarshal. */
int lc_cert_request_parses(const uint8_t *body, size_t len);

/* A handshake type the REALITY plane's reference has a message for: the cases of
 * unmarshalHandshakeMessage (vendor/utls/conn.go:1125-1185) and the two uTLS adds through
 * utlsHandshakeMessageType (vendor/utls/u_conn.go:826-839). A type it does NOT know draws
 * unexpected_message TWICE — that hook sends one from its own default case and returns the error to
 * the switch it was called from, whose default sends another (vendor/utls/u_conn.go:836-837, then
 * vendor/utls/conn.go:1184), and sendAlertLocked marks the connection broken without stopping the
 * next write. So a peer that sends type 7 reads two alert records back from every uTLS client, in
 * the handshake and after it alike. */
int lc_hs_utls_knows(uint8_t type);

/* What to answer an EncryptedExtensions with: 0 to accept it, or the alert to send — uTLS's
 * verdict on the whole message, see tls/msg.c. `hello` is our own ClientHello, which is where
 * the offered ALPN list is read from, the same place the reference reads it
 * (`checkALPN(hs.hello.alpnProtocols, ...)`, vendor/utls/handshake_client_tls13.go:639-646).
 *
 * Exposed because the message it judges arrives under the handshake keys: a test reaching it
 * through the machine would have to derive them, and would then be measuring the harness rather
 * than the rule. */
/* The body of extension `type` in one of our own ClientHellos, or NULL when it carries none — what
 * the reference reads back off the hello it sent, such as the ALPN list checkALPN compares against
 * and the algorithms a compressed certificate may use. */
const uint8_t *lc_ch_ext(const uint8_t *hello, size_t len, uint16_t type, size_t *out_len);

uint8_t lc_utls_ee_alert(const uint8_t *hello, size_t hello_len, const uint8_t *body,
                         size_t body_len, int quic);

/* Whether uTLS's readHandshake reads an EncryptedExtensions body, and a CompressedCertificate body:
 * 1 when the message unmarshals, whatever it then says. The QUIC plane asks this of a message out
 * of place, which uTLS unmarshals before it looks at the type. */
int lc_utls_ee_reads(const uint8_t *body, size_t body_len);
int lc_utls_certcomp_reads(const uint8_t *body, size_t body_len);

/* The EncryptedExtensions of our own that answers a server's application settings, sent after the
 * server's Finished — see tls/msg.c. Written into `out` for an EncryptedExtensions that carried
 * ALPS, returning its length; 0 when it carried none. `body` is a message lc_utls_ee_alert has
 * accepted. Exposed for the same reason as that one. */
#define LC_ALPS_ANSWER_LEN 10u
size_t lc_utls_alps_answer(const uint8_t *body, size_t body_len, uint8_t out[LC_ALPS_ANSWER_LEN]);

/* How large a buffer a CompressedCertificate body is opened into: the uncompressed length it
 * declares — up to the sixteen megabytes three bytes can say, as the reference allocates it — or 0
 * for a body too short to say one (lc_certcomp_open then refuses it). */
size_t lc_utls_certcomp_want(const uint8_t *body, size_t body_len);

/* What a Certificate message has earned: 0 to go on with, unexpected_message for one that does not
 * parse, decode_error for a well-formed one carrying no certificates, bad_certificate for one
 * carrying a certificate that is not X.509 or an RSA key over 8192 bits — in that order. Exposed
 * for the suite that pins them apart — see tls/msg.c. */
uint8_t lc_utls_cert_msg_alert(const uint8_t *body, size_t body_len);

#endif
