/* What a TLS 1.3 client makes of the records its server sends once the handshake is over, decided
 * the way the REALITY plane's reference decides it: uTLS's readRecordOrCCS
 * (vendor/utls/conn.go:612-791) and UConn's handlePostHandshakeMessage
 * (vendor/utls/u_conn.go:957-984) — the copy UConn.Read calls (vendor/utls/u_conn.go:874-883), the
 * same as tls.Conn's (vendor/utls/conn.go:1316-1343) — under the configuration Xray's REALITY client
 * runs with (vendor/Xray-core/transport/internet/reality/reality.go:151).
 *
 * Every refusal there sends an alert and ends the read, and the outbound then closes the
 * connection, which sends close_notify behind it. Several of them answer bytes anybody on the path
 * can write — a record header, a record that does not open, a ChangeCipherSpec, which is never
 * encrypted — so what the client says back is visible without a key. The rest take the server's
 * key, and a stock node does not produce them; they are decided here all the same, because the
 * reference decides them.
 *
 * This file decides; the caller owns the socket, seals the alert and ends the connection. What each
 * decision is was run against the reference itself: tools/vendorcap/nodealert puts a stock REALITY
 * node in front of Xray's own client and of lc-tunnel, one misbehaviour per connection, and compares
 * what each says back. test/post holds the same cases to this file. */
#ifndef LC_TLS_POST_H
#define LC_TLS_POST_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    /* c.retryCount: records in a row that moved nothing — empty application data, post-handshake
     * messages. More than `maxUselessRecords` (32, vendor/utls/common.go:73) is refused. */
    unsigned useless;
    /* c.hand: the start of a handshake message whose end has not arrived. Allocated only while one
     * is pending, which against a stock node is never. */
    uint8_t *hand;
    size_t   hand_len;
    /* What a KeyUpdate does, called at the message, in the order the messages came — the ones after
     * it in the same record were opened with the old key and are read as they are, which is what the
     * reference does with what is already in c.hand. `update_requested` is its one field. 0 to go
     * on; anything else ends the connection with no alert. Left NULL, a KeyUpdate ends it too. */
    int  (*key_update)(void *ctx, int update_requested);
    void *ctx;
    /* The connection is TLS 1.2 (T3): the server answered the hello with it. Its alerts have levels,
     * a handshake message after the handshake is a renegotiation, and a record may be longer — see
     * each function. Set by the caller when the handshake completes. */
    int tls12;
} lc_post;

enum {
    LC_POST_TAKEN = 0, /* nothing for the caller: an empty record, a session ticket */
    LC_POST_DATA,      /* application data with bytes in it */
    LC_POST_CLOSED,    /* the server's close_notify: the end of its stream (io.EOF) */
    LC_POST_ENDED,     /* the connection ends and no alert is owed: the server's own alert */
    LC_POST_REFUSED,   /* `*alert` is owed, then the end */
    LC_POST_TWICE,     /* the same, with the alert sent twice — see lc_hs_utls_knows */
    LC_POST_NOMEM = -1,
};

/* The five bytes in front of a record, before its body is waited for (vendor/utls/conn.go:653-679):
 * a version other than 0x0303 is protocol_version, a length over 2^14 + 256 record_overflow. */
int lc_post_header(const lc_post *p, const uint8_t hdr[5], uint8_t *alert, const char **why);

/* A ChangeCipherSpec, `body` its `n` bytes. Passed through undecrypted (vendor/utls/conn.go:347-351)
 * and always refused, with one of three numbers. */
int lc_post_ccs(const lc_post *p, const uint8_t *body, size_t n, uint8_t *alert, const char **why);

/* A record that opened: `plain` its content, `inner` its true type. */
int lc_post_record(lc_post *p, const uint8_t *plain, size_t len, uint8_t inner, uint8_t *alert,
                   const char **why);

void lc_post_free(lc_post *p);

#endif
