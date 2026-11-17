/* REALITY, client side.
 *
 * The whole protocol is forty lines of arithmetic on top of a TLS 1.3 handshake, and every one of
 * them happens at a moment no TLS library offers: after the ClientHello has been serialised and
 * before it is sent.
 *
 * What happens:
 *
 *   1. session_id — thirty-two bytes nobody else looks at — is overwritten with an authenticated
 *      payload: the client version, a timestamp and a short id shared with the server.
 *   2. The key that protects it comes from a SECOND X25519 exchange, performed with the SAME
 *      ephemeral key already sitting in key_share, against the server's static REALITY key. Only a
 *      server holding that key can derive it.
 *   3. The whole ClientHello — with session_id zeroed — is the associated data. Any middlebox that
 *      rewrites a single byte of the hello destroys the tag, and the server falls back to being an
 *      ordinary web site.
 *
 * To anyone watching, the result is a normal browser hello to a normal site, and the connection to
 * the wrong password is a normal connection to that site. That is the entire idea, and it is also
 * why every step here is byte-exact or worthless. */
#ifndef LC_REALITY_H
#define LC_REALITY_H

#include <stddef.h>
#include <stdint.h>

#define LC_REALITY_KEY 32u       /* the server's static public key */
#define LC_REALITY_SHORT_ID 8u   /* shared out of band, in the subscription */
#define LC_REALITY_AUTH_KEY 32u
#define LC_REALITY_SESSION_ID 32u
#define LC_REALITY_VERSION_MAJOR 26u
#define LC_REALITY_VERSION_MINOR 11u
#define LC_REALITY_VERSION_PATCH 9u

typedef struct {
    uint8_t public_key[LC_REALITY_KEY];
    uint8_t short_id[LC_REALITY_SHORT_ID];
    uint8_t version[3]; /* what the server compares against its min/max client version */
} lc_reality_config;

/* Stamps a serialised ClientHello in place.
 *
 * `hello` is the handshake message, header included; `sid_off` is where its session_id starts —
 * the fingerprint builder reports it rather than assuming the usual 39, because a fingerprint with
 * a different session_id length would move it.
 *
 * `x25519_priv` must be the private half of the X25519 key already present in key_share. Not a
 * fresh one: the server recovers the public half from the hello and expects the same key on both
 * sides of the exchange.
 *
 * `unix_time` is what the server MAY check against its own clock, and the "may" is the whole of it:
 * the test is `config.MaxTimeDiff == 0 || time.Since(hs.c.ClientTime).Abs() <= config.MaxTimeDiff`
 * (vendor/REALITY/tls.go:274), and MaxTimeDiff is zero unless an operator set maxTimeDiff by hand —
 * so against an ordinary node the timestamp is carried and never examined. This used to say a
 * router with no clock "will be refused … a real failure mode", which overstated it into a rule.
 *
 * Nothing is validated here and nothing should be: the reference client passes time.Now().Unix()
 * and has no notion of a clock too wrong to use
 * (vendor/Xray-core/transport/internet/reality/reality.go:172). Inventing a threshold would be
 * inventing a rule upstream does not have. What the
 * caller CAN do, and lc-tunnel does, is say the stamp out loud when it is obviously pre-NTP, so
 * that a refusal by a node which does set maxTimeDiff — and a REALITY refusal is silence, not an
 * error — can be told apart from the several other things that look exactly like it.
 *
 * `auth_key` is returned because the certificate check needs it. */
int lc_reality_stamp(uint8_t *hello, size_t hello_len, size_t sid_off,
                     const lc_reality_config *cfg,
                     const uint8_t *x25519_priv, uint32_t unix_time,
                     uint8_t auth_key[LC_REALITY_AUTH_KEY]);

/* Authenticates the server from its certificate: the signature field must equal HMAC-SHA512 over
 * the certificate's public key, keyed with the authentication key.
 *
 * A failure here does NOT mean a broken connection — it means the server did not know the key, so
 * what answered is the real web site or something pretending to be it. RFC-shaped certificate
 * checking has no part in this. */
int lc_reality_verify_cert(const uint8_t auth_key[LC_REALITY_AUTH_KEY],
                           const uint8_t *public_key, size_t public_key_len,
                           const uint8_t *signature, size_t signature_len);

#endif
