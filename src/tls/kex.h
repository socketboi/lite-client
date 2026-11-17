/* Key exchange for the REALITY handshake.
 *
 * Two groups matter and they are not interchangeable. X25519 is the classical half. X25519MLKEM768
 * is the hybrid the current fingerprints put FIRST in key_share, and REALITY needs it: with a
 * fingerprint that cannot offer a TLS 1.3 key share the handshake does not happen at all.
 *
 * The client also needs something no TLS library exposes: the ephemeral private key, before the
 * hello is sent. REALITY performs a SECOND exchange with the same key — against the server's static
 * REALITY key — and derives its authentication payload from the result. That is why key generation
 * lives here in the open rather than behind a handshake API. */
#ifndef LC_KEX_H
#define LC_KEX_H

#include <stddef.h>
#include <stdint.h>

#define LC_X25519_KEY 32u
#define LC_X25519_SHARED 32u

/* ⚠️ EVERY FUNCTION HERE TAKES FIXED-SIZE ARRAYS, AND IN C THAT DECIDES NOTHING — the length is the
 * CALLER's guarantee, and this is the one place that says who gives it. Written once because the
 * sieve has now raised the same false finding five times against five different files: "reads the
 * peer's coordinate without checking the length, unlike the reference". The reference checks it
 * because its reader is the parser (`if (plen != ilen) return MBEDTLS_ERR_ECP_BAD_INPUT_DATA`,
 * vendor/mbedtls/library/ecp.c:780-783); ours is not, and a file read alone cannot show the
 * difference.
 *
 * Three callers, and each refuses a wrong length before it gets here:
 *   tls/client.c:217   the pair (group, key_share_len) on the REALITY plane
 *   quic/qtls.c:986    the same pair on the QUIC plane, both halves checked together
 *   tls/hybrid.c       the hybrid's own split, itself guarded by LC_HYBRID_CT above it
 *
 * That placement is this tree's habit rather than an accident: the guard belongs where the byte
 * count is known, which is the parser, and the reference puts it in the consumer instead. Naming
 * the places is cheaper than arguing it again — and it is what the next reader, human or judge,
 * needs to see. */

/* TLS supported-group codepoints. Defined once here because three files place them — the TCP
 * handshake, the QUIC handshake and the fingerprint builder — and a fourth-hand copy of a protocol
 * constant is the kind that gets "corrected" in isolation and diverges silently. These are also the
 * only groups this build can produce a key for; a new entry means new key-exchange code below.
 *
 * ⚠️ AND THE ADVERTISED LIST IS LONGER THAN THIS ONE, which the first version of this note got
 * wrong: it said these three go on the wire "twice each, once in supported_groups and once as the
 * key_share entry". They do not. supported_groups is carried in the fingerprint table as literal
 * bytes, and the shipped one names FIVE — 0x11ec, 0x001d, 0x0017, 0x0018, 0x0019 — so secp384r1 and
 * secp521r1 are advertised and have no constant here on purpose: nothing generates a key for them.
 * Advertising a group without offering its key share is what the reference does too, and it is why
 * `lc_fpt_caps` lists only what this build can KEY rather than what it can name; test/fphello holds
 * the whole list to uTLS byte for byte. The error was found by the sieve asking why CurveP384 was
 * missing — the code was right and the sentence was wrong, which is the failure this file exists to
 * make impossible for numbers.
 *
 * The three below are the ones a key_share entry can be built for. The reference writes them in
 * decimal, which is the one detail worth having written down, because a hex-to-decimal slip here
 * produces a hello that is well-formed and wrong:
 *
 *     CurveP256      CurveID = 23
 *     X25519         CurveID = 29
 *     X25519MLKEM768 CurveID = 4588
 *                        (vendor/utls/common.go:152-161)
 *
 * 23 is 0x0017, 29 is 0x001d, 4588 is 0x11ec. */
#define LC_GROUP_X25519 0x001du
#define LC_GROUP_SECP256R1 0x0017u
#define LC_GROUP_SECP384R1 0x0018u
#define LC_GROUP_SECP521R1 0x0019u
#define LC_GROUP_X25519MLKEM768 0x11ecu
/* The two hybrids Go 1.26 added, advertised by a Hysteria2 client that does not parrot Chrome:
 *
 *     X25519MLKEM768     CurveID = 4588
 *     SecP256r1MLKEM768  CurveID = 4587
 *     SecP384r1MLKEM1024 CurveID = 4589
 *                        (GOROOT/src/crypto/tls/common.go:153-155, go1.26.6)
 *
 * 4587 is 0x11eb, 4589 is 0x11ed. */
#define LC_GROUP_SECP256R1MLKEM768 0x11ebu
#define LC_GROUP_SECP384R1MLKEM1024 0x11edu

/* Generates an ephemeral X25519 key pair. Both buffers are LC_X25519_KEY bytes. */
int lc_x25519_keygen(uint8_t priv[LC_X25519_KEY], uint8_t pub[LC_X25519_KEY]);

/* Derives the public key of a given private key. Needed because a REALITY client keeps the private
 * half around after the hello and has to be able to prove what it sent. */
int lc_x25519_public(const uint8_t priv[LC_X25519_KEY], uint8_t pub[LC_X25519_KEY]);

/* X25519 scalar multiplication. Returns non-zero on the all-zero output, which RFC 7748 requires
 * be treated as an error rather than used as a shared secret. */
int lc_x25519(const uint8_t priv[LC_X25519_KEY], const uint8_t peer[LC_X25519_KEY],
              uint8_t shared[LC_X25519_SHARED]);

/* secp256r1, present in every browser key_share alongside the modern groups.
 *
 * The client will almost never use it — servers pick the first group they support, and that is the
 * post-quantum hybrid — but it has to be a real point on the curve regardless. A key share filled
 * with something that is not a valid point is detectable by anyone who bothers to check, and being
 * detectable is the only failure this client cannot afford. */
#define LC_P256_KEY 32u
#define LC_P256_POINT 65u /* uncompressed: 0x04 || X || Y */
#define LC_P256_SHARED 32u

int lc_p256_keygen(uint8_t priv[LC_P256_KEY], uint8_t point[LC_P256_POINT]);
int lc_p256_shared(const uint8_t priv[LC_P256_KEY], const uint8_t peer[LC_P256_POINT],
                   uint8_t shared[LC_P256_SHARED]);

/* ⚠️ AND THE TWO CURVES THE SHIPPED FINGERPRINT NAMES WITHOUT KEYING, added 2026-08-29 because
 * their absence had a cost that was not obvious: `supported_groups` advertises 0x0018 and 0x0019
 * (see the note above), and a server — or a probe — may answer with either. Without a key exchange
 * behind them the only possible answer was to refuse, which is what made the HelloRetryRequest debt
 * unclosable: a retry naming secp384r1 would have landed back on the same refusal after all the
 * machinery of a second hello.
 *
 * Field sizes are RFC 8446 §4.2.8.2: the uncompressed point is 1 + 2*field, and the shared secret
 * is the x-coordinate alone. P-521's field is 521 bits, which is 66 bytes with one bit used in the
 * top one — not 65, and that is the arithmetic worth writing down rather than deriving twice.
 *
 * Both are mbedTLS's own curves, reached exactly as secp256r1 is; the device carries them (checked
 * on the router's libmbedcrypto rather than assumed from vendor/mbedtls's config, which is a
 * different build). */
#define LC_P384_KEY 48u
#define LC_P384_POINT 97u /* uncompressed: 0x04 || X || Y */
#define LC_P384_SHARED 48u

#define LC_P521_KEY 66u
#define LC_P521_POINT 133u
#define LC_P521_SHARED 66u

int lc_p384_keygen(uint8_t priv[LC_P384_KEY], uint8_t point[LC_P384_POINT]);
int lc_p384_shared(const uint8_t priv[LC_P384_KEY], const uint8_t peer[LC_P384_POINT],
                   uint8_t shared[LC_P384_SHARED]);

/* ⚠️ THE WIDEST SHARED SECRET ANY GROUP HERE PRODUCES, and it is NOT the hybrid's. Adding P-521
 * made this a trap: its secret is 66 bytes against the hybrid's 64, so every caller that had sized
 * a buffer by LC_HYBRID_SECRET — believing the post-quantum group to be the largest — was two bytes
 * short the moment a server could choose P-521. The compiler caught it (-Wstringop-overflow), which
 * is luck rather than design; the constant exists so the next group added cannot repeat it. */
/* And since Go 1.26 it is not P-521's either: SecP384r1MLKEM1024 joins a 48-byte ECDH secret and a
 * 32-byte ML-KEM one, 80 in all (GOROOT/src/crypto/tls/key_schedule.go:240-273, go1.26.6). */
#define LC_KEX_SHARED_MAX 80u

int lc_p521_keygen(uint8_t priv[LC_P521_KEY], uint8_t point[LC_P521_POINT]);
int lc_p521_shared(const uint8_t priv[LC_P521_KEY], const uint8_t peer[LC_P521_POINT],
                   uint8_t shared[LC_P521_SHARED]);

#endif
