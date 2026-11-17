/* Salamander — Hysteria2's packet obfuscation.
 *
 * Every datagram is scrambled before it leaves and unscrambled when it arrives, so what a censor
 * sees is bytes with no structure at all rather than a QUIC handshake. It is not encryption and is
 * not meant to be: the QUIC underneath is already encrypted, and this only removes the shape.
 *
 * It is also not optional when the server has it on. A server running Salamander deobfuscates
 * everything it receives, so a plain QUIC packet decodes to noise and is dropped without a word —
 * which is exactly what a client that does not know about it sees: silence, no alert, no reset.
 * That cost an afternoon to diagnose and is why this comment says it twice.
 *
 *     wire:  [8-byte salt][payload XOR keystream]
 *     key:   BLAKE2b-256(password ‖ salt), 32 bytes
 *     mask:  payload[i] ^= key[i % 32]
 *
 * A fresh salt per packet is what stops the keystream repeating across packets. It comes from Go's
 * math/rand, seeded from the clock when the connection is set up, because that is where the
 * reference takes it — see quic/gorand.h and lc_obfs_wrap. */
#ifndef LC_QOBFS_H
#define LC_QOBFS_H

#include "quic/gorand.h"

#include <stddef.h>
#include <stdint.h>

/* The salt in front of every obfuscated datagram. */
#define LC_OBFS_SALT 8u

/* How long a password this will hold.
 *
 * The reference sets no maximum at all: newSalamanderObfuscator refuses anything shorter than
 * smPSKMinLen — four bytes (vendor/hysteria/extras/obfs/salamander.go:14 and :35) — and then copies
 * whatever it was given, `pskCopy := append([]byte(nil), psk...)`, because the password is
 * concatenated with the salt and hashed, and a hash does not care how long its input is.
 *
 * A fixed field is what a C struct on a router can offer instead, so the number is chosen to be
 * past anything real rather than to be a rule. It was 128, which is small enough to refuse a
 * configuration the reference accepts — a generated password of that length is not exotic — and
 * this client would then decline to start where hysteria would have connected. */
#define LC_OBFS_PASSWORD_MAX 512u

typedef struct {
    uint8_t   password[LC_OBFS_PASSWORD_MAX];
    size_t    password_len;
    int       on;
    lc_gorand salt; /* the obfuscator's RandSrc */
} lc_obfs;

/* Arms the obfuscator, or leaves it off when `password` is NULL or empty. Returns -1 for a password
 * too long to hold or shorter than Hysteria's own minimum of four bytes. Armed, it seeds the salt
 * source from the clock, as newSalamanderObfuscator does. */
int lc_obfs_init(lc_obfs *o, const char *password);

/* Scrambles `in` into `out`, which must have room for len + LC_OBFS_SALT. With the obfuscator off
 * it copies. Returns the length written, or -1. Draws the next salt, so it is not const. */
long lc_obfs_wrap(lc_obfs *o, const uint8_t *in, size_t len, uint8_t *out, size_t out_cap);

/* The reverse. Returns the length written, or -1 for a datagram too short to carry a salt — which
 * is a packet from something that is not our server, and is dropped. */
long lc_obfs_unwrap(const lc_obfs *o, const uint8_t *in, size_t len, uint8_t *out, size_t out_cap);

#endif
