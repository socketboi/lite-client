/* BLAKE2b, because Hysteria2 needs it and mbedTLS does not have it.
 *
 * The device already carries SHA-2 and everything else this client uses, so adding a hash is a cost
 * that has to be justified: Salamander, Hysteria2's packet obfuscation, derives its key stream with
 * BLAKE2b-256 and nothing else will do — a server decrypts with what it decrypts with. Roughly a
 * hundred lines and no dependencies, against pulling in a second crypto library for one function.
 *
 * RFC 7693. Only what is needed: unkeyed, one-shot, digest sizes up to 64 bytes. No keyed mode, no
 * tree hashing, no streaming — Salamander hashes a key and eight bytes of salt, once per packet. */
#ifndef LC_BLAKE2B_H
#define LC_BLAKE2B_H

#include <stddef.h>
#include <stdint.h>

/* Hashes `in` into `out`. out_len is the digest size in bytes, 1 to 64. Returns 0, or -1 for a
 * digest size the algorithm does not define. */
int lc_blake2b(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len);

#endif
