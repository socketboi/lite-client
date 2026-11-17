/* The TLS 1.3 key schedule primitives: HKDF-Extract, HKDF-Expand-Label and Derive-Secret
 * (RFC 8446 section 7.1).
 *
 * Everything a TLS 1.3 connection keeps secret comes out of these three functions, so they are the
 * first thing in this client that is proved rather than reviewed: test_hkdf.c runs them against the
 * complete trace in RFC 8448, extracted mechanically by tools/vectors/extract.awk.
 *
 * The hash primitives themselves come from mbedTLS, which already sits on the flash of every
 * OpenWrt device. Hand-writing SHA-2 here would add nothing but a chance to get constant-time
 * behaviour wrong. */
#ifndef LC_HKDF_H
#define LC_HKDF_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    LC_SHA256 = 0,
    LC_SHA384 = 1,
} lc_hash;

/* Digest size in bytes: 32 or 48. Also the size of every secret in the schedule. */
size_t lc_hash_len(lc_hash h);

/* Longest digest this build handles; lets callers size buffers on the stack. */
#define LC_HASH_MAX 48

/* Plain digest of one contiguous message. */
int lc_hash_digest(lc_hash h, const uint8_t *in, size_t in_len, uint8_t *out);

/* HKDF-Extract. A NULL salt means "all zeroes", which is how the schedule starts. Writes
 * lc_hash_len(h) bytes. */
int lc_hkdf_extract(lc_hash h, const uint8_t *salt, size_t salt_len,
                    const uint8_t *ikm, size_t ikm_len, uint8_t *out);

/* Serialises the HkdfLabel structure that HKDF-Expand-Label feeds to HKDF-Expand:
 *
 *   uint16 length; opaque label<7..255> = "tls13 " + label; opaque context<0..255>;
 *
 * Exposed because RFC 8448 prints this structure for every derivation, so the tests can check the
 * label construction separately from the expansion — the two fail in different ways and finding out
 * which one broke matters. */
int lc_hkdf_label(const char *label, const uint8_t *ctx, size_t ctx_len,
                  size_t out_len, uint8_t *info, size_t info_cap, size_t *info_len);

/* Plain HKDF-Expand of RFC 5869, with an arbitrary info string. TLS itself never needs this — every
 * TLS derivation goes through HKDF-Expand-Label — but REALITY does: it derives its authentication
 * key with the info "REALITY" and no HkdfLabel wrapper at all. */
int lc_hkdf_expand(lc_hash h, const uint8_t *prk, const uint8_t *info, size_t info_len,
                   uint8_t *out, size_t out_len);

/* HKDF-Expand-Label. out_len is bounded by 255 * hash length, as HKDF is. */
int lc_hkdf_expand_label(lc_hash h, const uint8_t *secret, const char *label,
                         const uint8_t *ctx, size_t ctx_len, uint8_t *out, size_t out_len);

/* Derive-Secret: HKDF-Expand-Label with the transcript hash as context, output one digest long. */
int lc_derive_secret(lc_hash h, const uint8_t *secret, const char *label,
                     const uint8_t *transcript_hash, uint8_t *out);

#endif
