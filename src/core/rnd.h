/* Randomness for the handshake.
 *
 * One source, no alternatives. A proxy that quietly degrades to a weaker source when the good one
 * is unavailable produces traffic that looks fine and is not — and on this device the caller cannot
 * tell the difference. So the contract is: bytes, or an error the caller must handle. */
#ifndef LC_RND_H
#define LC_RND_H

#include <stddef.h>
#include <stdint.h>

/* Fills n bytes. Returns 0 on success, -1 if the system could not provide randomness. */
int lc_rnd(uint8_t *out, size_t n);

/* Draws one GREASE value as RFC 8701 defines it: both bytes equal, low nibble 0xA. Returns 0 on
 * success. A fixed GREASE value would itself be a fingerprint, so failure is reported, never
 * substituted. */
int lc_rnd_grease(uint16_t *out);

/* Uniform in [0, n), unbiased. Returns 0 on success, -1 for n == 0, n above 2^32-1, or a source
 * that could not answer. Three callers draw positions with it — the cookie insert, the extension
 * shuffle and the spider's path — and all three mirror a Go draw that rejects rather than folds. */
int lc_rnd_below(size_t n, size_t *out);

#endif
