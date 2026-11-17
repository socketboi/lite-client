/* The padding Hysteria2 puts on its messages.
 *
 * Three of them carry a run of random characters whose only job is to make the message a different
 * size each time. None of this is a knob: the alphabet decides how well the padding compresses in
 * a header, the range decides the distribution of sizes on the wire, and both are visible to
 * anything counting bytes. They are upstream's, and the four ranges below are its four `padding{}`
 * literals in order — authRequest, authResponse, tcpRequest, tcpResponse
 * (vendor/hysteria/core/internal/protocol/padding.go:26-31). Named with a line rather than only
 * with a file, because a file is not something the sieve can build a pair out of. */
#ifndef LC_PAD_H
#define LC_PAD_H

#include <stddef.h>
#include <stdint.h>

/* Half-open ranges, [min, max). */
#define LC_PAD_AUTH_MIN 256u
#define LC_PAD_AUTH_MAX 2048u
#define LC_PAD_TCP_REQ_MIN 64u
#define LC_PAD_TCP_REQ_MAX 512u
#define LC_PAD_TCP_RESP_MIN 128u
#define LC_PAD_TCP_RESP_MAX 1024u

/* A length in [min, max). Returns 0, or -1 if there is no randomness to be had. */
int lc_pad_draw(uint32_t min, uint32_t max, uint32_t *out);

/* Fills exactly `len` characters, not terminated. Returns 0 or -1. */
int lc_pad_fill(char *out, size_t len);

#endif
