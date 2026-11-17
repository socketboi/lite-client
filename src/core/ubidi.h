/* golang.org/x/text/unicode/bidi's class lookup and golang.org/x/text/secure/bidirule, as Go ships
 * them (GOROOT/src/vendor, x/text v0.32.0, Unicode 15.0.0), for idna.Lookup's Bidi Rule. Tables are
 * Go's own, written out by tools/unitables; test/unorm holds these to the real functions. */
#ifndef LC_UBIDI_H
#define LC_UBIDI_H

#include <stddef.h>
#include <stdint.h>

/* bidi's classes, in its order (trieval.go). */
enum {
    LC_BIDI_L,
    LC_BIDI_R,
    LC_BIDI_EN,
    LC_BIDI_ES,
    LC_BIDI_ET,
    LC_BIDI_AN,
    LC_BIDI_CS,
    LC_BIDI_B,
    LC_BIDI_S,
    LC_BIDI_WS,
    LC_BIDI_ON,
    LC_BIDI_BN,
    LC_BIDI_NSM,
    LC_BIDI_AL,
    LC_BIDI_CONTROL,
    LC_BIDI_NUM_CLASS,
    LC_BIDI_LRO,
    LC_BIDI_RLO,
    LC_BIDI_LRE,
    LC_BIDI_RLE,
    LC_BIDI_PDF,
    LC_BIDI_LRI,
    LC_BIDI_RLI,
    LC_BIDI_FSI,
    LC_BIDI_PDI,
};

/* bidi.LookupString(s).Class() and the width it reports — 0 for a sequence the end cuts short.
 * `n` is at least 1. */
unsigned lc_bidi_class(const char *s, size_t n, size_t *sz);

/* bidirule.ValidString and bidirule.DirectionString (1 for RightToLeft). */
int lc_bidirule_valid(const char *s, size_t n);
int lc_bidirule_rtl(const char *s, size_t n);

#endif
