/* golang.org/x/text/unicode/norm as Go ships it (GOROOT/src/vendor, x/text v0.32.0, Unicode
 * 15.0.0) — NFC, and only what idna.Lookup asks of it: String and Bytes, QuickSpan and
 * IsNormalString (GOROOT/src/vendor/golang.org/x/net/idna/idna10.0.0.go). Its tables are Go's own,
 * written out by tools/unitables; test/unorm holds the port to the real functions.
 *
 * NOT QUITE UNICODE'S NFC, and deliberately so: x/text makes its output stream-safe (UAX #15), so a
 * run of more than thirty non-starters gets a U+034F COMBINING GRAPHEME JOINER put into it. That is
 * what the reference writes, so it is what this writes. */
#ifndef LC_UNORM_H
#define LC_UNORM_H

#include <stddef.h>

/* NFC.String of `n` bytes, any bytes: 0 with a string of its own in `*out` (NUL-terminated, `*on`
 * long) for the caller to free, or -2 without memory. */
int lc_nfc(const char *s, size_t n, char **out, size_t *on);

/* NFC.QuickSpan: how much of the start is known to be NFC already. */
size_t lc_nfc_quick_span(const char *s, size_t n);

/* NFC.IsNormalString: 1 when NFC would give the string back unchanged. */
int lc_nfc_is_normal(const char *s, size_t n);

#endif
