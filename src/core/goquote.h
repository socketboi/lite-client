/* Go's %q of a string — strconv.Quote — for the texts the QUIC plane closes with under the Chrome
 * parrot, which quote what they refused: x509's "%q cannot be encoded as an IA5String", url's
 * `parse "…"`, netip's `ParseAddr("…")`. */
#ifndef LC_GOQUOTE_H
#define LC_GOQUOTE_H

#include "core/gotext.h"

#include <stddef.h>
#include <stdint.h>

/* strconv.Quote of `n` bytes, appended to `out`, double quotes and all: a printable rune as it is,
 * \a \b \f \n \r \t \v, \x for a byte that is not UTF-8 and for a control below U+0080, \u and \U
 * for any other rune strconv.IsPrint says is not printable (GOROOT/src/strconv/quote.go:31-119,
 * go1.26.6). */
void lc_go_quote(lc_obuf *out, const uint8_t *s, size_t n);

/* strconv.IsPrint, with go1.26.6's tables (core/goprint.h). */
int lc_go_is_print(uint32_t r);

#endif
