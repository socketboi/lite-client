/* THE REFERENCE'S OWN WORDS FOR A FAILURE, MARKED AS SUCH.
 *
 * Under the Chrome parrot hysteria turns on by default, a TLS failure on the QUIC plane is not
 * closed with its alert: quic-go does not know uTLS's AlertError, and closes with INTERNAL_ERROR
 * and err.Error() as the reason (wrapError, vendor/quic-go/internal/handshake/crypto_setup.go:
 * 700-705). So every refusal here says, besides its alert, what uTLS — or what uTLS hands on from
 * the hysteria client or Go's own packages — would have put in that error.
 *
 * LC_GO wraps each such string, format and all, so that `make check-qgo-reasons` can find every
 * one in src/ and hold it to the text of vendor/utls-hy, vendor/hysteria or GOROOT: a text typed
 * from memory, or one the reference has since reworded, fails the gate. */
#ifndef LC_GOERR_H
#define LC_GOERR_H

#define LC_GO(s) (s)

#include <stdarg.h>
#include <stdio.h>

/* vsnprintf of a Go format: the literal stays Go's, so that the gate can find it, and Go's %T —
 * which here only ever prints a type name the caller passes as a string — is read as %s. Every
 * other verb these formats use (%d, %x, %s) means the same to C when the caller passes the matching
 * type. */
static inline void lc_go_vsnprintf(char *out, size_t cap, const char *fmt, va_list ap)
{
    char   c_fmt[320];
    size_t i = 0;
    for (; *fmt != '\0' && i + 2u < sizeof c_fmt; fmt++) {
        c_fmt[i++] = *fmt;
        if (fmt[0] == '%' && fmt[1] == 'T') {
            c_fmt[i++] = 's';
            fmt++;
        }
    }
    c_fmt[i] = '\0';
    vsnprintf(out, cap, c_fmt, ap);
}

#endif
