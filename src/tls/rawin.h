/* How much the node's socket is asked for, read by read — as uTLS asks it.
 *
 * The reference reads the node's side into c.rawInput, a Go bytes.Buffer, and only through
 * readFromUntil: Grow(needs + bytes.MinRead), then read into AvailableBuffer until
 * `needs` bytes have come (vendor/utls/conn.go:808-841); readRecordOrCCS calls it for a record's
 * header, and — unless the header is refused — for the whole record, then takes it with Next
 * (conn.go:612-688). Every Read asks for the buffer's remaining free capacity, and
 * that capacity is bytes.Buffer's growth rounded to the size classes of Go's allocator.
 *
 * It matters on the wire. What a connection leaves unread in the socket when it is closed goes out
 * as a reset instead of a FIN, and the reference, refusing a record's header, leaves everything it
 * did not ask for. The nodealert stand's `huge`: a header over 2^14 + 256 on a fresh connection, and
 * the reference had asked for 576 bytes of the 16 646 — RST — where this client, reading a record's
 * worth at a time, had them all and closed with a FIN.
 *
 * So the buffer's shape is kept here — its offset, length and capacity, never its bytes, which are
 * the caller's — and every read of the node's socket asks for what the reference's would, from the
 * first byte of the handshake to the last record. The vectors in test/rawin are Go's own
 * (tools/rawin). */
#ifndef LC_RAWIN_H
#define LC_RAWIN_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t off; /* b.off */
    size_t len; /* len(b.buf) */
    size_t cap; /* cap(b.buf); zero for the nil buffer a connection starts with */

    /* A readFromUntil under way: `left` is its remaining needs across events,
     * as the reference's goroutine stays inside the loop. */
    int     until;
    int64_t left;
} lc_rawin;

/* Len(): what the buffer holds. The caller's bytes are exactly this many, at its front. */
size_t lc_rawin_len(const lc_rawin *r);

/* readFromUntil(n): 0 when the buffer holds n bytes already; otherwise how many the next read asks
 * for — the reference's Read(b.buf[i:cap(b.buf)]). Asking again before lc_rawin_got — the socket had
 * nothing — gives the same answer. The caller's storage must hold lc_rawin_cap bytes from here. */
size_t lc_rawin_ask(lc_rawin *r, size_t n);

/* What that read returned; more than zero. */
void lc_rawin_got(lc_rawin *r, size_t got);

/* Next(n): a record taken from the front. */
void lc_rawin_next(lc_rawin *r, size_t n);

/* cap(b.buf): the most the caller's bytes and one read can come to. */
size_t lc_rawin_cap(const lc_rawin *r);

/* The capacity growSlice's append gets for a length of c (runtime.roundupsize for a []byte). */
size_t lc_rawin_roundup(size_t c);

#endif
