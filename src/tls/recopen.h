/* The node's records opened ahead, on the other cores — the REALITY plane's half of what quic/rxopen
 * does for Hysteria2's packets. DIVERGES: O3.
 *
 * The reference opens every record in the goroutine that reads the connection: a download is one
 * TLS stream, and one stream is one core, whichever program carries it. On the MT7621 that core
 * spends about two thirds of itself in AES-128-GCM at the 28 Mbit/s one stream reaches, and the
 * other three hardware threads sit idle — measured 2026-09-29 through the live node.
 *
 * So when a read leaves several whole records in the session's buffer, they are handed to threads
 * — one fewer than the processors online — which open each with a key of their own built from the
 * same bytes and the sequence number that record will have. The loop then delivers the records in
 * order exactly as before, and asks here for each one: an answer is given only when it was made from
 * these very inputs — the same record at the same place, the same length, the same sequence
 * number, the same algorithm, key and IV — and only when the record opened. Anything else, a record
 * the threads have not reached, a key that moved with a KeyUpdate, a record that did not open, is
 * opened by the loop itself, as always. What reaches the client and what the node sees are the
 * same either way.
 *
 * The session's buffer must not change from lc_recopen_start until lc_recopen_finish, which waits
 * for every thread still reading it. */
#ifndef LC_RECOPEN_H
#define LC_RECOPEN_H

#include "tls/record.h"

#include <stddef.h>
#include <stdint.h>

/* How many records one start hands out. Beyond them a buffer is opened by the loop as it always was.
 * A read of the reference's size (tls/rawin.h) brings two or three of a download's full records, and
 * of small ones more than are worth handing out. */
#define LC_RECOPEN_SLOTS 16u

/* The room each record opens into, and the only room an answer is given for: lc_record_unprotect
 * decides by it whether a record fits (see there), so an answer made with any other would not be
 * the answer the loop's own call gives. It is what lc-tunnel opens into. */
#define LC_RECOPEN_CAP LC_REC_MAX_WIRE12

/* The most threads a pool starts, whatever the machine has. */
#define LC_RECOPEN_THREADS_MAX 7u

typedef struct lc_recopen lc_recopen;

/* A pool with one thread fewer than the processors online, at most LC_RECOPEN_THREADS_MAX. *out is
 * NULL on a single processor, where there is nobody to hand anything to, and every call below
 * takes a NULL pool as "nothing opened ahead". -1 when threads were wanted and could not be had. */
int lc_recopen_new(lc_recopen **out);
void lc_recopen_free(lc_recopen *r);

/* Hands out the whole records at the front of `buf` that the loop will open next with `k`: TLS 1.3
 * application data only, in order, up to LC_RECOPEN_SLOTS, stopping at the first record that is
 * anything else or is not whole. The first gets k's sequence number, the next one more, and so on.
 * Returns how many were handed out; none for a TLS 1.2 key. */
unsigned lc_recopen_start(lc_recopen *r, const lc_record_key *k, const uint8_t *buf, size_t len);

/* What lc_record_unprotect(k, rec, rec_len, out, out_cap, out_len, inner_type) would give, when a
 * thread has made it from these very inputs and the record opened: 1, with the outputs written and
 * k's sequence number advanced as that call advances it. 0 otherwise, touching nothing — the caller
 * opens it itself. A record a thread is opening at the moment is waited for; one no thread has
 * reached yet is taken back from them. */
int lc_recopen_take(lc_recopen *r, lc_record_key *k, const uint8_t *rec, size_t rec_len,
                    uint8_t *out, size_t out_cap, size_t *out_len, uint8_t *inner_type);

/* Every record handed out is let go: the ones no thread has reached are taken back, the ones being
 * opened are waited for, and what was opened and not taken is wiped. After it no thread reads the
 * buffer given to lc_recopen_start. */
void lc_recopen_finish(lc_recopen *r);

#endif
