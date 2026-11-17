/* The handshake transcript hash (RFC 8446 section 4.4.1).
 *
 * Every handshake message, in the order it appeared on the wire, hashed as one continuous stream.
 * The schedule then reads that hash at four exact points — after ServerHello, after the server
 * Finished, after the client Finished — and derives different secrets from each.
 *
 * Two properties make this worth its own module. The hash is over messages, not records: a message
 * split across two records hashes the same as one that was not, and the record layer must not be
 * visible here at all. And the hash has to be readable at those points WITHOUT ending it, since
 * more messages follow — so a snapshot is taken of a running state, which is exactly the operation
 * a plain "hash these bytes" helper cannot do. */
#ifndef LC_TRANSCRIPT_H
#define LC_TRANSCRIPT_H

#include "tls/hkdf.h"

#include <stddef.h>
#include <stdint.h>

#include <mbedtls/md.h>

typedef struct {
    mbedtls_md_context_t ctx;
    lc_hash              hash;
    int                  ready;
} lc_transcript;

/* Starts an empty transcript. Must be released with lc_transcript_free even if this fails. */
int lc_transcript_init(lc_transcript *t, lc_hash h);
void lc_transcript_free(lc_transcript *t);

/* Adds one handshake message — header included, exactly the bytes that were sent. */
int lc_transcript_add(lc_transcript *t, const uint8_t *msg, size_t len);

/* Reads the hash of everything added so far without disturbing the running state, so the schedule
 * can derive from it and the handshake can carry on. Writes lc_hash_len(t->hash) bytes. */
int lc_transcript_snapshot(const lc_transcript *t, uint8_t *out);

#endif
