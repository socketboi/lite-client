#include "tls/transcript.h"

#include <string.h>

static mbedtls_md_type_t md_type(lc_hash h)
{
    return h == LC_SHA384 ? MBEDTLS_MD_SHA384 : MBEDTLS_MD_SHA256;
}

int lc_transcript_init(lc_transcript *t, lc_hash h)
{
    mbedtls_md_init(&t->ctx);
    t->hash = h;
    t->ready = 0;

    /* Every failure releases the context here rather than leaving it to the caller, for the reason
     * spelled out in aead.c: the caller cannot be relied on for it. src/quic/qtls.c frees this only
     * when tr_ready is set, and tr_ready is set only on success — so a setup that allocated and then
     * failed at md_starts leaked the digest context, on the one path where it matters, which is a
     * machine that has just run out of memory. mbedtls_md_free zeroes the context, so a caller that
     * frees anyway stays correct. */
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(md_type(h));
    if (info == NULL) {
        mbedtls_md_free(&t->ctx);
        return -1;
    }
    if (mbedtls_md_setup(&t->ctx, info, 0) != 0) {
        mbedtls_md_free(&t->ctx);
        return -1;
    }
    if (mbedtls_md_starts(&t->ctx) != 0) {
        mbedtls_md_free(&t->ctx);
        return -1;
    }

    t->ready = 1;
    return 0;
}

void lc_transcript_free(lc_transcript *t)
{
    mbedtls_md_free(&t->ctx);
    t->ready = 0;
}

/* ⚠️ WHAT GOES IN IS THE BYTES AS THEY ARRIVED, HEADER AND ALL — the only claim this file
 * makes, and until now it cited nothing, so the sieve never opened the file to check it.
 *
 * A running hash has no protocol decisions in it; the decision is entirely in what the caller
 * feeds it, and getting that wrong produces a transcript that agrees with nobody — every Finished
 * fails, and the cause is nowhere near the symptom. The reference is explicit about preferring the
 * received bytes over a re-serialisation:
 *
 *     if msgWithOrig, ok := msg.(handshakeMessageWithOriginalBytes); ok {
 *         if orig := msgWithOrig.originalBytes(); orig != nil {
 *             h.Write(msgWithOrig.originalBytes())
 *             return nil
 *         }
 *     }
 *     data, err := msg.marshal()          (vendor/utls/handshake_messages.go:2009-2023)
 *
 * — marshal only when the original is gone. So the unit is one whole handshake message including
 * its four-byte type-and-length header, exactly as it came off the wire, and never a message this
 * client built again from its parsed parts. Every caller passes `whole`, which is that.
 *
 * The one place it matters visibly is the compressed certificate: the transcript gets the
 * COMPRESSED message, not the one we unpacked from it — see the note at that branch in
 * tls/client.c, which is the same rule seen from the side where it is easy to get backwards. */
int lc_transcript_add(lc_transcript *t, const uint8_t *msg, size_t len)
{
    if (!t->ready)
        return -1;
    return mbedtls_md_update(&t->ctx, msg, len) == 0 ? 0 : -1;
}

int lc_transcript_snapshot(const lc_transcript *t, uint8_t *out)
{
    if (!t->ready)
        return -1;

    /* Finishing a hash consumes its state, and the transcript has to survive being read: more
     * messages follow every point the schedule looks at it. So the state is cloned and the clone
     * is finished. */
    mbedtls_md_context_t copy;
    mbedtls_md_init(&copy);

    int rc = -1;
    if (mbedtls_md_setup(&copy, mbedtls_md_info_from_type(md_type(t->hash)), 0) != 0)
        goto done;
    if (mbedtls_md_clone(&copy, &t->ctx) != 0)
        goto done;
    if (mbedtls_md_finish(&copy, out) != 0)
        goto done;
    rc = 0;

done:
    mbedtls_md_free(&copy);
    return rc;
}
