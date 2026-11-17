/* The TLS 1.3 record layer (RFC 8446 section 5).
 *
 * Two things happen here that look like details and are not.
 *
 * The nonce is the write IV exclusive-ored with the record sequence number, and the sequence number
 * is never sent — both ends count independently. A single record processed out of order, or counted
 * twice, desynchronises the connection permanently and shows up as an authentication failure far
 * from the cause. The counter therefore lives inside the key, not beside it.
 *
 * The real content type is hidden inside the encrypted body: every protected record claims to be
 * application_data on the outside, and the true type is the last non-zero byte of the plaintext.
 * That trailing search is also how padding is removed, which is why the two cannot be separated. */
#ifndef LC_RECORD_H
#define LC_RECORD_H

#include "tls/aead.h"
#include "tls/suite.h"

#include <stddef.h>
#include <stdint.h>

/* Content types that appear on the wire. */
#define LC_REC_CHANGE_CIPHER_SPEC 0x14u
#define LC_REC_ALERT              0x15u
#define LC_REC_HANDSHAKE          0x16u
#define LC_REC_APPLICATION_DATA   0x17u

/* A record may carry at most 2^14 bytes of plaintext, plus the inner type and the tag. */
#define LC_REC_MAX_PLAINTEXT 16384u
#define LC_REC_HEADER 5u

/* AND THE INNER PLAINTEXT IS ONE BYTE LONGER THAN THAT, which is a distinction the decrypt side has
 * to make and had not been making.
 *
 * What a TLS 1.3 record protects is TLSInnerPlaintext: the content, then the real content type,
 * then any padding. So a peer sending a FULL record — 2^14 bytes of content, which is what it is
 * allowed to send — hands the reader 16385 bytes once the tag is off. The reference bounds exactly
 * that quantity and includes the type byte in the bound:
 *
 *     if len(plaintext) > maxPlaintext+1 {
 *         return nil, 0, alertRecordOverflow
 *     }                                          (vendor/utls/conn.go:411-416)
 *
 * lc_record_unprotect compared the same quantity against LC_REC_MAX_PLAINTEXT with no +1, so a
 * legal full-size record was refused. That is not a theoretical peer: the REALITY server is a fork
 * of Go's crypto/tls, and Go's own writer ramps its record size to the full 2^14 once it has sent
 * 128 KiB (vendor/utls/conn.go:903-948), so a bulk download reached the limit as a matter of
 * course and the connection was torn down partway through with nothing to name the cause.
 *
 * Buffers that RECEIVE an opened record are sized with at least this rather than with
 * LC_REC_MAX_PLAINTEXT — and with LC_REC_MAX_OPEN where a peer holding the key is to get the
 * reference's answer for too much; the length reported back to the caller is still content only,
 * and still at most 2^14.
 *
 * ⚠️ THE SAME RAMP IS ALSO WHAT THIS CLIENT WRITES, which the paragraph above describes only from
 * the receiving end. Go sizes its own outgoing records by
 *
 *     if c.config.DynamicRecordSizingDisabled || typ != recordTypeApplicationData {
 *         return maxPlaintext
 *     }
 *     if c.bytesSent >= recordSizeBoostThreshold {          // 128 * 1024
 *         return maxPlaintext
 *     }                                                     (vendor/utls/conn.go:903-948)
 *
 * — small records for the first 128 KiB of application data, full ones after. Nothing in Xray-core
 * sets DynamicRecordSizingDisabled, so the reference has this on, and so do we: tls_write
 * (lc-tunnel/main.c) caps each record at LC_RECORD_PAYLOAD_STEP * (records_sent + 1) until either
 * LC_RECORD_BOOST_THRESHOLD — the same 128 KiB — or a thousand records have gone out, and full
 * plaintext after that. The step is Go's tcpMSSEstimate of 1208 less the record header, the AEAD
 * tag and the inner ContentType byte, so the first records match the reference in size and not
 * merely in shape.
 *
 * ⚠️ AND THIS PARAGRAPH USED TO SAY THE OPPOSITE — "not implemented, on purpose" — which is worth
 * leaving a scar over, because a comment that lies is worse than one that is merely silent. The
 * text argued the ramp did not matter under Vision and declared the question closed, and the
 * closing itself was written to stop the vendor sieve from re-reporting it. It worked, and then it
 * outlived the code: the ramp was implemented afterwards, the prose was not revisited, and on
 * 2026-08-31 the sieve's reverse pass read this very block and reported "dynamic record sizing is
 * missing in write path" as its ONE borderline finding against the whole client. A wrong comment
 * does not just fail to help an audit, it manufactures the audit's findings. Verify against
 * tls_write, not against this paragraph.
 *
 * ⚠️ AND THE UPSTREAM HALF OF VISION IS MEASURED RATHER THAN ASSUMED, which matters because the
 * DOWNSTREAM half is not ours to decide. On 2026-08-27 every connection watched on a live router
 * logged `direct copy engaged upstream` — the client decides that one itself, from a complete record
 * it recognises — while the downstream hand-off is announced by the server (see tls/aead.h for what
 * it costs when it is not). The two directions are not one fact, and this paragraph only ever
 * needed the one it can prove.
 *
 * ⚠️ "OFTEN NEVER COMES AT ALL" STOOD HERE AND WAS TOO STRONG, and it is corrected rather than
 * deleted because the shape of the mistake is the useful part: one router-hour was read as a
 * property of the server. It is a per-connection lottery whose die the server throws. The writer
 * announces direct copy only for a buffer that BEGINS with a TLS application-data header and holds
 * a COMPLETE record — `w.trafficState.IsTLS && b.Len() >= 6 &&
 * bytes.Equal(TlsApplicationDataStart, b.BytesTo(3)) && isComplete`, with isComplete from
 * IsCompleteRecord(mb) two lines above (vendor/Xray-core/proxy/proxy.go:365-377) — so what settles
 * it is how the DESTINATION's bytes happen to land in the server's read buffer, and nothing the
 * client sends changes it. Measured accordingly: 89 % of downstream bytes spliced over a day on the
 * live router (2026-09-02), and 3 connections out of 6 announced on a test node the same week, with
 * sessions carrying none at all in between. A throughput figure taken without recording whether the
 * hand-off happened is a coin flip written down as a measurement. */
#define LC_REC_MAX_INNER (LC_REC_MAX_PLAINTEXT + 1u)

/* The largest a record can legally be ON THE WIRE: RFC 8446 caps TLSCiphertext.length at 2^14 + 256,
 * and the five-byte header sits in front of it.
 *
 * Stated once because it was stated four times, in three different values — three programs and the
 * handshake machine each sized their own buffer, two of them 192 bytes short. The cost was not an
 * overflow (every reader bounded its own array) but a livelock: the handshake machine would accept a
 * declared length its caller's buffer could not hold, the caller would read nothing and report
 * success, and a level-triggered event loop would spin on the same readable socket at full CPU until
 * the deadline. A size that must agree in four places will not. */
#define LC_REC_MAX_WIRE (LC_REC_HEADER + LC_REC_MAX_PLAINTEXT + 256u)

/* What a record the header allows can open to: 2^14 + 256 less the tag. More than a legal inner
 * plaintext — LC_REC_MAX_INNER — and that is the point: the reference opens whatever the header let
 * through and only then answers record_overflow for too much (vendor/utls/conn.go:415-417), so a
 * reader that is to give that answer, and not bad_record_mac, needs the room to open it first. See
 * lc_record_unprotect. */
#define LC_REC_MAX_OPEN (LC_REC_MAX_PLAINTEXT + 256u - LC_AEAD_TAG)

typedef struct {
    lc_aead  aead;
    uint8_t  iv[LC_AEAD_NONCE];
    uint64_t seq;

    /* The key itself, TLS 1.3 only, and what it is for: the one thing a second context for the same
     * key can be built from. An mbedTLS context cannot be copied — its round keys are found through
     * an offset into itself — so the threads that open the node's records ahead (tls/recopen.h)
     * build their own from these bytes, and the loop tells their answers from its own key's by
     * comparing them. Zero for a TLS 1.2 key, which is never opened ahead. */
    lc_aead_alg alg;
    uint8_t     key[32];
    size_t      key_len;

    /* TLS 1.2, when the server answered the hello with it (T3, closed 29.09); all zero for a TLS 1.3
     * key. What changes is the record's shape, not the callers: the same two functions protect and
     * open, and they read the type from the header rather than from inside the plaintext. See
     * lc_record_key_init12. */
    uint8_t             tls12;
    uint8_t             mode12; /* lc_tls12_mode */
    uint8_t             mac_len;
    uint8_t             mac_key[32];
    int                 mac_sha256;
    mbedtls_aes_context cbc; /* the CBC key schedule: encryption for our side, decryption for theirs */
    int                 cbc_ready;
} lc_record_key;

/* A TLS 1.2 key: |suite| is an lc_tls12_suite (tls/suite.h), |key|, |iv| and |mac_key| the slices of
 * the key block that belong to this direction, |for_reading| which one it is — CBC keeps a decryption
 * schedule for the peer's records. The sequence starts at zero, which is where changeCipherSpec puts
 * it (vendor/utls/conn.go:218-228). */
int lc_record_key_init12(lc_record_key *k, const lc_tls12_suite *suite, const uint8_t *key,
                         const uint8_t *iv, const uint8_t *mac_key, int for_reading);

/* The largest TLS 1.2 record body on the wire: maxCiphertext, 2^14 + 2048 (vendor/utls/common.go:68).
 * A CBC record at the full plaintext with the most padding a peer may add reaches past the 1.3 limit
 * that LC_REC_MAX_WIRE is. */
#define LC_REC_MAX_WIRE12 (LC_REC_HEADER + LC_REC_MAX_PLAINTEXT + 2048u)

/* Binds traffic keys. Sequence numbers start at zero and step on every record, per RFC 8446. */
int lc_record_key_init(lc_record_key *k, lc_aead_alg alg, const uint8_t *key, const uint8_t *iv);
void lc_record_key_free(lc_record_key *k);

/* Seals one record and advances the sequence number. `pad` zero bytes are appended after the inner
 * content type; passing zero is legal and is what every implementation does by default.
 * `pt` may be NULL when `pt_len` is zero. */
int lc_record_protect(lc_record_key *k, uint8_t inner_type,
                      const uint8_t *pt, size_t pt_len, size_t pad,
                      uint8_t *out, size_t out_cap, size_t *out_len);

/* Opens one whole record — header included — and advances the sequence number on success.
 * Reports the inner content type recovered from the plaintext. */
int lc_record_unprotect(lc_record_key *k, const uint8_t *rec, size_t rec_len,
                        uint8_t *out, size_t out_cap, size_t *out_len, uint8_t *inner_type);

#endif
