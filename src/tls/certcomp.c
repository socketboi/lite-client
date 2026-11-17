#include "tls/certcomp.h"

#include "tls/alert.h"
#include "tls/goerr.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <brotli/decode.h>
#include <zlib.h>
/* ZSTD_decompressContinue and ZSTD_getFrameHeader: the block-at-a-time interface, which is what
 * the reference's reader is. */
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

/* ---- zlib: Go's compress/zlib over compress/flate, one Read ----------------------------------
 *
 * flate's Read (GOROOT/src/compress/flate/inflate.go:335-353) decodes until it has something to
 * hand over, hands over what fits, and returns — and it has something to hand over at exactly four
 * moments (:505 and :612, :643-647, :678-685, :348-350):
 *
 *   the window is full   32768 bytes written (`dict.init(maxMatchOffset, …)`, :815, and
 *                        GOROOT/src/compress/flate/deflate.go:47), error nil;
 *   an empty stored block  what was written so far, if anything — the marker a sync flush leaves;
 *   the last block ends  everything written, error io.EOF;
 *   the stream is bad    what was written before the fault, and the error.
 *
 * If that is more than the caller's buffer, the buffer is filled and the error is not returned:
 * accepted, whatever comes after. Otherwise the call returns what there was with the error, and
 * zlib's Reader reads the Adler-32 only on io.EOF (GOROOT/src/compress/zlib/reader.go:92-121) — so
 * a declared length of exactly 32768 never meets the checksum, and a stream flushed every 500
 * bytes cannot declare more than 500. Measured, both of them, against the reference itself.
 *
 * libz does the decoding; what is modelled is where Go stops. inflate with Z_BLOCK returns at
 * every block boundary, where the next block's header is read ahead of it to see whether it is
 * an empty stored block — the one stop libz does not make on its own. */
#define FLATE_WINDOW 32768u

/* Whether the block starting at the inflate's position is an empty stored block that is not the
 * last. Read from the bits libz has not consumed: `data_type & 7` of the last byte it took, then
 * the bytes after it (zlib.h, "data_type"). A header the input does not hold is "no", and inflate
 * then fails on it the way flate does. */
static int next_is_empty_stored(const z_stream *s)
{
    const uint8_t *p = s->next_in;
    size_t         avail = s->avail_in;
    unsigned       have = (unsigned)s->data_type & 7u;
    uint64_t       bits = have != 0u ? (uint64_t)(p[-1] >> (8u - have)) : 0u;

    while (have < 3u) {
        if (avail == 0u)
            return 0;
        bits |= (uint64_t)*p++ << have;
        have += 8u;
        avail--;
    }
    if ((bits & 7u) != 0u) /* BFINAL 0 and BTYPE 00: a stored block that is not the last */
        return 0;
    bits >>= 3;
    have -= 3u;
    bits >>= have & 7u; /* LEN and NLEN start on the next byte */
    have -= have & 7u;
    while (have < 32u) {
        if (avail == 0u)
            return 0;
        bits |= (uint64_t)*p++ << have;
        have += 8u;
        avail--;
    }
    return (bits & 0xffffu) == 0u && ((bits >> 16) & 0xffffu) == 0xffffu;
}

static int open_zlib(const uint8_t *run, size_t run_len, size_t declared, uint8_t *out)
{
    uint8_t *window = malloc(FLATE_WINDOW);
    z_stream s;
    memset(&s, 0, sizeof s);
    if (window == NULL || inflateInit(&s) != Z_OK) {
        free(window);
        return LC_ALERT_INTERNAL_ERROR;
    }
    s.next_in = (Bytef *)(uintptr_t)run;
    s.avail_in = (uInt)run_len;

    enum { STOP_WINDOW, STOP_EMPTY_STORED, STOP_LAST, STOP_FAULT } stop;
    size_t written = 0;
    for (;;) {
        s.next_out = window + written;
        s.avail_out = (uInt)(FLATE_WINDOW - written);
        int rc = inflate(&s, Z_BLOCK);
        written = (size_t)(s.next_out - window);
        if (written == FLATE_WINDOW) {
            stop = STOP_WINDOW; /* before anything after it: flate hands over at the 32768th byte */
            break;
        }
        if (rc != Z_OK && rc != Z_STREAM_END) {
            stop = STOP_FAULT; /* a bad stream, or one that ends before it says it does */
            break;
        }
        if ((s.data_type & 128) != 0) { /* at a block boundary */
            if ((s.data_type & 64) != 0) {
                stop = STOP_LAST;
                break;
            }
            if (written > 0u && next_is_empty_stored(&s)) {
                stop = STOP_EMPTY_STORED;
                break;
            }
        }
    }

    int verdict = LC_ALERT_BAD_CERTIFICATE;
    if (written > declared) {
        verdict = 0; /* the buffer fills and the rest is never read */
    } else if (stop == STOP_WINDOW || stop == STOP_EMPTY_STORED) {
        verdict = written == declared ? 0 : LC_ALERT_BAD_CERTIFICATE;
    } else if (stop == STOP_LAST) {
        /* io.EOF, so zlib reads the Adler-32 that follows. libz checks it in the same call that
         * takes it; bytes after it are never looked at, by either. */
        int rc;
        do {
            s.next_out = window + written;
            s.avail_out = (uInt)(FLATE_WINDOW - written);
            rc = inflate(&s, Z_NO_FLUSH);
        } while (rc == Z_OK && s.avail_in > 0u);
        verdict = rc == Z_STREAM_END && written == declared ? 0 : LC_ALERT_BAD_CERTIFICATE;
    }
    if (verdict == 0 && declared > 0u)
        memcpy(out, window, declared);
    inflateEnd(&s);
    free(window);
    return verdict;
}

/* ---- brotli: andybalholm/brotli, one Read --------------------------------------------------
 *
 * A port of this very decoder, so its states are libbrotli's states and what is modelled is only
 * what Reader.Read does with them (Reader.Read in andybalholm/brotli v1.0.6, which the pinned uTLS
 * and Xray-core both require): it feeds the source in reads of `readBufSize`, 32768 bytes, and
 * returns on the first of
 *
 *   SUCCESS            with input left over in the current read: errExcessiveInput;
 *   NEEDS_MORE_OUTPUT  the buffer is full: accepted, whatever is still inside;
 *   NEEDS_MORE_INPUT   having written something: returns it, short or not;
 *   ERROR              the error.
 *
 * An empty buffer returns before any of it: a declared length of zero opens to nothing, whatever
 * the stream is.
 *
 * AND IN ITS WORDS, which the Hysteria2 plane closes with under the Chrome parrot: the reader's own
 * errors (vendor/brotli-go/reader.go:14-15, :72-107), a decoder's code as decodeError prints it
 * (:10-12, decoderErrorString at vendor/brotli-go/decode.go:2518-2581), io.ErrUnexpectedEOF, and a
 * short read in decompressCert's own words (vendor/utls-hy/u_handshake_client.go:103-114). Each is
 * one line below, whole, as utlsReadServerCertificate wraps it (:35-38); test/certcomp holds them
 * to what the reference returned, and check-qgo-reasons each code to its name. */
#define BROTLI_READ 32768u

/* The names decoderErrorString gives (vendor/brotli-go/decode.go:2518-2581), by the number each
 * is for: the constants from decoderNoError on (vendor/brotli-go/decode.go:22-50), the same numbers
 * in libbrotli, whose decoder that one is a port of (vendor/brotli/c/include/brotli/decode.h). A
 * code with no case there is INVALID; libbrotli's two it lacks (-17, -18) come from dictionaries
 * this client never attaches. */
static const struct {
    int         code;
    const char *go;
} brotli_errors[] = {
    { -1, LC_GO("tls: failed to decompress certificate message: brotli: EXUBERANT_NIBBLE") },
    { -2, LC_GO("tls: failed to decompress certificate message: brotli: RESERVED") },
    { -3, LC_GO("tls: failed to decompress certificate message: brotli: EXUBERANT_META_NIBBLE") },
    { -4, LC_GO("tls: failed to decompress certificate message: brotli: SIMPLE_HUFFMAN_ALPHABET") },
    { -5, LC_GO("tls: failed to decompress certificate message: brotli: SIMPLE_HUFFMAN_SAME") },
    { -6, LC_GO("tls: failed to decompress certificate message: brotli: CL_SPACE") },
    { -7, LC_GO("tls: failed to decompress certificate message: brotli: HUFFMAN_SPACE") },
    { -8, LC_GO("tls: failed to decompress certificate message: brotli: CONTEXT_MAP_REPEAT") },
    { -9, LC_GO("tls: failed to decompress certificate message: brotli: BLOCK_LENGTH_1") },
    { -10, LC_GO("tls: failed to decompress certificate message: brotli: BLOCK_LENGTH_2") },
    { -11, LC_GO("tls: failed to decompress certificate message: brotli: TRANSFORM") },
    { -12, LC_GO("tls: failed to decompress certificate message: brotli: DICTIONARY") },
    { -13, LC_GO("tls: failed to decompress certificate message: brotli: WINDOW_BITS") },
    { -14, LC_GO("tls: failed to decompress certificate message: brotli: PADDING_1") },
    { -15, LC_GO("tls: failed to decompress certificate message: brotli: PADDING_2") },
    { -16, LC_GO("tls: failed to decompress certificate message: brotli: DISTANCE") },
    { -19, LC_GO("tls: failed to decompress certificate message: brotli: DICTIONARY_NOT_SET") },
    { -20, LC_GO("tls: failed to decompress certificate message: brotli: INVALID_ARGUMENTS") },
    { -21, LC_GO("tls: failed to decompress certificate message: brotli: CONTEXT_MODES") },
    { -22, LC_GO("tls: failed to decompress certificate message: brotli: TREE_GROUPS") },
    { -25, LC_GO("tls: failed to decompress certificate message: brotli: CONTEXT_MAP") },
    { -26, LC_GO("tls: failed to decompress certificate message: brotli: RING_BUFFER_1") },
    { -27, LC_GO("tls: failed to decompress certificate message: brotli: RING_BUFFER_2") },
    { -30, LC_GO("tls: failed to decompress certificate message: brotli: BLOCK_TYPE_TREES") },
    { -31, LC_GO("tls: failed to decompress certificate message: brotli: UNREACHABLE") },
};

static void brotli_says(char *go, size_t go_cap, const char *text)
{
    if (go != NULL)
        snprintf(go, go_cap, "%s", text);
}

/* decompressCert's own words for a Read that came back short without an error
 * (vendor/utls-hy/u_handshake_client.go:108-114). */
static void brotli_short(char *go, size_t go_cap, size_t n, size_t declared)
{
    if (go != NULL)
        snprintf(go, go_cap,
                 LC_GO("tls: failed to decompress certificate message: decompressed len (%d) does not match specified len (%d)"),
                 (int)n, (int)declared);
}

static int open_brotli(const uint8_t *run, size_t run_len, size_t declared, uint8_t *out,
                       char *go, size_t go_cap)
{
    if (declared == 0u)
        return 0;
    if (run_len == 0u) {
        brotli_short(go, go_cap, 0u, declared); /* the source's first read is (0, io.EOF) */
        return LC_ALERT_BAD_CERTIFICATE;
    }

    BrotliDecoderState *st = BrotliDecoderCreateInstance(NULL, NULL, NULL);
    if (st == NULL)
        return LC_ALERT_INTERNAL_ERROR;

    size_t         fed = run_len < BROTLI_READ ? run_len : BROTLI_READ;
    const uint8_t *next_in = run;
    size_t         avail_in = fed;
    int            verdict;
    for (;;) {
        uint8_t *next_out = out;
        size_t   avail_out = declared;
        BrotliDecoderResult r =
            BrotliDecoderDecompressStream(st, &avail_in, &next_in, &avail_out, &next_out, NULL);
        size_t written = declared - avail_out;

        if (r == BROTLI_DECODER_RESULT_SUCCESS) {
            if (avail_in != 0u) {
                brotli_says(go, go_cap, LC_GO("tls: failed to decompress certificate message: brotli: excessive input"));
                verdict = LC_ALERT_BAD_CERTIFICATE;
            } else if (written != declared) {
                brotli_short(go, go_cap, written, declared);
                verdict = LC_ALERT_BAD_CERTIFICATE;
            } else {
                verdict = 0;
            }
            break;
        }
        if (r == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
            verdict = written == declared ? 0 : LC_ALERT_BAD_CERTIFICATE;
            break;
        }
        if (r != BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT) {
            int         code = (int)BrotliDecoderGetErrorCode(st);
            const char *text = LC_GO("tls: failed to decompress certificate message: brotli: INVALID");
            for (size_t i = 0; i < sizeof brotli_errors / sizeof brotli_errors[0]; i++)
                if (brotli_errors[i].code == code)
                    text = brotli_errors[i].go;
            brotli_says(go, go_cap, text);
            verdict = LC_ALERT_BAD_CERTIFICATE; /* ERROR */
            break;
        }
        if (avail_in != 0u) {
            brotli_says(go, go_cap, LC_GO("tls: failed to decompress certificate message: brotli: invalid state"));
            verdict = LC_ALERT_BAD_CERTIFICATE;
            break;
        }
        if (written > 0u) {
            if (written == declared) {
                verdict = 0;
            } else {
                brotli_short(go, go_cap, written, declared);
                verdict = LC_ALERT_BAD_CERTIFICATE;
            }
            break;
        }
        if (fed == run_len) {
            brotli_says(go, go_cap, LC_GO("tls: failed to decompress certificate message: unexpected EOF"));
            verdict = LC_ALERT_BAD_CERTIFICATE; /* io.ErrUnexpectedEOF */
            break;
        }
        size_t more = run_len - fed < BROTLI_READ ? run_len - fed : BROTLI_READ;
        next_in = run + fed;
        avail_in = more;
        fed += more;
    }
    BrotliDecoderDestroyInstance(st);
    return verdict;
}

/* ---- zstd: klauspost/compress's Decoder, one Read ------------------------------------------
 *
 * klauspost/compress v1.17.4 decodes a block at a time, and a block's output and its error travel
 * together (Decoder.Read and startStreamDecoder in its zstd package). Read copies block after
 * block until the buffer is full; a block's error is returned only once its bytes are used up, so
 * a buffer that fills inside a block never sees it. The frame's checksum is read WITH the last
 * block — if it is not there, that block is an error and its bytes are lost — and compared when
 * the block arrives, before a byte of it is copied. Frames follow frames; after the last, io.EOF.
 * A frame that names a dictionary is refused, none being registered — and libzstd refuses it too,
 * given none (dictionary_wrong), so that needs no line here. So is a window over 1<<29, its
 * MaxWindowSize, which libzstd would take. An empty buffer returns before anything is decoded.
 *
 * ⚠️ TWO THINGS THIS DOES NOT MODEL, NAMED. (1) With more than one core the decoder runs ahead in
 * goroutines and Read asks for each block after the first WITHOUT waiting (nextBlock(n == 0)): a
 * block not yet decoded ends the read short. On one core it always does. What is modelled is the
 * block being ready, which is what the reference answered in every case test/certcomp holds.
 * (2) A frame whose content size is exceeded or not met: the reference hands over the block's
 * bytes with the error, libzstd returns the error alone, so a declared length ending inside that
 * block is refused here and accepted there. Neither the Go encoder nor libzstd writes such a
 * frame. */
static int open_zstd(const uint8_t *run, size_t run_len, size_t declared, uint8_t *out)
{
    if (declared == 0u)
        return 0;

    ZSTD_DCtx *dc = ZSTD_createDCtx();
    uint8_t   *scratch = malloc(declared + ZSTD_BLOCKSIZE_MAX);
    if (dc == NULL || scratch == NULL) {
        ZSTD_freeDCtx(dc);
        free(scratch);
        return LC_ALERT_INTERNAL_ERROR;
    }

    size_t pos = 0, have = 0;
    int    verdict = LC_ALERT_BAD_CERTIFICATE;
    for (;;) { /* one frame per pass; every way out below is before `declared` was reached */
        ZSTD_FrameHeader fh;
        size_t           hr = ZSTD_getFrameHeader(&fh, run + pos, run_len - pos);
        if (ZSTD_isError(hr) || hr != 0u)
            break; /* io.EOF at the end, or a header that does not read */
        if (fh.frameType == ZSTD_frame && (run[pos + 4] & 0x20u) == 0u &&
            fh.windowSize > (1ull << 29))
            break; /* over MaxWindowSize; a single-segment frame is checked before its window is set */
        if (ZSTD_isError(ZSTD_decompressBegin(dc)))
            break;

        int done = 0, fault = 0;
        for (;;) {
            size_t need = ZSTD_nextSrcSizeToDecompress(dc);
            if (need == 0u)
                break; /* the frame is over */
            ZSTD_nextInputType_e kind = ZSTD_nextInputType(dc);
            if (run_len - pos < need ||
                (kind == ZSTDnit_lastBlock && fh.checksumFlag && run_len - pos < need + 4u)) {
                fault = 1; /* cut short — for the last block, short of its checksum too */
                break;
            }
            size_t r = ZSTD_decompressContinue(dc, scratch + have,
                                               declared + ZSTD_BLOCKSIZE_MAX - have, run + pos,
                                               need);
            pos += need;
            if (ZSTD_isError(r)) {
                fault = 1;
                break;
            }
            if (kind != ZSTDnit_block && kind != ZSTDnit_lastBlock)
                continue;

            int crc_bad = 0;
            if (kind == ZSTDnit_lastBlock && fh.checksumFlag) {
                crc_bad = ZSTD_isError(ZSTD_decompressContinue(dc, NULL, 0, run + pos, 4u)) != 0u;
                pos += 4u;
            }
            if (have + r > declared) { /* the buffer fills inside this block */
                verdict = 0;
                done = 1;
                break;
            }
            have += r;
            if (crc_bad) {
                fault = 1;
                break;
            }
            if (have == declared) {
                verdict = 0;
                done = 1;
                break;
            }
        }
        if (done || fault)
            break;
    }
    if (verdict == 0)
        memcpy(out, scratch, declared);
    ZSTD_freeDCtx(dc);
    free(scratch);
    return verdict;
}

int lc_certcomp_open(const uint8_t *body, size_t len, const uint8_t *offered, size_t offered_len,
                     uint8_t *out, size_t out_cap, size_t *out_len,
                     char *err, size_t err_cap, char *go, size_t go_cap)
{
    *out_len = 0;
    if (go != NULL && go_cap > 0u)
        go[0] = '\0';

    /* THE HEADER IS unmarshal's, AND A HEADER THAT DOES NOT READ IS 10, NOT 42. The reference reads
     * the algorithm, the declared length and a three-byte-prefixed run of compressed bytes, and
     * nothing else — no test that the message ends there (utlsCompressedCertificateMsg.unmarshal,
     * vendor/utls/u_handshake_messages.go:43-54). A false from it is readHandshake's
     * unexpected_message, like any message that does not unmarshal; only what follows a header
     * that DID read is bad_certificate. So a message too short for its header, or one whose run
     * claims more than it carries, is 10; and bytes after the run are not refused at all — the
     * decoders below are handed the run and never see them. This answered 42 for all three. */
    if (len < 8u) {
        snprintf(err, err_cap, "the compressed certificate message is %u bytes, too short to have "
                               "a header", (unsigned)len);
        return LC_ALERT_UNEXPECTED_MESSAGE;
    }

    unsigned algorithm = (unsigned)body[0] << 8 | body[1];
    size_t   declared = (size_t)body[2] << 16 | (size_t)body[3] << 8 | body[4];
    size_t   compressed = (size_t)body[5] << 16 | (size_t)body[6] << 8 | body[7];

    if (compressed > len - 8u) {
        snprintf(err, err_cap, "the compressed certificate declares %u bytes and carries %u",
                 (unsigned)compressed, (unsigned)(len - 8u));
        return LC_ALERT_UNEXPECTED_MESSAGE;
    }

    /* A hello that offered no compression has no reader for this message at all. uTLS decompresses
     * only when its own extension list holds a UtlsCompressCertExtension with algorithms in it
     * (utlsReadServerCertificate, vendor/utls/u_handshake_client.go:25-48); otherwise the message
     * reaches readServerCertificate as it came and fails the Certificate type assertion there —
     * unexpected_message (vendor/utls/handshake_client_tls13.go:754-758). */
    if (offered == NULL || offered_len < 3u) {
        snprintf(err, err_cap, "the server compressed its certificate, and our hello never offered "
                               "to take one compressed");
        return LC_ALERT_UNEXPECTED_MESSAGE;
    }

    /* The algorithm has to be one WE offered, not merely one that exists — and "we" is the hello
     * that went out, not this build. The reference checks against its own certCompressionAlgs,
     * filled from the extension it sent (vendor/utls/u_handshake_client.go:59-69). This used to
     * check against the three this client can open, which is the same list for the Firefox table
     * and a different one for every Chrome hello — brotli alone (vendor/utls/u_parrots.go:162,
     * vendor/quic-go/internal/handshake/chrome_client_hello.go:53-55) — so a server answering a
     * Chrome hello in zlib was opened where the reference refuses it. */
    int is_offered = 0;
    for (size_t i = 1u; i + 1u < offered_len && i <= (size_t)offered[0]; i += 2u) {
        if (((unsigned)offered[i] << 8 | offered[i + 1u]) == algorithm)
            is_offered = 1;
    }
    if (!is_offered) {
        snprintf(err, err_cap, "the server compressed its certificate with algorithm %u, which our "
                               "hello did not offer",
                 algorithm);
        return LC_ALERT_BAD_CERTIFICATE;
    }

    /* The buffer is the caller's, and the caller sizes it as the reference does: the declared length,
     * whatever it is (vendor/utls/u_handshake_client.go:100), up to the sixteen megabytes three bytes
     * can say — its brotli and zstd readers fill all of it in one Read, and measured, a 300000-byte
     * certificate opens there (test/certcomp/reference_open.h). Until 2026-09-25 the caller capped it
     * at the Certificate message's own ceiling, 262144, and a longer declaration was refused here: an
     * open divergence for the maintainer, closed on "finish it to the ideal". What is left of this check is
     * a caller that could not get the memory, which tls/client.c answers before it gets here. For
     * zlib the answer is the same either way — its one Read stops at 32768, see open_zlib. */
    if (declared > out_cap) {
        snprintf(err, err_cap, "the compressed certificate says it opens to %u bytes, more than "
                               "this client reassembles",
                 (unsigned)declared);
        return LC_ALERT_BAD_CERTIFICATE;
    }

    /* ONE Read, AS THE REFERENCE MAKES IT. It allocates exactly the declared size and calls
     * decompressed.Read once (vendor/utls/u_handshake_client.go:100-117): an error other than EOF is
     * bad_certificate, fewer bytes than declared is bad_certificate, and NOTHING AFTER THAT ONE
     * CALL IS LOOKED AT — not the rest of the stream, not its checksum, not its end. What one call
     * returns is each Go reader's own business, so each algorithm below is a model of its reader,
     * and test/certcomp holds all three to what that reader actually answered
     * (tools/certcompread runs decompressCert itself). Until 2026-09-24 this opened the whole
     * stream and demanded it be exactly the declared length: 254 of the 480 cases there answered
     * otherwise. */
    int verdict;
    if (algorithm == LC_CERTCOMP_ZLIB)
        verdict = open_zlib(body + 8, compressed, declared, out);
    else if (algorithm == LC_CERTCOMP_BROTLI)
        verdict = open_brotli(body + 8, compressed, declared, out, go, go_cap);
    else
        verdict = open_zstd(body + 8, compressed, declared, out);

    if (verdict == LC_ALERT_INTERNAL_ERROR) {
        snprintf(err, err_cap, "no memory to open a compressed certificate");
        return verdict;
    }
    if (verdict != 0) {
        snprintf(err, err_cap, "the compressed certificate does not open to the %u bytes it "
                               "declares, as the reference reads it (%s)",
                 (unsigned)declared,
                 algorithm == LC_CERTCOMP_ZLIB     ? "zlib"
                 : algorithm == LC_CERTCOMP_BROTLI ? "brotli"
                                                   : "zstd");
        return verdict;
    }
    *out_len = declared;
    return 0;
}
