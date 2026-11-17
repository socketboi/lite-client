/* compress/gzip's Reader, with compress/flate under it and a bufio.Reader of 4096 under that, as
 * x/net reads a gzip answer through them (vendor/x-net/http2/transport.go:2802-2893) — for WHEN it
 * reads its source and how much, which is what it is for.
 *
 * The spider reads the page and every redirect's body through this stack in the reference, and
 * every Read of the body under it hands window back to the site: so the reads are on the wire, and
 * where the reader stops reading — flate hands output out only when its window fills, a block ends
 * the stream, or an empty stored block flushes — decides how much of a body is read before it is
 * closed. zlib inflates the same bytes to the same text and reads them on a schedule of its own, so
 * this is Go's decoder, part for part: bufio.Reader (GOROOT/src/bufio/bufio.go Read, ReadByte,
 * fill), io.ReadFull, the decompressor's steps and its Huffman tables
 * (GOROOT/src/compress/flate/inflate.go, dict_decoder.go), gzip.Reader's header, trailer and
 * members (GOROOT/src/compress/gzip/gunzip.go), and x/net's gzipReader, which makes the Reader on
 * the first Read and keeps its error.
 *
 * Without goroutines, a Read that would wait for its source returns to say so, and the next call
 * goes on from exactly there. Held to Go by test/gozip, against the reads tools/gozip logs from
 * Go's own reader. */
#ifndef LC_GOZIP_H
#define LC_GOZIP_H

#include <stddef.h>
#include <stdint.h>

/* An error as far as what reads it can tell: none, io.EOF, or any other. */
enum { LC_GZ_NONE = 0, LC_GZ_EOF = 1, LC_GZ_ERR = 2 };

/* One Read of the source asking for up to `cap` bytes: 0 when it returned — `*n` bytes at `*p`,
 * which stay valid until the source is next called, and `*err` — or 1 when it would wait, having
 * taken nothing. */
typedef int (*lc_gz_source)(void *ctx, size_t cap, const uint8_t **p, size_t *n, int *err);

typedef struct lc_gozip lc_gozip;

/* NULL without memory. Distinct decoders may be used concurrently; the shared
 * fixed-Huffman table is initialized once before publication. Each decoder and
 * its source still have one caller, and must outlive an in-progress Read. */
lc_gozip *lc_gozip_new(lc_gz_source src, void *ctx);
void      lc_gozip_free(lc_gozip *z);

/* One Read of up to `cap` decompressed bytes: 0 when it returned, with `*n` bytes at `*out` — valid
 * until the next call — and `*err`; 1 when it waits for the source, in which case the same call is
 * made again once the source has something, and goes on from where it stopped. -1 without memory. */
int lc_gozip_read(lc_gozip *z, size_t cap, const uint8_t **out, size_t *n, int *err);

#endif
