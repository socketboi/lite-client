/* HPACK — the header compression HTTP/2 uses, RFC 7541.
 *
 * The same shape as QPACK next door and not the same table: sixty-one static entries instead of
 * ninety-nine, in a different order, one-based instead of zero-based. What the two do share is the
 * Huffman code — verified identical, all two hundred fifty-seven symbols, between nghttp2's table
 * and nghttp3's — and the prefixed integer. Both are already written, so this file is the part that
 * is genuinely different rather than a second copy of the part that is not.
 *
 * BOTH DIRECTIONS KEEP A DYNAMIC TABLE of the default 4096 bytes, as the reference's do: this client
 * sends no SETTINGS_HEADER_TABLE_SIZE — the reference sends it only to ask for something other than
 * the default (vendor/x-net/http2/transport.go:535) — so the peer may insert, and the decoder keeps
 * what it inserts (LC_HPACK_DYN_MAX). The encoder's table outlived one block only from 24 September:
 * until then it looked up the static table alone, which is right for a connection carrying one
 * request and wrong for the spider's redirects, which carry several — see lc_hpack_enc. */
#ifndef LC_HPACK_H
#define LC_HPACK_H

#include <stddef.h>
#include <stdint.h>

/* HOW LONG A NAME OR A VALUE MAY BE: as long as the peer sends, up to the decoder's `max_str` when
 * that is set — Go's SetMaxStringLength, which x/net sets to MAX_HEADER_LIST_SIZE, ten megabytes.
 *
 * ⚠️ THIS WAS A FIXED BUFFER, and the bound has had three histories, each a way of being wrong. At
 * 1024 it was shorter than what this tree itself emits: the XHTTP opening request carries its padding
 * in a `referer` that reaches 1034 for www.avito.ru, and one gate run in a hundred and thirty went
 * red when the draw came out long (3 in 400 before the fix; the range, 100 to 1000, is the
 * reference's own — vendor/Xray-core/transport/internet/splithttp/xpadding.go:180-184). At 2048
 * longer ones were refused, which ends the connection x/net keeps on an ordinary three-kilobyte
 * Content-Security-Policy. At 4096 longer ones were cut and flagged, and the bytes past the cut went
 * unchecked where x/net checks every one. The spider decodes every block a site sends
 * (reality/fetch.c); none of the three was the reference. */

typedef struct {
    const char *name;
    const char *value;
} lc_hpack_field;

/* Writes `n` fields as one header block from a fresh encoder — the first block of a connection,
 * which is all XHTTP sends. Returns its length, or -1 if it does not fit. */
long lc_hpack_encode(const lc_hpack_field *fields, unsigned n, uint8_t *out, size_t cap);

/* The dynamic table's size, and it is the reference's number rather than one chosen here:
 * `initialHeaderTableSize = 4096` (vendor/x-net/http2/http2.go:81) is what an HTTP/2 peer assumes
 * when nothing says otherwise, and Go's client sends SETTINGS_HEADER_TABLE_SIZE only when it wants
 * something ELSE (vendor/x-net/http2/transport.go:535). Sending the default is how a client says
 * nothing.
 *
 * An entry costs its name plus its value plus thirty-two, by RFC 7541 section 4.1 — the constant
 * standing for the two lengths and the bookkeeping. That is what bounds the entry count: the
 * smallest possible entry is those thirty-two bytes, so four kilobytes cannot hold more than
 * a hundred and twenty-eight of them however short the strings are. */
#define LC_HPACK_DYN_MAX 4096u
#define LC_HPACK_DYN_ENTRIES (LC_HPACK_DYN_MAX / 32u)

/* ⚠️ THE ENCODER OF A CONNECTION THAT CARRIES MORE THAN ONE BLOCK, as x/net's hpack.Encoder is one
 * per connection (vendor/x-net/http2/transport.go:518-519): its dynamic table lasts from block to
 * block, so a second request refers back to the first. The spider's redirect on the same host is a
 * block of 44 bytes after one of 464 (tools/vendorcap/spiderredir) — which an encoder that forgot
 * its table would write as a second 464.
 *
 * Every decision is Go's (vendor/x-net/http2/hpack/encode.go, tables.go): the static table first,
 * then the dynamic one — the NEWEST entry that matches, the pair before the name, and a name found
 * only in the dynamic table used only when the static table has not got the name at all; a field
 * that fits the table is inserted with incremental indexing and evicts the oldest entries until the
 * table fits, one that does not is a literal without indexing; and once the table size has been
 * changed, the next block opens with the update, preceded by the smallest size it passed through if
 * that was smaller. Held to the vendored encoder by test/hpack (tools/hpackenc). */
typedef struct {
    /* The table, OLDEST first. Strings live end to end in `arena`, compacted on eviction. The
     * arena holds what a table of LC_HPACK_DYN_MAX can: every entry costs its strings and 32. */
    uint8_t  arena[LC_HPACK_DYN_MAX];
    uint16_t off_name[LC_HPACK_DYN_ENTRIES];
    uint16_t len_name[LC_HPACK_DYN_ENTRIES];
    uint16_t off_value[LC_HPACK_DYN_ENTRIES];
    uint16_t len_value[LC_HPACK_DYN_ENTRIES];
    unsigned entries;
    unsigned used;        /* bytes of `arena` in use */
    unsigned size;        /* the RFC's accounted size */
    unsigned max;         /* dynTab.maxSize */
    unsigned limit;       /* maxSizeLimit */
    unsigned min_size;    /* minSize — UINT32 max when there is none to announce */
    int      size_update; /* tableSizeUpdate */
} lc_hpack_enc;

void lc_hpack_enc_init(lc_hpack_enc *e);
/* The peer's SETTINGS_HEADER_TABLE_SIZE: SetMaxDynamicTableSize
 * (vendor/x-net/http2/transport.go:2566). */
void lc_hpack_enc_table_size(lc_hpack_enc *e, uint32_t v);
/* SetMaxDynamicTableSizeLimit. Above LC_HPACK_DYN_MAX is taken as that, which is x/net's default
 * and the most this client's table has room for. */
void lc_hpack_enc_table_limit(lc_hpack_enc *e, uint32_t v);
/* One header block on that connection. Returns its length, or -1 if it does not fit — and then the
 * table is in whatever state the fields before the failure left it, as Go's would be. */
long lc_hpack_enc_block(lc_hpack_enc *e, const lc_hpack_field *fields, unsigned n, uint8_t *out,
                        size_t cap);

/* The decoder, as Go's hpack.Decoder is one (vendor/x-net/http2/hpack/hpack.go): a header block is
 * fed in the pieces it arrives in — HEADERS, then each CONTINUATION — and a field is read when its
 * last byte is in, whatever piece that was; the bytes of one still incomplete wait for the next
 * piece, as Go's saveBuf holds them. Nothing is cut: a name or a value is handed back whole, however
 * long — up to `max_str` when that is set, which is SetMaxStringLength and past which the block is
 * refused, as Go's is.
 *
 * Zeroed by its caller, it starts where the protocol starts: a table of LC_HPACK_DYN_MAX, allowed no
 * more than that. lc_hpack_dec_free lets go of what it grew. */
typedef struct {
    /* lc_hpack_next's input: a whole block, read from `off`. */
    const uint8_t *in;
    size_t         len;
    size_t         off;

    /* The field last read, each NUL-terminated for the convenience of C and with its real length —
     * a value may carry a NUL, and the table is charged for what the peer sent. `sensitive` is a
     * literal never to be indexed. Owned: they grow to what the peer sends. */
    char  *name, *value;
    size_t name_len, value_len;
    int    sensitive;

    /* SetMaxStringLength (0 for none), and SetEmitEnabled(false): a field is then still read — its
     * representation consumed and, if the peer asked, inserted — but a string not going into the
     * table is not decoded, and lc_hpack_write does not hand the field on. */
    size_t max_str;
    int    emit_off;

    /* The dynamic table, newest first, exactly as HPACK numbers it. Strings live end to end in
     * `arena`; eviction compacts, which is cheap because it happens on a four-kilobyte buffer and
     * only when one is actually full. */
    uint8_t  arena[LC_HPACK_DYN_MAX];
    uint16_t off_name[LC_HPACK_DYN_ENTRIES];
    uint16_t len_name[LC_HPACK_DYN_ENTRIES];
    uint16_t off_value[LC_HPACK_DYN_ENTRIES];
    uint16_t len_value[LC_HPACK_DYN_ENTRIES];
    unsigned entries;
    unsigned used;    /* bytes of `arena` in use */
    unsigned size;    /* the RFC's accounted size: sum of name + value + 32 */
    unsigned max;     /* dynTab.maxSize: what the peer last set, LC_HPACK_DYN_MAX before it says */
    unsigned allowed; /* dynTab.allowedMaxSize: what this side offered, LC_HPACK_DYN_MAX */
    int      started;

    /* lc_hpack_write's state between pieces: firstField, and saveBuf. */
    int      mid;
    uint8_t *save;
    size_t   save_len, save_cap;
    size_t   name_cap, value_cap;
} lc_hpack_dec;

/* One field of a whole block: 1 with it in `name` and `value`, 0 at the end of the block, -1 when the
 * block is malformed or ends inside a field — what hpack.Decoder answers with an error, which x/net
 * makes a COMPRESSION_ERROR on the whole connection. */
int lc_hpack_next(lc_hpack_dec *d);

/* Decoder.Write: one piece of a header block. `emit` is called with each field completed in it, in
 * order, unless emit_off — with emit_off turned on from inside `emit` taking effect from the next
 * field, as SetEmitEnabled does. 0, or -1 on the error Write returns. */
typedef void (*lc_hpack_emit)(void *ctx, lc_hpack_dec *d);
int lc_hpack_write(lc_hpack_dec *d, const uint8_t *p, size_t n, lc_hpack_emit emit, void *ctx);

/* Decoder.Close: the block is over. -1 when bytes of an unfinished field are left — "truncated
 * headers". */
int lc_hpack_close(lc_hpack_dec *d);

void lc_hpack_dec_free(lc_hpack_dec *d);

#endif
