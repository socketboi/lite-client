/* Our HPACK against nghttp2's.
 *
 * The same arrangement that settled QPACK: what we encode is handed to the reference decoder, and
 * what the reference encodes is handed to ours. One direction alone proves nothing — a pair of
 * matching mistakes reads back perfectly and is refused by every server in the world.
 *
 * nghttp2 is vendored for this and linked only here. Nothing shipped depends on it. */

#include "h2/hpack.h"

#include <nghttp2/nghttp2.h>

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

/* The headers XHTTP's stream-one mode actually sends, plus a couple chosen to exercise the paths a
 * request would otherwise never reach: a name absent from the static table, and a value long
 * enough that its length does not fit in the prefix. */
static char long_value[600];

static const lc_hpack_field FIELDS[] = {
    { ":method", "POST" },        /* both halves in the table: one byte */
    { ":scheme", "https" },       /* likewise */
    { ":authority", "www.avito.ru" }, /* name in the table, value not */
    { ":path", "/x" },            /* name in the table, value not */
    { "content-type", "application/grpc" },
    { "x-padding", long_value },  /* neither half in the table, and long */
};

#define FIELD_COUNT (sizeof FIELDS / sizeof FIELDS[0])

/* The encoder of a connection, block after block, against x/net's own: tools/hpackenc runs the
 * vendored encoder over each scenario and keeps every block's length and FNV-1a. */
#include "reference_enc.h"

static uint64_t fnv64(const uint8_t *b, size_t n)
{
    uint64_t h = 14695981039346656037ull;
    for (size_t i = 0; i < n; i++) {
        h ^= b[i];
        h *= 1099511628211ull;
    }
    return h;
}

static void against_go(void)
{
    printf("\nthe encoder of a connection, against x/net's (tools/hpackenc)\n");
    static char    rep[64][8192]; /* the longest value the generator writes is 5000 */
    static uint8_t out[1 << 16];
    unsigned       scenarios = sizeof ref_enc_scenarios / sizeof ref_enc_scenarios[0];
    unsigned       blocks = 0, matched = 0, first_bad = ~0u;
    unsigned       decoded = 0, dec_agree = 0, dec_refused = 0, dec_first_bad = ~0u;
    for (unsigned s = 0; s < scenarios; s++) {
        lc_hpack_enc e;
        lc_hpack_enc_init(&e);
        /* The other end: one decoder for the connection, as x/net's client keeps it, reading each
         * block the encoder wrote — Go's bytes, when the line above says they match — and held to
         * what Go's own decoder made of the same bytes: refused, or which fields in which order. */
        static lc_hpack_dec dec;
        lc_hpack_dec_free(&dec);
        memset(&dec, 0, sizeof dec);
        int dead = 0;
        for (unsigned o = ref_enc_scenarios[s][0]; o < ref_enc_scenarios[s][0] + ref_enc_scenarios[s][1]; o++) {
            const ref_enc_op *op = &ref_enc_ops[o];
            if (op->kind == 1) {
                lc_hpack_enc_table_size(&e, op->v);
                continue;
            }
            if (op->kind == 2) {
                lc_hpack_enc_table_limit(&e, op->v);
                continue;
            }
            lc_hpack_field fs[64];
            for (unsigned i = 0; i < op->n && i < 64u; i++) {
                const ref_enc_field *rf = &ref_enc_fields[op->first + i];
                fs[i].name = rf->name;
                if (rf->value != NULL) {
                    fs[i].value = rf->value;
                } else {
                    if (rf->rep_len >= sizeof rep[i]) {
                        ok(0, "reference_enc.h holds a value longer than this test can build");
                        return;
                    }
                    memset(rep[i], rf->rep, rf->rep_len);
                    rep[i][rf->rep_len] = '\0';
                    fs[i].value = rep[i];
                }
            }
            long n = lc_hpack_enc_block(&e, fs, op->n, out, sizeof out);
            blocks++;
            if (n == (long)op->len && fnv64(out, (size_t)n) == op->fnv)
                matched++;
            else if (first_bad == ~0u)
                first_bad = o;
            if (!dead && n > 0) {
                static uint8_t all[1 << 16];
                size_t         al = 0;
                int            r;
                dec.in = out;
                dec.len = (size_t)n;
                dec.off = 0;
                while ((r = lc_hpack_next(&dec)) == 1) {
                    if (al + dec.name_len + dec.value_len + 2u > sizeof all)
                        break;
                    memcpy(all + al, dec.name, dec.name_len);
                    al += dec.name_len;
                    all[al++] = 0;
                    memcpy(all + al, dec.value, dec.value_len);
                    al += dec.value_len;
                    all[al++] = 0;
                }
                int ok_here = r == 0 ? op->dec == 1 && fnv64(all, al) == op->dfnv : op->dec == 0;
                decoded++;
                dec_agree += (unsigned)ok_here;
                dec_refused += (unsigned)(r != 0);
                if (!ok_here && dec_first_bad == ~0u)
                    dec_first_bad = o;
                dead = r != 0;
            }
            /* The spider's own pair: its first request, and a redirect's on the same connection. */
            if (s == 0 && o == 1)
                ok(n == (long)op->len && n < 64,
                   "a redirect's block refers back to the first request's: tens of bytes, as Go's");
        }
    }
    printf("        %u blocks in %u scenarios, %u as Go wrote them", blocks, scenarios, matched);
    if (first_bad != ~0u)
        printf(" — the first that is not is operation %u", first_bad);
    printf("\n");
    ok(blocks > 0 && matched == blocks, "every block, byte for byte, as x/net's encoder wrote it");
    printf("        %u decoded, %u as Go's decoder read them, %u refused", decoded, dec_agree,
           dec_refused);
    if (dec_first_bad != ~0u)
        printf(" — the first that is not is operation %u", dec_first_bad);
    printf("\n");
    ok(decoded > 0 && dec_agree == decoded,
       "and every one reads back through one decoder per connection as x/net's decoder reads it");
}


/* The decoder, against x/net's (tools/hpackdec): the same header blocks in the same pieces — whole,
 * byte by byte, cut anywhere, malformed on purpose and at random — through one decoder per case,
 * with emission turned off after the same field when the case says so. Every piece has to come out
 * as Go's Write did: refused or not, the same fields emitted during it, and every block's Close the
 * same. */
#include "hpackdec_vectors.h"

static struct {
    unsigned           fields;
    unsigned long long h;
    unsigned           total;
    int                off_at;
} em;

static unsigned long long fnv_more(unsigned long long h, const void *p, size_t n)
{
    const uint8_t *b = p;
    for (size_t i = 0; i < n; i++) {
        h ^= b[i];
        h *= 1099511628211ull;
    }
    return h;
}

static void on_field(void *ctx, lc_hpack_dec *d)
{
    (void)ctx;
    static const uint8_t zero = 0, one = 1;
    em.h = fnv_more(em.h, d->name, d->name_len);
    em.h = fnv_more(em.h, &zero, 1);
    em.h = fnv_more(em.h, d->value, d->value_len);
    em.h = fnv_more(em.h, &zero, 1);
    if (d->sensitive)
        em.h = fnv_more(em.h, &one, 1);
    em.fields++;
    em.total++;
    if (em.off_at >= 0 && em.total == (unsigned)em.off_at)
        d->emit_off = 1;
}

static void against_go_decoder(void)
{
    printf("\nthe decoder, against x/net's (tools/hpackdec)\n");
    unsigned ncases = (unsigned)(sizeof ref_dec_cases / sizeof ref_dec_cases[0]);
    unsigned pieces = 0, agree = 0, bad_cases = 0;
    for (unsigned c = 0; c < ncases; c++) {
        const ref_dec_case *rc = &ref_dec_cases[c];
        lc_hpack_dec        d;
        memset(&d, 0, sizeof d);
        d.max_str = rc->max_str;
        em.total = 0;
        em.off_at = rc->off_at;
        int case_ok = 1;
        for (unsigned b = rc->first; b < rc->first + rc->n; b++) {
            const ref_dec_block *rb = &ref_dec_blocks[b];
            int                  dead = 0;
            for (unsigned p = rb->first; p < rb->first + rb->n; p++) {
                const ref_dec_piece *rp = &ref_dec_pieces[p];
                em.fields = 0;
                em.h = 14695981039346656037ull;
                int r = lc_hpack_write(&d, (const uint8_t *)rp->bytes, rp->len, on_field, NULL);
                int same = (r != 0) == (rp->err != 0) && em.fields == rp->fields && em.h == rp->fnv;
                pieces++;
                agree += (unsigned)same;
                if (!same && case_ok) {
                    printf("        %s: block %u piece %u — ours %s with %u fields, Go's %s with %u\n",
                           rc->name, b - rc->first, p - rb->first, r ? "refused" : "read", em.fields,
                           rp->err ? "refused" : "read", rp->fields);
                    case_ok = 0;
                }
                if (rp->err) {
                    dead = 1;
                    break;
                }
            }
            if (!dead && rb->close != 2) {
                int r = lc_hpack_close(&d);
                if ((r != 0) != (rb->close != 0)) {
                    if (case_ok)
                        printf("        %s: block %u — ours closed %s, Go's %s\n", rc->name,
                               b - rc->first, r ? "refused" : "clean", rb->close ? "refused" : "clean");
                    case_ok = 0;
                }
            }
        }
        bad_cases += (unsigned)!case_ok;
        lc_hpack_dec_free(&d);
    }
    printf("        %u cases, %u pieces, %u as Go's decoder read them\n", ncases, pieces, agree);
    ok(ncases > 400u && bad_cases == 0 && agree == pieces,
       "every piece read — or refused — as Go's decoder does, and every block closed the same");
}

int main(void)
{
    memset(long_value, 'q', sizeof long_value - 1u);
    long_value[sizeof long_value - 1u] = '\0';

    printf("\nHPACK against nghttp2\n");

    uint8_t block[4096];
    long    n = lc_hpack_encode(FIELDS, FIELD_COUNT, block, sizeof block);
    ok(n > 0, "the header block encodes");
    if (n <= 0)
        return 1;

    /* A field whose halves are both in the table has to cost one byte, or the lookup is not
     * finding what it should and the block is merely long rather than wrong — which no decoder
     * would ever complain about. */
    /* NOTHING BEFORE THE FIRST FIELD. The block used to open with 0x20 — a size update to zero —
     * and the reference opens with none: Go's encoder emits one only when the size it was given
     * changed (vendor/x-net/http2/hpack/encode.go:52-59), which on a fresh connection is never. */
    ok(block[0] == (0x80u | 3u), ":method POST is the single byte the table says it is, and first");
    ok(block[1] == (0x80u | 7u), ":scheme https likewise");

    /* A NAME THE STATIC TABLE HOLDS TWICE IS REFERRED TO BY ITS NEWER INDEX, as x/net's lookup maps
     * are built (vendor/x-net/http2/hpack/tables.go:53-64): `:path` other than `/` by 5, not 4;
     * `:method` other than GET and POST by 3, not 2. One byte each, the first of the field. */
    {
        static const lc_hpack_field path[] = { { ":path", "/x" } };
        static const lc_hpack_field method[] = { { ":method", "PUT" } };
        uint8_t b[64];
        ok(lc_hpack_encode(path, 1, b, sizeof b) > 0 && b[0] == (0x40u | 5u),
           ":path /x is a literal on index 5, the newest :path, as Go sends it");
        ok(lc_hpack_encode(method, 1, b, sizeof b) > 0 && b[0] == (0x40u | 3u),
           ":method PUT is a literal on index 3, the newest :method");
    }

    nghttp2_hd_inflater *inf = NULL;
    ok(nghttp2_hd_inflate_new(&inf) == 0, "nghttp2's decoder starts");
    if (inf == NULL)
        return 1;

    /* LEFT AT THE DEFAULT, which is what this client now advertises by saying nothing — and the
     * change is what this line is for. It used to call nghttp2_hd_inflate_change_table_size(inf, 0),
     * mirroring a SETTINGS_HEADER_TABLE_SIZE of zero we no longer send; that call arms nghttp2 to
     * DEMAND a dynamic table size update at the head of the next block, and a block without one is
     * refused whole with "Header compression/decompression error". Which is exactly what it did the
     * moment the update was removed — the reference noticing, on cue. */

    unsigned seen = 0;
    const uint8_t *p = block;
    size_t         left = (size_t)n;
    int            final = 1;

    for (;;) {
        nghttp2_nv nv;
        int        flags = 0;
        nghttp2_ssize r = nghttp2_hd_inflate_hd2(inf, &nv, &flags, p, left, final);
        if (r < 0) {
            printf("  FAIL  nghttp2 refused the block: %s\n", nghttp2_strerror((int)r));
            failures++;
            break;
        }
        p += r;
        left -= (size_t)r;

        if (flags & NGHTTP2_HD_INFLATE_EMIT) {
            int match = seen < FIELD_COUNT &&
                        strlen(FIELDS[seen].name) == nv.namelen &&
                        memcmp(FIELDS[seen].name, nv.name, nv.namelen) == 0 &&
                        strlen(FIELDS[seen].value) == nv.valuelen &&
                        memcmp(FIELDS[seen].value, nv.value, nv.valuelen) == 0;
            if (!match) {
                printf("  FAIL  field %u came back as %.*s: %.*s\n", seen, (int)nv.namelen,
                       nv.name, (int)nv.valuelen, nv.value);
                failures++;
            }
            seen++;
        }
        if (flags & NGHTTP2_HD_INFLATE_FINAL)
            break;
        if (left == 0)
            break;
    }

    ok(seen == FIELD_COUNT, "every field comes back, and no more than were sent");
    nghttp2_hd_inflate_end_headers(inf);
    nghttp2_hd_inflate_del(inf);

    /* And the other direction: what nghttp2 produces, we read. Its encoder chooses forms ours never
     * emits — indexed names with incremental indexing among them — so this is the half that catches
     * a decoder written to understand only its own encoder. */
    nghttp2_hd_deflater *def = NULL;
    /* WITH A REAL TABLE, four kilobytes of it, which is the size both ends now assume. Zero was
     * asked for here before, and zero is the one setting under which nghttp2 never inserts anything
     * — so the whole indexed half of HPACK went unexercised, and a decoder that ignored incremental
     * indexing passed. It no longer can: nghttp2 fills the table as it encodes, refers back to it,
     * and every reference that comes back wrong is a header pointing at the wrong value. */
    ok(nghttp2_hd_deflate_new(&def, LC_HPACK_DYN_MAX) == 0,
       "nghttp2's encoder starts with the four-kilobyte table both ends assume");
    if (def == NULL)
        return failures == 0 ? 0 : 1;

    nghttp2_nv out_nv[FIELD_COUNT];
    for (unsigned i = 0; i < FIELD_COUNT; i++) {
        out_nv[i].name = (uint8_t *)(size_t)FIELDS[i].name;
        out_nv[i].namelen = strlen(FIELDS[i].name);
        out_nv[i].value = (uint8_t *)(size_t)FIELDS[i].value;
        out_nv[i].valuelen = strlen(FIELDS[i].value);
        out_nv[i].flags = NGHTTP2_NV_FLAG_NONE;
    }

    /* TWICE, WITH ONE DECODER, and the second round is the one that matters. HPACK state belongs to
     * the connection, not the block: on the first block nghttp2 fills its dynamic table, and only on
     * the second does it refer BACK to it — a one-byte indexed field where the first block spelled
     * out a name and a value. A decoder that quietly ignores incremental indexing survives round one
     * and reads round two as a different set of headers, without erroring: every index above the
     * one it failed to insert has shifted by one, so it reports the neighbour's value. That is the
     * failure this loop exists to catch, and it cannot be caught with a single block. */
    uint8_t       theirs[4096];
    lc_hpack_dec  d;
    memset(&d, 0, sizeof d);

    for (unsigned round = 0; round < 2u; round++) {
        nghttp2_ssize tn = nghttp2_hd_deflate_hd2(def, theirs, sizeof theirs, out_nv, FIELD_COUNT);
        ok(tn > 0, round == 0 ? "nghttp2 encodes the same fields"
                              : "and encodes them again, now against its own dynamic table");
        if (tn <= 0)
            break;
        if (round == 1)
            ok((size_t)tn < sizeof theirs && tn < 200,
               "the second block is far shorter, which is the table being used");

        d.in = theirs;
        d.len = (size_t)tn;
        d.off = 0;

        unsigned back = 0;
        for (;;) {
            int r = lc_hpack_next(&d);
            if (r < 0) {
                printf("  FAIL  we refused nghttp2's block at byte %zu\n", d.off);
                failures++;
                break;
            }
            if (r == 0)
                break;
            int match = back < FIELD_COUNT && strcmp(d.name, FIELDS[back].name) == 0 &&
                        strcmp(d.value, FIELDS[back].value) == 0;
            if (!match) {
                printf("  FAIL  field %u read back as %s: %s\n", back, d.name, d.value);
                failures++;
            }
            back++;
        }
        ok(back == FIELD_COUNT, "and every one of them reads back");
    }
    nghttp2_hd_deflate_del(def);

    /* ---- boundaries ----------------------------------------------------------
     *
     * Every prefix of a good block, and a handful of bad ones. A decoder is fed by the peer, so the
     * lengths in front of it are the peer's choice — which is how the one real bug in this file got
     * in: a length used as an index wrote past the end for any value longer than the buffer.
     *
     * The property asserted is narrow on purpose: whatever it answers, it must not read or write
     * outside what it was given, and it must not claim a field it did not have all of. Under a
     * sanitiser that is a real check; without one it is still the shape that crashes. */
    int truncations = 0;
    for (size_t cut = 0; cut < (size_t)n; cut++) {
        lc_hpack_dec d2;
        memset(&d2, 0, sizeof d2);
        d2.in = block;
        d2.len = cut;

        for (;;) {
            int r = lc_hpack_next(&d2);
            if (r <= 0)
                break;
            /* A field it claims to have read must lie inside what it was given. */
            if (d2.off > cut) {
                printf("  FAIL  a %zu-byte prefix was read %zu bytes deep\n", cut, d2.off);
                failures++;
                break;
            }
        }
        truncations++;
    }
    ok(truncations == (int)n, "every prefix of the block is refused or read without running past it");

    /* Lengths that do not fit what follows them, at each width the encoding has. */
    static const struct {
        const char   *what;
        const uint8_t bytes[8];
        size_t        len;
    } bad[] = {
        { "an indexed field beyond the static table", { 0x20u, 0xffu, 0x01u }, 3u },
        { "a literal whose name length overruns", { 0x20u, 0x00u, 0x7fu, 0x00u }, 4u },
        { "a literal whose name length is enormous", { 0x20u, 0x00u, 0x7fu, 0xffu, 0xffu, 0xffu,
                                                       0xffu, 0x7fu }, 8u },
        { "a size update to something other than zero", { 0x3fu, 0xe1u, 0x1fu }, 3u },
        { "a continuation that never ends", { 0x20u, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu,
                                              0xffu }, 8u },
    };

    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        lc_hpack_dec d3;
        memset(&d3, 0, sizeof d3);
        d3.in = bad[i].bytes;
        d3.len = bad[i].len;

        int refused = 0;
        for (;;) {
            int r = lc_hpack_next(&d3);
            if (r < 0) {
                refused = 1;
                break;
            }
            if (r == 0 || d3.off > bad[i].len)
                break;
        }
        ok(refused || d3.off <= bad[i].len, bad[i].what);
    }

    /* Nothing at all is the end of a block, not a failure and not a field. */
    lc_hpack_dec d4;
    memset(&d4, 0, sizeof d4);
    d4.in = block;
    d4.len = 0;
    ok(lc_hpack_next(&d4) == 0, "an empty block is the end of one");

    against_go();
    against_go_decoder();
    printf("\n%s\n", failures == 0 ? "the header compression agrees" : "HPACK is WRONG");
    return failures == 0 ? 0 : 1;
}
