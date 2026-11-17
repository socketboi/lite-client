#include "h2/hpack.h"

#include "quic/huffman.h"
#include "quic/prefix.h"

#include <stdlib.h>
#include <string.h>

/* The static table, generated from nghttp2 at build time rather than typed out here. Its ORDER is
 * the protocol — an index is a position in it — so the one thing that must not happen is somebody
 * correcting an entry by hand. See the rule in the Makefile. */
static const struct {
    const char *name;
    const char *value;
} static_table[] = {
#include "hpack_static.h"
};

#define STATIC_COUNT (sizeof static_table / sizeof static_table[0])

/* ---- strings ----------------------------------------------------------------
 *
 * A length behind a one-bit flag saying whether what follows is Huffman-coded. Both directions use
 * the same seven-bit prefix, which is why neither needs to be told which it is. */

/* HPACK's string is QPACK's string with the pattern fixed at zero and seven bits of prefix, so the
 * body lives in lc_prefix_put_string and this is the shape the callers here expect: a signed length
 * with -1 for "did not fit". The two used to be separate functions that agreed on everything except
 * whether to check the coder against its own declared length — this one did, the other did not. */
static long put_string(uint8_t *out, size_t cap, const char *s, size_t len)
{
    size_t n = lc_prefix_put_string(out, cap, 0x00u, 7u, s, len);
    return n == 0 ? -1 : (long)n;
}

/* ---- encoding ---------------------------------------------------------------- */

/* Where this name and value already sit in the static table, if they do. Returns the index, or 0
 * for no match at all, and sets `name_only` when only the name was found — which is still worth
 * having, since it is the longer half of most headers.
 *
 * ⚠️ THE NEWEST ENTRY WITH THE NAME, NOT THE FIRST. x/net builds its lookup maps by walking the
 * table in order and letting a later entry overwrite an earlier one — "Map to the newest matching
 * entry: later (newer) entries overwrite earlier ones" (vendor/x-net/http2/hpack/tables.go:53-64) —
 * so a name the static table holds twice is referred to by its SECOND index. `:path` is the one
 * that matters here: entries 4 (`/`) and 5 (`/index.html`), so every path other than `/` goes out as
 * 0x45 from a Go client. This took the first match and sent 0x44, on every XHTTP request and every
 * spider request with a harvested path. `:method` (2, 3), `:scheme` (6, 7) and `:status` (8 to 14)
 * follow the same rule. */
static unsigned lookup(const char *name, const char *value, int *name_only)
{
    unsigned name_match = 0;
    *name_only = 0;

    for (unsigned i = 0; i < STATIC_COUNT; i++) {
        if (strcmp(static_table[i].name, name) != 0)
            continue;
        if (strcmp(static_table[i].value, value) == 0)
            return i + 1u; /* the table is one-based */
        name_match = i + 1u;
    }

    *name_only = name_match != 0;
    return name_match;
}

/* ---- the encoder's dynamic table ----------------------------------------------- */

#define NO_MIN_SIZE 0xffffffffu /* uint32Max, what minSize holds when there is nothing to announce */

static unsigned entry_size(size_t name_len, size_t value_len)
{
    return (unsigned)(name_len + value_len + 32u); /* HeaderField.Size, RFC 7541 section 4.1 */
}

/* Drops the `n` oldest entries and moves the rest of the arena down over their strings. */
static void enc_drop_oldest(lc_hpack_enc *e, unsigned n)
{
    if (n == 0u)
        return;
    unsigned gone = 0;
    for (unsigned i = 0; i < n; i++) {
        e->size -= entry_size(e->len_name[i], e->len_value[i]);
        gone += (unsigned)e->len_name[i] + e->len_value[i];
    }
    memmove(e->arena, e->arena + gone, e->used - gone);
    e->used -= gone;
    for (unsigned i = n; i < e->entries; i++) {
        e->off_name[i - n] = (uint16_t)(e->off_name[i] - gone);
        e->len_name[i - n] = e->len_name[i];
        e->off_value[i - n] = (uint16_t)(e->off_value[i] - gone);
        e->len_value[i - n] = e->len_value[i];
    }
    e->entries -= n;
}

/* dynamicTable.evict: the oldest go until what is left fits (vendor/x-net/http2/hpack/hpack.go). */
static void enc_evict(lc_hpack_enc *e, unsigned budget)
{
    unsigned n = 0, size = e->size;
    while (size > budget && n < e->entries) {
        size -= entry_size(e->len_name[n], e->len_value[n]);
        n++;
    }
    enc_drop_oldest(e, n);
}

void lc_hpack_enc_init(lc_hpack_enc *e)
{
    memset(e, 0, sizeof *e);
    e->max = LC_HPACK_DYN_MAX;
    e->limit = LC_HPACK_DYN_MAX;
    e->min_size = NO_MIN_SIZE;
}

void lc_hpack_enc_table_size(lc_hpack_enc *e, uint32_t v)
{
    if (v > e->limit)
        v = e->limit;
    if (v < e->min_size)
        e->min_size = v;
    e->size_update = 1;
    e->max = v;
    enc_evict(e, e->max);
}

void lc_hpack_enc_table_limit(lc_hpack_enc *e, uint32_t v)
{
    if (v > LC_HPACK_DYN_MAX)
        v = LC_HPACK_DYN_MAX;
    e->limit = v;
    if (e->max > v) {
        e->size_update = 1;
        e->max = v;
        enc_evict(e, e->max);
    }
}

/* The newest entry holding `name` — and `value` too, when `value` is given — as a dynamic index
 * (the newest is 1), or 0. The newest because x/net's lookup maps are overwritten by each insertion
 * and cleared only when the entry they point to is evicted, which with oldest-first eviction is
 * the same as asking for the newest one still there (vendor/x-net/http2/hpack/tables.go). */
static unsigned enc_find(const lc_hpack_enc *e, const char *name, size_t nl, const char *value,
                         size_t vl)
{
    for (unsigned k = e->entries; k-- > 0;) {
        if (e->len_name[k] != nl || memcmp(e->arena + e->off_name[k], name, nl) != 0)
            continue;
        if (value != NULL &&
            (e->len_value[k] != vl || memcmp(e->arena + e->off_value[k], value, vl) != 0))
            continue;
        return e->entries - k;
    }
    return 0;
}

/* dynamicTable.add — the eviction first, which comes to the same thing as Go's add-then-evict: the
 * field is added only when it fits the whole table, so the evicting never reaches it. */
static void enc_add(lc_hpack_enc *e, const char *name, size_t nl, const char *value, size_t vl)
{
    unsigned sz = entry_size(nl, vl);
    enc_evict(e, e->max - sz);
    unsigned k = e->entries;
    e->off_name[k] = (uint16_t)e->used;
    e->len_name[k] = (uint16_t)nl;
    memcpy(e->arena + e->used, name, nl);
    e->used += (unsigned)nl;
    e->off_value[k] = (uint16_t)e->used;
    e->len_value[k] = (uint16_t)vl;
    memcpy(e->arena + e->used, value, vl);
    e->used += (unsigned)vl;
    e->size += sz;
    e->entries++;
}

/* appendTableSize: 001xxxxx and a five-bit prefix. */
static int put_table_size(uint8_t *out, size_t cap, size_t *off, uint32_t v)
{
    size_t w = lc_prefix_put(out + *off, cap - *off, 0x20u, 5u, v);
    if (w == 0)
        return -1;
    *off += w;
    return 0;
}

long lc_hpack_enc_block(lc_hpack_enc *e, const lc_hpack_field *fields, unsigned n, uint8_t *out,
                        size_t cap)
{
    size_t off = 0;
    for (unsigned i = 0; i < n; i++) {
        const char *name = fields[i].name;
        const char *value = fields[i].value;
        if (name == NULL || value == NULL)
            return -1;
        size_t nl = strlen(name), vl = strlen(value);

        /* WriteField's first act, and only on the first field after a change: the smallest size the
         * table passed through, if smaller than where it ended up, then where it ended up. */
        if (e->size_update) {
            e->size_update = 0;
            if (e->min_size < e->max && put_table_size(out, cap, &off, e->min_size) != 0)
                return -1;
            e->min_size = NO_MIN_SIZE;
            if (put_table_size(out, cap, &off, e->max) != 0)
                return -1;
        }

        /* searchTable: the static table, then the dynamic one. */
        int      name_only = 0;
        uint64_t idx = lookup(name, value, &name_only);
        if (idx != 0 && !name_only) {
            size_t w = lc_prefix_put(out + off, cap - off, 0x80u, 7u, idx);
            if (w == 0)
                return -1;
            off += w;
            continue;
        }
        unsigned dyn_pair = enc_find(e, name, nl, value, vl);
        if (dyn_pair != 0) {
            size_t w = lc_prefix_put(out + off, cap - off, 0x80u, 7u, STATIC_COUNT + dyn_pair);
            if (w == 0)
                return -1;
            off += w;
            continue;
        }
        if (idx == 0) {
            unsigned dyn_name = enc_find(e, name, nl, NULL, 0);
            if (dyn_name != 0)
                idx = STATIC_COUNT + dyn_name;
        }

        /* shouldIndex: a field that fits the table goes into it, and says so; one that does not is
         * a literal WITHOUT indexing — 0x00 and a four-bit prefix, not 0x40 and six. */
        int indexing = entry_size(nl, vl) <= e->max;
        if (indexing)
            enc_add(e, name, nl, value, vl);
        size_t w = indexing ? lc_prefix_put(out + off, cap - off, 0x40u, 6u, idx)
                            : lc_prefix_put(out + off, cap - off, 0x00u, 4u, idx);
        if (w == 0)
            return -1;
        off += w;

        if (idx == 0) {
            long ln = put_string(out + off, cap - off, name, nl);
            if (ln < 0)
                return -1;
            off += (size_t)ln;
        }
        long lv = put_string(out + off, cap - off, value, vl);
        if (lv < 0)
            return -1;
        off += (size_t)lv;
    }
    return (long)off;
}

long lc_hpack_encode(const lc_hpack_field *fields, unsigned n, uint8_t *out, size_t cap)
{
    /* NO SIZE UPDATE OPENS THIS BLOCK, and its absence is the point: RFC 7541 section 4.2 requires
     * one only after the peer has announced a size, and this client announces none — the reference
     * sends SETTINGS_HEADER_TABLE_SIZE only to ask for something other than the default
     * (vendor/x-net/http2/transport.go:535). A fresh encoder has nothing to announce, which is what
     * Go's emits too until it is told a size (vendor/x-net/http2/hpack/encode.go:52-59).
     *
     * Fresh each time: the callers of this send one block per connection. The spider's later
     * requests keep an lc_hpack_enc of their own. */
    lc_hpack_enc e;
    lc_hpack_enc_init(&e);
    long r = lc_hpack_enc_block(&e, fields, n, out, cap);
    return r;
}


/* ---- the dynamic table -------------------------------------------------------
 *
 * Newest first, which is how HPACK numbers it: index 62 is the last thing inserted. An entry is
 * charged its name plus its value plus thirty-two (RFC 7541 section 4.1), and inserting evicts from
 * the OLD end until the charge fits — including, legally, evicting everything and then refusing the
 * entry itself, which section 4.4 says is not an error.
 *
 * Strings live end to end in one arena and eviction compacts it. That is the cheap way round here:
 * the arena is four kilobytes, evictions happen only when a peer actually fills it, and the
 * alternative — a ring with wrap-around — is where the bugs in this kind of code live. */
static void dyn_drop_oldest(lc_hpack_dec *d)
{
    if (d->entries == 0)
        return;
    unsigned last = d->entries - 1u;
    unsigned bytes = (unsigned)d->len_name[last] + (unsigned)d->len_value[last];

    /* The oldest entry is not necessarily last in the arena, so compaction moves everything above
     * its strings down and fixes every offset that pointed above them. */
    unsigned at = d->off_name[last];
    unsigned tail = d->used - (at + bytes);
    if (tail > 0)
        memmove(d->arena + at, d->arena + at + bytes, tail);
    d->used -= bytes;

    for (unsigned i = 0; i < last; i++) {
        if (d->off_name[i] > at)
            d->off_name[i] = (uint16_t)(d->off_name[i] - bytes);
        if (d->off_value[i] > at)
            d->off_value[i] = (uint16_t)(d->off_value[i] - bytes);
    }

    d->size -= bytes + 32u;
    d->entries = last;
}

static void dyn_insert(lc_hpack_dec *d, const char *name, size_t nl, const char *value, size_t vl)
{
    unsigned charge = (unsigned)nl + (unsigned)vl + 32u;

    while (d->entries > 0 && d->size + charge > d->max)
        dyn_drop_oldest(d);

    /* "If the size of the new entry is larger than the maximum size, the table is emptied of all
     * existing entries and results in an empty table" — section 4.4, and the entry is dropped. */
    if (charge > d->max || d->entries >= LC_HPACK_DYN_ENTRIES ||
        d->used + nl + vl > LC_HPACK_DYN_MAX)
        return;

    for (unsigned i = d->entries; i > 0; i--) {
        d->off_name[i] = d->off_name[i - 1u];
        d->len_name[i] = d->len_name[i - 1u];
        d->off_value[i] = d->off_value[i - 1u];
        d->len_value[i] = d->len_value[i - 1u];
    }

    memcpy(d->arena + d->used, name, nl);
    d->off_name[0] = (uint16_t)d->used;
    d->len_name[0] = (uint16_t)nl;
    d->used += (unsigned)nl;

    memcpy(d->arena + d->used, value, vl);
    d->off_value[0] = (uint16_t)d->used;
    d->len_value[0] = (uint16_t)vl;
    d->used += (unsigned)vl;

    d->size += charge;
    d->entries++;
}


/* ---- reading a block, as Go's Decoder reads one -------------------------------------------------
 *
 * Every rule below is hpack.Decoder's (vendor/x-net/http2/hpack/hpack.go), transcribed: the five
 * representations told apart by their top bits, readVarInt with its own overflow and its own "need
 * more", readString refusing a declared length past max_str before the bytes are in, decodeString
 * doing Huffman with the same bound, callEmit refusing a field whose name or value is longer, a size
 * update only as the block's first representation or into an empty table, and a string decoded only
 * when it is going to be emitted or into the table. Held to Go's own decoder by test/hpack
 * (tools/hpackenc and tools/hpackdec). */

enum { R_DONE, R_MORE, R_ERR };

static void dec_start(lc_hpack_dec *d)
{
    if (d->started)
        return;
    d->started = 1;
    if (d->allowed == 0)
        d->allowed = LC_HPACK_DYN_MAX;
    if (d->max == 0)
        d->max = d->allowed;
}

/* readVarInt (hpack.go:433-466): R_MORE when the integer runs past the input, R_ERR once nine bytes
 * of continuation have been read — errVarintOverflow, whether or not more bytes are there. */
static int read_varint(unsigned n, const uint8_t *p, size_t len, size_t *at, uint64_t *out)
{
    if (*at >= len)
        return R_MORE;
    uint64_t i = p[*at] & ((1u << n) - 1u);
    if (i < (1u << n) - 1u) {
        (*at)++;
        *out = i;
        return R_DONE;
    }
    size_t   k = *at + 1u;
    unsigned m = 0;
    while (k < len) {
        uint8_t b = p[k++];
        i += (uint64_t)(b & 127u) << m;
        if ((b & 128u) == 0) {
            *at = k;
            *out = i;
            return R_DONE;
        }
        m += 7u;
        if (m >= 63u)
            return R_ERR;
    }
    return R_MORE;
}

/* Room for `n` bytes and a NUL in one of the two strings. */
static int grow(char **s, size_t *cap, size_t n)
{
    if (n + 1u <= *cap)
        return 0;
    char *p = realloc(*s, n + 1u);
    if (p == NULL)
        return -1;
    *s = p;
    *cap = n + 1u;
    return 0;
}

/* readString (hpack.go:478-501): where the string's bytes are, R_MORE until all of them are in. */
static int read_string(const lc_hpack_dec *d, const uint8_t *p, size_t len, size_t *at, int *huff,
                       const uint8_t **s, size_t *n)
{
    if (*at >= len)
        return R_MORE;
    *huff = (p[*at] & 128u) != 0;
    uint64_t sl = 0;
    int      r = read_varint(7u, p, len, at, &sl);
    if (r != R_DONE)
        return r;
    if (d->max_str != 0u && sl > (uint64_t)d->max_str)
        return R_ERR; /* ErrStringLength */
    if ((uint64_t)(len - *at) < sl)
        return R_MORE;
    *s = p + *at;
    *n = (size_t)sl;
    *at += (size_t)sl;
    return R_DONE;
}

/* decodeString (hpack.go:508-522), into one of the two strings. */
static int decode_string(const lc_hpack_dec *d, int huff, const uint8_t *s, size_t n, char **out,
                         size_t *cap, size_t *out_len)
{
    if (!huff) {
        if (grow(out, cap, n) != 0)
            return R_ERR;
        memcpy(*out, s, n);
        (*out)[n] = '\0';
        *out_len = n;
        return R_DONE;
    }
    /* The shortest code is five bits, so n bytes decode to at most n * 8 / 5 symbols. */
    size_t most = n / 5u * 8u + 8u;
    if (grow(out, cap, most) != 0)
        return R_ERR;
    long got = lc_huff_decode(s, n, *out, *cap);
    if (got < 0)
        return R_ERR; /* ErrInvalidHuffman */
    if (d->max_str != 0u && (size_t)got > d->max_str)
        return R_ERR; /* huffmanDecode's ErrStringLength */
    *out_len = (size_t)got;
    return R_DONE;
}

/* d.at (hpack.go:198-212), into name and — when asked — value. */
static int table_at(lc_hpack_dec *d, uint64_t idx, int with_value)
{
    const char *nm, *vl;
    size_t      nl, vll;
    if (idx == 0u)
        return R_ERR;
    if (idx <= STATIC_COUNT) {
        nm = static_table[idx - 1u].name;
        vl = static_table[idx - 1u].value;
        nl = strlen(nm);
        vll = strlen(vl);
    } else {
        if (idx - STATIC_COUNT > d->entries)
            return R_ERR; /* InvalidIndexError */
        unsigned i = (unsigned)(idx - STATIC_COUNT - 1u);
        nm = (const char *)d->arena + d->off_name[i];
        vl = (const char *)d->arena + d->off_value[i];
        nl = d->len_name[i];
        vll = d->len_value[i];
    }
    if (grow(&d->name, &d->name_cap, nl) != 0)
        return R_ERR;
    memcpy(d->name, nm, nl);
    d->name[nl] = '\0';
    d->name_len = nl;
    if (with_value) {
        if (grow(&d->value, &d->value_cap, vll) != 0)
            return R_ERR;
        memcpy(d->value, vl, vll);
        d->value[vll] = '\0';
        d->value_len = vll;
    }
    return R_DONE;
}

/* parseHeaderFieldRepr (hpack.go:303-334) and the three it hands to (:336-396, :410-429): one
 * representation from `p`, `*used` bytes of it when R_DONE, `*field` set when it was a field rather
 * than a size update. `first` is firstField. */
static int parse_repr(lc_hpack_dec *d, const uint8_t *p, size_t len, int first, size_t *used,
                      int *field)
{
    uint8_t b = p[0];
    size_t  at = 0;
    *field = 0;

    if (b & 128u) { /* indexed — parseFieldIndexed */
        uint64_t idx = 0;
        int      r = read_varint(7u, p, len, &at, &idx);
        if (r != R_DONE)
            return r;
        if (table_at(d, idx, 1) != R_DONE)
            return R_ERR;
        d->sensitive = 0;
        *used = at;
        *field = 1;
        return R_DONE;
    }

    if ((b & 224u) == 32u) { /* dynamic table size update — parseDynamicTableSizeUpdate */
        if (!first && d->size > 0u)
            return R_ERR;
        uint64_t size = 0;
        int      r = read_varint(5u, p, len, &at, &size);
        if (r != R_DONE)
            return r;
        if (size > d->allowed)
            return R_ERR;
        d->max = (unsigned)size;
        while (d->entries > 0 && d->size > d->max)
            dyn_drop_oldest(d);
        *used = at;
        return R_DONE;
    }

    /* Literals — parseFieldLiteral: 01 with incremental indexing and six bits of index, 0000
     * without indexing and 0001 never indexed with four; anything else is "invalid encoding". */
    unsigned n;
    int      indexed = 0, never = 0;
    if ((b & 192u) == 64u) {
        n = 6u;
        indexed = 1;
    } else if ((b & 240u) == 0u) {
        n = 4u;
    } else if ((b & 240u) == 16u) {
        n = 4u;
        never = 1;
    } else {
        return R_ERR;
    }
    uint64_t name_idx = 0;
    int      r = read_varint(n, p, len, &at, &name_idx);
    if (r != R_DONE)
        return r;
    int            want = !d->emit_off || indexed;
    int            nh = 0, vh = 0;
    const uint8_t *ns = NULL, *vs = NULL;
    size_t         nn = 0, vn = 0;
    if (name_idx > 0u) {
        /* d.at is asked before the value is read, so a bad index is an error even when the value
         * is not all in yet. */
        if (name_idx > STATIC_COUNT && name_idx - STATIC_COUNT > d->entries)
            return R_ERR;
    } else if ((r = read_string(d, p, len, &at, &nh, &ns, &nn)) != R_DONE) {
        return r;
    }
    if ((r = read_string(d, p, len, &at, &vh, &vs, &vn)) != R_DONE)
        return r;

    /* All of it is in: now the strings, and only those that are wanted. */
    if (name_idx > 0u) {
        if (table_at(d, name_idx, 0) != R_DONE)
            return R_ERR;
    } else if (want) {
        if (decode_string(d, nh, ns, nn, &d->name, &d->name_cap, &d->name_len) != R_DONE)
            return R_ERR;
    } else {
        if (grow(&d->name, &d->name_cap, 0) != 0)
            return R_ERR;
        d->name[0] = '\0';
        d->name_len = 0;
    }
    if (want) {
        if (decode_string(d, vh, vs, vn, &d->value, &d->value_cap, &d->value_len) != R_DONE)
            return R_ERR;
    } else {
        if (grow(&d->value, &d->value_cap, 0) != 0)
            return R_ERR;
        d->value[0] = '\0';
        d->value_len = 0;
    }
    if (indexed)
        dyn_insert(d, d->name, d->name_len, d->value, d->value_len);
    d->sensitive = never;
    *used = at;
    *field = 1;
    return R_DONE;
}

/* callEmit (hpack.go:398-408): the length check applies whether or not emission is on. */
static int emit_check(const lc_hpack_dec *d)
{
    if (d->max_str != 0u && (d->name_len > d->max_str || d->value_len > d->max_str))
        return R_ERR;
    return R_DONE;
}

int lc_hpack_next(lc_hpack_dec *d)
{
    dec_start(d);
    while (d->off < d->len) {
        size_t used = 0;
        int    field = 0;
        int    r = parse_repr(d, d->in + d->off, d->len - d->off, d->off == 0u, &used, &field);
        if (r != R_DONE)
            return -1; /* malformed, or the block ends inside a representation */
        d->off += used;
        if (field)
            return emit_check(d) == R_DONE ? 1 : -1;
    }
    return 0;
}

int lc_hpack_write(lc_hpack_dec *d, const uint8_t *p, size_t n, lc_hpack_emit emit, void *ctx)
{
    dec_start(d);
    if (n == 0u)
        return 0; /* "Prevent state machine CPU attacks" — an empty write changes nothing */

    /* d.buf: the saved bytes and this piece, one run. */
    const uint8_t *buf = p;
    size_t         len = n;
    if (d->save_len > 0u) {
        if (d->save_len + n > d->save_cap) {
            size_t   cap = d->save_len + n;
            uint8_t *s = realloc(d->save, cap);
            if (s == NULL)
                return -1;
            d->save = s;
            d->save_cap = cap;
        }
        memcpy(d->save + d->save_len, p, n);
        buf = d->save;
        len = d->save_len + n;
        d->save_len = 0;
    }

    size_t at = 0;
    while (at < len) {
        size_t used = 0;
        int    field = 0;
        int    r = parse_repr(d, buf + at, len - at, !d->mid, &used, &field);
        if (r == R_MORE) {
            /* Kept for the next piece — unless it is already longer than any string the decoder
             * would take could make it: `2*(maxStrLen+varIntOverhead)`, varIntOverhead 8. */
            size_t rest = len - at;
            if (d->max_str != 0u && (uint64_t)rest > 2u * ((uint64_t)d->max_str + 8u))
                return -1;
            if (buf != d->save && rest > d->save_cap) {
                uint8_t *s = realloc(d->save, rest);
                if (s == NULL)
                    return -1;
                d->save = s;
                d->save_cap = rest;
            }
            memmove(d->save, buf + at, rest);
            d->save_len = rest;
            return 0;
        }
        d->mid = 1;
        if (r == R_ERR)
            return -1;
        at += used;
        if (field) {
            if (emit_check(d) != R_DONE)
                return -1;
            if (!d->emit_off && emit != NULL)
                emit(ctx, d);
        }
    }
    return 0;
}

int lc_hpack_close(lc_hpack_dec *d)
{
    if (d->save_len > 0u) {
        d->save_len = 0;
        return -1; /* "truncated headers" */
    }
    d->mid = 0;
    return 0;
}

void lc_hpack_dec_free(lc_hpack_dec *d)
{
    free(d->name);
    free(d->value);
    free(d->save);
    d->name = d->value = NULL;
    d->save = NULL;
    d->name_cap = d->value_cap = d->save_cap = 0;
    d->name_len = d->value_len = d->save_len = 0;
}
