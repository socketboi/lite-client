/* compress/gzip over compress/flate over bufio, as Go reads — see gozip.h.
 *
 * Each part is the Go it names, transcribed; what is added is only what lets a Read stop where Go's
 * would block and go on later from the same place. Every place Go reads its source is one of three:
 * bufio's fill under ReadByte, bufio's Read under io.ReadFull, and nothing else — so a wait is
 * always inside one of those, and each step below keeps enough to repeat the read it was in. */
#include "core/gozip.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#define BUF_SIZE 4096u  /* bufio.defaultBufSize */
#define WINDOW   32768u /* maxMatchOffset: flate's dictionary (inflate.go, dict_decoder.go) */

#define MAX_NUM_LIT  286
#define MAX_NUM_DIST 30
#define NUM_CODES    19
#define CHUNK_BITS   9u
#define NUM_CHUNKS   512u
#define COUNT_MASK   15u
#define VALUE_SHIFT  4u

/* A step's outcome: returned (what it produced, or its error, is in the state), or waiting for the
 * source. */
enum { OK = 0, WAIT = 1 };

/* ---- bufio.Reader ---------------------------------------------------------------------------- */

typedef struct {
    uint8_t buf[BUF_SIZE];
    size_t  r, w;
    int     err;
} bufr;

/* ---- flate's dictionary: dictDecoder (dict_decoder.go) --------------------------------------- */

typedef struct {
    uint8_t hist[WINDOW];
    size_t  wr, rd;
    int     full;
} dict;

/* ---- a Huffman decoder: huffmanDecoder (GOROOT/src/compress/flate/inflate.go:103-252) -------- */

typedef struct {
    int       min;
    uint32_t  chunks[NUM_CHUNKS];
    uint32_t *links;    /* `nlinks` tables of `link_n` each, one after another */
    unsigned  nlinks, link_n;
    uint32_t  link_mask;
} huff;

/* Where a step goes on: the function Go's f.step names, or the read a step was waiting in. */
enum {
    P_NEXT,        /* nextBlock */
    P_DB_ENTRY,    /* dataBlock */
    P_DB_READ,
    P_CD_ENTRY,    /* copyData */
    P_CD_READ,
    P_RH_HDR,      /* readHuffman */
    P_RH_CLEN,
    P_RH_SYM,
    P_RH_REP,
    P_HUFF,        /* huffmanBlock, by stepState */
    P_LIT,         /* readLiteral */
    P_LEN_EXTRA,
    P_DIST,
    P_DIST_EXTRA,
    P_COPY_HIST,   /* copyHistory */
};

enum { STATE_INIT = 0, STATE_DICT = 1 };

typedef struct {
    size_t have, len;
} rfull;

/* The decompressor (GOROOT/src/compress/flate/inflate.go:254-290), and where a waiting step goes on. */
typedef struct {
    uint32_t b;
    unsigned nb;
    huff     h1, h2;
    int      bits[MAX_NUM_LIT + MAX_NUM_DIST];
    int      codebits[NUM_CODES];
    dict     d;
    int      phase, step_state;
    int      final;
    int      err;
    const uint8_t *to_read;
    size_t         to_read_n;
    const huff    *hl, *hd;
    int            copy_len, copy_dist;
    uint8_t        buf[4];
    rfull          rf;
    /* readHuffman's */
    int nlit, ndist, nclen, i, n;
    int rep, rep_nb, rep_b;
    /* readLiteral's */
    int      length;
    unsigned extra_n;
    int      dist;
} inflater;

/* gzip.Reader.Read's place within one call, and readHeader's. */
enum { G_INIT, G_IDLE, G_DECOMP, G_TRAILER, G_HDR };
enum { H_FIXED, H_XLEN, H_XDATA, H_NAME, H_COMMENT, H_HCRC };

struct lc_gozip {
    lc_gz_source src;
    void        *ctx;
    int          zerr;  /* x/net's gzipReader: the error of making the Reader, kept */
    int          gstate;
    int          err;   /* gzip.Reader.err */
    uLong        digest;
    uint32_t     size;
    uint8_t      hbuf[512]; /* gzip.Reader.buf */
    int          hstate, hflags;
    rfull        hrf;
    size_t       str_i;
    const uint8_t *call_out;
    size_t         call_n;
    bufr         br;
    inflater     f;
};

/* ---- the source, through bufio --------------------------------------------------------------- */

/* Copies what a Read returned to where it goes; with no destination the bytes only go into the
 * digest (the FEXTRA field, which gzip.Reader reads into a slice of its own and hashes). */
static void put(uint8_t *dst, uLong *crc, const uint8_t *p, size_t n)
{
    if (dst != NULL && n > 0u)
        memcpy(dst, p, n);
    if (crc != NULL && n > 0u)
        *crc = crc32(*crc, p, (uInt)n);
}

/* fill (GOROOT/src/bufio/bufio.go:98-124): the buffered bytes moved to the front, then one Read
 * into the rest. A source never returns nothing without an error — it waits instead — so the loop
 * over empty reads never goes round. */
static int b_fill(lc_gozip *z)
{
    bufr *b = &z->br;
    if (b->r > 0u) {
        memmove(b->buf, b->buf + b->r, b->w - b->r);
        b->w -= b->r;
        b->r = 0;
    }
    const uint8_t *p;
    size_t         n;
    int            err;
    if (z->src(z->ctx, BUF_SIZE - b->w, &p, &n, &err))
        return WAIT;
    if (n > 0u)
        memcpy(b->buf + b->w, p, n);
    b->w += n;
    if (err != LC_GZ_NONE)
        b->err = err;
    return OK;
}

/* ReadByte (GOROOT/src/bufio/bufio.go:262-276): 0 with the byte, WAIT, or -1 with the error — which
 * is handed out once and forgotten (readErr). */
static int b_byte(lc_gozip *z, uint8_t *c, int *err)
{
    bufr *b = &z->br;
    while (b->r == b->w) {
        if (b->err != LC_GZ_NONE) {
            *err = b->err;
            b->err = LC_GZ_NONE;
            return -1;
        }
        if (b_fill(z) == WAIT)
            return WAIT;
    }
    *c = b->buf[b->r++];
    return 0;
}

/* Read (GOROOT/src/bufio/bufio.go:197-255), of len > 0: what is buffered; else, with an empty
 * buffer, straight from the source when len is a buffer or more, or one Read into the buffer. */
static int b_read(lc_gozip *z, uint8_t *dst, uLong *crc, size_t len, size_t *n, int *err)
{
    bufr *b = &z->br;
    *n = 0;
    *err = LC_GZ_NONE;
    if (b->r == b->w) {
        if (b->err != LC_GZ_NONE) {
            *err = b->err;
            b->err = LC_GZ_NONE;
            return OK;
        }
        const uint8_t *p;
        size_t         got;
        int            e;
        if (len >= BUF_SIZE) {
            if (z->src(z->ctx, len, &p, &got, &e))
                return WAIT;
            put(dst, crc, p, got);
            *n = got;
            *err = e; /* b.err set and handed straight back: readErr */
            return OK;
        }
        b->r = b->w = 0;
        if (z->src(z->ctx, BUF_SIZE, &p, &got, &e))
            return WAIT;
        if (got > 0u)
            memcpy(b->buf, p, got);
        b->err = e;
        if (got == 0u) {
            *err = b->err;
            b->err = LC_GZ_NONE;
            return OK;
        }
        b->w = got;
    }
    size_t k = len < b->w - b->r ? len : b->w - b->r;
    put(dst, crc, b->buf + b->r, k);
    b->r += k;
    *n = k;
    return OK;
}

/* io.ReadFull, which is ReadAtLeast of all of it (GOROOT/src/io/io.go:335-361): reads until it has
 * it or a Read fails; what it got is kept across a wait in `st`. */
static int read_full(lc_gozip *z, uint8_t *dst, uLong *crc, rfull *st, int *err)
{
    int e = LC_GZ_NONE;
    while (st->have < st->len && e == LC_GZ_NONE) {
        size_t nn;
        if (b_read(z, dst != NULL ? dst + st->have : NULL, crc, st->len - st->have, &nn, &e) == WAIT)
            return WAIT;
        st->have += nn;
    }
    if (st->have >= st->len)
        e = LC_GZ_NONE;
    else if (st->have > 0u && e == LC_GZ_EOF)
        e = LC_GZ_ERR; /* io.ErrUnexpectedEOF */
    *err = e;
    return OK;
}

/* noEOF (GOROOT/src/compress/flate/inflate.go:696-702, GOROOT/src/compress/gzip/gunzip.go:31-37). */
static int no_eof(int err)
{
    return err == LC_GZ_EOF ? LC_GZ_ERR : err;
}

/* ---- the dictionary -------------------------------------------------------------------------- */

static size_t hist_size(const dict *d)
{
    return d->full ? WINDOW : d->wr;
}

static size_t avail_write(const dict *d)
{
    return WINDOW - d->wr;
}

static size_t write_copy(dict *d, int dist, int length)
{
    size_t    dst_base = d->wr, dst = dst_base;
    ptrdiff_t src = (ptrdiff_t)dst - dist;
    size_t    end = dst + (size_t)length;
    if (end > WINDOW)
        end = WINDOW;
    if (src < 0) {
        src += (ptrdiff_t)WINDOW;
        size_t k = end - dst < WINDOW - (size_t)src ? end - dst : WINDOW - (size_t)src;
        memmove(d->hist + dst, d->hist + src, k);
        dst += k;
        src = 0;
    }
    while (dst < end) {
        size_t k = end - dst < dst - (size_t)src ? end - dst : dst - (size_t)src;
        memcpy(d->hist + dst, d->hist + src, k);
        dst += k;
    }
    d->wr = dst;
    return dst - dst_base;
}

static size_t try_write_copy(dict *d, int dist, int length)
{
    size_t dst = d->wr, end = dst + (size_t)length;
    if (dst < (size_t)dist || end > WINDOW)
        return 0;
    size_t dst_base = dst, src = dst - (size_t)dist;
    while (dst < end) {
        size_t k = end - dst < dst - src ? end - dst : dst - src;
        memcpy(d->hist + dst, d->hist + src, k);
        dst += k;
    }
    d->wr = dst;
    return dst - dst_base;
}

static void read_flush(inflater *f)
{
    dict *d = &f->d;
    f->to_read = d->hist + d->rd;
    f->to_read_n = d->wr - d->rd;
    d->rd = d->wr;
    if (d->wr == WINDOW) {
        d->wr = d->rd = 0;
        d->full = 1;
    }
}

/* ---- Huffman tables -------------------------------------------------------------------------- */

static unsigned reverse16(unsigned v)
{
    v = (v & 0x5555u) << 1 | (v >> 1 & 0x5555u);
    v = (v & 0x3333u) << 2 | (v >> 2 & 0x3333u);
    v = (v & 0x0f0fu) << 4 | (v >> 4 & 0x0f0fu);
    v = (v & 0x00ffu) << 8 | (v >> 8 & 0x00ffu);
    return v & 0xffffu;
}

static void huff_reset(huff *h)
{
    free(h->links);
    memset(h, 0, sizeof *h);
}

/* huffmanDecoder.init: 1 for a complete code, or an empty one, or the single code of length one zlib
 * accepts; 0 otherwise; -1 without memory. */
static int huff_init(huff *h, const int *lengths, int n)
{
    if (h->min != 0)
        huff_reset(h);
    int count[16] = { 0 }, min = 0, max = 0;
    for (int i = 0; i < n; i++) {
        int l = lengths[i];
        if (l == 0)
            continue;
        if (min == 0 || l < min)
            min = l;
        if (l > max)
            max = l;
        count[l]++;
    }
    if (max == 0)
        return 1;
    int code = 0, nextcode[16] = { 0 };
    for (int i = min; i <= max; i++) {
        code <<= 1;
        nextcode[i] = code;
        code += count[i];
    }
    if (code != 1 << max && !(code == 1 && max == 1))
        return 0;
    h->min = min;
    if (max > (int)CHUNK_BITS) {
        unsigned num_links = 1u << (unsigned)(max - (int)CHUNK_BITS);
        h->link_mask = num_links - 1u;
        unsigned link = (unsigned)nextcode[CHUNK_BITS + 1u] >> 1;
        h->nlinks = NUM_CHUNKS - link;
        h->link_n = num_links;
        h->links = calloc((size_t)h->nlinks * num_links, sizeof *h->links);
        if (h->links == NULL)
            return -1;
        for (unsigned j = link; j < NUM_CHUNKS; j++) {
            unsigned reverse = reverse16(j) >> (16u - CHUNK_BITS);
            unsigned off = j - link;
            h->chunks[reverse] = off << VALUE_SHIFT | (CHUNK_BITS + 1u);
        }
    }
    for (int i = 0; i < n; i++) {
        int l = lengths[i];
        if (l == 0)
            continue;
        int      c = nextcode[l]++;
        uint32_t chunk = (uint32_t)i << VALUE_SHIFT | (uint32_t)l;
        unsigned reverse = reverse16((unsigned)c) >> (16u - (unsigned)l);
        if (l <= (int)CHUNK_BITS) {
            for (unsigned off = reverse; off < NUM_CHUNKS; off += 1u << (unsigned)l)
                h->chunks[off] = chunk;
        } else {
            unsigned j = reverse & (NUM_CHUNKS - 1u);
            unsigned value = h->chunks[j] >> VALUE_SHIFT;
            if (value >= h->nlinks)
                return 0; /* not reached for a complete code: Go would index out of range */
            uint32_t *linktab = h->links + (size_t)value * h->link_n;
            reverse >>= CHUNK_BITS;
            for (unsigned off = reverse; off < h->link_n; off += 1u << (unsigned)(l - (int)CHUNK_BITS))
                linktab[off] = chunk;
        }
    }
    return 1;
}

static huff fixed_huff;
static pthread_once_t fixed_once = PTHREAD_ONCE_INIT;

static void fixed_init(void)
{
    int bits[288];
    for (int i = 0; i < 144; i++)
        bits[i] = 8;
    for (int i = 144; i < 256; i++)
        bits[i] = 9;
    for (int i = 256; i < 280; i++)
        bits[i] = 7;
    for (int i = 280; i < 288; i++)
        bits[i] = 8;
    (void)huff_init(&fixed_huff, bits, 288); /* no code is longer than nine bits: no links */
}

/* ---- the decompressor's reads ---------------------------------------------------------------- */

/* `for f.nb < k { f.moreBits() }`: OK, WAIT, or -1 with f->err set. */
static int need(lc_gozip *z, unsigned k)
{
    inflater *f = &z->f;
    while (f->nb < k) {
        uint8_t c;
        int     err;
        int     r = b_byte(z, &c, &err);
        if (r == WAIT)
            return WAIT;
        if (r < 0) {
            f->err = no_eof(err);
            return -1;
        }
        f->b |= (uint32_t)c << f->nb;
        f->nb += 8u;
    }
    return OK;
}

/* huffSym (GOROOT/src/compress/flate/inflate.go:715-760). Waiting keeps the bits read so far, and
 * going on starts the lookup again from them — which asks for exactly the bytes the uninterrupted
 * loop would. */
static int huff_sym(lc_gozip *z, const huff *h, int *sym)
{
    inflater *f = &z->f;
    unsigned  n = (unsigned)h->min, nb = f->nb;
    uint32_t  b = f->b;
    for (;;) {
        while (nb < n) {
            uint8_t c;
            int     err;
            int     r = b_byte(z, &c, &err);
            if (r == WAIT) {
                f->b = b;
                f->nb = nb;
                return WAIT;
            }
            if (r < 0) {
                f->b = b;
                f->nb = nb;
                f->err = no_eof(err);
                return -1;
            }
            b |= (uint32_t)c << (nb & 31u);
            nb += 8u;
        }
        uint32_t chunk = h->chunks[b & (NUM_CHUNKS - 1u)];
        n = chunk & COUNT_MASK;
        if (n > CHUNK_BITS) {
            uint32_t idx = chunk >> VALUE_SHIFT;
            chunk = idx < h->nlinks
                        ? h->links[(size_t)idx * h->link_n + ((b >> CHUNK_BITS) & h->link_mask)]
                        : 0u;
            n = chunk & COUNT_MASK;
        }
        if (n <= nb) {
            if (n == 0u) {
                f->b = b;
                f->nb = nb;
                f->err = LC_GZ_ERR; /* CorruptInputError */
                return -1;
            }
            f->b = b >> (n & 31u);
            f->nb = nb - n;
            *sym = (int)(chunk >> VALUE_SHIFT);
            return OK;
        }
    }
}

static void finish_block(inflater *f)
{
    if (f->final) {
        if (f->d.wr - f->d.rd > 0u)
            read_flush(f);
        f->err = LC_GZ_EOF;
    }
    f->phase = P_NEXT;
}

static const int code_order[NUM_CODES] = { 16, 17, 18, 0, 8,  7, 9,  6, 10, 5,
                                           11, 4,  12, 3, 13, 2, 14, 1, 15 };

static unsigned reverse8(unsigned v)
{
    return reverse16(v) >> 8;
}

/* One step: f.step() with whatever it calls. OK when it returned — having flushed output, ended a
 * block, or failed, all of which is in `f` — or WAIT; -1 without memory. */
static int step(lc_gozip *z)
{
    inflater *f = &z->f;
    int       r, e;
    for (;;) {
        switch (f->phase) {
        case P_NEXT: /* nextBlock (GOROOT/src/compress/flate/inflate.go:292-324) */
            if ((r = need(z, 3)) != OK)
                return r == WAIT ? WAIT : OK;
            f->final = (f->b & 1u) == 1u;
            f->b >>= 1;
            unsigned typ = f->b & 3u;
            f->b >>= 2;
            f->nb -= 3u;
            if (typ == 0u) {
                f->phase = P_DB_ENTRY;
            } else if (typ == 1u) {
                f->hl = &fixed_huff;
                f->hd = NULL;
                f->phase = P_HUFF;
            } else if (typ == 2u) {
                f->phase = P_RH_HDR;
            } else {
                f->err = LC_GZ_ERR;
                return OK;
            }
            break;

        case P_DB_ENTRY: /* dataBlock (GOROOT/src/compress/flate/inflate.go:617-651) */
            f->nb = 0;
            f->b = 0;
            f->rf = (rfull){ 0, 4 };
            f->phase = P_DB_READ;
            /* fall through */
        case P_DB_READ: {
            if (read_full(z, f->buf, NULL, &f->rf, &e) == WAIT)
                return WAIT;
            if (e != LC_GZ_NONE) {
                f->err = no_eof(e);
                return OK;
            }
            unsigned n = (unsigned)f->buf[0] | (unsigned)f->buf[1] << 8;
            unsigned nn = (unsigned)f->buf[2] | (unsigned)f->buf[3] << 8;
            if ((uint16_t)nn != (uint16_t)~n) {
                f->err = LC_GZ_ERR;
                return OK;
            }
            if (n == 0u) {
                read_flush(f);
                finish_block(f);
                return OK;
            }
            f->copy_len = (int)n;
            f->phase = P_CD_ENTRY;
            break;
        }

        case P_CD_ENTRY: { /* copyData (GOROOT/src/compress/flate/inflate.go:653-676) */
            size_t k = avail_write(&f->d);
            if (k > (size_t)f->copy_len)
                k = (size_t)f->copy_len;
            f->rf = (rfull){ 0, k };
            f->phase = P_CD_READ;
        }
            /* fall through */
        case P_CD_READ: {
            if (read_full(z, f->d.hist + f->d.wr, NULL, &f->rf, &e) == WAIT)
                return WAIT;
            f->copy_len -= (int)f->rf.have;
            f->d.wr += f->rf.have;
            if (e != LC_GZ_NONE) {
                f->err = no_eof(e);
                return OK;
            }
            if (avail_write(&f->d) == 0u || f->copy_len > 0) {
                read_flush(f);
                f->phase = P_CD_ENTRY;
                return OK;
            }
            finish_block(f);
            return OK;
        }

        case P_RH_HDR: /* readHuffman (GOROOT/src/compress/flate/inflate.go:370-465) */
            if ((r = need(z, 14)) != OK)
                return r == WAIT ? WAIT : OK;
            f->nlit = (int)(f->b & 0x1fu) + 257;
            if (f->nlit > MAX_NUM_LIT) {
                f->err = LC_GZ_ERR;
                return OK;
            }
            f->b >>= 5;
            f->ndist = (int)(f->b & 0x1fu) + 1;
            if (f->ndist > MAX_NUM_DIST) {
                f->err = LC_GZ_ERR;
                return OK;
            }
            f->b >>= 5;
            f->nclen = (int)(f->b & 0xfu) + 4;
            f->b >>= 4;
            f->nb -= 14u;
            f->i = 0;
            f->phase = P_RH_CLEN;
            /* fall through */
        case P_RH_CLEN:
            for (; f->i < f->nclen; f->i++) {
                if ((r = need(z, 3)) != OK)
                    return r == WAIT ? WAIT : OK;
                f->codebits[code_order[f->i]] = (int)(f->b & 7u);
                f->b >>= 3;
                f->nb -= 3u;
            }
            for (int i = f->nclen; i < NUM_CODES; i++)
                f->codebits[code_order[i]] = 0;
            if ((r = huff_init(&f->h1, f->codebits, NUM_CODES)) != 1) {
                if (r < 0)
                    return -1;
                f->err = LC_GZ_ERR;
                return OK;
            }
            f->i = 0;
            f->n = f->nlit + f->ndist;
            f->phase = P_RH_SYM;
            /* fall through */
        case P_RH_SYM:
            while (f->i < f->n) {
                int x;
                if ((r = huff_sym(z, &f->h1, &x)) != OK)
                    return r == WAIT ? WAIT : OK;
                if (x < 16) {
                    f->bits[f->i++] = x;
                    continue;
                }
                switch (x) {
                case 16:
                    f->rep = 3;
                    f->rep_nb = 2;
                    if (f->i == 0) {
                        f->err = LC_GZ_ERR;
                        return OK;
                    }
                    f->rep_b = f->bits[f->i - 1];
                    break;
                case 17:
                    f->rep = 3;
                    f->rep_nb = 3;
                    f->rep_b = 0;
                    break;
                case 18:
                    f->rep = 11;
                    f->rep_nb = 7;
                    f->rep_b = 0;
                    break;
                default:
                    f->err = LC_GZ_ERR; /* InternalError: a code-length code has nineteen symbols */
                    return OK;
                }
                f->phase = P_RH_REP;
                /* fall through */
        case P_RH_REP:
                if ((r = need(z, (unsigned)f->rep_nb)) != OK)
                    return r == WAIT ? WAIT : OK;
                f->rep += (int)(f->b & ((1u << (unsigned)f->rep_nb) - 1u));
                f->b >>= (unsigned)f->rep_nb;
                f->nb -= (unsigned)f->rep_nb;
                if (f->i + f->rep > f->n) {
                    f->err = LC_GZ_ERR;
                    return OK;
                }
                for (int j = 0; j < f->rep; j++)
                    f->bits[f->i++] = f->rep_b;
                f->phase = P_RH_SYM;
            }
            if ((r = huff_init(&f->h1, f->bits, f->nlit)) != 1 ||
                (r = huff_init(&f->h2, f->bits + f->nlit, f->ndist)) != 1) {
                if (r < 0)
                    return -1;
                f->err = LC_GZ_ERR;
                return OK;
            }
            if (f->h1.min < f->bits[256])
                f->h1.min = f->bits[256];
            f->hl = &f->h1;
            f->hd = &f->h2;
            f->phase = P_HUFF;
            break;

        case P_HUFF:
            /* huffmanBlock (GOROOT/src/compress/flate/inflate.go:467-615), entered by its
             * stepState. */
            f->phase = f->step_state == STATE_INIT ? P_LIT : P_COPY_HIST;
            break;

        case P_LIT: {
            int v;
            if ((r = huff_sym(z, f->hl, &v)) != OK)
                return r == WAIT ? WAIT : OK;
            unsigned n = 0;
            if (v < 256) {
                f->d.hist[f->d.wr++] = (uint8_t)v;
                if (avail_write(&f->d) == 0u) {
                    read_flush(f);
                    f->step_state = STATE_INIT;
                    f->phase = P_HUFF;
                    return OK;
                }
                break;
            }
            if (v == 256) {
                finish_block(f);
                return OK;
            }
            if (v < 265) {
                f->length = v - (257 - 3);
            } else if (v < 269) {
                f->length = v * 2 - (265 * 2 - 11);
                n = 1;
            } else if (v < 273) {
                f->length = v * 4 - (269 * 4 - 19);
                n = 2;
            } else if (v < 277) {
                f->length = v * 8 - (273 * 8 - 35);
                n = 3;
            } else if (v < 281) {
                f->length = v * 16 - (277 * 16 - 67);
                n = 4;
            } else if (v < 285) {
                f->length = v * 32 - (281 * 32 - 131);
                n = 5;
            } else if (v < MAX_NUM_LIT) {
                f->length = 258;
            } else {
                f->err = LC_GZ_ERR;
                return OK;
            }
            f->extra_n = n;
            f->phase = P_LEN_EXTRA;
        }
            /* fall through */
        case P_LEN_EXTRA:
            if (f->extra_n > 0u) {
                if ((r = need(z, f->extra_n)) != OK)
                    return r == WAIT ? WAIT : OK;
                f->length += (int)(f->b & ((1u << f->extra_n) - 1u));
                f->b >>= f->extra_n;
                f->nb -= f->extra_n;
            }
            f->phase = P_DIST;
            /* fall through */
        case P_DIST:
            if (f->hd == NULL) {
                if ((r = need(z, 5)) != OK)
                    return r == WAIT ? WAIT : OK;
                f->dist = (int)reverse8((f->b & 0x1fu) << 3 & 0xffu);
                f->b >>= 5;
                f->nb -= 5u;
            } else if ((r = huff_sym(z, f->hd, &f->dist)) != OK) {
                return r == WAIT ? WAIT : OK;
            }
            if (f->dist < 4) {
                f->dist++;
                f->extra_n = 0;
            } else if (f->dist < MAX_NUM_DIST) {
                f->extra_n = (unsigned)(f->dist - 2) >> 1;
            } else {
                f->err = LC_GZ_ERR;
                return OK;
            }
            f->phase = P_DIST_EXTRA;
            /* fall through */
        case P_DIST_EXTRA:
            if (f->extra_n > 0u) {
                unsigned nb = f->extra_n;
                if ((r = need(z, nb)) != OK)
                    return r == WAIT ? WAIT : OK;
                int extra = (f->dist & 1) << nb;
                extra |= (int)(f->b & ((1u << nb) - 1u));
                f->b >>= nb;
                f->nb -= nb;
                f->dist = (1 << (nb + 1u)) + 1 + extra;
            }
            if ((size_t)f->dist > hist_size(&f->d)) {
                f->err = LC_GZ_ERR;
                return OK;
            }
            f->copy_len = f->length;
            f->copy_dist = f->dist;
            f->phase = P_COPY_HIST;
            /* fall through */
        case P_COPY_HIST: {
            size_t cnt = try_write_copy(&f->d, f->copy_dist, f->copy_len);
            if (cnt == 0u)
                cnt = write_copy(&f->d, f->copy_dist, f->copy_len);
            f->copy_len -= (int)cnt;
            if (avail_write(&f->d) == 0u || f->copy_len > 0) {
                read_flush(f);
                f->step_state = STATE_DICT;
                f->phase = P_HUFF;
                return OK;
            }
            f->phase = P_LIT;
            break;
        }
        default:
            f->err = LC_GZ_ERR;
            return OK;
        }
    }
}

/* decompressor.Read (GOROOT/src/compress/flate/inflate.go:326-345). */
static int f_read(lc_gozip *z, size_t cap, const uint8_t **out, size_t *n, int *err)
{
    inflater *f = &z->f;
    for (;;) {
        if (f->to_read_n > 0u) {
            size_t k = cap < f->to_read_n ? cap : f->to_read_n;
            *out = f->to_read;
            f->to_read += k;
            f->to_read_n -= k;
            *n = k;
            *err = f->to_read_n == 0u ? f->err : LC_GZ_NONE;
            return OK;
        }
        if (f->err != LC_GZ_NONE) {
            *n = 0;
            *err = f->err;
            return OK;
        }
        int r = step(z);
        if (r != OK)
            return r;
        if (f->err != LC_GZ_NONE && f->to_read_n == 0u)
            read_flush(f);
    }
}

/* decompressor.Reset (GOROOT/src/compress/flate/inflate.go:790-800): everything but the buffers it
 * keeps. */
static void f_reset(inflater *f)
{
    huff_reset(&f->h1);
    huff_reset(&f->h2);
    f->b = 0;
    f->nb = 0;
    f->d.wr = f->d.rd = 0;
    f->d.full = 0;
    f->phase = P_NEXT;
    f->step_state = STATE_INIT;
    f->final = 0;
    f->err = LC_GZ_NONE;
    f->to_read = NULL;
    f->to_read_n = 0;
    f->hl = f->hd = NULL;
    f->copy_len = f->copy_dist = 0;
}

/* ---- gzip.Reader ----------------------------------------------------------------------------- */

/* readString (GOROOT/src/compress/gzip/gunzip.go:131-161): up to a NUL, in 512 bytes. */
static int read_string(lc_gozip *z, int *err)
{
    for (;; z->str_i++) {
        if (z->str_i >= sizeof z->hbuf) {
            *err = LC_GZ_ERR; /* ErrHeader */
            return OK;
        }
        uint8_t c;
        int     e;
        int     r = b_byte(z, &c, &e);
        if (r == WAIT)
            return WAIT;
        if (r < 0) {
            *err = e;
            return OK;
        }
        z->hbuf[z->str_i] = c;
        if (c == 0u) {
            z->digest = crc32(z->digest, z->hbuf, (uInt)(z->str_i + 1u));
            *err = LC_GZ_NONE;
            return OK;
        }
    }
}

static void header_start(lc_gozip *z)
{
    z->hstate = H_FIXED;
    z->hrf = (rfull){ 0, 10 };
    z->str_i = 0;
}

/* readHeader (GOROOT/src/compress/gzip/gunzip.go:163-238). */
static int read_header(lc_gozip *z, int *err)
{
    int e;
    switch (z->hstate) {
    case H_FIXED:
        if (read_full(z, z->hbuf, NULL, &z->hrf, &e) == WAIT)
            return WAIT;
        if (e != LC_GZ_NONE) {
            *err = e;
            return OK;
        }
        if (z->hbuf[0] != 0x1fu || z->hbuf[1] != 0x8bu || z->hbuf[2] != 8u) {
            *err = LC_GZ_ERR;
            return OK;
        }
        z->hflags = z->hbuf[3];
        z->digest = crc32(0L, z->hbuf, 10);
        if (z->hflags & 0x04) {
            z->hstate = H_XLEN;
            z->hrf = (rfull){ 0, 2 };
        } else {
            z->hstate = H_NAME;
        }
        return read_header(z, err);

    case H_XLEN:
        if (read_full(z, z->hbuf, NULL, &z->hrf, &e) == WAIT)
            return WAIT;
        if (e != LC_GZ_NONE) {
            *err = no_eof(e);
            return OK;
        }
        z->digest = crc32(z->digest, z->hbuf, 2);
        z->hrf = (rfull){ 0, (size_t)z->hbuf[0] | (size_t)z->hbuf[1] << 8 };
        z->hstate = H_XDATA;
        /* fall through */
    case H_XDATA:
        if (read_full(z, NULL, &z->digest, &z->hrf, &e) == WAIT)
            return WAIT;
        if (e != LC_GZ_NONE) {
            *err = no_eof(e);
            return OK;
        }
        z->hstate = H_NAME;
        /* fall through */
    case H_NAME:
        if (z->hflags & 0x08) {
            if (read_string(z, &e) == WAIT)
                return WAIT;
            if (e != LC_GZ_NONE) {
                *err = no_eof(e);
                return OK;
            }
        }
        z->str_i = 0;
        z->hstate = H_COMMENT;
        /* fall through */
    case H_COMMENT:
        if (z->hflags & 0x10) {
            if (read_string(z, &e) == WAIT)
                return WAIT;
            if (e != LC_GZ_NONE) {
                *err = no_eof(e);
                return OK;
            }
        }
        z->hstate = H_HCRC;
        z->hrf = (rfull){ 0, 2 };
        /* fall through */
    case H_HCRC:
        if (z->hflags & 0x02) {
            if (read_full(z, z->hbuf, NULL, &z->hrf, &e) == WAIT)
                return WAIT;
            if (e != LC_GZ_NONE) {
                *err = no_eof(e);
                return OK;
            }
            unsigned d = (unsigned)z->hbuf[0] | (unsigned)z->hbuf[1] << 8;
            if (d != (z->digest & 0xffffu)) {
                *err = LC_GZ_ERR;
                return OK;
            }
        }
        break;
    }
    z->digest = 0;
    f_reset(&z->f);
    *err = LC_GZ_NONE;
    return OK;
}

lc_gozip *lc_gozip_new(lc_gz_source src, void *ctx)
{
    lc_gozip *z = calloc(1, sizeof *z);
    if (z == NULL)
        return NULL;
    /* compress/flate.fixedHuffmanDecoderInit uses fixedOnce.Do too
     * (Go 1.27 src/compress/flate/inflate.go:766-783). Each fetch owns a
     * different mutex; only process-wide once can publish this shared table. */
    (void)pthread_once(&fixed_once, fixed_init);
    z->src = src;
    z->ctx = ctx;
    z->gstate = G_INIT;
    header_start(z);
    f_reset(&z->f);
    return z;
}

void lc_gozip_free(lc_gozip *z)
{
    if (z == NULL)
        return;
    huff_reset(&z->f.h1);
    huff_reset(&z->f.h2);
    free(z);
}

/* gzipReader.Read (vendor/x-net/http2/transport.go:2878-2886) — the Reader made on the first one,
 * its error kept — and gzip.Reader.Read (GOROOT/src/compress/gzip/gunzip.go:240-283). */
int lc_gozip_read(lc_gozip *z, size_t cap, const uint8_t **out, size_t *n, int *err)
{
    int e, r;
    *out = z->f.d.hist;
    *n = 0;
    switch (z->gstate) {
    case G_INIT:
        if (z->zerr != LC_GZ_NONE) {
            *err = z->zerr;
            return OK;
        }
        if (read_header(z, &e) == WAIT)
            return WAIT;
        if (e != LC_GZ_NONE) {
            z->zerr = e;
            *err = e;
            return OK;
        }
        z->gstate = G_IDLE;
        /* fall through */
    case G_IDLE:
        if (z->err != LC_GZ_NONE) {
            *err = z->err;
            return OK;
        }
        z->call_out = NULL;
        z->call_n = 0;
        z->gstate = G_DECOMP;
        /* fall through */
    case G_DECOMP:
    decomp:
        if ((r = f_read(z, cap, &z->call_out, &z->call_n, &e)) != OK)
            return r;
        if (z->call_n > 0u) /* zlib's crc32 of a NULL buffer is 0, not the digest */
            z->digest = crc32(z->digest, z->call_out, (uInt)z->call_n);
        z->size += (uint32_t)z->call_n;
        z->err = e;
        if (e != LC_GZ_EOF)
            break;
        z->hrf = (rfull){ 0, 8 };
        z->gstate = G_TRAILER;
        /* fall through */
    case G_TRAILER: {
        uint8_t *t = z->hbuf + 16; /* not the header's bytes, which the next member reads into */
        if (read_full(z, t, NULL, &z->hrf, &e) == WAIT)
            return WAIT;
        if (e != LC_GZ_NONE) {
            z->err = no_eof(e);
            break;
        }
        uint32_t digest = (uint32_t)t[0] | (uint32_t)t[1] << 8 | (uint32_t)t[2] << 16 |
                          (uint32_t)t[3] << 24;
        uint32_t size = (uint32_t)t[4] | (uint32_t)t[5] << 8 | (uint32_t)t[6] << 16 |
                        (uint32_t)t[7] << 24;
        if (digest != (uint32_t)z->digest || size != z->size) {
            z->err = LC_GZ_ERR; /* ErrChecksum */
            break;
        }
        z->digest = 0;
        z->size = 0;
        z->err = LC_GZ_NONE;
        header_start(z);
        z->gstate = G_HDR;
    }
        /* fall through */
    case G_HDR:
        if (read_header(z, &e) == WAIT)
            return WAIT;
        if (e != LC_GZ_NONE) {
            z->err = e;
            break;
        }
        if (z->call_n == 0u) {
            z->gstate = G_DECOMP;
            goto decomp;
        }
        break;
    }
    z->gstate = G_IDLE;
    *out = z->call_out != NULL ? z->call_out : z->f.d.hist;
    *n = z->call_n;
    *err = z->err;
    return OK;
}
