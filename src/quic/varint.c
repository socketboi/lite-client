#include "quic/varint.h"

/* ⚠️ WRITTEN SHORTEST, READ AT ANY LENGTH — an asymmetry that reads like a bug and is the rule.
 *
 * This file named no reference line until now, so the sieve never opened it, and what it holds is
 * the encoding every QUIC frame and every HTTP/3 field length is built out of: one form wrong and
 * nothing on the connection parses. RFC 9000 §16 gives a value up to four spellings and does NOT
 * require the shortest, so a peer may legally send 0x40 0x05 where 0x05 would do — and refusing
 * that would be a rule of our own.
 *
 * The reference reads it exactly this way. The length comes from the top two bits and from nothing
 * else:
 *
 *     size_t ngtcp2_get_uvarintlen(const uint8_t *p) { return (size_t)(1U << (*p >> 6)); }
 *                                            (vendor/ngtcp2/lib/ngtcp2_conv.c:194-196)
 *
 * and ngtcp2_get_uvarint masks the value with 0x3FFF, 0x3FFFFFFF or 0x3FFFFFFFFFFFFFFF and hands it
 * back without ever asking whether a shorter form existed (ngtcp2_conv.c:65-98). Its writer picks
 * the shortest at the same three thresholds as lc_varint_len below — 64, 16384, 1073741824
 * (ngtcp2_put_uvarintlen, ngtcp2_conv.c:198-210) — and ORs in the same 0x40, 0x80, 0xc0
 * (ngtcp2_put_uvarint, ngtcp2_conv.c:145-165).
 *
 * The one difference is above 2^62-1: ngtcp2 asserts, this returns zero and every caller treats
 * zero as a refusal. Such a value cannot arrive from the wire — no form can express it — so the
 * only way to reach it is this program's own arithmetic, and on a router an assert is a dead tunnel
 * where a refusal is one frame not sent. */
size_t lc_varint_len(uint64_t v)
{
    if (v <= 63ull)
        return 1u;
    if (v <= 16383ull)
        return 2u;
    if (v <= 1073741823ull)
        return 4u;
    if (v <= LC_VARINT_MAX)
        return 8u;
    return 0;
}

size_t lc_varint_put(uint8_t *out, size_t cap, uint64_t v)
{
    size_t n = lc_varint_len(v);
    if (n == 0 || n > cap)
        return 0;

    switch (n) {
    case 1:
        out[0] = (uint8_t)v;
        break;
    case 2:
        out[0] = (uint8_t)(0x40u | v >> 8);
        out[1] = (uint8_t)v;
        break;
    case 4:
        out[0] = (uint8_t)(0x80u | v >> 24);
        out[1] = (uint8_t)(v >> 16);
        out[2] = (uint8_t)(v >> 8);
        out[3] = (uint8_t)v;
        break;
    default:
        for (unsigned i = 0; i < 8u; i++)
            out[i] = (uint8_t)(v >> (56u - 8u * i));
        out[0] |= 0xc0u;
        break;
    }
    return n;
}

int lc_varint_get(const uint8_t *in, size_t len, size_t *off, uint64_t *out)
{
    if (*off >= len)
        return -1;
    unsigned n = 1u << (in[*off] >> 6);
    if (*off + n > len)
        return -1;

    uint64_t v = in[*off] & 0x3fu;
    for (unsigned i = 1; i < n; i++)
        v = v << 8 | in[*off + i];
    *off += n;
    *out = v;
    return 0;
}
