/* The node's response header, which says where the proxied stream begins.
 *
 * WHY IT MATTERS. lc_vless_response reports how many bytes the header took, and the caller advances
 * past exactly that many before handing the rest to whoever opened the connection. A count that is
 * one too small prepends a stray byte to somebody's TLS record or HTTP response; one too large eats
 * the first byte of it. Neither errors — the stream is simply not what was sent, and the fault
 * surfaces wherever that byte is next parsed, which is somewhere else entirely.
 *
 * It was reached on every proxied connection of the REALITY plane and asked nothing by any test
 * until 2026-09-02: test/vless covers what this client SENDS — the request, the flow, the UDP
 * request — and stopped at the reply.
 *
 * ⚠️ WHAT IS PINNED HERE IS THE BEHAVIOUR, INCLUDING THE PART THAT IS WRONG. -1 is returned both for
 * "not enough bytes yet" and for "this is not a VLESS server", and the one caller treats both as a
 * dead connection. vless.h carries the whole account and what would justify separating them. These
 * cases are written so that the day somebody does separate them, they fail and have to be revisited
 * deliberately rather than passing by accident. */

#include "vless/vless.h"

#include <stdio.h>
#include <string.h>

static int fails;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        fails++;
}

int main(void)
{
    printf("where the node's answer ends and the stream begins\n");

    size_t  hl = 0;
    uint8_t buf[300];

    /* What Xray actually sends: version zero, no additional information. Two bytes, and everything
     * after them belongs to whoever opened the connection. */
    memset(buf, 0xaa, sizeof buf);
    buf[0] = 0x00;
    buf[1] = 0x00;
    ok(lc_vless_response(buf, sizeof buf, &hl) == 0 && hl == 2u,
       "the ordinary reply is two bytes, and the stream starts right after them");

    /* An additional-information field is counted and skipped, not delivered as stream data. Its bytes
     * are fields of the Addons message, because the reference unmarshals them and refuses what does
     * not parse (vendor/Xray-core/proxy/vless/encoding/addons.go:46-54): an unknown varint field,
     * `18 01`, and one of two bytes, `18 81 01`, are five. The 0xaa filler that stood here is not
     * protobuf — a length past the end — and since 2026-09-27 that is refused. */
    buf[1] = 5;
    memcpy(buf + 2, "�", 5);
    ok(lc_vless_response(buf, sizeof buf, &hl) == 0 && hl == 7u,
       "five bytes of additional information make the header seven, not two");

    buf[1] = 255;
    /* Seed, field 2, as bytes: tag, a two-byte length of 252, and 252 bytes — 255 in all. */
    memcpy(buf + 2, "�", 3);
    ok(lc_vless_response(buf, sizeof buf, &hl) == 0 && hl == 257u,
       "and the largest the field can be is counted the same way");

    /* Exactly enough, and one short: the boundary is where an off-by-one lives, and being one short
     * must not be read as a complete header. */
    buf[1] = 3;
    memcpy(buf + 2, "�", 3);
    ok(lc_vless_response(buf, 5u, &hl) == 0 && hl == 5u, "a buffer holding exactly the header works");
    ok(lc_vless_response(buf, 4u, &hl) != 0, "one byte short of it does not");

    /* The version echoes ours. Anything else is not a VLESS server, and answering "read more" to
     * that would mean waiting out the deadline on a peer that will never satisfy it. */
    buf[0] = 0x01;
    buf[1] = 0;
    ok(lc_vless_response(buf, sizeof buf, &hl) != 0, "a non-zero version is refused");

    /* Too short to hold even the two fixed bytes. Same answer as a wrong version, which is the
     * conflation vless.h describes — pinned so that separating them is a deliberate act. */
    buf[0] = 0x00;
    ok(lc_vless_response(buf, 1u, &hl) != 0, "one byte is not a header");
    ok(lc_vless_response(buf, 0u, &hl) != 0, "and neither is none");

    /* ⚠️ THE OUTPUT IS NOT TOUCHED ON A REFUSAL, which matters because the caller keeps `hl` across
     * calls: a parser that wrote a length and then refused would leave the caller advancing by it. */
    hl = 12345u;
    buf[0] = 0x09;
    (void)lc_vless_response(buf, sizeof buf, &hl);
    ok(hl == 12345u, "a refused header leaves the caller's length alone");

    printf("\n%s\n", fails == 0 ? "the stream begins where the node said it does"
                                : "the response header is read DIFFERENTLY");
    return fails == 0 ? 0 : 1;
}
