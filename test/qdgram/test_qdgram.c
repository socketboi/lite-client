/* How large a proxied UDP payload may be, against the numbers the reference computes.
 *
 * ⚠️ THIS SUITE EXISTS BECAUSE A COMMENT WAS BELIEVED FOR MONTHS. One guessed constant of sixty
 * bytes stood in for two different wrappers — the DATAGRAM frame's header, which is three, and the
 * QUIC packet's, which is thirty-seven. An earlier fix removed the constant's role as a ceiling and
 * recorded in prose that the resulting fifty-seven-byte window was closed. It was not: the same
 * sixty was still being subtracted from the negotiated frame size, so against a node advertising
 * 1200 this client computed 1140 where the reference computes 1197, and every payload in between —
 * which is where ordinary DNS answers and tunnelled QUIC sit — went out as two datagrams instead of
 * one. Nothing failed, nothing was dropped, and no test could have said so, because the arithmetic
 * lived in conn.c and conn.c cannot be loaded without the whole vendored QUIC stack.
 *
 * So the cases below are written to fail on a return to a single sixty-byte reserve, and to fail on
 * `frame_max - 3` written as a shortcut. Being green here means this client fragments where quic-go
 * fragments and nowhere else.
 *
 * The reference:
 *   min(f.MaxDataLen(maxDatagramFrameSize, version), maxPayloadSizeEstimate)
 *                                              (vendor/quic-go/connection.go:3084-3093)
 *   MaxDataLen                    (vendor/quic-go/internal/wire/datagram_frame.go:61-76)
 *   estimateMaxPayloadSize                     (vendor/quic-go/connection.go:3199-3204)
 * and hysteria fragments against whatever comes back (core/client/udp.go:60-71). */
#include "quic/dgram.h"

#include <stdio.h>

static int failures;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

/* MaxDataLen, transcribed. Kept here as an independent second opinion rather than calling the
 * module: if both sides of a comparison come from the same expression, the comparison says nothing.
 * `quicvarint.Len(x) == 1` is `x < 64`. */
static uint64_t vendor_max_data_len(uint64_t max_size)
{
    uint64_t header_len = 2u; /* frame type, plus one for the length varint (DataLenPresent) */
    if (header_len > max_size)
        return 0;
    uint64_t max_data_len = max_size - header_len;
    if (max_data_len >= 64u)
        max_data_len--;
    return max_data_len;
}

static void test_frame_fit_matches_vendor(void)
{
    static const uint64_t sizes[] = { 0,  1,   2,   3,   4,    10,   63,   64,   65,   66,
                                      67, 128, 512, 999, 1200, 1252, 1350, 1452, 8192, 65535 };
    int    all = 1;
    size_t i;

    for (i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
        if (lc_qudp_frame_fit(sizes[i]) != (size_t)vendor_max_data_len(sizes[i])) {
            printf("        frame_max=%llu: ours %zu, reference %llu\n",
                   (unsigned long long)sizes[i], lc_qudp_frame_fit(sizes[i]),
                   (unsigned long long)vendor_max_data_len(sizes[i]));
            all = 0;
        }
    }
    ok(all, "the frame wrapper is MaxDataLen's, across twenty sizes");

    /* The varint step, named on its own because it is the whole reason this is a function and not
     * a subtraction: at 66 the answer stops fitting in a one-byte varint and loses a byte, so 65
     * and 66 both give 63. `frame_max - 3` would give 63 and 64. */
    ok(lc_qudp_frame_fit(65u) == 63u, "a frame of 65 carries 63 — one varint byte, no adjustment");
    ok(lc_qudp_frame_fit(66u) == 63u, "a frame of 66 also carries 63 — the varint grew, so the "
                                      "payload shrank");
    ok(lc_qudp_frame_fit(67u) == 64u, "a frame of 67 carries 64 — past the step, growing again");

    /* ⚠️ THE TIE BETWEEN THE CONSTANT AND THE FUNCTION, without which they are two independent
     * opinions about the same three bytes. LC_QUDP_FRAME_OVERHEAD exists because a macro cannot call
     * lc_qudp_frame_fit, so the fallback is spelled as a subtraction — and a subtraction that agrees
     * with the function today and is never asked to keep agreeing is the exact shape of the fault
     * this suite was written over. Changing either without the other fails here. */
    ok(lc_qudp_frame_fit(LC_HY_DATAGRAM_MAX) == LC_QUDP_PAYLOAD,
       "the fallback constant is what the function would have said about the same frame");

    /* Nothing to carry rather than a wrapped-around enormous number. */
    ok(lc_qudp_frame_fit(0u) == 0u, "a frame of nothing carries nothing");
    ok(lc_qudp_frame_fit(1u) == 0u, "a frame too small for its own type byte carries nothing");
    ok(lc_qudp_frame_fit(2u) == 0u, "a frame of exactly its header carries nothing");
}

/* THE CASE THIS FILE WAS WRITTEN FOR.
 *
 * A node advertising the 1200 hysteria assumes of a silent peer, on the 1280-byte path a connection
 * starts at. The frame wrapper binds: 1200 - 3 = 1197. Sixty bytes of reserve gives 1140, which is
 * what this client sent for months. */
static void test_the_fifty_seven_byte_window(void)
{
    size_t fit = lc_qudp_fit(1200u, 1280u);

    ok(fit == 1197u, "a node advertising 1200 on a 1280-byte path gives 1197, the reference's own "
                     "number");
    ok(fit != 1140u, "and NOT 1140 — the value a single sixty-byte reserve produced while a comment "
                     "said the fault was fixed");
    ok(fit > LC_QUDP_PAYLOAD - 1u, "which is at least what a silent peer would have given us");
}

static void test_which_wrapper_binds(void)
{
    /* A generous peer: the path decides, and it is the PACKET wrapper that comes off. The path is
     * not one number any more — it starts at 1280 and Path MTU Discovery walks it up towards
     * LC_QUDP_TX_MTU — so both ends of that walk are asked here. */
    ok(lc_qudp_fit(1452u, 1280u) == 1243u,
       "a generous node on the starting path binds at 1243 — estimateMaxPayloadSize, not the "
       "frame's");
    ok(lc_qudp_fit(1452u, LC_QUDP_TX_MTU) == 1415u,
       "and at the ceiling discovery can reach, at 1415");

    /* A mean peer: the frame decides. */
    ok(lc_qudp_fit(600u, LC_QUDP_TX_MTU) == 597u, "a node offering 600 binds at 597");

    /* Both halves consulted, not just whichever is written first. */
    ok(lc_qudp_fit(1452u, 700u) == 663u, "a short path binds even when the node is generous");
}

static void test_fallback_and_clamp(void)
{
    /* No connection to ask: the peer advertised nothing and there is no path estimate. This is the
     * case the reference never reaches, and the answer is what a silent node assumes we can take. */
    ok(lc_qudp_fit(0u, 0u) == LC_QUDP_PAYLOAD, "with nothing negotiated, the fallback answers");
    ok(LC_QUDP_PAYLOAD == 1197u, "and the fallback is LC_HY_DATAGRAM_MAX less the frame header");

    /* A peer that advertised something unusable is not the same as one that advertised nothing, but
     * it ends in the same place: there is no size we can send, so the fallback answers rather than
     * zero being passed on as a payload length. */
    ok(lc_qudp_fit(1u, 0u) == LC_QUDP_PAYLOAD, "a peer offering an unusable frame falls back too");

    /* THE CLAMP, which is not decoration: the answer is copied into a send-queue slot of
     * LC_QUDP_SLOT bytes, and lc_hy_udp_put refuses anything longer. An unclamped answer would turn
     * a generous negotiation into a drop on our own floor, logged as though the node had refused. */
    ok(lc_qudp_fit(65535u, 65535u) == LC_QUDP_SLOT,
       "an answer can never exceed the queue slot it is copied into");
    ok(LC_QUDP_SLOT == 1415u, "and the slot is the largest the path can ever carry");

    /* The two constants have to stay in this order, or the clamp silently becomes the answer for
     * every connection and the negotiation stops mattering. */
    ok(LC_QUDP_SLOT > LC_QUDP_PAYLOAD,
       "the slot is above the fallback, so the fallback is never itself clamped");
}

int main(void)
{
    printf("how large a datagram this client will send\n");

    test_frame_fit_matches_vendor();
    test_the_fifty_seven_byte_window();
    test_which_wrapper_binds();
    test_fallback_and_clamp();

    printf("\n%s\n", failures == 0 ? "datagrams are sized the way quic-go sizes them"
                                   : "this client fragments where the reference does NOT");
    return failures == 0 ? 0 : 1;
}
