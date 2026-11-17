/* Just enough HTTP/3 for Hysteria2's authentication, and no more.
 *
 * Hysteria2 authenticates with one request — POST https://hysteria/auth, four headers — and reads
 * one response. nghttp3 does HTTP/3 properly and costs 129 KB on the target; the whole REALITY
 * plane is 33 KB. That is not a trade worth making for four headers, so this writes the frames by
 * hand.
 *
 * What makes hand-writing safe rather than reckless is that the client decides how hard the server
 * is allowed to make it. Our SETTINGS declare a QPACK dynamic table of zero and no blocked streams,
 * which forbids the server from using anything but literal field lines — the one part of QPACK that
 * is simple. Huffman coding is not among the things a client may decline: the server's encoder uses
 * it whenever it is shorter, and it always is.
 *
 * If this ever proves too thin, nghttp3 is already in the build and can be swapped back in.
 *
 * ⚠️ AND "IN THE BUILD" MEANS COMPILED AND THEN DISCARDED, WHICH IS THE POINT — measured on the
 * shipped binary rather than argued: `nm -C build/lc-tunnel | grep -c nghttp3` is 0, while the same
 * count for ngtcp2 is 558. The Makefile compiles nghttp3's sources, nothing here calls them, and
 * --gc-sections drops every one of its sections at link time, so the 129 KB above is a cost this
 * client does not pay while the library stays one call away.
 *
 * ngtcp2 is the opposite and the contrast is worth having in one place: it is compiled, linked and
 * genuinely executed — the QUIC transport of the Hysteria2 plane IS ngtcp2, with our crypto
 * callbacks on top (quic/qcrypto.c). So this client is a hybrid, and reading it as all-ours or
 * all-library is wrong in both directions: TLS 1.3 and the fingerprint over TCP are written here
 * and held to uTLS byte for byte by test/fphello; QUIC is the library; HTTP/3 and QPACK above it
 * are ours again. Written down because an audit that assumed either extreme spent a pass on
 * requirements that belong to somebody else's code (the reverse sieve of 2026-08-29 did). */
#ifndef LC_H3_H
#define LC_H3_H

#include "quic/pad.h"

#include <stddef.h>
#include <stdint.h>

/* The longest a password may be here. A limit exists so that the buffer below can be a number
 * rather than a hope; this one is far past anything a node would hand out. */
#define LC_H3_PASSWORD_MAX 512u

/* Room the request needs in the worst case: the largest padding, the longest password, and every
 * field line written out in the clear because Huffman coding happened not to be shorter. */
#define LC_H3_AUTH_REQ_MAX 2816u

/* What the node said about itself when it let us in.
 *
 * ⚠️ THE NUMBERS AND THE ONE MAGIC WORD BELOW ARE THE REFERENCE'S, and until now this file named no
 * line for any of them — the blindness a header has by construction, since the sieve builds pairs
 * out of citations and a file without one is never opened. Every field here is decided by four
 * constants and one string comparison in one small reference file:
 *
 *     URLHost = "hysteria"
 *     URLPath = "/auth"
 *     RequestHeaderAuth        = "Hysteria-Auth"
 *     ResponseHeaderUDPEnabled = "Hysteria-UDP"
 *     CommonHeaderCCRX         = "Hysteria-CC-RX"
 *     CommonHeaderPadding      = "Hysteria-Padding"
 *     StatusAuthOK = 233
 *                    (vendor/hysteria/core/internal/protocol/http.go:8-18)
 *
 * and the rate is read as a number UNLESS it is exactly the word "auto", in which case the node is
 * asking the client to measure for itself: `if rxStr == "auto" { resp.RxAuto = true } else {
 * resp.Rx, _ = strconv.ParseUint(rxStr, 10, 64) }`
 * (vendor/hysteria/core/internal/protocol/http.go:48-56). That is why cc_rx is kept verbatim as
 * well as parsed: the string is the protocol, and the two fields below are what it meant. */
typedef struct {
    int  status;      /* 233 means accepted; Hysteria2 uses its own code on purpose */
    int  udp_enabled; /* whether the node will relay datagrams */
    char cc_rx[32];   /* what it said, verbatim, for reporting */

    /* And what that meant. A node states the rate it is willing to receive at — in bytes per
     * second, as everywhere in this protocol — or the word "auto", which is it asking us to work
     * out our own sending rate rather than be told one. */
    int      rate_auto;
    uint64_t rate_bytes;
} lc_h3_auth_result;

/* The control stream's opening bytes: the stream type, then SETTINGS. Written once, before
 * anything else, or the server has no idea what it is talking to. */
size_t lc_h3_control_preface(uint8_t *out, size_t cap);

/* The whole authentication request as it goes on a request stream: a HEADERS frame carrying the
 * field lines Hysteria2 expects, including the padding of its own randomly drawn length. The caller
 * does not choose that length — it is drawn per request between LC_PAD_AUTH_MIN and
 * LC_PAD_AUTH_MAX (quic/pad.h). */
long lc_h3_auth_request(const char *authority, const char *password, uint64_t rx_rate, uint8_t *out,
                        size_t cap);

/* The same with every drawn input given: the rate already in decimal, the padding, and the order the
 * three hysteria headers come out of Go's map in. What lc_h3_auth_request draws is passed here, so
 * that test/h3 can hold the bytes to the ones qpack itself writes for the same input. */
long lc_h3_auth_request_with(const char *authority, const char *password, const char *rx,
                             const char *pad, size_t pad_len, const unsigned order[3], uint8_t *out,
                             size_t cap);

/* Reads what came back on that stream. Returns 1 when a complete response was parsed, 0 when more
 * bytes are needed, -1 when it is not something this understands. */
int lc_h3_auth_response(const uint8_t *in, size_t len, lc_h3_auth_result *out);

#endif
