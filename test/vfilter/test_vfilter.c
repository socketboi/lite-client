/* The filter that decides whether direct copy is allowed, which nothing asked until 2026-09-02.
 *
 * ⚠️ WHY IT MATTERS MORE THAN THE FRAMING BESIDE IT. test/vision checks how Vision wraps and unwraps
 * bytes — a defect there corrupts a stream and is loud. lc_vision_filter decides something quieter
 * and worse: whether this client may stop sealing bytes into TLS records and hand them straight
 * through. Say yes about a stream that is not what it looks like, and raw bytes go out where
 * ciphertext was expected. Nothing errors. The stream simply is not what the far end reads.
 *
 * AND THE DEFECT IT GUARDS AGAINST HAS HAPPENED. The condition was once `cipher != 0x1305`, which
 * dropped the membership half of the reference's test:
 *
 *     v, ok := Tls13CipherSuiteDic[trafficState.Cipher]
 *     if !ok { … } else if v != "TLS_AES_128_CCM_8_SHA256" { trafficState.EnableXtls = true }
 *                                        (vendor/Xray-core/proxy/proxy.go:655-659, dict at :43-49)
 *
 * With `!=` alone, a cipher that was never parsed — zero, which is what a short ServerHello leaves —
 * and every TLS 1.2 suite enabled direct copy. It is fixed, to a range test over 0x1301..0x1304, and
 * until this file nothing would have noticed it going back.
 *
 * The cases below are written so that a return to `!= 0x1305` fails them. */

#include "vless/vision.h"

#include <stdio.h>
#include <string.h>

static int fails;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        fails++;
}

static const uint8_t uuid[LC_VLESS_UUID] = { 1, 2, 3, 4 };

/* A ServerHello shaped the way the filter reads one.
 *
 *   [0..2]  record header, 0x16 0x03 0x03
 *   [3..4]  record length, big-endian; the filter adds five and calls that the message
 *   [5]     handshake type, 0x02 for a ServerHello
 *   [43]    the session id length, after eleven bytes of header and thirty-two of random
 *   cipher  two bytes at 43 + sid + 1
 *
 * `tls13` places the supported_versions extension the filter looks for. Its absence is what a TLS
 * 1.2 ServerHello looks like from here, so the two differ by those six bytes and nothing else. */
#define BUF 200u
static void build(uint8_t *b, uint16_t cipher, int tls13)
{
    memset(b, 0, BUF);
    b[0] = 0x16;
    b[1] = 0x03;
    b[2] = 0x03;
    b[3] = (uint8_t)((BUF - 5u) >> 8);
    b[4] = (uint8_t)(BUF - 5u);
    b[5] = 0x02;

    b[43] = 32; /* session id length */
    b[76] = (uint8_t)(cipher >> 8);
    b[77] = (uint8_t)cipher;

    if (tls13) {
        static const uint8_t sv[6] = { 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04 };
        memcpy(b + 100, sv, sizeof sv);
    }
}

/* Runs one ServerHello through a fresh filter and hands back what it decided. */
static lc_vision decide(uint16_t cipher, int tls13)
{
    uint8_t   b[BUF];
    lc_vision v;
    build(b, cipher, tls13);
    lc_vision_init(&v, uuid);
    lc_vision_filter(&v, b, BUF);
    return v;
}

static void test_recognises_tls13(void)
{
    lc_vision v = decide(0x1301u, 1);
    ok(v.is_tls == 1, "a ServerHello is recognised as TLS");
    ok(v.is_tls12_or_above == 1, "and as at least TLS 1.2");
    ok(v.cipher == 0x1301u, "the cipher is read from behind the session id");
    ok(v.enable_xtls == 1, "TLS 1.3 with AES-128-GCM permits direct copy");
    ok(v.packets_to_filter == 0, "and the filter stops once it has decided");
}

/* ⚠️ THE FOUR CASES THAT SEPARATE A RANGE TEST FROM `!= 0x1305`. Every one of them is a cipher the
 * reference's dictionary lookup FAILS on, or the single member it excludes by name. */
static void test_which_ciphers_permit_it(void)
{
    ok(decide(0x1301u, 1).enable_xtls == 1, "0x1301 permits it");
    ok(decide(0x1304u, 1).enable_xtls == 1, "0x1304 permits it — the top of the range, not past it");

    ok(decide(0x1305u, 1).enable_xtls == 0,
       "0x1305 does NOT — TLS_AES_128_CCM_8_SHA256 is the one the reference excludes by name");

    /* The two the broken condition let through. */
    ok(decide(0x0000u, 1).enable_xtls == 0,
       "a cipher that was never parsed does NOT, though it is not 0x1305 either");
    ok(decide(0xc02fu, 1).enable_xtls == 0,
       "and neither does a TLS 1.2 suite, for the same reason: it is not in the dictionary");
    ok(decide(0x1300u, 1).enable_xtls == 0, "0x1300 does not — the bottom of the range holds too");
}

static void test_tls12(void)
{
    /* No supported_versions marker: a TLS 1.2 ServerHello. Direct copy must not be enabled however
     * good the cipher looks, and the filter must stop rather than keep hunting for the rest of the
     * connection. */
    lc_vision v = decide(0x1301u, 0);
    ok(v.is_tls == 1, "a TLS 1.2 ServerHello is still recognised as TLS");
    ok(v.enable_xtls == 0, "but direct copy is not enabled without the TLS 1.3 marker");
    ok(v.packets_to_filter == 0, "and the filter gives up rather than watching the whole connection");
}

static void test_client_hello_and_exhaustion(void)
{
    uint8_t   b[BUF];
    lc_vision v;

    /* A ClientHello, which says the stream is TLS and nothing more: the version and the cipher are
     * the server's to choose and are not in this message. */
    build(b, 0x1301u, 1);
    b[5] = 0x01;
    lc_vision_init(&v, uuid);
    lc_vision_filter(&v, b, BUF);
    ok(v.is_tls == 1, "a ClientHello marks the stream as TLS");
    ok(v.enable_xtls == 0, "and decides nothing about direct copy");
    ok(v.is_tls12_or_above == 0, "nor about the version, which the server has not named yet");

    /* Too short to hold a record header at all: looked at and left alone. */
    build(b, 0x1301u, 1);
    lc_vision_init(&v, uuid);
    lc_vision_filter(&v, b, 4u);
    ok(v.is_tls == 0 && v.enable_xtls == 0, "a fragment too short to hold a header decides nothing");

    /* ⚠️ THE BUDGET IS SPENT WHETHER OR NOT ANYTHING WAS FOUND, which is what stops this from
     * examining every packet of a long connection. A filter that never gave up would pay its cost
     * on traffic it has already failed to classify. */
    lc_vision_init(&v, uuid);
    int budget = v.packets_to_filter;
    ok(budget > 0, "a fresh connection starts with packets left to filter");
    for (int i = 0; i < budget; i++) {
        uint8_t junk[8] = { 0 };
        lc_vision_filter(&v, junk, sizeof junk);
    }
    ok(v.packets_to_filter == 0, "and the budget runs out after that many packets");

    /* Past the budget the filter returns without touching anything — checked by handing it the
     * ServerHello it would certainly have acted on while it still had a packet left. */
    build(b, 0x1301u, 1);
    lc_vision_filter(&v, b, BUF);
    ok(v.enable_xtls == 0 && v.is_tls == 0,
       "and a spent filter ignores even a ServerHello it would have acted on");
}

int main(void)
{
    printf("what Vision decides about the stream inside\n");

    test_recognises_tls13();
    test_which_ciphers_permit_it();
    test_tls12();
    test_client_hello_and_exhaustion();

    printf("\n%s\n", fails == 0 ? "direct copy is permitted where the reference permits it"
                                : "the direct-copy decision has CHANGED");
    return fails == 0 ? 0 : 1;
}
