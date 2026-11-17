/* Our QPACK against nghttp3's, in both directions.
 *
 * The request this client sends is encoded by hand, because nghttp3 costs 129 KB on the target and
 * the whole REALITY plane is 33 KB. Writing it by hand is only defensible if it is checked against
 * an implementation that does it properly — and nghttp3 is already in the tree, so the check costs
 * nothing to run and settles the question offline instead of by watching a server not answer.
 *
 * The response half of this test exists because watching a server not answer is exactly how the
 * Huffman gap was found, and only after a detour through the node's own logs. A Hysteria2 server is
 * Go, its QPACK encoder codes any literal that comes out shorter that way, and every literal in
 * that response does. A parser that refused Huffman refused every answer it would ever be given —
 * and refused it identically to how a server refuses a wrong password, since hysteria answers a bad
 * password with the masquerade page on purpose. Nothing about that is visible from this side. It is
 * visible from here. */

#include "quic/h3.h"
#include "quic/huffman.h"

#include <nghttp3/nghttp3.h>

#include "nghttp3_qpack_huffman.h"
#include "qpack_vectors.h"
#include "quic/pad.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

/* Whether `hay` contains `needle` anywhere. Written out because memmem is not everywhere. */
static int contains(const uint8_t *hay, size_t hlen, const void *needle, size_t nlen)
{
    if (nlen > hlen)
        return 0;
    for (size_t i = 0; i + nlen <= hlen; i++)
        if (memcmp(hay + i, needle, nlen) == 0)
            return 1;
    return 0;
}

/* ---- the coding itself, against nghttp3's ---- */

static void test_huffman(void)
{
    printf("\nHuffman coding against nghttp3\n");

    /* Every byte value, one at a time, so that a table entry that is wrong is named rather than
     * hidden in an average. Single symbols also exercise the padding rule hardest: one code of five
     * to thirty bits, then whatever it takes to reach a byte boundary. */
    int enc_bad = -1, dec_bad = -1, len_bad = -1;
    for (int c = 0; c < 256 && (enc_bad | dec_bad | len_bad) == -1; c++) {
        char    in = (char)c;
        uint8_t ours[8], theirs[8];

        long n = lc_huff_encode(&in, 1, ours, sizeof ours);
        size_t want = nghttp3_qpack_huffman_encode_count((const uint8_t *)&in, 1);
        if (n < 0 || (size_t)n != want || lc_huff_len(&in, 1) != want) {
            len_bad = c;
            break;
        }

        uint8_t *end = nghttp3_qpack_huffman_encode(theirs, (const uint8_t *)&in, 1);
        if ((size_t)(end - theirs) != (size_t)n || memcmp(ours, theirs, (size_t)n) != 0) {
            enc_bad = c;
            break;
        }

        /* And back, through our decoder, from the bytes nghttp3 produced. */
        char decoded[8];
        long d = lc_huff_decode(theirs, (size_t)n, decoded, sizeof decoded);
        if (d != 1 || decoded[0] != in)
            dec_bad = c;
    }
    ok(len_bad == -1, "the coded length of every byte matches nghttp3's");
    ok(enc_bad == -1, "the coded bytes of every byte match nghttp3's");
    ok(dec_bad == -1, "every byte survives nghttp3's encoder and our decoder");

    /* A long run, where codes cross byte boundaries in every alignment. */
    char all[256];
    for (int i = 0; i < 256; i++)
        all[i] = (char)i;
    uint8_t coded[1024];
    long    n = lc_huff_encode(all, sizeof all, coded, sizeof coded);
    ok(n > 0 && (size_t)n == nghttp3_qpack_huffman_encode_count((const uint8_t *)all, sizeof all),
       "a run of all 256 bytes codes to the length nghttp3 says");

    char back[512];
    ok(lc_huff_decode(coded, (size_t)n, back, sizeof back) == 256 &&
           memcmp(back, all, sizeof all) == 0,
       "and decodes back to what went in");

    /* Truncation is a report, not a silent loss: the caller is told the full length so it can tell
     * a value it did not have room for from one that was that short. Measured on text rather than
     * on the run above, whose first byte is a NUL and would make any length look like zero. */
    const char  *text = "hysteria-padding-goes-here";
    size_t       text_len = strlen(text);
    uint8_t      text_coded[64];
    long         tn = lc_huff_encode(text, text_len, text_coded, sizeof text_coded);
    char         small[8];
    ok(tn > 0 && lc_huff_decode(text_coded, (size_t)tn, small, sizeof small) == (long)text_len &&
           strlen(small) == 7 && memcmp(small, text, 7) == 0,
       "a value too long for the buffer reports its true length and keeps what fits");

    /* Refusals. Padding must be ones and must be shorter than a byte, and the end-of-string symbol
     * may not appear in a value at all — the three ways RFC 7541 section 5.2 says a coding is
     * malformed. */
    uint8_t zero_pad[2];
    long    zn = lc_huff_encode("a", 1, zero_pad, sizeof zero_pad);
    zero_pad[zn - 1] &= (uint8_t)0xf8u; /* 'a' is five bits; blank the three padding ones */
    ok(lc_huff_decode(zero_pad, (size_t)zn, back, sizeof back) < 0,
       "padding that is not all ones is refused");

    const uint8_t eos[] = { 0xff, 0xff, 0xff, 0xff, 0xff }; /* thirty ones: end of string */
    ok(lc_huff_decode(eos, sizeof eos, back, sizeof back) < 0,
       "an end-of-string symbol inside a value is refused");

    const uint8_t long_pad[] = { 0x1f, 0xff }; /* a code, then more than seven bits of padding */
    ok(lc_huff_decode(long_pad, sizeof long_pad, back, sizeof back) < 0,
       "padding of a whole byte or more is refused");
}

/* ---- the request, read back by nghttp3's decoder ---- */

/* THE ORDER OF THE THREE HYSTERIA HEADERS, AS GO'S MAP ITERATION DEALS IT.
 *
 * quic-go writes the caller's headers by ranging over the map they live in
 * (`for k, vv := range req.Header`, vendor/quic-go/http3/request_writer.go:168), and a map of three
 * in Go is a small map: slots 0, 1, 2 of eight, walked from a random slot. That gives exactly three
 * orders — auth, cc-rx, padding six times in eight; cc-rx, padding, auth once; padding, auth, cc-rx
 * once — and never the other three. Go 1.26.6 itself, 800 000 times: 0.7498, 0.1256, 0.1246. See
 * lc_h3_auth_request for the runtime lines.
 *
 * One request tells an observer nothing — every order is legal and the lengths do not move — so what
 * is checked is the DISTRIBUTION, which is where both earlier versions were wrong: one fixed order,
 * then a uniform shuffle over six that sent three orders the reference never does. Eight hundred
 * draws: the three forbidden orders must not appear at all, and the three allowed ones must sit
 * inside bounds more than five standard deviations wide around 600, 100 and 100 — so a uniform
 * shuffle (133 each, and forbidden ones present), a fixed order (800, 0, 0) and a swap of which
 * order is common all fail, and a correct build does not flake. */
static void test_header_order(void)
{
    printf("\nThe order of the three hysteria headers\n");

    int seen[27];
    memset(seen, 0, sizeof seen);

    int builds = 0, decodes = 0, triples = 0;
    for (int iter = 0; iter < 800; iter++) {
        uint8_t req[LC_H3_AUTH_REQ_MAX];
        long    n = lc_h3_auth_request("hysteria", "secret-password", 0, req, sizeof req);
        if (n <= 0)
            continue;
        builds++;

        size_t off = 1;
        off += (size_t)1u << (req[off] >> 6);

        nghttp3_qpack_decoder        *dec = NULL;
        nghttp3_qpack_stream_context *sctx = NULL;
        if (nghttp3_qpack_decoder_new(&dec, 0, 0, nghttp3_mem_default()) != 0)
            continue;
        if (nghttp3_qpack_stream_context_new(&sctx, 0, nghttp3_mem_default()) != 0) {
            nghttp3_qpack_decoder_del(dec);
            continue;
        }

        const uint8_t *p = req + off;
        size_t         left = (size_t)n - off;
        int            slot[3] = { -1, -1, -1 };
        int            got = 0;
        int            bad = 0;

        while (left > 0 && !bad) {
            nghttp3_qpack_nv nv;
            uint8_t          flags = 0;
            nghttp3_ssize    read =
                nghttp3_qpack_decoder_read_request(dec, sctx, &nv, &flags, p, left, 1);
            if (read < 0) {
                bad = 1;
                break;
            }
            p += read;
            left -= (size_t)read;
            if ((flags & NGHTTP3_QPACK_DECODE_FLAG_EMIT) == 0)
                continue;

            const char *nm = (const char *)nghttp3_rcbuf_get_buf(nv.name).base;
            size_t      nl = nghttp3_rcbuf_get_buf(nv.name).len;
            int         which = -1;
            if (nl == 13u && memcmp(nm, "hysteria-auth", 13u) == 0)
                which = 0;
            else if (nl == 14u && memcmp(nm, "hysteria-cc-rx", 14u) == 0)
                which = 1;
            else if (nl == 16u && memcmp(nm, "hysteria-padding", 16u) == 0)
                which = 2;
            if (which >= 0 && got < 3)
                slot[got++] = which;

            nghttp3_rcbuf_decref(nv.name);
            nghttp3_rcbuf_decref(nv.value);
        }

        nghttp3_qpack_stream_context_del(sctx);
        nghttp3_qpack_decoder_del(dec);

        if (bad || got != 3)
            continue;
        decodes++;
        if (slot[0] != slot[1] && slot[1] != slot[2] && slot[0] != slot[2]) {
            triples++;
            seen[slot[0] * 9 + slot[1] * 3 + slot[2]]++;
        }
    }

    ok(builds == 800, "eight hundred requests build");
    ok(decodes == 800, "nghttp3 decodes every one of them");
    ok(triples == 800, "and each carries the three hysteria headers exactly once");

    /* 0 = auth, 1 = cc-rx, 2 = padding. */
    int as_set = seen[0 * 9 + 1 * 3 + 2];
    int from_one = seen[1 * 9 + 2 * 3 + 0];
    int from_two = seen[2 * 9 + 0 * 3 + 1];
    int others = triples - as_set - from_one - from_two;
    ok(others == 0, "the three orders a small Go map cannot give never appear");
    ok(as_set >= 520 && as_set <= 680 && from_one >= 50 && from_one <= 150 && from_two >= 50 &&
           from_two <= 150,
       "and the three it can give come six to one to one, as ranging over it does");
    printf("        auth,cc-rx,padding %d · cc-rx,padding,auth %d · padding,auth,cc-rx %d · other %d\n",
           as_set, from_one, from_two, others);
}
static void test_request(void)
{
    printf("\nThe authentication request, decoded by nghttp3\n");

    uint8_t req[LC_H3_AUTH_REQ_MAX];
    long    n = lc_h3_auth_request("hysteria", "secret-password", 0, req, sizeof req);
    ok(n > 0, "the request builds");
    if (n <= 0)
        return;

    /* Step over the HEADERS frame header: a type and a length, both variable-length integers. */
    size_t off = 0;
    ok((req[0] & 0x3fu) == 0x01u, "the frame is HEADERS");
    off += 1;
    off += (size_t)1u << (req[off] >> 6);

    nghttp3_qpack_decoder *dec = NULL;
    ok(nghttp3_qpack_decoder_new(&dec, 0, 0, nghttp3_mem_default()) == 0,
       "nghttp3's decoder starts with no dynamic table, as our settings promised");

    nghttp3_qpack_stream_context *sctx = NULL;
    ok(nghttp3_qpack_stream_context_new(&sctx, 0, nghttp3_mem_default()) == 0,
       "a stream context for the request stream");

    nghttp3_qpack_nv nv;
    uint8_t          flags = 0;
    const uint8_t   *p = req + off;
    size_t           left = (size_t)n - off;

    int  seen_method = 0, seen_path = 0, seen_authority = 0, seen_auth = 0, seen_rx = 0, count = 0;
    char padding[LC_PAD_AUTH_MAX + 1];
    size_t padding_len = 0;

    padding[0] = '\0';

    while (left > 0) {
        nghttp3_ssize read = nghttp3_qpack_decoder_read_request(dec, sctx, &nv, &flags, p, left, 1);
        if (read < 0) {
            printf("  FAIL  nghttp3 refused the field section: %s\n",
                   nghttp3_strerror((int)read));
            failures++;
            break;
        }
        p += read;
        left -= (size_t)read;

        if ((flags & NGHTTP3_QPACK_DECODE_FLAG_EMIT) == 0)
            continue;
        count++;

        const char *name = (const char *)nghttp3_rcbuf_get_buf(nv.name).base;
        size_t      name_len = nghttp3_rcbuf_get_buf(nv.name).len;
        const char *value = (const char *)nghttp3_rcbuf_get_buf(nv.value).base;
        size_t      value_len = nghttp3_rcbuf_get_buf(nv.value).len;

        if (name_len == 7 && memcmp(name, ":method", 7) == 0)
            seen_method = value_len == 4 && memcmp(value, "POST", 4) == 0;
        else if (name_len == 5 && memcmp(name, ":path", 5) == 0)
            seen_path = value_len == 5 && memcmp(value, "/auth", 5) == 0;
        else if (name_len == 10 && memcmp(name, ":authority", 10) == 0)
            seen_authority = value_len == 8 && memcmp(value, "hysteria", 8) == 0;
        else if (name_len == 13 && memcmp(name, "hysteria-auth", 13) == 0)
            seen_auth = value_len == 15 && memcmp(value, "secret-password", 15) == 0;
        else if (name_len == 14 && memcmp(name, "hysteria-cc-rx", 14) == 0)
            seen_rx = 1;
        else if (name_len == 16 && memcmp(name, "hysteria-padding", 16) == 0) {
            padding_len = value_len;
            if (value_len <= LC_PAD_AUTH_MAX)
                memcpy(padding, value, value_len);
        }

        nghttp3_rcbuf_decref(nv.name);
        nghttp3_rcbuf_decref(nv.value);
    }

    /* Ten, because that is what the reference emits. Four pseudo-headers, the three hysteria sets
     * in AuthRequestToHeader, and the three quic-go appends to every request of its own accord —
     * content-length for a POST with an empty body, accept-encoding: gzip, and the constant
     * user-agent (vendor/quic-go/http3/request_writer.go:200-210). This asserted seven for as long
     * as those three were missing, which is how a test comes to certify a client that no node has
     * ever seen. */
    ok(count == 10, "ten field lines come back out, as the reference sends");
    ok(seen_method, ":method is POST");
    ok(seen_path, ":path is /auth");
    ok(seen_authority, ":authority is hysteria");
    ok(seen_auth, "hysteria-auth carries the password");
    ok(seen_rx, "hysteria-cc-rx is present");
    ok(padding_len >= LC_PAD_AUTH_MIN && padding_len < LC_PAD_AUTH_MAX,
       "the padding is in the range hysteria's own client draws from");

    /* Coded, not spelled out. Both of these are lower-case runs that Huffman shortens, so a request
     * that carried them in the clear would be a request no Go client would have sent — which is the
     * only thing about this exchange an observer gets to see. */
    ok(!contains(req, (size_t)n, "hysteria-padding", 16),
       "the padding's name is Huffman-coded, as Go's encoder would have written it");
    ok(padding_len > 0 && !contains(req, (size_t)n, padding, padding_len),
       "and so is the padding itself");

    nghttp3_qpack_stream_context_del(sctx);
    nghttp3_qpack_decoder_del(dec);
}

/* ---- the response, written by nghttp3's encoder ---- */

static void test_response(void)
{
    printf("\nA server's answer, encoded by nghttp3\n");

    /* The fields hysteria sends back, padding and all. nghttp3's encoder makes the same choice
     * about Huffman that Go's does, which is the point: this is the shape of message that our own
     * parser used to refuse. */
    char pad[600];
    memset(pad, 'x', sizeof pad - 1);
    pad[sizeof pad - 1] = '\0';

    nghttp3_nv nva[] = {
        { (uint8_t *)":status", (uint8_t *)"233", 7, 3, NGHTTP3_NV_FLAG_NONE },
        { (uint8_t *)"hysteria-udp", (uint8_t *)"true", 12, 4, NGHTTP3_NV_FLAG_NONE },
        { (uint8_t *)"hysteria-cc-rx", (uint8_t *)"auto", 14, 4, NGHTTP3_NV_FLAG_NONE },
        { (uint8_t *)"hysteria-padding", (uint8_t *)pad, 16, sizeof pad - 1,
          NGHTTP3_NV_FLAG_NONE },
    };

    nghttp3_qpack_encoder *enc = NULL;
    ok(nghttp3_qpack_encoder_new(&enc, 0, nghttp3_mem_default()) == 0,
       "nghttp3's encoder, with the dynamic table our settings forbade");

    nghttp3_buf pbuf, rbuf, ebuf;
    nghttp3_buf_init(&pbuf);
    nghttp3_buf_init(&rbuf);
    nghttp3_buf_init(&ebuf);

    ok(nghttp3_qpack_encoder_encode(enc, &pbuf, &rbuf, &ebuf, 0, nva,
                                    sizeof nva / sizeof nva[0]) == 0,
       "it encodes the four fields");

    size_t plen = nghttp3_buf_len(&pbuf), rlen = nghttp3_buf_len(&rbuf);
    ok(nghttp3_buf_len(&ebuf) == 0, "and asks for nothing on the encoder stream");

    /* Wrapped in the HEADERS frame it would arrive in. */
    uint8_t resp[4096];
    size_t  body = plen + rlen;
    size_t  at = 0;
    resp[at++] = 0x01;
    resp[at++] = (uint8_t)(0x40u | body >> 8);
    resp[at++] = (uint8_t)body;
    ok(at + body <= sizeof resp, "the response fits the buffer this client reads into");
    memcpy(resp + at, pbuf.pos, plen);
    memcpy(resp + at + plen, rbuf.pos, rlen);
    at += body;

    lc_h3_auth_result got;
    ok(lc_h3_auth_response(resp, at, &got) == 1, "our parser reads it");
    ok(got.status == 233, "the status is 233 — accepted");
    ok(got.udp_enabled, "the node says it will relay datagrams");
    ok(strcmp(got.cc_rx, "auto") == 0, "and asks us to work the rate out ourselves");

    /* Incomplete input is a request for more, never a refusal: the response arrives in as many
     * QUIC packets as it takes, and this parser sees each prefix of it on the way. */
    int impatient = 0;
    for (size_t cut = 1; cut < at; cut++) {
        lc_h3_auth_result partial;
        if (lc_h3_auth_response(resp, cut, &partial) != 0) {
            impatient = (int)cut;
            break;
        }
    }
    ok(impatient == 0, "every prefix of it asks for more rather than failing");

    nghttp3_buf_free(&pbuf, nghttp3_mem_default());
    nghttp3_buf_free(&rbuf, nghttp3_mem_default());
    nghttp3_buf_free(&ebuf, nghttp3_mem_default());
    nghttp3_qpack_encoder_del(enc);
}

/* ---- a real answer, captured from a node ---- */

/* Exactly the bytes a Hysteria2 server sent this client on its request stream, kept because every
 * assumption that broke here is one nghttp3's encoder happens not to exercise. Reading it needs
 * Huffman for the status, for two header names and for a few hundred characters of padding; it
 * carries a `date` whose name comes from the static table by reference; and it ends with an indexed
 * field line — a whole line that is one static entry — which an earlier parser read as a second
 * :status and used to overwrite the real one with nothing.
 *
 * There is nothing of anyone's in it: a status, a date, a length, and padding. */
static const char captured_response[] =
    "0144ed00005f0983132cff2f029fd2125b0c35ad92bf834d96972f039fd2125b0c358845acf381072f059fd2125b0c35"
    "ab1c921aa9bfff9f086a9d70ce6a01c6a9b3e0ecedec6473f3c6fdde2ac377d86dbc3fdc3d77b8f75e9607f31fae20d9"
    "9fa60c7987ab7eab26ce0986f538750b1839c67fc736fe777517734b48716d734786f4f1e9ef679fdea9d7af9e8ac867"
    "c779af7ecbac3677db64bef1698fb63eaee9f41e38fc0a7dd3efe5d6ae3faccfe1b17ee166eefd396b4edeb8348bbecc"
    "5ab65dc6d999f3a9dc5b3d73f7e36bd968fde2fb3978b7d73e3d89a47af459a66c433cfafd9b8fe67cbe401ed9741d3d"
    "ff50f7118b74727ae990aee64e0200d565f5313d7ac218781e6b3cdd773fe737f56f06dbdbb605ffc8f6bdef6feeac79"
    "b5e094297f8e9bbb3763f6596cc3b931de95f7c9aabd2fe0c7a649bd5dadfd1f93f20bcf4bd8a6f5ac3d0d0d5568afdf"
    "a0dff197c771d1af8fbbcf1aad80f41b7bb396700b1736bb5f79aebcf987c6ec9d66e926a6ecdfb6f74ef7cbe35de139"
    "a8bd3b8eef66f8cc3d47661e5df0e07afe47f9d1819bd828ab85ee91e416c117dbfc1a68b0e2d79d1c35183f993cd558"
    "2cf6e3e80550cb802efa6eff4aff7f69275ed7f06bd983027037c81b7dc621a01bb6cae64be5e1563ddaff6f51563bd3"
    "78b1bddcf2619b5b52e8b3d3db03e7a77ebd71075677bb97492d6babbbf163cfafdf8e14398fd6fa7f7ae09ff31f877a"
    "e2df9fa08b4a13b9c34daba15cfcbbbd91def1873598f40db87a3fc705da99841871f3d91c7d5d8eeb8232535e9f1cfc"
    "e19593db0f98d192dc16604dae5dba725ffcf1fb8bbdf165adaef55fe8ddad98469f5738ecab7c3919d7bc5666b7de13"
    "ed76dd7f9d1aa2dbf5e1ba57fa6fc8cf66fb64f36378b765cfaf8a727afddbc5bb1addd343ccc9d19b6896d8fa542e9d"
    "7408d0dddecfabd7f082ed979bb2fed28789acb11b749ef6a753fbeebaf84f3494064d62d377f7cce7e5a30ddec76b23"
    "c3cb824aface793672a83addeb91e7316167487a96f1b18f1feea6c523be2bef4562ef39aee148cbc49ce1c4e83a7abd"
    "f80e9d76b534399e3869efc73df0ee3a7f3bf0fceb8b467c11e3a73e82a386d162934daf561de5043a739cda386cedce"
    "80b5950fe1efc5f268337253ee8f296ff19c8195bd3fb7ff6b3e41d70eced7b0f471fed1f0e7abcebe5fb5e0ecdd01d5"
    "af275f60f6395fc7265076d59f5a3067bb35f7f9b5919e5834f4063ebac22f5d8f4e3771bbc1e4a5e4f0abc597f5c796"
    "fee1fb9746ce8f43a118edf3464d4d70c5eb634e6d477bf97afee6e3a91bc3c7bbfa711e4fcdc07765b1d83ad1c670f3"
    "e147e3535e05fabb9b9be0dfb4fc30e6c9edcf0805951dee67f77f9b37fdeac709a56eeddebc3669fdbb36cb74eac9d9"
    "b930b391d36593942f7ad926f15eea1fde10936f0c03d3e09a901672f7c39bbf9057e1f1e00dfd7cf5cb7d03a5cbacf7"
    "aff2bd21a0be78e3bc8f68f2e0df87bfbcb34fee7ea2f58adc8ff9fd179ddbda41b0d5b346966bfc3f2d5f9bc7a3393a"
    "934e64e8b6feda3777d0ea7bfef1cf268df34db0b76ced1e877cc9b7c9280db7faefa376dc6f57a1cedba81e893737b7"
    "88f93d2f1dfa01a77b37fb1db4c3d524cbbbf33dea76e5e66ce6c38f1a28f1d3b83617cc9a3333b7a5afde0593669af3"
    "ccf2d52fa7bae4bd9c6df8c38d1c3bb79edfde7f91f86b679ce27efa677a3d375e7b1b5e3f73ea5696df697e94085486"
    "d9941004e2807ee36e5c65b53168dfc4";

static void test_captured(void)
{
    printf("\nThe answer a node actually sent\n");

    uint8_t bytes[2048];
    size_t  n = (sizeof captured_response - 1u) / 2u;
    ok(n <= sizeof bytes, "the capture fits the buffer this client reads into");
    for (size_t i = 0; i < n && i < sizeof bytes; i++) {
        unsigned v = 0;
        if (sscanf(captured_response + 2u * i, "%2x", &v) != 1)
            break;
        bytes[i] = (uint8_t)v;
    }

    lc_h3_auth_result got;
    ok(lc_h3_auth_response(bytes, n, &got) == 1, "it parses as a complete answer");
    ok(got.status == 233, "the status is 233, and is still 233 at the end of the field section");
    ok(got.udp_enabled, "the node will relay datagrams");
    ok(strcmp(got.cc_rx, "0") == 0, "and states no receive rate of its own");

    /* THE FIELD SECTION PREFIX, ON THE ONE CAPTURE WHERE ITS REAL VALUE IS KNOWN.
     *
     * The capture opens `01 44ed 00 00`: HEADERS, a length, and then the two prefix octets —
     * Required Insert Count and Delta Base, both zero because we grant no dynamic table. The parser
     * used to skip those two without looking, so a node that sent anything else there shifted every
     * field line after it and the section was decoded from the wrong offset: at best refused as
     * malformed, at worst yielding a `:status` nobody sent.
     *
     * Tested by corrupting exactly those two bytes of a message that is otherwise known-good, so a
     * refusal can only be about the prefix. The reference refuses the same section for the same
     * reason (vendor/nghttp3/lib/nghttp3_qpack.c:3909-3925, a Required Insert Count above a zero
     * capacity is NGHTTP3_ERR_QPACK_DECOMPRESSION_FAILED). */
    lc_h3_auth_result tampered;
    uint8_t           ricnt = bytes[3], dbase = bytes[4];
    ok(ricnt == 0x00u && dbase == 0x00u, "the captured prefix is two zero octets, as it must be");

    bytes[3] = 0x01u;
    ok(lc_h3_auth_response(bytes, n, &tampered) < 0,
       "a non-zero Required Insert Count is refused, not skipped over");
    bytes[3] = ricnt;

    bytes[4] = 0x01u;
    ok(lc_h3_auth_response(bytes, n, &tampered) < 0,
       "and so is a non-zero Delta Base");
    bytes[4] = dbase;

    ok(lc_h3_auth_response(bytes, n, &tampered) == 1 && tampered.status == 233,
       "and the message reads as before once the two bytes are put back");

    printf("\nThe statuses a masquerade actually answers with\n");

    /* :status lives in TWO runs of the QPACK static table — 24..28 and 63..71
     * (vendor/nghttp3/lib/nghttp3_qpack.c:216-220 and :283-291) — and only the first was recognised,
     * so a node whose masquerade returns 403 or 500 was reported as "HTTP status 0".
     *
     * Encoded by hand because the point is the INDEX. An indexed field line is `1Txxxxxx` with a
     * six-bit prefix, T=1 for the static table, so index 68 does not fit in the prefix: it is 0xFF
     * (0xC0 | 0x3F) followed by the varint 68-63 = 5. The finding that raised this called it "a
     * single byte 0xC4", which is index 4 — worth writing out here so the next reader checks the
     * encoding rather than the sentence. */
    static const struct {
        uint8_t     idx_hi, idx_lo;
        int         want;
        const char *what;
    } indexed[] = {
        { 0xC0u | 25u, 0x00u, 200, "200, from the run that already worked" },
        { 0xFFu, 68u - 63u, 403, "403, which a reverse-proxy masquerade returns for a bad password" },
        { 0xFFu, 71u - 63u, 500, "500, which it returns when the site behind it is down" },
        { 0xFFu, 63u - 63u, 100, "100, the first of the second run" },
    };

    for (unsigned k = 0; k < sizeof indexed / sizeof indexed[0]; k++) {
        uint8_t frame[8];
        size_t  m = 0;
        int     two = indexed[k].idx_hi == 0xFFu;
        frame[m++] = 0x01u;                       /* HEADERS */
        frame[m++] = (uint8_t)(2u + (two ? 2u : 1u)); /* length: prefix + the field line */
        frame[m++] = 0x00u;                       /* Required Insert Count */
        frame[m++] = 0x00u;                       /* Delta Base */
        frame[m++] = indexed[k].idx_hi;
        if (two)
            frame[m++] = indexed[k].idx_lo;

        lc_h3_auth_result r;
        ok(lc_h3_auth_response(frame, m, &r) == 1 && r.status == indexed[k].want, indexed[k].what);
    }
}

/* The authentication request byte for byte against the encoder quic-go writes it with — qpack
 * v0.6.0, run by tools/qpackvec over the same password, rate, padding and header order. Decoding it
 * with nghttp3, as test_request does, says what the fields MEAN; only this says what the node reads:
 * the static-table references for content-length, accept-encoding and user-agent, and Huffman on
 * every string whether or not it is shorter. */
static void test_request_bytes(void)
{
    printf("\nthe authentication request against qpack's own encoding\n");
    int all = 1;
    for (size_t i = 0; i < sizeof qpack_auth / sizeof qpack_auth[0]; i++) {
        char    pad[LC_PAD_AUTH_MAX];
        uint8_t req[LC_H3_AUTH_REQ_MAX];
        for (unsigned k = 0; k < qpack_auth[i].pad_len; k++)
            pad[k] = qpack_pad_alphabet[(k * 7u + 3u) % (sizeof qpack_pad_alphabet - 1u)];
        long n = lc_h3_auth_request_with("hysteria", qpack_auth[i].password, qpack_auth[i].rx, pad,
                                         qpack_auth[i].pad_len, qpack_auth[i].order, req, sizeof req);
        size_t f = qpack_auth[i].len;
        int    same = n == (long)(3u + f) && req[0] == 0x01u && req[1] == (uint8_t)(0x40u | f >> 8) &&
                   req[2] == (uint8_t)f && memcmp(req + 3, qpack_auth[i].bytes, f) == 0;
        if (!same) {
            all = 0;
            printf("        case %zu differs (ours %ld bytes, qpack %zu + 3)\n", i, n, f);
        }
    }
    ok(all, "every case is the bytes qpack writes, frame header included");
}

int main(void)
{
    test_huffman();
    test_request_bytes();
    test_request();
    test_header_order();
    test_response();
    test_captured();

    printf("\n%s\n", failures == 0 ? "the request is what it claims to be, and the answer is read"
                                   : "the HTTP/3 layer is WRONG");
    return failures == 0 ? 0 : 1;
}
