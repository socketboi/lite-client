/* The acceptance rule for the fingerprint, run by the gate instead of by hand.
 *
 * src/fp/hello.h states it outright: "the output is compared byte for byte against uTLS by
 * tools/fp, and nothing here is considered done until that comparison is clean". That comparison
 * was real and it was not in the gate. `fp diff` is a Go program needing uTLS and a network to
 * build, and the copy in the tree is a prebuilt Windows binary — so the check that decides whether
 * this client is identifiable on the wire was one somebody had to remember to run.
 *
 * What test/hello checks is a different thing and both are wanted: it builds a table in-test and
 * asserts the RULES a fingerprint must satisfy — GREASE drawn from the sixteen legal values, the
 * two extension types distinct, the group agreeing between supported_groups and key_share. Rules
 * hold for a table nobody ships. This file asserts the OUTPUT for the table that is shipped.
 *
 * The vector is uTLS's own message, frozen: see reference_firefox.h for the command and for which
 * revision produced it. The table read here is package/files/fingerprint.fpt — the file installed
 * on a router — so a table that drifts from the uTLS it was cut from fails here rather than in a
 * traffic analysis somebody else runs.
 *
 * FOUR THINGS DIFFER ON EVERY CONNECTION AND ARE SKIPPED, which is the whole of what `fp diff`
 * ignores as well: the client random, the session id (REALITY overwrites it, and a fingerprint's
 * own value is not what goes out), the key share public keys, and the GREASE values. Everything
 * else — every extension, its order, every list and every length — is compared byte for byte. */

#include "fp/hello.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "reference_firefox.h"
#include "tls/certcomp.h"

static int failures;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

/* The sixteen values RFC 8701 reserves. Both bytes equal, low nibble 0x0a. */
static int is_grease(const uint8_t *p)
{
    return p[0] == p[1] && (p[0] & 0x0fu) == 0x0au;
}

/* Where the client random sits: four bytes of handshake header, two of legacy_version. */
#define RANDOM_OFF 6u
#define RANDOM_LEN 32u

/* GREASE ECH, whose body is fresh randomness on every connection.
 *
 * The fifth thing that legitimately differs, and the one this test got wrong first: uTLS fills a
 * GREASE encrypted_client_hello with a random config id, a random key and a random payload of a
 * length the extension itself declares (u_parrots.go builds it per hello). `fp diff` counts that as
 * GREASE, which is why its verdict said "differ only in random, session_id, key_share and GREASE"
 * about a message whose last three hundred bytes are unequal. Skipping the extension BODY and not
 * the extension — its type, its length and its position in the order are all still compared. */
#define EXT_ECH 0xfe0du

/* The walk to the extensions block, which both callers below need and neither should own.
 * Returns 0 when the message does not walk cleanly — a failure of this test, not of the client. */
static int walk_to_extensions(const uint8_t *msg, size_t len, size_t *ext_len_at, size_t *ext_end)
{
    size_t off = 4u + 2u + 32u; /* handshake header, legacy_version, random */
    if (off >= len)
        return 0;
    off += 1u + msg[off]; /* session_id */
    if (off + 2u > len)
        return 0;
    off += 2u + ((size_t)msg[off] << 8 | msg[off + 1]); /* cipher_suites */
    if (off >= len)
        return 0;
    off += 1u + msg[off]; /* compression_methods */
    if (off + 2u > len)
        return 0;

    *ext_len_at = off;
    *ext_end = off + 2u + ((size_t)msg[off] << 8 | msg[off + 1]);
    return *ext_end <= len;
}

/* Marks the body of every ECH extension in `msg` as skippable. Returns 0 if the message does not
 * walk cleanly, which is a failure of this test rather than of the client. */
static int skip_ech_bodies(const uint8_t *msg, size_t len, uint8_t *skip)
{
    size_t ext_len_at = 0, ext_end = 0;
    if (!walk_to_extensions(msg, len, &ext_len_at, &ext_end))
        return 0;
    size_t off = ext_len_at + 2u;

    while (off + 4u <= ext_end) {
        unsigned type = (unsigned)msg[off] << 8 | msg[off + 1];
        size_t   blen = (size_t)msg[off + 2] << 8 | msg[off + 3];
        off += 4u;
        if (off + blen > ext_end)
            return 0;
        if (type == EXT_ECH)
            memset(skip + off, 1, blen);
        off += blen;
    }
    return off == ext_end;
}

/* The extension types in the order they go out, with GREASE folded onto the one value it is stored
 * as. Folding is what makes the list comparable at all: a GREASE type is redrawn every hello, so
 * two hellos from the same table differ there by construction and that is not the question being
 * asked. Returns the count, or 0 when the message does not walk cleanly. */
#define MAX_TYPES 64u

/* The length of the GREASE-ECH payload a hello carries, or 0 if it carries none or does not walk. */
static size_t ech_payload_len(const uint8_t *msg, size_t len)
{
    size_t ext_len_at = 0, ext_end = 0;
    if (!walk_to_extensions(msg, len, &ext_len_at, &ext_end))
        return 0;
    size_t off = ext_len_at + 2u;
    while (off + 4u <= ext_end) {
        unsigned type = (unsigned)msg[off] << 8 | msg[off + 1];
        size_t   blen = (size_t)msg[off + 2] << 8 | msg[off + 3];
        size_t   b = off + 4u;
        if (b + blen > ext_end)
            return 0;
        if (type == 0xfe0du && blen >= 8u) {
            size_t enc = (size_t)msg[b + 6u] << 8 | msg[b + 7u];
            if (8u + enc + 2u > blen)
                return 0;
            return (size_t)msg[b + 8u + enc] << 8 | msg[b + 9u + enc];
        }
        off = b + blen;
    }
    return 0;
}

static unsigned ext_types(const uint8_t *msg, size_t len, unsigned *out)
{
    size_t ext_len_at = 0, ext_end = 0;
    if (!walk_to_extensions(msg, len, &ext_len_at, &ext_end))
        return 0;
    size_t   off = ext_len_at + 2u;
    unsigned n = 0;

    while (off + 4u <= ext_end) {
        unsigned type = is_grease(msg + off) ? 0x0a0au : (unsigned)msg[off] << 8 | msg[off + 1];
        size_t   blen = (size_t)msg[off + 2] << 8 | msg[off + 3];
        off += 4u + blen;
        if (off > ext_end || n == MAX_TYPES)
            return 0;
        out[n++] = type;
    }
    return off == ext_end ? n : 0;
}

static int by_value(const void *a, const void *b)
{
    unsigned x = *(const unsigned *)a, y = *(const unsigned *)b;
    return x < y ? -1 : (x > y ? 1 : 0);
}

int main(void)
{
    printf("fingerprint: the shipped table against uTLS\n");

    FILE *t = fopen("package/files/fingerprint.fpt", "rb");
    if (t == NULL) {
        printf("  FAIL  cannot open package/files/fingerprint.fpt\n");
        return 1;
    }
    static uint8_t table[65536];
    size_t         table_len = fread(table, 1, sizeof table, t);
    fclose(t);
    ok(table_len > 0, "the shipped table reads");

    static uint8_t ours[16384];
    lc_hello_out   info;
    lc_hello_err   e = lc_hello_build(table, table_len, "fp.example", ours, sizeof ours, &info);
    ok(e == LC_HELLO_OK, "and builds a hello");
    ok(e == LC_HELLO_OK && info.key_share_reuse == 1,
       "and the Firefox table asks for its X25519 key to be the hybrid's, as its parrot marks");
    if (e != LC_HELLO_OK) {
        printf("\n%d failed\n", failures + 1);
        return 1;
    }

    /* THE REFERENCE IS NO LONGER TRANSFORMED BEFORE THE COMPARISON, AND THAT IS THE POINT.
     *
     * Sixty lines here used to trim compress_certificate out of uTLS's hello and fix up the three
     * lengths enclosing it, back when the client advertised one algorithm where Firefox advertises
     * three — the one deliberate difference, written down rather than excused. With brotli and zstd
     * built in there is no difference left to excuse: the shipped hello is the capture, byte for
     * byte, so the comparison runs against the reference exactly as uTLS emits it. */
    const uint8_t *expected = reference_firefox;
    size_t         expected_len = sizeof reference_firefox;

    /* The length first, because every later comparison is offset by it and a length difference
     * reported as a thousand byte differences tells nobody anything. */
    ok(info.len == expected_len, "the message is exactly as long as uTLS's");
    if (info.len != expected_len) {
        printf("        ours %zu, uTLS %zu\n", info.len, expected_len);
        printf("\n%d failed\n", failures);
        return 1;
    }

    /* REALITY needs a thirty-two byte session id to write into, and the fingerprint is what decides
     * the width. A table whose session id is shorter cannot carry the authentication payload at
     * all — see reality.h — so this is asserted here rather than discovered at a node. */
    ok(info.sid_len == 32u, "and leaves a thirty-two byte session id for REALITY");

    /* A map of what may differ, built from the reference: a byte is skipped when it belongs to the
     * random, to the session id, to a key share public key, or to a GREASE value. GREASE is located
     * in the REFERENCE and then required of ours at the same place — so a client that sent a fixed
     * value where uTLS draws one still fails. */
    static uint8_t skip[16384];
    memset(skip, 0, sizeof skip);
    memset(skip + RANDOM_OFF, 1, RANDOM_LEN);
    memset(skip + info.sid_off, 1, info.sid_len);
    for (unsigned s = 0; s < info.slot_count; s++)
        memset(skip + info.slots[s].off, 1, info.slots[s].len);
    ok(skip_ech_bodies(expected, expected_len, skip),
       "the reference walks as a ClientHello, so the ECH body can be located");

    unsigned grease_seen = 0;
    for (size_t i = 0; i + 1 < info.len; i++) {
        if (skip[i] || !is_grease(expected + i))
            continue;
        /* Ours has to be GREASE here too — any of the sixteen, not this one. */
        if (!is_grease(ours + i)) {
            printf("  FAIL  offset %zu: uTLS drew GREASE, we sent %02x%02x\n", i, ours[i],
                   ours[i + 1]);
            failures++;
        }
        grease_seen++;
        skip[i] = skip[i + 1] = 1;
        i++;
    }
    /* Firefox offers no GREASE at all and Chrome offers several; asserting only "we matched
     * wherever uTLS had it" would pass a table with none. The count is stated so that a table
     * losing its GREASE is a visible change here rather than a silent one. */
    printf("  note  GREASE positions in the reference: %u\n", grease_seen);

    size_t differ = 0, first = 0;
    for (size_t i = 0; i < info.len; i++) {
        if (skip[i] || ours[i] == expected[i])
            continue;
        if (differ == 0)
            first = i;
        differ++;
    }
    ok(differ == 0, "and is byte for byte uTLS's, outside random, session id, key share and GREASE");
    if (differ != 0)
        printf("        %zu bytes differ, the first at offset %zu: ours %02x, uTLS %02x\n", differ,
               first, ours[first], expected[first]);

    /* ---- A TABLE THAT IS NOT THIS ONE, WHICH IS THE HOLE THIS FILE HAD ----
     *
     * Everything above reads ONE table, the shipped Firefox capture, so every assertion about the
     * emitter was an assertion about that profile. The compress_certificate check was written as an
     * equality against this client's own list and passed here for exactly that reason — while
     * refusing every Chrome table outright, because uTLS gives Chrome one algorithm (brotli,
     * u_parrots.go:162) where it gives Firefox 148 three (:1572-1576). The symptom in the field was
     * `the fingerprint table does not build a hello` on a device whose REALITY plane had worked the
     * day before.
     *
     * chrome.fpt is that profile's table. It used to be a fixture taken off the router and edited by
     * hand at every format bump, because a Chrome capture shuffles and could not be regenerated to
     * the same bytes. It can now: tools/fp stores Chrome in its parrot's literal order and folds
     * inline GREASE, so `make` cuts it from the pinned uTLS and check-fingerprint compares it byte
     * for byte, exactly as for Firefox.
     *
     * What is asserted is the rule that replaced the equality — the list is the PROFILE'S, and the
     * client's job is to be able to open it. So: the hello builds, and it carries Chrome's own
     * three-byte body rather than ours. */
    {
        FILE *c = fopen("test/fphello/chrome.fpt", "rb");
        ok(c != NULL, "the Chrome table reads");
        if (c != NULL) {
            static uint8_t ctable[65536];
            size_t         clen = fread(ctable, 1, sizeof ctable, c);
            fclose(c);

            static uint8_t chello[16384];
            lc_hello_out   cinfo;
            lc_hello_err   ce =
                lc_hello_build(ctable, clen, "fp.example", chello, sizeof chello, &cinfo);
            ok(ce == LC_HELLO_OK, "and a profile advertising ONE algorithm still builds a hello");

            if (ce == LC_HELLO_OK) {
                /* 00 1b | 00 03 | 02 00 02 — extension 27, three-byte body, brotli alone. */
                static const uint8_t want[] = { 0x00u, 0x1bu, 0x00u, 0x03u,
                                                0x02u, 0x00u, 0x02u };
                int                  found = 0;
                for (size_t i = 0; i + sizeof want <= cinfo.len; i++)
                    if (memcmp(chello + i, want, sizeof want) == 0)
                        found = 1;
                ok(found, "and puts THAT profile's list on the wire, not this client's");
            }

            /* ---- AND THE ORDER IS DRAWN, NOT REPLAYED ----
             *
             * uTLS wraps every Chrome parrot from 106 on in ShuffleChromeTLSExtensions
             * (u_parrots.go:552-917) and Xray's "chrome" is HelloChrome_133, so the reference sends
             * a different extension order on every connection. This client replayed the captured
             * one, which is invisible in any single hello and a mark across two.
             *
             * Sixteen builds, because one proves nothing about a draw. What is asserted is all four
             * halves of the rule, since three of them can hold while the fourth is broken:
             * the order MOVES, the SET does not, the invariant extensions do not move, and the
             * shipped Firefox profile does not shuffle at all. Sixteen identical draws of fifteen
             * movable extensions is one chance in 15! per build — this test does not flake. */
            {
                enum { RUNS = 16u };
                static unsigned types[RUNS][MAX_TYPES];
                unsigned        n0 = 0;
                int             built = 1, varied = 0, same_set = 1, pinned = 1;

                for (unsigned r = 0; r < RUNS; r++) {
                    static uint8_t h[16384];
                    lc_hello_out   in;
                    if (lc_hello_build(ctable, clen, "fp.example", h, sizeof h, &in) !=
                        LC_HELLO_OK) {
                        built = 0;
                        break;
                    }
                    unsigned n = ext_types(h, in.len, types[r]);
                    if (n == 0) {
                        built = 0;
                        break;
                    }
                    if (r == 0) {
                        n0 = n;
                        continue;
                    }
                    if (n != n0) {
                        same_set = 0;
                        break;
                    }
                    if (memcmp(types[r], types[0], n * sizeof types[0][0]) != 0)
                        varied = 1;

                    /* GREASE, padding and pre_shared_key are positionally invariant in the
                     * reference's own shuffle (u_parrots.go:2947-2955), so wherever the capture put
                     * them is where every hello must keep them. Chrome's table carries the first
                     * two; the check is written over all three so a table that gains a PSK is
                     * covered by the assertion that already exists. */
                    for (unsigned k = 0; k < n; k++) {
                        int inv = types[0][k] == 0x0a0au || types[0][k] == 0x0015u ||
                                  types[0][k] == 0x0029u;
                        if (inv && types[r][k] != types[0][k])
                            pinned = 0;
                    }

                    unsigned a[MAX_TYPES], c2[MAX_TYPES];
                    memcpy(a, types[0], n * sizeof a[0]);
                    memcpy(c2, types[r], n * sizeof c2[0]);
                    qsort(a, n, sizeof a[0], by_value);
                    qsort(c2, n, sizeof c2[0], by_value);
                    if (memcmp(a, c2, n * sizeof a[0]) != 0)
                        same_set = 0;
                }

                ok(built, "sixteen hellos build from the Chrome table");
                ok(built && varied,
                   "and they do NOT all carry the same extension order, as Chrome does not");
                ok(built && same_set,
                   "while the set of extensions is the same every time — a shuffle, not a rewrite");
                ok(built && pinned,
                   "and GREASE, padding and pre_shared_key stay where the table put them");
            }

            /* ---- AND THE LAW OF THE SHUFFLE IS THE REFERENCE'S, WHICH NEEDS ITS STARTING ORDER ----
             *
             * The swap loop declines swaps that touch a fixed slot, so it is not uniform: the
             * extension that STARTS in the first movable slot stays there with probability 2/17,
             * not 1/16. uTLS starts from the literal list in its spec, where that extension is
             * server_name (vendor/utls/u_parrots.go:917-919); a table cut from a capture started from
             * whatever that capture drew, and put server_name first about 5.9% of the time. Counted
             * over enough hellos to separate 11.8% from 5.9% by many standard deviations. */
            {
                enum { DRAWS = 3400u };
                unsigned sni_first = 0, built_n = 0;
                for (unsigned r = 0; r < DRAWS; r++) {
                    static uint8_t h[16384];
                    lc_hello_out   in;
                    unsigned       types[MAX_TYPES];
                    if (lc_hello_build(ctable, clen, "fp.example", h, sizeof h, &in) != LC_HELLO_OK)
                        break;
                    if (ext_types(h, in.len, types) < 2u)
                        break;
                    built_n++;
                    if (types[1] == 0x0000u)
                        sni_first++;
                }
                unsigned pct10 = built_n ? sni_first * 1000u / built_n : 0u;
                ok(built_n == DRAWS && pct10 >= 95u && pct10 <= 145u,
                   "server_name lands first about 2/17 of the time, as it does from uTLS's own list");
                if (!(pct10 >= 95u && pct10 <= 145u))
                    printf("        %u of %u (%u.%u%%)\n", sni_first, built_n, pct10 / 10u, pct10 % 10u);
            }

            /* ---- AND THE GREASE-ECH PAYLOAD LENGTH IS DRAWN FROM THE PARROT'S FOUR ----
             *
             * CandidatePayloadLens 128, 160, 192, 224 plus the 16-byte tag (vendor/utls/u_ech.go:328,
             * u_hpke.go:29-36), one drawn per hello (u_ech.go:160-166). The table used to carry the
             * one length its capture showed. Sixty-four hellos: every length must be one of the four,
             * and at least three of them must appear — fewer is a chance of about 6 in 2^64. */
            {
                unsigned seen[4] = { 0 }, other = 0, got = 0;
                for (unsigned r = 0; r < 64u; r++) {
                    static uint8_t h[16384];
                    lc_hello_out   in;
                    if (lc_hello_build(ctable, clen, "fp.example", h, sizeof h, &in) != LC_HELLO_OK)
                        break;
                    size_t pl = ech_payload_len(h, in.len);
                    if (pl == 0u)
                        break;
                    got++;
                    if (pl == 144u)
                        seen[0]++;
                    else if (pl == 176u)
                        seen[1]++;
                    else if (pl == 208u)
                        seen[2]++;
                    else if (pl == 240u)
                        seen[3]++;
                    else
                        other++;
                }
                unsigned kinds = 0;
                for (unsigned k = 0; k < 4u; k++)
                    kinds += seen[k] > 0u ? 1u : 0u;
                ok(got == 64u && other == 0u,
                   "every Chrome GREASE-ECH payload is 144, 176, 208 or 240 bytes");
                ok(got == 64u && kinds >= 3u, "and the length varies between hellos, as the parrot draws it");
                ok(cinfo.key_share_reuse == 0, "and the Chrome table does not ask for its X25519 key to be reused");
            }
        }
    }

    /* ---- THE CONTROL: THE PROFILE THAT SHIPS DOES NOT SHUFFLE ----
     *
     * Firefox does not permute — uTLS wraps no Firefox parrot (u_parrots.go:967-1591) — so the
     * table on every router must come out in the same order every time. The byte-for-byte
     * comparison above would also fail if this broke, but only by accident of running once: it
     * compares ONE build against the frozen vector, and "shuffle everything" would fail it about
     * fourteen times in fifteen rather than always. This asks the question directly. */
    {
        unsigned ff_first[MAX_TYPES];
        unsigned n0 = 0;
        int      built = 1, stable = 1;

        for (unsigned r = 0; r < 8u; r++) {
            static uint8_t h[16384];
            lc_hello_out   in;
            unsigned       ff[MAX_TYPES];
            if (lc_hello_build(table, table_len, "fp.example", h, sizeof h, &in) != LC_HELLO_OK) {
                built = 0;
                break;
            }
            unsigned n = ext_types(h, in.len, ff);
            if (n == 0) {
                built = 0;
                break;
            }
            if (r == 0) {
                n0 = n;
                memcpy(ff_first, ff, n * sizeof ff[0]);
            } else if (n != n0 || memcmp(ff_first, ff, n * sizeof ff[0]) != 0) {
                stable = 0;
            }
        }
        ok(built, "eight hellos build from the shipped Firefox table");
        ok(built && stable, "and every one has the SAME extension order, because Firefox replays");
    }

    printf(failures == 0 ? "\nall good\n" : "\n%d failed\n", failures);
    return failures == 0 ? 0 : 1;
}
