/* The GREASE rules, which no other test could have caught.
 *
 * Both rules are invisible to the acceptance comparator, because that tool ignores GREASE values on
 * purpose — a hello with the wrong ones is byte-identical to a right one as far as it is concerned.
 * They are equally invisible on the wire: a server refuses the connection and says nothing, the
 * handshake completes against the donor site, and the client reports success. So they are checked
 * here, against the rules themselves, by building the same hello many times and looking at what
 * varies.
 *
 *   extension types must DIFFER from each other. Two draws from sixteen values collide one time in
 *                     sixteen, and a duplicated extension type is refused by every TLS parser. This
 *                     cost roughly one connection in fourteen for weeks.
 *   the group         must be the SAME in supported_groups and key_share, or the client offers a
 *                     key share for a group it never proposed.
 *
 * The table is built here rather than loaded, so the test needs no network, no generated fixture
 * and no fingerprint capture — only the two shapes the rules are about. */

#include "fp/hello.h"

/* For the two suites the GREASE-ECH extension is drawn from — the assertion at the end is about
 * which of them turns up, so it has to name them the same way the builder does. */
#include "fp/fpt.h"

#include <stdio.h>
#include <string.h>

static int failures;

/* The two HPKE suites the SHIPPED firefox table lists as GREASE-ECH candidates.
 *
 * They live here and no longer in src/fp: the client used to carry them as constants and draw
 * between them, which is why this suite could name them by symbol. It reads the list out of the
 * table now, so the values are no longer the client's to know — and a test that imported them
 * from the code it checks would be asserting the code against itself.
 *
 * What is pinned below is therefore the OBSERVABLE half: every hello carries one of the two, both
 * appear across four hundred draws, and nothing else ever does. If the table is ever regenerated
 * from a parrot with a different list, these two numbers are what has to change with it — and the
 * failure will say so plainly rather than passing on a client that stopped drawing at all. */
#define TEST_ECH_AEAD_AES_128_GCM       0x0001u
#define TEST_ECH_AEAD_CHACHA20_POLY1305 0x0003u

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

/* A table with two GREASE extensions around one real one. Written by hand against the format in
 * tools/fp/pack.go, which is the only other thing that speaks it. */
static size_t build_table(uint8_t *t)
{
    size_t n = 0;
    memcpy(t + n, "LCFP", 4);
    n += 4;
    /* Version 4, which is what src/fp/fpt.c demands — and this table is the reason the number is
     * written out here rather than taken from the code. The thing under test is the READER, and a
     * reader that accepted a table it cannot interpret is precisely the failure each bump was made
     * to stop. */
    t[n++] = 4;

    /* requires: literal and sni, no key share groups */
    t[n++] = 0;
    t[n++] = 0;
    t[n++] = 0;
    t[n++] = 1u << 1 | 1u << 2;
    t[n++] = 0; /* group count */

    t[n++] = 1; /* name length */
    t[n++] = 't';
    t[n++] = 0; /* flags: no key share reuse (there is no key share) */

    t[n++] = 0x03; /* legacy_version */
    t[n++] = 0x03;
    t[n++] = 32; /* session_id length */

    t[n++] = 0; /* cipher count */
    t[n++] = 1;
    t[n++] = 0x13;
    t[n++] = 0x01;

    t[n++] = 1; /* compression methods */
    t[n++] = 0;

    t[n++] = 0; /* extension count */
    t[n++] = 3;

    /* GREASE, empty literal */
    t[n++] = 0x0a;
    t[n++] = 0x0a;
    t[n++] = 1; /* literal */
    t[n++] = 0;
    t[n++] = 0; /* zero bytes of data */
    t[n++] = 0; /* no inline GREASE */

    /* server_name */
    t[n++] = 0;
    t[n++] = 0;
    t[n++] = 2; /* sni */

    /* GREASE again */
    t[n++] = 0x0a;
    t[n++] = 0x0a;
    t[n++] = 1;
    t[n++] = 0;
    t[n++] = 0;
    t[n++] = 0;

    return n;
}

/* Reads the extension types out of a built hello. */
static unsigned ext_types(const uint8_t *h, size_t len, uint16_t *out, unsigned cap)
{
    size_t p = 4u + 2u + 32u; /* handshake header, legacy version, random */
    if (p >= len)
        return 0;
    p += 1u + h[p]; /* session id */
    if (p + 2u > len)
        return 0;
    p += 2u + ((size_t)h[p] << 8 | h[p + 1]); /* cipher suites */
    if (p >= len)
        return 0;
    p += 1u + h[p]; /* compression methods */
    if (p + 2u > len)
        return 0;
    size_t ext_end = p + 2u + ((size_t)h[p] << 8 | h[p + 1]);
    p += 2u;

    unsigned count = 0;
    while (p + 4u <= ext_end && p + 4u <= len && count < cap) {
        out[count++] = (uint16_t)((uint16_t)h[p] << 8 | h[p + 1]);
        p += 4u + ((size_t)h[p + 2] << 8 | h[p + 3]);
    }
    return count;
}

int main(void)
{
    static uint8_t table[256];
    size_t         table_len = build_table(table);

    printf("\nGREASE rules\n");

    /* Enough rounds that a one-in-sixteen collision would appear many times over: the chance of
     * missing it across this many builds is smaller than one in a million. */
    const unsigned rounds = 400;
    unsigned       built = 0, collisions = 0, both_grease = 0;

    for (unsigned i = 0; i < rounds; i++) {
        uint8_t      hello[4096];
        lc_hello_out info;
        if (lc_hello_build(table, table_len, "example.com", hello, sizeof hello, &info) != LC_HELLO_OK)
            continue;
        built++;

        uint16_t types[16];
        unsigned n = ext_types(hello, info.len, types, 16);
        if (n != 3)
            continue;

        /* The first and last are the GREASE slots; the middle one is server_name. */
        if ((types[0] & 0x0f0fu) == 0x0a0au && (types[2] & 0x0f0fu) == 0x0a0au)
            both_grease++;
        if (types[0] == types[2])
            collisions++;
    }

    char msg[96];
    snprintf(msg, sizeof msg, "%u hellos built from the table", built);
    ok(built == rounds, msg);

    snprintf(msg, sizeof msg, "both GREASE slots carry a GREASE value in all %u", both_grease);
    ok(both_grease == rounds, msg);

    snprintf(msg, sizeof msg, "no two GREASE extension types collide (%u collisions)", collisions);
    ok(collisions == 0, msg);

    /* ---- the GREASE-ECH cipher suite, against the table that actually ships ------------------ */
    printf("\nthe GREASE-ECH suite, from package/files/fingerprint.fpt\n");

    /* Read from the file rather than hand-built, and that is two checks in one: this is the table
     * the package installs and the REALITY plane is started with, and nothing anywhere had ever
     * asked whether it parses.
     *
     * What is asserted is a DISTRIBUTION, which is unusual here and is the point. uTLS picks this
     * extension's cipher suite at random per ClientHello out of two candidates (u_ech.go:47-48,
     * u_parrots.go:1455); this client used to copy whichever one the capture behind the table had
     * happened to draw, and send it for ever. A constant is not a wrong value that shows up in a
     * log — it is a client whose first packet says the same thing every time where a browser says
     * one of two, and it is in the clear. */
    uint8_t real_table[4096];
    size_t  real_len = 0;
    FILE   *tf = fopen("package/files/fingerprint.fpt", "rb");
    if (tf != NULL) {
        real_len = fread(real_table, 1, sizeof real_table, tf);
        fclose(tf);
    }
    ok(real_len > 0, "the table the package ships is there and readable");

    unsigned saw_aes = 0, saw_chacha = 0, saw_other = 0, ech_seen = 0;
    unsigned ech_high_bit = 0, ech_bad_shape = 0;
    for (unsigned i = 0; real_len > 0 && i < rounds; i++) {
        uint8_t      hello[4096];
        lc_hello_out info;
        if (lc_hello_build(real_table, real_len, "example.com", hello, sizeof hello, &info) !=
            LC_HELLO_OK)
            continue;

        /* Walk the extension block for 0xfe0d and read the suite out of its body: one byte of
         * ECHClientHello type, then the KDF and the AEAD. */
        /* WALKED, NOT SCANNED FOR.
         *
         * The first version of this looked for the two bytes 0xfe 0x0d anywhere in the message, and
         * failed about once in four hundred — because a ClientHello is mostly random bytes (GREASE
         * payloads, key shares, session id) and any given pair turns up by chance across nineteen
         * hundred positions often enough to matter. The failure looked exactly like the defect this
         * test was written for: a suite "uTLS would not have picked". A scan through random data is
         * not a parser, and a test that cannot tell its own false positive from the fault it hunts
         * is worse than no test. */
        size_t p = 4u + 2u + 32u;              /* handshake header, legacy_version, random */
        p += 1u + (size_t)hello[p];            /* session_id */
        if (p + 2u > info.len)
            continue;
        p += 2u + ((size_t)hello[p] << 8 | hello[p + 1]); /* cipher_suites */
        if (p >= info.len)
            continue;
        p += 1u + (size_t)hello[p];            /* compression_methods */
        if (p + 2u > info.len)
            continue;
        size_t ext_end = p + 2u + ((size_t)hello[p] << 8 | hello[p + 1]);
        p += 2u;
        if (ext_end > info.len)
            continue;

        while (p + 4u <= ext_end) {
            uint16_t type = (uint16_t)((uint16_t)hello[p] << 8 | hello[p + 1]);
            size_t   len = (size_t)hello[p + 2] << 8 | hello[p + 3];
            size_t   body = p + 4u;
            if (body + len > ext_end)
                break;
            if (type == 0xfe0du && len >= 5u) {
                uint16_t aead = (uint16_t)((uint16_t)hello[body + 3] << 8 | hello[body + 4]);
                ech_seen++;
                /* And the encapsulated key, whose TOP BIT IS NOT FREE.
                 *
                 * The body is: type(1) kdf(2) aead(2) config_id(1) enc_len(2) enc(enc_len). uTLS
                 * fills enc by running HPKE's sender half (vendor/utls/u_ech.go:150 into
                 * GOROOT/src/crypto/hpke/kem.go:235-252, go1.27.3), so it is an X25519 public key: a
                 * u-coordinate reduced mod 2^255-19, whose most significant bit is therefore always
                 * zero. Filled from the CSPRNG instead, as this client did, that bit is set half the
                 * time — one test at a fixed offset in the last extension of the first packet, and
                 * half of all connections are flagged on sight.
                 *
                 * Asserted over every round rather than once, because half of a small sample can
                 * pass by luck. */
                if (len >= 8u) {
                    size_t enc_len = (size_t)hello[body + 6] << 8 | hello[body + 7];
                    if (enc_len == 32u && body + 8u + enc_len <= ext_end) {
                        if ((hello[body + 8u + 31u] & 0x80u) != 0u)
                            ech_high_bit++;
                    } else {
                        ech_bad_shape++;
                    }
                } else {
                    ech_bad_shape++;
                }
                if (aead == TEST_ECH_AEAD_AES_128_GCM)
                    saw_aes++;
                else if (aead == TEST_ECH_AEAD_CHACHA20_POLY1305)
                    saw_chacha++;
                else
                    saw_other++;
                break;
            }
            p = body + len;
        }
    }

    if (real_len > 0) {
        snprintf(msg, sizeof msg, "the extension is there in all %u hellos", ech_seen);
        ok(ech_seen == rounds, msg);
        ok(saw_other == 0, "and never carries a suite uTLS would not have picked");
        /* Four hundred draws: seeing only one of two would be a one-in-2^400 accident, so this is a
         * constant if it fails, not an unlucky run. */
        snprintf(msg, sizeof msg, "both suites appear across %u hellos (%u aes, %u chacha)", rounds,
                 saw_aes, saw_chacha);
        ok(saw_aes > 0 && saw_chacha > 0, msg);

        snprintf(msg, sizeof msg,
                 "the ECH enc is an x25519 point in all %u hellos (%u with the top bit set)", rounds,
                 ech_high_bit);
        ok(ech_high_bit == 0 && ech_bad_shape == 0, msg);
    }

    /* ---- what a refusal is allowed to say ------------------------------------------------------
     *
     * ⚠️ ONE SENTENCE STOOD FOR FOUR CODES and named the wrong one for three of them. An empty
     * server name — an argument — was reported as "the fingerprint table does not build a hello",
     * which sends whoever is holding the router to a file that is perfectly fine. So what is pinned
     * is that the four are DISTINCT and that each says its own subject out loud; a mapping where
     * two codes share a sentence passes every other check in this tree. */
    printf("\nwhat a refusal says\n");
    {
        const char *w_table = lc_hello_why(LC_HELLO_BAD_TABLE);
        const char *w_space = lc_hello_why(LC_HELLO_NO_SPACE);
        const char *w_rnd = lc_hello_why(LC_HELLO_NO_RANDOM);
        const char *w_sni = lc_hello_why(LC_HELLO_BAD_SNI);
        ok(strcmp(w_table, w_space) != 0 && strcmp(w_table, w_rnd) != 0 &&
               strcmp(w_table, w_sni) != 0 && strcmp(w_space, w_rnd) != 0 &&
               strcmp(w_space, w_sni) != 0 && strcmp(w_rnd, w_sni) != 0,
           "four codes, four different sentences");
        ok(strstr(w_sni, "server name") != NULL, "and the one about the name says server name");
        ok(strstr(w_table, "table") != NULL, "while the one about the table still says table");
    }

    /* The rule itself, at both edges, and the wiring that makes the daemon's startup check and the
     * builder's per-connection check the same question rather than two spellings of it. */
    {
        static char big[0xfff2u];
        memset(big, 'a', sizeof big);
        big[0xfff0u] = 0;
        ok(lc_hello_sni_ok("") == 0, "an empty server name is refused");
        ok(lc_hello_sni_ok(NULL) == 0, "and so is none at all");
        ok(lc_hello_sni_ok("a") != 0, "one character is a name");
        ok(lc_hello_sni_ok(big) != 0, "0xfff0 characters is the longest that fits");
        big[0xfff0u] = 'a';
        big[0xfff1u] = 0;
        ok(lc_hello_sni_ok(big) == 0, "and one more does not, so the bound is not off by one");

        uint8_t      out2[4096];
        lc_hello_out info2;
        uint8_t      t2[256];
        size_t       tn2 = build_table(t2);
        ok(lc_hello_build(t2, tn2, "", out2, sizeof out2, &info2) == LC_HELLO_BAD_SNI,
           "the builder refuses the same name the predicate does, and calls it the name");
    }

    /* ---- hostnameInSNI: what goes in server_name for a name ---- */
    printf("\nthe name on the wire, as hostnameInSNI makes it\n");
    {
        /* vendor/utls/handshake_client.go:1367-1382, the IP test being net.ParseIP — which since
         * Go 1.17 refuses an IPv4 field with a leading zero, so "01.2.3.4" is a name. */
        static const struct { const char *name; size_t want; } sc[] = {
            { "example.com", 11u },     { "example.com.", 11u },  { "example.com..", 11u },
            { "1.2.3.4", 0u },          { "1.2.3.4.", 7u },       { "01.2.3.4", 8u },
            { "256.1.1.1", 9u },        { "::1", 0u },            { "[::1]", 0u },
            { "fe80::1%eth0", 0u },     { "[fe80::1%eth0]", 0u }, { "::ffff:1.2.3.4", 0u },
            { "[example.com]", 13u },   { "%x", 2u },
        };
        unsigned bad = 0;
        for (size_t i = 0; i < sizeof sc / sizeof sc[0]; i++) {
            size_t got = lc_hello_sni_len(sc[i].name);
            if (got != sc[i].want) {
                printf("        %s: %zu, want %zu\n", sc[i].name, got, sc[i].want);
                bad++;
            }
        }
        ok(bad == 0, "IP literals have no name, trailing dots come off, the rest stands");

        uint8_t      out3[4096];
        lc_hello_out info3;
        uint8_t      t3[256];
        size_t       tn3 = build_table(t3);
        uint16_t     types[16];
        int          built3 = lc_hello_build(t3, tn3, "192.0.2.1", out3, sizeof out3, &info3) ==
                     LC_HELLO_OK;
        unsigned     n3 = built3 ? ext_types(out3, info3.len, types, 16) : 0u;
        int          has_sni = 0;
        for (unsigned i = 0; i < n3; i++)
            has_sni |= types[i] == 0x0000u;
        ok(built3 && n3 == 2u && !has_sni,
           "and a hello for an IP literal carries no server_name at all, its GREASE either side");
    }

    printf("\n%s\n", failures == 0 ? "GREASE rules hold" : "GREASE rules BROKEN");
    return failures == 0 ? 0 : 1;
}
