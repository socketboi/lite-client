/* The two spellings a REALITY credential arrives in, and the refusals that keep a half-read one out.
 *
 * WHY IT MATTERS. `lc_from_base64url` reads the node's public key and `lc_from_hex` its short id,
 * off the command line or out of UCI. src/core/args.h states the hazard at the declaration: "a key
 * half read is a key that authenticates nothing" — a parser that padded a short string, or stopped
 * early on a long one, would hand the handshake a key nobody chose and produce a failure that looks
 * like the node's fault. Neither function was reached by any test until 2026-09-02.
 *
 * THE EXPECTED ENCODINGS COME FROM OUTSIDE THIS TREE. base64url is not a thing worth reimplementing
 * in a test to check an implementation of it: the vectors below are Python's
 * `base64.urlsafe_b64encode` with the padding stripped, which is the spelling Xray prints. A vector
 * this file computed with the code it is checking would agree with itself. */

#include "core/args.h"

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
    printf("how a REALITY credential is read\n");

    uint8_t out[64];
    uint8_t want[32];
    for (unsigned i = 0; i < 32u; i++)
        want[i] = (uint8_t)i;

    /* ---- base64url, the spelling Xray prints a public key in ---- */

    memset(out, 0xcd, sizeof out);
    ok(lc_from_base64url("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", out, 32u) == 0 &&
           memcmp(out, want, 32u) == 0,
       "a thirty-two byte key decodes to exactly those bytes");

    ok(lc_from_base64url("__________________________________________8", out, 32u) == 0 &&
           out[0] == 0xffu && out[31] == 0xffu,
       "and the URL alphabet is the one used: - and _ where the other spelling has + and /");

    /* The alphabet is the URL one and only it. A key copied out of a tool that prints standard
     * base64 must be refused rather than silently decoded to different bytes. */
    ok(lc_from_base64url("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh+", out, 32u) != 0,
       "a + is not in this alphabet and is refused");
    ok(lc_from_base64url("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh/", out, 32u) != 0,
       "and neither is a /");
    ok(lc_from_base64url("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", out, 32u) != 0,
       "padding is not part of the unpadded spelling and is refused too");

    /* ⚠️ THE HALF-READ KEY, which is what the declaration warns about. One character short is
     * thirty-one bytes and a half; it must not become a thirty-two byte key with a zero on the end. */
    ok(lc_from_base64url("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh", out, 32u) != 0,
       "one character short is refused, not padded out");
    ok(lc_from_base64url("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8A", out, 32u) != 0,
       "and one character long is refused, not truncated");
    ok(lc_from_base64url("", out, 32u) != 0, "an empty string is not a key");

    /* A shorter key is a different question from a wrong one: asked for eight bytes, eight is what
     * a correct string of them gives. */
    memset(out, 0xcd, sizeof out);
    ok(lc_from_base64url("AAAAAAAAAAA", out, 8u) == 0 && out[0] == 0 && out[7] == 0 &&
           out[8] == 0xcdu,
       "a shorter key fills exactly its own bytes and not one more");

    /* ---- hex, the spelling a short id arrives in ---- */

    memset(out, 0xcd, sizeof out);
    ok(lc_from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", out, 32u) ==
               0 &&
           memcmp(out, want, 32u) == 0,
       "thirty-two bytes come from sixty-four hex digits");

    ok(lc_from_hex("0123456789ABCDEF", out, 8u) == 0 && out[0] == 0x01u && out[7] == 0xefu,
       "upper case reads the same as lower");

    /* Length is checked against what was asked for, before a single digit is read: half a short id
     * is not a short id, and a long one is not one either. */
    ok(lc_from_hex("0102030405060708090a0b0c0d0e0f", out, 32u) != 0, "too few digits are refused");
    ok(lc_from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00", out,
                   32u) != 0,
       "and too many are refused rather than read up to the count");
    ok(lc_from_hex("", out, 8u) != 0, "an empty string is not a short id");
    ok(lc_from_hex("", out, 0u) == 0, "though asking for nothing and getting nothing is fine");

    /* Anything that is not a hex digit, including the characters that look like they might be. */
    ok(lc_from_hex("0g", out, 1u) != 0, "a letter past f is not a digit");
    ok(lc_from_hex("0 ", out, 1u) != 0, "nor is a space");
    ok(lc_from_hex("0x", out, 1u) != 0, "nor the x of a prefix somebody pasted");

    /* ⚠️ NOTHING IS WRITTEN ON A REFUSAL past what a correct prefix would have filled — checked
     * because the caller keeps the buffer and a partly-filled key is the shape of the fault the
     * declaration warns about. */
    memset(out, 0xcd, sizeof out);
    (void)lc_from_hex("00zz", out, 2u);
    ok(out[1] == 0xcdu, "a refusal partway through does not leave the rest of the key filled in");

    printf("\n%s\n", fails == 0 ? "a credential is read whole or not at all"
                                : "credential parsing has CHANGED");
    return fails == 0 ? 0 : 1;
}
