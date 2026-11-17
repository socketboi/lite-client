/* BLAKE2b against Go's implementation.
 *
 * Against Go's rather than against the RFC's single example, because Go is what Hysteria runs: if
 * the two ever disagreed, the RFC would not be the one deciding whether a packet decodes. The
 * lengths are chosen around the 128-byte block boundary, which is where a hash implementation goes
 * wrong — and where the "stop one block short so the last one can be marked" rule bites. */

#include "core/blake2b.h"

#include "blake2b_vectors.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

int main(void)
{
    printf("\nBLAKE2b-256 against Go\n");

    const unsigned char *in[LC_BLAKE2B_CASES] = { b2b_in_0, b2b_in_1, b2b_in_2, b2b_in_3, b2b_in_4,
                                                  b2b_in_5, b2b_in_6, b2b_in_7, b2b_in_8 };
    unsigned len[LC_BLAKE2B_CASES] = { b2b_in_0_len, b2b_in_1_len, b2b_in_2_len, b2b_in_3_len,
                                       b2b_in_4_len, b2b_in_5_len, b2b_in_6_len, b2b_in_7_len,
                                       b2b_in_8_len };
    const unsigned char *want[LC_BLAKE2B_CASES] = { b2b_out_0, b2b_out_1, b2b_out_2, b2b_out_3,
                                                    b2b_out_4, b2b_out_5, b2b_out_6, b2b_out_7,
                                                    b2b_out_8 };

    for (unsigned i = 0; i < LC_BLAKE2B_CASES; i++) {
        uint8_t got[32];
        char    msg[64];
        snprintf(msg, sizeof msg, "%u bytes", len[i]);
        ok(lc_blake2b(in[i], len[i], got, sizeof got) == 0 && memcmp(got, want[i], 32) == 0, msg);
    }

    /* Digest length is part of the parameter block, so the same input at a different length is a
     * different hash rather than a truncation of the longer one. Getting this wrong produces a
     * function that passes every 32-byte test and fails everywhere else. */
    uint8_t short_digest[16], long_digest[32];
    lc_blake2b(b2b_in_4, b2b_in_4_len, short_digest, sizeof short_digest);
    lc_blake2b(b2b_in_4, b2b_in_4_len, long_digest, sizeof long_digest);
    ok(memcmp(short_digest, long_digest, sizeof short_digest) != 0,
       "a shorter digest is not a prefix of a longer one");

    uint8_t any[32];
    ok(lc_blake2b(b2b_in_1, b2b_in_1_len, any, 0) != 0, "a zero-length digest is refused");
    ok(lc_blake2b(b2b_in_1, b2b_in_1_len, any, 65) != 0, "a digest over 64 bytes is refused");

    printf("\n%s\n", failures == 0 ? "BLAKE2b agrees with Go" : "BLAKE2b DISAGREES");
    return failures == 0 ? 0 : 1;
}
