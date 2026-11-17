/* The fingerprint table's header and its cursor, on tables that are wrong.
 *
 * WHY. Every router reads a .fpt at startup and renders its hello from it. test/fphello checks that
 * the SHIPPED table renders byte for byte like uTLS — the happy path, and a strong check of it — but
 * a parser is judged on what it does with a file that is not the shipped one: a flash write that
 * stopped halfway, a table from a build that speaks a version this one does not, a table asking for
 * a key exchange this build cannot do. None of those paths was reached by any test until 2026-09-02.
 *
 * The failure they guard against is specific. The cursor here is the deferred kind — reading past
 * the end returns zero and sets a flag, and the flag is checked once at the end of a walk — so a
 * truncated table does not crash, it produces a hello made of zeros. That is a client with a
 * fingerprint nobody has ever seen, which is the one outcome this whole subsystem exists to avoid,
 * and it would look like nothing at all going wrong. */

#include "fp/fpt.h"
#include "tls/kex.h"

#include <stdio.h>
#include <string.h>

static int fails;

/* The version a table has to carry to be read at all, written out rather than taken from fp/fpt.h.
 *
 * Importing it would make every case below agree with the reader by construction, including the one
 * case that matters: this suite exists to say that a table this build cannot read is REFUSED, and a
 * refusal asserted against a constant the reader itself supplies asserts nothing. So the number is
 * typed here, and when the format grows again this line is what has to be changed by hand. */
#define TEST_FPT_VERSION 4u


static void ok(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        fails++;
}

/* A header, built by hand so that each field can be wrong on purpose: magic, version, two halves of
 * the mode set, a group count, and that many groups. */
static size_t header(uint8_t *b, uint8_t version, uint32_t modes, const uint16_t *groups,
                     unsigned count)
{
    size_t n = 0;
    b[n++] = 'L';
    b[n++] = 'C';
    b[n++] = 'F';
    b[n++] = 'P';
    b[n++] = version;
    b[n++] = (uint8_t)(modes >> 24);
    b[n++] = (uint8_t)(modes >> 16);
    b[n++] = (uint8_t)(modes >> 8);
    b[n++] = (uint8_t)modes;
    b[n++] = (uint8_t)count;
    for (unsigned i = 0; i < count; i++) {
        b[n++] = (uint8_t)(groups[i] >> 8);
        b[n++] = (uint8_t)groups[i];
    }
    return n;
}

int main(void)
{
    printf("a fingerprint table that is not the shipped one\n");

    uint8_t            b[64];
    lc_fpt             c;
    lc_fpt_needs       need;
    static const uint16_t good[2] = { LC_GROUP_X25519, LC_GROUP_X25519MLKEM768 };

    /* ---- what a table has to be before anything is read out of it ---- */

    size_t n = header(b, TEST_FPT_VERSION, 1u << LC_FPT_LITERAL | 1u << LC_FPT_SNI, good, 2u);
    ok(lc_fpt_open(&c, b, n, &need) == 0 && !lc_fpt_failed(&c),
       "a well-formed header opens and leaves the cursor healthy");
    ok(need.modes == (1u << LC_FPT_LITERAL | 1u << LC_FPT_SNI) && need.group_count == 2u &&
           need.groups[0] == LC_GROUP_X25519 && need.groups[1] == LC_GROUP_X25519MLKEM768,
       "and the requirements come back as they were written");

    b[0] = 'X';
    ok(lc_fpt_open(&c, b, n, &need) != 0, "a table without the magic is refused");
    b[0] = 'L';

    /* The PREDECESSOR, and not some number no build ever wrote: version 3 was version 2 with the
     * GREASE-ECH record grown a candidate list, and for about an hour the layout changed while the
     * version did not — so a version-2 table passed this check and was then read as though the
     * count byte were the top half of an aead id. Not a refusal, a MISREADING, which is why the
     * predecessor is the version worth pinning as refused. Version 4 moved the layout again (a flags
     * byte after the name, payload lengths in GREASE-ECH), so 3 is the one pinned now, and 2 with it.
     * A check written as "at most 4" would still pass an arbitrary 1 and fail only here. */
    b[4] = 3u;
    ok(lc_fpt_open(&c, b, n, &need) != 0, "and one of the version this build read before it grew");
    b[4] = 2u;
    ok(lc_fpt_open(&c, b, n, &need) != 0, "and the one before that");
    b[4] = (uint8_t)TEST_FPT_VERSION;

    ok(lc_fpt_open(&c, b, 4u, &need) != 0, "a file too short to hold magic and version is refused");
    ok(lc_fpt_open(&c, b, 0u, &need) != 0, "and so is an empty one");

    /* ⚠️ TRUNCATED PAST THE HEADER, which is what a flash write that stopped leaves behind. The
     * fields are read with a cursor that answers zero past the end, so nothing here fails loudly —
     * the refusal has to come from the flag being checked. */
    ok(lc_fpt_open(&c, b, 6u, &need) != 0,
       "a header cut off inside the mode set is refused, not read as zeros");
    ok(lc_fpt_open(&c, b, 10u, &need) != 0,
       "and one whose group count promises groups that are not there");

    /* More groups than the structure holds. Refused rather than written past. */
    {
        static const uint16_t many[9] = { LC_GROUP_X25519, LC_GROUP_X25519, LC_GROUP_X25519,
                                          LC_GROUP_X25519, LC_GROUP_X25519, LC_GROUP_X25519,
                                          LC_GROUP_X25519, LC_GROUP_X25519, LC_GROUP_X25519 };
        size_t m = header(b, TEST_FPT_VERSION, 0u, many, 9u);
        ok(lc_fpt_open(&c, b, m, &need) != 0,
           "a group count past what the table can hold is refused, not written past");
        m = header(b, TEST_FPT_VERSION, 0u, many, 8u);
        ok(lc_fpt_open(&c, b, m, &need) == 0,
           "and exactly the maximum is accepted, so the bound is not off by one");
    }

    /* ---- the cursor, once a table is open ---- */

    n = header(b, TEST_FPT_VERSION, 0u, good, 0u);
    ok(lc_fpt_open(&c, b, n, &need) == 0, "a table with no groups is still a table");
    ok(lc_fpt_u8(&c) == 0u && lc_fpt_failed(&c),
       "reading past the end gives zero AND raises the flag — the zero alone would be a hello of zeros");

    (void)lc_fpt_open(&c, b, n, &need);
    ok(lc_fpt_u16(&c) == 0u && lc_fpt_failed(&c), "the same for a two-byte read");

    (void)lc_fpt_open(&c, b, n, &need);
    ok(lc_fpt_bytes(&c, 4u) == NULL && lc_fpt_failed(&c),
       "and a run of bytes past the end comes back as nothing rather than as something");

    (void)lc_fpt_open(&c, b, n, &need);
    ok(lc_fpt_bytes(&c, 0u) != NULL && !lc_fpt_failed(&c),
       "while asking for no bytes at the very end is not an overrun");

    /* ---- what this build says it can do, and what it refuses ---- */

    {
        lc_fpt_needs have;
        lc_fpt_caps(&have);
        ok(have.group_count == 5u, "this build states five groups it can make a key share for");
        ok((have.modes >> LC_FPT_ECH_GREASE & 1u) != 0u, "and ech_grease among its modes");
    }

    {
        char why[128];
        n = header(b, TEST_FPT_VERSION, 1u << LC_FPT_LITERAL | 1u << LC_FPT_SNI, good, 2u);
        why[0] = 'x';
        ok(lc_fpt_supported(b, n, why, sizeof why) == 0,
           "a table asking only for what this build does is supported");

        /* A mode number nothing implements. The refusal has to NAME it: "unsupported table" is not
         * something anyone can act on, and the person reading it is holding a router. */
        n = header(b, TEST_FPT_VERSION, 1u << 7, good, 2u);
        why[0] = '\0';
        ok(lc_fpt_supported(b, n, why, sizeof why) != 0 && strstr(why, "mode") != NULL,
           "one needing a mode this build does not emit is refused, and the mode is named");

        {
            static const uint16_t odd[1] = { 0x1234u };
            n = header(b, TEST_FPT_VERSION, 0u, odd, 1u);
            why[0] = '\0';
            ok(lc_fpt_supported(b, n, why, sizeof why) != 0 && strstr(why, "0x1234") != NULL,
               "one needing a key share this build cannot make is refused, and the group is named");
        }

        /* THE VERSION THE FILE CARRIES, NOT ONLY THE ONE THIS BUILD WANTS.
         *
         * The refusal used to print FPT_VERSION alone, and read as though that were the file's:
         * "not a table this build reads (magic, version 4, …)" of a version-2 table. That is how a
         * live router's table went unnoticed until its first bytes were read by hand — the message
         * named 4 and the file was 2. Both numbers now, and this is the check that keeps them. */
        n = header(b, TEST_FPT_VERSION, 0u, good, 2u);
        b[4] = 2; /* a table from an older build, header otherwise intact */
        why[0] = '\0';
        ok(lc_fpt_supported(b, n, why, sizeof why) != 0 && strstr(why, "version 2") != NULL &&
             strstr(why, "version 4") != NULL,
           "an older table is refused naming BOTH versions, its own and this build's");

        b[0] = 'X';
        why[0] = '\0';
        ok(lc_fpt_supported(b, n, why, sizeof why) != 0 && strstr(why, "LCFP") != NULL,
           "and one that is not a table at all says so, rather than naming a version");

    }

    printf("\n%s\n", fails == 0 ? "a table that cannot be trusted is refused, not read as zeros"
                                : "the table parser has CHANGED");
    return fails == 0 ? 0 : 1;
}
