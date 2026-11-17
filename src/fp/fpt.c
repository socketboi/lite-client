#include "fp/fpt.h"
#include "tls/kex.h"

#include <stdio.h>
#include <string.h>

/* ⚠️ NO REFERENCE TO CITE, AND THE STRONGEST GATE IN THE TREE INSTEAD — a boundary rather than
 * a hole, said here because COVERAGE.md lists this file among the uncited and cannot say why.
 *
 * There is nothing in vendor/ that this format could be compared against: the container is ours.
 * uTLS carries its fingerprints as Go structures compiled into the binary; a router cannot, so
 * the same information is cut into a file the client reads at startup. A pair against a vendor
 * line would be comparing a serialisation format with a language's struct literals.
 *
 * What replaces it is stricter than any pair could be. test/fphello reads the table that actually
 * ships — package/files/fingerprint.fpt, the file installed on a router — builds a ClientHello
 * from it, and compares the RESULT byte for byte against a frozen uTLS message, ignoring only the
 * four fields that must differ every time: random, session id, key share and the GREASE draws. So
 * the question the sieve would ask about this file ("does it agree with the reference?") is
 * answered on the only thing that reaches anybody: the bytes on the wire.
 *
 * That is a better question than a pair asks, and it is worth saying why: a pair checks a CLAIM a
 * comment makes about one line. This checks the whole hello, including everything nobody thought
 * to claim — an extension in the wrong order, a length that changed when the table was recut, a
 * field this parser reads correctly and the builder then emits in the wrong place. None of those
 * has a line to cite, and all of them are what a traffic analysis looks for.
 *
 * The two checks are deliberately different and both are wanted: test/hello builds a table in-test
 * and asserts the RULES a fingerprint must satisfy, which hold for a table nobody ships; this one
 * asserts the OUTPUT for the table that is shipped. */
/* ⚠️ BUMPED TO 3 ON 2026-09-08, AND THE BUMP IS THE POINT RATHER THAN A FORMALITY.
 *
 * Version 3 is version 2 with the GREASE-ECH record grown a candidate list: `kdf count aead[count]
 * enc_len payload_len` where 2 had a single `aead`. The layout changed and the version did not,
 * for about an hour — which meant a version-2 table passed the check above and was then read as
 * version 3: the count byte taken from the high half of the old aead, the list from its low half
 * and whatever followed. Not a refusal, a MISREADING, and the hello it produced would have been
 * wrong in exactly the field this whole change is about.
 *
 * A binary and its table are one artefact from here on. The package ships them together and they
 * move together; a hand-placed binary meeting the table already on a router is the case this
 * number exists to catch, and it now says so through the message at lc_fpt_open rather than
 * building a subtly wrong ClientHello.
 *
 * ⚠️ AND TO 4 ON 2026-09-15, for the same reason twice over: a flags byte follows the name (bit 0,
 * whether the X25519 key share reuses the hybrid's classical half — uTLS decides it per parrot), and
 * the GREASE-ECH record ends in a counted list of PRE-encryption payload lengths where it ended in
 * the one length a capture drew. A version-3 table read as 4 would take its legacy_version's high
 * byte for flags and everything after it one byte out. */
#define FPT_VERSION 4

static const uint8_t fpt_magic[4] = { 'L', 'C', 'F', 'P' };

int lc_fpt_open(lc_fpt *c, const uint8_t *blob, size_t len, lc_fpt_needs *needs)
{
    c->p = blob;
    c->len = len;
    c->off = 0;
    c->err = 0;

    if (len < sizeof(fpt_magic) + 1)
        return -1;
    if (memcmp(blob, fpt_magic, sizeof(fpt_magic)) != 0)
        return -1;
    if (blob[sizeof(fpt_magic)] != FPT_VERSION)
        return -1;

    c->off = sizeof(fpt_magic) + 1;

    lc_fpt_needs local;
    lc_fpt_needs *n = needs != NULL ? needs : &local;
    memset(n, 0, sizeof *n);

    n->modes = (uint32_t)lc_fpt_u16(c) << 16;
    n->modes |= lc_fpt_u16(c);

    unsigned count = lc_fpt_u8(c);
    if (count > LC_FPT_MAX_GROUPS) {
        c->err = 1;
        return -1;
    }
    for (unsigned i = 0; i < count; i++)
        n->groups[i] = lc_fpt_u16(c);
    n->group_count = count;

    return lc_fpt_failed(c) ? -1 : 0;
}

void lc_fpt_caps(lc_fpt_needs *out)
{
    memset(out, 0, sizeof *out);

    /* Every mode this build implements. Adding one here without implementing it in hello.c would
     * turn a clean refusal into a malformed hello, which is the worse of the two failures. */
    out->modes = 1u << LC_FPT_LITERAL | 1u << LC_FPT_SNI | 1u << LC_FPT_KEY_SHARE |
                 1u << LC_FPT_RANDOM_PAYLOAD | 1u << LC_FPT_PADDING | 1u << LC_FPT_ECH_GREASE;

    /* Every group this build can generate a key pair for. This is the list that cannot be extended
     * from the table side: a new entry means new key exchange code. */
    out->groups[0] = LC_GROUP_X25519;
    out->groups[1] = LC_GROUP_SECP256R1;
    out->groups[2] = LC_GROUP_X25519MLKEM768;
    out->groups[3] = LC_GROUP_SECP384R1;
    out->groups[4] = LC_GROUP_SECP521R1;
    out->group_count = 5;
}

static const char *mode_name(unsigned m)
{
    switch (m) {
    case LC_FPT_LITERAL:        return "literal";
    case LC_FPT_SNI:            return "sni";
    case LC_FPT_KEY_SHARE:      return "key_share";
    case LC_FPT_RANDOM_PAYLOAD: return "random_payload";
    case LC_FPT_PADDING:        return "padding";
    case LC_FPT_ECH_GREASE:     return "ech_grease";
    case LC_FPT_QUIC_PARAMS:    return "quic_transport_parameters";
    default:                    return "unnamed";
    }
}

int lc_fpt_supported(const uint8_t *blob, size_t len, char *why, size_t why_cap)
{
    return lc_fpt_supported_with(blob, len, 0u, why, why_cap);
}

int lc_fpt_supported_with(const uint8_t *blob, size_t len, uint32_t extra_modes, char *why,
                          size_t why_cap)
{
    lc_fpt       c;
    lc_fpt_needs need;
    if (lc_fpt_open(&c, blob, len, &need) != 0) {
        /* BOTH NUMBERS, because one of them sent somebody looking in the wrong place.
         *
         * This printed only FPT_VERSION — the version this build WANTS — and the sentence reads as
         * if that is what the file carries: "not a table this build reads (magic, version 4, ...)"
         * of a version-2 table. Found on a live router on 19 September, where the box still held a
         * table from 12 August: the message named 4 and the file was 2, and the only way to see that
         * was to read the first bytes by hand. The version found is printed when there is a header
         * to read it from, and the wanted one beside it. */
        if (len > sizeof(fpt_magic) && memcmp(blob, fpt_magic, sizeof(fpt_magic)) == 0) {
            snprintf(why, why_cap, "a table of version %u, and this build reads version %u",
                     (unsigned)blob[sizeof(fpt_magic)], (unsigned)FPT_VERSION);
        } else {
            snprintf(why, why_cap,
                     "not a fingerprint table at all (its first four bytes are not LCFP) or too "
                     "short to hold a header");
        }

        return -1;
    }

    lc_fpt_needs have;
    lc_fpt_caps(&have);
    have.modes |= extra_modes;

    uint32_t missing = need.modes & ~have.modes;
    if (missing != 0u) {
        for (unsigned m = 0; m < 32u; m++) {
            if ((missing >> m & 1u) != 0u) {
                snprintf(why, why_cap, "table needs mode %u (%s), which this build does not emit",
                         m, mode_name(m));
                return -1;
            }
        }
    }

    for (unsigned i = 0; i < need.group_count; i++) {
        int found = 0;
        for (unsigned j = 0; j < have.group_count && !found; j++)
            found = have.groups[j] == need.groups[i];
        if (!found) {
            /* Stated as new key exchange code rather than as a table problem, because that is what
             * it is: the table is correct and this build simply cannot do the arithmetic. */
            snprintf(why, why_cap,
                     "table needs a key share for group 0x%04x, which needs key exchange code this "
                     "build does not have",
                     need.groups[i]);
            return -1;
        }
    }

    return 0;
}

/* take advances the cursor by n and returns where those bytes start, or NULL past the end. All
 * reads funnel through it, so one check of c->err after a full walk covers the whole table. */
static const uint8_t *take(lc_fpt *c, size_t n)
{
    if (c->err)
        return NULL;
    if (n > c->len - c->off) {
        c->err = 1;
        return NULL;
    }
    const uint8_t *at = c->p + c->off;
    c->off += n;
    return at;
}

void lc_fpt_seek(lc_fpt *c, size_t off)
{
    if (off > c->len) {
        c->err = 1;
        return;
    }
    c->off = off;
}

size_t lc_fpt_tell(const lc_fpt *c)
{
    return c->off;
}

uint8_t lc_fpt_u8(lc_fpt *c)
{
    const uint8_t *b = take(c, 1);
    return b ? b[0] : 0;
}

uint16_t lc_fpt_u16(lc_fpt *c)
{
    const uint8_t *b = take(c, 2);
    if (b == NULL)
        return 0;
    return (uint16_t)((uint16_t)b[0] << 8 | b[1]);
}

const uint8_t *lc_fpt_bytes(lc_fpt *c, size_t n)
{
    return take(c, n);
}

int lc_fpt_failed(const lc_fpt *c)
{
    return c->err != 0;
}
