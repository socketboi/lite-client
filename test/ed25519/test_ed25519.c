/* Ed25519 verification, against RFC 8032's own vectors.
 *
 * This is the newest asymmetric primitive in the tree and the only one this project implements
 * itself, so it is checked against the numbers every other implementation is checked against:
 * §7.1's TEST 1, 2, 3 and "TEST SHA(abc)". Being wrong in the same way as everyone else is not
 * possible against these; being wrong alone is exactly what they catch.
 *
 * The negative cases matter more than the positive ones here. A verifier that returns success for
 * everything passes all four vectors above and is worthless, and that failure mode is not
 * theoretical — it is what this client did before this file existed, by never checking the
 * signature at all. So: a flipped bit in each half of the signature, the wrong public key, a
 * mutated message, an S at and above the group order, and encodings that are not points. */

#include "tls/ed25519.c"

#include <stdio.h>

static int failures;

static void expect(int cond, const char *what)
{
    if (cond) {
        printf("  ok    %s\n", what);
        return;
    }
    printf("  FAIL  %s\n", what);
    failures++;
}

static int unhex(const char *hex, uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t n = 0;
    for (const char *p = hex; p[0] != '\0' && p[1] != '\0'; p += 2) {
        if (n >= out_cap)
            return -1;
        unsigned v = 0;
        for (unsigned i = 0; i < 2u; i++) {
            char c = p[i];
            unsigned d;
            if (c >= '0' && c <= '9')      d = (unsigned)(c - '0');
            else if (c >= 'a' && c <= 'f') d = (unsigned)(c - 'a') + 10u;
            else if (c >= 'A' && c <= 'F') d = (unsigned)(c - 'A') + 10u;
            else return -1;
            v = (v << 4) | d;
        }
        out[n++] = (uint8_t)v;
    }
    *out_len = n;
    return 0;
}

struct vector {
    const char *name;
    const char *pub;
    const char *msg;
    const char *sig;
};

/* RFC 8032 §7.1. */
static const struct vector vectors[] = {
    { "TEST 1 (empty message)",
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
      "",
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b" },
    { "TEST 2 (one byte)",
      "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
      "72",
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00" },
    { "TEST 3 (two bytes)",
      "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
      "af82",
      "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a" },
    { "TEST SHA(abc) (64 bytes)",
      "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
      "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704" },
};

int main(void)
{
    printf("Ed25519 verification, RFC 8032 section 7.1\n");

    uint8_t pub[32], sig[64], msg[128];
    size_t  publen = 0, siglen = 0, msglen = 0;

    for (unsigned i = 0; i < sizeof vectors / sizeof vectors[0]; i++) {
        const struct vector *v = &vectors[i];
        if (unhex(v->pub, pub, sizeof pub, &publen) != 0 || publen != 32u ||
            unhex(v->sig, sig, sizeof sig, &siglen) != 0 || siglen != 64u ||
            unhex(v->msg, msg, sizeof msg, &msglen) != 0) {
            expect(0, v->name);
            continue;
        }
        expect(lc_ed25519_verify(pub, msg, msglen, sig) == 0, v->name);
    }

    printf("\nand what must NOT verify\n");

    /* TEST 3 is the working set the negatives are built from. */
    if (unhex(vectors[2].pub, pub, sizeof pub, &publen) != 0 ||
        unhex(vectors[2].sig, sig, sizeof sig, &siglen) != 0 ||
        unhex(vectors[2].msg, msg, sizeof msg, &msglen) != 0) {
        printf("  FAIL  the working vector does not decode\n");
        return 1;
    }

    {
        uint8_t bad[64];
        memcpy(bad, sig, sizeof bad);
        bad[0] ^= 0x01u;
        expect(lc_ed25519_verify(pub, msg, msglen, bad) != 0, "a flipped bit in R is refused");

        memcpy(bad, sig, sizeof bad);
        bad[32] ^= 0x01u;
        expect(lc_ed25519_verify(pub, msg, msglen, bad) != 0, "a flipped bit in S is refused");
    }
    {
        uint8_t other[32];
        size_t  n = 0;
        unhex(vectors[1].pub, other, sizeof other, &n);
        expect(lc_ed25519_verify(other, msg, msglen, sig) != 0,
               "the signature does not verify under a different public key");
    }
    {
        uint8_t m2[128];
        memcpy(m2, msg, msglen);
        m2[0] ^= 0x01u;
        expect(lc_ed25519_verify(pub, m2, msglen, sig) != 0, "a mutated message is refused");
        expect(lc_ed25519_verify(pub, msg, msglen - 1u, sig) != 0,
               "and so is a truncated one, which no length check alone would catch");
    }
    {
        /* S must be BELOW the group order, not reduced into it. S+L verifies under a verifier that
         * reduces, and then one signature has many encodings — RFC 8032 5.1.7 refuses it by name. */
        mbedtls_mpi s, l;
        mbedtls_mpi_init(&s);
        mbedtls_mpi_init(&l);
        uint8_t be[32], mal[64];
        for (size_t i = 0; i < 32u; i++)
            be[i] = sig[63u - i];
        int ok = mbedtls_mpi_read_binary(&s, be, sizeof be) == 0 &&
                 mbedtls_mpi_read_string(&l, 10, L_DEC) == 0 &&
                 mbedtls_mpi_add_mpi(&s, &s, &l) == 0 &&
                 mbedtls_mpi_write_binary(&s, be, sizeof be) == 0;
        if (ok) {
            memcpy(mal, sig, 32u);
            for (size_t i = 0; i < 32u; i++)
                mal[32u + i] = be[31u - i];
            expect(lc_ed25519_verify(pub, msg, msglen, mal) != 0,
                   "S + L is refused rather than reduced back to S");
        } else {
            expect(0, "S + L is refused rather than reduced back to S");
        }
        mbedtls_mpi_free(&s);
        mbedtls_mpi_free(&l);
    }
    {
        /* A y with no matching x is not a point at all, and bytes an attacker chooses: refused
         * rather than run through the arithmetic. A key's y at or above p is first reduced, as Go's
         * Point.SetBytes reduces it — 2^255-1 is 18, which is no point either — while R must be
         * canonical; test-ed25519go holds both rules to Go. */
        uint8_t bad_pub[32];
        memset(bad_pub, 0xffu, sizeof bad_pub); /* y = 2^255-1 > p, sign bit set */
        expect(lc_ed25519_verify(bad_pub, msg, msglen, sig) != 0,
               "a public key that is not a point is refused");

        uint8_t bad_r[64];
        memcpy(bad_r, sig, sizeof bad_r);
        memset(bad_r, 0xffu, 32u);
        expect(lc_ed25519_verify(pub, msg, msglen, bad_r) != 0,
               "and an R that is not a point is refused");
    }

    printf("\n%s\n", failures == 0 ? "Ed25519 verification matches RFC 8032"
                                   : "ED25519 VERIFICATION IS WRONG");
    return failures == 0 ? 0 : 1;
}
