#include "reality/reality.h"

#include "tls/aead.h"
#include "tls/hkdf.h"
#include "tls/kex.h"
#include "core/wipe.h"

#include <string.h>

#include <mbedtls/md.h>

/* The sealed payload is sixteen bytes; the tag makes up the other sixteen of session_id. */
#define REALITY_PLAINTEXT 16u

/* Where the random sits relative to session_id: two bytes of legacy_version and thirty-two of
 * random precede the one-byte session_id length. Derived from sid_off rather than hardcoded,
 * because the caller is the one that knows the layout it built. */
#define RANDOM_BEFORE_SID 33u

int lc_reality_stamp(uint8_t *hello, size_t hello_len, size_t sid_off,
                     const lc_reality_config *cfg,
                     const uint8_t *x25519_priv, uint32_t unix_time,
                     uint8_t auth_key[LC_REALITY_AUTH_KEY])
{
    if (sid_off < RANDOM_BEFORE_SID)
        return -1;
    if (hello_len < sid_off + LC_REALITY_SESSION_ID)
        return -1;

    const uint8_t *random = hello + sid_off - RANDOM_BEFORE_SID;
    uint8_t       *sid = hello + sid_off;

    /* ⚠️ THIS FILE HAD NO CITATION AT ALL UNTIL NOW, WHICH MADE IT A BLIND SPOT.
     *
     * The vendor sieve builds its pairs from references our comments make; a file that names no
     * reference line gets no pair, so the forward pass never opens it. COVERAGE.md listed
     * src/reality/reality.c among the files nothing ever cited — 125 lines carrying the whole of
     * REALITY's authentication, the most consequential code in this client, checked by nothing but
     * somebody deciding to sit down and read it. On 2026-08-28 somebody did, found it correct to the
     * byte, and added the references below so that it is checked from now on rather than admired.
     *
     * The stamp, whole, is vendor/Xray-core/transport/internet/reality/reality.go:163-200 in the
     * reference. Each step below carries the line it comes from.
     *
     * ⚠️ THAT RANGE STARTS ON A BARE `{` AND IS MEANT TO. lcblank.sh reports references whose first
     * line is blank or a lone brace, because that is what an off-by-one looks like — and on
     * 2026-09-07 it found nineteen real ones, every other reference in this tree, each pointing one
     * line above the code it claimed. This is the twentieth and the false positive: the stamp IS
     * that block, `{` to `}`, and 139 would name its contents while dropping the thing being named.
     * Written down so the next pass does not shift it to make a report clean.
     *
     * The associated data is the hello with session_id ZEROED — `hello.SessionId = make([]byte, 32)`
     * then `copy(hello.Raw[39:], hello.SessionId)` before anything is sealed
     * (vendor/Xray-core/transport/internet/reality/reality.go:166-167). The server does the same
     * before opening, so the two agree on what was authenticated — and the ciphertext then lands in
     * the very bytes it covers, which is why they have to be cleared first rather than after. The 39
     * is the reference's own constant, commented there as "the fixed location of `Session ID`", and
     * it is what RANDOM_BEFORE_SID above is derived against: 39 - 33 = 6, where the random begins. */
    memset(sid, 0, LC_REALITY_SESSION_ID);

    /* The second exchange: the ephemeral key from key_share against the server's static key.
     * Reusing the ephemeral key is what makes this free — no extra bytes on the wire, and the
     * server already has the public half. */
    uint8_t shared[LC_X25519_SHARED];
    if (lc_x25519(x25519_priv, cfg->public_key, shared) != 0)
        return -1;

    /* HKDF with the first twenty bytes of the hello's random as salt and a bare "REALITY" as info —
     * `hkdf.Key(sha256.New, uConn.AuthKey, hello.Random[:20], "REALITY", 32)`
     * (vendor/Xray-core/transport/internet/reality/reality.go:191), the shared secret being the
     * ikm and the result overwriting it in place.
     *
     * Not HKDF-Expand-Label: REALITY is not a TLS derivation and carries no HkdfLabel. */
    static const uint8_t info[] = { 'R', 'E', 'A', 'L', 'I', 'T', 'Y' };
    uint8_t              prk[LC_HASH_MAX];
    int                  rc = -1;

    if (lc_hkdf_extract(LC_SHA256, random, 20u, shared, sizeof shared, prk) != 0)
        goto done;
    if (lc_hkdf_expand(LC_SHA256, prk, info, sizeof info, auth_key, LC_REALITY_AUTH_KEY) != 0)
        goto done;

    /* version, one reserved byte, the time the server checks against its own clock, and the short
     * id that says which subscription this is. Sixteen bytes exactly — the tag needs the rest. */
    uint8_t plaintext[REALITY_PLAINTEXT];
    plaintext[0] = cfg->version[0];
    plaintext[1] = cfg->version[1];
    plaintext[2] = cfg->version[2];
    plaintext[3] = 0x00u;
    plaintext[4] = (uint8_t)(unix_time >> 24);
    plaintext[5] = (uint8_t)(unix_time >> 16);
    plaintext[6] = (uint8_t)(unix_time >> 8);
    plaintext[7] = (uint8_t)unix_time;
    memcpy(plaintext + 8, cfg->short_id, LC_REALITY_SHORT_ID);

    /* AES-256-GCM, and the reason is worth stating: both ends call aes.NewCipher on the whole
     * thirty-two byte authentication key, and in Go the key length is what selects the variant.
     * Reading that as AES-128 would produce a client that never authenticates and no diagnostic
     * anywhere — the server would simply treat it as a stranger and serve the real web site.
     *
     * `aead := crypto.NewAesGcm(uConn.AuthKey)` (reality.go:194) — one constructor, and the key it
     * is handed is the thirty-two byte output of the HKDF above. */
    lc_aead aead;
    if (lc_aead_init(&aead, LC_AEAD_AES_256_GCM, auth_key) != 0) {
        lc_aead_free(&aead);
        goto done;
    }

    uint8_t sealed[LC_REALITY_SESSION_ID];
    size_t  sealed_len = 0;
    /* The nonce is the last twelve bytes of the hello's random; the first twenty were the salt.
     * Plaintext, nonce and associated data in one line of the reference:
     * `aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)`
     * (vendor/Xray-core/transport/internet/reality/reality.go:198) — the AAD is the WHOLE raw
     * hello, with the session_id still zeroed, and the sealed result is written back over those
     * same thirty-two bytes at :199. */
    if (lc_aead_seal(&aead, random + 20u, hello, hello_len,
                     plaintext, sizeof plaintext, sealed, sizeof sealed, &sealed_len) != 0) {
        lc_aead_free(&aead);
        goto done;
    }
    lc_aead_free(&aead);

    if (sealed_len != LC_REALITY_SESSION_ID)
        goto done;

    memcpy(sid, sealed, LC_REALITY_SESSION_ID);
    lc_wipe(sealed, sizeof sealed);
    lc_wipe(plaintext, sizeof plaintext);
    rc = 0;

done:
    lc_wipe(shared, sizeof shared);
    lc_wipe(prk, sizeof prk);
    return rc;
}

int lc_reality_verify_cert(const uint8_t auth_key[LC_REALITY_AUTH_KEY],
                           const uint8_t *public_key, size_t public_key_len,
                           const uint8_t *signature, size_t signature_len)
{
    /* WHAT THE NODE PROVES AND HOW, both sides of it named.
     *
     * The server signs its temporary certificate's Ed25519 PUBLIC key with the authentication key:
     * `h := hmac.New(sha512.New, c.AuthKey); h.Write(ed25519Priv[32:]); h.Sum(cert[:len(cert)-64])`
     * (vendor/REALITY/handshake_server_tls13.go:149-151) — `[32:]` of a Go Ed25519 private key IS
     * the public half, and the 64-byte digest is appended as the certificate's signature.
     *
     * The reference client checks exactly that and nothing else:
     * `h := hmac.New(sha512.New, c.AuthKey); h.Write(pub); if bytes.Equal(h.Sum(nil), certs[0].Signature)`
     * (vendor/Xray-core/transport/internet/reality/reality.go:109-112), under a type assertion that
     * the key IS Ed25519 (:109). Ours is enforced a step earlier — lc_cert_parse accepts only the
     * ed25519 shape REALITY generates, which is the same gate in a different place.
     *
     * ⚠️ AND THERE IS A SECOND SIGNATURE IN THE REFERENCE THAT WE DO NOT CHECK, deliberately: with
     * `Mldsa65Verify` configured, the client additionally verifies an ML-DSA-65 signature carried in
     * the certificate's extension (reality.go:113-120). That is a CLIENT-SIDE option; a client without
     * it takes the `else` branch and accepts on the HMAC alone (:123-125). This client has no such
     * option, so it behaves as the reference does on its default — including against a node that has
     * the post-quantum signature enabled, which simply goes unread. Matching, not missing. */
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    if (info == NULL)
        return -1;
    if (signature_len != 64u)
        return -1;

    uint8_t want[64];
    if (mbedtls_md_hmac(info, auth_key, LC_REALITY_AUTH_KEY, public_key, public_key_len, want) != 0)
        return -1;

    /* Constant time: this comparison decides whether we are talking to our server or to the site it
     * is hiding behind, and an attacker who can time it learns the key one byte at a time. */
    uint8_t diff = 0;
    for (size_t i = 0; i < sizeof want; i++)
        diff = (uint8_t)(diff | (want[i] ^ signature[i]));

    lc_wipe(want, sizeof want);
    return diff == 0 ? 0 : -1;
}
