/* AEAD for the TLS 1.3 record layer.
 *
 * Three algorithms, because those are the three TLS 1.3 defines and the fingerprint decides which
 * one the server will pick. That decision is not ours to make: a browser's cipher list puts
 * AES-GCM first, so on hardware without AES instructions we pay for it. Reordering the list to take
 * the faster one would change the fingerprint, which is the one thing that must not change.
 *
 * ⚠️ WHAT IT COSTS, RE-MEASURED 2026-09-19 with test/bench/bench-aead on the target router
 * (MIPS 1004Kc, 880 MHz), 8 MB through each in 16 KB records:
 *
 *     AES-128-GCM        seal 2148 ms, open 2128 ms   -> 14 Mbit/s counting both directions
 *     AES-256-GCM        seal 2342 ms, open 2333 ms   -> 13
 *     ChaCha20-Poly1305  seal  363 ms, open  362 ms   -> 88
 *
 * ⛔ RE-MEASURED 2026-09-21, AND THE `open` COLUMN WAS NOT A DECRYPTION. The bench opened the one
 * record left in its buffer under every round's nonce and ignored the result, so all rounds but
 * one failed their tag — and gcm_open authenticates first, so a failure cost GHASH alone. 1398 ms
 * was GHASH without the counter mode; decrypting costs what encrypting does, 2128 against 2148.
 * One way, AES-128-GCM on this router is about 30 Mbit/s, not 46. Found by a sampling profile of
 * the live tunnel (GHASH 52 % of the core, AES 27 %), whose GHASH alone cost what the bench said the
 * whole open did. ChaCha20's row was right: mbedTLS decrypts before it compares the tag.
 *
 * ⚠️⚠️ AND THE NUMBERS THIS REPLACED WERE ALSO WRONG, WHICH IS TWICE IN A ROW ON THE SAME LINES.
 * They said 4312/4314 ms for AES-128-GCM and 7 Mbit/s, and were not misread: the bench itself
 * measured its own build. It compiled everything at TEST_CFLAGS, which is -O1, while the binary
 * ships src/ at -Os and the GHASH at -O2, so it under-reported the one cipher whose code it compiled
 * — AES-GCM — by a factor of 2.4 and reported ChaCha20 correctly, because ChaCha20 is the device's
 * own mbedTLS and no flag of the bench's could touch it. That asymmetry is how it was caught, and
 * the rule it leaves behind is at the bench-aead rule in the Makefile.
 *
 * AND THE CONCLUSION DRAWN FROM THE OLD NUMBERS DOES NOT SURVIVE THEM. It read: one-way,
 * AES-128-GCM is 14.8 Mbit/s, the tunnel on the same box carries 11.9, so at 80% of the ceiling
 * "the record layer IS the speed of this client". One-way is the `open` column, and at 1398 ms per
 * 8 MB that is 45.8 Mbit/s — the tunnel's 11.9 is a QUARTER of it, not four fifths. [⛔ 2026-09-21: the
 * open column was GHASH alone, see above; one way is ~30 Mbit/s and 11.9 is two fifths of it.] The record
 * layer is one cost among several here, and the profile a few paragraphs down, which was measured
 * rather than derived, says the same thing.
 *
 * The line before those said 37 and 152, wrong since the first commit and in the other direction.
 * Three sets of numbers, two of them wrong: whatever is quoted here next should name the flags it
 * was built with.
 *
 * ⚠️ ON THE CONNECTIONS THAT REACH THIS CODE, AND THAT IS A CONDITION THE SENTENCE ABOVE DID NOT
 * CARRY — it read as a statement about the tunnel, and measured 2026-08-27 it is not one. When
 * Vision hands a stream to the kernel, the bytes never come here at all: 20 MB pulled through a
 * router split 20 042 935 spliced against 14 894 through the record layer, which is 99.93% of the
 * download untouched by any of this, at 36.8 Mbit/s — twice the ceiling above. The same 20 MB from
 * a peer that did NOT get the hand-off: 0.23% spliced, 17.6 Mbit/s, sitting exactly on it.
 *
 * ⚠️ AND WHICH OF THE TWO A CONNECTION GETS IS THE SERVER'S DECISION, NOT OURS. Read in Xray's own
 * debug log on a test node: the hand-off is announced with CommandPaddingDirect, and the branch that
 * sends it needs the buffer to be whole TLS records end to end — `isComplete := IsCompleteRecord(mb)`
 * at vendor/Xray-core/proxy/proxy.go:365, tested at :369. A response that begins as a saturated
 * stream fills the reader's 8192-byte buffers mid-record and never satisfies it again, so those
 * connections pay this code for their whole life. A response that begins with something small — a
 * page, a set of headers — satisfies it immediately and pays it for nothing.
 *
 * So the honest form of the sentence above: this is the speed of the connections Vision could not
 * hand to the kernel, and how many of them there are is not decided in this repository.
 *
 * ⚠️ AND THE GAP IS mbedTLS's, NOT THE PROCESSOR'S. OpenSSL 3.5.7 on the same CPU, same 16 KB
 * blocks, measured the same day: AES-128-GCM 57.3 Mbit/s, ChaCha20-Poly1305 184.7. So its ChaCha is
 * within 5% of ours and its AES-GCM is 3.9x faster — OpenSSL carries hand-written MIPS assembly
 * (crypto/aes/asm/aes-mips.pl and an optimised GHASH) and mbedTLS carries portable C with tables.
 * The 12x spread between our two ciphers is therefore not what MIPS costs; it is what a missing
 * assembly path costs, and it applies to exactly one of the three.
 *
 * ⚠️ AND IT IS NOT THE AES. CTR is the same key schedule and the same block function with no
 * authentication, so GCM minus CTR is what authenticating costs. Both arms are in bench-aead, one
 * direction, 8 MB each:
 *
 *     AES-128-GCM  open 4310 ms     AES-128-CTR  751 ms   ->  GHASH     3559 ms
 *     AES-256-GCM  open 4517 ms     AES-256-CTR  958 ms   ->  GHASH     3559 ms
 *     ChaCha20-Poly1305 open 364    ChaCha20     296 ms   ->  Poly1305    68 ms
 *
 * The two GHASH figures come out EQUAL, from different key lengths and different totals. That is
 * the check on the subtraction: GHASH cannot depend on the key length, and the arithmetic says so
 * without being told to. mbedTLS's AES is fine — 85 Mbit/s — and its GHASH alone runs at 18.
 *
 * Set beside each other, the two authenticators do the same job over the same eight megabytes for
 * 3559 ms and 68 ms. Fifty-two to one. Against OpenSSL's 57.3 for the whole AES-GCM suite its GHASH
 * must be near 185, so ours is roughly ten times slower than an optimised one and about fifty times
 * slower than the Poly1305 sitting next to it in the same library.
 *
 * That narrows the fix from "replace the crypto" to "replace one multiply in GF(2^128)", and it
 * explains why the key length barely matters: 128 and 256 differ by 4.6% in GCM because the only
 * part that grows is the fifth of it that is AES.
 *
 * ⚠️ AND THE SUBSTITUTION IS UNCONDITIONAL, WHICH IS RIGHT ONLY WHERE IT WAS MEASURED. br_ghash_ctmul
 * is compiled into every build and called with no test of the machine (BEARSSL_OBJ is always in
 * LIB_OBJ; aead.c calls it directly). The argument for it is the paragraph above, and every number
 * in that paragraph is from one processor. OpenWrt is not one processor: the router scripts in this
 * repository already handle x86_64, aarch64, armv7, armv6, mips and mipsel.
 *
 * Measured on the nearest machine that is not the router, 8 MB one way, same 16 KB chunks:
 *
 *     mipsel_24kc   mbedTLS 3559 ms   ours 1369 ms   ours is 2.6x FASTER
 *     x86_64        mbedTLS   20 ms   ours   39 ms   ours is 1.95x SLOWER
 *
 * The reason is the same one that made it a win on MIPS, read the other way round: mbedTLS takes a
 * word-wise path only under MBEDTLS_EFFICIENT_UNALIGNED_ACCESS, which its alignment.h defines for
 * x86, x64 and ARM-with-that-trait and not for MIPS — and where the processor also carries carry-less
 * multiply, mbedTLS uses it and we cannot. So on everything except the platform this was written for,
 * this code is the slower of the two.
 *
 * ⚠️ KEPT ANYWAY, AND THIS IS THE REASONING RATHER THAN AN OVERSIGHT. On those platforms neither
 * figure is a limit on anything: 1721 Mbit/s against 3355 on x86_64 is two numbers far above any
 * household line, so the loss buys back nothing a user could see, while a second code path would be
 * a second thing to keep correct in the part of this client where being wrong is silent. The place
 * it matters — the MIPS box that is genuinely crypto-bound at 17 Mbit/s — is the place it is right.
 *
 * What is NOT known, and is not claimed: armv7 and aarch64 have never been measured here. On aarch64
 * mbedTLS can reach PMULL and this path certainly loses; whether it loses by enough to matter on a
 * box that is not crypto-bound is exactly the question nobody has asked with a stopwatch.
 *
 * ⚠️ THE FAST ONE IS OUT OF REACH, AND THE REFERENCE IS WHAT PUTS IT THERE. ChaCha20 appears above
 * as a CONTROL, not a proposal: it is how the 3559 ms is shown to be GHASH rather than "crypto on
 * MIPS". The suite is chosen by the SERVER, and Go decides it like this:
 *
 *     if !hasAESGCMHardwareSupport || !isAESGCMPreferred(hs.clientHello.cipherSuites) {
 *                                    (vendor/utls/handshake_server_tls13.go:181)
 *
 * — it moves to the ChaCha-first order only when the SERVER has no AES instructions, or when the
 * client's first known suite is not AES-GCM. `aesgcmPreferred` reads the first entry of the list
 * (vendor/utls/cipher_suites.go:384-397), and the hello this client actually sends opens with
 * TLS_AES_128_GCM_SHA256. The node is x86-64 with AES-NI. So neither arm fires and AES-128-GCM is
 * picked, every time, and the only way to be given ChaCha is to reorder the client's list — which
 * is the fingerprint, and the one thing that must not change.
 *
 * ⚠️ THIS USED TO CITE CHROME, AND THIS CLIENT DOES NOT IMITATE CHROME. The frozen vector the gate
 * compares the packaged table against is reference_firefox.h (test/fphello), so the identity on the
 * wire is Firefox's. The conclusion survives the correction — read out of a hello this client
 * builds, the suites are 0x1301, 0x1303, 0x1302, then the TLS 1.2 block, so the first entry is
 * AES-128-GCM either way — but the reasoning rested on the wrong browser, and an argument that
 * happens to reach the right answer from the wrong premise is one nobody can check. Cited to the
 * hello we send rather than to a parrot we do not wear.
 *
 * ⚠️ REPLACING THE GHASH IS NOT A FINGERPRINT QUESTION, which is why it is the lever left. What an
 * observer sees is the suite and the order it was offered in; AES-128-GCM computed by a faster
 * GHASH is byte-identical to AES-128-GCM computed by a slower one. The vendor rule binds what this
 * client SAYS, not how many cycles it spends saying it.
 *
 * ⚠️ SO AES-GCM IS ASSEMBLED FROM TWO LIBRARIES HERE, and the split follows the measurement rather
 * than a preference. mbedTLS keeps the part it is good at — AES-CTR, 85 Mbit/s, which is the same
 * key schedule and the same block function GCM needs — and the authentication moves to BearSSL's
 * br_ghash_ctmul (vendor/bearssl/src/hash/ghash_ctmul.c), measured on this router at 1369 ms per
 * 8 MB against mbedTLS's 3559: 46 Mbit/s against 18.
 *
 * WHAT IT ACTUALLY BOUGHT, re-run on the same box after the change:
 *
 *     AES-128-GCM  1077 ms per MB  ->  343    (7 Mbit/s -> 23, both directions)
 *     AES-256-GCM  1128            ->  365    (7 -> 21)
 *     one way, which is what a download pays:  14.8 Mbit/s -> 36.2
 *
 * and end to end, the same 30 MB pulled through a live server three times with each binary,
 * alternating: 1.32 MB/s against 2.25 MB/s. **10.6 Mbit/s to 17.9**, for 140 bytes of binary.
 *
 * ⚠️ THAT PAIR WAS MEASURED ON A PEER THAT NEVER GETS VISION'S HAND-OFF, which was not known when it
 * was written and changes what it means rather than whether it is true. 17.9 is the no-hand-off
 * ceiling — 2026-08-27 the same measurement on the same box gave 17.6 — so this is the gain on the
 * connections that pay the record layer, which is exactly the population this change is for. On a
 * connection that DOES get the hand-off the figure is untouched by anything in this file, because
 * 99.93% of its bytes are spliced past it. Both halves of that are worth keeping: the change is
 * worth its 140 bytes, and it is not a change to "the tunnel's speed".
 *
 * ⚠️ AND THERE IS NOTHING LEFT BESIDE IT, which was worth establishing rather than assuming.
 * Dividing the tunnel's rate by the figures above suggested the record layer was about half the
 * cost and half was somewhere unattributed; a scratch build timing each phase of the downlink says
 * otherwise. 20 MB through the stand over plain HTTP — no TLS inside, so Vision cannot splice and
 * every byte passes here:
 *
 *     calls 2456 | total 6341 ms | aead 5628 (88%) | unpad 56 | queue 600 | rest 56
 *
 * The queue, which is a memcpy and the write to the client, is 9.5%. Unpadding is 0.9%. Everything
 * else together is 0.9%. So the "other half" does not exist, and copies are not worth chasing.
 *
 * The arithmetic that suggested it was wrong in a way worth naming: it used 36.2 Mbit/s, which is
 * bench-aead's figure for 16 KB records in a hot loop. Real records here average 8143 bytes and
 * arrive cold, and the AEAD then runs at 5628 ms per 20 MB — 28.4 Mbit/s. That is what the two
 * halves predict together, 1/(1/85 + 1/46) = 29.8, so nothing is missing; the benchmark was simply
 * measuring a kinder case than the one the tunnel is in.
 * [⛔ 2026-09-21: it was not a kinder case, it was a broken one — its `open` never ran the counter
 * mode (see the top of this file). Measured honestly the bench says 2128 ms per 8 MB one way, 30
 * Mbit/s, and the tunnel's 28.4 is simply that.]
 *
 * ⚠️ AND THE HALF OF THAT EXPLANATION ABOUT RECORD SIZE IS WRONG — measured 2026-09-19, which is
 * what the size became settable for (see CHUNK in test/bench/bench_aead.c). On the same router,
 * same build, AES-128-GCM costs 443 ms per megabyte at 8143-byte records against 442 at 16 KB, and
 * ChaCha20-Poly1305 is slightly CHEAPER small (89 against 93). Record size does not move this
 * cipher on this CPU at all, so "real records average 8143 bytes" explains none of the gap.
 *
 * What the gap is, then: the bench's one-way AES-128-GCM at 8143-byte records is 8 MB in 1431 ms,
 * which is 44.7 Mbit/s, and the tunnel's AEAD ran at 28.4 — a factor of 1.57 that belongs to the
 * word COLD in that sentence and to nothing else that has been named. It is not explained here.
 *
 * (The figure the old comparison used, 36.2, came from the bench before either of its corrections,
 * so it is a number from a program that no longer exists. The profile beside it — 5628 ms of AEAD
 * per 20 MB — was measured on the tunnel itself and stands.)
 *
 * ⚠️ WHAT IS LEFT, AND WHAT EACH HALF WOULD COST — measured rather than guessed, because the guess
 * was wrong. OpenSSL 3.5.7 on this CPU, 16 KB blocks: AES-128-CTR 102.5 Mbit/s, AES-128-GCM 57.5.
 * Subtracting one from the other gives its GHASH at 131, not the 185 estimated earlier from its
 * suite figure alone.
 *
 *     ours     OpenSSL   ratio
 *     AES-CTR    85       102.5    1.21x
 *     GHASH      46       131      2.85x
 *
 * So replacing the AES is very nearly pointless — 1/(1/102.5 + 1/46) is 31.8 against 29.8 — while
 * replacing the GHASH again would give 1/(1/85 + 1/131) = 51.5. With the record layer at 88% of the
 * downlink that is about 1.6x on the tunnel, and the whole of OpenSSL would be 1.74x. One lever,
 * still the same one.
 *
 * ⚠️ AND "TABLES WOULD BE FASTER" IS NOT WHAT THIS SHOWS. mbedTLS's GHASH IS table-driven — 4-bit
 * Shoup — and runs at 18 where BearSSL's table-free ctmul runs at 46. The spread is implementation
 * quality, not the presence of a table, so trading the constant-time property away buys nothing on
 * its own; whatever replaces this has to be measured, not assumed faster for being a table.
 *
 * ⚠️ SO IT WAS MEASURED. All three of BearSSL's, plus a 4-bit Shoup table written as a probe — the
 * same algorithm mbedTLS uses, but on uint32_t[4] with word-wise XOR instead of the byte-wise one
 * that MIPS falls into. 8 MB each, on the target router, and all four produce the SAME tag, which
 * is what makes the comparison a comparison:
 *
 *     BearSSL ctmul     1383 ms    46 Mbit/s   <- what this client uses
 *     BearSSL ctmul32   1882 ms    34
 *     BearSSL ctmul64   2129 ms    30          <- slowest: 64-bit ops are emulated here
 *     4-bit table         682 ms    93
 *
 * (The three BearSSL rows were re-run on the same router on 2026-09-20, after the bench was found
 * to have been measuring its own -O1 build: 1398, 1908 and 2159 ms. The order and the spread are
 * the same, so the table above survived that correction — which is worth one line, because the
 * correction invalidated other numbers in this file and a reader is right to ask.)
 *
 * So the table is exactly twice ours, and mbedTLS's 18 with the same algorithm is entirely its
 * byte-wise XOR. Taking it would give 1/(1/85 + 1/93) = 44.4 against 29.8, about 1.4x on the
 * tunnel — and would give up the property BearSSL was chosen for, since a table indexed by the data
 * and the key is what cache timing reads. That is a decision about what this client is for, not a
 * performance question, so the fast one is measured and NOT taken. OpenSSL's 131 is faster still,
 * which says the table direction has more in it than this probe found.
 *
 * ⛔ TAKEN, 2026-09-21, AND NOT AS "A TABLE BECAUSE IT IS FASTER". The maintainer's rule for this client is
 * one to one with the reference, and the reference on these routers is Xray, which is Go, which on
 * mipsle has no GCM assembly and runs the generic crypto/internal/fips140/aes/gcm/ghash.go — a 4-bit
 * Shoup table with a reduction table. So the constant-time property this paragraph kept was one the
 * reference does not have, and the table is now the reference's own file ported line for line
 * (src/tls/ghash.c), not a probe: 88 ms per MB on this router against ctmul's 172, same tag on 2000
 * random inputs and on every vector test/aead has. What it gives up is written in ghash.h. The
 * trigger was a sampling profile of the live REALITY tunnel: GHASH 51.6 % of the core, AES 26.6 %.
 * The numbers above for ctmul stay as the record of what was measured and why it was kept then.
 *
 * Why that one of the three BearSSL offers: ctmul32 avoids needing the upper half of a product and
 * is meant for cores that cannot produce it, ctmul takes MUL(x,y) as a 32x32->64 multiply, and
 * MIPS 1004Kc has `mult`. Both were built and run here — 1369 ms against 1895 — and both produced
 * the same tag over the same input, which is what makes the comparison a comparison rather than
 * two numbers. Neither uses a lookup table, so neither has the cache-timing shape a table-driven
 * GHASH has; that is the reason not to write one by hand for this.
 *
 * ⛔ "ChaCha20-Poly1305 STAYS ENTIRELY mbedTLS's, WITH NOTHING TO GAIN BY TOUCHING IT" STOOD HERE UNTIL
 * 2026-09-23, and it was a judgement against OpenSSL on the MIPS router, not against the reference on
 * the router that has one. On the AX3000T the reference's AEAD — x/crypto's, ChaCha20 in NEON
 * assembly (chacha_arm64.s), Poly1305 in 64-bit limbs — sealed a 1350-byte packet in 14.4 us where
 * mbedTLS took about 35, and a Hysteria2 upload pays that once per datagram. So ChaCha20-Poly1305 is
 * now the reference's too: src/tls/chacha.c and poly1305.c, composed in aead.c the way
 * chacha20poly1305_generic.go composes them. Measured with bench-aead on the same boxes, 8 MB sealed
 * in 16 KB records, old binary against new in alternation:
 *
 *     AX3000T (A53)      mbedTLS 104-106 ms   ported 61-62 ms    (the reference: ~68, from its own
 *                                                                 seal of 16 KB, 132 us)
 *     Xiaomi 4A (MT7621) mbedTLS 362-371 ms   ported 353 ms      (Poly1305 stays mbedTLS's there —
 *                                                                 see src/tls/poly1305.h for why)
 *
 * What it did NOT do is close the gap it was taken on for. Uploads through a relay on the AX3000T
 * put 67-71 % of our datagrams back to back against the reference's 75-76 %, from 66-70 % before:
 * a point or two. The rest is the send queue's writer waking — see quic/sendq.h.
 *
 * And libcrypto stays off the device — 6.2 MB against 2.2 MB free on the target's overlay — which is
 * what makes a few kilobytes of ported C the right shape of answer here. */
#ifndef LC_AEAD_H
#define LC_AEAD_H

#include <stddef.h>
#include <stdint.h>

#include <mbedtls/aes.h>

#include "tls/ghash.h"


typedef enum {
    LC_AEAD_AES_128_GCM,
    LC_AEAD_AES_256_GCM,
    LC_AEAD_CHACHA20_POLY1305,
} lc_aead_alg;

/* Every TLS 1.3 AEAD authenticates with sixteen bytes and takes a twelve-byte nonce. */
#define LC_AEAD_TAG 16u
#define LC_AEAD_NONCE 12u

typedef struct {
    /* ChaCha20-Poly1305 only: the key, which is all x/crypto's chacha20poly1305 keeps — every seal
     * and open starts a cipher of its own from it and the nonce (chacha20poly1305_generic.go). */
    uint8_t chacha_key[32];

    /* ⚠️ THE GCM SUITES HOLD THE BLOCK CIPHER DIRECTLY, and that is not a preference.
     * mbedtls_cipher_update REFUSES an in-place call whose length is not a whole number of blocks:
     *
     *     if (input == output && (ctx->unprocessed_len != 0 || ilen % block_size))
     *         return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
     *
     * and lc_record_protect seals in place, over a record whose length is whatever the payload
     * happened to be — 658 bytes, 37, 3. Going through the generic layer therefore failed on every
     * real record while passing a test that used 512. mbedtls_aes_crypt_ctr has no such rule, is
     * the documented way to drive CTR, and skips a dispatch and a heap allocation on the way. */
    mbedtls_aes_context aes;
    /* The same key for the counter mode on the ARMv8 crypto extension, where the CPU has it — see
     * lc_aes_hw_ctr32 in tls/ghash.h. `hw.rounds` is 0 where it does not, and `aes` does the work. */
    lc_aes_hw hw;

    size_t key_len;
    int    ready;

    /* Set for the GCM suites only. `h` is the hash subkey, E(K, 0^128), which is what GHASH
     * multiplies by; it is derived once at init because it depends on the key alone. */
    int     is_gcm;
    uint8_t h[16];
} lc_aead;

size_t lc_aead_key_len(lc_aead_alg alg);

/* Which algorithm a bound context holds, and the one spelling of each name — see aead.c for why a
 * plane that cannot say which cipher it negotiated gets guessed about instead. */
lc_aead_alg lc_aead_alg_of(const lc_aead *a);
const char *lc_aead_alg_name(lc_aead_alg alg);

/* Binds a key. On failure the context is already released, so a caller that gives up may simply
 * return; calling lc_aead_free anyway is still correct and does nothing. */
int lc_aead_init(lc_aead *a, lc_aead_alg alg, const uint8_t *key);
void lc_aead_free(lc_aead *a);

/* out must hold pt_len + LC_AEAD_TAG bytes. */
int lc_aead_seal(lc_aead *a, const uint8_t nonce[LC_AEAD_NONCE],
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *pt, size_t pt_len,
                 uint8_t *out, size_t out_cap, size_t *out_len);

/* out must hold ct_len - LC_AEAD_TAG bytes. Returns non-zero when authentication fails, and writes
 * nothing in that case — a record that does not authenticate is not data, it is an attack or a bug,
 * and either way the caller must not see its contents. */
int lc_aead_open(lc_aead *a, const uint8_t nonce[LC_AEAD_NONCE],
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *ct, size_t ct_len,
                 uint8_t *out, size_t out_cap, size_t *out_len);

#endif
