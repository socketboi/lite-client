/* Destroying key material, as opposed to asking politely.
 *
 * WHY memset IS NOT ENOUGH, AND WHY THIS IS NOT A STYLE PREFERENCE.
 *
 * A buffer wiped on the last line of a function is, to the compiler, a store to memory that nothing
 * reads afterwards. C says an object's lifetime ends with its block, so the store has no observable
 * effect, so the as-if rule permits deleting it — and every optimiser at -O2 does exactly that. The
 * result is a function whose source destroys a private key and whose object code does not. Nothing
 * warns, the tests pass, and the secret stays in the frame until something else happens to write
 * over it. On this device the next thing to use that frame is often a parser being fed bytes the
 * peer chose.
 *
 * That is why this tree calls mbedtls_platform_zeroize instead. It is a real function in a separate
 * translation unit, so the write is not provably dead at the call site, and mbedTLS additionally
 * takes its own measures against a link-time optimiser that can see through that — see the comment
 * at vendor/mbedtls/include/mbedtls/platform_util.h:134-158, which is where the guarantee actually
 * lives. We depend on the library for every hash, cipher and bignum already; depending on it for
 * this costs nothing and is the same answer mbedTLS gives itself throughout.
 *
 * WHAT BELONGS HERE AND WHAT DOES NOT. The rule is the memset's PURPOSE, not its arguments:
 *
 *   - a memset that exists to DESTROY — a private key, a shared secret, a traffic secret, an AEAD
 *     key or IV, a password, an account identifier, decrypted plaintext — becomes lc_wipe;
 *   - a memset that exists to PREPARE — the block of zero bytes HKDF-Extract uses for an absent
 *     salt, a session id cleared so both ends authenticate the same bytes, a struct zeroed before
 *     it is filled in — stays memset, because the value written is the point and something reads
 *     it immediately afterwards.
 *
 * Two things are deliberately left alone. Overwriting argv — which this program does to keep a
 * password out of /proc — is a different job: it is not clearing a secret out of our own frame but
 * editing a string the kernel shows to every other process on the machine, and it writes 'x' rather
 * than zero so that the argument still looks like an argument. And scratch that held nothing secret
 * is not made safer by a stronger wipe: the signature-verification path handles a public key and a
 * signature that already travelled the wire in clear, and calling this on them would claim a
 * protection with no subject.
 *
 * NONE OF THIS SURVIVES THE VALUE BEING COPIED. Wiping the frame does not reach a copy the AEAD
 * kept, a page the allocator handed back, or anything that has been swapped — and a router with no
 * swap is the only reason the last of those is not a concern here.
 */
#ifndef LC_CORE_WIPE_H
#define LC_CORE_WIPE_H

#include <stddef.h>

#include <mbedtls/platform_util.h>

/* Overwrites n bytes at p and is not removed by the optimiser. p may not be NULL unless n is 0,
 * which is mbedtls_platform_zeroize's own contract. */
static inline void lc_wipe(void *p, size_t n)
{
    mbedtls_platform_zeroize(p, n);
}

#endif
