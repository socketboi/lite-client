/* ML-DSA signature verification (FIPS 204), as Go 1.27.1's crypto/mldsa answers it.
 *
 * WHY: the REALITY plane's reference is built with Go 1.27, whose crypto/x509 knows ML-DSA keys
 * and signatures. parsePublicKey hands an ML-DSA SubjectPublicKeyInfo to mldsa.NewPublicKey
 * (GOROOT/src/crypto/x509/parser.go:366-374) and checkSignature hands the signature to
 * mldsa.Verify(pub, signed, signature, nil) (GOROOT/src/crypto/x509/x509.go:1115-1138). A port of
 * either has to accept exactly what they accept and refuse the rest in their words, so this is
 * GOROOT/src/crypto/mldsa and GOROOT/src/crypto/internal/fips140/mldsa of that toolchain, rule for
 * rule and in its order, and test/mldsa holds it to what Go answered (tools/mldsavec).
 *
 * VERIFICATION ONLY: no key generation and no signing, because this client never holds an ML-DSA
 * private key. Every value touched here is public, so nothing needs to run in constant time and
 * nothing here pretends to.
 *
 * Pure ML-DSA with an empty context — the only way x509 calls it. No HashML-DSA, no external mu. */
#ifndef LC_MLDSA_H
#define LC_MLDSA_H

#include "core/gotext.h"

#include <stddef.h>
#include <stdint.h>

/* The parameter sets, as x509's mldsaParametersFromOID picks them. Any other value is Go's zero
 * mldsa.Parameters{}, which NewPublicKey refuses as "invalid parameters". */
#define LC_MLDSA_44 1
#define LC_MLDSA_65 2
#define LC_MLDSA_87 3

#define LC_MLDSA44_PUBKEY 1312u
#define LC_MLDSA65_PUBKEY 1952u
#define LC_MLDSA87_PUBKEY 2592u
#define LC_MLDSA44_SIG 2420u
#define LC_MLDSA65_SIG 3309u
#define LC_MLDSA87_SIG 4627u

/* mldsa.NewPublicKey(params, pk): 0 when Go makes a key of it, -1 when it does not, with its
 * error's text appended to `err` when that is not NULL. Only the parameter set and the length are
 * judged; every byte string of the right length is a key. */
int lc_mldsa_public_key_ok(int params, const uint8_t *pk, size_t len, lc_obuf *err);

/* mldsa.Verify(pub, msg, sig, nil) for the key NewPublicKey(params, pk) makes: 0 when `sig` is a
 * valid signature of `msg`, -1 otherwise with the error's text appended to `err` when that is not
 * NULL. A key NewPublicKey refuses is refused first, in NewPublicKey's words — Go has no Verify
 * without a key. Uses about 14 KiB of stack and no heap. */
int lc_mldsa_verify(int params, const uint8_t *pk, size_t pk_len, const uint8_t *msg, size_t msg_len,
                    const uint8_t *sig, size_t sig_len, lc_obuf *err);

#endif
