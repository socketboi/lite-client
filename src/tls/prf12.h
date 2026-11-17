/* The TLS 1.2 key schedule: the PRF and what the client derives with it (RFC 5246 section 5, RFC
 * 7627 for the extended master secret).
 *
 * Only for a server that answered the parrot's hello with TLS 1.2 — a site the REALITY node
 * forwarded us to, or one the spider fetches — which uTLS carries on with where this client used to
 * stop (DIVERGENCES.md, T3, closed 29.09). The reference is vendor/utls/prf.go and
 * vendor/utls/internal/tls12/tls12.go; nothing here is TLS 1.0 or 1.1, which the parrot never
 * offers: the ServerHello that picked either is refused before a key is made. */
#ifndef LC_PRF12_H
#define LC_PRF12_H

#include "tls/hkdf.h"

#include <stddef.h>
#include <stdint.h>

/* masterSecretLength and finishedVerifyLength (vendor/utls/prf.go:88-89). */
#define LC_TLS12_MASTER_LEN   48u
#define LC_TLS12_VERIFY_LEN   12u

/* P_hash over label || seed, `out_len` bytes of it: tls12.PRF and its pHash
 * (vendor/utls/internal/tls12/tls12.go:14-22, :25-42). The seed may be up to 2 * 32 + 48 bytes, which is
 * more than any caller here passes. */
int lc_prf12(lc_hash h, const uint8_t *secret, size_t secret_len, const char *label,
             const uint8_t *seed, size_t seed_len, uint8_t *out, size_t out_len);

/* The master secret: masterFromPreMasterSecret, or with the extended master secret agreed
 * extMasterFromPreMasterSecret over the transcript hash up to the ClientKeyExchange
 * (vendor/utls/prf.go:112-118, :122-130). */
int lc_tls12_master(lc_hash h, const uint8_t *pms, size_t pms_len, const uint8_t client_random[32],
                    const uint8_t server_random[32], uint8_t out[LC_TLS12_MASTER_LEN]);
int lc_tls12_master_ems(lc_hash h, const uint8_t *pms, size_t pms_len, const uint8_t *transcript_hash,
                        uint8_t out[LC_TLS12_MASTER_LEN]);

/* The key block, in keysFromMasterSecret's order: client MAC, server MAC, client key, server key,
 * client IV, server IV (vendor/utls/prf.go:135-154). */
int lc_tls12_key_block(lc_hash h, const uint8_t master[LC_TLS12_MASTER_LEN],
                       const uint8_t client_random[32], const uint8_t server_random[32],
                       uint8_t *out, size_t out_len);

/* verify_data of a Finished: clientSum and serverSum (vendor/utls/prf.go:201-217). */
int lc_tls12_finished(lc_hash h, const uint8_t master[LC_TLS12_MASTER_LEN], int server,
                      const uint8_t *transcript_hash, uint8_t out[LC_TLS12_VERIFY_LEN]);

#endif
