/* X25519MLKEM768 — the hybrid group every current browser fingerprint offers first.
 *
 * The construction is deliberately plain: both halves are concatenated, in a fixed order, and the
 * two shared secrets are concatenated in the same order to form the input keying material. There is
 * no hashing, no combiner, nothing to get creative about — and the order is the one thing that can
 * be got wrong while still producing a self-consistent implementation, so it is stated here once:
 *
 *   key share    = ML-KEM-768 encapsulation key (1184) || X25519 public key (32)   = 1216 bytes
 *   shared secret = ML-KEM-768 shared secret (32)      || X25519 shared secret (32) =   64 bytes
 *
 * The 1216 is worth remembering: it is what the fingerprint tables record as the key length for
 * this group, and a client that emits any other length is identifiable before it says anything. */
#ifndef LC_HYBRID_H
#define LC_HYBRID_H

#include "tls/kex.h"
#include "tls/mlkem.h"

#include <stddef.h>
#include <stdint.h>

#define LC_HYBRID_SHARE (LC_MLKEM_EK + LC_X25519_KEY)      /* 1216 */
#define LC_HYBRID_CT (LC_MLKEM_CT + LC_X25519_KEY)         /* 1120 */
#define LC_HYBRID_SECRET (LC_MLKEM_SS + LC_X25519_SHARED)  /*   64 */

/* Everything the client must keep between building its hello and reading the server's reply.
 *
 * The X25519 private key stays here for a second reason beyond the handshake: REALITY performs its
 * own exchange with the same key against the server's static key, and derives its authentication
 * payload from the result. */
typedef struct {
    uint8_t mlkem_dk[LC_MLKEM_DK];
    uint8_t x25519_priv[LC_X25519_KEY];
} lc_hybrid_key;

/* Generates both halves and writes the key share exactly as it goes into the extension. */
int lc_hybrid_keygen(lc_hybrid_key *k, uint8_t share[LC_HYBRID_SHARE]);

/* Consumes the server's key share and produces the shared secret the schedule takes as IKM. */
int lc_hybrid_shared(const lc_hybrid_key *k, const uint8_t peer[LC_HYBRID_CT],
                     uint8_t secret[LC_HYBRID_SECRET]);

/* Wipes the private material. Called once the handshake no longer needs it. */
void lc_hybrid_key_free(lc_hybrid_key *k);

#endif
