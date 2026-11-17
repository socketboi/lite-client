#include "tls/hybrid.h"
#include "core/wipe.h"

#include <string.h>

/* ⚠️ TWO CONCATENATIONS, AND BOTH ORDERS ARE THE PROTOCOL — cited now, because COVERAGE.md had
 * this file down as one with no reference to compare against and that was wrong. The reference is
 * exact and it is in two places, one per direction.
 *
 * Nothing here can fail visibly if an order is reversed. The share is still the right length, the
 * server still answers, and the secrets simply differ — so the Finished fails, the connection dies
 * without a diagnostic, and the cause is thirty-two bytes from the symptom.
 *
 * WHAT GOES OUT is the ML-KEM encapsulation key first, the X25519 public second:
 *
 *     mlkemEncapsulationKey := keyShareKeys.mlkem.EncapsulationKey().Bytes()
 *     x25519EphemeralKey := keyShareKeys.ecdhe.PublicKey().Bytes()
 *     hello.keyShares = []keyShare{
 *         {group: X25519MLKEM768, data: append(mlkemEncapsulationKey, x25519EphemeralKey...)},
 *     }                                    (vendor/utls/handshake_client.go:179-183)
 *
 * WHAT COMES BACK is split the same way, and the reference checks the length before splitting it:
 * `if len(ecdhePeerData) != mlkem.CiphertextSize768+x25519PublicKeySize` then
 * `ecdhePeerData = hs.serverHello.serverShare.data[mlkem.CiphertextSize768:]`
 * (vendor/utls/handshake_client_tls13.go:587-591), with the ciphertext taken as the leading bytes
 * (vendor/utls/handshake_client_tls13.go:618-619). That is what `peer + LC_MLKEM_CT` reads below.
 *
 * The branch immediately after it in the same file is the OPPOSITE order — X25519Kyber768Draft00
 * puts the X25519 point first (vendor/utls/handshake_client_tls13.go:595-599) — which is the best
 * possible argument for citing this rather than remembering it: the two live twelve lines apart and
 * differ in nothing a reader would notice. THAT BRANCH CANNOT BE REACHED FROM HERE, and the reason
 * belongs beside the citation rather than in somebody's head: this client never offers
 * X25519Kyber768Draft00 — it is not in the supported_groups it sends, not in tls/kex.h, and a
 * server naming a group we did not offer is refused before any of this runs (tls/client.c:217 and
 * quic/qtls.c:986-988). The order below is therefore the only order that can occur.
 *
 * ⚠️ AND THE LENGTH IS CHECKED BY THE CALLER, NOT HERE, which is worth saying because reading this
 * file alone makes it look unchecked: `peer` arrives as a fixed-size array and nothing below it
 * counts bytes. Both callers refuse a share of the wrong size before they get here, and each one
 * says which group it is refusing for — src/tls/client.c:217 on the REALITY plane
 * (`sh->key_share_len != LC_HYBRID_CT`), and src/quic/qtls.c:986-988 on the QUIC one, where the
 * pair (group, length) is checked together so that X25519MLKEM768 must bring LC_HYBRID_CT and bare
 * X25519 must bring LC_X25519_KEY. That placement is this tree's habit rather than an accident: the
 * guard belongs in the parser that knows how many bytes arrived, and the reference puts the same
 * check in its consumer instead (`if len(ecdhePeerData) != mlkem.CiphertextSize768 +
 * x25519PublicKeySize` at vendor/utls/handshake_client_tls13.go:587-589). Same refusal, one layer
 * apart — and an audit that opens only this file will read the difference as a missing check.
 *
 * AND THE SECRET IS ML-KEM FIRST, X25519 SECOND, which is the same order as the share but is a
 * separate decision and reads backwards in the reference because it prepends rather than appends:
 * `sharedKey = append(mlkemShared, sharedKey...)`
 * (vendor/utls/handshake_client_tls13.go:625) — sharedKey held the X25519 secret at that point. */
int lc_hybrid_keygen(lc_hybrid_key *k, uint8_t share[LC_HYBRID_SHARE])
{
    uint8_t ek[LC_MLKEM_EK];
    if (lc_mlkem_keygen(ek, k->mlkem_dk) != 0)
        return -1;

    uint8_t x_pub[LC_X25519_KEY];
    if (lc_x25519_keygen(k->x25519_priv, x_pub) != 0) {
        lc_wipe(k->mlkem_dk, sizeof k->mlkem_dk);
        return -1;
    }

    memcpy(share, ek, LC_MLKEM_EK);
    memcpy(share + LC_MLKEM_EK, x_pub, LC_X25519_KEY);
    return 0;
}

int lc_hybrid_shared(const lc_hybrid_key *k, const uint8_t peer[LC_HYBRID_CT],
                     uint8_t secret[LC_HYBRID_SECRET])
{
    /* The X25519 half is computed first even though it comes second in the output: it is the half
     * that can legitimately fail — a low-order peer key — and failing before touching the KEM keeps
     * the partial secret from ever existing. */
    uint8_t x_shared[LC_X25519_SHARED];
    if (lc_x25519(k->x25519_priv, peer + LC_MLKEM_CT, x_shared) != 0)
        return -1;

    /* The whole `peer` pointer, and only its leading LC_MLKEM_CT bytes are read: the prototype
     * declares `ct[LC_MLKEM_CT]`, which in C is a pointer and decides nothing, so the boundary is
     * worth stating rather than inferring. The X25519 half sits behind those bytes and is taken
     * above, at `peer + LC_MLKEM_CT`. Read the two lines together and the split is the reference's;
     * read either alone and it looks like the whole buffer is being handed over. */
    uint8_t kem_shared[LC_MLKEM_SS];
    if (lc_mlkem_decap(peer, k->mlkem_dk, kem_shared) != 0) {
        lc_wipe(x_shared, sizeof x_shared);
        return -1;
    }

    memcpy(secret, kem_shared, LC_MLKEM_SS);
    memcpy(secret + LC_MLKEM_SS, x_shared, LC_X25519_SHARED);

    lc_wipe(kem_shared, sizeof kem_shared);
    lc_wipe(x_shared, sizeof x_shared);
    return 0;
}

void lc_hybrid_key_free(lc_hybrid_key *k)
{
    lc_wipe(k->mlkem_dk, sizeof k->mlkem_dk);
    lc_wipe(k->x25519_priv, sizeof k->x25519_priv);
}
