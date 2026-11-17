#include "tls/kex.h"

#include "core/rnd.h"
#include "core/wipe.h"
#include "tls/x25519.h"

#include <string.h>

#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>

/* mbedTLS wants a randomness callback for every operation that needs blinding. Ours is the one
 * source the client has; there is no fallback, and an operation that cannot get randomness fails
 * rather than proceeding with something weaker. */
static int rnd_cb(void *unused, unsigned char *out, size_t len)
{
    (void)unused;
    return lc_rnd(out, len) == 0 ? 0 : -1;
}

/* ⚠️ CURVE25519 NO LONGER GOES THROUGH mbedTLS, AND THE TWO TRAPS THAT USED TO LIVE HERE ARE GONE
 * WITH IT. This file drove mbedtls_ecp for X25519 until 2026-09-20, and what that cost was measured
 * on the router the client is for: 16.4 ms per scalar multiplication, three per REALITY handshake,
 * half of everything a handshake spent on asymmetric work. src/tls/x25519.h says where the cost
 * came from and why replacing it is not new cryptography.
 *
 * The two paragraphs this replaces were both about feeding mbedTLS correctly, and both described
 * defects that had already happened. One was the scalar: RFC 7748 clamping is part of the function,
 * not something callers do first, and mbedTLS refuses an unclamped scalar outright — so a private
 * key arriving from the wire had to be clamped and byte-reversed here. The other was the peer's
 * u-coordinate: RFC 7748 §5 says the receiver MUST mask the top bit of the last byte, mbedTLS does
 * that inside the point parser this file did not use, and loading the coordinate directly took the
 * masking with it — a peer that set the bit derived a different secret and the handshake died at
 * Finished with nothing pointing here.
 *
 * Both are now properties of the arithmetic rather than things a caller must remember: lc_x25519_mul
 * clamps what it is given, and the limb widths sum to 255 so bit 255 of a u-coordinate is never
 * read. The NIST curves below still use mbedTLS and still need rnd_cb, which is why it stays.
 *
 * The other three curves are unchanged. They are a HelloRetryRequest away from never being used,
 * and dedicated arithmetic for a curve nobody negotiates would be flash spent on nothing. */
int lc_x25519_keygen(uint8_t priv[LC_X25519_KEY], uint8_t pub[LC_X25519_KEY])
{
    if (lc_rnd(priv, LC_X25519_KEY) != 0)
        return -1;
    /* RFC 7748 clamping. mbedTLS applies it internally, but the private key is also handed to
     * REALITY for its own exchange, and it must be the same scalar in both places. */
    priv[0] = (uint8_t)(priv[0] & 248u);
    priv[31] = (uint8_t)((priv[31] & 127u) | 64u);
    return lc_x25519_public(priv, pub);
}

int lc_x25519_public(const uint8_t priv[LC_X25519_KEY], uint8_t pub[LC_X25519_KEY])
{
    lc_x25519_basemul(pub, priv);
    return 0;
}

int lc_x25519(const uint8_t priv[LC_X25519_KEY], const uint8_t peer[LC_X25519_KEY],
              uint8_t shared[LC_X25519_SHARED])
{
    uint8_t acc = 0;

    lc_x25519_mul(shared, priv, peer);

    /* An all-zero result means the peer sent a low-order point. RFC 7748 §6.1 says to reject it: it
     * would give an attacker a shared secret they can predict. This is the one place that decides
     * it — src/tls/x25519.h says why the arithmetic below deliberately does not. */
    for (size_t i = 0; i < LC_X25519_SHARED; i++)
        acc = (uint8_t)(acc | shared[i]);
    if (acc == 0) {
        lc_wipe(shared, LC_X25519_SHARED);
        return -1;
    }
    return 0;
}

/* ⚠️ ONE IMPLEMENTATION FOR THREE CURVES, because the difference between them is a group id and
 * three lengths and nothing else. Three copies of this would be three places to get the P-521 field
 * size wrong — it is 66 bytes, not 65, and that is exactly the kind of constant a copy drifts on.
 *
 * The curve is loaded per call rather than cached: a handshake generates one key and computes one
 * secret, so the load happens twice per connection and costs nothing measurable beside the
 * multiplication it precedes. */
static int nist_keygen(mbedtls_ecp_group_id id, uint8_t *priv, size_t priv_len,
                       uint8_t *point, size_t point_len)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi       d;
    mbedtls_ecp_point q;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&q);

    int    rc = -1;
    size_t written = 0;

    if (mbedtls_ecp_group_load(&grp, id) != 0)
        goto done;
    if (mbedtls_ecp_gen_keypair(&grp, &d, &q, rnd_cb, NULL) != 0)
        goto done;
    if (mbedtls_mpi_write_binary(&d, priv, priv_len) != 0)
        goto done;
    /* TLS carries the point uncompressed, which is the only format RFC 8446 allows for the
     * NIST curves. */
    if (mbedtls_ecp_point_write_binary(&grp, &q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                       &written, point, point_len) != 0)
        goto done;
    if (written != point_len)
        goto done;
    rc = 0;

done:
    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return rc;
}

static int nist_shared(mbedtls_ecp_group_id id, const uint8_t *priv, size_t priv_len,
                       const uint8_t *peer, size_t point_len,
                       uint8_t *shared, size_t shared_len)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi       d, z;
    mbedtls_ecp_point qp;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);
    mbedtls_ecp_point_init(&qp);

    int rc = -1;
    if (mbedtls_ecp_group_load(&grp, id) != 0)
        goto done;
    if (mbedtls_mpi_read_binary(&d, priv, priv_len) != 0)
        goto done;
    if (mbedtls_ecp_point_read_binary(&grp, &qp, peer, point_len) != 0)
        goto done;
    /* A peer point that is not on the curve turns the exchange into a small-subgroup attack, and
     * mbedTLS will not check it for us. */
    if (mbedtls_ecp_check_pubkey(&grp, &qp) != 0)
        goto done;
    if (mbedtls_ecdh_compute_shared(&grp, &z, &qp, &d, rnd_cb, NULL) != 0)
        goto done;
    if (mbedtls_mpi_write_binary(&z, shared, shared_len) != 0)
        goto done;
    rc = 0;

done:
    mbedtls_ecp_point_free(&qp);
    mbedtls_mpi_free(&z);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return rc;
}

int lc_p384_keygen(uint8_t priv[LC_P384_KEY], uint8_t point[LC_P384_POINT])
{
    return nist_keygen(MBEDTLS_ECP_DP_SECP384R1, priv, LC_P384_KEY, point, LC_P384_POINT);
}

int lc_p384_shared(const uint8_t priv[LC_P384_KEY], const uint8_t peer[LC_P384_POINT],
                   uint8_t shared[LC_P384_SHARED])
{
    return nist_shared(MBEDTLS_ECP_DP_SECP384R1, priv, LC_P384_KEY, peer, LC_P384_POINT,
                       shared, LC_P384_SHARED);
}

int lc_p521_keygen(uint8_t priv[LC_P521_KEY], uint8_t point[LC_P521_POINT])
{
    return nist_keygen(MBEDTLS_ECP_DP_SECP521R1, priv, LC_P521_KEY, point, LC_P521_POINT);
}

int lc_p521_shared(const uint8_t priv[LC_P521_KEY], const uint8_t peer[LC_P521_POINT],
                   uint8_t shared[LC_P521_SHARED])
{
    return nist_shared(MBEDTLS_ECP_DP_SECP521R1, priv, LC_P521_KEY, peer, LC_P521_POINT,
                       shared, LC_P521_SHARED);
}

int lc_p256_keygen(uint8_t priv[LC_P256_KEY], uint8_t point[LC_P256_POINT])
{
    return nist_keygen(MBEDTLS_ECP_DP_SECP256R1, priv, LC_P256_KEY, point, LC_P256_POINT);
}

int lc_p256_shared(const uint8_t priv[LC_P256_KEY], const uint8_t peer[LC_P256_POINT],
                   uint8_t shared[LC_P256_SHARED])
{
    return nist_shared(MBEDTLS_ECP_DP_SECP256R1, priv, LC_P256_KEY, peer, LC_P256_POINT,
                       shared, LC_P256_SHARED);
}
