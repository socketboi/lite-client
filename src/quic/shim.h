/* What ngtcp2 holds as its TLS connection.
 *
 * ngtcp2 stores one opaque pointer per connection and hands it back to the backend from inside
 * shared.c. That pointer is this structure rather than the lc_qtls inside it, because the backend
 * needs more than the handshake: the connection to submit crypto data to, the parameters ngtcp2
 * produced, and the buffers keeping submitted bytes alive until they are acknowledged. */
#ifndef LC_QUIC_SHIM_H
#define LC_QUIC_SHIM_H

#include "core/rnd.h"
#include "quic/qtls.h"

#include <ngtcp2/ngtcp2.h>

typedef struct {
    lc_qtls      tls;
    ngtcp2_conn *conn;

    /* Borrowed, not copied: the caller owns the name for the life of the connection, and a second
     * copy of a string that must match the pinned certificate is a second thing to keep in step. */
    const char *sni;

    /* The node's expected certificate digest, held until ngtcp2 hands over the transport parameters
     * and the handshake can actually start. Copied rather than borrowed — unlike the name above it
     * is small and fixed, and the caller should not have to keep it alive. */
    uint8_t pin[LC_QTLS_PIN];
    int     have_pin;

    /* LC_QTLS_* for the handshake, LC_QTLS_CHROME while the connection parrots Chrome. */
    unsigned tls_flags;

    uint8_t local_params[256];
    size_t  local_params_len;

    /* Handshake bytes we have submitted, one buffer per level — initial, handshake, application.
     * ngtcp2 keeps pointers into these until the peer acknowledges the frames, so they live as long
     * as the connection and are only ever appended to. The initial level holds a ClientHello, the
     * handshake level a Finished; neither approaches the size below, which is set by what a
     * handshake message may legally be rather than by what this client sends. */
    struct {
        uint8_t buf[4096];
        size_t  len;
    } out[3];
} lc_qshim;

/* Binds a fresh shim to a connection. The handshake does not start here — it starts when ngtcp2
 * supplies the local transport parameters, because the ClientHello has to carry them.
 *
 * `pin` is LC_QTLS_PIN bytes, or NULL to leave the node unauthenticated; see qtls.h. */
int lc_qshim_init(lc_qshim *s, ngtcp2_conn *conn, const char *sni, const uint8_t *pin,
                  unsigned tls_flags);

void lc_qshim_free(lc_qshim *s);

#endif
