/* THE NODE'S PACKETS OPENED AHEAD, ON THE CORES THE LOOP LEAVES IDLE.
 *
 * On the MT7621 a Hysteria2 download holds one core while three sit idle, and more than half of
 * what that core does per datagram is work that needs nothing from the connection but its keys:
 * Salamander off (lc_obfs_unwrap, a BLAKE2b and an XOR), header protection off, the AEAD opened —
 * 19 % and 32 % of the receive path as profiled. The rest — ngtcp2 reading the frames, the
 * streams, the acknowledgements, the output to the LAN — is the connection's and stays on the loop.
 *
 * So the loop reads a batch, hands it here, and while other threads open it, feeds ngtcp2 the batch
 * before. ngtcp2 still opens every packet itself, through its hp_mask and decrypt callbacks, and
 * those answer from what was computed here only when it was computed from exactly their inputs
 * (lc_qhint in quic/qcrypto.h) — otherwise they compute as they always did. So what the library
 * decides, and everything on the wire, is what it was; only which thread spent the cycles changed.
 *
 * quic-go opens packets in the connection's own goroutine, so this is not the reference's shape. It
 * is the maintainer's decision of 2026-09-29, and CONCURRENCY.md has the measurements (DIVERGES: O2). */
#ifndef LC_RXOPEN_H
#define LC_RXOPEN_H

#include "quic/obfs.h"
#include "quic/qcrypto.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <ngtcp2/ngtcp2.h>

/* How many datagrams a batch holds: the thirty-two the reference's loop reads before it writes
 * (maxPacketsToProcess, vendor/quic-go/connection.go:1022; LC_QRX_PER_TURN in conn.c). They
 * are read eight to a recvmmsg, as before. */
#define LC_RXOPEN_BATCH 32u
#define LC_RXOPEN_PACKET_MAX 2048u /* LC_QCONN_PACKET_MAX */

/* How many datagrams one receive takes. Eight is what the reference gets per `recvmmsg` on a
 * loaded connection, measured 2026-09-01 — its batch (sys_conn_helper_linux.go:24); see the note at
 * the receive loop in conn.c for the profile that made reading in batches necessary. */
#define LC_QRX_BATCH 8u

/* The connection's 1-RTT receive keys, copied for the threads: made from the same key bytes as the
 * contexts ngtcp2 holds, never the same objects, so that nothing ngtcp2 frees or replaces while a
 * batch is being opened is touched by it. Remade only when a key changed. */
typedef struct {
    int      valid;
    int      have_aead, have_hp;
    lc_qaead aead;
    lc_qhp   hp;
    uint8_t  iv[LC_AEAD_NONCE];
    int      key_phase;
    int64_t  max_pkt_num;
    size_t   dcidlen;
} lc_rxkeys;

/* One datagram: as read, as unwrapped, as opened, and the hint for the callbacks. */
typedef struct {
    uint8_t  raw[LC_RXOPEN_PACKET_MAX];
    size_t   raw_len;
    long     plain_len; /* lc_obfs_unwrap's answer: < 0 when the datagram did not unwrap */
    uint8_t  plain[LC_RXOPEN_PACKET_MAX];
    uint8_t  opened[LC_RXOPEN_PACKET_MAX];
    lc_qhint hint;
    int64_t  wall_minus_mono; /* taken right after the recvmmsg this datagram came in */
    union {
        struct cmsghdr align;
        unsigned char  buf[CMSG_SPACE(sizeof(int)) * 2u + CMSG_SPACE(sizeof(struct timespec))];
    } ctl;
    struct msghdr hdr;
    struct iovec  iov;
} lc_rxslot;

typedef struct {
    unsigned  n;
    lc_rxkeys keys;
    lc_rxslot slot[LC_RXOPEN_BATCH];
} lc_rxbatch;

typedef struct lc_rxopen lc_rxopen;

/* The two batches and the threads, one fewer than the processors online: none on a single core,
 * where the loop opens each batch itself when it is finished, through the same code. 0, or -1 when
 * memory or a thread could not be had. `obfs` is the connection's, read-only from here on. */
int  lc_rxopen_new(lc_rxopen **out, const lc_obfs *obfs);
void lc_rxopen_free(lc_rxopen *r);

/* The batch `i` (0 or 1). */
lc_rxbatch *lc_rxopen_batch(lc_rxopen *r, unsigned i);

/* Reads up to LC_RXOPEN_BATCH datagrams from `fd`, eight to a recvmmsg, into `b`, until the socket
 * is dry. Returns how many; when a read failed with anything but EAGAIN, *err is its errno and what
 * came before it is still in the batch, to be processed first, as the loop did. */
unsigned lc_rxopen_fill(lc_rxbatch *b, int fd, int *err);

/* Takes the connection's current receive keys into `b` and hands the batch to the threads. One
 * batch at a time: the one before must have been finished. */
void lc_rxopen_start(lc_rxopen *r, lc_rxbatch *b, ngtcp2_conn *conn);

/* Hands out a batch whose keys are already in place — lc_rxopen_start after the keys; exposed for
 * test/rxopen, which has keys and no connection. Empty batches wake no workers;
 * small batches notify at most one worker per datagram. The pool size is unchanged. */
void lc_rxopen_hand(lc_rxopen *r, lc_rxbatch *b);

/* Opens whatever of the batch in hand no thread has taken yet, then waits for the rest. */
void lc_rxopen_finish(lc_rxopen *r);

/* One datagram, as the threads do it: exposed for test/rxopen, which holds it to ngtcp2's own
 * reading of the same packet. */
void lc_rxopen_slot(const lc_obfs *obfs, lc_rxkeys *k, lc_rxslot *s);

/* The keys, as lc_rxopen_start takes them; exposed for the same test. */
void lc_rxkeys_take(lc_rxkeys *k, ngtcp2_conn *conn);
void lc_rxkeys_free(lc_rxkeys *k);

#endif
