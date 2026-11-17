/* The UDP sessions of one Hysteria2 connection, found by id.
 *
 * Split out of conn.c for the reason reasm.c and dgram.c were: conn.c cannot be loaded without the
 * vendored QUIC stack, so for as long as this lived there nothing could ask it anything — and what
 * it answers is which session every arriving datagram belongs to.
 *
 * ⚠️ THERE IS NO CEILING, as the reference has none: its client keeps its sessions in a map by id
 * and NewUDP adds to it for as long as the connection lasts
 * (vendor/hysteria/core/client/udp.go:85-103, :144-171). There were thirty-two here, for the whole
 * connection — every device in the house together, one session per client and destination — and
 * the thirty-third was refused or took the place of the quietest. A household on HTTP/3 with a
 * resolver asking from a fresh port every time is past that without trying, and the reference
 * would have carried every one. What bounds them now is what bounds the reference's: memory, which
 * lc-tunnel asks for before each session it opens (session_new). */
#ifndef LC_QUDPTAB_H
#define LC_QUDPTAB_H

#include "quic/reasm.h"

#include <stdint.h>

/* One UDP session. Fragments are kept in the order they arrive and put together at the end, because
 * nothing in a fragment says where in the packet it belongs — only which number it is — and the
 * ones before it may not have come yet.
 *
 * Its reassembly buffer is taken when the first piece of a split packet arrives, not when the
 * session opens: most sessions never see one — a name lookup or a QUIC packet fits a datagram — and
 * the reference's Defragger holds nothing either until a fragment comes
 * (vendor/hysteria/core/internal/frag/frag.go:36-45, :55-60). */
typedef struct {
    uint32_t id;

    /* Everything a half-arrived packet occupies, and the rules for joining it back up. `r.buf` is
     * NULL until the first fragment, and freed with the session. */
    lc_qreasm r;

    uint16_t next_packet; /* ours, for the packets we split */

    /* WHAT WAITS WHILE THE CLIENT'S SOCKET IS FULL — the reference's ReceiveCh. Every message of the
     * session goes into a channel of udpMessageChanSize, and the session's goroutine takes them out
     * one at a time, puts the packet together and writes it to the client's socket, waiting there
     * when the socket is full; a message that finds the channel full is dropped
     * (vendor/hysteria/core/client/udp.go:17, :36-49, :125-141;
     * vendor/hysteria/app/internal/tproxy/udp_linux.go:97-110). Nothing waits while the socket takes
     * what it is given — the goroutine drains as fast as they come — so this holds nothing until a
     * write would block, and then holds the messages as they arrived, before reassembly, as the
     * channel does. `held` is set while the writer waits; the ring is taken the first time. */
    int       held;
    uint8_t **hq;
    uint16_t *hq_len;
    unsigned  hq_head, hq_n;
} lc_qudp;

/* udpMessageChanSize (vendor/hysteria/core/client/udp.go:17). */
#define LC_QUDP_CHAN 1024u

/* The sessions in the order of their ids, which only grow: a new one goes on the end, a closed one
 * is taken out and those after it close up, so finding one by id is a binary search — the map the
 * reference keeps, without the hashing. Zeroed, it is empty. */
typedef struct {
    lc_qudp *v;
    unsigned n, cap;
    uint32_t last_id; /* the last id handed out; ids start at one, as the reference's do */
} lc_qudptab;

/* The session with this id, or NULL. The pointer lasts until the next open or close. */
lc_qudp *lc_qudptab_find(lc_qudptab *t, uint32_t id);

/* A new session with the next id, or NULL when there is no memory for it — or no id: they stop at
 * INT_MAX, because the caller hands an id out as an int. */
lc_qudp *lc_qudptab_open(lc_qudptab *t);

/* Forgets the session with this id, and its reassembly buffer. An id that is not there is nothing. */
void lc_qudptab_close(lc_qudptab *t, uint32_t id);

/* Every session, and the table; it is empty again afterwards. */
void lc_qudptab_free(lc_qudptab *t);

#endif
