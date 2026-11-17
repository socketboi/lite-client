/* Which port of the node's range the next dial goes to.
 *
 * Its own file because two callers ask it — the first dial in lc_qconn_open and every later move in
 * lc_qconn_hop — and it stood written twice, in two shapes that were already drifting apart. One
 * writing is only an improvement if the one writing is pinned, so test/hop exists alongside it.
 *
 * See hop.c for what the reference does and where. */
#ifndef LC_QUIC_HOP_H
#define LC_QUIC_HOP_H

#include <stdint.h>

#include "core/portunion.h"

/* Picks a port uniformly in [lo, hi] and writes it to *out. Returns 0, or -1 if the system could
 * not provide randomness — the same contract lc_rnd has and for the same reason: a port chosen
 * without randomness is a port chosen predictably, and the caller can act on an error where this
 * cannot.
 *
 * lo is non-zero and hi is not below it. Whether there is a range at all is a different question,
 * asked once where it is decided — lc_qconn_hop_on — and not re-asked here. */
int lc_hop_port(uint16_t lo, uint16_t hi, uint16_t *out);

/* Whether a socket to the node is given DF (IP_PMTUDISC_PROBE). Without hopping, every socket, as
 * quic-go's setDF does at setup; with it, the FIRST socket and none after: the hop conn hands quic-go
 * the SyscallConn of the socket it holds at that moment, so setDF reaches that one, and hop() carries
 * the buffer sizes and deadlines over to each new socket but not DF. Here rather than in conn.c so
 * that test/hop holds the rule; conn.c says where each socket comes from. */
int lc_hop_sets_df(int hopping, int first_socket);

#endif
