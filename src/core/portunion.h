/* The node's ports when they are a hop address, as hysteria parses and draws them. Its own file,
 * outside quic/, because the argument is parsed by both builds of lc-tunnel and only one of them
 * carries the QUIC stack. */
#ifndef LC_CORE_PORTUNION_H
#define LC_CORE_PORTUNION_H

#include <stdint.h>

/* THE NODE'S PORTS WHEN THEY ARE A HOP ADDRESS: what hysteria's ParsePortUnion makes of the port
 * string, normalized — comma-separated single ports and `a-b` ranges, a reversed range turned round,
 * then sorted and every overlapping or touching pair merged
 * (vendor/hysteria/extras/utils/portunion.go:21-60, :64-86). The string is a hop address when it
 * holds a '-' or a ','
 * (isPortHoppingPort, vendor/hysteria/app/cmd/client.go:1257-1261). */
typedef struct {
    uint16_t *lo, *hi; /* n ranges, sorted, disjoint and not touching */
    unsigned  n;
    uint32_t  total;   /* ports in all of them */
} lc_hop_ports;

/* 0, or -1 for a string the reference refuses (ParsePortUnion's nil) or no memory. Frees nothing
 * it was not given; lc_hop_ports_free releases what this allocated. */
int  lc_hop_ports_parse(const char *s, lc_hop_ports *out);
void lc_hop_ports_free(lc_hop_ports *p);

/* A port drawn uniformly from ALL of them, as `rand.Intn(len(addrs))` draws one from the list Ports()
 * expands (vendor/hysteria/extras/transport/udphop/addr.go:34-44,
 * vendor/hysteria/extras/transport/udphop/conn.go:89, :218). 0, or -1
 * without randomness. */
int lc_hop_ports_pick(const lc_hop_ports *p, uint16_t *out);

#endif
