/* Go's map, as far as the ORDER of a walk goes — nothing else about it.
 *
 * Three things this client sends are the order in which the reference walks a Go map: hysteria's
 * three auth headers (quic-go ranges over req.Header), the headers of each HTTP/2 request x/net
 * writes (it ranges over req.Header, vendor/x-net/internal/httpcommon/request.go:156), and the
 * path REALITY's spider asks for (it walks its path set to a drawn index,
 * vendor/Xray-core/transport/internet/reality/reality.go:313-323). A walk in Go is neither the
 * insertion order nor a shuffle: it is the layout of the map's slots, read from a random starting
 * point. For a small map that makes the insertion order the likeliest by far; for a larger one the
 * layout comes from the keys' hashes under a seed the map draws once and keeps.
 *
 * So this models what the walk depends on and only that, from the Go 1.24+ runtime in
 * GOROOT/src/internal/runtime/maps: up to eight keys sit in one group, in the order they came
 * (putSlotSmall takes the first empty slot,
 * GOROOT/src/internal/runtime/maps/map.go:536-596); the ninth moves them into a table of sixteen
 * slots (growToTable, GOROOT/src/internal/runtime/maps/map.go:608-635), after which a key goes to
 * the first empty slot of the first group its hash's probe sequence reaches with room (PutSlot,
 * GOROOT/src/internal/runtime/maps/table.go:266-370); a table that has used up seven eighths of its
 * slots doubles, re-placing every key in its old slot order (rehash, grow,
 * GOROOT/src/internal/runtime/maps/table.go:1145-1260), until it would pass 1024 slots — then it
 * splits in two by the next bit of the hash, and the directory of tables the map is doubles when
 * the split table was as deep as it (split, installTableSplit,
 * GOROOT/src/internal/runtime/maps/table.go:1179-1225,
 * GOROOT/src/internal/runtime/maps/map.go:363-395). A walk starts at a random table and a random
 * slot, and reads every table from there in directory order and every slot of
 * each from the same offset, wrapping (Iter.Init and Iter.Next,
 * GOROOT/src/internal/runtime/maps/table.go:678-700, :810-1082). The hash of each key is drawn when
 * it is inserted and kept — Go's seed is fixed for the map's lifetime, and a hash under a random
 * seed is as good as a random number for where it lands.
 *
 * A layout is a function of the hashes in the order they came, so that is all a map is here: the
 * walk builds the layout from them. Which lets a map of any size live wherever its hashes do —
 * in memory other processes share, for the spider's paths (reality/paths.c).
 *
 * Held to Go by test/gomap, against distributions tools/gomap measures from Go's own maps. */
#ifndef LC_GOMAP_H
#define LC_GOMAP_H

#include <stdint.h>

/* The maps this client builds of a fixed set of keys — a request's header map: fourteen browser
 * headers, the cookie, a referer, an Authorization at most. The path set is not one of these; see
 * lc_gomap_order. */
#define LC_GOMAP_KEYS 64u

typedef struct {
    unsigned n;    /* keys inserted, numbered 0..n-1 in insertion order */
    unsigned hint; /* make(map, hint), 0 for none */
    uint64_t hash[LC_GOMAP_KEYS];
} lc_gomap;

void lc_gomap_init(lc_gomap *m);

/* Inserts the next key — its number is the count before the call. -1 when the map is full or no
 * randomness could be had for its hash. The caller must not insert a key twice: Go would find the
 * existing slot, and this does not look. */
int lc_gomap_insert(lc_gomap *m);

/* One walk: the key numbers in the order Go would visit them, `n` of them into `order`. -1 when no
 * randomness could be had for the starting point, or no memory for the layout. */
int lc_gomap_walk(const lc_gomap *m, unsigned *order);

/* A fresh map with `n` keys inserted in order, walked once — what `range` over a just-built
 * http.Header gives. */
int lc_gomap_fresh_walk(unsigned n, unsigned *order);

/* make(map, hint): past eight, tables sized for `hint` from the start rather than a group that
 * grows into one — the capacity `hint * 8 / 7` over as many tables of at most 1024 as that needs, a
 * power of two of them (NewMap, GOROOT/src/internal/runtime/maps/map.go:264-323, and newTable,
 * GOROOT/src/internal/runtime/maps/table.go:73-99). Header.Clone makes its map this way. */
void lc_gomap_init_hint(lc_gomap *m, unsigned hint);

/* `for k := range from { to[k] = … }`: one walk of `from`, each key inserted into `to` in the order
 * met — except `skip`, when it is a key of `from` (~0u for none). `to_from[i]` receives which key of
 * `from` the i-th key of `to` is. Returns how many were copied, -1 when `to` is full or no
 * randomness could be had. */
int lc_gomap_copy(const lc_gomap *from, lc_gomap *to, unsigned skip, unsigned *to_from);

/* The general one: a map made with `hint` (0 for none) and given `n` keys in order with these
 * hashes, walked from the offsets Iter.Init draws — `entry_off`, the slot every table's walk starts
 * at, and `dir_off`, the table the walk starts at. Its key numbers into `order`. -1 without memory. */
int lc_gomap_order(const uint64_t *hash, unsigned n, unsigned hint, uint64_t entry_off,
                   uint64_t dir_off, unsigned *order);

/* The key at one zero-based walk position, with identical layout/offset rules.
 * No full order array is needed; traversal ends at that position. Returns -1
 * for an invalid rank/output pointer or allocation failure. */
int lc_gomap_at(const uint64_t *hash, unsigned n, unsigned hint, uint64_t entry_off,
                uint64_t dir_off, unsigned rank, unsigned *key);

#endif
