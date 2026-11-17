//go:build qgovec

package utils

// Laid over vendor/quic-go/internal/utils/rand.go by tools/qgovec/gen.sh, in every generator's build:
// the same Rand, except that the four bytes Int31 reads from crypto/rand are QgoRandFill four times
// over. That lets the reference's own packet-number skipping (packet_number_generator.go) run on
// the bytes test/ngpatch hands ngtcp2's rand callback. Int31n is the file's own, word for word
// (rand.go:18-29). Nothing else the generators drive draws from Rand but the connection-ID
// manager, whose draw quic_test.go overrides.

import (
	"encoding/binary"
)

var QgoRandFill byte

// Rand is a wrapper around crypto/rand that adds some convenience functions known from math/rand.
type Rand struct {
	buf [4]byte
}

func (r *Rand) Int31() int32 {
	for i := range r.buf {
		r.buf[i] = QgoRandFill
	}
	return int32(binary.BigEndian.Uint32(r.buf[:]) & ^uint32(1<<31))
}

// copied from the standard library math/rand implementation of Int63n
func (r *Rand) Int31n(n int32) int32 {
	if n&(n-1) == 0 { // n is power of two, can mask
		return r.Int31() & (n - 1)
	}
	max := int32((1 << 31) - 1 - (1<<31)%uint32(n))
	v := r.Int31()
	for v > max {
		v = r.Int31()
	}
	return v % n
}
