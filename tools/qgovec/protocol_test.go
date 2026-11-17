//go:build qgovec

package protocol

// Laid into vendor/quic-go/internal/protocol by tools/qgovec/gen.sh through `go test -overlay`;
// vendor/ itself is never written. Prints the packet-number lengths quic-go chooses.

import (
	"fmt"
	"testing"
)

func TestQgoVec(t *testing.T) {
	type c struct{ pn, la, cw PacketNumber }
	cases := []c{
		{1, InvalidPacketNumber, 0}, {1, InvalidPacketNumber, 32}, {62, InvalidPacketNumber, 0},
		{63, InvalidPacketNumber, 0}, {100, 36, 0}, {100, 37, 0}, {100, 99, 63}, {100, 99, 64},
		{20000, 3616, 0}, {20000, 3617, 0}, {20000, 19999, 16383}, {20000, 19999, 16384},
		{1 << 20, 0, 0}, {5, 4, 20000},
	}
	fmt.Println("static const struct { int64_t pn, largest_acked, cwnd_pkts; uint8_t len; } qgo_pn_chrome[] = {")
	for _, x := range cases {
		fmt.Printf("    { %d, %d, %d, %d },\n", x.pn, x.la, x.cw, PacketNumberLengthForHeaderChrome(x.pn, x.la, x.cw))
	}
	fmt.Println("};")
	fmt.Println("static const struct { int64_t pn, largest_acked; uint8_t len; } qgo_pn_default[] = {")
	for _, x := range [][2]PacketNumber{{0, InvalidPacketNumber}, {1, 0}, {1 << 15, -1}, {1<<15 - 2, InvalidPacketNumber},
		{1 << 15, 0}, {1<<15 + 5, 5}, {1<<15 + 5, 6}, {1 << 23, 0}, {1<<23 + 9, 10}, {1 << 24, 0}} {
		fmt.Printf("    { %d, %d, %d },\n", x[0], x[1], PacketNumberLengthForHeader(x[0], x[1]))
	}
	fmt.Println("};")
}
