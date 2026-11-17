//go:build qtrust

package handshake

import (
	"fmt"
	"os"
	"testing"
)

// Overlay into the reference's internal/handshake, never into the capture tool's copy.
func TestTrustAnchorVec(t *testing.T) {
	f, err := os.Create(os.Getenv("LC_TRUST_ANCHORS_OUT"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fmt.Fprintln(f, "/* Generated from vendor/quic-go's chromeTrustAnchorsData; do not edit. */")
	fmt.Fprintf(f, "static const uint8_t reference_trust_anchors[%d] = {", len(chromeTrustAnchorsData))
	for _, b := range chromeTrustAnchorsData {
		fmt.Fprintf(f, "0x%02x,", b)
	}
	fmt.Fprintln(f, "};")
}
