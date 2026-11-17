package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestQUICSpecCopyIncludesTrustAnchors(t *testing.T) {
	const upstream = "../../vendor/quic-go/internal/handshake/chrome_client_hello.go"
	src, err := os.ReadFile("quic.go")
	if err != nil {
		t.Fatal(err)
	}
	if err := checkQUICSpecCopy(upstream, "quic.go"); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct{ name, from, to string }{
		{"extension ID", "uint16 = 0xca34", "uint16 = 0xca35"},
		{"anchor ID", "{0x82, 0xdf, 0x13, 0x02, 0x01}", "{0x82, 0xdf, 0x13, 0x02, 0x02}"},
		{"encoder", "slices.SortFunc(sorted, bytes.Compare)", "slices.SortFunc(ids, bytes.Compare)"},
		{"data binding", "encodeTrustAnchorIDs(chromeTrustAnchorIDs)", "encodeTrustAnchorIDs(nil)"},
	} {
		t.Run(change.name, func(t *testing.T) {
			copy := strings.Replace(string(src), change.from, change.to, 1)
			if copy == string(src) {
				t.Fatal("mutation did not change the isolated copy")
			}
			path := filepath.Join(t.TempDir(), "quic.go")
			if err := os.WriteFile(path, []byte(copy), 0600); err != nil {
				t.Fatal(err)
			}
			if err := checkQUICSpecCopy(upstream, path); err == nil {
				t.Fatal("changed trust-anchor declaration accepted")
			}
		})
	}
}
