package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Each case is a comment this tree carried, or one that was right, against the vendored file it
// cites. The wrong ones are the numbers that stood here before 2026-09-24 — so a rule that stops
// working lets one of them through, and a rule that grows too eager fails one of the right ones.
// The vendored trees sit at the revisions check-vendor holds them to, so the numbers do not move
// under the test.
var cases = []struct {
	name, ext, text string
	bad             bool
}{
	{"a quote in its lines", ".c", "/* Go answers `c.sendAlert(alertDecodeError)` and \"received empty certificates message\"\n * (vendor/utls/handshake_client_tls13.go:759-762). */\n", false},
	{"a quote thirteen lines away", ".c", "/* Go answers `c.sendAlert(alertDecodeError)` and \"received empty certificates message\"\n * (vendor/utls/handshake_client_tls13.go:806-809). */\n", true},
	{"a quote in the list's second place", ".c", "/* `c.sendAlert(alertDecodeError)` (vendor/utls/handshake_client_tls13.go:1-2, :759-762). */\n", false},
	{"a quote after its citation", ".c", "/* vendor/hysteria/app/cmd/client.go:285 asks `if hyConfig.ServerAddr.Network() == \"udphop\"`,\n * and the hop interval is read either way (:278). */\n", false},
	{"a paraphrase is not a quote", ".c", "/* \"as all records are one version\" (vendor/utls/conn.go:1-2). */\n", false},
	{"one word in quotes is prose", ".c", "/* the \"silent\" branch (vendor/hysteria/core/client/client.go:126). */\n", false},
	{"a hyphenated word in quotes is prose", ".c", "/* what \"quic-go\" does (vendor/quic-go/connection.go:600). */\n", false},
	{"a range into the next doc comment", ".c", "/* pipe.Write (vendor/x-net/http2/pipe.go:87-108). */\n", false},
	{"a range into the next function's code", ".c", "/* pipe.Write (vendor/x-net/http2/pipe.go:87-130). */\n", true},
	{"a range across two functions", ".c", "/* readServerParameters wants EncryptedExtensions (vendor/utls/handshake_client_tls13.go:669-706). */\n", true},
	{"the function it names", ".c", "/* readServerParameters wants EncryptedExtensions (vendor/utls/handshake_client_tls13.go:625-700). */\n", false},
	{"a function it names, elsewhere", ".c", "/* processPing (vendor/x-net/http2/transport.go:2610-2640). */\n", true},
	{"a caller of the function it names", ".c", "/* readUint24LengthPrefixed (vendor/utls/handshake_messages.go:1599-1610). */\n", false},
	{"a C function it names", ".c", "/* `ngtcp2_conn_set_remote_transport_params` (vendor/ngtcp2/lib/ngtcp2_conn.c:11657). */\n", false},
	{"a C function it names, elsewhere", ".c", "/* `ngtcp2_conn_set_remote_transport_params` (vendor/ngtcp2/lib/ngtcp2_conn.c:11781). */\n", true},
	{"the number on the line", ".c", "#define G 2.885 /* vendor/hysteria/core/internal/congestion/bbr/bbr_sender.go:38 */\n", false},
	{"the number a line away", ".c", "#define G 2.885 /* vendor/hysteria/core/internal/congestion/bbr/bbr_sender.go:37 */\n", true},
	{"the Go function the C one ports", ".c", "/* vendor/hysteria/core/internal/congestion/bbr/bbr_sender.go:674-689 */\nstatic long hybbr_get_min_rtt(void) {\n  return 0;\n}\n", false},
	{"another Go function than the C one ports", ".c", "/* vendor/hysteria/core/internal/congestion/bbr/bbr_sender.go:709-718 */\nstatic long hybbr_get_min_rtt(void) {\n  return 0;\n}\n", true},
	{"a bare name after GOROOT is the toolchain's", ".c", "/* PutSlot (GOROOT/src/internal/runtime/maps/map.go:486-596, table.go:266-380). */\n", false},
	{"a citation broken across lines", ".c", "/* `if c.buffering {` (vendor/utls/conn.go:\n * 950-959). */\n", false},
	{"a citation broken across lines, wrong", ".c", "/* `if c.buffering {` (vendor/utls/conn.go:\n * 960-969). */\n", true},
	{"a code block, one line short", ".c", "/* One more packet:\n *\n *     case ackhandler.SendPacingLimited:\n *         return c.maybeSendAckOnlyPacket(now)\n *                          (vendor/quic-go/connection.go:2496-2504)\n */\n", true},
	{"a code block", ".c", "/* One more packet:\n *\n *     case ackhandler.SendPacingLimited:\n *         return c.maybeSendAckOnlyPacket(now)\n *                          (vendor/quic-go/connection.go:2496-2505)\n */\n", false},
	{"a patch's code is not its comment", ".patch", "Subject.\n\n--- a/x.c\n+++ b/x.c\n@@ -1,3 +1,4 @@\n     } else {\n+      /* pads its leading Initial packet (vendor/quic-go/packet_packer.go:324-333). */\n", false},
	{"a hunk cut short inside a comment ends it", ".patch", "Subject.\n\n--- a/x.c\n+++ b/x.c\n@@ -1,2 +1,2 @@\n   /* a comment the hunk\n      cuts short\n@@ -9,3 +9,4 @@\n     } else {\n+      /* initialPaddingLen (vendor/quic-go/packet_packer.go:347-356). */\n", false},
}

func TestCases(t *testing.T) {
	dir := t.TempDir()
	for i, c := range cases {
		findings, unres = nil, map[string]int{}
		p := filepath.Join(dir, strings.ReplaceAll(c.name, " ", "_")+c.ext)
		if err := os.WriteFile(p, []byte(c.text), 0o644); err != nil {
			t.Fatal(err)
		}
		scan(p)
		if got := len(findings) > 0; got != c.bad {
			var why []string
			for _, f := range findings {
				why = append(why, f.lines...)
			}
			t.Errorf("case %d, %s: misplaced = %v, want %v %v", i, c.name, got, c.bad, why)
		}
	}
}

func TestMain(m *testing.M) {
	if err := os.Chdir("../../.."); err != nil {
		panic(err)
	}
	if _, err := os.Stat("vendor/utls"); err != nil {
		panic("vendor/ is needed: the cases cite it")
	}
	indexVendor()
	ourNames = map[string]bool{}
	os.Exit(m.Run())
}
