// Throughput of the DATAGRAM path: send N packets of size S from ONE socket and count how many come
// back from the echo.
//
// WHY ONE SOCKET, which is the whole point of the program. `dig` opens a fresh socket per query, so
// a loop over `dig` measures N clients rather than one client with N destinations — that mistake
// produced a stand run whose "two destinations" were two clients, and the number it reported was
// meaningless. The case worth measuring is the one the session model exists for: a single client
// socket carrying a stream of datagrams, which is also how games and WebRTC behave.
//
//   go build -o /tmp/udpbench .
//   /tmp/udpbench <node-public-ip>:18081 2000 1200        # count, size
//   /tmp/udpbench <node-public-ip>:18081 2000 1200 2      # ... with 2 ms between sends
//
// ⚠️ PACING IS NOT COSMETIC. Sent flat out, the whole burst lands in the tens of milliseconds while
// the VLESS stream for that destination is still being opened; the datagrams queue, the queue
// overflows, and what gets reported is the drop policy rather than the throughput. The reference
// behaves the same way by design — `pipe.New(pipe.DiscardOverflow(), pipe.WithSizeLimit(16*1024))`
// (app/proxyman/inbound/worker.go:289) — so this is a property of the thing being measured, not a
// defect to tune around. The default pause of 1 ms every 16 packets exists for that reason; raise
// it with the fourth argument when the loss figure looks like a cliff rather than a curve.
//
// ⚠️ AND THE LOSS FIGURE IS NOT ALL TUNNEL. UDP echo over a real path loses packets on its own.
// Run the same command against the target DIRECTLY, without the tunnel, and subtract — a stand that
// reports only the through-tunnel number cannot tell a client that drops from a network that does.
package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: udpbench HOST:PORT COUNT SIZE [DELAY_MS]")
		os.Exit(2)
	}
	target := os.Args[1]
	count, _ := strconv.Atoi(os.Args[2])
	size, _ := strconv.Atoi(os.Args[3])
	delayMs := 0
	if len(os.Args) > 4 {
		delayMs, _ = strconv.Atoi(os.Args[4])
	}

	ua, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "resolve:", err)
		os.Exit(1)
	}
	pc, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	defer pc.Close()

	payload := make([]byte, size)
	var got, gotBytes int
	var mu sync.Mutex
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 65535)
		for {
			// Three seconds of silence ends the run: long enough that a slow reply is not counted
			// as a loss, short enough that a dead path does not hang the stand.
			_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				close(done)
				return
			}
			mu.Lock()
			got++
			gotBytes += n
			mu.Unlock()
		}
	}()

	start := time.Now()
	sent := 0
	for i := 0; i < count; i++ {
		if _, err := pc.WriteTo(payload, ua); err != nil {
			break
		}
		sent++
		if delayMs > 0 {
			time.Sleep(time.Duration(delayMs) * time.Millisecond)
		} else if i%16 == 15 {
			time.Sleep(time.Millisecond)
		}
	}
	<-done
	el := time.Since(start)
	mu.Lock()
	defer mu.Unlock()
	fmt.Printf("sent %d packets of %d bytes, %d came back (%d bytes) in %.2fs\n",
		sent, size, got, gotBytes, el.Seconds())
	if el.Seconds() > 0 {
		fmt.Printf("echo rate: %.2f Mbit/s, delivered %.1f%%\n",
			float64(gotBytes*8)/el.Seconds()/1e6, 100*float64(got)/float64(sent))
	}
}
