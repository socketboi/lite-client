// A UDP relay that loses and delays packets on purpose, so that two clients can be measured
// against the SAME impaired path.
//
// Why not netem: the build image has no tc, and asking for NET_ADMIN to get one would make the
// stand need a privilege nothing else in this tree needs. This does the same job in the one place
// both clients already have in common — the wire between them and the node — and it does it
// identically in both directions.
//
// It relays for one client at a time, which is what the stand does: the last address that sent a
// packet is where the node's answers go back. Loss is drawn per packet from a seeded source, so a
// run can be repeated exactly; delay is one-way, applied to both directions, so the round trip is
// twice what is asked for.
package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sort"
	"sync"
	"time"
)



// ---- the delay, applied IN ORDER ------------------------------------------------
//
// ⚠️ THIS WAS A time.AfterFunc PER PACKET, and that is not a delay line: every packet got its own
// timer and its own goroutine, and the Go runtime is under no obligation to fire two timers due at
// the same nanosecond in the order they were set. So the relay reordered — mildly, but a QUIC
// sender answers reordering with loss detection, and the two clients being compared do not answer
// it identically. A stand that impairs the two paths differently cannot be used to tell the two
// clients apart, which is the one thing it exists for.
//
// A queue with one goroutine instead: packets leave in the order they arrived, each held until its
// own due time. Loss is still drawn per packet, before the queue, so a dropped packet costs nothing
// here and the seeded draw is unchanged.
type delayed struct {
	pkt []byte
	due time.Time
}

type line struct {
	ch chan delayed
}

func newLine(send func([]byte)) *line {
	l := &line{ch: make(chan delayed, 4096)}

	go func() {
		for d := range l.ch {
			if w := time.Until(d.due); w > 0 {
				time.Sleep(w)
			}
			send(d.pkt)
		}
	}()

	return l
}

// put returns false when the queue is full, which is a drop with a reason: a path that cannot hold
// any more is a path that drops, and pretending otherwise would block the reader and stop the relay.
func (l *line) put(pkt []byte, due time.Time) bool {
	select {
	case l.ch <- delayed{pkt: pkt, due: due}:
		return true
	default:
		return false
	}
}

// ---- the shape of what the client sends ----------------------------------------
//
// WHY THIS IS HERE AND NOT IN A CAPTURE. What a path sees of a QUIC sender, without decrypting
// anything, is when its datagrams arrive: a sender that empties its window in one burst and one
// that spreads the same bytes over the same interval look nothing alike from the outside. The
// congestion controller and the pacer decide that shape, and this relay is already the one place
// both clients have in common — every datagram either of them sends to the node passes through
// here, on the same path, with the same impairment.
//
// What is reported is the gap between consecutive datagrams from the client, as a histogram rather
// than a mean: a mean cannot tell "eight together then a pause" from "one every millisecond", and
// that difference is the whole question.
type shape struct {
	mu      sync.Mutex
	last    time.Time
	gaps    []time.Duration
	bursts  map[int]int // how many runs of N datagrams arrived inside burstGap of each other
	run     int
	sizes   []int
	maxSize int
}

// A run ends when a gap this long or longer appears. 200 µs is chosen against what it has to
// separate: datagrams handed to the kernel in one batch land microseconds apart, while anything the
// pacer held back waits at least a scheduler tick.
const burstGap = 200 * time.Microsecond

func newShape() *shape { return &shape{bursts: map[int]int{}} }

func (s *shape) saw(now time.Time, size int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sizes = append(s.sizes, size)
	if size > s.maxSize {
		s.maxSize = size
	}


	if !s.last.IsZero() {
		d := now.Sub(s.last)
		s.gaps = append(s.gaps, d)

		if d < burstGap {
			s.run++
		} else {
			if s.run > 0 {
				s.bursts[s.run+1]++
			}
			s.run = 0
		}
	}

	s.last = now
}

func (s *shape) report(who string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.run > 0 {
		s.bursts[s.run+1]++
		s.run = 0
	}

	if len(s.gaps) == 0 {
		fmt.Printf("shape %s: nothing arrived\n", who)
		return
	}

	sorted := make([]time.Duration, len(s.gaps))
	copy(sorted, s.gaps)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	pct := func(p float64) time.Duration { return sorted[int(float64(len(sorted)-1)*p)] }

	// The buckets are the decisions a sender makes, not round numbers: under 50 µs is the same
	// batch handed to the kernel, under 1 ms is a wait finer than a scheduler tick, and 1 ms and up
	// is a sender that was told to wait.
	var b [4]int
	for _, d := range sorted {
		switch {
		case d < 50*time.Microsecond:
			b[0]++
		case d < time.Millisecond:
			b[1]++
		case d < 5*time.Millisecond:
			b[2]++
		default:
			b[3]++
		}
	}

	// The SIZE of what arrives, because a datagram carrying eight QUIC packets is one arrival to a
	// path and eight to a protocol, and the two clients need not agree about which they send.
	var total int
	for _, v := range s.sizes {
		total += v
	}
	// SMALL DATAGRAMS, COUNTED SEPARATELY, because the means said something the rest of this report
	// could not explain: on the same transfer the reference sent 48 902 datagrams averaging 1147
	// bytes where this client sent 39 811 averaging 1313. More datagrams, each smaller, for the same
	// payload — which is what a sender looks like when it puts something OTHER than stream data on
	// the wire between the full packets. An acknowledgement on its own is a few dozen bytes, and a
	// run of two or three that a path sees may be "one small, two full" rather than a short burst of
	// data. The burst histogram cannot tell those apart; this line can.
	//
	// The threshold is 300 bytes: well above an ACK-only QUIC packet with its header and AEAD tag,
	// well below anything carrying a useful slice of a stream at this MTU.
	small, mid := 0, 0
	for _, z := range s.sizes {
		if z < 300 {
			small++
		} else if z < 1000 {
			mid++
		}
	}
	fmt.Printf("shape %s: sizes — under 300 B: %d (%.1f%%), 300-1000 B: %d, rest full\n",
		who, small, float64(small)*100/float64(len(s.sizes)), mid)

	fmt.Printf("shape %s: %d bytes in %d datagrams, mean %d, largest %d\n",
		who, total, len(s.sizes), total/len(s.sizes), s.maxSize)

	fmt.Printf("shape %s: %d datagrams, gaps p50 %v p90 %v p99 %v\n",
		who, len(s.gaps)+1, pct(0.50).Round(time.Microsecond),
		pct(0.90).Round(time.Microsecond), pct(0.99).Round(time.Microsecond))
	fmt.Printf("shape %s: gaps <50us %d (%.0f%%), <1ms %d (%.0f%%), <5ms %d (%.0f%%), >=5ms %d\n",
		who, b[0], 100*float64(b[0])/float64(len(sorted)),
		b[1], 100*float64(b[1])/float64(len(sorted)),
		b[2], 100*float64(b[2])/float64(len(sorted)), b[3])

	// Burst lengths, largest first, three at most: what a path sees as one arrival.
	type kv struct {
		n, c int
	}
	var runs []kv
	for n, c := range s.bursts {
		runs = append(runs, kv{n, c})
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].c > runs[j].c })
	line := ""
	for i, r := range runs {
		if i == 3 {
			break
		}
		line += fmt.Sprintf(" %d×%d", r.c, r.n)
	}
	fmt.Printf("shape %s: commonest runs (count×datagrams):%s\n", who, line)
}

func main() {
	listen := flag.String("listen", ":4443", "address to listen on")
	remote := flag.String("remote", "", "address of the node")
	loss := flag.Float64("loss", 0.01, "probability that a packet is dropped, each way")
	delay := flag.Duration("delay", 25*time.Millisecond, "one-way delay")
	seed := flag.Int64("seed", 1, "seed for the loss draw")
	shapeOf := flag.String("shape", "", "name to report the client's sending shape under, at each tick")
	flag.Parse()

	if *remote == "" {
		fmt.Fprintln(os.Stderr, "impair: -remote is required")
		os.Exit(2)
	}

	upstream, err := net.ResolveUDPAddr("udp", *remote)
	if err != nil {
		fmt.Fprintln(os.Stderr, "impair: resolve:", err)
		os.Exit(1)
	}
	front, err := net.ListenPacket("udp", *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "impair: listen:", err)
		os.Exit(1)
	}
	back, err := net.ListenPacket("udp", ":0")
	if err != nil {
		fmt.Fprintln(os.Stderr, "impair: listen back:", err)
		os.Exit(1)
	}

	var (
		mu     sync.Mutex
		client net.Addr
		rng    = rand.New(rand.NewSource(*seed))
		sent, dropped int
	)

	// One source for both directions, so a run is reproducible from the seed alone.
	drop := func() bool {
		mu.Lock()
		defer mu.Unlock()
		sent++
		if rng.Float64() < *loss {
			dropped++
			return true
		}
		return false
	}

	toNode := newLine(func(p []byte) { back.WriteTo(p, upstream) })
	toClient := newLine(func(p []byte) {
		mu.Lock()
		to := client
		mu.Unlock()
		if to == nil {
			return
		}
		front.WriteTo(p, to)
	})

	sh := newShape()
	// AND THE SAME FOR WHAT THE NODE SENDS BACK, which on a one-way transfer (the stand's SINK=1) is
	// almost nothing but acknowledgements — the clock the sender's pacer and window run on. Two clients
	// talking to the same server get different ack clocks only because they sent differently, and a
	// hole in that clock is a pause the sender has to wait out on its pacer's timer instead. Taken as
	// the node hands it over, before the delay line, so it is the node's shape and not the path's.
	fromNode := newShape()

	// client -> node
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := front.ReadFrom(buf)
			if err != nil {
				return
			}
			sh.saw(time.Now(), n)
			mu.Lock()
			client = from
			mu.Unlock()
			if drop() {
				continue
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			toNode.put(pkt, time.Now().Add(*delay))
		}
	}()

	// node -> client
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := back.ReadFrom(buf)
			if err != nil {
				return
			}
			fromNode.saw(time.Now(), n)
			if drop() {
				continue
			}
			mu.Lock()
			to := client
			mu.Unlock()
			if to == nil {
				continue
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			toClient.put(pkt, time.Now().Add(*delay))
		}
	}()

	// A line a run can be read back from: how many packets went through, how many were taken, and —
	// when the stand asked for it — the shape the client sent in.
	for range time.Tick(time.Second) {
		mu.Lock()
		fmt.Printf("impair: %d packets, %d dropped\n", sent, dropped)
		mu.Unlock()

		if *shapeOf != "" {
			sh.report(*shapeOf)
			fromNode.report(*shapeOf + " <- node")
		}
	}
}
