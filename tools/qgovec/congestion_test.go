//go:build qgovec

package congestion

// Laid into vendor/quic-go/internal/congestion by tools/qgovec/gen.sh. The controller a quic-go
// connection starts on — cubicSender with reno set, and its pacer — driven through a script that
// test/hybbr replays on the port (patches/ngtcp2/0018).

import (
	"fmt"
	"testing"
	"time"

	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/utils"
)

func TestQgoVec(t *testing.T) {
	rtt := utils.NewRTTStats()
	c := NewCubicSender(DefaultClock{}, rtt, &utils.ConnectionStats{}, 1250, true, nil)
	now := monotime.Time(1_000_000_000)
	var bif protocol.ByteCount
	var pn protocol.PacketNumber

	fmt.Println("/* Steps: 'S' sends n packets, 'A' acknowledges packets [a, a+n) after an RTT sample of rtt ns,")
	fmt.Println("   'L' declares packet a lost, 'T' moves the clock. After each: the window, the threshold")
	fmt.Println("   (0 for none), the pacer's budget and TimeUntilSend relative to the start (0 for now),")
	fmt.Println("   and the RTT statistics the controller read. */")
	fmt.Println("static const struct { char op; int64_t a, n, dt, rtt; uint64_t cwnd, ssthresh, budget;")
	fmt.Println("                     int64_t next; int64_t srtt, latest, min; } qgo_reno[] = {")
	emit := func(op byte, a, n int64, dt time.Duration, r time.Duration) {
		th := uint64(c.slowStartThreshold)
		if c.slowStartThreshold == protocol.MaxByteCount {
			th = 0
		}
		next := int64(0)
		if tu := c.TimeUntilSend(bif); tu != 0 {
			next = int64(tu) - 1_000_000_000
		}
		fmt.Printf("    { '%c', %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d },\n", op, a, n, dt.Nanoseconds(),
			r.Nanoseconds(), c.GetCongestionWindow(), th, c.pacer.Budget(now), next,
			rtt.SmoothedRTT().Nanoseconds(), rtt.LatestRTT().Nanoseconds(), rtt.MinRTT().Nanoseconds())
	}
	send := func(n int) {
		for i := 0; i < n; i++ {
			bif += 1250
			c.OnPacketSent(now, bif, pn, 1250, true)
			pn++
		}
		emit('S', int64(pn)-int64(n), int64(n), 0, 0)
	}
	ack := func(a, n int, r time.Duration) {
		now = now.Add(r)
		prior := bif
		rtt.UpdateRTT(r, 0)
		c.MaybeExitSlowStart()
		for i := 0; i < n; i++ {
			c.OnPacketAcked(protocol.PacketNumber(a+i), 1250, prior, now)
			bif -= 1250
		}
		emit('A', int64(a), int64(n), 0, r)
	}
	lose := func(a int) {
		prior := bif
		c.OnCongestionEvent(protocol.PacketNumber(a), 1250, prior)
		bif -= 1250
		emit('L', int64(a), 1, 0, 0)
	}
	tick := func(d time.Duration) {
		now = now.Add(d)
		emit('T', 0, 0, d, 0)
	}

	emit('I', 0, 0, 0, 0)
	send(30)
	ack(0, 10, 20*time.Millisecond)
	tick(2 * time.Millisecond)
	send(20)
	ack(10, 10, 22*time.Millisecond)
	lose(20)
	lose(25)
	ack(21, 4, 21*time.Millisecond)
	send(10)
	ack(26, 24, 20*time.Millisecond)
	send(40)
	ack(50, 40, 25*time.Millisecond)
	for i := 0; i < 6; i++ {
		send(30)
		ack(int(pn)-30, 30, 20*time.Millisecond)
	}
	tick(50 * time.Millisecond)
	// An RTT long enough that a datagram's pacing delay passes MinPacingDelay, and one that divides
	// nothing evenly: the next send time is a rounded-up quotient here, where every step above
	// either divides exactly or is held at the 1 ms floor.
	send(7)
	ack(int(pn)-7, 7, 345678901*time.Nanosecond)
	send(40)
	tick(333 * time.Microsecond)
	fmt.Println("};")
}
