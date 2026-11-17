// The REFERENCE congestion controller, driven by hand through a scripted sequence of events, printing
// its state after each one.
//
// Its twin is ours/main.c, which drives the C port (patch 0009) through the SAME script and prints
// the same fields in the same format. Two files, one diff: that is the difference between "the phases
// matched on a stand" and "the numbers are the same, event by event".
//
// The controller is hysteria's own — copied into a scratch module by run.sh, because the package lives
// under core/internal/ and Go will not let anything outside core/ import it. The copy is a build
// artefact in /tmp; vendor/ is not touched.
package main

import (
	"fmt"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"

	"bbrcmp/bbr"
)

// What the sender asks of the connection's RTT statistics. Only MinRTT is read by BBR (getMinRtt and
// calculatePacingRate); the rest exist to satisfy the interface, and returning zero from them is
// what an unmeasured connection looks like.
type rttStats struct{ min time.Duration }

func (r *rttStats) MinRTT() time.Duration                      { return r.min }
func (r *rttStats) LatestRTT() time.Duration                   { return r.min }
func (r *rttStats) SmoothedRTT() time.Duration                 { return r.min }
func (r *rttStats) MeanDeviation() time.Duration               { return 0 }
func (r *rttStats) MaxAckDelay() time.Duration                 { return 0 }
func (r *rttStats) PTO(bool) time.Duration                     { return 0 }
func (r *rttStats) UpdateRTT(_, _ time.Duration)               {}
func (r *rttStats) SetMaxAckDelay(_ time.Duration)             {}
func (r *rttStats) SetInitialRTT(_ time.Duration)              {}

// A clock the script moves, not the wall: a comparison of two implementations cannot depend on when
// it was run.
type clock struct{ now monotime.Time }

func (c *clock) Now() monotime.Time { return c.now }

const (
	packet   = 1280
	perRound = 10
	rtt      = 20 * time.Millisecond
	rounds   = 14
)

func main() {
	clk := &clock{now: monotime.Time(1_000_000_000)}
	stats := &rttStats{}

	sender := bbr.NewBbrSender(clk, packet, bbr.ProfileStandard)
	sender.SetRTTStatsProvider(stats)

	var pn congestion.PacketNumber

	line := func(round int) {
		fmt.Printf("round %02d cwnd=%d pacing=%d slowstart=%d recovery=%d\n",
			round, sender.GetCongestionWindow(), sender.PacingRate(),
			b2i(sender.InSlowStart()), b2i(sender.InRecovery()))
	}

	for round := 1; round <= rounds; round++ {
		first := pn
		inFlight := congestion.ByteCount(0)

		// Ten packets out. quic-go adds the packet to its in-flight total and THEN calls the
		// controller, so the count passed includes the packet itself.
		for i := 0; i < perRound; i++ {
			inFlight += packet
			sender.OnPacketSent(clk.now, inFlight, pn, packet, true)
			pn++
		}

		// A round trip later, all ten acknowledged as one event.
		clk.now = clk.now.Add(rtt)
		stats.min = rtt

		acked := make([]congestion.AckedPacketInfo, 0, perRound)
		for i := 0; i < perRound; i++ {
			acked = append(acked, congestion.AckedPacketInfo{
				PacketNumber: first + congestion.PacketNumber(i),
				BytesAcked:   packet,
			})
		}

		sender.OnCongestionEventEx(inFlight, clk.now, acked, nil)
		line(round)
	}

	// One round with a loss: the first packet declared lost, the rest acknowledged.
	{
		first := pn
		inFlight := congestion.ByteCount(0)

		for i := 0; i < perRound; i++ {
			inFlight += packet
			sender.OnPacketSent(clk.now, inFlight, pn, packet, true)
			pn++
		}

		clk.now = clk.now.Add(rtt)

		acked := make([]congestion.AckedPacketInfo, 0, perRound-1)
		for i := 1; i < perRound; i++ {
			acked = append(acked, congestion.AckedPacketInfo{
				PacketNumber: first + congestion.PacketNumber(i),
				BytesAcked:   packet,
			})
		}
		lost := []congestion.LostPacketInfo{{PacketNumber: first, BytesLost: packet}}

		sender.OnCongestionEventEx(inFlight, clk.now, acked, lost)
		line(rounds + 1)
	}
}

func b2i(b bool) int {
	if b {
		return 1
	}

	return 0
}
