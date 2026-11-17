//go:build qgovec

package ackhandler

// Laid into vendor/quic-go/internal/ackhandler by tools/qgovec/gen.sh. quic-go's sentPacketHandler —
// its loss detection and the RTT estimator behind it — driven through five scripts that
// test/ngpatch replays on the patched ngtcp2 connection:
//
//   - the order lost data is handed back for retransmission when one ACK declares several
//     packets lost;
//   - the packet threshold with a large flight;
//   - a loss window long enough for RFC 9002's persistent congestion, which quic-go does not have;
//   - RTT samples with and without an ACK delay, above and below max_ack_delay;
//   - a Retry, which quic-go takes for an RTT sample;
//   - ECN: which packets its ecnTracker marks, and the verdicts it reaches, over the scripts in
//     qgoECNScripts.

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/utils"
	"github.com/apernet/quic-go/internal/wire"
)

type qgoLost struct {
	order *[]string
}

func (l qgoLost) OnAcked(wire.Frame) {}
func (l qgoLost) OnLost(f wire.Frame) {
	s := f.(*wire.StreamFrame)
	*l.order = append(*l.order, fmt.Sprintf("{ %d, %d }", s.StreamID, s.Offset))
}

type qgoNop struct{}

func (qgoNop) OnAcked(wire.Frame) {}
func (qgoNop) OnLost(wire.Frame)  {}

func qgoHandler() (*sentPacketHandler, *utils.RTTStats) {
	rtt := utils.NewRTTStats()
	rtt.SetMaxAckDelay(25 * time.Millisecond)
	h := NewSentPacketHandler(0, 1250, rtt, &utils.ConnectionStats{}, true, false, nil,
		protocol.PerspectiveClient, false, nil, utils.DefaultLogger).(*sentPacketHandler)
	h.DropPackets(protocol.EncryptionInitial, 0)
	h.DropPackets(protocol.EncryptionHandshake, 0)
	return h, rtt
}

func TestQgoVec(t *testing.T) {
	t0 := monotime.Time(1_000_000_000)
	var order []string
	send := func(h *sentPacketHandler, at monotime.Time, pn protocol.PacketNumber, id protocol.StreamID,
		off, n protocol.ByteCount) {
		f := &wire.StreamFrame{StreamID: id, Offset: off, Data: make([]byte, n)}
		h.SentPacket(at, pn, protocol.InvalidPacketNumber, []StreamFrame{{Frame: f, Handler: qgoLost{&order}}},
			nil, protocol.Encryption1RTT, protocol.ECNNon, n+30, false, false)
	}
	ack := func(h *sentPacketHandler, at monotime.Time, delay time.Duration, ranges ...wire.AckRange) {
		if _, err := h.ReceivedAck(&wire.AckFrame{AckRanges: ranges, DelayTime: delay}, protocol.Encryption1RTT, at); err != nil {
			t.Fatal(err)
		}
	}

	// ---- one ACK, three packets lost: stream 4's two, then stream 0's.
	h, _ := qgoHandler()
	for i := 0; i < 7; i++ {
		id, off, n := protocol.StreamID(8), protocol.ByteCount(10*(i-3)), protocol.ByteCount(10)
		switch i {
		case 0, 1:
			id, off, n = 4, protocol.ByteCount(1100*i), 1100
		case 2:
			id, off, n = 0, 0, 1100
		}
		send(h, t0.Add(time.Duration(i+1)*time.Millisecond), protocol.PacketNumber(i), id, off, n)
	}
	ack(h, t0.Add(27*time.Millisecond), 0, wire.AckRange{Smallest: 3, Largest: 6})
	fmt.Println("/* The stream frames handed back as lost, in order, by one ACK of packets 3-6 of seven:")
	fmt.Println("   packets 0 and 1 carried stream 4, packet 2 stream 0. */")
	fmt.Printf("static const struct { int64_t stream_id; uint64_t offset; } qgo_lost_order[] = { %s };\n",
		join(order))

	// ---- the packet threshold with a hundred packets out.
	h, _ = qgoHandler()
	send(h, t0, 0, 8, 0, 100)
	ack(h, t0.Add(20*time.Millisecond), 0, wire.AckRange{Smallest: 0, Largest: 0})
	t1 := t0.Add(21 * time.Millisecond)
	for i := 1; i <= 100; i++ {
		send(h, t1.Add(time.Duration(i)*time.Microsecond), protocol.PacketNumber(i), 8, protocol.ByteCount(100*i), 100)
	}
	order = order[:0]
	ack(h, t1.Add(20*time.Millisecond), 0, wire.AckRange{Smallest: 50, Largest: 50})
	fmt.Println("/* After an RTT sample of 20 ms, packets 1-100 out 1 us apart and only packet 50")
	fmt.Println("   acknowledged, 20 ms later: the number declared lost. */")
	fmt.Printf("#define QGO_THRESH_LOST %d\n", len(order))

	// ---- a loss window of a second: persistent congestion in RFC 9002, nothing in quic-go.
	h, rtt := qgoHandler()
	send(h, t0, 0, 8, 0, 100)
	ack(h, t0.Add(20*time.Millisecond), 0, wire.AckRange{Smallest: 0, Largest: 0})
	t2 := t0.Add(30 * time.Millisecond)
	send(h, t2, 1, 8, 100, 100)
	send(h, t2.Add(500*time.Millisecond), 2, 8, 200, 100)
	send(h, t2.Add(1000*time.Millisecond), 3, 8, 300, 100)
	send(h, t2.Add(1001*time.Millisecond), 4, 8, 400, 100)
	send(h, t2.Add(1002*time.Millisecond), 5, 8, 500, 100)
	ack(h, t2.Add(1022*time.Millisecond), 0, wire.AckRange{Smallest: 5, Largest: 5})
	fmt.Println("/* The RTT statistics after packets 1 and 2 of five, sent 500 ms apart, are lost by one")
	fmt.Println("   ACK — a window RFC 9002 calls persistent congestion. */")
	fmt.Printf("#define QGO_PC_SRTT_NS %dll\n#define QGO_PC_MIN_NS %dll\n", rtt.SmoothedRTT().Nanoseconds(),
		rtt.MinRTT().Nanoseconds())

	// ---- RTT samples, one packet and one ACK at a time.
	h, rtt = qgoHandler()
	type sample struct{ rtt, delay time.Duration }
	samples := []sample{
		{20 * time.Millisecond, 0}, {22 * time.Millisecond, 0}, {21 * time.Millisecond, 0},
		{30 * time.Millisecond, 8 * time.Millisecond}, {30 * time.Millisecond, 40 * time.Millisecond},
		{19*time.Millisecond + 333*time.Microsecond, 0}, {25 * time.Millisecond, 7 * time.Millisecond},
		{19 * time.Millisecond, 2 * time.Millisecond}, {40*time.Millisecond + 1234*time.Nanosecond, 0},
		{21 * time.Millisecond, 24 * time.Millisecond},
		// a delay beyond max_ack_delay that decides the sample: capped at 25 ms it is taken off
		{60 * time.Millisecond, 40 * time.Millisecond},
	}
	fmt.Println("/* One packet sent and acknowledged after rtt with the ACK Delay field saying delay; after")
	fmt.Println("   each, the estimator's latest, min, smoothed and mean deviation. */")
	fmt.Println("static const struct { int64_t rtt, delay, latest, min, smoothed, meandev; } qgo_rtt[] = {")
	at := t0
	for i, s := range samples {
		send(h, at, protocol.PacketNumber(i), 8, protocol.ByteCount(100*i), 100)
		at = at.Add(s.rtt)
		ack(h, at, s.delay, wire.AckRange{Smallest: protocol.PacketNumber(i), Largest: protocol.PacketNumber(i)})
		fmt.Printf("    { %d, %d, %d, %d, %d, %d },\n", s.rtt.Nanoseconds(), s.delay.Nanoseconds(),
			rtt.LatestRTT().Nanoseconds(), rtt.MinRTT().Nanoseconds(), rtt.SmoothedRTT().Nanoseconds(),
			rtt.MeanDeviation().Nanoseconds())
		at = at.Add(time.Millisecond)
	}
	fmt.Println("};")

	// ---- a Retry, 2 ms and 30 ms after the first Initial: quic-go takes it for an RTT sample, of at
	// least minRTTAfterRetry.
	for _, d := range []time.Duration{2 * time.Millisecond, 30 * time.Millisecond} {
		rs := utils.NewRTTStats()
		hr := NewSentPacketHandler(0, 1250, rs, &utils.ConnectionStats{}, true, false, nil,
			protocol.PerspectiveClient, false, nil, utils.DefaultLogger).(*sentPacketHandler)
		hr.SentPacket(t0, 0, protocol.InvalidPacketNumber, nil,
			[]Frame{{Frame: &wire.PingFrame{}, Handler: qgoNop{}}}, protocol.EncryptionInitial,
			protocol.ECNNon, 1250, false, false)
		hr.ResetForRetry(t0.Add(d))
		fmt.Printf("#define QGO_RETRY_SRTT_%dMS_NS %dll\n", d.Milliseconds(), rs.SmoothedRTT().Nanoseconds())
	}

	// ---- the packet numbers left out, the random bytes all 0x00 and all 0xff (utils_rand.go).
	fmt.Println("/* The first twelve 1-RTT packet numbers quic-go leaves out, its random bytes all 0x00 and")
	fmt.Println("   all 0xff. */")
	for _, fill := range []byte{0x00, 0xff} {
		utils.QgoRandFill = fill
		g := newSkippingPacketNumberGenerator(0, protocol.SkipPacketInitialPeriod, protocol.SkipPacketMaxPeriod)
		var skipped []string
		for len(skipped) < 12 {
			if skip, pn := g.Pop(); skip {
				skipped = append(skipped, fmt.Sprint(int64(pn-1)))
			}
		}
		fmt.Printf("static const int64_t qgo_skip_%02x[] = { %s };\n", fill, join(skipped))
	}
	utils.QgoRandFill = 0

	qgoECN(t, t0)
	qgoHistory(t, t0)
}

// qgoHistory: what quic-go's history holds decides what an ACK does — packets that elicit no
// acknowledgement are in it, and a packet declared lost is not. Three scripts, replayed by
// test/ngpatch; a packet goes out 1 ms after the one before it, "K" is an ACK-only packet.
func qgoHistory(t *testing.T, t0 monotime.Time) {
	var c qgoCounter
	handler := func() *sentPacketHandler {
		rtt := utils.NewRTTStats()
		rtt.SetMaxAckDelay(25 * time.Millisecond)
		h := NewSentPacketHandler(0, 1250, rtt, &utils.ConnectionStats{}, true, false, nil,
			protocol.PerspectiveClient, false, nil, utils.DefaultLogger).(*sentPacketHandler)
		h.DropPackets(protocol.EncryptionInitial, 0)
		h.DropPackets(protocol.EncryptionHandshake, 0)
		return h
	}
	data := func(h *sentPacketHandler, at monotime.Time, pn protocol.PacketNumber) {
		f := &wire.StreamFrame{StreamID: 0, Offset: protocol.ByteCount(100 * pn), Data: make([]byte, 100)}
		h.SentPacket(at, pn, protocol.InvalidPacketNumber, []StreamFrame{{Frame: f, Handler: qgoCount{&c}}},
			nil, protocol.Encryption1RTT, protocol.ECNNon, 130, false, false)
	}
	ackOnly := func(h *sentPacketHandler, at monotime.Time, pn protocol.PacketNumber) {
		h.SentPacket(at, pn, protocol.InvalidPacketNumber, nil, nil, protocol.Encryption1RTT,
			protocol.ECNNon, 30, false, false)
	}
	ack := func(h *sentPacketHandler, at monotime.Time, lo, hi protocol.PacketNumber) {
		if _, err := h.ReceivedAck(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: lo, Largest: hi}}},
			protocol.Encryption1RTT, at); err != nil {
			t.Fatal(err)
		}
	}
	ms := func(n int) monotime.Time { return t0.Add(time.Duration(n) * time.Millisecond) }

	// ---- data in packet 0, three ACK-only packets after it; the server acknowledges the three.
	h := handler()
	c = qgoCounter{}
	data(h, ms(0), 0)
	for pn := protocol.PacketNumber(1); pn <= 3; pn++ {
		ackOnly(h, ms(int(pn)), pn)
	}
	ack(h, ms(23), 1, 3)
	fmt.Println("/* Packet 0 carries data and 1-3 are ACK-only, 1 ms apart; an ACK of 1-3 arrives at 23 ms:")
	fmt.Println("   the data packets declared lost by it. */")
	fmt.Printf("#define QGO_HIST_ACKONLY_LOST %d\n", c.lost)

	// ---- four data packets; an ACK of 1-3 loses packet 0, and an ACK of 0 arrives after it.
	h = handler()
	c = qgoCounter{}
	for pn := protocol.PacketNumber(0); pn <= 3; pn++ {
		data(h, ms(int(pn)), pn)
	}
	ack(h, ms(23), 1, 3)
	lostBefore, ackedBefore := c.lost, c.acked
	ack(h, ms(24), 0, 0)
	fmt.Println("/* Data packets 0-3, 1 ms apart; an ACK of 1-3 at 23 ms, then one of 0 at 24 ms: the frames")
	fmt.Println("   lost by the first, and how many more frames the second acknowledged. */")
	fmt.Printf("#define QGO_HIST_LATE_LOST %d\n#define QGO_HIST_LATE_ACKED %d\n", lostBefore, c.acked-ackedBefore)

	// ---- data in packet 0, an ACK-only packet 1; an ACK of both, its largest the ACK-only one.
	h = handler()
	data(h, ms(0), 0)
	ackOnly(h, ms(1), 1)
	ack(h, ms(21), 0, 1)
	fmt.Println("/* Packet 0 carries data, packet 1 is ACK-only a millisecond later; an ACK of both at 21 ms:")
	fmt.Println("   the smoothed RTT after it. */")
	fmt.Printf("#define QGO_HIST_NAE_SRTT_NS %dll\n", h.rttStats.SmoothedRTT().Nanoseconds())

	// ---- the loss timer from an ACK-only packet: data 0 acknowledged, then ACK-only 1 and data 2,
	// and an ACK of 2 alone.
	// In the first run data 3 is still out; in the second nothing is, and there is no timer (-1).
	fmt.Println("/* Data 0 at 0 ms, acknowledged at 20; ACK-only 1 at 21, data 2 at 22 and, in the first run,")
	fmt.Println("   data 3 at 23; an ACK of 2 at 42 ms: when the loss detection timer fires, from the start. */")
	for _, outstanding := range []bool{true, false} {
		h = handler()
		data(h, ms(0), 0)
		ack(h, ms(20), 0, 0)
		ackOnly(h, ms(21), 1)
		data(h, ms(22), 2)
		if outstanding {
			data(h, ms(23), 3)
		}
		ack(h, ms(42), 2, 2)
		timer := int64(-1)
		if a := h.GetLossDetectionTimeout(); !a.IsZero() {
			timer = a.Sub(t0).Nanoseconds()
		}
		name := "QGO_HIST_LOSS_TIMER_NS"
		if !outstanding {
			name = "QGO_HIST_NO_TIMER_NS"
		}
		fmt.Printf("#define %s %dll\n", name, timer)
	}

	// ---- a late ACK of an older packet, after its successor was sampled.
	h = handler()
	data(h, ms(0), 0)
	data(h, ms(1), 1)
	ack(h, ms(21), 1, 1)
	ack(h, ms(41), 0, 0)
	fmt.Println("/* Data 0 and 1, 1 ms apart; an ACK of 1 at 21 ms, then one of 0 at 41: the smoothed RTT. */")
	fmt.Printf("#define QGO_HIST_LATE_SRTT_NS %dll\n", h.rttStats.SmoothedRTT().Nanoseconds())

	qgoProbe(t, t0)
}

// qgoProbe: what a 1-RTT PTO does to the history before the probes go. Three data packets of one
// stream, 100 bytes each, numbered as the handler numbers them, 1 ms apart, an RTT sample of 20 ms
// before them; the timer fires; each of the two probes runs QueueProbePacket first
// (connection.go:2745-2757). Replayed by test/ngpatch.
func qgoProbe(t *testing.T, t0 monotime.Time) {
	// All 0xff: the first number the generator leaves out of its own accord is 514 (qgo_skip_ff),
	// far past these packets, so the only one left out is the probe's.
	utils.QgoRandFill = 0xff
	defer func() { utils.QgoRandFill = 0 }()
	rtt := utils.NewRTTStats()
	rtt.SetMaxAckDelay(25 * time.Millisecond)
	h := NewSentPacketHandler(0, 1250, rtt, &utils.ConnectionStats{}, true, false, nil,
		protocol.PerspectiveClient, false, nil, utils.DefaultLogger).(*sentPacketHandler)
	h.DropPackets(protocol.EncryptionInitial, 0)
	h.DropPackets(protocol.EncryptionHandshake, 0)

	var lost []string
	send := func(at monotime.Time, off protocol.ByteCount) protocol.PacketNumber {
		pn := h.PopPacketNumber(protocol.Encryption1RTT)
		f := &wire.StreamFrame{StreamID: 0, Offset: off, Data: make([]byte, 100)}
		h.SentPacket(at, pn, protocol.InvalidPacketNumber,
			[]StreamFrame{{Frame: f, Handler: qgoProbeLost{&lost}}}, nil, protocol.Encryption1RTT,
			protocol.ECNNon, 130, false, false)
		return pn
	}
	first := send(t0, 0)
	if _, err := h.ReceivedAck(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: first, Largest: first}}},
		protocol.Encryption1RTT, t0.Add(20*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var last protocol.PacketNumber
	for i := 0; i < 3; i++ {
		last = send(t0.Add(time.Duration(21+i)*time.Millisecond), protocol.ByteCount(100*(i+1)))
	}
	alarm := h.GetLossDetectionTimeout()
	if err := h.OnLossDetectionTimeout(alarm); err != nil {
		t.Fatal(err)
	}
	mode := h.SendMode(alarm)
	for i := 0; i < 2; i++ {
		if !h.QueueProbePacket(protocol.Encryption1RTT) {
			t.Fatal("nothing to queue")
		}
	}
	probe := h.PopPacketNumber(protocol.Encryption1RTT)
	// The first packet the probes took is acknowledged after all: it left the history, so the ACK
	// acknowledges nothing and the largest acknowledged stays where it was.
	if _, err := h.ReceivedAck(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: first + 1, Largest: first + 1}}},
		protocol.Encryption1RTT, alarm.Add(10*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	fmt.Println("/* Data at offset 0 acknowledged after 20 ms, then data at 100, 200 and 300 1 ms apart; the")
	fmt.Println("   PTO: when it fires from the start, whether it is a 1-RTT probe, the offsets two probes")
	fmt.Println("   hand back to be sent again, and how far past the last data packet the first probe is")
	fmt.Println("   numbered. */")
	fmt.Printf("#define QGO_PTO_AT_NS %dll\n", alarm.Sub(t0).Nanoseconds())
	fmt.Printf("#define QGO_PTO_APPDATA %d\n", map[bool]int{true: 1, false: 0}[mode == SendPTOAppData])
	fmt.Printf("static const uint64_t qgo_pto_requeued[] = { %s };\n", join(lost))
	fmt.Printf("#define QGO_PTO_PN_GAP %d\n", probe-last)
	fmt.Println("/* Then an ACK of the first packet the probes took: the largest acknowledged, from the")
	fmt.Println("   packet acknowledged before them. */")
	fmt.Printf("#define QGO_PTO_LATE_LARGEST %d\n", h.appDataPackets.largestAcked-first)
}

type qgoProbeLost struct {
	order *[]string
}

func (q qgoProbeLost) OnAcked(wire.Frame) {}
func (q qgoProbeLost) OnLost(f wire.Frame) {
	*q.order = append(*q.order, fmt.Sprint(uint64(f.(*wire.StreamFrame).Offset)))
}

type qgoCounter struct{ acked, lost int }

type qgoCount struct {
	c *qgoCounter
}

func (q qgoCount) OnAcked(wire.Frame) { q.c.acked++ }
func (q qgoCount) OnLost(wire.Frame)  { q.c.lost++ }

// qgoECNScripts are replayed by test/ngpatch on the patched connection, word for word: "S<n>" sends
// n packets that elicit an acknowledgement, one datagram each; "K" and "k" send one ACK-only packet
// (test/ngpatch writes the two through ngtcp2's two ways of writing one);
// "T<ms>" lets that many milliseconds pass; and
// "A<lo>-<hi>[:<ect0>,<ect1>,<ce>]" is the server acknowledging packets lo to hi, the ECN counts
// after the colon or none at all. Packet numbers count from 0 in the order sent. After a send the
// clock moves 1 ms, and an acknowledgement arrives 20 ms after the packet before it.
var qgoECNScripts = []string{
	"S12 A0-9:10,0,0 S3",
	"S5 A0-4:5,0,0 S8",
	"S10 A0-9 S3",
	"S10 A0-9:0,0,10 S2",
	"S10 A0-9:5,0,0 S2",
	"S3 A0-2:4,0,0 S2",
	"S14 A10-13 S2",
	"S3 K S7 A0-10:10,0,0 S2",
	"S4 A0-1:2,0,0 S1 A0-4:1,0,0 S1",
	"S4 A0-3:4,0,0 S2 A4-5:4,0,2 S1",
	"S12 A0-11:10,0,0 S2",
	"S12 A10-11:0,0,0 S2",
	"S2 K A2-2 S9",
	"S11 A0-0:1,0,0 A1-1:1,0,0 S2",
	"S10 A0-9:9,0,0 S2",
	"S5 T1000 S6",
	"S4 A2-3:2,0,0 A0-1:1,0,0 S1",
	"S2 k A2-2 S9",
	"S4 A0-1:2,0,0 S2 A0-5:1,0,5 S1",
	"S12 A10-11:1,0,0 S2",
	"S1 K S5 A2-6:5,0,0 S1 A0-7:6,0,0 S1",
}

// qgoECN runs the scripts through a sentPacketHandler with ECN on, asking ECNMode(true) for every
// packet as a client past its handshake does, and prints the marking each packet went out with
// and the tracker's state at the end.
func qgoECN(t *testing.T, t0 monotime.Time) {
	names := map[ecnState]string{ecnStateInitial: "testing", ecnStateTesting: "testing",
		ecnStateUnknown: "unknown", ecnStateCapable: "capable", ecnStateFailed: "failed"}

	fmt.Println("/* ECN: each script, the marking of every packet it sent (E for ECT(0), N for Not-ECT) and")
	fmt.Println("   the tracker's state after it. */")
	fmt.Println("static const struct { const char *script, *marks, *state; } qgo_ecn[] = {")
	for _, script := range qgoECNScripts {
		rtt := utils.NewRTTStats()
		rtt.SetMaxAckDelay(25 * time.Millisecond)
		h := NewSentPacketHandler(0, 1250, rtt, &utils.ConnectionStats{}, true, true, nil,
			protocol.PerspectiveClient, false, nil, utils.DefaultLogger).(*sentPacketHandler)
		h.DropPackets(protocol.EncryptionInitial, 0)
		h.DropPackets(protocol.EncryptionHandshake, 0)

		at := t0
		pn := protocol.PacketNumber(0)
		marks := ""
		sendOne := func(ackEliciting bool) {
			ecn := h.ECNMode(true)
			var frames []Frame
			if ackEliciting {
				frames = []Frame{{Frame: &wire.PingFrame{}, Handler: qgoNop{}}}
			}
			h.SentPacket(at, pn, protocol.InvalidPacketNumber, nil, frames, protocol.Encryption1RTT, ecn,
				100, false, false)
			if ecn == protocol.ECT0 {
				marks += "E"
			} else {
				marks += "N"
			}
			pn++
			at = at.Add(time.Millisecond)
		}
		for _, w := range strings.Fields(script) {
			switch w[0] {
			case 'S':
				n, _ := strconv.Atoi(w[1:])
				for i := 0; i < n; i++ {
					sendOne(true)
				}
			case 'K', 'k':
				sendOne(false)
			case 'T':
				ms, _ := strconv.Atoi(w[1:])
				at = at.Add(time.Duration(ms) * time.Millisecond)
			case 'A':
				var lo, hi int64
				var ect0, ect1, ce uint64
				rng, counts, _ := strings.Cut(w[1:], ":")
				fmt.Sscanf(rng, "%d-%d", &lo, &hi)
				if counts != "" {
					fmt.Sscanf(counts, "%d,%d,%d", &ect0, &ect1, &ce)
				}
				at = at.Add(19 * time.Millisecond)
				if _, err := h.ReceivedAck(&wire.AckFrame{
					AckRanges: []wire.AckRange{{Smallest: protocol.PacketNumber(lo), Largest: protocol.PacketNumber(hi)}},
					ECT0:      ect0, ECT1: ect1, ECNCE: ce,
				}, protocol.Encryption1RTT, at); err != nil {
					t.Fatal(err)
				}
				at = at.Add(time.Millisecond)
			}
		}
		fmt.Printf("    { %q, %q, %q },\n", script, marks, names[h.ecnTracker.(*ecnTracker).state])
	}
	fmt.Println("};")
}

func join(s []string) string {
	out := ""
	for i, x := range s {
		if i > 0 {
			out += ", "
		}
		out += x
	}
	return out
}
