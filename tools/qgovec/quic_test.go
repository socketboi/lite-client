//go:build qgovec

package quic

// Laid by tools/qgovec/gen.sh into internal/qgovec, beside four files of quic-go's root package
// (package quic) laid there unchanged. Two scripts run on quic-go's own
// code, whose every step test/ngpatch replays on the patched ngtcp2:
//
//   - the Destination Connection IDs a client uses after its handshake (connIDManager);
//   - the receive windows it advertises while a download is read (the flow controllers).

import (
	"fmt"
	"testing"
	"time"

	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/qerr"
	"github.com/apernet/quic-go/internal/utils"
	"github.com/apernet/quic-go/internal/wire"
)

// conn_id_manager.go names the paths of connection migration by this type, which is declared in
// path_manager.go:16 — a file not laid here, since it would bring the rest of the package with it.
type pathID int64

func cidOf(seq byte) protocol.ConnectionID {
	return protocol.ParseConnectionID([]byte{0xc0, 0, 0, 0, 0, 0, 0, seq})
}

func TestQgoVec(t *testing.T) {
	// ---- connIDManager: three IDs arrive in one packet, listed highest first as quic-go's server
	// lists them; the client finishes its handshake and writes packets.
	var retired []uint64
	m := newConnIDManager(cidOf(0), func(protocol.StatelessResetToken) {},
		func(protocol.StatelessResetToken) {},
		func(f wire.Frame) {
			if r, ok := f.(*wire.RetireConnectionIDFrame); ok {
				retired = append(retired, r.SequenceNumber)
			}
		})
	for _, s := range []uint64{3, 2, 1} {
		if err := m.Add(&wire.NewConnectionIDFrame{SequenceNumber: s, ConnectionID: cidOf(byte(s)),
			StatelessResetToken: protocol.StatelessResetToken{byte(s)}}); err != nil {
			t.Fatal(err)
		}
	}
	// Before the handshake completes nothing changes.
	pre := m.Get()
	m.SetHandshakeComplete()
	fmt.Printf("#define QGO_CID_BEFORE_HANDSHAKE %d\n", pre.Bytes()[7])
	fmt.Println("/* The sequence number of the Destination Connection ID of each packet, and the RETIRE frames")
	fmt.Println("   queued by then, after the handshake; the change interval is set to 3 after the first. */")
	fmt.Println("static const struct { uint8_t seq; uint8_t nretired; } qgo_cid_pkts[] = {")
	for i := 0; i < 10; i++ {
		id := m.Get()
		if i == 0 {
			m.packetsPerConnectionID = 3
		}
		fmt.Printf("    { %d, %d },\n", id.Bytes()[7], len(retired))
		m.SentPacket()
	}
	fmt.Println("};")
	fmt.Print("static const uint8_t qgo_cid_retired[] = {")
	for i, r := range retired {
		if i > 0 {
			fmt.Print(",")
		}
		fmt.Printf(" %d", r)
	}
	fmt.Println(" };")

	// ---- the flow controllers, parroting Chrome: 6 MiB and 15 MiB under hysteria's 8 and 20.
	rtt := utils.NewRTTStats()
	rtt.UpdateRTT(20*time.Millisecond, 0)
	cfc := newConnectionFlowController(15728640, 20971520, func(protocol.ByteCount) bool { return true },
		rtt, utils.DefaultLogger)
	sfc := newStreamFlowController(1, cfc, 6291456, 8388608, 0, rtt, utils.DefaultLogger)
	const chunk, fast, slow = 16384, 1000, 200
	const fastDt, slowDt = 125 * time.Microsecond, 1250 * time.Microsecond
	fmt.Printf("#define QGO_FLOW_SRTT_NS %dll\n", rtt.SmoothedRTT().Nanoseconds())
	fmt.Printf("#define QGO_FLOW_CHUNK %d\n", chunk)
	fmt.Printf("#define QGO_FLOW_FAST_STEPS %d\n", fast)
	fmt.Printf("#define QGO_FLOW_SLOW_STEPS %d\n", slow)
	fmt.Printf("#define QGO_FLOW_FAST_DT_NS %d\n", fastDt.Nanoseconds())
	fmt.Printf("#define QGO_FLOW_SLOW_DT_NS %d\n", slowDt.Nanoseconds())
	fmt.Println("/* One STREAM frame of QGO_FLOW_CHUNK bytes received and read at each step, the fast steps")
	fmt.Println("   apart by the fast interval and then the slow ones by the slow; the steps whose following")
	fmt.Println("   packet carries a window update, with its MAX_STREAM_DATA and MAX_DATA (0 for none). */")
	fmt.Println("static const struct { int step; uint64_t max_stream_data, max_data; } qgo_flow[] = {")
	now := monotime.Time(1_000_000_000)
	var offset protocol.ByteCount
	for i := 0; i < fast+slow; i++ {
		dt := fastDt
		if i >= fast {
			dt = slowDt
		}
		now = now.Add(dt)
		offset += chunk
		if err := sfc.UpdateHighestReceived(offset, false, now); err != nil {
			t.Fatal(err)
		}
		hasS, _ := sfc.AddBytesRead(chunk)
		// The send loop: MAX_DATA first (connection.go), then the framer's stream control frames.
		c := cfc.GetWindowUpdate(now)
		var s protocol.ByteCount
		if hasS {
			s = sfc.GetWindowUpdate(now)
		}
		if s != 0 || c != 0 {
			fmt.Printf("    { %d, %d, %d },\n", i, s, c)
		}
	}
	fmt.Println("};")

	qgoCloseRoot()
}

// streams_map_outgoing.go names this error of streams_map.go, a file not laid here, since it would
// bring the streams themselves with it; the paths run here never make one.
type StreamLimitReachedError struct{}

func (e StreamLimitReachedError) Error() string { return "too many open streams" }

// A stream as the streams maps hold one; none of it is called on the paths run here.
type qgoStream struct{}

func (qgoStream) closeForShutdown(error)                  {}
func (qgoStream) updateSendWindow(protocol.ByteCount)     {}
func (qgoStream) enableResetStreamAt()                    {}
func qgoNewStream(protocol.StreamID) qgoStream            { return qgoStream{} }
func qgoQueue(wire.Frame)                                 {}
func qgoToken(protocol.StatelessResetToken)               {}

// qgoCloseRoot runs the checks of quic-go's root package that a server's frames reach, on the
// state test/ngpatch gives its client, and prints the close each ends in — the error code and the
// reason; quic-go's handleCloseError turns an error that is no TransportError into INTERNAL_ERROR
// with its text (vendor/quic-go/connection.go:2283-2290).
func qgoCloseRoot() {
	type row struct {
		name string
		code uint64
		msg  string
		bad  bool
	}
	var rows []row
	add := func(name string, err error) {
		r := row{name: name}
		if err != nil {
			r.bad = true
			if te, ok := err.(*qerr.TransportError); ok {
				r.code, r.msg = uint64(te.ErrorCode), te.ErrorMessage
			} else {
				r.code, r.msg = 0x1, err.Error()
			}
		}
		rows = append(rows, r)
	}
	first := func(errs ...error) error {
		for _, e := range errs {
			if e != nil {
				return e
			}
		}
		return nil
	}
	now := monotime.Time(1_000_000_000)
	rtt := utils.NewRTTStats()

	// The windows of the client test/ngpatch builds: 6291456 on a stream the server opens, 15728640
	// on the connection.
	flow := func() (*connectionFlowController, func(protocol.StreamID) *streamFlowController) {
		cfc := newConnectionFlowController(15728640, 20971520, func(protocol.ByteCount) bool { return true },
			rtt, utils.DefaultLogger)
		return cfc, func(id protocol.StreamID) *streamFlowController {
			return newStreamFlowController(id, cfc, 6291456, 8388608, 0, rtt, utils.DefaultLogger)
		}
	}
	{
		_, s := flow()
		add("STREAM past the stream window", s(1).UpdateHighestReceived(6291457, false, now))
	}
	{
		_, s := flow()
		f := s(1)
		add("FIN at 10, then FIN at 20", first(f.UpdateHighestReceived(10, true, now), f.UpdateHighestReceived(20, true, now)))
	}
	{
		_, s := flow()
		f := s(1)
		add("FIN at 10, then data to 16", first(f.UpdateHighestReceived(10, true, now), f.UpdateHighestReceived(16, false, now)))
	}
	{
		_, s := flow()
		f := s(1)
		add("data to 100, then FIN at 50", first(f.UpdateHighestReceived(100, false, now), f.UpdateHighestReceived(50, true, now)))
	}
	{
		_, s := flow()
		add("RESET_STREAM past the stream window", s(1).UpdateHighestReceived(7000000, true, now))
	}
	{
		_, s := flow()
		add("three RESET_STREAMs past the connection window", first(s(1).UpdateHighestReceived(6291456, true, now),
			s(5).UpdateHighestReceived(6291456, true, now), s(9).UpdateHighestReceived(6291456, true, now)))
	}

	// The streams the server may open — four bidirectional, as test/ngpatch's client grants, and no
	// unidirectional one — and the ones the client has opened: none.
	{
		m := newIncomingStreamsMap(protocol.StreamTypeBidi, qgoNewStream, 4, qgoQueue, protocol.PerspectiveClient)
		_, err := m.GetOrOpenStream(17)
		add("STREAM on the server's bidirectional stream 17, four allowed", err)
	}
	{
		m := newIncomingStreamsMap(protocol.StreamTypeUni, qgoNewStream, 0, qgoQueue, protocol.PerspectiveClient)
		_, err := m.GetOrOpenStream(3)
		add("STREAM on the server's unidirectional stream 3, none allowed", err)
	}
	{
		m := newOutgoingStreamsMap(protocol.StreamTypeBidi, qgoNewStream, qgoQueue, protocol.PerspectiveClient)
		_, err := m.GetStream(4)
		add("MAX_STREAM_DATA on our bidirectional stream 4, not opened", err)
	}

	// NEW_CONNECTION_ID, on the Connection ID test/ngpatch's client starts with.
	ncid := func(seq uint64, cid byte, token byte) *wire.NewConnectionIDFrame {
		return &wire.NewConnectionIDFrame{SequenceNumber: seq, ConnectionID: cidOf(cid),
			StatelessResetToken: protocol.StatelessResetToken{token}}
	}
	{
		m := newConnIDManager(protocol.ConnectionID{}, qgoToken, qgoToken, qgoQueue)
		add("NEW_CONNECTION_ID while zero-length IDs are in use", m.Add(ncid(1, 1, 1)))
	}
	{
		m := newConnIDManager(cidOf(0), qgoToken, qgoToken, qgoQueue)
		add("NEW_CONNECTION_ID 1 twice, another ID", first(m.Add(ncid(1, 1, 1)), m.Add(ncid(1, 9, 1))))
	}
	{
		m := newConnIDManager(cidOf(0), qgoToken, qgoToken, qgoQueue)
		add("NEW_CONNECTION_ID 1 twice, another token", first(m.Add(ncid(1, 1, 1)), m.Add(ncid(1, 1, 9))))
	}
	{
		m := newConnIDManager(cidOf(0), qgoToken, qgoToken, qgoQueue)
		add("NEW_CONNECTION_ID 1 to 4", first(m.Add(ncid(1, 1, 1)), m.Add(ncid(2, 2, 2)), m.Add(ncid(3, 3, 3)),
			m.Add(ncid(4, 4, 4))))
	}
	{
		m := newConnIDManager(cidOf(0), qgoToken, qgoToken, qgoQueue)
		add("NEW_CONNECTION_ID 1 to 3", first(m.Add(ncid(1, 1, 1)), m.Add(ncid(2, 2, 2)), m.Add(ncid(3, 3, 3))))
	}
	{
		m := newConnIDManager(cidOf(0), qgoToken, qgoToken, qgoQueue)
		add("NEW_CONNECTION_ID 0 again, another ID", m.Add(ncid(0, 9, 9)))
	}

	// CRYPTO.
	data := func(n int) []byte { return make([]byte, n) }
	{
		s := newCryptoStream()
		add("1-RTT CRYPTO past 16384", s.HandleCryptoFrame(&wire.CryptoFrame{Offset: 16380, Data: data(10)}))
	}
	{
		s := newCryptoStream()
		add("empty 1-RTT CRYPTO at 20000", s.HandleCryptoFrame(&wire.CryptoFrame{Offset: 20000}))
	}
	{
		s := newCryptoStream()
		add("Handshake CRYPTO after the level changed", first(s.HandleCryptoFrame(&wire.CryptoFrame{Data: data(5)}),
			func() error { s.GetCryptoData(); return s.Finish() }(),
			s.HandleCryptoFrame(&wire.CryptoFrame{Offset: 5, Data: data(5)})))
	}
	{
		s := newCryptoStream()
		add("Handshake CRYPTO left over when the level changed", first(
			s.HandleCryptoFrame(&wire.CryptoFrame{Offset: 10, Data: data(5)}),
			s.HandleCryptoFrame(&wire.CryptoFrame{Data: data(5)}),
			func() error { s.GetCryptoData(); return s.Finish() }()))
	}

	fmt.Println("/* The close quic-go's own streams, flow controllers, Connection ID manager and crypto streams")
	fmt.Println("   end in, for what test/ngpatch sends under each name; no close when reason is NULL. */")
	fmt.Println("static const struct { const char *name; uint64_t code; const char *reason; } qgo_root_close[] = {")
	for _, r := range rows {
		reason := "NULL"
		if r.bad {
			reason = fmt.Sprintf("%q", r.msg)
		}
		fmt.Printf("    { %q, 0x%x, %s },\n", r.name, r.code, reason)
	}
	fmt.Println("};")
}
