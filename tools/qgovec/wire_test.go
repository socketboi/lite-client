//go:build qgovec

package wire

// Laid into vendor/quic-go/internal/wire by tools/qgovec/gen.sh. The long header quic-go writes for
// a client's Initial: the bytes, with the Length field as quic-go encodes it. How much data a
// STREAM frame takes for the room left in a packet. And what quic-go's frame parser and its
// transport parameters' Unmarshal refuse, and in which words (qgoCloseVectors).

import (
	"fmt"
	"io"
	"testing"

	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/qerr"
	"github.com/apernet/quic-go/quicvarint"
)

func TestQgoVec(t *testing.T) {
	dcid := protocol.ParseConnectionID([]byte{0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8})
	for _, l := range []protocol.ByteCount{25, 1216, 1228} {
		h := &ExtendedHeader{
			Header: Header{
				Type:             protocol.PacketTypeInitial,
				Version:          protocol.Version1,
				DestConnectionID: dcid,
				Length:           l,
			},
			PacketNumber:    1,
			PacketNumberLen: protocol.PacketNumberLen1,
		}
		b, err := h.Append(nil, protocol.Version1)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("static const uint8_t qgo_initial_hdr_%d[] = {", l)
		for i, x := range b {
			if i > 0 {
				fmt.Print(",")
			}
			fmt.Printf(" 0x%02x", x)
		}
		fmt.Println(" };")
	}

	// How much new data getNextStreamFrame puts in a STREAM frame with left bytes of the packet
	// left: popStreamFrame is asked with the Length field's length added, since the last STREAM
	// frame goes without one (framer.go:442-446), and MaxDataLen sizes it (stream_frame.go:136-155).
	// with: the frame as popped; without: the same frame last in the packet.
	fmt.Println("static const struct { int64_t id; uint64_t offset, left, datalen, with, without; } qgo_stream_datalen[] = {")
	for _, id := range []protocol.StreamID{0, 4, 60, 64, 16380, 16384} {
		for _, off := range []protocol.ByteCount{0, 1, 63, 64, 16383, 16384, 1 << 30} {
			for left := protocol.ByteCount(0); left <= 1500; left++ {
				if left > 140 && left < 1380 && left%37 != 0 {
					continue
				}
				maxBytes := left + protocol.ByteCount(quicvarint.Len(uint64(left)))
				f := StreamFrame{StreamID: id, Offset: off, DataLenPresent: true}
				n := f.MaxDataLen(maxBytes, protocol.Version1)
				f.Data = make([]byte, n)
				with := f.Length(protocol.Version1)
				f.DataLenPresent = false
				without := f.Length(protocol.Version1)
				fmt.Printf("    { %d, %d, %d, %d, %d, %d },\n", id, off, left, n, with, without)
			}
		}
	}
	fmt.Println("};")

	qgoCloseVectors()
}

// qgoParseErr walks a payload the way handleFrames does (vendor/quic-go/connection.go:1813-1916):
// the type, then the body by the parser its type calls for, frame after frame, until the first
// error.
func qgoParseErr(p *FrameParser, b []byte, lvl protocol.EncryptionLevel) (uint64, uint64, string, bool) {
	for len(b) > 0 {
		ft, l, err := p.ParseType(b, lvl)
		if err == io.EOF {
			break
		}
		if err != nil {
			te := err.(*qerr.TransportError)
			return uint64(te.ErrorCode), te.FrameType, te.ErrorMessage, true
		}
		b = b[l:]
		switch {
		case ft.IsStreamFrameType():
			_, l, err = p.ParseStreamFrame(ft, b, protocol.Version1)
		case ft.IsAckFrameType():
			_, l, err = p.ParseAckFrame(ft, b, lvl, protocol.Version1)
		case ft.IsDatagramFrameType():
			_, l, err = p.ParseDatagramFrame(ft, b, protocol.Version1)
		default:
			_, l, err = p.ParseLessCommonFrame(ft, b, protocol.Version1)
		}
		if err != nil {
			te := err.(*qerr.TransportError)
			return uint64(te.ErrorCode), te.FrameType, te.ErrorMessage, true
		}
		b = b[l:]
	}
	return 0, 0, "", false
}

func qgoCBytes(b []byte) string {
	s := "\""
	for _, x := range b {
		s += fmt.Sprintf("\\x%02x", x)
	}
	return s + "\""
}

func qgoCat(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

func qgoParam(id uint64, v []byte) []byte {
	b := quicvarint.Append(nil, id)
	b = quicvarint.Append(b, uint64(len(v)))
	return append(b, v...)
}

func qgoNum(id, v uint64) []byte { return qgoParam(id, quicvarint.Append(nil, v)) }

func qgoCloseVectors() {
	// Hysteria's client: datagrams on, RESET_STREAM_AT and ACK_FREQUENCY off
	// (vendor/quic-go/connection.go:533-537 with hysteria's config).
	p := NewFrameParser(true, false, false)
	vi := func(v uint64) []byte { return quicvarint.Append(nil, v) }
	hs, one := protocol.EncryptionHandshake, protocol.Encryption1RTT
	cases := []struct {
		name string
		lvl  protocol.EncryptionLevel
		b    []byte
	}{
		{"unknown type", one, []byte{0x1f}},
		{"unknown type after PING", one, []byte{0x01, 0x21}},
		{"PING as two bytes, then unknown", one, []byte{0x40, 0x01, 0x1f}},
		{"type varint cut", one, []byte{0x01, 0x40}},
		{"type 0x40 as two bytes", one, []byte{0x40, 0x40}},
		{"RESET_STREAM_AT off", one, []byte{0x24, 0x00, 0x00, 0x00, 0x00}},
		{"DATAGRAM length past the end", one, []byte{0x31, 0x05, 0xaa}},
		{"STREAM at Handshake", hs, []byte{0x08, 0x00, 0xaa}},
		{"application CONNECTION_CLOSE at Handshake", hs, []byte{0x1d, 0x00, 0x00}},
		{"HANDSHAKE_DONE at Handshake", hs, []byte{0x01, 0x1e}},
		{"NEW_TOKEN at Handshake, cut", hs, []byte{0x07}},
		{"ACK first range above largest", one, []byte{0x02, 0x05, 0x00, 0x00, 0x06}},
		{"ACK gap below zero", one, []byte{0x02, 0x05, 0x00, 0x01, 0x00, 0x04, 0x00}},
		{"ACK range below zero", one, []byte{0x02, 0x09, 0x00, 0x01, 0x00, 0x00, 0x08}},
		{"ACK cut", one, []byte{0x02, 0x05}},
		{"ACK_ECN without counts", one, []byte{0x03, 0x00, 0x00, 0x00, 0x00}},
		{"STREAM past 2^62-1", one, qgoCat([]byte{0x0e, 0x01}, vi(1<<62-1), []byte{0x01, 0xaa})},
		{"STREAM length past the end", one, []byte{0x0a, 0x01, 0x05, 0xaa}},
		{"STREAM cut", one, []byte{0x0c, 0x01}},
		{"MAX_STREAMS above 2^60", one, qgoCat([]byte{0x12}, vi(1<<60+1))},
		{"STREAMS_BLOCKED above 2^60", one, qgoCat([]byte{0x17}, vi(1<<60+1))},
		{"NEW_CONNECTION_ID Retire Prior To above", one, []byte{0x18, 0x01, 0x02, 0x08}},
		{"NEW_CONNECTION_ID zero length", one, []byte{0x18, 0x01, 0x00, 0x00}},
		{"NEW_CONNECTION_ID 21 bytes", one, []byte{0x18, 0x01, 0x00, 0x15}},
		{"NEW_CONNECTION_ID token cut", one, []byte{0x18, 0x01, 0x00, 0x01, 0xaa, 0x00}},
		{"NEW_TOKEN empty", one, []byte{0x07, 0x00}},
		{"CRYPTO past the end", one, []byte{0x06, 0x00, 0x05, 0xaa}},
		{"CONNECTION_CLOSE reason past the end", one, []byte{0x1c, 0x00, 0x00, 0x05, 0xaa}},
		{"PATH_CHALLENGE cut", one, []byte{0x1a, 0x01, 0x02}},
		{"RESET_STREAM cut", one, []byte{0x04, 0x01}},
		{"MAX_DATA cut", one, []byte{0x01, 0x10}},
		{"RETIRE_CONNECTION_ID cut", one, []byte{0x19}},
		{"PADDING to the end", one, []byte{0x01, 0x00, 0x00, 0x00}},
	}
	fmt.Println("/* A payload of the server's, and the close quic-go's frame parser makes of it; none when")
	fmt.Println("   reason is NULL. level: 2 Handshake, 3 1-RTT. */")
	fmt.Println("static const struct { const char *name; int level; const char *payload; size_t len; uint64_t code, frame_type; const char *reason; } qgo_frame_close[] = {")
	for _, c := range cases {
		code, ft, msg, bad := qgoParseErr(p, c.b, c.lvl)
		lvl := 3
		if c.lvl == hs {
			lvl = 2
		}
		reason := "NULL"
		if bad {
			reason = fmt.Sprintf("%q", msg)
		}
		fmt.Printf("    { %q, %d, %s, %d, 0x%x, 0x%x, %s },\n", c.name, lvl, qgoCBytes(c.b), len(c.b), code, ft, reason)
	}
	fmt.Println("};")

	// The server's transport parameters, and what Unmarshal says of them, which the TLS layer passes
	// on as the whole text of the TRANSPORT_PARAMETER_ERROR (vendor/quic-go/internal/handshake/
	// crypto_setup.go:700-705).
	cid := []byte{0xc0, 0, 0, 0, 0, 0, 0, 0}
	od, is := qgoParam(0x0, cid), qgoParam(0xf, cid)
	pa := func(cidLen byte, tail int) []byte {
		b := make([]byte, 24)
		b = append(b, cidLen)
		return append(b, make([]byte, int(cidLen)+16+tail)...)
	}
	tps := []struct {
		name string
		b    []byte
	}{
		{"the two IDs", qgoCat(od, is)},
		{"no initial_source_connection_id", qgoCat(od)},
		{"no original_destination_connection_id", qgoCat(is)},
		{"initial_max_data twice", qgoCat(od, is, qgoNum(0x4, 1), qgoNum(0x4, 2))},
		{"two parameters twice, the lower named", qgoCat(od, is, qgoNum(0x9, 1), qgoNum(0x5, 1), qgoNum(0x9, 1), qgoNum(0x5, 1))},
		{"max_udp_payload_size 1199", qgoCat(od, is, qgoNum(0x3, 1199))},
		{"ack_delay_exponent 21", qgoCat(od, is, qgoNum(0xa, 21))},
		{"max_ack_delay 16384", qgoCat(od, is, qgoNum(0xb, 16384))},
		{"active_connection_id_limit 1", qgoCat(od, is, qgoNum(0xe, 1))},
		{"initial_max_streams_bidi above 2^60", qgoCat(od, is, qgoNum(0x8, 1<<60+1))},
		{"initial_max_streams_uni above 2^60", qgoCat(od, is, qgoNum(0x9, 1<<60+1))},
		{"stateless_reset_token of 15", qgoCat(od, is, qgoParam(0x2, make([]byte, 15)))},
		{"disable_active_migration with a byte", qgoCat(od, is, qgoParam(0xc, []byte{1}))},
		{"original_destination_connection_id of 21", qgoCat(qgoParam(0x0, make([]byte, 21)), is)},
		{"retry_source_connection_id of 21", qgoCat(od, is, qgoParam(0x10, make([]byte, 21)))},
		{"preferred_address too short, last", qgoCat(od, is, qgoParam(0xd, make([]byte, 10)))},
		{"preferred_address with no ID", qgoCat(od, is, qgoParam(0xd, pa(0, 0)))},
		{"preferred_address longer than it reads", qgoCat(od, is, qgoParam(0xd, pa(4, 2)))},
		{"preferred_address of 4", qgoCat(od, is, qgoParam(0xd, pa(4, 0)))},
		{"a number one byte short of its length", qgoCat(od, is, qgoParam(0x4, []byte{0x05, 0x00}))},
		{"a number longer than its length", qgoCat(od, is, qgoParam(0x4, []byte{0x40}), []byte{0x05})},
		{"an empty number last", qgoCat(od, is, qgoParam(0x4, nil))},
		{"a length past the end", qgoCat(od, is, []byte{0x04, 0x05, 0x01})},
		{"an ID cut", qgoCat(od, is, []byte{0x40})},
		{"a length missing", qgoCat(od, is, []byte{0x04})},
		{"reset_stream_at with a byte", qgoCat(od, is, qgoParam(0x1d, []byte{1}))},
		{"min_ack_delay 30ms over the default", qgoCat(od, is, qgoNum(0xff04de1b, 30000))},
		{"min_ack_delay 1.5ms over 1ms", qgoCat(od, is, qgoNum(0xb, 1), qgoNum(0xff04de1b, 1500))},
		{"min_ack_delay 1.2345s over 1s", qgoCat(od, is, qgoNum(0xb, 1000), qgoNum(0xff04de1b, 1234500))},
		{"min_ack_delay 61.000001s over 16.383s", qgoCat(od, is, qgoNum(0xb, 16383), qgoNum(0xff04de1b, 61000001))},
		{"min_ack_delay 3723s, hours and minutes", qgoCat(od, is, qgoNum(0xff04de1b, 3723000000))},
		{"min_ack_delay 20ms before max_ack_delay 1ms", qgoCat(od, is, qgoNum(0xff04de1b, 20000), qgoNum(0xb, 1))},
		{"min_ack_delay 7us over max_ack_delay 0", qgoCat(od, is, qgoNum(0xb, 0), qgoNum(0xff04de1b, 7))},
		{"version_information quic-go does not read", qgoCat(od, is, qgoParam(0x11, []byte{1, 2, 3}))},
		{"grease_quic_bit with a byte", qgoCat(od, is, qgoParam(0x2ab2, []byte{1}))},
	}
	fmt.Println("/* The server's transport parameters, and the reason quic-go's client closes with: NULL when")
	fmt.Println("   it takes them. */")
	fmt.Println("static const struct { const char *name; const char *tp; size_t len; const char *reason; } qgo_tp_close[] = {")
	for _, c := range tps {
		var tp TransportParameters
		reason := "NULL"
		if err := tp.Unmarshal(c.b, protocol.PerspectiveServer); err != nil {
			reason = fmt.Sprintf("%q", err.Error())
		}
		fmt.Printf("    { %q, %s, %d, %s },\n", c.name, qgoCBytes(c.b), len(c.b), reason)
	}
	fmt.Println("};")
}
