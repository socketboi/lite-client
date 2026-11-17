// A REALITY node that misbehaves on purpose, one way per connection, and writes down what the
// client said back. Built by run.sh inside a copy of vendor/REALITY together with hook.go; see
// run.sh for the recipe and for what the lines mean.
//
//	node LISTEN TARGET PRIVATE_KEY SHORT_ID SERVER_NAME SCENARIO_FILE
//
// Every connection reads SCENARIO_FILE when it is accepted — "label scenario" — so the stand picks
// the misbehaviour from outside, and the log line carries the label of whichever client it was.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/xtls/reality"
)

// What passes from the client, kept from the moment the misbehaviour starts.
type tap struct {
	net.Conn
	mu  sync.Mutex
	on  bool
	got []byte
	fin bool
}

func (t *tap) Read(b []byte) (int, error) {
	n, err := t.Conn.Read(b)
	t.mu.Lock()
	if t.on {
		t.got = append(t.got, b[:n]...)
	}
	if err == io.EOF {
		t.fin = true
	}
	t.mu.Unlock()
	return n, err
}

// reality.Server asks for it: it half-closes the client's side when it hands a stranger to the
// target (vendor/REALITY/tls.go:187, :461).
func (t *tap) CloseWrite() error { return t.Conn.(*net.TCPConn).CloseWrite() }

func (t *tap) mark() {
	t.mu.Lock()
	t.on = true
	t.mu.Unlock()
}

// The records the client wrote after the mark, as a path sees them: outer type and body length.
func (t *tap) shape() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var parts []string
	b := t.got
	for len(b) >= 5 {
		n := int(b[3])<<8 | int(b[4])
		if len(b) < 5+n {
			parts = append(parts, fmt.Sprintf("%d/%d(cut)", b[0], n))
			b = nil
			break
		}
		parts = append(parts, fmt.Sprintf("%d/%d", b[0], n))
		b = b[5+n:]
	}
	if len(b) > 0 {
		parts = append(parts, fmt.Sprintf("+%dB", len(b)))
	}
	if t.fin {
		parts = append(parts, "fin")
	}
	if len(parts) == 0 {
		return "nothing"
	}
	return strings.Join(parts, " ")
}

func h(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

// A NewSessionTicket that unmarshals: lifetime 7200, age_add, a one-byte nonce, a four-byte ticket,
// no extensions.
var nst = h("04 000012 00001c20 01020304 01 00 0004 aabbccdd 0000")

type step struct {
	raw  []byte // written past the record layer, or
	typ  byte   // sealed as one record of this inner type
	data []byte
	rot  bool // or the write key moved on, as after a KeyUpdate
	bare bool // or sealed with `typ` as the header and `data` as the whole inner plaintext
}

func raw(b []byte) step              { return step{raw: b} }
func seal(typ byte, b []byte) step   { return step{typ: typ, data: b} }
func rotate() step                   { return step{rot: true} }
func bare(outer byte, b []byte) step { return step{bare: true, typ: outer, data: b} }
func fill(n int, v byte) []byte      { return bytes.Repeat([]byte{v}, n) }
func cat(parts ...[]byte) []byte     { return bytes.Join(parts, nil) }
func times(n int, s step) (r []step) {
	for i := 0; i < n; i++ {
		r = append(r, s)
	}
	return r
}

// closeslow: eight megabytes in 16000-byte records, the last line of them "pre", then close_notify,
// then one more line. Driven by the probe's `tcplate`, which waits two seconds and then reads slowly
// through a 4 KB window, so the client is behind when the close_notify arrives. Meant to reach the
// one place where records are left in hand after it, and where reading past the end would show as
// "post" at the far end; on loopback it does not — see the guard at the top of records_ready.
func slow() (r []step) {
	line := append(bytes.Repeat([]byte{'a'}, 99), '\n')
	chunk := bytes.Repeat(line, 160)
	for i := 0; i < 512; i++ {
		b := append([]byte(nil), chunk...)
		if i == 0 {
			b = append([]byte("\x00\x00"), b[2:]...)
		}
		if i == 511 {
			copy(b[len(b)-4:], "pre\n")
		}
		r = append(r, seal(23, b))
	}
	return append(r, seal(21, h("01 00")), seal(23, []byte("post\n")))
}

var scenarios = map[string][]step{
	// Nothing: the stream as a stock node leaves it. The reply below proves it still carries data.
	"none": nil,

	// Bytes anybody on the path can write.
	"ccs":    {raw(h("14 0303 0001 01"))},
	"ccs2":   {raw(h("14 0303 0001 02"))},
	"ccs0":   {raw(h("14 0303 0000"))},
	"ccsbig": {raw(cat(h("14 0303 4001"), fill(16385, 1)))},
	"vers":   {raw(cat(h("17 0301 0020"), fill(32, 0xaa)))},
	"huge":   {raw(cat(h("17 0303 4101"), fill(16641, 0xaa)))},
	// The same, run last, when the client reads ahead — see run.sh.
	"hugeahead": {raw(cat(h("17 0303 4101"), fill(16641, 0xaa)))},
	"junk":      {raw(cat(h("17 0303 0020"), fill(32, 0x5c)))},
	"tiny":      {raw(cat(h("17 0303 0005"), fill(5, 0xaa)))},
	"palert":    {raw(h("15 0303 0002 020a"))},
	"phs":       {raw(h("16 0303 0004 0b000000"))},

	// Records only the node's key can seal.
	"nst":       {seal(22, nst)},
	"nstsplit":  {seal(22, nst[:3]), seal(22, nst[3:])},
	"nstbad":    {seal(22, h("04 000005 0000000000"))},
	"nst32":     {seal(22, bytes.Repeat(nst, 32))},
	"nst33":     {seal(22, bytes.Repeat(nst, 33))},
	"hs0":       {seal(22, nil)},
	"hsunknown": {seal(22, h("63 000000"))},
	"hsfin":     {seal(22, h("14 000000"))},
	"hsbig":     {seal(22, h("04 010001"))},
	"hscert":    {seal(22, h("0b 040001"))},
	"hscertok":  {seal(22, h("0b 010000"))},
	"partccs":   {seal(22, nst[:3]), raw(h("14 0303 0001 01"))},
	"alertbad":  {seal(21, h("02 28 00"))},
	"alert":     {seal(21, h("02 50"))},
	"alertwarn": {seal(21, h("01 5a"))},
	"close":     {seal(21, h("01 00"))},
	"type24":    {seal(24, h("0100"))},
	// The same two once the stream is up: a VLESS response header and a line first.
	"closelate": {seal(23, []byte("\x00\x00pre\n")), seal(21, h("01 00"))},
	"alertlate": {seal(23, []byte("\x00\x00pre\n")), seal(21, h("02 50"))},
	// And data after close_notify, in the same flight: the reference reads nothing past its end.
	"closemore": {seal(23, []byte("\x00\x00pre\n")), seal(21, h("01 00")), seal(23, []byte("post\n"))},
	"empty30":   times(30, seal(23, nil)),
	"empty31":   times(31, seal(23, nil)),
	"empty32":   times(32, seal(23, nil)),
	"empty33":   times(33, seal(23, nil)),
	"closeslow": slow(),
	// KeyUpdate, the node's write key moved on after it as its sender's is — so the reply below is
	// sealed with the next generation and only a client that followed can open it. Asked for an
	// answer, the client sends its own and moves its write key; the node's read takes that in its
	// stride, and the client's close_notify at the end is sealed with the key it moved to.
	"ku":      {seal(22, h("18 000001 00")), rotate()},
	"kureq":   {seal(22, h("18 000001 01")), rotate()},
	"ku2":     {seal(22, h("18 000001 00 18 000001 01")), rotate(), rotate()},
	"kusplit": {seal(22, h("18 00")), seal(22, h("00 01 01")), rotate()},
	"kumix":   {seal(22, cat(nst, h("18 000001 01"), nst)), rotate()},
	// The record layer itself, sealed by hand: a body of nothing but a tag, an inner plaintext of
	// 2^14 + 1 (the most there may be) and of one more, one that is all padding, and one sealed under
	// a handshake header — each only the node's key can make.
	"tagonly": {bare(23, nil)},
	"maxin":   {bare(23, cat([]byte("\x00\x00"), fill(16381, 'a'), []byte("\n\x17")))},
	"bigin":   {bare(23, cat(fill(16385, 'a'), []byte{0x17}))},
	"zeros":   {bare(23, fill(3, 0))},
	"outer22": {bare(22, []byte("x\x17"))},
}

// What one read window brought: the client's alert, its close_notify, or nothing.
func verdict(err error) string {
	var ne net.Error
	switch {
	case err == nil:
		return "data"
	case errors.As(err, &ne) && ne.Timeout():
		return "silent"
	case err == io.EOF:
		return "EOF"
	}
	s := err.Error()
	if i := strings.Index(s, "remote error: tls: "); i >= 0 {
		return "alert:" + strings.ReplaceAll(s[i+len("remote error: tls: "):], " ", "_")
	}
	return "error:" + strings.ReplaceAll(s, " ", "_")
}

func window(c *reality.Conn, d time.Duration) string {
	c.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 4096)
	got := 0
	for {
		n, err := c.Read(buf)
		got += n
		if err != nil {
			v := verdict(err)
			if got > 0 && v == "silent" {
				return fmt.Sprintf("data(%d)", got)
			}
			return v
		}
	}
}

func serve(conn net.Conn, cfg *reality.Config, scenarioFile string) {
	defer conn.Close()
	label := "?"
	name := "none"
	if b, err := os.ReadFile(scenarioFile); err == nil {
		if f := strings.Fields(string(b)); len(f) == 2 {
			label, name = f[0], f[1]
		}
	}
	// The alps scenarios change the handshake itself — see hook.go. Settings as a server speaking
	// ALPS for h2 sends them, a SETTINGS payload: SETTINGS_MAX_CONCURRENT_STREAMS 100.
	settings := []byte{0x00, 0x03, 0x00, 0x00, 0x00, 0x64}
	reality.StandALPS, reality.StandALPSData, reality.StandALPN, reality.StandClientEE = 0, nil, "", nil
	reality.StandHandshakeErr = nil
	switch name {
	case "alpn": // a protocol and no settings: nothing to answer
		reality.StandALPN = "h2"
	case "alps": // settings under the codepoint Chrome offers now
		reality.StandALPN, reality.StandALPS, reality.StandALPSData = "h2", 17613, settings
	case "alpsold": // and under the one it offered before
		reality.StandALPN, reality.StandALPS, reality.StandALPSData = "h2", 17513, settings
	case "alpsnoalpn": // settings with no protocol chosen, which uTLS refuses
		reality.StandALPS, reality.StandALPSData = 17613, settings
	}
	ee := func() string {
		if reality.StandClientEE == nil {
			return "-"
		}
		return hex.EncodeToString(reality.StandClientEE)
	}

	t := &tap{Conn: conn}
	c, err := reality.Server(context.Background(), t, cfg)
	if err != nil {
		if reality.StandHandshakeErr != nil {
			err = reality.StandHandshakeErr
		}
		fmt.Printf("%s %s | handshake: %v | client ee %s\n", label, name, err, ee())
		return
	}
	// The VLESS request, or the start of it: the misbehaviour starts once the client has spoken.
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	req := make([]byte, 4096)
	if _, err := c.Read(req); err != nil {
		fmt.Printf("%s %s | request: %v\n", label, name, err)
		return
	}
	t.mark()
	if name == "kufull" {
		kufull(c, t, label)
		return
	}

	for _, s := range scenarios[name] {
		if s.rot {
			c.StandRotateWrite()
			continue
		}
		if s.bare {
			err = c.StandSealBare(s.typ, s.data)
		} else if s.raw != nil {
			_, err = c.StandRaw().Write(s.raw)
		} else {
			err = c.StandSeal(s.typ, s.data)
		}
		if err != nil {
			fmt.Printf("%s %s | write: %v\n", label, name, err)
			return
		}
	}
	first := window(c, 400*time.Millisecond)

	// Still there: a VLESS response header and a line for the probe to print, then close_notify —
	// the node's own end, so what the client does at the end is on the record as well.
	then := "-"
	if first == "silent" {
		c.StandSeal(23, []byte("\x00\x00OK "+name+"\n"))
		then = window(c, 400*time.Millisecond)
		if then == "silent" {
			c.StandSeal(21, h("0100"))
			then = "silent>" + window(c, 2500*time.Millisecond)
		}
	}
	// Whatever else the client sends before it lets go of the socket.
	t.SetReadDeadline(time.Now().Add(2500 * time.Millisecond))
	io.Copy(io.Discard, t)
	fmt.Printf("%s %s | client ee %s | first %s | then %s | client wrote %s\n", label, name, ee(), first, then, t.shape())
}

// kufull: a KeyUpdate asking for an answer while the client's way to the node is full. The probe's
// `tcpup` pushes 48 MB up behind its request and the node reads none of it for two seconds — more
// than the sockets between them hold — so the client's writes to the node have stopped when the
// KeyUpdate arrives. The reference's answer then waits for the write lock, which the Write that
// cannot finish is holding (vendor/utls/conn.go:1360-1381), and goes out once the node reads
// again. The upload has to arrive whole, the answer has to be taken — the node's read key one
// generation on — and the line after it, sealed with the node's next key, has to reach the probe.
//
// Not the shape: where among 48 MB of records the answer lands is timing, and so is the size of
// every record around it. What is compared is how much arrived, how many answers the node took and
// how the client ended.
func kufull(c *reality.Conn, t *tap, label string) {
	time.Sleep(2 * time.Second)
	from := c.StandInSecret()
	if err := c.StandSeal(22, h("18 000001 01")); err != nil {
		fmt.Printf("%s kufull | write: %v\n", label, err)
		return
	}
	c.StandRotateWrite()

	// Up to the probe's last line. The count is only told apart as whole or short: Vision pads the
	// first few writes by a random amount, and the node's first read above took some of the upload
	// with the request — at most a record — so "whole" is 48 MB less 64 KB or more.
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	buf := make([]byte, 65536)
	var got int64
	var tail []byte
	first := ""
	for first == "" {
		n, err := c.Read(buf)
		got += int64(n)
		tail = append(tail, buf[:n]...)
		if len(tail) > 8 {
			tail = tail[len(tail)-8:]
		}
		switch {
		case bytes.HasSuffix(tail, []byte("END\n")) && got >= 48<<20-65536:
			first = "up_whole_END"
		case bytes.HasSuffix(tail, []byte("END\n")):
			first = fmt.Sprintf("up_short_%d_END", got)
		case err != nil:
			first = fmt.Sprintf("up_%dMB_%s", got>>20, verdict(err))
		}
	}
	then := "-"
	if strings.HasSuffix(first, "_END") {
		c.StandSeal(23, []byte("\x00\x00OK kufull\n"))
		then = window(c, 400*time.Millisecond)
		if then == "silent" {
			c.StandSeal(21, h("0100"))
			then = "silent>" + window(c, 2500*time.Millisecond)
		}
	}
	answers := c.StandReadGens(from)
	t.SetReadDeadline(time.Now().Add(2500 * time.Millisecond))
	io.Copy(io.Discard, t)
	// Whether the client closed. Not the records it wrote, as `shape` has them for the others: the
	// tap starts at the mark, which here falls inside a record, so the framing is lost.
	t.mu.Lock()
	end := "open"
	if t.fin {
		end = "fin"
	}
	t.mu.Unlock()
	fmt.Printf("%s kufull | client ee - | first %s | then %s | answers taken %d | client %s\n",
		label, first, then, answers, end)
}

func main() {
	if len(os.Args) != 7 {
		fmt.Fprintln(os.Stderr, "node LISTEN TARGET PRIVATE_KEY SHORT_ID SERVER_NAME SCENARIO_FILE")
		os.Exit(2)
	}
	priv, err := base64.RawURLEncoding.DecodeString(os.Args[3])
	if err != nil || len(priv) != 32 {
		fmt.Fprintln(os.Stderr, "private key:", err)
		os.Exit(2)
	}
	var sid [8]byte
	b, err := hex.DecodeString(os.Args[4])
	if err != nil || len(b) > 8 {
		fmt.Fprintln(os.Stderr, "short id:", err)
		os.Exit(2)
	}
	copy(sid[:], b)
	var d net.Dialer
	cfg := &reality.Config{
		DialContext:            d.DialContext,
		Type:                   "tcp",
		Dest:                   os.Args[2],
		PrivateKey:             priv,
		ServerNames:            map[string]bool{os.Args[5]: true},
		ShortIds:               map[[8]byte]bool{sid: true},
		SessionTicketsDisabled: true,
	}
	// As Xray does when it loads a REALITY inbound, so that each connection carries the empty records
	// a stock node sends in the target's post-handshake lengths (vendor/REALITY/tls.go:419-435).
	reality.DetectPostHandshakeRecordsLens(cfg)
	time.Sleep(time.Second)

	ln, err := net.Listen("tcp", os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go serve(conn, cfg, os.Args[6])
	}
}
