//go:build go1.27 && !http2legacy

// Exercise the pinned Go transport without overlays or scheduler timing guesses.
package spiderclose

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"testing"
	"testing/synctest"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type observation struct {
	Case         string `json:"case"`
	Cancel       int    `json:"cancel"`
	ConnCredit   uint32 `json:"conn_credit"`
	StreamCredit uint32 `json:"stream_credit"`
	Ping         int    `json:"ping"`
}

var candidateLog = flag.String("c-log", "", "C --close-oracle output to compare with the pinned Go transport")

// Hold an actual reset Write after cleanup has selected CANCEL. Channel waits
// are test-only; the reference transport and its readLoop stay unmodified.
type resetGate struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
}

func (g *resetGate) Write(p []byte) (int, error) {
	frames := p
	if bytes.HasPrefix(frames, []byte(http2.ClientPreface)) {
		frames = frames[len(http2.ClientPreface):]
	}
	fr := http2.NewFramer(nil, bytes.NewReader(frames))
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			if err != io.EOF {
				panic(fmt.Sprintf("partial client Write in oracle: %v", err))
			}
			break
		}
		if _, ok := f.(*http2.RSTStreamFrame); ok {
			close(g.entered)
			<-g.release
		}
	}
	return g.Conn.Write(p)
}

func TestCloseOracle(t *testing.T) {
	if runtime.Version() != "go1.27.3" {
		t.Fatalf("expected pinned go1.27.3, got %s", runtime.Version())
	}
	reference := make(map[string]observation)
	for _, name := range []string{"end_before_close", "close_before_end", "end_during_reset"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { reference[name] = runCase(t, name) })
		})
	}
	if *candidateLog != "" {
		compareCandidate(t, reference)
	}
}

func compareCandidate(t *testing.T, reference map[string]observation) {
	data, err := os.ReadFile(*candidateLog)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		encoded, ok := strings.CutPrefix(line, "CLOSE_ORACLE ")
		if !ok {
			continue
		}
		var got observation
		dec := json.NewDecoder(strings.NewReader(encoded))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&got); err != nil {
			t.Fatal(err)
		}
		var tail any
		if err := dec.Decode(&tail); err != io.EOF {
			t.Fatal("unexpected data after C observation")
		}
		want, exists := reference[got.Case]
		if !exists || seen[got.Case] || got != want {
			t.Fatalf("C close result differs from pinned Go: got %+v, want %+v", got, want)
		}
		seen[got.Case] = true
	}
	if len(seen) != 3 || len(reference) != 3 {
		t.Fatal("expected exactly three complete C/Go observations")
	}
	t.Log("Three controlled C/Go close cases match; this does not grant G2 acceptance.")
}

func runCase(t *testing.T, name string) observation {
	client, server := net.Pipe()
	gate := &resetGate{Conn: client, entered: make(chan struct{}), release: make(chan struct{})}
	defer client.Close()
	defer server.Close()
	result := observation{Case: name}
	collect, request, ack := false, false, false
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(server, preface); err != nil || string(preface) != http2.ClientPreface {
			t.Errorf("invalid preface: %v", err)
			return
		}
		fr := http2.NewFramer(nil, server)
		for {
			frame, err := fr.ReadFrame()
			if err != nil {
				return
			}
			switch f := frame.(type) {
			case *http2.HeadersFrame:
				if f.StreamID != 1 || !f.StreamEnded() || !f.HeadersEnded() || request {
					t.Error("expected exactly one complete GET request on stream 1")
				}
				request = true
			case *http2.SettingsFrame:
				ack = ack || f.IsAck()
			case *http2.RSTStreamFrame:
				if !collect || f.StreamID != 1 || f.ErrCode != http2.ErrCodeCancel {
					t.Errorf("unexpected reset: %v", f)
				}
				result.Cancel++
			case *http2.WindowUpdateFrame:
				if collect {
					if f.StreamID != 0 || f.Increment != 5000 {
						t.Errorf("expected one exact connection-only refund: %v", f)
					}
					if f.StreamID == 0 {
						result.ConnCredit += f.Increment
					} else {
						result.StreamCredit += f.Increment
					}
				}
			case *http2.PingFrame:
				result.Ping++
			default:
				t.Errorf("unexpected client frame: %T", f)
			}
		}
	}()
	cc, err := (&http2.Transport{}).NewClientConn(gate)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	fr := http2.NewFramer(server, nil)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	synctest.Wait()
	if !ack {
		t.Fatal("missing initial SETTINGS ACK")
	}
	responses := make(chan *http.Response, 1)
	go func() {
		req, err := http.NewRequest("GET", "https://close-oracle.example/", nil)
		if err != nil {
			t.Error(err)
			return
		}
		resp, err := cc.RoundTrip(req)
		if err != nil {
			t.Error(err)
		}
		responses <- resp
	}()
	synctest.Wait()
	if !request {
		t.Fatal("missing request HEADERS")
	}
	collect = true
	var headers bytes.Buffer
	enc := hpack.NewEncoder(&headers)
	for _, h := range []hpack.HeaderField{
		{Name: ":status", Value: "302"},
		{Name: "location", Value: "/next"},
		{Name: "content-length", Value: "5000"},
	} {
		if err := enc.WriteField(h); err != nil {
			t.Fatal(err)
		}
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1, EndHeaders: true, BlockFragment: headers.Bytes(),
	}); err != nil {
		t.Fatal(err)
	}
	resp := <-responses
	if resp == nil || resp.StatusCode != 302 || resp.ContentLength != 5000 {
		t.Fatal("expected unread 5000-byte redirect response")
	}
	body := bytes.Repeat([]byte{'b'}, 5000)
	if name != "close_before_end" {
		if err := fr.WriteData(1, name == "end_before_close", body); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
	}
	if name == "end_before_close" && cc.State().StreamsActive != 0 {
		t.Fatal("END_STREAM must finish request cleanup before Close")
	}
	closed := make(chan error, 1)
	go func() { closed <- resp.Body.Close() }()
	synctest.Wait()
	if name != "end_before_close" {
		select {
		case <-gate.entered:
		default:
			t.Fatal("cleanup did not select CANCEL")
		}
		select {
		case <-closed:
			t.Fatal("Close returned before its reset Write completed")
		default:
		}
		if name == "end_during_reset" {
			if err := fr.WriteData(1, true, nil); err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
			if cc.State().StreamsActive != 1 {
				t.Fatal("reset Write must retain its stream until completion")
			}
		}
		close(gate.release)
		synctest.Wait()
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("Close did not finish")
	}
	if cc.State().StreamsActive != 0 {
		t.Fatal("Close did not complete stream cleanup")
	}
	if name == "close_before_end" {
		if err := fr.WriteData(1, true, body); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
	}
	wantReset := 1
	if name == "end_before_close" {
		wantReset = 0
	}
	if result.Cancel != wantReset || result.ConnCredit != 5000 || result.StreamCredit != 0 || result.Ping != 0 {
		t.Fatalf("unexpected wire result: %+v", result)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("CLOSE_ORACLE %s\n", encoded)
	cc.Close()
	server.Close()
	<-readDone
	return result
}
