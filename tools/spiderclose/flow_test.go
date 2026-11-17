//go:build go1.27 && !http2legacy

package spiderclose

import (
	"bufio"
	"encoding/json"
	"flag"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"testing/synctest"

	"golang.org/x/net/http2"
)

var flowLog = flag.String("flow-log", "", "candidate FLOW_ORACLE observations")

type flowObservation struct {
	Case        string `json:"case"`
	SettingsAck int    `json:"settings_ack"`
	ConnClosed  bool   `json:"conn_closed"`
	StreamFlow  int    `json:"stream_flow"`
}

func observeFlow(t *testing.T, name string) flowObservation {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	result := flowObservation{Case: name}
	requestSeen := false
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(server, preface); err != nil || string(preface) != http2.ClientPreface {
			t.Error("invalid client preface")
			return
		}
		fr := http2.NewFramer(nil, server)
		for {
			frame, err := fr.ReadFrame()
			if err != nil {
				return
			}
			switch f := frame.(type) {
			case *http2.SettingsFrame:
				if f.IsAck() {
					result.SettingsAck++
				}
			case *http2.HeadersFrame:
				requestSeen = true
			case *http2.RSTStreamFrame:
				if f.ErrCode == http2.ErrCodeFlowControl {
					result.StreamFlow++
				}
			}
		}
	}()
	cc, err := (&http2.Transport{}).NewClientConn(client)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	fr := http2.NewFramer(server, nil)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	synctest.Wait()
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		req, err := http.NewRequest("GET", "https://flow-oracle.example/", nil)
		if err != nil {
			t.Error(err)
			return
		}
		response, _ := cc.RoundTrip(req)
		if response != nil {
			response.Body.Close()
		}
	}()
	synctest.Wait()
	if !requestSeen {
		t.Fatal("missing GET request")
	}
	if err := fr.WriteWindowUpdate(1, 0x7fff0000); err != nil {
		t.Fatal(err)
	}
	if err := fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 65536}); err != nil {
		t.Fatal(err)
	}
	synctest.Wait()
	if name == "window_detects" {
		if err := fr.WriteWindowUpdate(1, 1); err != nil {
			t.Fatal(err)
		}
	} else if name == "settings_restore" {
		if err := fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 65534}); err != nil {
			t.Fatal(err)
		}
		if err := fr.WriteWindowUpdate(1, 1); err != nil {
			t.Fatal(err)
		}
	}
	synctest.Wait()
	result.ConnClosed = cc.State().Closed
	cc.Close()
	server.Close()
	<-requestDone
	<-readDone
	return result
}

func TestFlowOracle(t *testing.T) {
	reference := make(map[string]flowObservation)
	for _, name := range []string{"settings_only", "window_detects", "settings_restore"} {
		t.Run(name, func(t *testing.T) { synctest.Test(t, func(t *testing.T) { reference[name] = observeFlow(t, name) }) })
	}
	if *flowLog == "" {
		t.Fatal("candidate flow log is required")
	}
	file, err := os.Open(*flowLog)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "FLOW_ORACLE ") {
			continue
		}
		var got flowObservation
		decoder := json.NewDecoder(strings.NewReader(strings.TrimPrefix(line, "FLOW_ORACLE ")))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&got); err != nil {
			t.Fatal(err)
		}
		want, exists := reference[got.Case]
		if !exists || seen[got.Case] || got != want {
			t.Fatalf("candidate flow differs: got %+v, want %+v", got, want)
		}
		seen[got.Case] = true
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 3 {
		t.Fatal("incomplete candidate flow observations")
	}
	t.Log("Three SETTINGS/WINDOW_UPDATE cases match the actual Go transport")
}
