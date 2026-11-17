package main

import (
	"bytes"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"

	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/log"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/proxy/dokodemo"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/transport/internet/headers/noop"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("expected one protobuf configuration path")
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		return err
	}
	config, err := core.LoadConfig("protobuf", bytes.NewReader(data))
	if err != nil {
		return err
	}
	server, err := core.New(config)
	if err != nil {
		return err
	}
	if err = server.Start(); err != nil {
		return err
	}
	defer server.Close()
	// Same post-start collection and signal lifetime as main.executeRun.
	runtime.GC()
	debug.FreeOSMemory()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	<-signals
	return nil
}
