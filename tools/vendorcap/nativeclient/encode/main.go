package main

import (
	"fmt"
	"github.com/xtls/xray-core/infra/conf/serial"
	"google.golang.org/protobuf/proto"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		panic("expected input JSON and output protobuf paths")
	}
	file, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer file.Close()
	config, err := serial.LoadJSONConfig(file)
	if err != nil {
		panic(err)
	}
	data, err := proto.Marshal(config)
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile(os.Args[2], data, 0600); err != nil {
		panic(err)
	}
	fmt.Println("CONFIG_PROTOBUF_ENCODED")
}
