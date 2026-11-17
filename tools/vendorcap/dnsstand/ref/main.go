// The reference's lookup, as a dial of Xray or a start of hysteria makes it: Go's own resolver
// (built with CGO_ENABLED=0, as both are), Resolver.LookupIPAddr, which is lookupIPAddr(ctx, "ip",
// name). Prints the addresses in the order Go returns them, or the error.
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
)

func main() {
	addrs, err := net.DefaultResolver.LookupIPAddr(context.Background(), os.Args[1])
	if err != nil {
		fmt.Println("ERR", err)
		return
	}
	s := make([]string, len(addrs))
	for i, a := range addrs {
		s[i] = a.String()
	}
	fmt.Println("ADDRS", strings.Join(s, " "))
}
