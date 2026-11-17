// Laid beside Xray's own browser.go (vendor/Xray-core/common/utils/browser.go, brought into this
// package by `go build -overlay`, see gen.sh) so that the package initialises the way Xray's does,
// on a CPU the generator names instead of the one it runs on.
package utils

import (
	"fmt"
	"math"
	"os"

	"github.com/klauspost/cpuid/v2"
)

// Declared before browser.go's globalRng — the go command hands a package's files to the compiler
// sorted by name, and a package's variables initialise in declaration order — so this runs first
// and globalRng, CurlUA, ... AnchoredChromeVersion are then computed by browser.go as written.
var lcCPU = lcSetCPU()

func lcSetCPU() bool {
	s := os.Getenv("LC_CPU")
	if s == "" {
		return false
	}
	c := &cpuid.CPU
	if _, err := fmt.Sscanf(s, "%d,%d,%d,%d,%d,%d", &c.Family, &c.Model, &c.PhysicalCores,
		&c.LogicalCores, &c.CacheLine, &c.ThreadsPerCore); err != nil {
		panic(err)
	}
	return true
}

// LcFloats is the first four Float64 of a generator seeded by GetRandomizer for the CPU as it
// stands, as bits.
func LcFloats() [4]uint64 {
	r := GetRandomizer()
	var o [4]uint64
	for i := range o {
		o[i] = math.Float64bits(r.Float64())
	}
	return o
}
