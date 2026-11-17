// What Xray's package init makes of a CPU: the fields klauspost/cpuid holds, the Chrome version
// AnchoredChromeVersion came out at and the day that was, and the first four draws of the
// generator. One line per run; gen.sh runs it once per CPU and once as the machine itself.
package main

import (
	"fmt"
	"time"

	"github.com/klauspost/cpuid/v2"

	"xraybrowser/utils"
)

func main() {
	// The day ChromeVersion read at init; a run that straddles midnight UTC is told apart by the
	// generator comparing two readings, and redone.
	day := time.Now().Unix() / 86400
	c := cpuid.CPU
	f := utils.LcFloats()
	fmt.Printf("%d %d %d %d %d %d %d %d 0x%016xULL 0x%016xULL 0x%016xULL 0x%016xULL\n",
		c.Family, c.Model, c.PhysicalCores, c.LogicalCores, c.CacheLine, c.ThreadsPerCore,
		utils.AnchoredChromeVersion, day, f[0], f[1], f[2], f[3])
}
