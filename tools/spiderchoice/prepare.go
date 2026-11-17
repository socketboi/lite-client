//go:build ignore

// Build test-only overlays; never edit the pinned Go installation.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const helper = `package maps

import (
    "internal/abi"
    "unsafe"
)

var choiceEnabled bool
var choiceEntry, choiceDir uint64

//go:linkname choiceOffsets lite_spiderchoice_offsets
func choiceOffsets(entry, dir uint64, enabled bool) {
    choiceEntry, choiceDir, choiceEnabled = entry, dir, enabled
}

//go:linkname choiceHash lite_spiderchoice_hash
func choiceHash(typ *abi.MapType, m *Map, key unsafe.Pointer) uint64 {
    return uint64(typ.Hasher(key, m.seed))
}
`

func main() {
	if len(os.Args) != 2 || runtime.Version() != "go1.27.3" {
		panic("expected output directory and pinned Go 1.27.3")
	}
	out, err := filepath.Abs(os.Args[1])
	if err != nil {
		panic(err)
	}
	path := filepath.Join(runtime.GOROOT(), "src/internal/runtime/maps/table.go")
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	old := "\tit.entryOffset = rand()\n\tit.dirOffset = rand()"
	if strings.Count(string(data), old) != 1 {
		panic("Go Iter.Init observer anchor is not unique")
	}
	changed := strings.Replace(string(data), old, old+`
    if choiceEnabled {
        it.entryOffset = choiceEntry
        it.dirOffset = choiceDir
    }`, 1)
	files := map[string]string{"table.go": changed, "helper.go": helper}
	for name, text := range files {
		if err := os.WriteFile(filepath.Join(out, name), []byte(text), 0600); err != nil {
			panic(err)
		}
	}
	replace := map[string]string{
		path: filepath.Join(out, "table.go"),
		filepath.Join(filepath.Dir(path), "lite_spiderchoice.go"): filepath.Join(out, "helper.go"),
	}
	encoded, err := json.Marshal(map[string]any{"Replace": replace})
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(out, "overlay.json"), encoded, 0600); err != nil {
		panic(err)
	}
	fmt.Println("Go Iter.Init overlay prepared")
}
