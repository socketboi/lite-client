// Emit exact orders from the pinned Go iterator, with controlled starting offsets.
package main

import (
	"fmt"
	"runtime"
	"strconv"
	"unsafe"
)

// The overlay exports these test-only hooks. Ordinary runtime code has neither.
//
//go:linkname choiceOffsets lite_spiderchoice_offsets
func choiceOffsets(entry, dir uint64, enabled bool)

//go:linkname choiceHash lite_spiderchoice_hash
func choiceHash(typ, m, key unsafe.Pointer) uint64

func main() {
	if runtime.Version() != "go1.27.3" || unsafe.Sizeof(uintptr(0)) != 8 {
		panic("expected the pinned 64-bit Go 1.27.3 oracle")
	}
	fmt.Printf("/* Actual %s Iter.Next orders; test-only offsets; do not edit. */\n", runtime.Version())
	fmt.Println("struct choice_walk { uint64_t entry, dir; const unsigned *order; };")
	fmt.Println("struct choice_map { unsigned n, walks; const uint64_t *hash; const struct choice_walk *walk; };")
	sizes := []int{1, 2, 3, 7, 8, 9, 14, 15, 16, 21, 28, 29, 56, 57, 112, 113, 896, 897, 1800, 3600}
	mapID := 0
	for _, n := range sizes {
		for trial := 0; trial < 2; trial++ {
			m := make(map[string]struct{})
			keys := make([]string, n)
			for i := range keys {
				keys[i] = "/"
				if i != 0 {
					keys[i] = "/h" + strconv.Itoa(i-1)
				}
				m[keys[i]] = struct{}{}
			}
			// Empty-interface words are type and data; data is this actual map.
			var boxed any = m
			words := *(*[2]unsafe.Pointer)(unsafe.Pointer(&boxed))
			fmt.Printf("static const uint64_t choice_hash_%d[%d] = {", mapID, n)
			for _, key := range keys {
				fmt.Printf("0x%xull,", choiceHash(words[0], words[1], unsafe.Pointer(&key)))
			}
			fmt.Println("};")
			entries := []uint64{0, 1, 7, 8, 15, 31, ^uint64(0)}
			if n <= 21 {
				entries = make([]uint64, 32)
				for i := range entries {
					entries[i] = uint64(i)
				}
			}
			dirs := []uint64{0, 1, 3, ^uint64(0)}
			walkID := 0
			for _, entry := range entries {
				for _, dir := range dirs {
					choiceOffsets(entry, dir, true)
					order := make([]int, 0, n)
					for key := range m {
						i := 0
						if key != "/" {
							value, err := strconv.Atoi(key[2:])
							if err != nil {
								panic(err)
							}
							i = value + 1
						}
						order = append(order, i)
					}
					choiceOffsets(0, 0, false)
					if len(order) != n {
						panic("incomplete Go iterator")
					}
					fmt.Printf("static const unsigned choice_order_%d_%d[%d] = {", mapID, walkID, n)
					for _, key := range order {
						fmt.Printf("%d,", key)
					}
					fmt.Println("};")
					walkID++
				}
			}
			fmt.Printf("static const struct choice_walk choice_walk_%d[%d] = {\n", mapID, walkID)
			walkID = 0
			for _, entry := range entries {
				for _, dir := range dirs {
					fmt.Printf("{0x%xull,0x%xull,choice_order_%d_%d},\n", entry, dir, mapID, walkID)
					walkID++
				}
			}
			fmt.Println("};")
			runtime.KeepAlive(m)
			mapID++
		}
	}
	fmt.Printf("#define CHOICE_MAPS %du\nstatic const struct choice_map choice_maps[CHOICE_MAPS] = {\n", mapID)
	for i, n := range sizes {
		walks := 28
		if n <= 21 {
			walks = 128
		}
		for trial := 0; trial < 2; trial++ {
			id := i*2 + trial
			fmt.Printf("{%du,%du,choice_hash_%d,choice_walk_%d},\n", n, walks, id, id)
		}
	}
	fmt.Println("};")
}
