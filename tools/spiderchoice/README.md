# Exact REALITY path-choice oracle

Run `make build/test-spider-choice` inside the documented Linux build environment.
The test is part of `make check`. It complements the Go 1.26 statistical map
fixtures retained for Hysteria with an independent pinned Go 1.27.1 oracle for
REALITY's `getPathLocked`.

`gen.sh` runs the two Go programs by filename. `prepare.go` creates an isolated
GOROOT overlay: a hook reads each real map's hash through its actual ABI Hasher
and seed; another supplies entry/directory offsets to the ordinary `Iter.Init`.
The ordinary insertion, growth, splitting and `Iter.Next` remain Go's own code.
No C layout algorithm is copied into the oracle. Both original offset draws
still occur before the test offsets are installed. Runtime files are hashed
before and after generation and stay untouched. The script rejects a different
toolchain before producing a header; GOTOOLCHAIN switching and network downloads
are disabled. Its output header and `.inputs.sha256` identify the retained run.

Two actual maps at each of twenty sizes cover 1--3600 keys, including the
21-path closeafter set, small-group promotion, growth and directory splits.
Small sets cover every slot offset of the 32-slot table and four directory
offsets; larger sets include group boundaries and unsigned wraparound. Each
generated vector records the real key hashes and complete Go iteration order.
Map seeds vary when regenerating vectors; comparisons are exact for each
recorded layout and do not use statistical tolerances.

The C fixture compares `lc_gomap_order` with all recorded orders. For sets up to
21 keys it installs those hashes into an isolated path store, then drives the
public `lc_spider_path` through the real `rnd.c` sampler using scripted getrandom
bytes. Every allowed rank is checked: the reference's upper bound is excluded,
so the final iteration position is never chosen. Root remains an ordinary
eligible key, and cached hashes/counts must survive every draw. Separate cases
require rejection of an unacceptable random word and failure on missing entropy.

The fixture establishes exact agreement for its sampled layouts and controlled
inputs. It is not a performance, frequency or G2 acceptance test. Cross-build it
for the target and distinguish QEMU results from execution on the device.

The fixture also checks `lc_gomap_at` at every rank through 21 keys and six ranks
for larger maps, including the final position. Hinted-map comparisons cover empty
tables and directory aliases. Linker-wrapped allocator failures require complete
cleanup; wrappers exclude nested calls inside statically linked musl allocators.

`make build/bench-spider-choice` builds a separate deterministic CPU microbenchmark
of actual path draws and full header walks. Keep its inputs and compiler flags
matched for before/after measurements; compare output checksums and distinguish
process CPU cost from network throughput. It is not part of G2 acceptance.
