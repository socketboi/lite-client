#!/bin/sh
# Writes src/core/goprint.h: strconv's isPrint tables from the go1.26.6 toolchain in the build image
# (GOROOT/src/strconv/isprint.go), four Go slices turned into C arrays. Run from the repository root:
#   docker run --rm -v "$PWD:/w" -w /w lc-build:local sh tools/goprint/gen.sh
set -e
F=$(go env GOROOT)/src/strconv/isprint.go
go version | grep -q 'go1.26.6 ' || { echo "not go1.26.6: $(go version)" >&2; exit 1; }
{
	echo "/* strconv's isPrint tables, copied from GOROOT/src/strconv/isprint.go of go1.26.6 — the toolchain"
	echo " * pinned for the Hysteria client oracles, whose %q the QUIC plane's texts are written in — by"
	echo " * tools/goprint/gen.sh. Do not edit. */"
	echo "#ifndef LC_GOPRINT_H"
	echo "#define LC_GOPRINT_H"
	echo
	echo "#include <stdint.h>"
	echo
	awk '/^var isPrint16 = /{print "static const uint16_t go_is_print16[] = {"; on=1; next}
/^var isNotPrint16 = /{print "static const uint16_t go_is_not_print16[] = {"; on=1; next}
/^var isPrint32 = /{print "static const uint32_t go_is_print32[] = {"; on=1; next}
/^var isNotPrint32 = /{print "static const uint16_t go_is_not_print32[] = { /* add 0x10000 to each entry */"; on=1; next}
/^var isGraphic = /{on=0; next}
on && /^}/{print "};"; print ""; on=0; next}
on{print}' "$F"
	echo "#endif"
} > src/core/goprint.h
