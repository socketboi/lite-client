#!/bin/sh
# Run only in the documented Linux build environment; do not modify GOROOT.
set -eu
test "$#" -eq 1
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
go=${GO127:-/usr/local/go1.27/bin/go}
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
expected=$(awk -F= '$1=="ARG GO127_VERSION" {print $2}' "$root/docker/Dockerfile")
test "$expected" = 1.27.3
test "$("$go" env GOVERSION)" = "go$expected"
mkdir -p "$(dirname "$1")"
out=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
work=$(mktemp -d "$out.overlay.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
goroot=$("$go" env GOROOT)
sha256sum "$goroot/src/internal/runtime/maps/map.go" "$goroot/src/internal/runtime/maps/table.go" > "$work/before.sha256"
cd "$here"
"$go" run prepare.go "$work" >&2
"$go" run -overlay "$work/overlay.json" main.go > "$work/vectors.h"
sha256sum -c "$work/before.sha256" >&2
cp "$work/before.sha256" "$out.inputs.sha256"
mv "$work/vectors.h" "$out"
