#!/bin/sh
# Build a test-only distribution of the pinned Xray, without editing vendor/.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out=${1:-"$root/build/native-reference"}
mkdir -p "$out"
out=$(cd "$out" && pwd)
go=${XRAY_GO:-/usr/local/go1.27/bin/go}
test -x "$go" || { echo "Missing pinned Xray Go toolchain: $go" >&2; exit 1; }
export GOTOOLCHAIN=local
expected=$(awk -F= '$1=="ARG GO127_VERSION" {print $2}' "$root/docker/Dockerfile")
actual=$("$go" env GOVERSION)
if [ -z "$expected" ] || [ "$actual" != "go$expected" ]; then
    echo "Xray reference requires Go $expected; found $actual" >&2
    exit 1
fi
CGO_ENABLED=0 "$go" env GOVERSION GOOS GOARCH GOMIPS CGO_ENABLED > "$out/toolchain.txt"
cd "$root/vendor/Xray-core"

# The target runner consumes protobuf, so no configuration-parser or unrelated
# protocol implementation is linked into the small-router test executable.
CGO_ENABLED=0 "$go" build -mod=readonly -trimpath -ldflags='-s -w' \
    -o "$out/reference" "$here/runner/main.go"

# Encoding remains a HOST operation even when the runner is cross-built.
GOOS=$("$go" env GOHOSTOS) GOARCH=$("$go" env GOHOSTARCH) CGO_ENABLED=0 \
    "$go" build -mod=readonly -trimpath -ldflags='-s -w' \
    -o "$out/encode" "$here/encode/main.go"
sha256sum go.mod go.sum core/config.go core/xray.go main/run.go \
    transport/internet/reality/reality.go > "$out/vendor-source.sha256"
sha256sum "$here/runner/main.go" "$here/encode/main.go" > "$out/adapter-source.sha256"
sha256sum "$out/reference" "$out/encode" > "$out/binaries.sha256"
