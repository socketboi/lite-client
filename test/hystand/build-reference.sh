#!/bin/sh
# Always build from the current vendor pin; an old executable is not cache proof.
set -eu
out=$1
mkdir -p "$out"
out=$(cd "$out" && pwd)
revision=$(git -C vendor/hysteria rev-parse HEAD)
go=${LC_HYSTAND_GO:-/usr/local/go1.27/bin/go}
pkg=github.com/apernet/hysteria/app/v2/cmd
toolchain=$("$go" env GOVERSION)
architecture=$("$go" env GOARCH)
build_date=$(date -u +%Y-%m-%dT%H:%M:%SZ)
quic_version=$(cd vendor/hysteria/app && GOWORK=off "$go" list -mod=readonly -m -f '{{.Version}}' github.com/apernet/quic-go)
(cd vendor/hysteria/app && GOWORK=off CGO_ENABLED=0 "$go" build -mod=readonly -trimpath \
  -ldflags "-X $pkg.appVersion=reference-$revision -X $pkg.appCommit=$revision -X $pkg.appToolchain=$toolchain \
  -X $pkg.appDate=$build_date -X $pkg.appType=local-qualification -X $pkg.appPlatform=linux \
  -X $pkg.appArch=$architecture -X $pkg.libVersion=$quic_version" \
  -o "$out/ref-hysteria" .)
