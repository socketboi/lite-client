#!/bin/sh
# Qualify the launcher against the official Linux x86-64 release.
set -eu
cd "$(dirname "$0")"

version=$(sed -n 's/^XRAY_VERSION=//p' lc-xray)
sha256=b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

curl --fail --silent --show-error --location --proto '=https' \
	--connect-timeout 10 --max-time 120 --output "$work/xray.zip" \
	"https://github.com/XTLS/Xray-core/releases/download/v$version/Xray-linux-64.zip"
printf '%s  %s\n' "$sha256" "$work/xray.zip" | sha256sum -c -
python3 -m zipfile -e "$work/xray.zip" "$work"
chmod 0755 "$work/xray"
sh -n lc-xray
sh -n files/lite-client-xray.init
XRAY_TEST_CORE="$work/xray" XRAY_LOCATION_ASSET="$work" python3 test_runtime.py -v
