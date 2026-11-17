#!/bin/sh
# Render the trust-anchor body from the actual reference, independently of tools/fp.
set -eu
out=$1
here=$(cd "$(dirname "$0")" && pwd)
q=$(cd vendor/quic-go && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
python3 - "$q" "$here" "$tmp/overlay.json" <<'PY'
import json
from pathlib import Path
import sys
q, here, out = map(Path, sys.argv[1:])
replace = {str(path): '' for path in (q / 'internal/handshake').glob('*_test.go')}
replace[str(q / 'internal/handshake/zz_trustanchors_test.go')] = str(here / 'trustanchors_test.go')
out.write_text(json.dumps({'Replace': replace}))
PY
(cd "$q" && go test -c -vet=off -tags qtrust -overlay "$tmp/overlay.json" -o "$tmp/oracle" ./internal/handshake)
LC_TRUST_ANCHORS_OUT="$tmp/output.h" "$tmp/oracle" -test.run '^TestTrustAnchorVec$'
grep -q '^static const uint8_t reference_trust_anchors\[' "$tmp/output.h"
mv "$tmp/output.h" "$out"
