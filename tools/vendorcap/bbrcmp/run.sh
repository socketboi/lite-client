#!/bin/sh
# The ninth stand: the REFERENCE congestion controller and the PORT of it, driven through one script,
# compared number by number.
#
# WHY THIS AND NOT THE OTHER STANDS. test/hystand/loss.sh runs both clients over a path and prints what
# each achieved; test/hybbr checks the port against values worked out by hand; the phases were compared
# against the reference's own debug output. None of those answers "does this compute what the
# reference computes" — they answer "is it fast", "does it match what I believed", "does it change
# state at the same times". This one puts the two implementations side by side on identical input and
# diffs their output.
#
# HOW THE REFERENCE IS REACHED. Its package lives at core/internal/congestion/bbr, and Go refuses an
# import of internal/ from outside core/. So run.sh copies that package and its neighbour common/ into
# a scratch module under /tmp and builds the driver there, with quic-go resolved to the vendored copy.
# vendor/ is never written to; the copy is a build artefact like every other in build-stand.
#
# WHERE THE COMPARISON STOPS BEING POSSIBLE, and it is one line: entering PROBE_BW draws a random
# cycle offset (rand.Int31n in the reference, ngtcp2's PCG here), and from that event on the two
# pacing gains are different by construction. The script therefore stays in STARTUP and DRAIN, which
# is where the sampler, the filter, the min-RTT logic, full-bandwidth detection and both windows do
# their work. If a round enters PROBE_BW the diff says so rather than pretending.
#
# WHAT IT SAYS, 19 September: no difference at all. Fifteen rounds, and the two implementations print
# the same window, the same pacing rate and the same flags at every one of them:
#
#   the startup ramp        53760 -> 66560 -> 79360 bytes, pacing 47267840 then 16384000 bits/s
#   full bandwidth at 07    the window comes DOWN to 25600 = twice the bandwidth-delay product
#   PROBE_BW gain           6400000 bits/s, which is 1.25 x the 5120000 the path gives
#   the round with a loss   the cycle advances to 0.75 (3840000), recovery window 11520
#
# The first version of this stand reported one difference, and it was the die roll above: the reference
# had drawn offset 0 and the port something in 2..7, so the pacing rates differed by exactly 1.25.
# Everything else was already identical — which is the result, and holding the die made it visible as
# one rather than as nine rounds of noise.
#
# Run from the repository root:
#
#	sh tools/vendorcap/bbrcmp/run.sh
set -e

IMG=lc-build:local
OUT=build-stand
HERE=tools/vendorcap/bbrcmp

W=$(pwd)
if WW=$(pwd -W 2>/dev/null) && [ -n "$WW" ]; then W=$WW; fi
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

docker run -i --rm -v "$W:/w" -v hy-gocache:/root/.cache/go-build -v hy-gomod:/go/pkg/mod \
	-w /w "$IMG" sh -s <<'SH'
set -e
cd /w
mkdir -p build-stand

# ---- the reference, in a scratch module ------------------------------------------
rm -rf /tmp/bbrcmp
mkdir -p /tmp/bbrcmp/bbr /tmp/bbrcmp/common
cp vendor/hysteria/core/internal/congestion/bbr/*.go /tmp/bbrcmp/bbr/
cp vendor/hysteria/core/internal/congestion/common/*.go /tmp/bbrcmp/common/
rm -f /tmp/bbrcmp/bbr/*_test.go
cp tools/vendorcap/bbrcmp/ref/main.go /tmp/bbrcmp/main.go

# The package imports itself by its module path inside hysteria; in the scratch module it is bbrcmp/…
sed -i 's|github.com/apernet/hysteria/core/v2/internal/congestion/common|bbrcmp/common|' /tmp/bbrcmp/bbr/*.go

# ---- the one thing that cannot be compared, pinned on both sides -------------------
#
# Entering PROBE_BW draws a cycle offset at random — `rand.Int31n` in the reference, ngtcp2's PCG in
# the port — and the offset decides the pacing gain: 1.25 for offset 0, 1.0 for 2..7. Two honest
# implementations therefore print different pacing rates from that event on, which is a difference in
# a die roll and not in the algorithm. Left alone, this stand read that as its only finding.
#
# So the die is held on both sides. Here, by rewriting the draw in the COPY to the constant zero —
# a build artefact in /tmp, never vendor/; and on our side by the driver choosing the PCG seed whose
# first draw gives the same offset. Everything else about the cycle — when it advances, what it does
# to the window — is compared as it is.
sed -i 's|b.cycleCurrentOffset = int(rand.Int31n(congestion.PacketsPerConnectionID)) % (gainCycleLength - 1)|b.cycleCurrentOffset = 0 // pinned by tools/vendorcap/bbrcmp/run.sh: see the note there|' /tmp/bbrcmp/bbr/bbr_sender.go
# The import goes with the call: Go refuses a package that is imported and not used.
sed -i "s|^	\"math/rand\"$|	_ \"math/rand\"|" /tmp/bbrcmp/bbr/bbr_sender.go
grep -q "pinned by tools/vendorcap/bbrcmp" /tmp/bbrcmp/bbr/bbr_sender.go || { echo "== the draw in the reference has moved: the pin no longer applies, and the comparison would be a die roll"; exit 1; }

cat > /tmp/bbrcmp/go.mod <<'MOD'
module bbrcmp

go 1.25.0

require (
	github.com/apernet/quic-go v0.0.0
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842
)

replace github.com/apernet/quic-go => /w/vendor/quic-go
MOD

cd /tmp/bbrcmp
go mod tidy >/tmp/bbrcmp-tidy.log 2>&1 || { echo "== the reference module does not resolve"; tail -15 /tmp/bbrcmp-tidy.log; exit 1; }
go build -o /tmp/bbr-ref . 2>/tmp/bbrcmp-build.log || { echo "== the reference driver does not build"; tail -20 /tmp/bbrcmp-build.log; exit 1; }
cd /w

# ---- ours ------------------------------------------------------------------------
# QUIC_GEN first: the controller lives in the patched tree, which the stamp creates.
# The controller lives in the patched tree; BUILD names which tree, and the stamp creates it.
make -s BUILD=build-stand/lc build-stand/lc/gen/ngtcp2/version.h build-stand/lc/ngtcp2/.patched >/dev/null
gcc -std=c11 -O2 -w -fno-common -D_GNU_SOURCE \
    -I build-stand/lc/gen -I build-stand/lc/ngtcp2/lib -I build-stand/lc/ngtcp2/lib/includes \
    -o /tmp/bbr-ours tools/vendorcap/bbrcmp/ours/main.c \
    build-stand/lc/ngtcp2/lib/ngtcp2_mem.c build-stand/lc/ngtcp2/lib/ngtcp2_pcg.c

# ---- the comparison ---------------------------------------------------------------
/tmp/bbr-ref  > /tmp/ref.txt
/tmp/bbr-ours > /tmp/ours.txt

echo "=== the reference"
cat /tmp/ref.txt
echo "=== ours"
cat /tmp/ours.txt
echo "=== difference"
if diff -u /tmp/ref.txt /tmp/ours.txt > /tmp/bbr.diff; then
	echo "  none: the port computes what the reference computes, round for round"
else
	# The first round that differs is the whole of the report: everything after it is downstream of
	# the same divergence and reading it as more findings is how one bug looks like twelve.
	sed -n '1,40p' /tmp/bbr.diff
	first=$(grep -n '^-round' /tmp/bbr.diff | head -1 | sed 's/.*round \([0-9]*\).*/\1/')
	echo "  first round that differs: ${first:-?}"
	exit 1
fi
SH
