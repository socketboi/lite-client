#!/bin/sh
# The ambiguous citations, with everything needed to resolve each one by reading rather than guessing.
#
# check.sh counts them; this prints them. For every citation whose file name exists more than once
# under vendor/, it shows WHERE we cite it from (with the sentence that makes the claim) and WHAT
# each candidate file says at those lines. The one whose lines carry the claim is the one meant, and
# the citation is then rewritten to a path that can only mean that file.
#
# Why this is not done automatically: the claim lives in prose. A machine can see that two candidates
# both have a line 146; only a reader can see which line 146 is the one the sentence is about. What
# is mechanical here is the gathering, and that is what this does.
#
#	sh tools/cites/ambiguous.sh [citation]    (default: every ambiguous one)
set -u

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT" || exit 1

tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT

find vendor -type f \( -name '*.go' -o -name '*.c' -o -name '*.h' -o -name '*.cc' \
    -o -name '*.hpp' -o -name '*.rs' -o -name '*.py' -o -name '*.md' -o -name '*.proto' \) \
    2>/dev/null > "$tmp/index"

if [ $# -gt 0 ]; then
	echo "$1" > "$tmp/cites"
else
	grep -rhoE '[A-Za-z0-9_][A-Za-z0-9_./+-]*\.(go|c|h|cc|hpp|rs|py|md|proto):[0-9]+([-,][0-9]+)*' \
	    src patches Makefile README.md docs/BUILD.md docs/DESIGN.md test tools 2>/dev/null | sort -u > "$tmp/cites"
fi

while IFS= read -r cite; do
	path=${cite%%:*}
	nums=${cite#*:}

	case "$path" in
	vendor/* | src/* | test/* | tools/* | patches/* | package/* | openwrt/* | build*/*) continue ;;
	esac

	cands=$(grep "/$path\$" "$tmp/index" || true)
	[ -n "$cands" ] || continue
	n=$(echo "$cands" | grep -c .)
	[ "$n" -gt 1 ] || continue

	echo "=============================================================================="
	echo "CITATION  $cite   ($n candidates)"
	echo "--- cited from:"
	grep -rn --include='*.c' --include='*.h' --include='*.go' --include='*.sh' \
	    --include='*.patch' --include='Makefile' --include='*.md' \
	    -F "$cite" src patches Makefile README.md docs/BUILD.md docs/DESIGN.md test tools 2>/dev/null | head -4 | sed 's/^/    /'

	first=${nums%%[-,]*}
	last=${nums##*[-,]}
	[ "$last" = "$nums" ] && last=$first

	for c in $cands; do
		echo "--- $c, lines $first-$last:"
		sed -n "${first},${last}p" "$c" 2>/dev/null | head -12 | sed 's/^/    /'
	done
done < "$tmp/cites"
