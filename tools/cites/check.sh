#!/bin/sh
# Every citation into vendor/, in every form this tree actually writes one, checked to land inside
# the file it names.
#
# WHY THIS EXISTS AS A SCRIPT. The gate used to be four lines of shell in the Makefile and it matched
# ONE form, `vendor/path/file.go` followed by a line number. The comments in this tree write four
# more, and the difference is not cosmetic — a citation the checker cannot see is a claim nobody
# verifies:
#
#   vendor/hysteria/core/client/client.go, line 146   the form it saw
#   core/internal/congestion/utils.go, lines 36-42    a path, no vendor/ prefix         — unseen
#   bbr_sender dot go, line 801                       a bare file name                  — unseen
#   udp_linux dot go, lines 71,80                     a list, second number dropped     — half seen
#   send_conn dot go                                  a name with no line at all        — unseen
#
# (spelled out rather than written as citations, so that this comment is not itself a finding.)
#
# The last of those is how a claim about `maxPacketsPerBatch` in send_conn.go survived here for
# weeks: there is no such identifier in the pinned revision, and nothing looked. It was found by
# measuring the thing the comment described, which is an expensive way to read a comment.
#
# TWO LEVELS, AND THE SECOND ONE IS A NUMBER RATHER THAN A VETO.
#
#   FAIL       the citation cannot be right: the file does not exist, or the line is past the end of
#              every file it could mean. Nothing about the tree makes this acceptable.
#   AMBIGUOUS  the file name matches more than one file under vendor/ and the lines are valid in at
#              least one of them. A reader in context usually knows which is meant; a machine never
#              does, and neither does the automated citation audit, which drops these silently.
#              Counted and summarised so the debt is visible and can be worked down, rather than
#              failing a build that has carried these since August.
#
# Xray-core vendors its own copy of hysteria's congestion package, so `bbr_sender` and its
# neighbours exist TWICE under vendor/ with different line numbers. That is why the ambiguity level
# is not cosmetic: a bare name there resolves to the wrong file half the time.
#
# WHAT THIS DOES NOT CHECK: the claim. A citation can point at a real line that says something else
# entirely. That is what the citation audit and a reader are for. This only guarantees that an
# address is an address.
#
#	sh tools/cites/check.sh [dir...]     (default: src patches Makefile README.md docs/BUILD.md docs/DESIGN.md test tools)
set -u

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT" || exit 1

[ $# -gt 0 ] && WHERE="$*" || WHERE="src patches Makefile README.md docs/BUILD.md docs/DESIGN.md test tools"

[ -d vendor ] || { echo "  ok    no vendor/ tree to check citations against"; exit 0; }

tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT

# One index of the vendor tree: resolving a few hundred citations with a find each takes minutes on a
# bind mount and seconds this way.
find vendor -type f \( -name '*.go' -o -name '*.c' -o -name '*.h' -o -name '*.cc' \
    -o -name '*.hpp' -o -name '*.rs' -o -name '*.py' -o -name '*.md' -o -name '*.proto' \
    -o -name '*.yaml' -o -name '*.json' \) 2>/dev/null > "$tmp/index"

grep -rhoE '[A-Za-z0-9_][A-Za-z0-9_./+-]*\.(go|c|h|cc|hpp|rs|py|md|proto|yaml|json):[0-9]+([-,][0-9]+)*' \
    $WHERE 2>/dev/null | sort -u > "$tmp/cites"

: > "$tmp/fail"
: > "$tmp/ambig"
checked=0

# Whether every number in |nums| is a line of |file|.
lines_fit() {
	_file=$1
	_nums=$2
	_end=$(wc -l < "$_file")
	_bad=0

	for _n in $(echo "$_nums" | tr ',-' '  '); do
		[ -n "$_n" ] || continue
		[ "$_n" -ge 1 ] 2>/dev/null && [ "$_n" -le "$_end" ] || _bad=1
	done

	return $_bad
}

while IFS= read -r cite; do
	path=${cite%%:*}
	nums=${cite#*:}

	case "$path" in
	vendor/*)
		if [ ! -f "$path" ]; then
			echo "$cite (no such file)" >> "$tmp/fail"
			continue
		fi

		checked=$((checked + 1))
		lines_fit "$path" "$nums" ||
			echo "$cite (past the end of $path, which has $(wc -l < "$path") lines)" >> "$tmp/fail"
		;;
	src/* | test/* | tools/* | patches/* | package/* | openwrt/* | build*/*)
		# Ours, checked by the compiler and by whoever moves the line.
		continue
		;;
	*)
		cands=$(grep "/$path\$" "$tmp/index" || true)
		[ -n "$cands" ] || continue # a name that is not in vendor at all: not a citation into it

		n_cands=$(echo "$cands" | grep -c .)
		fits=0
		for c in $cands; do
			lines_fit "$c" "$nums" && fits=$((fits + 1))
		done

		if [ "$fits" = "0" ]; then
			echo "$cite (past the end of all $n_cands files it could mean)" >> "$tmp/fail"
		elif [ "$n_cands" = "1" ]; then
			checked=$((checked + 1))
		else
			echo "$cite -> $n_cands candidates" >> "$tmp/ambig"
		fi
		;;
	esac
done < "$tmp/cites"

if [ -s "$tmp/fail" ]; then
	sort -u "$tmp/fail" | sed 's|^|  FAIL  citation does not land: |'
	exit 1
fi

n_ambig=$(wc -l < "$tmp/ambig" | tr -d " ")

echo "  ok    all $checked resolvable citations into vendor/ land inside the file they name"

if [ "$n_ambig" != "0" ]; then
	echo "  ----  $n_ambig citations name a file that exists more than once under vendor/, so no"
	echo "        machine can say which is meant. The lines are valid in at least one. Worst offenders:"
	sort -t'>' -k2 -rn "$tmp/ambig" | head -5 | sed 's|^|          |'
fi
