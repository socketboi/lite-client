#!/bin/sh
# DIVERGENCES.md against the code: every `DIVERGES: <id>` mark in the tree names a row of the list,
# and every row of the list is marked somewhere. Then the count, so the gate says every time how far
# this client is from its reference and in which way.
#
# Run from the repository root (make check-divergences does).
LIST=DIVERGENCES.md

[ -f "$LIST" ] || { echo "  FAIL  $LIST is missing: the one list of divergences from the reference is gone"; exit 1; }

# A row: `| \`X1\` | ...` — the id in back-quotes in the first column. The section a row sits under
# is its kind; any other `## ` heading ends a section, so a heading renamed in one place and not the
# other leaves its rows without a kind and fails, instead of filing them under the section above.
rows=$(awk '
	/^## /                       { kind = "" }
	/^## Not yet ported/          { kind = "pending" }
	/^## Not reproducible/        { kind = "runtime" }
	/^## Maintainer.s decision/   { kind = "maintainer" }
	/^\| `[A-Z][0-9]+` \|/ {
		id = $2; gsub(/`/, "", id)
		print id, (kind == "" ? "none" : kind)
	}' "$LIST")

[ -n "$rows" ] || { echo "  FAIL  $LIST has no rows: the table this reads is gone"; exit 1; }

dup=$(printf '%s\n' "$rows" | awk '{print $1}' | sort | uniq -d)
[ -z "$dup" ] || { echo "  FAIL  $LIST names $dup more than once"; exit 1; }

nokind=$(printf '%s\n' "$rows" | awk '$2 == "none" {print $1}')
[ -z "$nokind" ] || { echo "  FAIL  $LIST has rows outside the three sections: $nokind"; exit 1; }

# The marks, wherever code or the patches to vendored code live.
marks=$(grep -rhoE 'DIVERGES: [A-Z][0-9]+' src patches package tools --include='*.c' --include='*.h' \
	--include='*.patch' --include='*.go' --include='*.init' --include='*.sh' 2>/dev/null \
	| awk '{print $2}' | sort -u)

fail=0
for m in $marks; do
	printf '%s\n' "$rows" | awk -v id="$m" '$1 == id {f = 1} END {exit !f}' \
		|| { echo "  FAIL  the code marks DIVERGES: $m, and $LIST has no row $m"; fail=1; }
done
for id in $(printf '%s\n' "$rows" | awk '{print $1}'); do
	printf '%s\n' "$marks" | grep -qx "$id" \
		|| { echo "  FAIL  $LIST lists $id, and nothing in the code is marked DIVERGES: $id — ported and not struck off, or never marked"; fail=1; }
done
[ "$fail" = 0 ] || exit 1

n=$(printf '%s\n' "$rows" | grep -c .)
p=$(printf '%s\n' "$rows" | awk '$2 == "pending"' | grep -c .)
r=$(printf '%s\n' "$rows" | awk '$2 == "runtime"' | grep -c .)
o=$(printf '%s\n' "$rows" | awk '$2 == "maintainer"' | grep -c .)
echo "  ok    $n known divergences from the reference, each marked where it is: $p not yet ported, $r Go's runtime rather than its code, $o the maintainer's decision ($LIST)"
