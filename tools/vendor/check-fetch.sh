#!/bin/sh
# tools/vendor/fetch.sh is how anyone else gets vendor/, so it has to fetch exactly what the table in
# docs/BUILD.md pins: every tree the table gives a revision is fetched at that revision, every tree
# fetched is in the table, and no tree is fetched twice. Names are compared as strings, not patterns.
cd "$(dirname "$0")/../.."
table=$(sh tools/vendor/pins.sh) || exit 1
[ -n "$table" ] || { echo "  FAIL  no pinned revisions found in docs/BUILD.md: the table this reads is gone"; exit 1; }
fetched=$(awk '/^PINS=\x27$/ { on = 1; next } on && /^\x27$/ { on = 0 } on && NF >= 3 { print $1, $3 }' tools/vendor/fetch.sh)
[ -n "$fetched" ] || { echo "  FAIL  tools/vendor/fetch.sh has no PINS list"; exit 1; }
bad=$(printf '%s\n--\n%s\n' "$table" "$fetched" | awk '
    $0 == "--" { part = 2; next }
    part != 2 { want[$1] = $2; next }
    { if ($1 in got) print $1 ": fetched twice"; got[$1] = $2 }
    END {
        for (n in want) {
            if (!(n in got)) { if (want[n] != "-") print n ": pinned at " want[n] " in docs/BUILD.md, not fetched" }
            else if (want[n] != "-" && index(got[n], want[n]) != 1) print n ": docs/BUILD.md pins " want[n] ", fetch.sh fetches " got[n]
        }
        for (n in got) if (!(n in want)) print n ": fetched, but not in the table in docs/BUILD.md"
    }' | sort)
[ -z "$bad" ] && echo "  ok    tools/vendor/fetch.sh fetches exactly what docs/BUILD.md pins ($(printf '%s\n' "$fetched" | grep -c .) trees)" \
    || { printf '%s\n' "$bad" | sed 's/^/  FAIL  /'; exit 1; }
