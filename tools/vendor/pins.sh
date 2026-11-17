#!/bin/sh
# The rows of the "Pinned revisions" table in docs/BUILD.md, one "name revision" per line, with "-"
# for a tree the table names without a revision. The one reader of that table: check-vendor holds
# the checkouts in vendor/ to it, check-fetch holds tools/vendor/fetch.sh to it.
cd "$(dirname "$0")/../.."
[ -f docs/BUILD.md ] || { echo "pins.sh: docs/BUILD.md is missing" >&2; exit 1; }
sed -n 's/^| *`\([A-Za-z0-9._-]*\)` *| *\(`\([0-9a-f]\{7,\}\)`\|—\) *|.*/\1 \3/p' docs/BUILD.md \
    | awk '{ print $1, ($2 == "" ? "-" : $2) }'
