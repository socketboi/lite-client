<!--
One logical change per pull request. Read CONTRIBUTING.md first if this is your first one.
Delete the parts that do not apply, but keep the checklist.
-->

## What changes

<!-- One or two sentences. What the client does differently after this, or what was broken. -->

## Where the reference does it

<!--
For any change in behaviour: the reference, its pinned version and the lines, e.g.
vendor/Xray-core/proxy/vless/vless.go:9-10 or vendor/quic-go/connection.go:887-892.
The same citations must be in the code comments. Write "no behaviour change" for refactors,
tests, docs and build work.
-->

## How it was tested

<!--
Which suite covers it, and where its expected values come from (a tool under tools/ that runs
the reference code, or values copied from the reference with a citation).

Mutation check: what you reverted or broke, and which line of which suite failed.
For wire-level changes: the captures or the stand run (test/hystand, a reference server) you compared.
-->

## Checklist

- [ ] `make check-spider-behavior` exits 0 in the `lc-build:local` image (the exit status, not the absence of `FAIL` lines).
- [ ] Every behavioural claim in new or changed code cites the reference as `vendor/<tree>/<file>:<line>`, and `make check-cites` passes.
- [ ] New behaviour has a test, and the test fails when the change is reverted (mutation check described above).
- [ ] Expected values in the test come from the reference code where that is possible.
- [ ] If this adds, closes or changes a difference from the reference, `DIVERGENCES.md` and the `DIVERGES: <id>` marks are updated in this pull request (see "Differences from the reference" in CONTRIBUTING.md). Otherwise: this introduces no difference from the reference.
- [ ] If this adds a "Maintainer's decision" (O) row: the maintainer agreed to it in the issue linked below. Rows under "Not yet ported" need no prior agreement.
- [ ] Docs updated where relevant: `docs/TESTING.md` for a new suite or gate, `README.md` for anything a user sees, `CHANGELOG.md` in the unreleased section at the top.
- [ ] No files under `vendor/` or `build/` are committed; changes to ngtcp2 are a numbered patch in `patches/ngtcp2/`.
- [ ] Every commit is signed off (`git commit -s`, see "Developer Certificate of Origin" in CONTRIBUTING.md).

Related issue: <!-- #123 -->
