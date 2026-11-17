# REALITY spider acceptance

Owner clarification, 2026-11-05: flash is the size constraint. Current native
v4 checkpoints have no minimum MemAvailable or maximum RSS criterion. Memory
measurements are diagnostic. Incomplete execution, process failure, invalid
protocol behavior, failed monitoring or cleanup still invalidate a trial.
Historical native v1/v2/v3 plans retain their original RAM criteria and results.

Owner decision, 2026-11-03: keep protocol behavior and the existing spider.
Go's scheduler and frequencies of its permitted interleavings are not a porting
target. G2 remains a documented implementation difference; a statistical gap
alone does not make it a protocol defect or a release blocker.

The spider runs after TLS succeeds with an ordinary trusted site certificate
but REALITY authentication does not. It sends its own cover request and reports
the VPN attempt as failed. It must never turn that connection into an
authenticated VLESS transport. See pinned
`vendor/Xray-core/transport/internet/reality/reality.go::UClient` and
`src/cmd/lc-tunnel/main.c`'s `!s->cl.reality_verified` handoff.

## Required properties

- HTTP/2 framing, headers, flow-control credit and request/response ownership
  follow the pinned reference contracts. Buffered accepted input cannot be lost
  or reordered at cancellation, backpressure or EOF.
- Cancellation is valid for the actual stream state. It must not duplicate a
  reset, mutate HPACK for an unsent request, lose credit or leave a writer held.
- Close, stop and error paths complete ownership transfer and join worker
  tasks before freeing their state. Unrelated sessions keep progressing.
- Harvested paths stay committed and visible across the supported sharing
  boundaries. A later draw of `/` is legal and does not by itself prove cache loss.
- Device trials retain their memory, duration, liveness, identity and restoration
  guards. A resource stop or incomplete run is a failure, not missing data to omit.
- Unverified REALITY remains a failed VPN attempt. A cover HTTP exchange is not
  evidence of successful VPN authentication.

Existing C suites exercise these properties with actual queues, sockets, TLS,
epoll, controlled interruptions and cleanup ownership. The close oracle checks
forced legal orders against the pinned unmodified Go transport. Its outcomes
are deterministic contracts, independent of observed scheduling frequencies.

## Diagnostic quantities

Keep CANCEL counts, selected-path frequencies, frame order variants and timing
in reports. Use them to locate a correctness problem; do not force their rates
to equal Go by delaying C, forcing cleanup priority or moving socket ownership.
The independent first-request regression budget remains 100 microseconds:
`max(0, median_C - median_Go)`. Earlier C execution is permitted.

The Xray-versus-itself path calibration retains its frozen 10-point comparison
as an experiment about that old metric. It never grants LiteClient acceptance.
It does not supply a rate threshold to current checkpoints.

## Running the gate

Use the documented `docker/Dockerfile` build environment, which includes
Python 3 and both pinned Go toolchains:

```sh
docker run --rm -i --network none -v "$(pwd):/w" -w /w lc-build:local \
  make check-spider-behavior
```

This runs the complete existing `make check` contract, including cross-target
checks, checkpoint/receipt analyzer tests and the divergence gate, followed by
the controlled spider-close oracle. It does not run a live device trial, install
packages, modify routing on a working router or grant resource acceptance from
host-only execution. The runtime spider and its wire defaults are unchanged.

## New checkpoint formats

New host runs use `host-g2-checkpoint-v4`; native plans use
`native-g2-checkpoint-v4`. Their criteria contain only the independent timing
regression budget. Wire, provenance, completion and lifecycle validation remain
mandatory. Native plans retain the 1200-second duration limit and declare
`resource_policy: flash-only`; RAM has no numeric acceptance threshold.
Native evidence must use the corresponding reviewed analyzer;
an older archived analyzer is not a validator for a new-format plan.

After preparing the exact host binaries, configurations, driver and analyzer
inputs, freeze a new plan before starting the workload:

```sh
python3 tools/vendorcap/nativeclient/analyze_checkpoint.py RUN_DIRECTORY --prepare-plan
```

The command hashes every required input and creates `plan.json` exclusively;
it refuses to overwrite an existing plan. Execute exactly its 24 phases with
container-local live journals, then analyze the resulting directory:

```sh
python3 tools/vendorcap/nativeclient/analyze_checkpoint.py RUN_DIRECTORY
```

Reports declare `acceptance_scope: checkpoint`. A valid host checkpoint is not
a declaration that native memory/lifetime acceptance or production release is
complete. There is no `G2Closed` release flag in the new formats.
Analysis prints its report and exits nonzero when checkpoint criteria fail;
successful parsing alone is not a passing checkpoint.

Historical plans, raw captures, criteria, source hashes and results remain
unchanged. Old host v1/v2/v3 and native v1/v2/v3 plans must be replayed with their
retained analyzers; the current validator rejects them. Do not relabel an old
failed checkpoint as a new passing trial.

The [executable checkpoint workflow](../tools/vendorcap/nativeclient/README.md#executable-checkpoint-workflow)
documents fresh preparation, the frozen host driver, bounded native staging and
execution, and evidence collection. Native acceptance also verifies unchanged
configuration hashes and successful resource-monitor termination. Retain the
whole run privately, including failed/incomplete attempts, and export live
journals only after workload and cleanup finish.
