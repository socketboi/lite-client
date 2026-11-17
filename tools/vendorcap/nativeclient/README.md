# Native REALITY reference distribution

`native-dual-smoke.sh DIRECTORY` is a separate short device data-path check.
It requires an owner-prepared `/tmp/lc-dual-*` directory containing `client`
(the SDK-packaged dual-plane binary), a matching `soak_probe.c` executable
named `probe`, `fingerprint.fpt`, `cert.pem`, `uuid`, `auth`, `obfs`, the
driver itself, `settings.sh` and a `device.sha256` covering every input.
The script verifies its own executed bytes before reading settings.

Settings identify `EXPECTED_BOARD`, `EXPECTED_BOOT`, `EXPECTED_VERSION`,
`RUN_LABEL` (an ASCII letters/digits/underscore/hyphen run identifier),
`PEER`, `REALITY_PORT`, `HYSTERIA_PORT`, `SALAMANDER_PORT`, `PUBLIC_KEY`,
`SHORT_ID`, `CERT_PIN` and `BODY_SHA`. The lab peer needs a TLS 1.3 donor
for `smoke.test`, a distinct HTTP/TLS destination at `127.0.0.1:29762`
serving `bytes(range(256))*4096`, and a UDP nonce echo at `127.0.0.1:29763`.
Use separate donor and payload listeners so REALITY's donor handshakes do
not count as failed application requests. Only the authenticated protocol
listeners need to be reachable from the device; destinations stay on loopback.

Six cases cover REALITY, Hysteria without obfuscation and Salamander, each
with one/four workers. Each verifies four concurrent HTTP/TLS payloads and
64 UDP echoes, then bounded disappearance of the whole process group.
Receipts include configuration, interface, boot and policy-rule snapshots;
RAM observations are diagnostic. Archive the stage and peer receipts after
cleanup. This check changes no packages, services, UCI or routing. It does
not qualify package hooks, production API delivery, interception rules,
service switching, long-duration reclamation or comparative throughput.

Owner clarification (2026-11-05): flash is the size constraint. Current native
v4 checkpoints have no MemAvailable/RSS acceptance floor or cap. RAM counters
remain diagnostic; process liveness, complete execution, monitor health,
protocol correctness and cleanup remain mandatory. Retained native v1/v2/v3
evidence uses its archived plan and analyzer, including any historical RAM floor.

Current owner policy (2026-11-03): CANCEL and selected-path frequencies are
diagnostic, not LiteClient acceptance thresholds. Protocol, flow-control,
cancellation/close/lifetime, provenance and resource validation remain required.
See [spider acceptance](../../../docs/SPIDER-ACCEPTANCE.md). Historical results
keep their archived plans and analyzers; they are not retroactively reclassified.

`calibrate_paths.py DIRECTORY` checks a separate ordinary Xray-versus-itself
host control. Both `ref` and `lc` are labels for the same Xray binary and JSON
configuration; neither label executes LiteClient. The frozen design has twelve
blocks, three rounds per block and five retry connections per phase, with role
order counterbalanced within and across blocks. Every block applies the existing
15-connection closeafter comparison through `compare_control`; no other scenario
is fabricated to fill a checkpoint. Metrics come from `compare_scenario`, while
the frozen control retains its own old thresholds independently of current
LiteClient acceptance.

All twelve blocks must validate: input and executed-binary hashes, progress order,
probe exits 52/56, client/stand liveness, ordinary process exits, complete wire
groups and cleanup. The report separates path-rate rejections from timing or
cancellation failures. It never pools blocks for acceptance, grants G2, changes
thresholds or reclassifies historical checkpoints. Retry connections share a
phase cache; the observed rejection count is not a population false-rejection
estimate. Run workload/journals on container-local storage, export after cleanup,
and retain the frozen plan, driver, analyzers, exact inputs and every raw block.

For the separate frozen host checkpoint, run `python3 analyze_checkpoint.py DIRECTORY`.
It validates the host-g2-checkpoint-v4 plan, exact input hashes, three paired
rounds of all four scenarios with counterbalanced role order, five connections
per probe, phase markers, wrong-key probe exits, opening frames, paths and
driver/cleanup completion. It reports cancellation/harvesting gaps and
first-request medians. Rates are descriptive; only the independent 100-us candidate
latency-regression budget is a comparison criterion. Negative C-minus-Go latency
is permitted. A valid checkpoint can fail this criterion. Reports declare
`acceptance_scope: checkpoint`; they do not grant a production release. This
analysis does not replace the frozen full experiment or native acceptance.
Run `python3 -m unittest discover -s . -p 'test_*.py'` for analyzer and plan tests.

V4 retains one executable/liveness/probe/stop receipt per client
phase, plus the server/destination identities and ordinary stop results. The
manifest hashes the actual server configuration, leaf private key and imported
network analyzer as well as the client configuration and binaries. All 24 phases
must complete. Use `--prepare-plan` on a new run directory to hash the exact
inputs before execution; it refuses to overwrite `plan.json`. Old host v1/v2/v3
evidence must use its retained analyzer, with no automatic reinterpretation.
The separate Xray-versus-itself calibration keeps its frozen format and criteria.

For startup diagnostics, build with `EXTRA_CFLAGS=-DLC_SPIDER_PROFILE=1`.
`python3 analyze_startup.py --expected-count 15 client-1.log client-2.log client-3.log`
validates complete samples and reports handoff/logging, allocation, fetch,
thread creation/entry and first-HEADERS intervals. All offsets are nanoseconds
from the invalid-certificate handoff boundary; summaries convert to microseconds.
Immutable 64-bit entry timestamps use 32-bit ready flags with release/acquire
publication, including on MIPS32 without libatomic. The loop logs
samples after the first request reaches the socket; profiling is disabled in
ordinary builds. Instrumented results cannot grant G2 acceptance.

Run performance workloads and all live journals on container-local storage.
Copy retained evidence to the host only after the workload and cleanup finish.
On Docker Desktop a Windows bind mount may make each synchronous log write
hundreds of microseconds long; an asynchronous reference logger pays that cost
on a different path. Record storage placement and actual executable hashes.
Do not remove client logs or change protocol scheduling to compensate for the
test stand. Historical bind-mounted measurements remain evidence of that stand,
not ordinary-client timing parity or regression.

Before launching a paired checkpoint, inspect first-role order separately for
each scenario. Rotating scenario positions and choosing roles from that rotating
position can accidentally leave the same client first every round. Derive role
order from round and stable scenario identity, then validate the frozen plan.
Fixed-order diagnostics must state that limitation and cannot close G2.

`native_checkpoint_plan.make_plan()` generates the three-round, four-scenario
native checkpoint (120 connections). `validate_plan()` independently checks
coverage, adjacent role pairs, closeafter last, per-scenario role counterbalance,
the fixed 100-us regression budget and current device policy. Validate the frozen
plan before starting the workload and again when analyzing its evidence. Deriving
role order uses stable scenario identity rather than its rotating position.

The owner approved preserving C speed improvements with unchanged protocol
behavior on 2026-10-28 and removing rate matching on 2026-11-03. Current checkpoints
report absolute timing difference, signed C-minus-Go
delta and nonnegative regression separately; only the regression has a 100-us
budget. Native plans use native-g2-checkpoint-v4 and criteria_frozen. No legacy
schema/criterion aliases are accepted. Historical v1 evidence keeps its original
absolute-gap result and hashed analyzers; v2/v3 host and v2 native rate-gated
results also retain their archived policy. Replay each with its retained sources.
Do not rewrite old plans, substitute scheduling delays, or weaken frame,
flow-control, cancellation, close/lifetime or restoration checks for speed.

The summary field harvested counts selection of a harvested path; it is not a
count of cache commits. Root / remains a valid random draw after links have
been harvested. A selected-path rate difference requires inspection of commit/
retention evidence; it does not justify removing root from the draw or claiming
cache loss from selection counts alone.

`make BUILD=build-retention build-retention/test-spider-retention` builds a
separate direct cache fixture; run that executable after building it. It is also
part of `make check`. It includes the unchanged `paths.c` in the test translation
unit so observations use its real store lock without adding a production API.
The fixture checks exact membership and retained hashes before/after sharing,
commit visibility after a forked producer exits, and concurrent duplicate inserts
across table growth. It does not infer membership from random path selections.
This local ownership fixture does not explain a particular captured connection,
replace paired C/Go traces, or grant G2 acceptance.

This is a test adapter around the pinned Xray implementation, not another
implementation of REALITY. The full Xray executable carries unrelated protocols
and command/configuration frontends; staging it in an OpenWrt router's tmpfs can
exhaust memory before a comparison starts.

## Executable checkpoint workflow

### Controlled UDP lifecycle

`udp_lifecycle.py` compares full Xray and ordinary LiteClient with one/four
workers in three rounds. Baseline, injected TCP FIN and injected TCP RST cases
check nonce-tagged UDP traffic, recovery after a quiet interval, rebinding the
same source port and a fresh source. The first reply after an injected fault
is diagnostic: UDP does not retransmit a lost packet. Every baseline, recovered,
rebound and fresh-source echo is mandatory with the original five-second reply
deadline. This is a controlled lifecycle test, not a throughput benchmark.

Run inside a dedicated Linux container with `--network none` and raw packet
capture capability (Docker's default CAP_NET_RAW). The driver refuses any
namespace with an interface other than loopback. It records a complete PCAP
and rejects capture drops; it changes no firewall, routes or installed services.
Use Docker `--init` when the driver would otherwise be PID 1, so orphaned
workers have a reaper. Owned-process shutdown waits for the parent and the
entire process group, including zombies, within one 15-second deadline. A
forced kill is a failure retained through subsequent cleanup calls; completed
groups are never signaled again.
Keep runtime journals on container-local storage and export the directory
after cleanup. Inputs include disposable test credentials and remain private.

```sh
python3 tools/vendorcap/nativeclient/udp_lifecycle.py /run/udp-lifecycle \
    --lc /binaries/lc-tunnel.host --reference /binaries/full-xray.host \
    --fingerprint package/files/fingerprint.fpt
python3 /run/udp-lifecycle/driver.py /run/udp-lifecycle --analyze
```

Use the full pinned Xray executable, not the protobuf-only reference adapter.
The frozen manifest retains executable/configuration/driver/helper hashes and
the reported Xray version. Independent analysis verifies complete role/fault/
round coverage, unique nonces in both client and backend UDP directions, the
actual injected FIN/RST flags, recovery timing, worker startup and process exits.
These controls can demonstrate a fault-loss mechanism without proving the
cause of a historical timeout for which no packet capture exists.

### Independent streams during a UDP upstream close

`flow_isolation.py` extends the host loopback method with four independently
mapped upstream connections: a victim UDP session and persistent neighboring
UDP, plain TCP and TLS 1.3 streams. Each neighbor keeps its original socket and
continues nonce-checked exchanges while the victim receives a controlled FIN
or RST. Only the victim becomes quiet before its mandatory recovery request;
neighbor activity continues throughout. The first victim reply after a fault
remains diagnostic under the same five-second deadline.

```sh
python3 tools/vendorcap/nativeclient/flow_isolation.py /run/flow-isolation \
    --lc /binaries/lc-tunnel.host --reference /binaries/full-xray.host \
    --fingerprint package/files/fingerprint.fpt
python3 /run/flow-isolation/driver.py /run/flow-isolation --analyze
```

Use the same dedicated `--network none` container and retain private inputs
after cleanup. Three rounds cover full Xray and LiteClient with one/four workers
under baseline/FIN/RST. The new schema freezes the UDP helper as an additional
input. Replay requires progress before and after injection on every neighbor,
unchanged source sockets, distinct live upstreams, no neighbor FIN/RST during
observation, stable backend TCP connection identities, complete nonce receipts,
lossless capture, full case coverage and ordinary process-group cleanup. Neighbor
streams never reconnect, and the loader never retries a request. This checks
bounded host flow isolation, not hardware performance, throughput or hours-long
stability.

### Native mixed workload and socket reclamation

`native_soak.py` and `native-soak.sh` run a separate MIPS-only device test:
one and four workers each perform two epochs of 60 seconds of mixed load and
190 seconds of quiet. Each epoch has six bursts of four concurrent HTTP/TLS
downloads and 64 exact nonce-checked UDP echoes. The quiet interval covers the
pinned UDP checker's 120-second idle rule and 60-second scan interval. Only the
client's TCP/UDP listeners may remain afterward. RAM counters are diagnostic;
there is no MemAvailable floor or RSS cap, and this is not a throughput comparison.

Build `soak_probe.c` with the documented OpenWrt MIPS toolchain in the build
image, then supply the native client/helper and full pinned host Xray:

```sh
mipsel-openwrt-linux-gcc -std=c11 -Os -Wall -Wextra -Werror -Wconversion -Wshadow \
    tools/vendorcap/nativeclient/soak_probe.c -o /binaries/soak-probe
python3 tools/vendorcap/nativeclient/native_soak.py prepare /run/native-soak \
    --source-root "$PWD" --lc /binaries/lc-tunnel.mipsel --probe /binaries/soak-probe \
    --reference /binaries/full-xray.host --device-json /private/device.json \
    --advertised-host "$LAB_HOST"
python3 /run/native-soak/driver.py serve /run/native-soak
```

The preparation checks both native ELF targets and stages owner-only files,
including the UUID that the ordinary client requires to be mode 0600. Use the
same device identity JSON as the native checkpoint. Copy `device-stage/` into
a fresh mode-0700 `/tmp/lc-native-soak-...` directory on the authorized device,
then run `sh native-soak.sh "$DEVICE_DIR"`. It uses loopback loaders and outbound
lab connections; no installed service, firewall, route or UCI setting changes.
The 1200-second device guard, complete monitor coverage, stable process identities,
payload hashes, helper identity and ordinary cleanup remain mandatory.

After the device exits, archive its directory. Return the archive with an
authenticated PUT to the stand's `/results` endpoint, using the frozen plan's
control token from a separate mode-0600 file:

```sh
archive="${DEVICE_DIR}.results.tgz"
tar -C "$DEVICE_DIR" -czf "$archive" .
curl -q -fsS --noproxy '*' --connect-timeout 5 --max-time 30 \
    -H "Authorization: Bearer $(cat "$CONTROL_TOKEN_FILE")" \
    -H "X-Archive-SHA256: $(sha256sum "$archive" | awk '{print $1}')" \
    --upload-file "$archive" "$LAB_CONTROL_URL/results"
```

The stand then stops its owned server and listeners. On the host, unpack
`device-results.tgz` into `device-results/` beneath the stand directory and run
`python3 driver.py analyze .` there. Preserve the complete stand/device evidence,
including failed preparations, before removing owned temporary files. The
retained driver/helper sources permit replay without the working checkout.
The default short profile is a bounded load/quiet test, not an hours-long soak.

For the authorized test device, preparation accepts `--profile long`. Its
separate `native-mixed-soak-v2` schema fixes two 1800-second load epochs per
worker mode, with 190 quiet seconds after each epoch. This gives two active
hours across one/four workers and about 133 elapsed minutes. It requires all
720 bursts, 2880 one-MiB HTTP/TLS downloads, 46,080 nonce UDP echoes, complete
one-second monitoring, stable process identities and four empty-session-socket
checkpoints. The device deadline is 8400 seconds; the stand allows another
600 seconds for returning evidence. All earlier integrity, cleanup and
flash-only resource checks remain mandatory. Active seconds describe the
scheduled burst window, not continuous maximum-rate saturation.

Use the same prepare/serve/device/return/analyze workflow and preserve private
artifacts on failure. A background launch is not an accepted result: only the
final device/stand receipts and complete analysis can establish completion.
Neither profile proves the absence of every kind of resource leak.

Analysis also checks every burst's byte/echo counters and append order. Monitor
phases must occur once in ready/active/idle order, with known role/epoch labels
and timestamps within the run. Each completed burst must fall in its matching
active window and respect the ten-second schedule; the existing three-second
monitor tolerance covers phase sampling. A long journal of quiet samples cannot
substitute for a correctly scheduled load window. When reviewing older frozen
attempts, keep the original replay and separately run the current analyzer;
preserve both receipts and the additional analyzer's source hash.

### Fallback checkpoints

`prepare_checkpoint.py` prepares new host v4 or native v4 evidence exclusively:
an existing directory is an error. Run it in the documented build container,
using container-local storage for the run. It creates a disposable stand CA and
REALITY identities, unrelated to deployed credentials. Keep the whole directory
private: its frozen inputs include test private keys and a native control token.
The source manifest includes the C source, pinned Xray source, reference adapter,
configuration encoder and destination fixture. Supply binaries built from that
exact source snapshot; preparing hashes does not itself rebuild them.

For a host checkpoint, supply the ordinary tunnel, full pinned Xray executable
and the destination built from `tools/vendorcap/spiderredir/dest`:

Build the destination with `/usr/local/go1.27/bin/go build -mod=readonly` in
its module directory. Its independent x/net v0.58.0 fixture pin and committed
`go.sum` are seeded into the documented image and included in source manifests;
do not resolve a different dependency set while preparing a measurement.

```sh
python3 tools/vendorcap/nativeclient/prepare_checkpoint.py host /run/host-v4 \
    --source-root "$PWD" --lc /binaries/lc-tunnel.host \
    --reference /binaries/reference.host --destination /binaries/dest.host
python3 -u /run/host-v4/driver.py /run/host-v4
```

The frozen driver verifies executable identities and listener ownership, runs
all 24 phases and validates the evidence. It exits nonzero on a failed comparison
or invalid/incomplete evidence. SIGTERM/HUP unwind owned-process cleanup as well.
Export the entire run directory only after the driver and cleanup finish.

For a native checkpoint, create a private `device.json` with exactly
`board_name`, `boot_id` and `architecture` (`mipsel` or `aarch64`), read from the
authorized test device. Build the matching reference/encoder with `build.sh`.
Use a LAN-reachable isolated container with TCP 14480 and the selected control
port published only on the lab address; its destination stays on loopback.

```sh
python3 tools/vendorcap/nativeclient/prepare_checkpoint.py native /run/native-v4 \
    --source-root "$PWD" --lc /binaries/lc-tunnel.host \
    --reference /binaries/reference.host --destination /binaries/dest.host \
    --native-lc /binaries/lc-tunnel.native \
    --native-reference /binaries/reference.native --encoder /binaries/encode \
    --device-json /private/device.json --advertised-host "$LAB_HOST"
python3 -u /run/native-v4/native_checkpoint.py serve /run/native-v4
```

After `NATIVE_STAND_READY`, copy the contents of `device-stage/` into a fresh,
mode-0700 `/tmp/lc-native-...` directory on that device. Check available memory
before and after staging; the device runner verifies every staged hash before
launch. Run `sh native-device.sh /tmp/lc-native-...` there. It uses temporary
listeners without changing services, routing, packages or UCI. The runner checks
boot identity, configuration hashes, interfaces, client identity, CPU, sampled
RSS/fds/threads and a 1200-second duration limit. MemAvailable and RSS do not
decide acceptance. Flash fit is assessed for the installed package and its
dependencies separately; disposable stand binaries stay in tmpfs.
The stand checks ordered authenticated phase acknowledgements and process
liveness; idle connections cannot hold its control server indefinitely.
Before launching processes, it verifies the executed native driver and all
loaded checkpoint helpers against the frozen manifest, as the host runner does.
The device script also verifies its executed file before loading staged settings.

Wait for both device and stand exits. Copy the device evidence into
`/run/native-v4/device-results/`, then run:

```sh
python3 /run/native-v4/analyze_native_checkpoint.py /run/native-v4
```

Archive the full stand directory and device evidence after cleanup, including
failed runs. Remove only the owned temporary device directory after archiving;
never remove another session's files. A successful bounded checkpoint grants
checkpoint scope only, not a mixed-workload soak or release approval. Qualify the
selected reference distribution against full Xray as documented below before
relying on its device results.

The runner imports the mandatory dispatcher and proxy managers listed in
`vendor/Xray-core/main/distro/all/all.go`, logging, dokodemo, VLESS outbound,
TCP, TLS and REALITY. Unsupported modules are errors, never substituted handlers.
It uses the existing protobuf loader (`core/config.go::loadProtobufConfig`) and
`core.New`/`Start`. Post-start GC, memory release, signal waiting and `Close`
follow `main/run.go::executeRun`. No vendor sources, HTTP/2 task drivers,
fingerprints, retries or spider settings are changed.

The host encoder uses `infra/conf/serial/loader.go::LoadJSONConfig` and protobuf
serialization. Thus the ordinary JSON configuration is built with the same
defaults as full Xray before the target reads it. Configuration parsing moves
off the device; this adapter cannot measure full-Xray startup memory or time.

Run in the documented LiteClient build image with the pinned Go module cache:

```sh
GOOS=linux GOARCH=mipsle GOMIPS=softfloat GOPROXY=off GOSUMDB=off \
    sh tools/vendorcap/nativeclient/build.sh
build/native-reference/encode client.json client.pb
# On the matching test target, with its controlled stand's trust root:
SSL_CERT_FILE=ca.pem ./reference client.pb
```

`XRAY_GO` names the required Go executable; its version must equal
`GO127_VERSION` in `docker/Dockerfile`. Automatic toolchain switching is disabled.
It does not select an alternate reference revision. The build uses the pinned
vendor module in place and emits source/binary hashes. It writes only to its
output directory and the Go caches.
Before relying on device results, run full Xray and this distribution against
the same host stand, verify complete connection groups and frame/lifecycle
invariants, then retain their exact hashes with the device measurements.

Use an isolated temporary process on an authorized test router. Preserve and
restore any paused services, bound the test, monitor available memory including
binary staging, and accept output only after successful exit. A smaller binary
does not waive memory checks or establish G2 acceptance. No installed router
client or service should be replaced with this test adapter.

`analyze_network.py DIRECTORY` validates the retained paired network diagnostic;
`--host-only` validates its full-Xray versus selected-distribution control.
It never grants G2 acceptance. Opening SETTINGS values, order and length, and
the initial connection credit must match the pinned
`vendor/x-net/http2/transport.go::newClientConn` defaults in every capture.
SETTINGS ACK scheduling and randomized HPACK field order remain unconstrained.

The wrong-key HTTP probe must finish with curl 52 (empty reply) or 56 (receive
failure), with a complete matching wire capture. Timeout 28, connection refusal,
successful authenticated traffic and local command failures invalidate the run.
The device driver must enforce this same exit-code contract before reporting
probe completion; an arbitrary nonzero status is insufficient.

The one-second memory log must include binary staging and all phase labels in
order, with strictly increasing timestamps and no gap above three seconds (two
missed ticks allowed for scheduling). Each phase needs at least eight samples
spanning seven seconds, covering its fixed two-second startup and six-second
post-probe waits. These are diagnostic evidence checks, not new G2 acceptance
thresholds. Host/device clocks need not be synchronized. Sampling cannot prove
instantaneous peaks or monitor liveness after its last recorded observation;
future device drivers must also check the monitor process at phase boundaries
and record its exit status rather than ignoring its wait result.

Run the analyzer regression suite inside the documented build environment:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
    -s tools/vendorcap/nativeclient -p 'test_*.py' -v
```

`analyze_refunds.py DIRECTORY` additionally validates a test-only buffered trace
from the active Go 1.27 internal HTTP/2 transport and an isolated C build.
The ordinary network evidence must pass first. Each client log must contain one
complete `TRACE_BEGIN N` / `TRACE_END N` dump, with contiguous event indexes and
at most 2048 events. Per-connection credit-value multisets must match the wire
captures; local pointer identities are not treated as network identifiers.

The trace distinguishes `close_refund`, `read_refund`, `data_refund` and
`late_refund`, and records unread pipe bytes when Close breaks the body.
Accounting can precede competing writers' acquisition of cc.wmu, so trace order
does not establish their wire order. Instrumentation retains records in memory
and dumps after traffic; its CPU, timing and resource observations are not
performance measurements. It never grants G2 acceptance. The instrumentation
overlays and exact build inputs belong with the private run evidence; production
source, pinned vendor files, node settings and trust roots are not modified.

`analyze_cleanup.py DIRECTORY` requires the additional cleanup milestones:
`cleanup_enter`, `reset_send`, `reset_complete`, `cleanup_postwrite`, `forget`,
`done` and `headers_send`. It checks producer ordering, local Flush success,
stream removal before redirected headers, and reset counts against wire frames.
It locates the first DATA handling event relative to those milestones; this is
not a timestamp of physical packet arrival. `reset_complete` is local completion,
not a peer acknowledgment. Go closes donec before recording `done`, so a consumer
may send redirected headers before that following trace marker. The analyzer
does not impose the opposite scheduling order or grant acceptance.

`first_data_vs_redirect` further separates DATA before and after the local
`headers_send` marker. Removal alone cannot distinguish those cases; that marker
does not mean that the peer has received HEADERS. Likewise, `reset_send` precedes
Flush: DATA between reset-send and reset-complete can overlap queued work or
socket I/O. It is not evidence of socket backpressure without another observation
at actual Write entry. The regression accepts both orderings, including a Go
consumer running before the producer records its post-donec trace marker.

`analyze_dispatch.py DIRECTORY` additionally requires C-only `reset_take` and
`reset_socket` events for every reset. It validates the complete cleanup/wire
evidence first, including the Go phases, then locates C DATA before reset-send,
while reset is queued, after TLS-owner take, or after socket-result/completion.
Missing, repeated and reordered dispatch events are errors. Go does not use the
C TLS-owner handoff, so these additional markers are not inferred for it.

`reset_take` carries the local Write id and the reset's plaintext length (13, or
30 with its PING). `reset_socket` is recorded after conn_write's syscall result,
with positive bytes / errno 0, or zero bytes / Linux EINTR 4 or EAGAIN 11. The
observer preserves errno and does not complete or retry Writes. Later q_flush
syscall retries are outside this observer; take is not socket submission, and
no performance result follows from the instrumented sequence.

Additional C-only `do_notify`, `do_ready`, `do_step` and `request_queue` markers
locate the consumer handoff after cleanup. Notify is recorded before the
condition broadcast; ready is the wait predicate returning with the protocol
mutex held, not the instant an OS thread becomes runnable. Step marks entry to
fetch settling. Notify/ready carry the generation value; their extra field,
and step's extra field, is the Do state. Queue records the next
proposed stream ID while its value is the still-unassigned ID (zero), before
request admission/encoding. It is not a transmitted HEADERS marker.
Do can already be running when donec completes, so the absence of a later
wait-return marker does not establish a lost wake. Fragmented DATA is classified
by its first handling event, and clean peer completion can validly omit reset.

`prepare_cache_trace.py SOURCE OUTPUT` generates test-only C replacements and a
Go overlay for direct cache observations. OUTPUT must be a new directory outside
SOURCE. Unique source anchors must match before any output is created. The receipt
hashes the original and generated files; apply C replacements only to an isolated
copy and restore its exact original bytes after building. Build Go with the emitted
overlay, without editing the pinned vendor tree.

The observer records successful first-path draws and harvest commits under the
existing cache mutex. Each event retains the count and membership of `/` plus
`/h0`--`/h19`; commits also retain the previous count. The bounded 128-event buffer
adds no random draws, clocks or I/O while traffic runs. After the phase is quiet,
SIGUSR1 dumps the C buffer through the existing statistics path; normal Xray
shutdown dumps its buffer after server Close. The driver must collect exactly one
complete, nonoverflowing dump per client process. C retains ordinary SIGTERM
termination (Python return code -15); Xray exits 0.

`analyze_cache.py DIRECTORY` validates the frozen two-round host diagnostic:
closeafter only, five connections per phase, reference/C then C/reference. Each
phase requires five draws, five commits, exact retained membership and matching
wire path multisets. A root draw after commit is valid when the full cache is
present; neither a root draw nor its absence is required. Events are not matched
to individual sockets or forced into wire order. Input/source/observer/executed
binary hashes, probe exits 52/56, process liveness, shutdown and stand cleanup must
also validate. The ordinary binaries are retained as build inputs; this diagnostic
does not itself run an uninstrumented comparison.

```sh
python3 tools/vendorcap/nativeclient/prepare_cache_trace.py /work/lite-client /work/cache-observers
PYTHONDONTWRITEBYTECODE=1 python3 tools/vendorcap/nativeclient/analyze_cache.py /evidence/run
```

For the protobuf reference, generate with `--native-reference`. This selects the
existing `runner/main.go` entry point and a distinct observer schema; the runner
itself and vendor files stay untouched. Its deferred dump runs after server Close.
Before device use, verify the overlaid runner against full Xray on the same host
stand, with complete wire and cache traces. Cross-build both clients for the test
target, and retain the exact toolchain, overlay, source and executed binary hashes.

The following cache-observer format is a historical frozen diagnostic, retained
with its original RAM floor for replay. Current ordinary native v4 checkpoints
use the flash-only policy in the executable workflow above.

`analyze_cache.py --native DIRECTORY` accepts only the native schema and requires
the additional device/monitor/stand scripts, protobuf configuration and toolchain
receipt. Host mode rejects native plans. Native mode requires two counterbalanced
closeafter rounds, unchanged boot/configuration/interfaces, monitor exit 0, a
4096-KiB MemAvailable floor, a 240-second device bound and memory samples covering
binary staging, every phase and cleanup. Each phase needs eight samples spanning
seven seconds; timestamps must increase with gaps no larger than three seconds.
The native C stop receipt uses shell status 143; reference exit remains 0. Stage
only one client binary at a time on small tmpfs targets and keep live journals
local to their test machine. Export evidence after workload and cleanup, verify
archive checksums, and keep incomplete attempts separate. No installed client or
router service needs replacing for this diagnostic.

The driver, plan, generated overlays, build receipts and raw observations belong
with the private run evidence. Instrumentation can affect scheduling and resource
use. This diagnostic does not measure timing or path-selection frequencies,
retroactively explain another run, replace an ordinary checkpoint, or grant G2
acceptance. See `docs/TESTING.md` for the retained host and native results.
